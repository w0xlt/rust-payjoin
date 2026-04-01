use std::fmt::Debug;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Sink, SinkExt, StreamExt};
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::header::{CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{tungstenite, WebSocketStream};
use tracing::{error, instrument};

use crate::ohttp_relay::error::Error;
use crate::ohttp_relay::gateway_uri::GatewayUri;
use crate::ohttp_relay::{empty, GatewayConnector};

/// Check if the request is a WebSocket upgrade request.
///
/// This is done manually to support generic body types.
/// When bootstrapping moves to axum, this can be replaced with
/// `axum::extract::ws::WebSocketUpgrade`.
pub(crate) fn is_websocket_request<B>(req: &Request<B>) -> bool {
    let dominated_by_upgrade = req
        .headers()
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);

    let upgrade_to_websocket = req
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    dominated_by_upgrade && upgrade_to_websocket && req.headers().contains_key(SEC_WEBSOCKET_KEY)
}

/// Upgrade the request to a WebSocket connection and proxy to the gateway.
///
/// This performs the WebSocket handshake to support generic body types.
/// When bootstrapping moves to axum, this can be replaced with
/// `axum::extract::ws::WebSocketUpgrade`.
#[instrument]
pub(crate) async fn try_upgrade<B>(
    req: Request<B>,
    gateway_origin: GatewayUri,
    connector: GatewayConnector,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error>
where
    B: Send + Debug + 'static,
{
    let key = req
        .headers()
        .get(SEC_WEBSOCKET_KEY)
        .ok_or_else(|| Error::BadRequest("Missing Sec-WebSocket-Key header".to_string()))?
        .to_str()
        .map_err(|_| Error::BadRequest("Invalid Sec-WebSocket-Key header".to_string()))?
        .to_string();

    let accept_key = derive_accept_key(key.as_bytes());

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let ws_stream = WebSocketStream::from_raw_socket(
                    TokioIo::new(upgraded),
                    tungstenite::protocol::Role::Server,
                    None,
                )
                .await;
                if let Err(e) = serve_websocket(ws_stream, gateway_origin, connector).await {
                    error!("Error in websocket connection: {e}");
                }
            }
            Err(e) => error!("WebSocket upgrade error: {}", e),
        }
    });

    let res = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "Upgrade")
        .header(SEC_WEBSOCKET_ACCEPT, accept_key)
        .body(empty())
        .map_err(|e| Error::InternalServerError(Box::new(e)))?;

    Ok(res)
}

/// Stream WebSocket frames from the client to the gateway server's TCP socket and vice versa.
#[instrument(skip(ws_stream))]
async fn serve_websocket<S>(
    ws_stream: WebSocketStream<S>,
    gateway_origin: GatewayUri,
    connector: GatewayConnector,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut tcp_stream = connector.connect(&gateway_origin).await?;
    let mut ws_io = WsIo::new(ws_stream);
    let (_, _) = tokio::io::copy_bidirectional(&mut ws_io, &mut tcp_stream).await?;
    Ok(())
}

// NOTE: this type mirrors payjoin-cli/src/app/v2/bootstrap.rs `WsIo`.
// If you change the implementation here, update the other copy too.
pub struct WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ws_stream: WebSocketStream<S>,
    read_buffer: Vec<u8>,
    pong_state: PongState,
    closing: bool,
}

enum PongState {
    Idle,
    NeedSend(Message),
    NeedFlush,
}

impl<S> WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(ws_stream: WebSocketStream<S>) -> Self {
        WsIo {
            ws_stream,
            read_buffer: Vec::new(),
            pong_state: PongState::Idle,
            closing: false,
        }
    }

    /// Drive a queued Pong reply through `poll_ready` → `start_send` → `poll_flush`.
    ///
    /// The Sink contract requires `poll_ready` before `start_send`, and a queued Pong
    /// must be flushed or the peer can time out the keep-alive. Called from every
    /// poll entry point so progress happens regardless of read/write traffic.
    fn drive_pending_pong(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.pong_state {
                PongState::Idle => return Poll::Ready(Ok(())),
                PongState::NeedSend(_) => match self.ws_stream.poll_ready_unpin(cx) {
                    Poll::Ready(Ok(())) => {
                        let msg = match std::mem::replace(&mut self.pong_state, PongState::NeedFlush)
                        {
                            PongState::NeedSend(msg) => msg,
                            _ => unreachable!("pong_state is NeedSend in this arm"),
                        };
                        if let Err(e) = self.ws_stream.start_send_unpin(msg) {
                            return Poll::Ready(Err(map_ws_error(e)));
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(map_ws_error(e))),
                    Poll::Pending => return Poll::Pending,
                },
                PongState::NeedFlush => match self.ws_stream.poll_flush_unpin(cx) {
                    Poll::Ready(Ok(())) => {
                        self.pong_state = PongState::Idle;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(map_ws_error(e))),
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }
}

impl<S> AsyncRead for WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let self_mut = self.get_mut();

        loop {
            if !self_mut.read_buffer.is_empty() {
                let len = std::cmp::min(buf.remaining(), self_mut.read_buffer.len());
                buf.put_slice(&self_mut.read_buffer[..len]);
                self_mut.read_buffer.drain(..len);
                return Poll::Ready(Ok(()));
            }

            match self_mut.drive_pending_pong(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

            if self_mut.closing {
                return Pin::new(&mut self_mut.ws_stream).poll_close(cx).map_err(map_ws_error);
            }

            match self_mut.ws_stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(message))) => match message {
                    Message::Binary(data) => {
                        self_mut.read_buffer.extend_from_slice(&data);
                        let len = std::cmp::min(buf.remaining(), self_mut.read_buffer.len());
                        buf.put_slice(&self_mut.read_buffer[..len]);
                        self_mut.read_buffer.drain(..len);
                        return Poll::Ready(Ok(()));
                    }
                    Message::Ping(data) => {
                        self_mut.pong_state = PongState::NeedSend(Message::Pong(data));
                        continue;
                    }
                    Message::Pong(_) => continue,
                    Message::Close(_) => {
                        self_mut.closing = true;
                        continue;
                    }
                    _ => continue,
                },
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(map_ws_error(e))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let self_mut = self.get_mut();
        match self_mut.drive_pending_pong(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        match self_mut.ws_stream.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(
                self_mut
                    .ws_stream
                    .start_send_unpin(Message::Binary(data.to_vec().into()))
                    .map(|_| data.len())
                    .map_err(map_ws_error),
            ),
            Poll::Ready(Err(e)) => Poll::Ready(Err(map_ws_error(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let self_mut = self.get_mut();
        match self_mut.drive_pending_pong(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        self_mut.ws_stream.poll_flush_unpin(cx).map_err(map_ws_error)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().ws_stream).poll_close(cx).map_err(map_ws_error)
    }
}

fn map_ws_error(e: tungstenite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, format!("Tungstenite error: {}", e))
}
