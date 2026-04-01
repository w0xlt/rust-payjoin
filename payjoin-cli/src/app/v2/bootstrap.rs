use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{anyhow, Context as _, Result};
use futures_util::{Sink, SinkExt, StreamExt};
use payjoin::OhttpKeys;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{client_async, WebSocketStream};
use url::Url;

use crate::app::config::Config;
use crate::app::isolated_socks_proxy_url;

pub(super) async fn fetch_ohttp_keys_via_relay_tunnel(
    config: &Config,
    relay: &Url,
    directory: &Url,
) -> Result<OhttpKeys> {
    if relay.scheme() != "http" {
        return Err(anyhow!(
            "BIP77 SOCKS relay bootstrap currently requires an http:// relay URL"
        ));
    }

    let ws_url = relay_websocket_url(relay, directory)?;
    let stream = connect_relay_stream(config.v2()?.socks_proxy.as_ref(), relay).await?;
    let (ws_stream, _) = client_async(ws_url.as_str(), stream).await?;

    let mut tunnel = WsIo::new(ws_stream);

    #[cfg(feature = "_manual-tls")]
    if directory.scheme() == "https" {
        return fetch_ohttp_keys_over_tls_tunnel(config, directory, tunnel).await;
    }

    if directory.scheme() != "http" {
        return Err(anyhow!(
            "BIP77 SOCKS relay bootstrap only supports http:// directories without _manual-tls"
        ));
    }

    fetch_ohttp_keys_from_http_stream(directory, &mut tunnel).await
}

fn relay_websocket_url(relay: &Url, directory: &Url) -> Result<Url> {
    let mut ws_url = relay.clone();
    match ws_url.scheme() {
        "http" => ws_url
            .set_scheme("ws")
            .expect("replacing http scheme with ws should succeed"),
        "https" => ws_url
            .set_scheme("wss")
            .expect("replacing https scheme with wss should succeed"),
        _ => return Err(anyhow!("unsupported relay URL scheme: {}", ws_url.scheme())),
    }

    ws_url.set_path(directory.join("/")?.as_str());
    ws_url.set_query(None);
    ws_url.set_fragment(None);
    Ok(ws_url)
}

async fn connect_relay_stream(socks_proxy: Option<&Url>, relay: &Url) -> Result<TcpStream> {
    let relay_host = relay.host_str().context("relay URL is missing a host")?;
    let relay_port = relay
        .port_or_known_default()
        .context("relay URL is missing a known port for its scheme")?;

    match socks_proxy {
        Some(socks_proxy) => {
            let socks_proxy = isolated_socks_proxy_url(socks_proxy)?;
            let proxy_host = socks_proxy.host_str().context("SOCKS proxy URL is missing a host")?;
            let proxy_port = socks_proxy
                .port_or_known_default()
                .context("SOCKS proxy URL is missing a known port for its scheme")?;

            let stream = if !socks_proxy.username().is_empty() || socks_proxy.password().is_some() {
                tokio_socks::tcp::Socks5Stream::connect_with_password(
                    (proxy_host, proxy_port),
                    (relay_host, relay_port),
                    socks_proxy.username(),
                    socks_proxy.password().unwrap_or(""),
                )
                .await?
            } else {
                tokio_socks::tcp::Socks5Stream::connect((proxy_host, proxy_port), (relay_host, relay_port))
                    .await?
            };
            Ok(stream.into_inner())
        }
        None => Ok(TcpStream::connect((relay_host, relay_port)).await?),
    }
}

#[cfg(feature = "_manual-tls")]
async fn fetch_ohttp_keys_over_tls_tunnel(
    config: &Config,
    directory: &Url,
    tunnel: WsIo<impl AsyncRead + AsyncWrite + Unpin>,
) -> Result<OhttpKeys> {
    use std::sync::Arc;

    let cert_path = config
        .root_certificate
        .as_ref()
        .context("HTTPS gateway bootstrap via SOCKS requires --root-certificate")?;
    let cert_der = std::fs::read(cert_path)?;
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    root_store.add(tokio_rustls::rustls::pki_types::CertificateDer::from(cert_der))?;
    let client_config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let dns_name = tokio_rustls::rustls::pki_types::ServerName::try_from(
        directory.host_str().context("directory URL is missing a host")?.to_owned(),
    )
    .map_err(|_| anyhow!("directory URL host is not a valid TLS server name"))?;
    let mut tls_stream = connector.connect(dns_name, tunnel).await?;
    fetch_ohttp_keys_from_http_stream(directory, &mut tls_stream).await
}

async fn fetch_ohttp_keys_from_http_stream(
    directory: &Url,
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> Result<OhttpKeys> {
    let host_header = host_header(directory)?;
    let request = format!(
        "GET /.well-known/ohttp-gateway HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/ohttp-keys\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    parse_ohttp_keys_http_response(&response)
}

fn host_header(directory: &Url) -> Result<String> {
    let host = directory.host_str().context("directory URL is missing a host")?;
    let port = directory
        .port_or_known_default()
        .context("directory URL is missing a known port for its scheme")?;
    let default_port = match directory.scheme() {
        "http" => 80,
        "https" => 443,
        _ => return Err(anyhow!("unsupported directory URL scheme: {}", directory.scheme())),
    };
    if port == default_port {
        Ok(host.to_owned())
    } else {
        Ok(format!("{host}:{port}"))
    }
}

fn parse_ohttp_keys_http_response(response: &[u8]) -> Result<OhttpKeys> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
        .context("relay bootstrap response is missing HTTP headers")?;
    let headers = std::str::from_utf8(&response[..header_end])?;
    let mut lines = headers.lines();
    let status_line = lines.next().context("relay bootstrap response is missing a status line")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .context("relay bootstrap response is missing an HTTP status code")?
        .parse::<u16>()?;
    if !(200..300).contains(&status) {
        return Err(anyhow!("unexpected status code from OHTTP gateway bootstrap: {status}"));
    }
    OhttpKeys::decode(&response[header_end..]).map_err(|e| anyhow!(e.to_string()))
}

struct WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ws_stream: WebSocketStream<S>,
    read_buffer: Vec<u8>,
}

impl<S> WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(ws_stream: WebSocketStream<S>) -> Self {
        Self { ws_stream, read_buffer: Vec::new() }
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
        let this = self.get_mut();

        if !this.read_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), this.read_buffer.len());
            buf.put_slice(&this.read_buffer[..len]);
            this.read_buffer.drain(..len);
            return Poll::Ready(Ok(()));
        }

        match this.ws_stream.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(message))) => match message {
                Message::Binary(data) => {
                    this.read_buffer.extend_from_slice(&data);
                    let len = std::cmp::min(buf.remaining(), this.read_buffer.len());
                    buf.put_slice(&this.read_buffer[..len]);
                    this.read_buffer.drain(..len);
                    Poll::Ready(Ok(()))
                }
                Message::Ping(data) => {
                    Poll::Ready(this.ws_stream.start_send_unpin(Message::Pong(data)).map_err(map_ws_error))
                }
                Message::Pong(_) => Poll::Pending,
                Message::Close(_) => Poll::Ready(Ok(())),
                _ => Poll::Pending,
            },
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(map_ws_error(e))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
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
        let this = self.get_mut();
        match Pin::new(&mut this.ws_stream).poll_ready(cx) {
            Poll::Ready(Ok(())) =>
                Poll::Ready(
                    this.ws_stream
                        .start_send_unpin(Message::Binary(data.to_vec().into()))
                        .map(|_| data.len())
                        .map_err(map_ws_error),
                ),
            Poll::Ready(Err(e)) => Poll::Ready(Err(map_ws_error(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().ws_stream).poll_flush(cx).map_err(map_ws_error)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().ws_stream).poll_close(cx).map_err(map_ws_error)
    }
}

fn map_ws_error(e: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, format!("WebSocket error: {e}"))
}

#[cfg(test)]
mod tests {
    use payjoin::bitcoin::bech32::primitives::decode::CheckedHrpstring;
    use payjoin::bitcoin::bech32::NoChecksum;

    use super::{parse_ohttp_keys_http_response, relay_websocket_url};

    #[test]
    fn relay_websocket_url_encodes_gateway_origin_in_path() {
        let relay = url::Url::parse("http://relay.example").expect("static URL is valid");
        let directory = url::Url::parse("http://directory.example").expect("static URL is valid");

        let ws_url = relay_websocket_url(&relay, &directory).expect("websocket URL should build");
        assert_eq!(ws_url.as_str(), "ws://relay.example/http://directory.example/");
    }

    #[test]
    fn parse_ohttp_keys_http_response_accepts_successful_gateway_response() {
        let bytes = CheckedHrpstring::new::<NoChecksum>(
            "OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC",
        )
        .expect("bech32 test vector should decode")
        .byte_iter()
        .collect::<Vec<u8>>();
        let body = payjoin::OhttpKeys::try_from(&bytes[..])
            .expect("test vector should convert to OHTTP keys")
            .encode()
            .expect("test OHTTP keys should re-encode");
        let headers = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/ohttp-keys\r\ncontent-length: {}\r\n\r\n",
            body.len()
        );
        let mut response = headers.into_bytes();
        response.extend_from_slice(&body);

        let decoded = parse_ohttp_keys_http_response(&response)
            .expect("bootstrap parser should accept a valid response");
        assert_eq!(
            decoded.encode().expect("keys should re-encode").len(),
            body.len(),
            "decoded OHTTP keys should match the expected encoded size"
        );
    }
}
