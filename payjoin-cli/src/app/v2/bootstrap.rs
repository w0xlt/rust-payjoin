use std::borrow::Cow;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use futures_util::{Sink, SinkExt, StreamExt};
use payjoin::OhttpKeys;
use percent_encoding::percent_decode;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{client_async, WebSocketStream};
use url::Url;

use crate::app::config::Config;
use crate::app::v2_socks_proxy_url;
use crate::db::v2::SocksAuth;

const OHTTP_KEYS_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BOOTSTRAP_RESPONSE_HEADER_SIZE: usize = 16 * 1024;
const MAX_BOOTSTRAP_RESPONSE_BODY_SIZE: usize = 64 * 1024;

pub(super) async fn fetch_ohttp_keys_via_relay_tunnel(
    config: &Config,
    relay: &impl AsRef<str>,
    directory: &impl AsRef<str>,
    session_socks_auth: Option<&SocksAuth>,
) -> Result<OhttpKeys> {
    let relay = Url::parse(relay.as_ref()).context("relay URL should parse for SOCKS bootstrap")?;
    let directory =
        Url::parse(directory.as_ref()).context("directory URL should parse for SOCKS bootstrap")?;
    fetch_ohttp_keys_via_relay_tunnel_with_timeout(
        config,
        &relay,
        &directory,
        session_socks_auth,
        OHTTP_KEYS_FETCH_TIMEOUT,
    )
    .await
}

async fn fetch_ohttp_keys_via_relay_tunnel_with_timeout(
    config: &Config,
    relay: &Url,
    directory: &Url,
    session_socks_auth: Option<&SocksAuth>,
    timeout: Duration,
) -> Result<OhttpKeys> {
    tokio::time::timeout(timeout, async {
        if relay.scheme() != "http" {
            return Err(anyhow!(
                "BIP77 SOCKS relay bootstrap currently requires an http:// relay URL"
            ));
        }

        let ws_url = relay_websocket_url(relay, directory)?;
        let stream = connect_relay_stream(config, relay, session_socks_auth).await?;
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
    })
    .await
    .map_err(|_| anyhow!("timed out fetching OHTTP keys over relay tunnel"))?
}

/// Build a WebSocket URL that encodes the directory origin in the path.
///
/// The resulting URL looks like `ws://relay.example/http://directory.example/`.
/// The relay's `parse_gateway_uri_from_path` strips the leading `/` and parses
/// the remainder as a full URL to recover the gateway origin.
fn relay_websocket_url(relay: &Url, directory: &Url) -> Result<Url> {
    let mut ws_url = relay.clone();
    match ws_url.scheme() {
        "http" => ws_url.set_scheme("ws").expect("replacing http scheme with ws should succeed"),
        "https" =>
            ws_url.set_scheme("wss").expect("replacing https scheme with wss should succeed"),
        _ => return Err(anyhow!("unsupported relay URL scheme: {}", ws_url.scheme())),
    }

    ws_url.set_path(directory.join("/")?.as_str());
    ws_url.set_query(None);
    ws_url.set_fragment(None);
    Ok(ws_url)
}

async fn connect_relay_stream(
    config: &Config,
    relay: &Url,
    session_socks_auth: Option<&SocksAuth>,
) -> Result<TcpStream> {
    let relay_host = url_host_for_socket(relay, "relay URL is missing a host")?;
    let relay_port = relay
        .port_or_known_default()
        .context("relay URL is missing a known port for its scheme")?;

    match v2_socks_proxy_url(config, session_socks_auth)? {
        Some(socks_proxy) => {
            let proxy_host =
                url_host_for_socket(&socks_proxy, "SOCKS proxy URL is missing a host")?;
            let proxy_port = socks_proxy
                .port_or_known_default()
                .context("SOCKS proxy URL is missing a known port for its scheme")?;

            let stream = if let Some((username, password)) = socks_url_auth(&socks_proxy) {
                tokio_socks::tcp::Socks5Stream::connect_with_password(
                    (proxy_host.as_ref(), proxy_port),
                    (relay_host.as_ref(), relay_port),
                    username.as_ref(),
                    password.as_ref(),
                )
                .await?
            } else {
                tokio_socks::tcp::Socks5Stream::connect(
                    (proxy_host.as_ref(), proxy_port),
                    (relay_host.as_ref(), relay_port),
                )
                .await?
            };
            Ok(stream.into_inner())
        }
        None => Ok(TcpStream::connect((relay_host.as_ref(), relay_port)).await?),
    }
}

fn url_host_for_socket<'a>(
    url: &'a Url,
    missing_host_context: &'static str,
) -> Result<Cow<'a, str>> {
    match url.host().context(missing_host_context)? {
        url::Host::Domain(host) => Ok(Cow::Borrowed(host)),
        url::Host::Ipv4(addr) => Ok(Cow::Owned(addr.to_string())),
        url::Host::Ipv6(addr) => Ok(Cow::Owned(addr.to_string())),
    }
}

fn socks_url_auth(url: &Url) -> Option<(Cow<'_, str>, Cow<'_, str>)> {
    if url.username().is_empty() && url.password().is_none() {
        return None;
    }

    Some((
        decode_socks_url_credential(url.username()),
        decode_socks_url_credential(url.password().unwrap_or("")),
    ))
}

fn decode_socks_url_credential(credential: &str) -> Cow<'_, str> {
    percent_decode(credential.as_bytes()).decode_utf8_lossy()
}

#[cfg(feature = "_manual-tls")]
async fn fetch_ohttp_keys_over_tls_tunnel(
    config: &Config,
    directory: &Url,
    tunnel: WsIo<impl AsyncRead + AsyncWrite + Unpin>,
) -> Result<OhttpKeys> {
    use std::sync::Arc;

    let root_store = bootstrap_root_store(config)?;
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

#[cfg(feature = "_manual-tls")]
fn bootstrap_root_store(config: &Config) -> Result<tokio_rustls::rustls::RootCertStore> {
    finalize_bootstrap_root_store(config, default_bootstrap_root_store()?)
}

#[cfg(feature = "_manual-tls")]
fn finalize_bootstrap_root_store(
    config: &Config,
    mut root_store: tokio_rustls::rustls::RootCertStore,
) -> Result<tokio_rustls::rustls::RootCertStore> {
    if let Some(cert_path) = config.root_certificate.as_ref() {
        let cert_der = std::fs::read(cert_path)?;
        root_store.add(tokio_rustls::rustls::pki_types::CertificateDer::from(cert_der))?;
    }

    if root_store.is_empty() {
        return Err(anyhow!(
            "no root certificates available for SOCKS bootstrap; provide --root-certificate or make native roots available"
        ));
    }

    Ok(root_store)
}

#[cfg(all(feature = "_manual-tls", feature = "native-certs"))]
fn default_bootstrap_root_store() -> Result<tokio_rustls::rustls::RootCertStore> {
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs();
    if !certs.errors.is_empty() {
        tracing::warn!(
            "Failed to load some native root certificates for SOCKS bootstrap: {} errors",
            certs.errors.len()
        );
    }
    if certs.certs.is_empty() {
        tracing::warn!("No native root certificates available for SOCKS bootstrap");
    }
    for cert in certs.certs {
        root_store.add(cert)?;
    }
    Ok(root_store)
}

#[cfg(all(feature = "_manual-tls", not(feature = "native-certs")))]
fn default_bootstrap_root_store() -> Result<tokio_rustls::rustls::RootCertStore> {
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(root_store)
}

async fn fetch_ohttp_keys_from_http_stream(
    directory: &Url,
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> Result<OhttpKeys> {
    fetch_ohttp_keys_from_http_stream_with_timeout(directory, stream, OHTTP_KEYS_FETCH_TIMEOUT)
        .await
}

async fn fetch_ohttp_keys_from_http_stream_with_timeout(
    directory: &Url,
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    timeout: Duration,
) -> Result<OhttpKeys> {
    // Mirror the 10-second request timeout used by payjoin::io::fetch_ohttp_keys.
    tokio::time::timeout(timeout, async {
        let host_header = host_header(directory)?;
        let request = format!(
            "GET /.well-known/ohttp-gateway HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/ohttp-keys\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let response = read_bootstrap_http_response(stream).await?;
        let _ = stream.shutdown().await;
        parse_ohttp_keys_http_response(&response)
    })
    .await
    .map_err(|_| anyhow!("timed out fetching OHTTP keys over relay tunnel"))?
}

async fn read_bootstrap_http_response(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut framing = None;

    loop {
        if framing.is_none() {
            if let Some(header_end) = find_header_end(&response) {
                ensure_bootstrap_header_size(header_end)?;
                let head = parse_http_response_head(&response)?;
                framing = Some((header_end, response_body_framing(&head.headers)?));
            } else {
                ensure_bootstrap_header_size(response.len())?;
            }
        }

        if let Some((header_end, framing)) = &framing {
            let body = &response[*header_end..];
            ensure_bootstrap_body_size(body.len())?;
            if http_response_complete(body, framing)? {
                return Ok(response);
            }
        }

        let mut buf = [0_u8; 1024];
        let bytes_read = stream.read(&mut buf).await?;
        if bytes_read == 0 {
            return if response.is_empty() {
                Err(anyhow!("relay bootstrap response ended before HTTP headers completed"))
            } else {
                Ok(response)
            };
        }
        response.extend_from_slice(&buf[..bytes_read]);
    }
}

fn ensure_bootstrap_header_size(header_len: usize) -> Result<()> {
    if header_len > MAX_BOOTSTRAP_RESPONSE_HEADER_SIZE {
        return Err(anyhow!(
            "relay bootstrap response headers exceeded {MAX_BOOTSTRAP_RESPONSE_HEADER_SIZE} bytes"
        ));
    }
    Ok(())
}

fn ensure_bootstrap_body_size(body_len: usize) -> Result<()> {
    if body_len > MAX_BOOTSTRAP_RESPONSE_BODY_SIZE {
        return Err(anyhow!(
            "relay bootstrap response body exceeded {MAX_BOOTSTRAP_RESPONSE_BODY_SIZE} bytes"
        ));
    }
    Ok(())
}

fn host_header(directory: &Url) -> Result<String> {
    let host = match directory.host().context("directory URL is missing a host")? {
        url::Host::Domain(domain) => domain.to_owned(),
        url::Host::Ipv4(addr) => addr.to_string(),
        url::Host::Ipv6(addr) => format!("[{addr}]"),
    };
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
    let head = parse_http_response_head(response)?;
    if !(200..300).contains(&head.status) {
        let status = reqwest::StatusCode::from_u16(head.status)?;
        return Err(payjoin::io::Error::UnexpectedStatusCode(status).into());
    }
    let body = decode_http_response_body(&head.headers, &response[head.header_end..])?;
    OhttpKeys::decode(&body).map_err(|e| anyhow!(e.to_string()))
}

#[derive(Debug, Clone, Copy)]
enum HttpBodyFraming {
    Chunked,
    ContentLength(usize),
    UntilEof,
}

#[derive(Debug)]
struct HttpResponseHead {
    header_end: usize,
    status: u16,
    headers: Vec<(String, String)>,
}

fn parse_http_response_head(response: &[u8]) -> Result<HttpResponseHead> {
    let header_end =
        find_header_end(response).context("relay bootstrap response is missing HTTP headers")?;
    let headers = std::str::from_utf8(&response[..header_end])?;
    let mut lines = headers.lines();
    let status_line = lines.next().context("relay bootstrap response is missing a status line")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .context("relay bootstrap response is missing an HTTP status code")?
        .parse::<u16>()?;
    let headers = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect::<Vec<_>>();
    Ok(HttpResponseHead { header_end, status, headers })
}

fn find_header_end(response: &[u8]) -> Option<usize> {
    response.windows(4).position(|window| window == b"\r\n\r\n").map(|idx| idx + 4)
}

fn decode_http_response_body(headers: &[(String, String)], body: &[u8]) -> Result<Vec<u8>> {
    match response_body_framing(headers)? {
        HttpBodyFraming::Chunked => decode_chunked_http_body(body),
        HttpBodyFraming::ContentLength(length) => {
            if body.len() < length {
                return Err(anyhow!(
                    "relay bootstrap response body ended before the declared Content-Length"
                ));
            }
            Ok(body[..length].to_vec())
        }
        HttpBodyFraming::UntilEof => Ok(body.to_vec()),
    }
}

fn response_body_framing(headers: &[(String, String)]) -> Result<HttpBodyFraming> {
    if headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value.split(',').any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
    }) {
        return Ok(HttpBodyFraming::Chunked);
    }

    if let Some((_, value)) =
        headers.iter().find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        let length = value
            .parse::<usize>()
            .context("relay bootstrap response has an invalid Content-Length header")?;
        ensure_bootstrap_body_size(length)?;
        return Ok(HttpBodyFraming::ContentLength(length));
    }

    Ok(HttpBodyFraming::UntilEof)
}

fn http_response_complete(body: &[u8], framing: &HttpBodyFraming) -> Result<bool> {
    match framing {
        HttpBodyFraming::Chunked => Ok(chunked_body_end(body)?.is_some()),
        HttpBodyFraming::ContentLength(length) => Ok(body.len() >= *length),
        HttpBodyFraming::UntilEof => Ok(false),
    }
}

fn decode_chunked_http_body(mut body: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();

    loop {
        let size_line = std::str::from_utf8(read_crlf_line(&mut body)?)?;
        let size = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size, 16)
            .context("chunked response contains an invalid chunk size")?;

        if size == 0 {
            loop {
                if read_crlf_line(&mut body)?.is_empty() {
                    return Ok(decoded);
                }
            }
        }

        let decoded_len =
            decoded.len().checked_add(size).context("chunked response body is too large")?;
        ensure_bootstrap_body_size(decoded_len)?;
        let chunk_end = size.checked_add(2).context("chunked response chunk is too large")?;
        if body.len() < chunk_end {
            return Err(anyhow!("chunked response ended before the chunk payload completed"));
        }
        decoded.extend_from_slice(&body[..size]);
        if &body[size..chunk_end] != b"\r\n" {
            return Err(anyhow!("chunked response chunk is missing a trailing CRLF"));
        }
        body = &body[chunk_end..];
    }
}

fn chunked_body_end(body: &[u8]) -> Result<Option<usize>> {
    let mut offset = 0;

    loop {
        let Some(size_line_end) = find_crlf(&body[offset..]) else {
            return Ok(None);
        };
        let size_line = std::str::from_utf8(&body[offset..offset + size_line_end])?;
        let size = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size, 16)
            .context("chunked response contains an invalid chunk size")?;
        offset += size_line_end + 2;

        if size == 0 {
            loop {
                let Some(trailer_end) = find_crlf(&body[offset..]) else {
                    return Ok(None);
                };
                offset += trailer_end + 2;
                if trailer_end == 0 {
                    return Ok(Some(offset));
                }
            }
        }

        let chunk_payload_end =
            offset.checked_add(size).context("chunked response chunk is too large")?;
        let chunk_end =
            chunk_payload_end.checked_add(2).context("chunked response chunk is too large")?;
        if body.len() < chunk_end {
            return Ok(None);
        }
        if &body[chunk_payload_end..chunk_end] != b"\r\n" {
            return Err(anyhow!("chunked response chunk is missing a trailing CRLF"));
        }
        offset = chunk_end;
    }
}

fn read_crlf_line<'a>(body: &mut &'a [u8]) -> Result<&'a [u8]> {
    let line_end = find_crlf(body).context("chunked response is missing a CRLF terminator")?;
    let line = &body[..line_end];
    *body = &body[line_end + 2..];
    Ok(line)
}

fn find_crlf(body: &[u8]) -> Option<usize> { body.windows(2).position(|window| window == b"\r\n") }

// NOTE: this type mirrors payjoin-mailroom/src/ohttp_relay/bootstrap/ws.rs `WsIo`.
// If you change the implementation here, update the other copy too.
struct WsIo<S>
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
    fn new(ws_stream: WebSocketStream<S>) -> Self {
        Self {
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
        let this = self.get_mut();

        loop {
            if !this.read_buffer.is_empty() {
                let len = std::cmp::min(buf.remaining(), this.read_buffer.len());
                buf.put_slice(&this.read_buffer[..len]);
                this.read_buffer.drain(..len);
                return Poll::Ready(Ok(()));
            }

            match this.drive_pending_pong(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

            if this.closing {
                return Pin::new(&mut this.ws_stream).poll_close(cx).map_err(map_ws_error);
            }

            match this.ws_stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(message))) => match message {
                    Message::Binary(data) => {
                        this.read_buffer.extend_from_slice(&data);
                        let len = std::cmp::min(buf.remaining(), this.read_buffer.len());
                        buf.put_slice(&this.read_buffer[..len]);
                        this.read_buffer.drain(..len);
                        return Poll::Ready(Ok(()));
                    }
                    Message::Ping(data) => {
                        this.pong_state = PongState::NeedSend(Message::Pong(data));
                        continue;
                    }
                    Message::Pong(_) => continue,
                    Message::Close(_) => {
                        this.closing = true;
                        continue;
                    }
                    _ => continue,
                },
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(map_ws_error(e))),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
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
        let this = self.get_mut();
        match this.drive_pending_pong(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        match this.ws_stream.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(
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
        let this = self.get_mut();
        match this.drive_pending_pong(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        this.ws_stream.poll_flush_unpin(cx).map_err(map_ws_error)
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
    use std::path::PathBuf;
    use std::time::Duration;

    use futures_util::{SinkExt, StreamExt};
    use payjoin::bitcoin::bech32::primitives::decode::CheckedHrpstring;
    use payjoin::bitcoin::bech32::NoChecksum;
    use payjoin::Url as PayjoinUrl;
    #[cfg(feature = "_manual-tls")]
    use payjoin_test_utils::local_cert_key;
    use payjoin_test_utils::TestServices;
    #[cfg(feature = "_manual-tls")]
    use tempfile::tempdir;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    #[cfg(feature = "_manual-tls")]
    use tokio_tungstenite::accept_async;
    use tokio_tungstenite::tungstenite::protocol::{Message, Role};
    use tokio_tungstenite::WebSocketStream;
    use url::Url;

    #[cfg(feature = "_manual-tls")]
    use super::finalize_bootstrap_root_store;
    use super::{
        fetch_ohttp_keys_from_http_stream_with_timeout, fetch_ohttp_keys_via_relay_tunnel,
        fetch_ohttp_keys_via_relay_tunnel_with_timeout, host_header,
        parse_ohttp_keys_http_response, read_bootstrap_http_response, relay_websocket_url,
        socks_url_auth, url_host_for_socket, WsIo, MAX_BOOTSTRAP_RESPONSE_BODY_SIZE,
        MAX_BOOTSTRAP_RESPONSE_HEADER_SIZE,
    };
    use crate::app::config::{BitcoindConfig, Config, V2Config, VersionConfig};
    fn encoded_ohttp_keys_body() -> Vec<u8> {
        let bytes = CheckedHrpstring::new::<NoChecksum>(
            "OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC",
        )
        .expect("bech32 test vector should decode")
        .byte_iter()
        .collect::<Vec<u8>>();
        payjoin::OhttpKeys::try_from(&bytes[..])
            .expect("test vector should convert to OHTTP keys")
            .encode()
            .expect("test OHTTP keys should re-encode")
    }

    #[test]
    fn relay_websocket_url_encodes_gateway_origin_in_path() {
        let relay = url::Url::parse("http://relay.example").expect("static URL is valid");
        let directory = url::Url::parse("http://directory.example").expect("static URL is valid");

        let ws_url = relay_websocket_url(&relay, &directory).expect("websocket URL should build");
        assert_eq!(ws_url.as_str(), "ws://relay.example/http://directory.example/");
    }

    #[test]
    fn socks_url_auth_decodes_percent_encoded_credentials() {
        let proxy = Url::parse("socks5h://us%40er:p%40ss+word%3Aok@127.0.0.1:9050")
            .expect("static URL is valid");

        let (username, password) = socks_url_auth(&proxy).expect("SOCKS auth should be present");

        assert_eq!(username.as_ref(), "us@er");
        assert_eq!(password.as_ref(), "p@ss+word:ok");
    }

    #[test]
    fn url_host_for_socket_strips_ipv6_uri_brackets() {
        let relay = Url::parse("http://[::1]:8080").expect("static URL is valid");
        let proxy = Url::parse("socks5h://[::1]:9050").expect("static URL is valid");

        assert_eq!(
            url_host_for_socket(&relay, "missing host").expect("relay host should normalize"),
            "::1"
        );
        assert_eq!(
            url_host_for_socket(&proxy, "missing host").expect("proxy host should normalize"),
            "::1"
        );
    }

    #[test]
    fn url_host_for_socket_preserves_non_ipv6_hosts() {
        let domain = Url::parse("http://relay.example:8080").expect("static URL is valid");
        let ipv4 = Url::parse("socks5h://127.0.0.1:9050").expect("static URL is valid");

        assert_eq!(
            url_host_for_socket(&domain, "missing host").expect("domain host should normalize"),
            "relay.example"
        );
        assert_eq!(
            url_host_for_socket(&ipv4, "missing host").expect("IPv4 host should normalize"),
            "127.0.0.1"
        );
    }

    #[test]
    fn host_header_brackets_ipv6_default_port() {
        let directory = Url::parse("http://[::1]").expect("static URL is valid");

        let host = host_header(&directory).expect("IPv6 host header should build");

        assert_eq!(host, "[::1]");
    }

    #[test]
    fn host_header_brackets_ipv6_with_non_default_port() {
        let directory = Url::parse("http://[::1]:8080").expect("static URL is valid");

        let host = host_header(&directory).expect("IPv6 host header should build");

        assert_eq!(host, "[::1]:8080");
    }

    #[test]
    fn parse_ohttp_keys_http_response_accepts_successful_gateway_response() {
        let body = encoded_ohttp_keys_body();
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

    #[test]
    fn parse_ohttp_keys_http_response_preserves_unexpected_status_code() {
        let response = b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n".to_vec();

        let err = parse_ohttp_keys_http_response(&response)
            .expect_err("non-2xx bootstrap replies should surface the HTTP status");
        assert!(matches!(
            err.downcast_ref::<payjoin::io::Error>(),
            Some(payjoin::io::Error::UnexpectedStatusCode(code))
                if *code == reqwest::StatusCode::SERVICE_UNAVAILABLE
        ));
    }

    #[test]
    fn parse_ohttp_keys_http_response_accepts_chunked_gateway_response() {
        let body = encoded_ohttp_keys_body();
        let split = body.len() / 2;
        let headers = "HTTP/1.1 200 OK\r\ncontent-type: application/ohttp-keys\r\ntransfer-encoding: chunked\r\n\r\n";
        let mut response = headers.as_bytes().to_vec();
        response.extend_from_slice(format!("{split:x}\r\n").as_bytes());
        response.extend_from_slice(&body[..split]);
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(format!("{:x}\r\n", body.len() - split).as_bytes());
        response.extend_from_slice(&body[split..]);
        response.extend_from_slice(b"\r\n0\r\nx-extra: trailer\r\n\r\n");

        let decoded = parse_ohttp_keys_http_response(&response)
            .expect("bootstrap parser should accept a valid chunked response");
        assert_eq!(
            decoded.encode().expect("keys should re-encode"),
            body,
            "decoded OHTTP keys should match the original chunked payload"
        );
    }

    #[tokio::test]
    async fn ws_io_ignores_ping_frames_without_signaling_eof() {
        let expected_response = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".to_vec();
        let (client_stream, server_stream) = duplex(4096);
        let expected_response_for_server = expected_response.clone();

        let client_task = tokio::spawn(async move {
            let client_ws =
                WebSocketStream::from_raw_socket(client_stream, Role::Client, None).await;
            let mut tunnel = WsIo::new(client_ws);
            let mut response = Vec::new();
            tunnel
                .read_to_end(&mut response)
                .await
                .expect("client tunnel should read the full HTTP response");
            response
        });

        let server_task = tokio::spawn(async move {
            let mut server_ws =
                WebSocketStream::from_raw_socket(server_stream, Role::Server, None).await;
            server_ws
                .send(Message::Ping(b"keepalive".to_vec().into()))
                .await
                .expect("server should send a ping frame");
            server_ws
                .send(Message::Binary(expected_response_for_server.into()))
                .await
                .expect("server should send the HTTP response payload");
            server_ws
                .send(Message::Close(None))
                .await
                .expect("server should initiate the websocket close handshake");
            server_ws
                .next()
                .await
                .expect("client should send a close frame in response")
                .expect("close handshake should not fail");
        });

        let response = client_task.await.expect("client task should complete");
        server_task.await.expect("server task should complete");
        assert_eq!(
            response, expected_response,
            "control frames should not terminate the tunneled HTTP response"
        );
    }

    #[tokio::test]
    async fn ws_io_replies_with_pong_when_only_reading() {
        let (client_stream, server_stream) = duplex(4096);
        let payload = b"keepalive".to_vec();
        let payload_for_server = payload.clone();

        let client_task = tokio::spawn(async move {
            let client_ws =
                WebSocketStream::from_raw_socket(client_stream, Role::Client, None).await;
            let mut tunnel = WsIo::new(client_ws);
            // Drive `poll_read` once. With only a Ping pending on the wire, this returns
            // `Pending` (no binary data), but it must still flush a Pong reply before yielding.
            let mut buf = [0u8; 16];
            let _ = tokio::time::timeout(Duration::from_millis(50), tunnel.read(&mut buf)).await;
            // Continue polling the tunnel so the Pong actually goes out, then complete the
            // close handshake initiated by the server.
            let mut sink = Vec::new();
            tunnel
                .read_to_end(&mut sink)
                .await
                .expect("client tunnel should read until close");
        });

        let server_task = tokio::spawn(async move {
            let mut server_ws =
                WebSocketStream::from_raw_socket(server_stream, Role::Server, None).await;
            server_ws
                .send(Message::Ping(payload_for_server.into()))
                .await
                .expect("server should send a ping frame");
            // The client must reply with a matching Pong without any binary write activity.
            let pong = tokio::time::timeout(Duration::from_secs(1), server_ws.next())
                .await
                .expect("client should reply to ping promptly")
                .expect("server should receive a frame")
                .expect("pong frame should not error");
            server_ws.send(Message::Close(None)).await.expect("server should send close");
            server_ws.next().await; // drain client's close reply
            pong
        });

        let pong = server_task.await.expect("server task should complete");
        client_task.await.expect("client task should complete");
        match pong {
            Message::Pong(data) => assert_eq!(
                data.as_ref(),
                b"keepalive",
                "pong payload should mirror the ping payload"
            ),
            other => panic!("expected Pong frame in response to Ping, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ws_io_completes_close_handshake_before_signaling_eof() {
        let expected_response = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".to_vec();
        let (client_stream, server_stream) = duplex(4096);
        let expected_response_for_server = expected_response.clone();

        let client_task = tokio::spawn(async move {
            let client_ws =
                WebSocketStream::from_raw_socket(client_stream, Role::Client, None).await;
            let mut tunnel = WsIo::new(client_ws);
            let mut response = Vec::new();
            tunnel
                .read_to_end(&mut response)
                .await
                .expect("client tunnel should read the full HTTP response");
            response
        });

        let server_task = tokio::spawn(async move {
            let mut server_ws =
                WebSocketStream::from_raw_socket(server_stream, Role::Server, None).await;
            server_ws
                .send(Message::Binary(expected_response_for_server.into()))
                .await
                .expect("server should send the HTTP response payload");
            server_ws
                .send(Message::Close(None))
                .await
                .expect("server should initiate the websocket close handshake");
            server_ws
                .next()
                .await
                .expect("client should send a close frame in response")
                .expect("close handshake should not fail")
        });

        let response = client_task.await.expect("client task should complete");
        let close_message = server_task.await.expect("server task should complete");
        assert_eq!(
            response, expected_response,
            "the tunneled HTTP response should still be delivered before EOF"
        );
        assert!(
            matches!(close_message, Message::Close(_)),
            "client should complete the websocket close handshake"
        );
    }

    #[tokio::test]
    async fn fetch_ohttp_keys_from_http_stream_times_out_when_gateway_stalls() {
        let directory = Url::parse("http://directory.example").expect("static URL is valid");
        let (mut client, mut gateway) = duplex(4096);

        let gateway_task = tokio::spawn(async move {
            let mut request = Vec::new();
            loop {
                let mut buf = [0u8; 1024];
                let bytes_read = gateway
                    .read(&mut buf)
                    .await
                    .expect("stalled gateway should read the bootstrap request");
                assert!(bytes_read > 0, "bootstrap request should not terminate before headers");
                request.extend_from_slice(&buf[..bytes_read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            std::future::pending::<()>().await;
        });

        let err = fetch_ohttp_keys_from_http_stream_with_timeout(
            &directory,
            &mut client,
            Duration::from_millis(100),
        )
        .await
        .expect_err("stalled gateway should time out");
        assert!(
            err.to_string().contains("timed out fetching OHTTP keys over relay tunnel"),
            "timeout error should explain the relay tunnel stall"
        );

        gateway_task.abort();
        let _ = gateway_task.await;
    }

    #[tokio::test]
    async fn read_bootstrap_http_response_rejects_oversized_headers() {
        let (mut client, mut gateway) = duplex(MAX_BOOTSTRAP_RESPONSE_HEADER_SIZE + 4096);

        let gateway_task = tokio::spawn(async move {
            gateway
                .write_all(b"HTTP/1.1 200 OK\r\n")
                .await
                .expect("gateway should write the partial response head");
            gateway
                .write_all(&vec![b'a'; MAX_BOOTSTRAP_RESPONSE_HEADER_SIZE])
                .await
                .expect("gateway should write oversized response headers");
            std::future::pending::<()>().await;
        });

        let err = read_bootstrap_http_response(&mut client)
            .await
            .expect_err("oversized headers should be rejected before timeout");
        assert!(
            err.to_string().contains("headers exceeded"),
            "error should explain the header size limit"
        );

        gateway_task.abort();
        let _ = gateway_task.await;
    }

    #[tokio::test]
    async fn read_bootstrap_http_response_rejects_oversized_content_length() {
        let (mut client, mut gateway) = duplex(4096);

        let gateway_task = tokio::spawn(async move {
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n",
                MAX_BOOTSTRAP_RESPONSE_BODY_SIZE + 1
            );
            gateway
                .write_all(response.as_bytes())
                .await
                .expect("gateway should write response headers");
            std::future::pending::<()>().await;
        });

        let err = read_bootstrap_http_response(&mut client)
            .await
            .expect_err("oversized Content-Length should be rejected before reading the body");
        assert!(
            err.to_string().contains("body exceeded"),
            "error should explain the body size limit"
        );

        gateway_task.abort();
        let _ = gateway_task.await;
    }

    #[tokio::test]
    async fn read_bootstrap_http_response_rejects_oversized_until_eof_body() {
        let (mut client, mut gateway) = duplex(MAX_BOOTSTRAP_RESPONSE_BODY_SIZE + 4096);

        let gateway_task = tokio::spawn(async move {
            gateway
                .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
                .await
                .expect("gateway should write response headers");
            gateway
                .write_all(&vec![0; MAX_BOOTSTRAP_RESPONSE_BODY_SIZE + 1])
                .await
                .expect("gateway should write oversized response body");
            std::future::pending::<()>().await;
        });

        let err = read_bootstrap_http_response(&mut client)
            .await
            .expect_err("oversized EOF-delimited body should be rejected before timeout");
        assert!(
            err.to_string().contains("body exceeded"),
            "error should explain the body size limit"
        );

        gateway_task.abort();
        let _ = gateway_task.await;
    }

    #[tokio::test]
    async fn read_bootstrap_http_response_rejects_oversized_chunked_body() {
        let (mut client, mut gateway) = duplex(MAX_BOOTSTRAP_RESPONSE_BODY_SIZE + 4096);

        let gateway_task = tokio::spawn(async move {
            gateway
                .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                .await
                .expect("gateway should write response headers");
            gateway
                .write_all(format!("{:x}\r\n", MAX_BOOTSTRAP_RESPONSE_BODY_SIZE + 1).as_bytes())
                .await
                .expect("gateway should write chunk size");
            gateway
                .write_all(&vec![b'a'; MAX_BOOTSTRAP_RESPONSE_BODY_SIZE + 1])
                .await
                .expect("gateway should write oversized chunk payload");
            std::future::pending::<()>().await;
        });

        let err = read_bootstrap_http_response(&mut client)
            .await
            .expect_err("oversized chunked body should be rejected before timeout");
        assert!(
            err.to_string().contains("body exceeded"),
            "error should explain the body size limit"
        );

        gateway_task.abort();
        let _ = gateway_task.await;
    }

    #[tokio::test]
    async fn fetch_ohttp_keys_from_http_stream_does_not_wait_for_eof_after_content_length() {
        let directory = Url::parse("http://directory.example").expect("static URL is valid");
        let (mut client, mut gateway) = duplex(4096);
        let expected_body = encoded_ohttp_keys_body();
        let expected_body_for_gateway = expected_body.clone();

        let gateway_task = tokio::spawn(async move {
            let mut request = Vec::new();
            loop {
                let mut buf = [0u8; 1024];
                let bytes_read = gateway
                    .read(&mut buf)
                    .await
                    .expect("gateway should read the bootstrap request");
                assert!(bytes_read > 0, "bootstrap request should not terminate before headers");
                request.extend_from_slice(&buf[..bytes_read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            let headers = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/ohttp-keys\r\ncontent-length: {}\r\n\r\n",
                expected_body_for_gateway.len()
            );
            gateway
                .write_all(headers.as_bytes())
                .await
                .expect("gateway should write the response headers");
            gateway
                .write_all(&expected_body_for_gateway)
                .await
                .expect("gateway should write the response body");
            gateway.flush().await.expect("gateway should flush the response");

            std::future::pending::<()>().await;
        });

        let fetched = fetch_ohttp_keys_from_http_stream_with_timeout(
            &directory,
            &mut client,
            Duration::from_millis(100),
        )
        .await
        .expect("bootstrap should not wait for EOF once Content-Length bytes are available");
        assert_eq!(
            fetched.encode().expect("fetched keys should re-encode"),
            expected_body,
            "bootstrap should return the full OHTTP keys payload"
        );

        gateway_task.abort();
        let _ = gateway_task.await;
    }

    #[tokio::test]
    async fn fetch_ohttp_keys_via_relay_tunnel_times_out_when_websocket_handshake_stalls() {
        let relay_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("stalling relay should bind");
        let relay_port =
            relay_listener.local_addr().expect("stalling relay should have a local address").port();
        let relay_task = tokio::spawn(async move {
            let (mut stream, _) =
                relay_listener.accept().await.expect("stalling relay should accept a client");
            let mut request = Vec::new();
            loop {
                let mut buf = [0u8; 1024];
                let bytes_read = stream
                    .read(&mut buf)
                    .await
                    .expect("stalling relay should read the websocket handshake");
                assert!(bytes_read > 0, "websocket handshake should not end before headers");
                request.extend_from_slice(&buf[..bytes_read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            std::future::pending::<()>().await;
        });

        let relay = Url::parse(&format!("http://127.0.0.1:{relay_port}"))
            .expect("stalling relay URL should parse");
        let directory = Url::parse("http://directory.example").expect("static URL is valid");
        let config = test_config(relay.clone(), directory.clone());

        let err = fetch_ohttp_keys_via_relay_tunnel_with_timeout(
            &config,
            &relay,
            &directory,
            None,
            Duration::from_millis(100),
        )
        .await
        .expect_err("websocket handshake stall should time out");
        assert!(
            err.to_string().contains("timed out fetching OHTTP keys over relay tunnel"),
            "timeout should cover the websocket handshake phase"
        );

        relay_task.abort();
        let _ = relay_task.await;
    }

    #[tokio::test]
    async fn fetch_ohttp_keys_via_relay_tunnel_accepts_chunked_gateway_response() {
        let mut services = TestServices::initialize()
            .await
            .expect("bootstrap integration test services should start");
        services
            .wait_for_services_ready()
            .await
            .expect("bootstrap integration test services should become ready");

        let gateway_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("chunked test gateway should bind");
        let gateway_addr = gateway_listener
            .local_addr()
            .expect("chunked test gateway should have a local address");
        let expected_body = encoded_ohttp_keys_body();
        let expected_body_for_gateway = expected_body.clone();
        let allowed_purposes_body =
            [b"\x00\x01\x2a".as_slice(), b"BIP77 454403bb-9f7b-4385-b31f-acd2dae20b7e".as_slice()]
                .concat();
        let gateway_task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = gateway_listener
                    .accept()
                    .await
                    .expect("relay should connect to the chunked test gateway");
                let mut request = Vec::new();
                loop {
                    let mut buf = [0u8; 1024];
                    let bytes_read = stream
                        .read(&mut buf)
                        .await
                        .expect("chunked test gateway should read the bootstrap request");
                    assert!(
                        bytes_read > 0,
                        "bootstrap request should not terminate before headers"
                    );
                    request.extend_from_slice(&buf[..bytes_read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }

                let request = String::from_utf8(request)
                    .expect("chunked test gateway should receive a valid HTTP request");
                let request_line = request
                    .lines()
                    .next()
                    .expect("chunked test gateway should receive an HTTP request line");

                match request_line {
                    "GET /.well-known/ohttp-gateway?allowed_purposes HTTP/1.1" => {
                        let headers = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/x-ohttp-allowed-purposes\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                            allowed_purposes_body.len()
                        );
                        stream
                            .write_all(headers.as_bytes())
                            .await
                            .expect("chunked test gateway should write allowed_purposes headers");
                        stream
                            .write_all(&allowed_purposes_body)
                            .await
                            .expect("chunked test gateway should write allowed_purposes body");
                        stream
                            .shutdown()
                            .await
                            .expect("chunked test gateway should close the probe stream");
                    }
                    "GET /.well-known/ohttp-gateway HTTP/1.1" => {
                        let split = expected_body_for_gateway.len() / 2;
                        let headers = "HTTP/1.1 200 OK\r\ncontent-type: application/ohttp-keys\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n";
                        stream
                            .write_all(headers.as_bytes())
                            .await
                            .expect("chunked test gateway should write HTTP headers");

                        for chunk in [
                            &expected_body_for_gateway[..split],
                            &expected_body_for_gateway[split..],
                        ] {
                            stream
                                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                                .await
                                .expect("chunked test gateway should write the chunk length");
                            stream
                                .write_all(chunk)
                                .await
                                .expect("chunked test gateway should write the chunk body");
                            stream
                                .write_all(b"\r\n")
                                .await
                                .expect("chunked test gateway should terminate the chunk");
                        }
                        stream
                            .write_all(b"0\r\n\r\n")
                            .await
                            .expect("chunked test gateway should finish the chunked body");
                        stream
                            .shutdown()
                            .await
                            .expect("chunked test gateway should close the bootstrap stream");
                        break;
                    }
                    _ => panic!("unexpected chunked bootstrap gateway request: {request_line}"),
                }
            }
        });

        let directory = Url::parse(&format!("http://127.0.0.1:{}", gateway_addr.port()))
            .expect("chunked test gateway URL should parse");
        let relay = Url::parse(&services.ohttp_relay_url()).expect("relay URL should parse");
        let config = Config {
            db_path: PathBuf::from("unused-payjoin.sqlite"),
            max_fee_rate: None,
            bitcoind: BitcoindConfig {
                rpchost: PayjoinUrl::parse("http://127.0.0.1:18443")
                    .expect("static RPC URL should parse"),
                cookie: None,
                rpcuser: "bitcoin".to_owned(),
                rpcpassword: String::new(),
            },
            version: Some(VersionConfig::V2(V2Config {
                ohttp_keys: None,
                ohttp_relays: vec![
                    PayjoinUrl::parse(relay.as_str()).expect("relay URL should parse")
                ],
                pj_directory: PayjoinUrl::parse(directory.as_str())
                    .expect("directory URL should parse"),
                socks_proxy: None,
                tor_stream_isolation: false,
            })),
            #[cfg(feature = "_manual-tls")]
            root_certificate: None,
            #[cfg(feature = "_manual-tls")]
            certificate_key: None,
        };

        let fetched = fetch_ohttp_keys_via_relay_tunnel(&config, &relay, &directory, None)
            .await
            .expect("bootstrap should decode chunked OHTTP keys through the relay tunnel");
        assert_eq!(
            fetched.encode().expect("fetched OHTTP keys should re-encode"),
            expected_body,
            "relay tunnel bootstrap should preserve the chunked OHTTP keys payload"
        );

        gateway_task.await.expect("chunked test gateway task should complete successfully");
        let relay_handle = services.take_ohttp_relay_handle();
        let directory_handle = services.take_directory_handle();
        relay_handle.abort();
        directory_handle.abort();
        let _ = relay_handle.await;
        let _ = directory_handle.await;
    }

    #[cfg(feature = "_manual-tls")]
    #[tokio::test]
    async fn fetch_ohttp_keys_via_relay_tunnel_times_out_when_tls_handshake_stalls() {
        let relay_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("stalling relay should bind");
        let relay_port =
            relay_listener.local_addr().expect("stalling relay should have a local address").port();
        let relay_task = tokio::spawn(async move {
            let (stream, _) =
                relay_listener.accept().await.expect("stalling relay should accept a client");
            let _ws_stream =
                accept_async(stream).await.expect("stalling relay should complete the handshake");
            std::future::pending::<()>().await;
        });

        let relay = Url::parse(&format!("http://127.0.0.1:{relay_port}"))
            .expect("stalling relay URL should parse");
        let directory = Url::parse("https://directory.example").expect("static URL is valid");
        let temp_dir = tempdir().expect("temp dir should be created");
        let cert_path = temp_dir.path().join("localhost.der");
        let cert = local_cert_key();
        std::fs::write(&cert_path, cert.cert.der()).expect("test certificate should be written");
        let mut config = test_config_with_root_certificate(Some(cert_path));
        if let Some(VersionConfig::V2(v2_config)) = config.version.as_mut() {
            v2_config.ohttp_relays =
                vec![PayjoinUrl::parse(relay.as_str()).expect("relay URL should parse")];
            v2_config.pj_directory =
                PayjoinUrl::parse(directory.as_str()).expect("directory URL should parse");
            v2_config.socks_proxy = None;
        }

        let err = fetch_ohttp_keys_via_relay_tunnel_with_timeout(
            &config,
            &relay,
            &directory,
            None,
            Duration::from_millis(250),
        )
        .await
        .expect_err("TLS handshake stall should time out");
        assert!(
            err.to_string().contains("timed out fetching OHTTP keys over relay tunnel"),
            "timeout should cover the tunneled TLS handshake phase"
        );

        relay_task.abort();
        let _ = relay_task.await;
    }

    #[cfg(feature = "_manual-tls")]
    #[test]
    fn bootstrap_root_store_accepts_custom_root_without_native_roots() {
        let temp_dir = tempdir().expect("temp dir should be created");
        let cert_path = temp_dir.path().join("localhost.der");
        let cert = local_cert_key();
        std::fs::write(&cert_path, cert.cert.der()).expect("test certificate should be written");

        let config = test_config_with_root_certificate(Some(cert_path));
        let root_store =
            finalize_bootstrap_root_store(&config, tokio_rustls::rustls::RootCertStore::empty())
                .expect("custom root certificate should make the bootstrap root store usable");

        assert_eq!(root_store.len(), 1, "custom root should be added to an empty store");
    }

    #[cfg(feature = "_manual-tls")]
    #[test]
    fn bootstrap_root_store_rejects_empty_store_without_custom_root() {
        let config = test_config_with_root_certificate(None);
        let err =
            finalize_bootstrap_root_store(&config, tokio_rustls::rustls::RootCertStore::empty())
                .expect_err("bootstrap root store should reject an empty trust store");

        assert!(
            err.to_string().contains("no root certificates available for SOCKS bootstrap"),
            "error should explain that the bootstrap root store has no trust anchors"
        );
    }

    #[cfg(feature = "_manual-tls")]
    fn test_config_with_root_certificate(root_certificate: Option<PathBuf>) -> Config {
        Config {
            db_path: PathBuf::from("unused-payjoin.sqlite"),
            max_fee_rate: None,
            bitcoind: BitcoindConfig {
                rpchost: PayjoinUrl::parse("http://127.0.0.1:18443")
                    .expect("static RPC URL should parse"),
                cookie: None,
                rpcuser: "bitcoin".to_owned(),
                rpcpassword: String::new(),
            },
            version: Some(VersionConfig::V2(V2Config {
                ohttp_keys: None,
                ohttp_relays: vec![PayjoinUrl::parse("http://relay.example")
                    .expect("static relay URL should parse")],
                pj_directory: PayjoinUrl::parse("https://directory.example")
                    .expect("static directory URL should parse"),
                socks_proxy: Some(
                    Url::parse("socks5h://127.0.0.1:9050")
                        .expect("static SOCKS proxy URL should parse"),
                ),
                tor_stream_isolation: false,
            })),
            root_certificate,
            certificate_key: None,
        }
    }

    fn test_config(relay: Url, directory: Url) -> Config {
        Config {
            db_path: PathBuf::from("unused-payjoin.sqlite"),
            max_fee_rate: None,
            bitcoind: BitcoindConfig {
                rpchost: PayjoinUrl::parse("http://127.0.0.1:18443")
                    .expect("static RPC URL should parse"),
                cookie: None,
                rpcuser: "bitcoin".to_owned(),
                rpcpassword: String::new(),
            },
            version: Some(VersionConfig::V2(V2Config {
                ohttp_keys: None,
                ohttp_relays: vec![
                    PayjoinUrl::parse(relay.as_str()).expect("relay URL should parse")
                ],
                pj_directory: PayjoinUrl::parse(directory.as_str())
                    .expect("directory URL should parse"),
                socks_proxy: None,
                tor_stream_isolation: false,
            })),
            #[cfg(feature = "_manual-tls")]
            root_certificate: None,
            #[cfg(feature = "_manual-tls")]
            certificate_key: None,
        }
    }

    fn test_config_with_socks_proxy(relay: Url, directory: Url, socks_proxy: Url) -> Config {
        let mut config = test_config(relay, directory);
        if let Some(VersionConfig::V2(v2)) = config.version.as_mut() {
            v2.socks_proxy = Some(socks_proxy);
        }
        config
    }

    /// Returns a 127.0.0.1 port that no socket is currently listening on.
    ///
    /// Bind to an ephemeral port, capture it, then drop the listener so the next
    /// connection attempt is refused at TCP. Inherently racy if another process
    /// grabs the port in between, but this is a single-host unit test so the
    /// window is tiny.
    async fn unbound_loopback_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding an ephemeral port should succeed");
        let port = listener
            .local_addr()
            .expect("listener should expose its local address")
            .port();
        drop(listener);
        port
    }

    #[tokio::test]
    async fn fetch_ohttp_keys_via_relay_tunnel_surfaces_socks_error_when_proxy_is_unreachable() {
        let port = unbound_loopback_port().await;
        let relay = Url::parse("http://relay.example").expect("static relay URL should parse");
        let directory =
            Url::parse("http://directory.example").expect("static directory URL should parse");
        let socks_proxy = Url::parse(&format!("socks5h://127.0.0.1:{port}"))
            .expect("synthetic SOCKS URL should parse");
        let config = test_config_with_socks_proxy(relay.clone(), directory.clone(), socks_proxy);

        let err = fetch_ohttp_keys_via_relay_tunnel(&config, &relay, &directory, None)
            .await
            .expect_err("bootstrap should fail when the SOCKS proxy is unreachable");

        assert!(
            crate::app::v2::is_socks_proxy_error(&err),
            "unreachable SOCKS proxy must be classified as a SOCKS error so failover skips, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn fetch_ohttp_keys_via_relay_tunnel_surfaces_socks_error_when_proxy_rejects_auth() {
        use payjoin_test_utils::{Socks5Behavior, TestSocks5Proxy};

        let proxy = TestSocks5Proxy::start_with_behavior(Socks5Behavior::RejectAuthMethod)
            .await
            .expect("test SOCKS proxy should start");
        let relay = Url::parse("http://relay.example").expect("static relay URL should parse");
        let directory =
            Url::parse("http://directory.example").expect("static directory URL should parse");
        let socks_proxy = Url::parse(&proxy.url()).expect("test proxy URL should parse");
        let config = test_config_with_socks_proxy(relay.clone(), directory.clone(), socks_proxy);

        let err = fetch_ohttp_keys_via_relay_tunnel(&config, &relay, &directory, None)
            .await
            .expect_err("bootstrap should fail when the proxy refuses every auth method");

        assert!(
            crate::app::v2::is_socks_proxy_error(&err),
            "auth-method rejection must be classified as a SOCKS error so failover skips, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn fetch_ohttp_keys_via_relay_tunnel_surfaces_socks_error_when_proxy_rejects_target() {
        use payjoin_test_utils::{Socks5Behavior, TestSocks5Proxy};

        // 0x02 = connection not allowed by ruleset.
        let proxy = TestSocks5Proxy::start_with_behavior(Socks5Behavior::RejectTarget(0x02))
            .await
            .expect("test SOCKS proxy should start");
        let relay = Url::parse("http://relay.example").expect("static relay URL should parse");
        let directory =
            Url::parse("http://directory.example").expect("static directory URL should parse");
        let socks_proxy = Url::parse(&proxy.url()).expect("test proxy URL should parse");
        let config = test_config_with_socks_proxy(relay.clone(), directory.clone(), socks_proxy);

        let err = fetch_ohttp_keys_via_relay_tunnel(&config, &relay, &directory, None)
            .await
            .expect_err("bootstrap should fail when the proxy rejects the target host");

        assert!(
            crate::app::v2::is_socks_proxy_error(&err),
            "target rejection must be classified as a SOCKS error so failover skips, got: {err:?}"
        );
    }
}
