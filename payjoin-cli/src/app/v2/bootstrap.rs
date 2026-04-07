use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use futures_util::{Sink, SinkExt, StreamExt};
use payjoin::OhttpKeys;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{client_async, WebSocketStream};
use url::Url;

use crate::app::config::Config;
use crate::app::v2_socks_proxy_url;
use crate::db::v2::SocksAuth;

const OHTTP_KEYS_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) async fn fetch_ohttp_keys_via_relay_tunnel(
    config: &Config,
    relay: &Url,
    directory: &Url,
    session_socks_auth: Option<&SocksAuth>,
) -> Result<OhttpKeys> {
    fetch_ohttp_keys_via_relay_tunnel_with_timeout(
        config,
        relay,
        directory,
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
    let relay_host = relay.host_str().context("relay URL is missing a host")?;
    let relay_port = relay
        .port_or_known_default()
        .context("relay URL is missing a known port for its scheme")?;

    match v2_socks_proxy_url(config, session_socks_auth)? {
        Some(socks_proxy) => {
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
                tokio_socks::tcp::Socks5Stream::connect(
                    (proxy_host, proxy_port),
                    (relay_host, relay_port),
                )
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

/// Fetch OHTTP keys by issuing a raw HTTP/1.1 request over an already-established
/// stream (WebSocket tunnel or TLS-over-tunnel).
///
/// No timeout is applied here — callers are expected to enforce their own deadline
/// (e.g., `fetch_ohttp_keys_via_relay_tunnel_with_timeout` wraps the entire
/// connection + handshake + fetch sequence in a single timeout).
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

    let response = read_bootstrap_http_response(stream).await?;
    let _ = stream.shutdown().await;
    parse_ohttp_keys_http_response(&response)
}

/// Test-friendly variant that applies its own timeout, for unit tests that call
/// the HTTP stream layer directly without the outer relay tunnel timeout.
#[cfg(test)]
async fn fetch_ohttp_keys_from_http_stream_with_timeout(
    directory: &Url,
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    timeout: Duration,
) -> Result<OhttpKeys> {
    tokio::time::timeout(timeout, fetch_ohttp_keys_from_http_stream(directory, stream))
        .await
        .map_err(|_| anyhow!("timed out fetching OHTTP keys over relay tunnel"))?
}

async fn read_bootstrap_http_response(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut framing = None;

    loop {
        if framing.is_none() {
            if let Some(header_end) = find_header_end(&response) {
                let head = parse_http_response_head(&response)?;
                framing = Some((header_end, response_body_framing(&head.headers)?));
            }
        }

        if let Some((header_end, framing)) = &framing {
            if http_response_complete(&response[*header_end..], framing)? {
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

        if body.len() < size + 2 {
            return Err(anyhow!("chunked response ended before the chunk payload completed"));
        }
        decoded.extend_from_slice(&body[..size]);
        if &body[size..size + 2] != b"\r\n" {
            return Err(anyhow!("chunked response chunk is missing a trailing CRLF"));
        }
        body = &body[size + 2..];
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

        if body.len() < offset + size + 2 {
            return Ok(None);
        }
        if &body[offset + size..offset + size + 2] != b"\r\n" {
            return Err(anyhow!("chunked response chunk is missing a trailing CRLF"));
        }
        offset += size + 2;
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
    closing: bool,
}

impl<S> WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(ws_stream: WebSocketStream<S>) -> Self {
        Self { ws_stream, read_buffer: Vec::new(), closing: false }
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
                        if let Err(e) = this
                            .ws_stream
                            .start_send_unpin(Message::Pong(data))
                            .map_err(map_ws_error)
                        {
                            return Poll::Ready(Err(e));
                        }
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
        match Pin::new(&mut this.ws_stream).poll_ready(cx) {
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
    use std::path::PathBuf;
    use std::time::Duration;

    use futures_util::{SinkExt, StreamExt};
    use payjoin::bitcoin::bech32::primitives::decode::CheckedHrpstring;
    use payjoin::bitcoin::bech32::NoChecksum;
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
        parse_ohttp_keys_http_response, relay_websocket_url, WsIo,
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
                rpchost: Url::parse("http://127.0.0.1:18443").expect("static RPC URL should parse"),
                cookie: None,
                rpcuser: "bitcoin".to_owned(),
                rpcpassword: String::new(),
            },
            version: Some(VersionConfig::V2(V2Config {
                ohttp_keys: None,
                ohttp_relays: vec![relay.clone()],
                pj_directory: directory.clone(),
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
            v2_config.ohttp_relays = vec![relay.clone()];
            v2_config.pj_directory = directory.clone();
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
                rpchost: Url::parse("http://127.0.0.1:18443").expect("static RPC URL should parse"),
                cookie: None,
                rpcuser: "bitcoin".to_owned(),
                rpcpassword: String::new(),
            },
            version: Some(VersionConfig::V2(V2Config {
                ohttp_keys: None,
                ohttp_relays: vec![
                    Url::parse("http://relay.example").expect("static relay URL should parse")
                ],
                pj_directory: Url::parse("https://directory.example")
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
                rpchost: Url::parse("http://127.0.0.1:18443").expect("static RPC URL should parse"),
                cookie: None,
                rpcuser: "bitcoin".to_owned(),
                rpcpassword: String::new(),
            },
            version: Some(VersionConfig::V2(V2Config {
                ohttp_keys: None,
                ohttp_relays: vec![relay],
                pj_directory: directory,
                socks_proxy: None,
                tor_stream_isolation: false,
            })),
            #[cfg(feature = "_manual-tls")]
            root_certificate: None,
            #[cfg(feature = "_manual-tls")]
            certificate_key: None,
        }
    }
}
