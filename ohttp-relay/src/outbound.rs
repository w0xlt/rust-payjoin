use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;
use tower::Service;

use crate::error::BoxError;
use crate::GatewayUri;

const ENV_OUTBOUND_PROXY: &str = "OUTBOUND_PROXY";
const ENV_OUTBOUND_CONNECT_TIMEOUT_SECS: &str = "OUTBOUND_CONNECT_TIMEOUT_SECS";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundTransportConfig {
    proxy: Option<OutboundProxy>,
    connect_timeout: Option<Duration>,
}

impl OutboundTransportConfig {
    pub fn new(proxy: Option<OutboundProxy>, connect_timeout: Option<Duration>) -> Self {
        Self { proxy, connect_timeout }
    }

    pub fn from_env() -> Result<Self, BoxError> {
        let proxy = match std::env::var(ENV_OUTBOUND_PROXY) {
            Ok(raw) => Some(OutboundProxy::parse(&raw)?),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => return Err(format!("Failed reading {ENV_OUTBOUND_PROXY}: {e}").into()),
        };

        let connect_timeout = match std::env::var(ENV_OUTBOUND_CONNECT_TIMEOUT_SECS) {
            Ok(raw) => Some(parse_connect_timeout_secs(&raw)?),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => {
                return Err(
                    format!("Failed reading {ENV_OUTBOUND_CONNECT_TIMEOUT_SECS}: {e}").into()
                );
            }
        };

        Ok(Self::new(proxy, connect_timeout))
    }

    pub fn proxy(&self) -> Option<&OutboundProxy> { self.proxy.as_ref() }

    pub fn connect_timeout(&self) -> Option<Duration> { self.connect_timeout }
}

fn parse_connect_timeout_secs(raw: &str) -> Result<Duration, BoxError> {
    let secs = raw
        .parse::<u64>()
        .map_err(|e| format!("Invalid {ENV_OUTBOUND_CONNECT_TIMEOUT_SECS} value '{raw}': {e}"))?;
    Ok(Duration::from_secs(secs))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundProxy {
    host: String,
    port: u16,
}

impl OutboundProxy {
    pub fn parse(raw: &str) -> Result<Self, BoxError> {
        let parsed = url::Url::parse(raw)
            .map_err(|e| format!("Invalid {ENV_OUTBOUND_PROXY} URL '{raw}': {e}"))?;

        if parsed.scheme() != "socks5h" {
            return Err(format!(
                "{ENV_OUTBOUND_PROXY} must use socks5h:// scheme, got '{}://'",
                parsed.scheme()
            )
            .into());
        }

        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(format!(
                "{ENV_OUTBOUND_PROXY} must not include userinfo; provide only host and port"
            )
            .into());
        }

        if (parsed.path() != "/" && !parsed.path().is_empty())
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(
                format!("{ENV_OUTBOUND_PROXY} must not include path, query, or fragment").into()
            );
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| format!("{ENV_OUTBOUND_PROXY} must include a host"))?
            .to_string();
        let port = parsed
            .port()
            .ok_or_else(|| format!("{ENV_OUTBOUND_PROXY} must include an explicit port"))?;

        Ok(Self { host, port })
    }

    pub fn host(&self) -> &str { &self.host }

    pub fn port(&self) -> u16 { self.port }
}

pub(crate) async fn connect_gateway_stream(
    gateway: &GatewayUri,
    outbound: &OutboundTransportConfig,
) -> io::Result<OutboundStream> {
    match outbound.proxy() {
        Some(proxy) =>
            connect_via_proxy(proxy, gateway.host(), gateway.port(), outbound.connect_timeout())
                .await
                .map(OutboundStream::Proxied),
        None => {
            let addr = gateway.to_socket_addr().await?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Failed to resolve gateway address for {}", gateway.to_uri()),
                )
            })?;
            connect_tcp(addr, outbound.connect_timeout()).await.map(OutboundStream::Direct)
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TransportConnector {
    outbound: OutboundTransportConfig,
}

impl TransportConnector {
    pub(crate) fn new(outbound: OutboundTransportConfig) -> Self { Self { outbound } }
}

impl Service<Uri> for TransportConnector {
    type Response = TokioIo<OutboundStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let outbound = self.outbound.clone();
        Box::pin(async move {
            let gateway = destination_uri_to_gateway(&dst)?;
            let stream = connect_gateway_stream(&gateway, &outbound).await?;
            Ok(TokioIo::new(stream))
        })
    }
}

fn destination_uri_to_gateway(dst: &Uri) -> io::Result<GatewayUri> {
    let scheme = dst.scheme().cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Destination URI must include scheme: {dst}"),
        )
    })?;
    let authority = dst.authority().cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Destination URI must include authority: {dst}"),
        )
    })?;

    GatewayUri::new(scheme, authority).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid destination URI for outbound connection ({dst}): {e}"),
        )
    })
}

async fn connect_tcp(
    addr: std::net::SocketAddr,
    timeout: Option<Duration>,
) -> io::Result<TcpStream> {
    match timeout {
        Some(timeout) => match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(connect_result) => connect_result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("Timed out connecting to gateway address {addr}"),
            )),
        },
        None => TcpStream::connect(addr).await,
    }
}

async fn connect_via_proxy(
    proxy: &OutboundProxy,
    target_host: &str,
    target_port: u16,
    timeout: Option<Duration>,
) -> io::Result<Socks5Stream<TcpStream>> {
    let proxy_addr =
        tokio::net::lookup_host((proxy.host(), proxy.port())).await?.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Failed to resolve SOCKS proxy {}:{}", proxy.host(), proxy.port()),
            )
        })?;

    let target = (target_host, target_port);
    match timeout {
        Some(timeout) =>
            match tokio::time::timeout(timeout, Socks5Stream::connect(proxy_addr, target)).await {
                Ok(connect_result) => connect_result.map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("SOCKS5h connect failed for {target_host}:{target_port}: {e}"),
                    )
                }),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("Timed out connecting to {target_host}:{target_port} via SOCKS5h"),
                )),
            },
        None => Socks5Stream::connect(proxy_addr, target).await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("SOCKS5h connect failed for {target_host}:{target_port}: {e}"),
            )
        }),
    }
}

pub(crate) enum OutboundStream {
    Direct(TcpStream),
    Proxied(Socks5Stream<TcpStream>),
}

impl Connection for OutboundStream {
    fn connected(&self) -> Connected {
        match self {
            Self::Direct(stream) => stream.connected(),
            Self::Proxied(stream) => Connection::connected(&**stream),
        }
    }
}

impl AsyncRead for OutboundStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Self::Proxied(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for OutboundStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            Self::Direct(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Self::Proxied(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Direct(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::Proxied(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Direct(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::Proxied(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::*;

    #[test]
    fn parse_socks5h_proxy_url() {
        let proxy = OutboundProxy::parse("socks5h://127.0.0.1:9050").expect("valid proxy");
        assert_eq!(proxy.host(), "127.0.0.1");
        assert_eq!(proxy.port(), 9050);
    }

    #[test]
    fn reject_non_socks5h_proxy_scheme() {
        let err = OutboundProxy::parse("http://127.0.0.1:8080").expect_err("must fail");
        assert!(err.to_string().contains("must use socks5h:// scheme"));
    }

    #[test]
    fn reject_proxy_with_path_or_query() {
        let err = OutboundProxy::parse("socks5h://127.0.0.1:9050/path")
            .expect_err("path should be rejected");
        assert!(err.to_string().contains("must not include path, query, or fragment"));
    }

    #[test]
    fn parse_timeout_from_env_value() {
        let timeout = parse_connect_timeout_secs("10").expect("valid timeout");
        assert_eq!(timeout, Duration::from_secs(10));
    }

    #[test]
    fn reject_invalid_timeout_from_env_value() {
        let err = parse_connect_timeout_secs("invalid").expect_err("must fail");
        assert!(err.to_string().contains("Invalid OUTBOUND_CONNECT_TIMEOUT_SECS value"));
    }

    #[test]
    fn destination_uri_requires_scheme() {
        let uri = Uri::from_static("/relative");
        let err = destination_uri_to_gateway(&uri).expect_err("must fail");
        assert!(err.to_string().contains("must include scheme"));
    }

    #[tokio::test]
    async fn socks5h_connect_uses_domain_target_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy listener");
        let proxy_port = listener.local_addr().expect("proxy local addr").port();
        let (tx, rx) = oneshot::channel::<(String, u16)>();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept proxy connection");

            let mut greeting = [0_u8; 3];
            socket.read_exact(&mut greeting).await.expect("read socks greeting");
            assert_eq!(greeting, [0x05, 0x01, 0x00], "expected unauthenticated SOCKS greeting");
            socket.write_all(&[0x05, 0x00]).await.expect("write socks method selection");

            let mut request_header = [0_u8; 4];
            socket.read_exact(&mut request_header).await.expect("read socks request header");
            assert_eq!(request_header[..3], [0x05, 0x01, 0x00], "expected CONNECT request");
            assert_eq!(request_header[3], 0x03, "expected domain target type");

            let mut host_len = [0_u8; 1];
            socket.read_exact(&mut host_len).await.expect("read domain length");
            let mut host = vec![0_u8; host_len[0] as usize];
            socket.read_exact(&mut host).await.expect("read domain bytes");

            let mut port_bytes = [0_u8; 2];
            socket.read_exact(&mut port_bytes).await.expect("read target port");
            let target_host = String::from_utf8(host).expect("valid utf8 host");
            let target_port = u16::from_be_bytes(port_bytes);
            tx.send((target_host, target_port)).expect("send target address to test");

            socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .expect("write socks success response");
        });

        let gateway = GatewayUri::from_static("http://example1234567890example1234567890.onion:80");
        let proxy = OutboundProxy::parse(&format!("socks5h://127.0.0.1:{proxy_port}"))
            .expect("valid outbound proxy");
        let outbound = OutboundTransportConfig::new(Some(proxy), Some(Duration::from_secs(5)));

        let _stream =
            connect_gateway_stream(&gateway, &outbound).await.expect("socks5h connect should work");
        let (target_host, target_port) = rx.await.expect("receive target address");
        assert_eq!(target_host, gateway.host(), "socks proxy should receive domain target");
        assert_eq!(target_port, gateway.port(), "socks proxy should receive gateway port");
    }
}
