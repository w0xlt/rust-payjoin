use std::fmt::Debug;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};

pub(crate) use gateway_prober::Prober;
pub use gateway_uri::GatewayUri;
use http::uri::Authority;
use http::Uri;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{
    HeaderValue, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_LENGTH, CONTENT_TYPE,
};
use hyper::{Method, Request, Response};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tracing::instrument;
use url::Url;

pub mod error;
mod gateway_prober;
mod gateway_uri;
pub mod sentinel;
pub use sentinel::SentinelTag;

use self::error::{BoxError, Error};

#[cfg(any(feature = "connect-bootstrap", feature = "ws-bootstrap"))]
pub mod bootstrap;

pub const EXPECTED_MEDIA_TYPE: HeaderValue = HeaderValue::from_static("message/ohttp-req");
pub const DEFAULT_GATEWAY: &str = "https://payjo.in";

#[derive(Debug)]
struct RelayConfig {
    default_gateway: GatewayUri,
    client: HttpClient,
    connector: GatewayConnector,
    prober: Prober,
    sentinel_tag: SentinelTag,
}

impl RelayConfig {
    fn new(
        default_gateway: GatewayUri,
        client: HttpClient,
        connector: GatewayConnector,
        sentinel_tag: SentinelTag,
    ) -> Self {
        let prober = Prober::new_with_client(client.clone());
        RelayConfig { default_gateway, client, connector, prober, sentinel_tag }
    }
}

#[derive(Clone)]
pub struct Service {
    config: Arc<RelayConfig>,
}

impl Service {
    pub async fn new(
        sentinel_tag: SentinelTag,
        outbound_socks_proxy: Option<url::Url>,
    ) -> anyhow::Result<Self> {
        // The default gateway is hardcoded because it is obsolete and required only for backwards
        // compatibility.
        // The new mechanism for specifying a custom gateway is via RFC 9540 using
        // `/.well-known/ohttp-gateway` request paths.
        let gateway_origin = GatewayUri::from_str(DEFAULT_GATEWAY).expect("valid gateway uri");
        let socks_proxy = SocksProxyConfig::parse(outbound_socks_proxy)?;
        let connector = GatewayConnector::new(socks_proxy.clone());
        let client = HttpClient::new(socks_proxy, None)?;
        let config = RelayConfig::new(gateway_origin, client, connector, sentinel_tag);
        config.prober.assert_opt_in(&config.default_gateway).await;
        Ok(Self { config: Arc::new(config) })
    }

    #[cfg(feature = "_manual-tls")]
    pub async fn new_with_roots(
        sentinel_tag: SentinelTag,
        root_store: rustls::RootCertStore,
        default_gateway: Option<GatewayUri>,
        outbound_socks_proxy: Option<url::Url>,
    ) -> anyhow::Result<Self> {
        let gateway_origin = default_gateway
            .unwrap_or_else(|| GatewayUri::from_str(DEFAULT_GATEWAY).expect("valid gateway uri"));
        let socks_proxy = SocksProxyConfig::parse(outbound_socks_proxy)?;
        let connector = GatewayConnector::new(socks_proxy.clone());
        let client = HttpClient::new(socks_proxy, Some(root_store))?;
        let config = RelayConfig::new(gateway_origin, client, connector, sentinel_tag);
        config.prober.assert_opt_in(&config.default_gateway).await;
        Ok(Self { config: Arc::new(config) })
    }
}

impl<B> tower::Service<Request<B>> for Service
where
    B: hyper::body::Body<Data = Bytes> + Send + Debug + 'static,
    B::Error: Into<BoxError>,
{
    type Response = Response<BoxBody<Bytes, hyper::Error>>;
    type Error = hyper::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let config = self.config.clone();
        Box::pin(async move { serve_ohttp_relay(req, &config).await })
    }
}

#[derive(Debug, Clone)]
struct SocksProxyConfig {
    url: Url,
}

impl SocksProxyConfig {
    fn parse(url: Option<Url>) -> anyhow::Result<Option<Self>> {
        match url {
            Some(url) => {
                if url.scheme() != "socks5h" {
                    anyhow::bail!("mailroom outbound SOCKS proxy must use the socks5h:// scheme");
                }
                Ok(Some(Self { url }))
            }
            None => Ok(None),
        }
    }

    async fn connect(&self, gateway: &GatewayUri) -> std::io::Result<tokio::net::TcpStream> {
        self.connect_to(gateway.host(), gateway.port()).await
    }

    async fn connect_to(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
        let proxy_host =
            self.url.host_str().ok_or_else(|| std::io::Error::other("missing SOCKS proxy host"))?;
        let proxy_port = self
            .url
            .port_or_known_default()
            .ok_or_else(|| std::io::Error::other("missing SOCKS proxy port"))?;

        let stream = if !self.url.username().is_empty() || self.url.password().is_some() {
            tokio_socks::tcp::Socks5Stream::connect_with_password(
                (proxy_host, proxy_port),
                (host, port),
                self.url.username(),
                self.url.password().unwrap_or(""),
            )
            .await
            .map_err(std::io::Error::other)?
        } else {
            tokio_socks::tcp::Socks5Stream::connect((proxy_host, proxy_port), (host, port))
                .await
                .map_err(std::io::Error::other)?
        };
        Ok(stream.into_inner())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SocksConnector {
    socks_proxy: SocksProxyConfig,
}

impl SocksConnector {
    fn new(socks_proxy: SocksProxyConfig) -> Self { Self { socks_proxy } }
}

impl tower::Service<Uri> for SocksConnector {
    type Response = hyper_util::rt::TokioIo<tokio::net::TcpStream>;
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let socks_proxy = self.socks_proxy.clone();
        Box::pin(async move {
            let host = dst
                .host()
                .ok_or_else(|| std::io::Error::other("destination URI is missing a host"))?
                .to_owned();
            let port = dst
                .port_u16()
                .or_else(|| match dst.scheme_str() {
                    Some("http") => Some(80),
                    Some("https") => Some(443),
                    _ => None,
                })
                .ok_or_else(|| std::io::Error::other("destination URI is missing a known port"))?;
            let stream = socks_proxy.connect_to(&host, port).await?;
            Ok(hyper_util::rt::TokioIo::new(stream))
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GatewayConnector {
    socks_proxy: Option<SocksProxyConfig>,
}

impl GatewayConnector {
    fn new(socks_proxy: Option<SocksProxyConfig>) -> Self { Self { socks_proxy } }

    async fn connect(&self, gateway: &GatewayUri) -> std::io::Result<tokio::net::TcpStream> {
        match &self.socks_proxy {
            Some(socks_proxy) => socks_proxy.connect(gateway).await,
            None => {
                let addr = gateway
                    .to_socket_addr()
                    .await?
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
                tokio::net::TcpStream::connect(addr).await
            }
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct HttpResponse {
    pub(crate) status: hyper::StatusCode,
    pub(crate) body: Bytes,
}

#[derive(Debug, Clone)]
pub(crate) enum HttpClient {
    Direct(
        hyper_util::client::legacy::Client<
            HttpsConnector<HttpConnector>,
            BoxBody<Bytes, hyper::Error>,
        >,
    ),
    Socks(
        hyper_util::client::legacy::Client<
            HttpsConnector<SocksConnector>,
            BoxBody<Bytes, hyper::Error>,
        >,
    ),
}

impl HttpClient {
    fn new(
        socks_proxy: Option<SocksProxyConfig>,
        #[cfg(feature = "_manual-tls")] root_store: Option<rustls::RootCertStore>,
        #[cfg(not(feature = "_manual-tls"))] _root_store: Option<()>,
    ) -> anyhow::Result<Self> {
        if let Some(socks_proxy) = socks_proxy {
            #[cfg(feature = "_manual-tls")]
            let https = match root_store {
                Some(root_store) => HttpsConnectorBuilder::new()
                    .with_tls_config(
                        rustls::ClientConfig::builder()
                            .with_root_certificates(root_store)
                            .with_no_client_auth(),
                    )
                    .https_or_http()
                    .enable_http1()
                    .wrap_connector(SocksConnector::new(socks_proxy)),
                None => HttpsConnectorBuilder::new()
                    .with_webpki_roots()
                    .https_or_http()
                    .enable_http1()
                    .wrap_connector(SocksConnector::new(socks_proxy)),
            };
            #[cfg(not(feature = "_manual-tls"))]
            let https = HttpsConnectorBuilder::new()
                .with_webpki_roots()
                .https_or_http()
                .enable_http1()
                .wrap_connector(SocksConnector::new(socks_proxy));
            Ok(Self::Socks(Client::builder(TokioExecutor::new()).build(https)))
        } else {
            #[cfg(feature = "_manual-tls")]
            if let Some(root_store) = root_store {
                let https = HttpsConnectorBuilder::new()
                    .with_tls_config(
                        rustls::ClientConfig::builder()
                            .with_root_certificates(root_store)
                            .with_no_client_auth(),
                    )
                    .https_or_http()
                    .enable_http1()
                    .build();
                return Ok(Self::Direct(Client::builder(TokioExecutor::new()).build(https)));
            }

            let https = HttpsConnectorBuilder::new()
                .with_webpki_roots()
                .https_or_http()
                .enable_http1()
                .build();
            Ok(Self::Direct(Client::builder(TokioExecutor::new()).build(https)))
        }
    }

    pub(crate) async fn request_streaming(
        &self,
        req: Request<BoxBody<Bytes, hyper::Error>>,
    ) -> Result<Response<Incoming>, BoxError> {
        match self {
            Self::Direct(client) => client.request(req).await.map_err(Into::into),
            Self::Socks(client) => client.request(req).await.map_err(Into::into),
        }
    }

    #[cfg(test)]
    pub(crate) async fn request_buffered(
        &self,
        req: Request<BoxBody<Bytes, hyper::Error>>,
    ) -> Result<HttpResponse, BoxError> {
        let response = self.request_streaming(req).await?;
        let (parts, body) = response.into_parts();
        let body = body.collect().await?.to_bytes();
        Ok(HttpResponse { status: parts.status, body })
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        let https =
            HttpsConnectorBuilder::new().with_webpki_roots().https_or_http().enable_http1().build();
        Self::Direct(Client::builder(TokioExecutor::new()).build(https))
    }
}

#[instrument]
async fn serve_ohttp_relay<B>(
    req: Request<B>,
    config: &RelayConfig,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>
where
    B: hyper::body::Body<Data = Bytes> + Send + Debug + 'static,
    B::Error: Into<BoxError>,
{
    let method = req.method().clone();
    let path = req.uri().path();
    let authority = req.uri().authority().cloned();

    let mut res = match (&method, path) {
        (&Method::OPTIONS, _) => Ok(handle_preflight()),
        (&Method::GET, "/health") => Ok(health_check().await),
        (&Method::POST, _) => match parse_gateway_uri(&method, path, authority, config).await {
            Ok(gateway_uri) => handle_ohttp_relay(req, config, gateway_uri).await,
            Err(e) => Err(e),
        },
        #[cfg(any(feature = "connect-bootstrap", feature = "ws-bootstrap"))]
        (&Method::GET, _) | (&Method::CONNECT, _) => {
            match parse_gateway_uri(&method, path, authority, config).await {
                Ok(gateway_uri) =>
                    crate::ohttp_relay::bootstrap::handle_ohttp_keys(
                        req,
                        gateway_uri,
                        config.connector.clone(),
                    )
                    .await,
                Err(e) => Err(e),
            }
        }
        _ => Err(Error::NotFound),
    }
    .unwrap_or_else(|e| e.to_response());
    res.headers_mut().insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    Ok(res)
}

async fn parse_gateway_uri(
    method: &Method,
    path: &str,
    authority: Option<Authority>,
    config: &RelayConfig,
) -> Result<GatewayUri, Error> {
    // for POST and GET (websockets), the gateway URI is provided in the path
    // for CONNECT requests, just an authority is provided, and we assume HTTPS
    let gateway_uri = match method {
        &Method::CONNECT => authority.map(GatewayUri::from),
        _ => parse_gateway_uri_from_path(path, &config.default_gateway).ok(),
    }
    .ok_or_else(|| Error::BadRequest("Invalid gateway".to_string()))?;

    let policy = match config.prober.check_opt_in(&gateway_uri).await {
        Some(policy) => Ok(policy),
        None => Err(Error::Unavailable(config.prober.unavailable_for().await)),
    }?;

    if policy.bip77_allowed {
        Ok(gateway_uri)
    } else {
        // TODO Cache-Control header for error based on policy.expires
        // is not found the right error? maybe forbidden or bad gateway?
        // prober policy judgement can be an enum instead of a bool to
        // distinguish 4xx vs. 5xx failures, 4xx being an explicit opt out and
        // 5xx for IO errors etc
        Err(Error::NotFound)
    }
}

fn parse_gateway_uri_from_path(path: &str, default: &GatewayUri) -> Result<GatewayUri, BoxError> {
    if path.is_empty() || path == "/" {
        return Ok(default.clone());
    }

    let path = &path[1..];

    if path.starts_with("http://") || path.starts_with("https://") {
        GatewayUri::from_str(path)
    } else {
        Ok(Authority::from_str(path)?.into())
    }
}

fn handle_preflight() -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut res = Response::new(empty());
    *res.status_mut() = hyper::StatusCode::NO_CONTENT;
    res.headers_mut().insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    res.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("CONNECT, GET, OPTIONS, POST"),
    );
    res.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type, Content-Length"),
    );
    res
}

async fn health_check() -> Response<BoxBody<Bytes, hyper::Error>> { Response::new(empty()) }

#[instrument]
async fn handle_ohttp_relay<B>(
    req: Request<B>,
    config: &RelayConfig,
    gateway: GatewayUri,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error>
where
    B: hyper::body::Body<Data = Bytes> + Send + Debug + 'static,
    B::Error: Into<BoxError>,
{
    let fwd_req = into_forward_req(req, gateway, &config.sentinel_tag).await?;
    forward_request(fwd_req, config).await
}

/// Convert an incoming request into a request to forward to the target gateway server.
#[instrument]
async fn into_forward_req<B>(
    req: Request<B>,
    gateway_origin: GatewayUri,
    sentinel_tag: &SentinelTag,
) -> Result<Request<BoxBody<Bytes, hyper::Error>>, Error>
where
    B: hyper::body::Body<Data = Bytes> + Send + Debug + 'static,
    B::Error: Into<BoxError>,
{
    let (head, body) = req.into_parts();

    if head.method != hyper::Method::POST {
        return Err(Error::MethodNotAllowed);
    }

    if head.headers.get(CONTENT_TYPE) != Some(&EXPECTED_MEDIA_TYPE) {
        return Err(Error::UnsupportedMediaType);
    }

    let mut builder = Request::builder()
        .method(hyper::Method::POST)
        .uri(gateway_origin.rfc_9540_url())
        .header(CONTENT_TYPE, EXPECTED_MEDIA_TYPE);

    if let Some(content_length) = head.headers.get(CONTENT_LENGTH) {
        builder = builder.header(CONTENT_LENGTH, content_length);
    }

    let bytes =
        body.collect().await.map_err(|e| Error::BadRequest(e.into().to_string()))?.to_bytes();

    builder = builder.header(sentinel::HEADER_NAME, sentinel_tag.to_header_value());

    builder.body(full(bytes)).map_err(|e| Error::InternalServerError(Box::new(e)))
}

#[instrument]
async fn forward_request(
    req: Request<BoxBody<Bytes, hyper::Error>>,
    config: &RelayConfig,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error> {
    let response = config.client.request_streaming(req).await.map_err(|_| Error::BadGateway)?;
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(parts, BoxBody::new(body)))
}

pub(crate) fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

pub(crate) fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "_manual-tls")]
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    #[cfg(feature = "_manual-tls")]
    use std::sync::{Arc, Once};

    use http_body_util::BodyExt;
    use hyper::{Method, Request};
    #[cfg(feature = "_manual-tls")]
    use payjoin_test_utils::local_cert_key;
    #[cfg(feature = "_manual-tls")]
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    #[cfg(feature = "_manual-tls")]
    use tokio::net::TcpStream;
    #[cfg(feature = "_manual-tls")]
    use tokio_rustls::TlsAcceptor;
    use url::Url;

    use super::*;

    #[cfg(feature = "_manual-tls")]
    static INIT: Once = Once::new();

    #[cfg(feature = "_manual-tls")]
    fn init_crypto_provider() {
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[cfg(feature = "_manual-tls")]
    async fn serve_socks5_connection(mut inbound: TcpStream) -> std::io::Result<()> {
        let mut greeting = [0u8; 2];
        inbound.read_exact(&mut greeting).await?;
        if greeting[0] != 5 {
            return Err(std::io::Error::other("unexpected SOCKS version"));
        }

        let mut methods = vec![0u8; usize::from(greeting[1])];
        inbound.read_exact(&mut methods).await?;
        inbound.write_all(&[5, 0]).await?;

        let mut request = [0u8; 4];
        inbound.read_exact(&mut request).await?;
        if request[0] != 5 || request[1] != 1 {
            return Err(std::io::Error::other("unsupported SOCKS request"));
        }

        let host = match request[3] {
            1 => {
                let mut octets = [0u8; 4];
                inbound.read_exact(&mut octets).await?;
                IpAddr::V4(Ipv4Addr::from(octets)).to_string()
            }
            3 => {
                let mut len = [0u8; 1];
                inbound.read_exact(&mut len).await?;
                let mut host = vec![0u8; usize::from(len[0])];
                inbound.read_exact(&mut host).await?;
                String::from_utf8(host)
                    .map_err(|err| std::io::Error::other(err.utf8_error().to_string()))?
            }
            4 => {
                let mut octets = [0u8; 16];
                inbound.read_exact(&mut octets).await?;
                IpAddr::V6(Ipv6Addr::from(octets)).to_string()
            }
            _ => return Err(std::io::Error::other("unsupported SOCKS address type")),
        };

        let mut port = [0u8; 2];
        inbound.read_exact(&mut port).await?;
        let port = u16::from_be_bytes(port);

        let mut outbound = TcpStream::connect((host.as_str(), port)).await?;
        inbound.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
        Ok(())
    }

    #[tokio::test]
    async fn service_rejects_non_socks5h_outbound_proxy() {
        let result = Service::new(
            SentinelTag::new([0u8; 32]),
            Some(Url::parse("http://127.0.0.1:9050").expect("static URL is valid")),
        )
        .await;
        let err = match result {
            Ok(_) => panic!("non-socks5h proxy should be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("socks5h://"),
            "error should explain the required SOCKS scheme"
        );
    }

    #[tokio::test]
    async fn parse_gateway_uri_accepts_https_gateway_in_socks_mode() {
        let socks_proxy =
            SocksProxyConfig::parse(Some(Url::parse("socks5h://127.0.0.1:9050").unwrap()))
                .expect("SOCKS proxy should parse");
        let config = RelayConfig::new(
            GatewayUri::from_str(DEFAULT_GATEWAY).expect("default gateway is valid"),
            HttpClient::new(socks_proxy.clone(), None).expect("SOCKS client should build"),
            GatewayConnector::new(socks_proxy),
            SentinelTag::new([0u8; 32]),
        );

        let https_gateway =
            GatewayUri::from_str("https://directory.example").expect("HTTPS gateway should parse");
        config.prober.assert_opt_in(&https_gateway).await.expect("asserting opt in should succeed");

        let gateway = parse_gateway_uri(&Method::GET, "/https://directory.example/", None, &config)
            .await
            .expect("HTTPS gateway should remain usable in SOCKS mode");
        assert_eq!(gateway, https_gateway);
    }

    #[tokio::test]
    async fn parse_gateway_uri_accepts_connect_gateway_in_socks_mode() {
        let socks_proxy =
            SocksProxyConfig::parse(Some(Url::parse("socks5h://127.0.0.1:9050").unwrap()))
                .expect("SOCKS proxy should parse");
        let config = RelayConfig::new(
            GatewayUri::from_str(DEFAULT_GATEWAY).expect("default gateway is valid"),
            HttpClient::new(socks_proxy.clone(), None).expect("SOCKS client should build"),
            GatewayConnector::new(socks_proxy),
            SentinelTag::new([0u8; 32]),
        );

        let authority: Authority =
            "directory.example:443".parse().expect("CONNECT authority should parse");
        config
            .prober
            .assert_opt_in(&GatewayUri::from(authority.clone()))
            .await
            .expect("asserting opt in should succeed");

        let gateway = parse_gateway_uri(&Method::CONNECT, "/", Some(authority), &config)
            .await
            .expect("CONNECT bootstrap should remain usable in SOCKS mode");
        assert_eq!(gateway.scheme_str(), "https");
    }

    #[tokio::test]
    async fn forward_request_streams_gateway_response_body() {
        let gateway_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("streaming test gateway should bind");
        let gateway_port = gateway_listener
            .local_addr()
            .expect("streaming test gateway should have a local address")
            .port();

        let gateway_handle = tokio::spawn(async move {
            let (mut stream, _) = gateway_listener
                .accept()
                .await
                .expect("streaming test gateway should accept a client");
            let mut request = Vec::new();
            loop {
                let mut buf = [0u8; 1024];
                let bytes_read = stream
                    .read(&mut buf)
                    .await
                    .expect("streaming test gateway should read the forwarded request");
                assert!(bytes_read > 0, "forwarded request should not end before headers");
                request.extend_from_slice(&buf[..bytes_read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            let headers = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-type: application/octet-stream\r\nconnection: close\r\n\r\n";
            stream
                .write_all(headers)
                .await
                .expect("streaming test gateway should write response headers");
            stream
                .write_all(b"5\r\nhello\r\n")
                .await
                .expect("streaming test gateway should write the first chunk");
            stream.flush().await.expect("streaming test gateway should flush the first chunk");

            tokio::time::sleep(std::time::Duration::from_millis(200)).await;

            stream
                .write_all(b"6\r\n world\r\n0\r\n\r\n")
                .await
                .expect("streaming test gateway should write the second chunk");
            stream.shutdown().await.expect("streaming test gateway should close the connection");
        });

        let gateway =
            GatewayUri::from_str(&format!("http://127.0.0.1:{gateway_port}")).expect("URL valid");
        let config = RelayConfig::new(
            gateway.clone(),
            HttpClient::default(),
            GatewayConnector::new(None),
            SentinelTag::new([0u8; 32]),
        );
        let request = Request::builder()
            .method(Method::POST)
            .uri(gateway.rfc_9540_url())
            .header(CONTENT_TYPE, EXPECTED_MEDIA_TYPE)
            .body(full(Bytes::from_static(b"test payload")))
            .expect("forwarded request should build");

        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            forward_request(request, &config),
        )
        .await
        .expect("relay should return once gateway headers are available")
        .expect("gateway response should be forwarded");
        assert_eq!(response.status(), hyper::StatusCode::OK);

        let (_parts, mut body) = response.into_parts();
        let first = tokio::time::timeout(std::time::Duration::from_millis(50), body.frame())
            .await
            .expect("first response chunk should arrive promptly")
            .expect("streamed response should contain a first frame")
            .expect("first response frame should not error")
            .into_data()
            .expect("first response frame should contain data");
        assert_eq!(first, Bytes::from_static(b"hello"));

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), body.frame()).await.is_err(),
            "relay should not buffer the delayed second chunk before returning"
        );

        let second = tokio::time::timeout(std::time::Duration::from_millis(300), body.frame())
            .await
            .expect("second response chunk should arrive after the upstream delay")
            .expect("streamed response should contain a second frame")
            .expect("second response frame should not error")
            .into_data()
            .expect("second response frame should contain data");
        assert_eq!(second, Bytes::from_static(b" world"));

        gateway_handle.await.expect("streaming test gateway should complete successfully");
    }

    #[cfg(feature = "_manual-tls")]
    #[tokio::test]
    async fn socks_client_uses_manual_root_store_for_https_gateway() {
        init_crypto_provider();

        let cert = local_cert_key();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(cert_der.clone())
            .expect("self-signed localhost certificate should be a valid root");

        let tls_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("TLS test gateway should bind");
        let tls_port =
            tls_listener.local_addr().expect("TLS test gateway should have a local address").port();
        let tls_acceptor = {
            let server_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .expect("test gateway TLS config should build");
            TlsAcceptor::from(Arc::new(server_config))
        };

        let gateway_handle = tokio::spawn(async move {
            loop {
                let (stream, _) =
                    tls_listener.accept().await.expect("TLS test gateway should accept a client");
                let tls_acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    let mut stream =
                        tls_acceptor.accept(stream).await.expect("TLS handshake should succeed");
                    let mut request = Vec::new();
                    loop {
                        let mut buf = [0u8; 1024];
                        let bytes_read = stream
                            .read(&mut buf)
                            .await
                            .expect("TLS test gateway should read the HTTP request");
                        if bytes_read == 0 {
                            break;
                        }
                        request.extend_from_slice(&buf[..bytes_read]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }

                    let body = b"proxied HTTPS response";
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    stream
                        .write_all(headers.as_bytes())
                        .await
                        .expect("TLS test gateway should write HTTP headers");
                    stream.write_all(body).await.expect("TLS test gateway should write HTTP body");
                    stream.shutdown().await.expect("TLS test gateway should close the TLS stream");
                });
            }
        });

        let socks_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("SOCKS test proxy should bind");
        let socks_port = socks_listener
            .local_addr()
            .expect("SOCKS test proxy should have a local address")
            .port();
        let socks_handle = tokio::spawn(async move {
            loop {
                let (stream, _) =
                    socks_listener.accept().await.expect("SOCKS test proxy should accept a client");
                tokio::spawn(async move {
                    serve_socks5_connection(stream)
                        .await
                        .expect("SOCKS test proxy should relay the connection");
                });
            }
        });

        let socks_proxy = SocksProxyConfig::parse(Some(
            Url::parse(&format!("socks5h://127.0.0.1:{socks_port}"))
                .expect("SOCKS test proxy URL should parse"),
        ))
        .expect("SOCKS proxy config should parse")
        .expect("SOCKS proxy config should be present");
        let client = HttpClient::new(Some(socks_proxy), Some(root_store))
            .expect("SOCKS HTTP client should build with manual roots");
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("https://localhost:{tls_port}/"))
            .body(empty())
            .expect("test request should build");

        let response = client
            .request_buffered(request)
            .await
            .expect("manual TLS roots should allow the proxied HTTPS request");
        assert_eq!(response.status, hyper::StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"proxied HTTPS response"));

        socks_handle.abort();
        gateway_handle.abort();
        let _ = socks_handle.await;
        let _ = gateway_handle.await;
    }
}
