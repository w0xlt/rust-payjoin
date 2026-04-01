use std::fmt::Debug;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};

pub(crate) use gateway_prober::Prober;
pub use gateway_uri::GatewayUri;
use http::uri::Authority;
use http::HeaderMap;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Bytes;
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
    fn new(default_gateway: GatewayUri, client: HttpClient, connector: GatewayConnector, sentinel_tag: SentinelTag) -> Self {
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

    fn reqwest_proxy(&self) -> Result<reqwest::Proxy, reqwest::Error> {
        reqwest::Proxy::all(self.url.as_str())
    }

    async fn connect(&self, gateway: &GatewayUri) -> std::io::Result<tokio::net::TcpStream> {
        let proxy_host =
            self.url.host_str().ok_or_else(|| std::io::Error::other("missing SOCKS proxy host"))?;
        let proxy_port = self
            .url
            .port_or_known_default()
            .ok_or_else(|| std::io::Error::other("missing SOCKS proxy port"))?;

            let stream = if !self.url.username().is_empty() || self.url.password().is_some() {
                tokio_socks::tcp::Socks5Stream::connect_with_password(
                    (proxy_host, proxy_port),
                    (gateway.host(), gateway.port()),
                    self.url.username(),
                    self.url.password().unwrap_or(""),
                )
                .await
                .map_err(std::io::Error::other)?
            } else {
                tokio_socks::tcp::Socks5Stream::connect(
                    (proxy_host, proxy_port),
                    (gateway.host(), gateway.port()),
                )
                .await
                .map_err(std::io::Error::other)?
            };
            Ok(stream.into_inner())
        }
}

#[derive(Debug, Clone)]
pub(crate) struct GatewayConnector {
    socks_proxy: Option<SocksProxyConfig>,
}

impl GatewayConnector {
    fn new(socks_proxy: Option<SocksProxyConfig>) -> Self { Self { socks_proxy } }

    fn requires_plain_http(&self) -> bool { self.socks_proxy.is_some() }

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

#[derive(Debug, Clone)]
pub(crate) struct HttpResponse {
    pub(crate) status: hyper::StatusCode,
    pub(crate) headers: HeaderMap,
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
    Socks(reqwest::Client),
}

impl HttpClient {
    fn new(
        socks_proxy: Option<SocksProxyConfig>,
        #[cfg(feature = "_manual-tls")] root_store: Option<rustls::RootCertStore>,
        #[cfg(not(feature = "_manual-tls"))] _root_store: Option<()>,
    ) -> anyhow::Result<Self> {
        if let Some(socks_proxy) = socks_proxy {
            let builder = reqwest::Client::builder().proxy(socks_proxy.reqwest_proxy()?).http1_only();
            Ok(Self::Socks(builder.build()?))
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

            let https = HttpsConnectorBuilder::new().with_webpki_roots().https_or_http().enable_http1().build();
            Ok(Self::Direct(Client::builder(TokioExecutor::new()).build(https)))
        }
    }

    pub(crate) async fn request(
        &self,
        req: Request<BoxBody<Bytes, hyper::Error>>,
    ) -> Result<HttpResponse, BoxError> {
        match self {
            Self::Direct(client) => {
                let response = client.request(req).await?;
                let (parts, body) = response.into_parts();
                let body = body.collect().await?.to_bytes();
                Ok(HttpResponse { status: parts.status, headers: parts.headers, body })
            }
            Self::Socks(client) => {
                let (parts, body) = req.into_parts();
                let body = body.collect().await?.to_bytes();
                let mut builder = client.request(parts.method, parts.uri.to_string()).body(body);
                for (name, value) in &parts.headers {
                    builder = builder.header(name, value);
                }
                let response = builder.send().await?;
                let status = response.status();
                let headers = response.headers().clone();
                let body = response.bytes().await?;
                Ok(HttpResponse { status, headers, body })
            }
        }
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
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

    if config.connector.requires_plain_http() && gateway_uri.scheme_str() != "http" {
        return Err(Error::BadRequest(
            "SOCKS relay mode currently requires http:// gateway URLs".to_string(),
        ));
    }

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

    if "http://" == &path[..7] || "https://" == &path[..8] {
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
    let response = config.client.request(req).await.map_err(|_| Error::BadGateway)?;
    let mut builder = Response::builder().status(response.status);
    for (name, value) in &response.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(full(response.body))
        .map_err(|e| Error::InternalServerError(Box::new(e)))
}

pub(crate) fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

pub(crate) fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hyper::Method;
    use url::Url;

    use super::*;

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
    async fn parse_gateway_uri_rejects_https_gateway_in_socks_mode() {
        let socks_proxy =
            SocksProxyConfig::parse(Some(Url::parse("socks5h://127.0.0.1:9050").unwrap()))
                .expect("SOCKS proxy should parse");
        let config = RelayConfig::new(
            GatewayUri::from_str(DEFAULT_GATEWAY).expect("default gateway is valid"),
            HttpClient::new(socks_proxy.clone(), None).expect("SOCKS client should build"),
            GatewayConnector::new(socks_proxy),
            SentinelTag::new([0u8; 32]),
        );

        let err = parse_gateway_uri(
            &Method::GET,
            "/https://directory.example/",
            None,
            &config,
        )
        .await
        .expect_err("https gateway should be rejected in SOCKS relay mode");
        assert!(
            matches!(err, Error::BadRequest(_)),
            "SOCKS relay mode should reject https gateways before probing"
        );
    }
}
