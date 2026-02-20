//! IO-related types and functions. Specifically, fetching OHTTP keys from a payjoin directory.
use std::time::Duration;

use http::header::ACCEPT;
use reqwest::{Client, Proxy};

use crate::into_url::IntoUrl;
use crate::OhttpKeys;

const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Determines how OHTTP key bootstrapping is performed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum KeyBootstrapMethod {
    /// Fetch keys through an OHTTP relay using an HTTP proxy request.
    #[default]
    RelayConnect,
    /// Fetch keys directly from the directory.
    ///
    /// A transport proxy (for example `socks5h://127.0.0.1:9050`) may be configured through
    /// [`FetchOhttpKeysOptions::transport_proxy`] to avoid exposing direct network metadata.
    Direct,
}

/// Optional settings for fetching OHTTP keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOhttpKeysOptions {
    /// How key bootstrapping should be performed.
    pub key_bootstrap_method: KeyBootstrapMethod,
    /// Request timeout for the key fetch request.
    pub timeout: Duration,
    /// Optional transport proxy used in [`KeyBootstrapMethod::Direct`] mode.
    pub transport_proxy: Option<url::Url>,
}

impl FetchOhttpKeysOptions {
    /// Create direct-bootstrap options with sensible defaults.
    pub fn direct() -> Self {
        Self {
            key_bootstrap_method: KeyBootstrapMethod::Direct,
            timeout: DEFAULT_FETCH_TIMEOUT,
            transport_proxy: None,
        }
    }
}

impl Default for FetchOhttpKeysOptions {
    fn default() -> Self {
        Self {
            key_bootstrap_method: KeyBootstrapMethod::RelayConnect,
            timeout: DEFAULT_FETCH_TIMEOUT,
            transport_proxy: None,
        }
    }
}

/// Fetch the ohttp keys from the specified payjoin directory via relay proxy.
///
/// * `ohttp_relay`: The http CONNECT method proxy to request the ohttp keys from a payjoin
///   directory. Proxying requests for ohttp keys ensures a client IP address is never revealed to
///   the payjoin directory.
///
/// * `payjoin_directory`: The payjoin directory from which to fetch the ohttp keys. This
///   directory stores and forwards payjoin client payloads.
pub async fn fetch_ohttp_keys(
    ohttp_relay: impl IntoUrl,
    payjoin_directory: impl IntoUrl,
) -> Result<OhttpKeys, Error> {
    fetch_ohttp_keys_with_options(Some(ohttp_relay), payjoin_directory, Default::default()).await
}

/// Fetch the ohttp keys from a payjoin directory using the provided options.
///
/// * `ohttp_relay`: Optional relay URL. Required for [`KeyBootstrapMethod::RelayConnect`].
///
/// * `payjoin_directory`: The payjoin directory from which to fetch the ohttp keys. This
///   directory stores and forwards payjoin client payloads.
///
/// * `options`: Key bootstrap options. [`FetchOhttpKeysOptions::default`] preserves the
///   pre-existing relay bootstrap behavior.
pub async fn fetch_ohttp_keys_with_options(
    ohttp_relay: Option<impl IntoUrl>,
    payjoin_directory: impl IntoUrl,
    options: FetchOhttpKeysOptions,
) -> Result<OhttpKeys, Error> {
    let mut builder = Client::builder().http1_only();

    if options.transport_proxy.is_some()
        && matches!(options.key_bootstrap_method, KeyBootstrapMethod::RelayConnect)
    {
        return Err(InternalErrorInner::ProxyChainingNotSupported.into());
    }

    if let Some(transport_proxy) = options.transport_proxy.as_ref() {
        builder = builder.proxy(Proxy::all(transport_proxy.as_str())?);
    }

    let builder = match options.key_bootstrap_method {
        KeyBootstrapMethod::RelayConnect => {
            let relay = ohttp_relay.ok_or(InternalErrorInner::MissingRelay)?;
            let proxy = Proxy::all(relay.into_url()?.as_str())?;
            builder.proxy(proxy)
        }
        KeyBootstrapMethod::Direct => builder,
    };

    fetch_ohttp_keys_inner(builder, payjoin_directory, options.timeout).await
}

/// Fetch the ohttp keys from the specified payjoin directory via proxy.
///
/// * `ohttp_relay`: The http CONNECT method proxy to request the ohttp keys from a payjoin
///   directory. Proxying requests for ohttp keys ensures a client IP address is never revealed to
///   the payjoin directory.
///
/// * `payjoin_directory`: The payjoin directory from which to fetch the ohttp keys. This
///   directory stores and forwards payjoin client payloads.
///
/// * `cert_der`: The DER-encoded certificate to use for local HTTPS connections.
#[cfg(feature = "_manual-tls")]
pub async fn fetch_ohttp_keys_with_cert(
    ohttp_relay: impl IntoUrl,
    payjoin_directory: impl IntoUrl,
    cert_der: Vec<u8>,
) -> Result<OhttpKeys, Error> {
    let proxy = Proxy::all(ohttp_relay.into_url()?.as_str())?;
    let builder = Client::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::tls::Certificate::from_der(&cert_der)?)
        .proxy(proxy)
        .http1_only();

    fetch_ohttp_keys_inner(builder, payjoin_directory, DEFAULT_FETCH_TIMEOUT).await
}

async fn fetch_ohttp_keys_inner(
    builder: reqwest::ClientBuilder,
    payjoin_directory: impl IntoUrl,
    timeout: Duration,
) -> Result<OhttpKeys, Error> {
    let ohttp_keys_url = payjoin_directory.into_url()?.join("/.well-known/ohttp-gateway")?;
    let client = builder.build()?;
    let res = client
        .get(ohttp_keys_url)
        .timeout(timeout)
        .header(ACCEPT, "application/ohttp-keys")
        .send()
        .await?;
    parse_ohttp_keys_response(res).await
}

async fn parse_ohttp_keys_response(res: reqwest::Response) -> Result<OhttpKeys, Error> {
    if !res.status().is_success() {
        return Err(Error::UnexpectedStatusCode(res.status()));
    }

    let body = res.bytes().await?.to_vec();
    OhttpKeys::decode(&body).map_err(|e| {
        Error::Internal(InternalError(InternalErrorInner::InvalidOhttpKeys(e.to_string())))
    })
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// When the payjoin directory returns an unexpected status code
    UnexpectedStatusCode(http::StatusCode),
    /// Internal errors that should not be pattern matched by users
    #[doc(hidden)]
    Internal(InternalError),
}

#[derive(Debug)]
pub struct InternalError(InternalErrorInner);

#[derive(Debug)]
enum InternalErrorInner {
    ParseUrl(crate::into_url::Error),
    Reqwest(reqwest::Error),
    Io(std::io::Error),
    #[cfg(feature = "_manual-tls")]
    Rustls(rustls::Error),
    InvalidOhttpKeys(String),
    MissingRelay,
    ProxyChainingNotSupported,
}

impl From<url::ParseError> for Error {
    fn from(value: url::ParseError) -> Self {
        Self::Internal(InternalError(InternalErrorInner::ParseUrl(value.into())))
    }
}

macro_rules! impl_from_error {
    ($from:ty, $to:ident) => {
        impl From<$from> for Error {
            fn from(value: $from) -> Self {
                Self::Internal(InternalError(InternalErrorInner::$to(value)))
            }
        }
    };
}

impl_from_error!(crate::into_url::Error, ParseUrl);
impl_from_error!(reqwest::Error, Reqwest);
impl_from_error!(std::io::Error, Io);
#[cfg(feature = "_manual-tls")]
impl_from_error!(rustls::Error, Rustls);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::UnexpectedStatusCode(code) => {
                write!(f, "Unexpected status code from payjoin directory: {code}")
            }
            Self::Internal(InternalError(e)) => e.fmt(f),
        }
    }
}

impl std::fmt::Display for InternalErrorInner {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use InternalErrorInner::*;

        match &self {
            Reqwest(e) => e.fmt(f),
            ParseUrl(e) => e.fmt(f),
            Io(e) => e.fmt(f),
            InvalidOhttpKeys(e) => {
                write!(f, "Invalid ohttp keys returned from payjoin directory: {e}")
            }
            MissingRelay => write!(f, "Relay bootstrap mode requires an ohttp relay URL"),
            ProxyChainingNotSupported => {
                write!(f, "Transport proxy with relay bootstrap mode is not supported")
            }
            #[cfg(feature = "_manual-tls")]
            Rustls(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(InternalError(e)) => e.source(),
            Self::UnexpectedStatusCode(_) => None,
        }
    }
}

impl std::error::Error for InternalErrorInner {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalErrorInner::*;

        match self {
            Reqwest(e) => Some(e),
            ParseUrl(e) => Some(e),
            Io(e) => Some(e),
            InvalidOhttpKeys(_) => None,
            MissingRelay => None,
            ProxyChainingNotSupported => None,
            #[cfg(feature = "_manual-tls")]
            Rustls(e) => Some(e),
        }
    }
}

impl From<InternalError> for Error {
    fn from(value: InternalError) -> Self {
        Self::Internal(value)
    }
}

impl From<InternalErrorInner> for Error {
    fn from(value: InternalErrorInner) -> Self {
        Self::Internal(InternalError(value))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use http::StatusCode;
    use reqwest::Response;

    use super::*;

    fn mock_response(status: StatusCode, body: Vec<u8>) -> Response {
        Response::from(http::response::Response::builder().status(status).body(body).unwrap())
    }

    #[tokio::test]
    async fn test_parse_success_response() {
        let valid_keys =
            OhttpKeys::from_str("OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC")
                .expect("valid keys")
                .encode()
                .expect("encodevalid keys");

        let response = mock_response(StatusCode::OK, valid_keys);
        assert!(parse_ohttp_keys_response(response).await.is_ok(), "expected valid keys response");
    }

    #[tokio::test]
    async fn test_parse_error_status_codes() {
        let error_codes = [
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
        ];

        for status in error_codes {
            let response = mock_response(status, vec![]);
            match parse_ohttp_keys_response(response).await {
                Err(Error::UnexpectedStatusCode(code)) => assert_eq!(code, status),
                result => panic!(
                    "Expected UnexpectedStatusCode error for status code: {status}, got: {result:?}"
                ),
            }
        }
    }

    #[tokio::test]
    async fn test_parse_invalid_keys() {
        // Invalid OHTTP keys (not properly encoded)
        let invalid_keys = vec![1, 2, 3, 4];

        let response = mock_response(StatusCode::OK, invalid_keys);

        assert!(
            matches!(
                parse_ohttp_keys_response(response).await,
                Err(Error::Internal(InternalError(InternalErrorInner::InvalidOhttpKeys(_))))
            ),
            "expected InvalidOhttpKeys error"
        );
    }

    #[test]
    fn test_direct_options_helper() {
        let options = FetchOhttpKeysOptions::direct();
        assert_eq!(options.key_bootstrap_method, KeyBootstrapMethod::Direct);
        assert_eq!(options.timeout, DEFAULT_FETCH_TIMEOUT);
        assert!(options.transport_proxy.is_none());
    }

    #[tokio::test]
    async fn test_missing_relay_for_relay_bootstrap_mode() {
        let err = fetch_ohttp_keys_with_options(
            None::<&str>,
            "https://example.com",
            FetchOhttpKeysOptions::default(),
        )
        .await
        .expect_err("relay bootstrap mode should require relay URL");

        assert_eq!(err.to_string(), "Relay bootstrap mode requires an ohttp relay URL");
    }

    #[tokio::test]
    async fn test_reject_transport_proxy_with_relay_bootstrap_mode() {
        let options = FetchOhttpKeysOptions {
            key_bootstrap_method: KeyBootstrapMethod::RelayConnect,
            timeout: DEFAULT_FETCH_TIMEOUT,
            transport_proxy: Some(
                url::Url::parse("socks5h://127.0.0.1:9050").expect("proxy URL should parse"),
            ),
        };

        let err = fetch_ohttp_keys_with_options(
            Some("https://relay.example"),
            "https://directory.example",
            options,
        )
        .await
        .expect_err("proxy chaining is intentionally unsupported");

        assert_eq!(err.to_string(), "Transport proxy with relay bootstrap mode is not supported");
    }

    #[tokio::test]
    async fn test_direct_mode_does_not_require_relay_url() {
        let err = fetch_ohttp_keys_with_options(
            None::<&str>,
            "not a valid url",
            FetchOhttpKeysOptions::direct(),
        )
        .await
        .expect_err("direct mode should not require a relay URL");

        assert!(matches!(
            err,
            Error::Internal(InternalError(InternalErrorInner::ParseUrl(_)))
        ));
    }

    #[tokio::test]
    async fn test_direct_mode_rejects_invalid_transport_proxy_scheme() {
        let options = FetchOhttpKeysOptions {
            key_bootstrap_method: KeyBootstrapMethod::Direct,
            timeout: DEFAULT_FETCH_TIMEOUT,
            transport_proxy: Some(
                url::Url::parse("ftp://127.0.0.1:21").expect("proxy URL should parse"),
            ),
        };

        let err = fetch_ohttp_keys_with_options(None::<&str>, "https://directory.example", options)
            .await
            .expect_err("invalid transport proxy scheme should fail");

        assert!(matches!(
            err,
            Error::Internal(InternalError(InternalErrorInner::Reqwest(_)))
        ));
    }
}
