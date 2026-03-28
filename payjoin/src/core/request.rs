use url::Url;
#[cfg(feature = "v1")]
const V1_REQ_CONTENT_TYPE: &str = "text/plain";

#[cfg(feature = "v2")]
const V2_REQ_CONTENT_TYPE: &str = "message/ohttp-req";

#[cfg(feature = "v2")]
const RFC_9540_GATEWAY_PATH: &str = "/.well-known/ohttp-gateway";

#[cfg(feature = "v2")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OhttpTransport {
    Relay(Url),
    Direct(Url),
}

#[cfg(feature = "v2")]
impl OhttpTransport {
    pub fn relay(url: impl crate::IntoUrl) -> Result<Self, crate::IntoUrlError> {
        Ok(Self::Relay(url.into_url()?))
    }

    pub fn direct(url: impl crate::IntoUrl) -> Result<Self, crate::IntoUrlError> {
        Ok(Self::Direct(url.into_url()?))
    }

    pub(crate) fn request_url(&self, directory_base: &Url) -> Result<Url, url::ParseError> {
        match self {
            Self::Relay(relay_base) => relay_base.join(&format!("/{directory_base}")),
            Self::Direct(directory) => directory.join(RFC_9540_GATEWAY_PATH),
        }
    }
}

/// Represents data that needs to be transmitted to the receiver or payjoin directory.
/// Ensure the `Content-Length` is set to the length of `body`. (most libraries do this automatically)
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Request {
    /// URL to send the request to.
    ///
    /// This is full URL with scheme etc - you can pass it right to `reqwest` or a similar library.
    pub url: String,

    /// The `Content-Type` header to use for the request.
    ///
    /// `text/plain` for v1 requests and `message/ohttp-req` for v2 requests.
    pub content_type: &'static str,

    /// Bytes to be sent to the receiver.
    ///
    /// This is properly encoded PSBT payload either in base64 in v1 or an OHTTP encapsulated payload in v2.
    pub body: Vec<u8>,
}

impl Request {
    /// Construct a new v1 request.
    #[cfg(feature = "v1")]
    pub(crate) fn new_v1(url: &Url, body: &[u8]) -> Self {
        Self { url: url.to_string(), content_type: V1_REQ_CONTENT_TYPE, body: body.to_vec() }
    }

    /// Construct a new v2 request.
    #[cfg(feature = "v2")]
    pub(crate) fn new_v2(
        url: &Url,
        body: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES],
    ) -> Self {
        Self { url: url.to_string(), content_type: V2_REQ_CONTENT_TYPE, body: body.to_vec() }
    }
}
