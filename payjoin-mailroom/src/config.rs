use std::path::{Path, PathBuf};
use std::time::Duration;

use config::{ConfigError, File};
use ohttp_relay::{OutboundProxy, OutboundTransportConfig};
use serde::Deserialize;
use tokio_listener::ListenerAddress;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listener: ListenerAddress,
    pub storage_dir: PathBuf,
    #[serde(deserialize_with = "deserialize_duration_secs")]
    pub timeout: Duration,
    pub enable_v1: bool,
    pub relay: RelayConfig,
    #[cfg(feature = "telemetry")]
    pub telemetry: Option<TelemetryConfig>,
    #[cfg(feature = "acme")]
    pub acme: Option<AcmeConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct RelayConfig {
    /// Optional outbound SOCKS5h proxy for relay egress.
    pub outbound_proxy: Option<String>,
    /// Optional relay outbound connect timeout in seconds.
    pub outbound_connect_timeout_secs: Option<u64>,
}

#[cfg(feature = "telemetry")]
#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    pub endpoint: String,
    pub auth_token: String,
    pub operator_domain: String,
}

#[cfg(feature = "acme")]
#[derive(Debug, Clone, Deserialize)]
pub struct AcmeConfig {
    pub domains: Vec<String>,
    pub contact: Vec<String>,
    #[serde(default)]
    pub directory_url: Option<String>,
}

#[cfg(feature = "acme")]
impl AcmeConfig {
    pub fn into_rustls_config(
        self,
        storage_dir: &Path,
    ) -> tokio_rustls_acme::AcmeConfig<std::io::Error, std::io::Error> {
        let cache_dir = storage_dir.join("acme");
        let config = tokio_rustls_acme::AcmeConfig::new(self.domains)
            .contact(self.contact)
            .cache(tokio_rustls_acme::caches::DirCache::new(cache_dir));
        match self.directory_url {
            Some(url) => config.directory(url),
            None => config.directory_lets_encrypt(true),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listener: "[::]:8080".parse().expect("valid default listener address"),
            storage_dir: PathBuf::from("./data"),
            timeout: Duration::from_secs(30),
            enable_v1: false,
            relay: RelayConfig::default(),
            #[cfg(feature = "telemetry")]
            telemetry: None,
            #[cfg(feature = "acme")]
            acme: None,
        }
    }
}

fn deserialize_duration_secs<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    Ok(Duration::from_secs(secs))
}

impl Config {
    pub fn new(
        listener: ListenerAddress,
        storage_dir: PathBuf,
        timeout: Duration,
        enable_v1: bool,
    ) -> Self {
        Self {
            listener,
            storage_dir,
            timeout,
            enable_v1,
            relay: RelayConfig::default(),
            #[cfg(feature = "telemetry")]
            telemetry: None,
            #[cfg(feature = "acme")]
            acme: None,
        }
    }

    pub fn relay_outbound_transport(&self) -> Result<OutboundTransportConfig, ConfigError> {
        self.relay.as_outbound_transport_config()
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.relay.as_outbound_transport_config()?;
        Ok(())
    }

    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let config: Self = config::Config::builder()
            // Add from optional config file
            .add_source(File::from(path).required(false))
            // Add from the environment (with a prefix of PJ)
            // Nested values are separated with a double underscore,
            // e.g. `PJ_ACME__DOMAINS=payjo.in`
            .add_source(
                config::Environment::with_prefix("PJ")
                    .separator("__")
                    .prefix_separator("_")
                    .list_separator(",")
                    .with_list_parse_key("acme.domains")
                    .with_list_parse_key("acme.contact")
                    .try_parsing(true),
            )
            .build()?
            .try_deserialize()?;
        config.validate()?;
        Ok(config)
    }
}

impl RelayConfig {
    fn as_outbound_transport_config(&self) -> Result<OutboundTransportConfig, ConfigError> {
        if matches!(self.outbound_connect_timeout_secs, Some(0)) {
            return Err(ConfigError::Message(
                "relay.outbound_connect_timeout_secs must be greater than 0".to_string(),
            ));
        }

        let proxy = self
            .outbound_proxy
            .as_ref()
            .map(|raw| {
                OutboundProxy::parse(raw).map_err(|e| {
                    ConfigError::Message(format!("Invalid relay.outbound_proxy value '{raw}': {e}"))
                })
            })
            .transpose()?;
        let connect_timeout = self.outbound_connect_timeout_secs.map(Duration::from_secs);

        Ok(OutboundTransportConfig::new(proxy, connect_timeout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_proxy_config_accepts_socks5h() {
        let relay = RelayConfig {
            outbound_proxy: Some("socks5h://127.0.0.1:9050".to_string()),
            outbound_connect_timeout_secs: Some(10),
        };

        let outbound = relay.as_outbound_transport_config().unwrap();
        assert!(outbound.proxy().is_some());
        assert_eq!(outbound.connect_timeout(), Some(Duration::from_secs(10)));
    }

    #[test]
    fn relay_proxy_config_rejects_non_socks5h_scheme() {
        let relay = RelayConfig {
            outbound_proxy: Some("http://127.0.0.1:9050".to_string()),
            outbound_connect_timeout_secs: None,
        };

        let err = relay.as_outbound_transport_config().unwrap_err();
        assert!(err.to_string().contains("Invalid relay.outbound_proxy"));
    }

    #[test]
    fn relay_proxy_config_rejects_zero_timeout() {
        let relay = RelayConfig { outbound_proxy: None, outbound_connect_timeout_secs: Some(0) };

        let err = relay.as_outbound_transport_config().unwrap_err();
        assert!(err.to_string().contains("outbound_connect_timeout_secs must be greater than 0"));
    }
}
