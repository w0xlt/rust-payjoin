use std::path::PathBuf;

use anyhow::Result;
use config::builder::DefaultState;
use config::{ConfigError, File, FileFormat};
use payjoin::bitcoin::FeeRate;
use payjoin::Version;
use serde::Deserialize;
use url::Url;

use crate::cli::{Cli, Commands};
use crate::db;

const CONFIG_DIR: &str = "payjoin-cli";

type Builder = config::builder::ConfigBuilder<DefaultState>;

#[derive(Debug, Clone, Deserialize)]
pub struct BitcoindConfig {
    pub rpchost: Url,
    pub cookie: Option<PathBuf>,
    pub rpcuser: String,
    pub rpcpassword: String,
}

#[cfg(feature = "v1")]
#[derive(Debug, Clone, Deserialize)]
pub struct V1Config {
    pub port: u16,
    pub pj_endpoint: Url,
}

#[cfg(feature = "v2")]
#[derive(Debug, Clone, Deserialize)]
pub struct V2Config {
    #[serde(deserialize_with = "deserialize_ohttp_keys_from_path")]
    pub ohttp_keys: Option<payjoin::OhttpKeys>,
    pub ohttp_relays: Vec<Url>,
    pub pj_directory: Url,
    pub socks_proxy: Option<Url>,
    pub tor_stream_isolation: bool,
}

#[cfg(feature = "v2")]
impl V2Config {
    fn validate(self) -> Result<Self, ConfigError> {
        if self.tor_stream_isolation && self.socks_proxy.is_none() {
            return Err(ConfigError::Message(
                "BIP77 Tor stream isolation requires a SOCKS proxy".to_owned(),
            ));
        }
        if let Some(socks_proxy) = &self.socks_proxy {
            if socks_proxy.scheme() != "socks5h" {
                return Err(ConfigError::Message(
                    "BIP77 SOCKS proxy must use the socks5h:// scheme".to_owned(),
                ));
            }
            if self.tor_stream_isolation
                && (!socks_proxy.username().is_empty() || socks_proxy.password().is_some())
            {
                return Err(ConfigError::Message(
                    "BIP77 Tor stream isolation cannot be combined with SOCKS proxy credentials in the URL"
                        .to_owned(),
                ));
            }
            if self.ohttp_keys.is_none()
                && self.ohttp_relays.iter().any(|relay| relay.scheme() != "http")
            {
                return Err(ConfigError::Message(
                    "BIP77 SOCKS relay bootstrap currently requires http:// relay URLs".to_owned(),
                ));
            }
            if self.ohttp_keys.is_none() {
                #[cfg(not(feature = "_manual-tls"))]
                if self.pj_directory.scheme() != "http" {
                    return Err(ConfigError::Message(
                        "BIP77 SOCKS relay bootstrap without _manual-tls requires an http:// directory URL"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(self)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "version")]
pub enum VersionConfig {
    #[cfg(feature = "v1")]
    #[serde(rename = "v1")]
    V1(V1Config),
    #[cfg(feature = "v2")]
    #[serde(rename = "v2")]
    V2(V2Config),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub db_path: PathBuf,
    pub max_fee_rate: Option<FeeRate>,
    pub bitcoind: BitcoindConfig,
    #[serde(skip)]
    pub version: Option<VersionConfig>,
    #[cfg(feature = "_manual-tls")]
    pub root_certificate: Option<PathBuf>,
    #[cfg(feature = "_manual-tls")]
    #[cfg_attr(not(feature = "v1"), allow(dead_code))]
    pub certificate_key: Option<PathBuf>,
}

impl Config {
    /// Check for multiple version flags and return the highest precedence version
    fn determine_version(cli: &Cli) -> Result<Version, ConfigError> {
        let mut selected_version = None;

        // Check for BIP77 (v2)
        if cli.flags.bip77.unwrap_or(false) {
            selected_version = Some(Version::Two);
        }

        // Check for BIP78 (v1)
        if cli.flags.bip78.unwrap_or(false) {
            if selected_version.is_some() {
                return Err(ConfigError::Message(
                    "Multiple version flags specified. Please use only one of: --bip77, --bip78"
                        .to_string(),
                ));
            }
            selected_version = Some(Version::One);
        }

        if let Some(version) = selected_version {
            return Ok(version);
        };

        // If no version explicitly selected, use default based on available features
        #[cfg(feature = "v2")]
        return Ok(Version::Two);
        #[cfg(all(feature = "v1", not(feature = "v2")))]
        return Ok(Version::One);
        #[cfg(not(any(feature = "v1", feature = "v2")))]
        return Err(ConfigError::Message(
            "No valid version available - must compile with v1 or v2 feature".to_string(),
        ));
    }

    pub(crate) fn new(cli: &Cli) -> Result<Self, ConfigError> {
        let mut config = config::Config::builder();
        config = add_bitcoind_defaults(config, cli)?;
        config = add_common_defaults(config, cli)?;

        let version = Self::determine_version(cli)?;

        match version {
            Version::One => {
                #[cfg(feature = "v1")]
                {
                    config = add_v1_defaults(config, cli)?;
                }
                #[cfg(not(feature = "v1"))]
                return Err(ConfigError::Message(
                    "BIP78 (v1) selected but v1 feature not enabled".to_string(),
                ));
            }
            Version::Two => {
                #[cfg(feature = "v2")]
                {
                    config = add_v2_defaults(config, cli)?;
                }
                #[cfg(not(feature = "v2"))]
                return Err(ConfigError::Message(
                    "BIP77 (v2) selected but v2 feature not enabled".to_string(),
                ));
            }
        }

        config = handle_subcommands(config, cli)?;

        if let Some(config_dir) = dirs::config_dir() {
            let global_config_path = config_dir.join(CONFIG_DIR).join("config.toml");
            config = config.add_source(File::from(global_config_path).required(false));
        }

        config = config.add_source(File::new("config.toml", FileFormat::Toml).required(false));
        let built_config = config.build()?;

        let mut config = Config {
            db_path: built_config.get("db_path")?,
            max_fee_rate: built_config.get("max_fee_rate").ok(),
            bitcoind: built_config.get("bitcoind")?,
            version: None,
            #[cfg(feature = "_manual-tls")]
            root_certificate: built_config.get("root_certificate").ok(),
            #[cfg(feature = "_manual-tls")]
            certificate_key: built_config.get("certificate_key").ok(),
        };

        match version {
            Version::One => {
                #[cfg(feature = "v1")]
                {
                    match built_config.get::<V1Config>("v1") {
                        Ok(v1) => {
                            if v1.pj_endpoint.port().is_none() != (v1.port == 0) {
                                return Err(ConfigError::Message(
                                    "If --port is 0, --pj-endpoint may not have a port".to_owned(),
                                ));
                            }

                            config.version = Some(VersionConfig::V1(v1))
                        }
                        Err(e) =>
                            return Err(ConfigError::Message(format!(
                                "Valid V1 configuration is required for BIP78 mode: {e}"
                            ))),
                    }
                }
                #[cfg(not(feature = "v1"))]
                return Err(ConfigError::Message(
                    "BIP78 (v1) selected but v1 feature not enabled".to_string(),
                ));
            }
            Version::Two => {
                #[cfg(feature = "v2")]
                {
                    match built_config.get::<V2Config>("v2") {
                        Ok(v2) => config.version = Some(VersionConfig::V2(v2.validate()?)),
                        Err(e) =>
                            return Err(ConfigError::Message(format!(
                                "Valid V2 configuration is required for BIP77 mode: {e}"
                            ))),
                    }
                }
                #[cfg(not(feature = "v2"))]
                return Err(ConfigError::Message(
                    "BIP77 (v2) selected but v2 feature not enabled".to_string(),
                ));
            }
        }

        if config.version.is_none() {
            return Err(ConfigError::Message(
                "No valid version configuration found for the specified mode".to_string(),
            ));
        }

        tracing::trace!("App config: {config:?}");
        Ok(config)
    }

    #[cfg(feature = "v1")]
    pub fn v1(&self) -> Result<&V1Config, anyhow::Error> {
        match &self.version {
            Some(VersionConfig::V1(v1_config)) => Ok(v1_config),
            #[allow(unreachable_patterns)]
            _ => Err(anyhow::anyhow!("V1 configuration is required for BIP78 mode")),
        }
    }

    #[cfg(feature = "v2")]
    pub fn v2(&self) -> Result<&V2Config, anyhow::Error> {
        match &self.version {
            Some(VersionConfig::V2(v2_config)) => Ok(v2_config),
            #[allow(unreachable_patterns)]
            _ => Err(anyhow::anyhow!("V2 configuration is required for v2 mode")),
        }
    }
}

/// Set up default values and CLI overrides for Bitcoin RPC connection settings
fn add_bitcoind_defaults(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    // Set default values
    let config = config
        .set_default("bitcoind.rpchost", "http://localhost:18443")?
        .set_default("bitcoind.cookie", None::<String>)?
        .set_default("bitcoind.rpcuser", "bitcoin")?
        .set_default("bitcoind.rpcpassword", "")?;

    // Override config values with command line arguments if applicable
    let rpchost = cli.rpchost.as_ref().map(|s| s.as_str());
    let cookie_file = cli.cookie_file.as_ref().map(|p| p.to_string_lossy().into_owned());
    let rpcuser = cli.rpcuser.as_deref();
    let rpcpassword = cli.rpcpassword.as_deref();

    config
        .set_override_option("bitcoind.rpchost", rpchost)?
        .set_override_option("bitcoind.cookie", cookie_file)?
        .set_override_option("bitcoind.rpcuser", rpcuser)?
        .set_override_option("bitcoind.rpcpassword", rpcpassword)
}

fn add_common_defaults(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    let db_path = cli.db_path.as_ref().map(|p| p.to_string_lossy().into_owned());
    config.set_default("db_path", db::DB_PATH)?.set_override_option("db_path", db_path)
}

#[cfg(feature = "v1")]
fn add_v1_defaults(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    // Set default values
    let config = config
        .set_default("v1.port", 3000_u16)?
        .set_default("v1.pj_endpoint", "https://localhost:3000")?;

    // Override config values with command line arguments if applicable
    let pj_endpoint = cli.pj_endpoint.as_ref().map(|s| s.as_str());

    config
        .set_override_option("v1.port", cli.port)?
        .set_override_option("v1.pj_endpoint", pj_endpoint)
}

/// Set up default values and CLI overrides for v2-specific settings
#[cfg(feature = "v2")]
fn add_v2_defaults(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    // Set default values
    let config = config
        .set_default("v2.pj_directory", "https://payjo.in")?
        .set_default("v2.ohttp_keys", None::<String>)?
        .set_default("v2.socks_proxy", None::<String>)?
        .set_default("v2.tor_stream_isolation", false)?;

    // Override config values with command line arguments if applicable
    let pj_directory = cli.pj_directory.as_ref().map(|s| s.as_str());
    let ohttp_keys = cli.ohttp_keys.as_ref().map(|p| p.to_string_lossy().into_owned());
    let socks_proxy = cli.socks_proxy.as_ref().map(|url| url.as_str());
    let tor_stream_isolation = cli.tor_stream_isolation;
    let ohttp_relays = cli
        .ohttp_relays
        .as_ref()
        .map(|urls| urls.iter().map(|url| url.as_str()).collect::<Vec<_>>());

    config
        .set_override_option("v2.pj_directory", pj_directory)?
        .set_override_option("v2.ohttp_keys", ohttp_keys)?
        .set_override_option("v2.socks_proxy", socks_proxy)?
        .set_override_option("v2.tor_stream_isolation", tor_stream_isolation)?
        .set_override_option("v2.ohttp_relays", ohttp_relays)
}

/// Handles configuration overrides based on CLI subcommands
fn handle_subcommands(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    #[cfg(feature = "_manual-tls")]
    let config = {
        config
            .set_override_option(
                "root_certificate",
                Some(cli.root_certificate.as_ref().map(|s| s.to_string_lossy().into_owned())),
            )?
            .set_override_option(
                "certificate_key",
                Some(cli.certificate_key.as_ref().map(|s| s.to_string_lossy().into_owned())),
            )?
    };
    match &cli.command {
        Commands::Send { .. } => Ok(config),
        Commands::Receive {
            #[cfg(feature = "v1")]
            port,
            #[cfg(feature = "v1")]
            pj_endpoint,
            #[cfg(feature = "v2")]
            pj_directory,
            #[cfg(feature = "v2")]
            ohttp_keys,
            ..
        } => {
            #[cfg(feature = "v1")]
            let config = config
                .set_override_option("v1.port", port.map(|p| p.to_string()))?
                .set_override_option("v1.pj_endpoint", pj_endpoint.as_ref().map(|s| s.as_str()))?;
            #[cfg(feature = "v2")]
            let config = config
                .set_override_option("v2.pj_directory", pj_directory.as_ref().map(|s| s.as_str()))?
                .set_override_option(
                    "v2.ohttp_keys",
                    ohttp_keys.as_ref().map(|s| s.to_string_lossy().into_owned()),
                )?;
            Ok(config)
        }
        #[cfg(feature = "v2")]
        Commands::Resume => Ok(config),
        #[cfg(feature = "v2")]
        Commands::History => Ok(config),
    }
}

#[cfg(feature = "v2")]
fn deserialize_ohttp_keys_from_path<'de, D>(
    deserializer: D,
) -> Result<Option<payjoin::OhttpKeys>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let path_str: Option<String> = Option::deserialize(deserializer)?;

    match path_str {
        None => Ok(None),
        Some(path) => std::fs::read(path)
            .map_err(|e| serde::de::Error::custom(format!("Failed to read ohttp_keys file: {e}")))
            .and_then(|bytes| {
                payjoin::OhttpKeys::decode(&bytes).map_err(|e| {
                    serde::de::Error::custom(format!("Failed to decode ohttp keys: {e}"))
                })
            })
            .map(Some),
    }
}

#[cfg(all(test, feature = "v2"))]
mod tests {
    use super::V2Config;

    #[test]
    fn v2_config_accepts_socks5h_proxy() {
        let config = V2Config {
            ohttp_keys: None,
            ohttp_relays: vec![
                url::Url::parse("http://relay.example").expect("static URL is valid")
            ],
            pj_directory: url::Url::parse("http://directory.example").expect("static URL is valid"),
            socks_proxy: Some(
                url::Url::parse("socks5h://127.0.0.1:9050").expect("static URL is valid"),
            ),
            tor_stream_isolation: false,
        };

        assert!(config.validate().is_ok(), "socks5h proxy should be accepted");
    }

    #[test]
    fn v2_config_rejects_non_socks5h_proxy() {
        let config = V2Config {
            ohttp_keys: None,
            ohttp_relays: vec![
                url::Url::parse("http://relay.example").expect("static URL is valid")
            ],
            pj_directory: url::Url::parse("http://directory.example").expect("static URL is valid"),
            socks_proxy: Some(
                url::Url::parse("socks5://127.0.0.1:9050").expect("static URL is valid"),
            ),
            tor_stream_isolation: false,
        };

        let err = config.validate().expect_err("non-socks5h proxy should be rejected");
        assert!(
            err.to_string().contains("socks5h://"),
            "validation error should explain the required scheme"
        );
    }

    #[test]
    fn v2_config_rejects_https_relays_in_socks_mode() {
        let config = V2Config {
            ohttp_keys: None,
            ohttp_relays: vec![
                url::Url::parse("https://relay.example").expect("static URL is valid")
            ],
            pj_directory: url::Url::parse("http://directory.example").expect("static URL is valid"),
            socks_proxy: Some(
                url::Url::parse("socks5h://127.0.0.1:9050").expect("static URL is valid"),
            ),
            tor_stream_isolation: false,
        };

        let err = config.validate().expect_err("https relay should be rejected in SOCKS mode");
        assert!(
            err.to_string().contains("http:// relay"),
            "validation error should explain the relay scheme restriction"
        );
    }

    #[cfg(not(feature = "_manual-tls"))]
    #[test]
    fn v2_config_rejects_https_directory_without_manual_tls() {
        let config = V2Config {
            ohttp_keys: None,
            ohttp_relays: vec![
                url::Url::parse("http://relay.example").expect("static URL is valid")
            ],
            pj_directory: url::Url::parse("https://directory.example")
                .expect("static URL is valid"),
            socks_proxy: Some(
                url::Url::parse("socks5h://127.0.0.1:9050").expect("static URL is valid"),
            ),
            tor_stream_isolation: false,
        };

        let err =
            config.validate().expect_err("https directory should be rejected without _manual-tls");
        assert!(
            err.to_string().contains("http:// directory"),
            "validation error should explain the directory scheme restriction"
        );
    }

    #[test]
    fn v2_config_accepts_https_relays_with_preconfigured_ohttp_keys() {
        let config = V2Config {
            ohttp_keys: Some(test_ohttp_keys()),
            ohttp_relays: vec![
                url::Url::parse("https://relay.example").expect("static URL is valid")
            ],
            pj_directory: url::Url::parse("https://directory.example")
                .expect("static URL is valid"),
            socks_proxy: Some(
                url::Url::parse("socks5h://127.0.0.1:9050").expect("static URL is valid"),
            ),
            tor_stream_isolation: true,
        };

        assert!(
            config.validate().is_ok(),
            "preconfigured OHTTP keys should bypass bootstrap URL restrictions"
        );
    }

    #[test]
    fn v2_config_rejects_tor_stream_isolation_without_socks_proxy() {
        let config = V2Config {
            ohttp_keys: Some(test_ohttp_keys()),
            ohttp_relays: vec![
                url::Url::parse("https://relay.example").expect("static URL is valid")
            ],
            pj_directory: url::Url::parse("https://directory.example")
                .expect("static URL is valid"),
            socks_proxy: None,
            tor_stream_isolation: true,
        };

        let err = config.validate().expect_err("Tor stream isolation should require a SOCKS proxy");
        assert!(
            err.to_string().contains("requires a SOCKS proxy"),
            "validation error should explain the missing SOCKS proxy"
        );
    }

    #[test]
    fn v2_config_rejects_tor_stream_isolation_with_explicit_proxy_credentials() {
        let config = V2Config {
            ohttp_keys: Some(test_ohttp_keys()),
            ohttp_relays: vec![
                url::Url::parse("https://relay.example").expect("static URL is valid")
            ],
            pj_directory: url::Url::parse("https://directory.example")
                .expect("static URL is valid"),
            socks_proxy: Some(
                url::Url::parse("socks5h://user:pass@127.0.0.1:9050").expect("static URL is valid"),
            ),
            tor_stream_isolation: true,
        };

        let err = config
            .validate()
            .expect_err("Tor stream isolation should reject explicit proxy credentials");
        assert!(
            err.to_string().contains("cannot be combined"),
            "validation error should explain the credentials conflict"
        );
    }

    fn test_ohttp_keys() -> payjoin::OhttpKeys {
        use payjoin::bitcoin::bech32::primitives::decode::CheckedHrpstring;
        use payjoin::bitcoin::bech32::NoChecksum;

        let bytes = CheckedHrpstring::new::<NoChecksum>(
            "OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC",
        )
        .expect("bech32 test vector should decode")
        .byte_iter()
        .collect::<Vec<u8>>();

        payjoin::OhttpKeys::try_from(&bytes[..]).expect("test vector should convert to OHTTP keys")
    }
}
