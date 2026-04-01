use std::collections::HashMap;

use anyhow::Result;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{self, Address, Amount, FeeRate};
use tokio::signal;
use tokio::sync::watch;
#[cfg(feature = "v2")]
use url::Url;

pub mod config;
pub mod wallet;
use crate::app::config::Config;
use crate::app::wallet::BitcoindWallet;
#[cfg(feature = "v2")]
use crate::db::v2::SocksAuth;

#[cfg(feature = "v1")]
pub(crate) mod v1;
#[cfg(feature = "v2")]
pub(crate) mod v2;

#[async_trait::async_trait]
pub trait App: Send + Sync {
    async fn new(config: Config) -> Result<Self>
    where
        Self: Sized;
    fn wallet(&self) -> BitcoindWallet;
    async fn send_payjoin(&self, bip21: &str, fee_rate: FeeRate) -> Result<()>;
    async fn receive_payjoin(&self, amount: Amount) -> Result<()>;
    #[cfg(feature = "v2")]
    async fn resume_payjoins(&self) -> Result<()>;
    #[cfg(feature = "v2")]
    async fn history(&self) -> Result<()>;

    fn create_original_psbt(
        &self,
        address: &Address,
        amount: Amount,
        fee_rate: FeeRate,
    ) -> Result<Psbt> {
        // Check if wallet has spendable UTXOs before attempting to create PSBT
        if !self.wallet().has_spendable_utxos()? {
            return Err(anyhow::anyhow!(
                "No spendable UTXOs available in wallet. Please ensure your wallet has confirmed funds."
            ));
        }

        // wallet_create_funded_psbt requires a HashMap<address: String, Amount>
        let mut outputs = HashMap::with_capacity(1);
        outputs.insert(address.to_string(), amount);

        self.wallet().create_psbt(outputs, fee_rate, true)
    }

    fn process_pj_response(&self, psbt: Psbt) -> Result<bitcoin::Txid> {
        tracing::trace!("Proposed psbt: {psbt:#?}");

        let signed = self.wallet().process_psbt(&psbt)?;
        let tx = signed.extract_tx()?;

        let txid = self.wallet().broadcast_tx(&tx)?;

        println!("Payjoin sent. TXID: {txid}");
        Ok(txid)
    }
}

#[cfg(feature = "_manual-tls")]
fn http_agent(config: &Config) -> Result<reqwest::Client> {
    Ok(http_agent_builder(config.root_certificate.as_ref())?.build()?)
}

#[cfg(not(feature = "_manual-tls"))]
fn http_agent(_config: &Config) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().http1_only().build()?)
}

#[cfg(feature = "v2")]
#[allow(dead_code)]
pub(crate) fn v2_http_agent(
    config: &Config,
    session_socks_auth: Option<&SocksAuth>,
) -> Result<reqwest::Client> {
    match v2_socks_proxy_url(config, session_socks_auth)? {
        Some(socks_proxy) => http_agent_with_socks(config, &socks_proxy),
        None => http_agent(config),
    }
}

#[cfg(feature = "_manual-tls")]
fn http_agent_builder(
    root_cert_path: Option<&std::path::PathBuf>,
) -> Result<reqwest::ClientBuilder> {
    let mut builder = reqwest::ClientBuilder::new().use_rustls_tls().http1_only();

    if let Some(root_cert_path) = root_cert_path {
        let cert_der = std::fs::read(root_cert_path)?;
        builder =
            builder.add_root_certificate(reqwest::tls::Certificate::from_der(cert_der.as_slice())?)
    }
    Ok(builder)
}

#[cfg(feature = "v2")]
#[allow(dead_code)]
fn http_agent_with_socks(_config: &Config, socks_proxy: &Url) -> Result<reqwest::Client> {
    let proxy = reqwest::Proxy::all(socks_proxy.as_str())?;
    #[cfg(feature = "_manual-tls")]
    let builder = http_agent_builder(_config.root_certificate.as_ref())?;
    #[cfg(not(feature = "_manual-tls"))]
    let builder = reqwest::ClientBuilder::new().http1_only();
    Ok(builder.proxy(proxy).build()?)
}

#[cfg(feature = "v2")]
pub(crate) fn v2_socks_proxy_url(
    config: &Config,
    session_socks_auth: Option<&SocksAuth>,
) -> Result<Option<Url>> {
    let v2 = config.v2()?;
    let session_socks_auth = if v2.tor_stream_isolation {
        Some(session_socks_auth.ok_or_else(|| {
            anyhow::anyhow!("BIP77 Tor stream isolation requires per-session SOCKS credentials")
        })?)
    } else {
        None
    };

    v2.socks_proxy
        .as_ref()
        .map(|socks_proxy| effective_socks_proxy_url(socks_proxy, session_socks_auth))
        .transpose()
}

#[cfg(feature = "v2")]
pub(crate) fn effective_socks_proxy_url(
    socks_proxy: &Url,
    session_socks_auth: Option<&SocksAuth>,
) -> Result<Url> {
    if session_socks_auth.is_some()
        && (!socks_proxy.username().is_empty() || socks_proxy.password().is_some())
    {
        return Err(anyhow::anyhow!(
            "Tor stream isolation cannot be combined with SOCKS proxy credentials in the URL"
        ));
    }

    let mut proxy = socks_proxy.clone();
    if let Some(session_socks_auth) = session_socks_auth {
        proxy
            .set_username(&session_socks_auth.username)
            .expect("generated SOCKS username should always be valid");
        proxy
            .set_password(Some(&session_socks_auth.password))
            .expect("generated SOCKS password should always be valid");
    }
    Ok(proxy)
}

async fn handle_interrupt(tx: watch::Sender<()>) {
    if let Err(e) = signal::ctrl_c().await {
        eprintln!("Error setting up Ctrl-C handler: {e}");
    }
    let _ = tx.send(());
}

#[cfg(all(test, feature = "v2"))]
mod tests {
    use super::{effective_socks_proxy_url, v2_socks_proxy_url};
    use crate::app::config::{BitcoindConfig, Config, V2Config, VersionConfig};
    use crate::db::v2::SocksAuth;

    #[test]
    fn effective_socks_proxy_url_preserves_endpoint_without_isolation() {
        let base = url::Url::parse("socks5h://127.0.0.1:9050").expect("static URL is valid");
        let effective =
            effective_socks_proxy_url(&base, None).expect("proxy URL should remain usable");

        assert_eq!(effective, base);
    }

    #[test]
    fn effective_socks_proxy_url_applies_session_credentials() {
        let base = url::Url::parse("socks5h://127.0.0.1:9050").expect("static URL is valid");
        let session_auth = SocksAuth { username: "user".to_owned(), password: "pass".to_owned() };
        let isolated = effective_socks_proxy_url(&base, Some(&session_auth))
            .expect("isolated proxy URL should be built");

        assert_eq!(isolated.scheme(), "socks5h");
        assert_eq!(isolated.host_str(), Some("127.0.0.1"));
        assert_eq!(isolated.port(), Some(9050));
        assert_eq!(isolated.username(), "user");
        assert_eq!(isolated.password(), Some("pass"));
    }

    #[test]
    fn v2_socks_proxy_url_requires_session_credentials_when_isolation_is_enabled() {
        let config = test_config(
            Some(url::Url::parse("socks5h://127.0.0.1:9050").expect("static URL is valid")),
            true,
        );
        let err = v2_socks_proxy_url(&config, None)
            .expect_err("isolated SOCKS proxy should require session credentials");

        assert!(
            err.to_string().contains("per-session SOCKS credentials"),
            "error should explain that session credentials are required"
        );
    }

    #[test]
    fn effective_socks_proxy_url_preserves_explicit_credentials_without_isolation() {
        let base =
            url::Url::parse("socks5h://user:pass@127.0.0.1:9050").expect("static URL is valid");
        let effective =
            effective_socks_proxy_url(&base, None).expect("proxy URL should remain usable");

        assert_eq!(effective, base);
    }

    #[test]
    fn effective_socks_proxy_url_rejects_explicit_credentials_with_isolation() {
        let base =
            url::Url::parse("socks5h://user:pass@127.0.0.1:9050").expect("static URL is valid");
        let session_auth =
            SocksAuth { username: "session-user".to_owned(), password: "session-pass".to_owned() };
        let err = effective_socks_proxy_url(&base, Some(&session_auth))
            .expect_err("explicit proxy credentials should conflict with isolation");

        assert!(
            err.to_string().contains("cannot be combined"),
            "error should explain the isolation conflict"
        );
    }

    fn test_config(socks_proxy: Option<url::Url>, tor_stream_isolation: bool) -> Config {
        Config {
            db_path: std::path::PathBuf::from("unused-payjoin.sqlite"),
            max_fee_rate: None,
            bitcoind: BitcoindConfig {
                rpchost: url::Url::parse("http://127.0.0.1:18443")
                    .expect("static RPC URL is valid"),
                cookie: None,
                rpcuser: "bitcoin".to_owned(),
                rpcpassword: String::new(),
            },
            version: Some(VersionConfig::V2(V2Config {
                ohttp_keys: None,
                ohttp_relays: Vec::new(),
                pj_directory: url::Url::parse("http://directory.example")
                    .expect("static directory URL should parse"),
                socks_proxy,
                tor_stream_isolation,
            })),
            #[cfg(feature = "_manual-tls")]
            root_certificate: None,
            #[cfg(feature = "_manual-tls")]
            certificate_key: None,
        }
    }
}
