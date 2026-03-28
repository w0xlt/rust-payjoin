use std::collections::HashMap;

use anyhow::Result;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{self, Address, Amount, FeeRate};
use tokio::signal;
use tokio::sync::watch;
use url::Url;

pub mod config;
pub mod wallet;
use crate::app::config::Config;
#[cfg(feature = "v2")]
use crate::app::config::V2Transport;
use crate::app::wallet::BitcoindWallet;

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
fn http_agent(_config: &Config) -> Result<reqwest::Client> { Ok(http_agent_builder()?.build()?) }

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

#[cfg(not(feature = "_manual-tls"))]
fn http_agent_builder() -> Result<reqwest::ClientBuilder> {
    Ok(reqwest::Client::builder().http1_only())
}

#[cfg(feature = "v2")]
#[allow(dead_code)]
pub(crate) fn v2_http_agent(config: &Config) -> Result<reqwest::Client> {
    match config.v2()?.transport {
        V2Transport::Relay => http_agent(config),
        V2Transport::Direct => direct_http_agent(config),
    }
}

#[cfg(feature = "v2")]
#[allow(dead_code)]
fn direct_http_agent(config: &Config) -> Result<reqwest::Client> {
    let socks_proxy = config
        .v2()?
        .socks_proxy
        .as_ref()
        .expect("direct transport validation should guarantee a SOCKS proxy");
    let proxy = reqwest::Proxy::all(isolated_socks_proxy_url(socks_proxy)?.as_str())?;
    #[cfg(feature = "_manual-tls")]
    let builder = http_agent_builder(config.root_certificate.as_ref())?;
    #[cfg(not(feature = "_manual-tls"))]
    let builder = http_agent_builder()?;
    Ok(builder.proxy(proxy).build()?)
}

#[cfg(feature = "v2")]
#[allow(dead_code)]
fn isolated_socks_proxy_url(socks_proxy: &Url) -> Result<Url> {
    use payjoin::bitcoin::key::rand::Rng;

    let mut proxy = socks_proxy.clone();
    let mut rng = payjoin::bitcoin::key::rand::thread_rng();
    let username = format!("{:032x}", rng.gen::<u128>());
    let password = format!("{:032x}", rng.gen::<u128>());
    proxy.set_username(&username).expect("generated SOCKS username should always be valid");
    proxy.set_password(Some(&password)).expect("generated SOCKS password should always be valid");
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
    use super::isolated_socks_proxy_url;

    #[test]
    fn isolated_socks_proxy_url_preserves_endpoint() {
        let base = url::Url::parse("socks5h://127.0.0.1:9050").expect("static URL is valid");
        let isolated = isolated_socks_proxy_url(&base).expect("isolation should succeed");

        assert_eq!(isolated.scheme(), "socks5h");
        assert_eq!(isolated.host_str(), Some("127.0.0.1"));
        assert_eq!(isolated.port(), Some(9050));
        assert!(isolated.username().len() == 32);
        assert!(isolated.password().is_some());
    }

    #[test]
    fn isolated_socks_proxy_url_changes_credentials() {
        let base = url::Url::parse("socks5h://127.0.0.1:9050").expect("static URL is valid");
        let first = isolated_socks_proxy_url(&base).expect("isolation should succeed");
        let second = isolated_socks_proxy_url(&base).expect("isolation should succeed");

        assert_ne!(first.username(), second.username());
        assert_ne!(first.password(), second.password());
    }
}
