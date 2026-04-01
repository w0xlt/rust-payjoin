use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};

use super::bootstrap::fetch_ohttp_keys_via_relay_tunnel;
use super::Config;
use crate::db::v2::SocksAuth;

#[derive(Debug, Clone)]
pub struct RelayManager {
    selected_relay: Option<url::Url>,
    failed_relays: Vec<url::Url>,
}

impl RelayManager {
    pub fn new() -> Self { RelayManager { selected_relay: None, failed_relays: Vec::new() } }

    pub fn set_selected_relay(&mut self, relay: url::Url) { self.selected_relay = Some(relay); }

    pub fn get_selected_relay(&self) -> Option<url::Url> { self.selected_relay.clone() }

    pub fn mark_relay_failed(&mut self, relay: url::Url) {
        if self.selected_relay.as_ref() == Some(&relay) {
            self.selected_relay = None;
        }
        if !self.failed_relays.contains(&relay) {
            self.failed_relays.push(relay);
        }
    }

    pub fn get_failed_relays(&self) -> Vec<url::Url> { self.failed_relays.clone() }
}

pub(crate) struct ValidatedOhttpKeys {
    pub(crate) ohttp_keys: payjoin::OhttpKeys,
    pub(crate) relay_url: url::Url,
}

pub(crate) async fn unwrap_ohttp_keys_or_else_fetch(
    config: &Config,
    directory: Option<url::Url>,
    relay_manager: Arc<Mutex<RelayManager>>,
    session_socks_auth: Option<&SocksAuth>,
) -> Result<ValidatedOhttpKeys> {
    if let Some(ohttp_keys) = config.v2()?.ohttp_keys.clone() {
        println!("Using OHTTP Keys from config");
        let relay_url = select_relay(config, relay_manager)?;
        Ok(ValidatedOhttpKeys { ohttp_keys, relay_url })
    } else {
        println!("Bootstrapping private network transport over Oblivious HTTP");
        let fetched_keys =
            fetch_ohttp_keys(config, directory, relay_manager, session_socks_auth).await?;

        Ok(fetched_keys)
    }
}

pub(crate) async fn unwrap_relay_or_else_fetch(
    config: &Config,
    directory: Option<url::Url>,
    relay_manager: Arc<Mutex<RelayManager>>,
    session_socks_auth: Option<&SocksAuth>,
) -> Result<url::Url> {
    let selected_relay =
        relay_manager.lock().expect("Lock should not be poisoned").get_selected_relay();
    match selected_relay {
        Some(relay) => Ok(relay),
        None =>
            unwrap_ohttp_keys_or_else_fetch(config, directory, relay_manager, session_socks_auth)
                .await
                .map(|validated| validated.relay_url),
    }
}
fn select_relay(config: &Config, relay_manager: Arc<Mutex<RelayManager>>) -> Result<url::Url> {
    use payjoin::bitcoin::secp256k1::rand::prelude::SliceRandom;

    let relays = config.v2()?.ohttp_relays.clone();
    let failed_relays =
        relay_manager.lock().expect("Lock should not be poisoned").get_failed_relays();

    let remaining_relays: Vec<_> =
        relays.iter().filter(|r| !failed_relays.contains(r)).cloned().collect();

    let selected_relay = remaining_relays
        .choose(&mut payjoin::bitcoin::key::rand::thread_rng())
        .cloned()
        .ok_or_else(|| anyhow!("No valid relays available"))?;

    relay_manager
        .lock()
        .expect("Lock should not be poisoned")
        .set_selected_relay(selected_relay.clone());

    Ok(selected_relay)
}

async fn fetch_ohttp_keys(
    config: &Config,
    directory: Option<url::Url>,
    relay_manager: Arc<Mutex<RelayManager>>,
    session_socks_auth: Option<&SocksAuth>,
) -> Result<ValidatedOhttpKeys> {
    let payjoin_directory = directory.unwrap_or(config.v2()?.pj_directory.clone());

    loop {
        let selected_relay = select_relay(config, relay_manager.clone())?;

        let ohttp_keys = {
            if config.v2()?.socks_proxy.is_some() {
                fetch_ohttp_keys_via_relay_tunnel(
                    config,
                    &selected_relay,
                    &payjoin_directory,
                    session_socks_auth,
                )
                .await
            } else {
                #[cfg(feature = "_manual-tls")]
                {
                    if let Some(cert_path) = config.root_certificate.as_ref() {
                        let cert_der = std::fs::read(cert_path)?;
                        payjoin::io::fetch_ohttp_keys_with_cert(
                            selected_relay.as_str(),
                            payjoin_directory.as_str(),
                            &cert_der,
                        )
                        .await
                        .map_err(anyhow::Error::from)
                    } else {
                        payjoin::io::fetch_ohttp_keys(
                            selected_relay.as_str(),
                            payjoin_directory.as_str(),
                        )
                        .await
                        .map_err(anyhow::Error::from)
                    }
                }
                #[cfg(not(feature = "_manual-tls"))]
                payjoin::io::fetch_ohttp_keys(selected_relay.as_str(), payjoin_directory.as_str())
                    .await
                    .map_err(anyhow::Error::from)
            }
        };

        match ohttp_keys {
            Ok(keys) =>
                return Ok(ValidatedOhttpKeys { ohttp_keys: keys, relay_url: selected_relay }),
            Err(err) => {
                if let Some(payjoin::io::Error::UnexpectedStatusCode(code)) =
                    err.downcast_ref::<payjoin::io::Error>()
                {
                    return Err(payjoin::io::Error::UnexpectedStatusCode(code.to_owned()).into());
                }
                tracing::debug!("Failed to connect to relay: {selected_relay}, {err:?}");
                relay_manager
                    .lock()
                    .expect("Lock should not be poisoned")
                    .mark_relay_failed(selected_relay);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use payjoin::bitcoin::bech32::primitives::decode::CheckedHrpstring;
    use payjoin::bitcoin::bech32::NoChecksum;
    use url::Url;

    use super::{select_relay, unwrap_ohttp_keys_or_else_fetch, RelayManager};
    use crate::app::config::{BitcoindConfig, Config, V2Config, VersionConfig};

    #[tokio::test]
    async fn configured_ohttp_keys_skip_bootstrap_in_socks_mode() {
        let relay_manager = Arc::new(Mutex::new(RelayManager::new()));
        let relay = Url::parse("https://relay.example").expect("static URL is valid");
        let config = test_config(vec![relay.clone()]);
        let expected_keys = test_ohttp_keys().encode().expect("test keys re-encode");

        let validated = unwrap_ohttp_keys_or_else_fetch(&config, None, relay_manager.clone(), None)
            .await
            .expect("configured OHTTP keys should skip bootstrap");
        assert_eq!(
            validated.ohttp_keys.encode().expect("returned keys re-encode"),
            expected_keys,
            "configured OHTTP keys should be returned unchanged"
        );
        assert_eq!(
            validated.relay_url, relay,
            "configured OHTTP keys should still pick a relay for session traffic"
        );
        assert_eq!(
            relay_manager.lock().expect("lock should not be poisoned").get_selected_relay(),
            Some(relay),
            "using configured OHTTP keys should still record the selected relay"
        );
    }

    #[test]
    fn relay_failures_are_scoped_to_each_manager() {
        let relay = Url::parse("https://relay.example").expect("static URL is valid");
        let failed_manager = Arc::new(Mutex::new(RelayManager::new()));
        failed_manager
            .lock()
            .expect("lock should not be poisoned")
            .mark_relay_failed(relay.clone());

        let config = test_config(vec![relay.clone()]);
        let err = select_relay(&config, failed_manager)
            .expect_err("a manager that already failed its only relay should stay exhausted");
        assert!(
            err.to_string().contains("No valid relays available"),
            "failed manager should only poison its own session state"
        );

        let fresh_manager = Arc::new(Mutex::new(RelayManager::new()));
        let selected =
            select_relay(&config, fresh_manager).expect("a fresh session should retry the relay");
        assert_eq!(selected, relay);
    }

    fn test_ohttp_keys() -> payjoin::OhttpKeys {
        let bytes = CheckedHrpstring::new::<NoChecksum>(
            "OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC",
        )
        .expect("bech32 test vector should decode")
        .byte_iter()
        .collect::<Vec<u8>>();

        payjoin::OhttpKeys::try_from(&bytes[..]).expect("test vector should convert to OHTTP keys")
    }

    fn test_config(ohttp_relays: Vec<Url>) -> Config {
        Config {
            db_path: PathBuf::from("unused-payjoin.sqlite"),
            max_fee_rate: None,
            bitcoind: BitcoindConfig {
                rpchost: Url::parse("http://127.0.0.1:18443").expect("static RPC URL is valid"),
                cookie: None,
                rpcuser: "bitcoin".to_owned(),
                rpcpassword: String::new(),
            },
            version: Some(VersionConfig::V2(V2Config {
                ohttp_keys: Some(test_ohttp_keys()),
                ohttp_relays,
                pj_directory: Url::parse("https://directory.example").expect("static URL is valid"),
                socks_proxy: Some(
                    Url::parse("socks5h://127.0.0.1:9050").expect("static URL is valid"),
                ),
                tor_stream_isolation: true,
            })),
            #[cfg(feature = "_manual-tls")]
            root_certificate: None,
            #[cfg(feature = "_manual-tls")]
            certificate_key: None,
        }
    }
}
