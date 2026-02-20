use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use payjoin::io::{FetchOhttpKeysOptions, KeyBootstrapMethod};

use crate::app::config::{BootstrapMode, V2Config};
use super::Config;

#[derive(Debug, Clone)]
pub struct RelayManager {
    selected_relay: Option<url::Url>,
    failed_relays: Vec<url::Url>,
}

impl RelayManager {
    pub fn new() -> Self { RelayManager { selected_relay: None, failed_relays: Vec::new() } }

    pub fn set_selected_relay(&mut self, relay: url::Url) { self.selected_relay = Some(relay); }

    pub fn get_selected_relay(&self) -> Option<url::Url> { self.selected_relay.clone() }

    pub fn add_failed_relay(&mut self, relay: url::Url) { self.failed_relays.push(relay); }

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
) -> Result<ValidatedOhttpKeys> {
    if let Some(ohttp_keys) = config.v2()?.ohttp_keys.clone() {
        println!("Using OHTTP Keys from config");
        return Ok(ValidatedOhttpKeys {
            ohttp_keys,
            relay_url: config.v2()?.ohttp_relays[0].clone(),
        });
    } else {
        println!("Bootstrapping private network transport over Oblivious HTTP");
        let fetched_keys = fetch_ohttp_keys(config, directory, relay_manager).await?;

        Ok(fetched_keys)
    }
}

async fn fetch_ohttp_keys(
    config: &Config,
    directory: Option<url::Url>,
    relay_manager: Arc<Mutex<RelayManager>>,
) -> Result<ValidatedOhttpKeys> {
    use payjoin::bitcoin::secp256k1::rand::prelude::SliceRandom;
    let v2_config = config.v2()?;
    let payjoin_directory = directory.unwrap_or(v2_config.pj_directory.clone());
    let relays = config.v2()?.ohttp_relays.clone();
    let bootstrap_method =
        select_bootstrap_method(&v2_config.bootstrap_mode, &payjoin_directory, v2_config)?;

    loop {
        let failed_relays =
            relay_manager.lock().expect("Lock should not be poisoned").get_failed_relays();

        let remaining_relays: Vec<_> =
            relays.iter().filter(|r| !failed_relays.contains(r)).cloned().collect();

        if remaining_relays.is_empty() {
            return Err(anyhow!("No valid relays available"));
        }

        let selected_relay =
            match remaining_relays.choose(&mut payjoin::bitcoin::key::rand::thread_rng()) {
                Some(relay) => relay.clone(),
                None => return Err(anyhow!("Failed to select from remaining relays")),
            };

        relay_manager
            .lock()
            .expect("Lock should not be poisoned")
            .set_selected_relay(selected_relay.clone());

        let ohttp_options = FetchOhttpKeysOptions {
            key_bootstrap_method: bootstrap_method,
            timeout: Default::default(),
            transport_proxy: transport_proxy_for_method(bootstrap_method, v2_config),
        };

        let ohttp_keys = {
            #[cfg(feature = "_manual-tls")]
            {
                if bootstrap_method == KeyBootstrapMethod::RelayConnect {
                    if let Some(cert_path) = config.root_certificate.as_ref() {
                        let cert_der = std::fs::read(cert_path)?;
                        payjoin::io::fetch_ohttp_keys_with_cert(
                            selected_relay.as_str(),
                            payjoin_directory.as_str(),
                            cert_der,
                        )
                        .await
                    } else {
                        payjoin::io::fetch_ohttp_keys_with_options(
                            Some(selected_relay.as_str()),
                            payjoin_directory.as_str(),
                            ohttp_options,
                        )
                        .await
                    }
                } else {
                    payjoin::io::fetch_ohttp_keys_with_options(
                        Some(selected_relay.as_str()),
                        payjoin_directory.as_str(),
                        ohttp_options,
                    )
                    .await
                }
            }
            #[cfg(not(feature = "_manual-tls"))]
            payjoin::io::fetch_ohttp_keys_with_options(
                Some(selected_relay.as_str()),
                payjoin_directory.as_str(),
                ohttp_options,
            )
            .await
        };

        match ohttp_keys {
            Ok(keys) =>
                return Ok(ValidatedOhttpKeys { ohttp_keys: keys, relay_url: selected_relay }),
            Err(payjoin::io::Error::UnexpectedStatusCode(e)) => {
                return Err(payjoin::io::Error::UnexpectedStatusCode(e).into());
            }
            Err(e) => {
                tracing::debug!("Failed to connect to relay: {selected_relay}, {e:?}");
                relay_manager
                    .lock()
                    .expect("Lock should not be poisoned")
                    .add_failed_relay(selected_relay);
            }
        }
    }
}

fn select_bootstrap_method(
    bootstrap_mode: &BootstrapMode,
    payjoin_directory: &url::Url,
    v2_config: &V2Config,
) -> Result<KeyBootstrapMethod> {
    match bootstrap_mode {
        BootstrapMode::Auto => {
            if is_onion(payjoin_directory) && v2_config.network_proxy.is_some() {
                Ok(KeyBootstrapMethod::Direct)
            } else {
                Ok(KeyBootstrapMethod::RelayConnect)
            }
        }
        BootstrapMode::RelayConnect => Ok(KeyBootstrapMethod::RelayConnect),
        BootstrapMode::DirectTor => {
            if v2_config.network_proxy.is_none() {
                return Err(anyhow!(
                    "bootstrap_mode=direct_tor requires v2.network_proxy to be configured"
                ));
            }

            Ok(KeyBootstrapMethod::Direct)
        }
    }
}

fn transport_proxy_for_method(
    method: KeyBootstrapMethod,
    v2_config: &V2Config,
) -> Option<url::Url> {
    match method {
        KeyBootstrapMethod::RelayConnect => None,
        KeyBootstrapMethod::Direct => v2_config.network_proxy.clone(),
    }
}

fn is_onion(url: &url::Url) -> bool {
    url.domain()
        .map(|domain| domain.to_ascii_lowercase().ends_with(".onion"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_v2_config(network_proxy: Option<url::Url>, bootstrap_mode: BootstrapMode) -> V2Config {
        V2Config {
            ohttp_keys: None,
            ohttp_relays: vec![url::Url::parse("https://relay.example").unwrap()],
            pj_directory: url::Url::parse("https://payjo.in").unwrap(),
            network_proxy,
            bootstrap_mode,
        }
    }

    #[test]
    fn auto_uses_direct_when_onion_directory_and_proxy_set() {
        let directory = url::Url::parse("http://directoryexample1234567890.onion").unwrap();
        let v2_config = dummy_v2_config(
            Some(url::Url::parse("socks5h://127.0.0.1:9050").unwrap()),
            BootstrapMode::Auto,
        );

        let method =
            select_bootstrap_method(&v2_config.bootstrap_mode, &directory, &v2_config).unwrap();

        assert_eq!(method, KeyBootstrapMethod::Direct);
    }

    #[test]
    fn auto_uses_relay_connect_when_proxy_missing() {
        let directory = url::Url::parse("http://directoryexample1234567890.onion").unwrap();
        let v2_config = dummy_v2_config(None, BootstrapMode::Auto);

        let method =
            select_bootstrap_method(&v2_config.bootstrap_mode, &directory, &v2_config).unwrap();

        assert_eq!(method, KeyBootstrapMethod::RelayConnect);
    }

    #[test]
    fn auto_uses_relay_connect_for_non_onion_directory() {
        let directory = url::Url::parse("https://payjo.in").unwrap();
        let v2_config = dummy_v2_config(
            Some(url::Url::parse("socks5h://127.0.0.1:9050").unwrap()),
            BootstrapMode::Auto,
        );

        let method =
            select_bootstrap_method(&v2_config.bootstrap_mode, &directory, &v2_config).unwrap();

        assert_eq!(method, KeyBootstrapMethod::RelayConnect);
    }

    #[test]
    fn direct_tor_requires_proxy() {
        let directory = url::Url::parse("http://directoryexample1234567890.onion").unwrap();
        let v2_config = dummy_v2_config(None, BootstrapMode::DirectTor);

        let err =
            select_bootstrap_method(&v2_config.bootstrap_mode, &directory, &v2_config).unwrap_err();

        assert!(err
            .to_string()
            .contains("bootstrap_mode=direct_tor requires v2.network_proxy"));
    }

    #[test]
    fn transport_proxy_only_used_for_direct_method() {
        let proxy = url::Url::parse("socks5h://127.0.0.1:9050").unwrap();
        let v2_config = dummy_v2_config(Some(proxy.clone()), BootstrapMode::DirectTor);

        assert_eq!(transport_proxy_for_method(KeyBootstrapMethod::RelayConnect, &v2_config), None);
        assert_eq!(
            transport_proxy_for_method(KeyBootstrapMethod::Direct, &v2_config),
            Some(proxy)
        );
    }

    #[test]
    fn onion_detection_is_case_insensitive() {
        let onion = url::Url::parse("http://EXAMPLE.onion").unwrap();
        let non_onion = url::Url::parse("https://payjo.in").unwrap();

        assert!(is_onion(&onion));
        assert!(!is_onion(&non_onion));
    }
}
