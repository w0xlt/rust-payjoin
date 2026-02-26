use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use payjoin::io::{FetchOhttpKeysOptions, KeyBootstrapMethod};

use super::Config;

const ONION_PROXY_REQUIRED_ERR: &str =
    "v2.pj_directory is an onion endpoint but v2.network_proxy is not configured. \
     Refusing clearnet fallback; set v2.network_proxy to socks5h://127.0.0.1:9050";
const DIRECT_BOOTSTRAP_ATTEMPTS: usize = 2;

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
    let v2_config = config.v2()?;
    let payjoin_directory = directory.unwrap_or(v2_config.pj_directory.clone());
    ensure_network_proxy_for_onion_directory(&payjoin_directory, v2_config.network_proxy.as_ref())?;

    if let Some(ohttp_keys) = v2_config.ohttp_keys.clone() {
        let relay_url = v2_config
            .ohttp_relays
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("No OHTTP relays configured"))?;
        println!("Using OHTTP Keys from config");
        Ok(ValidatedOhttpKeys { ohttp_keys, relay_url })
    } else {
        println!("Bootstrapping private network transport over Oblivious HTTP");
        let fetched_keys = fetch_ohttp_keys(config, Some(payjoin_directory), relay_manager).await?;

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
    let bootstrap_method = select_bootstrap_method(&payjoin_directory);
    let ohttp_options = build_ohttp_key_fetch_options(
        bootstrap_method,
        &payjoin_directory,
        v2_config.network_proxy.as_ref(),
    )?;

    if bootstrap_method == KeyBootstrapMethod::Direct {
        let selected_relay = relays
            .choose(&mut payjoin::bitcoin::key::rand::thread_rng())
            .cloned()
            .ok_or_else(|| anyhow!("No OHTTP relays configured"))?;
        relay_manager
            .lock()
            .expect("Lock should not be poisoned")
            .set_selected_relay(selected_relay.clone());

        for attempt in 1..=DIRECT_BOOTSTRAP_ATTEMPTS {
            let result = payjoin::io::fetch_ohttp_keys_with_options(
                None::<&str>,
                payjoin_directory.as_str(),
                ohttp_options.clone(),
            )
            .await;

            match result {
                Ok(ohttp_keys) => {
                    return Ok(ValidatedOhttpKeys { ohttp_keys, relay_url: selected_relay });
                }
                Err(payjoin::io::Error::UnexpectedStatusCode(status))
                    if !status.is_server_error() =>
                {
                    return Err(payjoin::io::Error::UnexpectedStatusCode(status).into());
                }
                Err(e) => {
                    tracing::debug!(
                        "Direct key bootstrap attempt {attempt}/{DIRECT_BOOTSTRAP_ATTEMPTS} \
                         failed for {payjoin_directory}: {e:?}"
                    );
                    if attempt == DIRECT_BOOTSTRAP_ATTEMPTS {
                        return Err(e.into());
                    }
                    tokio::time::sleep(Duration::from_millis((attempt as u64) * 250)).await;
                }
            }
        }
    }

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

        let ohttp_keys = {
            #[cfg(feature = "_manual-tls")]
            {
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
                        ohttp_options.clone(),
                    )
                    .await
                }
            }
            #[cfg(not(feature = "_manual-tls"))]
            payjoin::io::fetch_ohttp_keys_with_options(
                Some(selected_relay.as_str()),
                payjoin_directory.as_str(),
                ohttp_options.clone(),
            )
            .await
        };

        match ohttp_keys {
            Ok(keys) =>
                return Ok(ValidatedOhttpKeys { ohttp_keys: keys, relay_url: selected_relay }),
            Err(payjoin::io::Error::UnexpectedStatusCode(status)) if !status.is_server_error() => {
                return Err(payjoin::io::Error::UnexpectedStatusCode(status).into());
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

fn build_ohttp_key_fetch_options(
    method: KeyBootstrapMethod,
    payjoin_directory: &url::Url,
    network_proxy: Option<&url::Url>,
) -> Result<FetchOhttpKeysOptions> {
    let mut options = match method {
        KeyBootstrapMethod::Direct => FetchOhttpKeysOptions::direct(),
        KeyBootstrapMethod::RelayConnect => FetchOhttpKeysOptions::default(),
    };
    options.transport_proxy = transport_proxy_for_method(method, payjoin_directory, network_proxy)?;
    Ok(options)
}

fn select_bootstrap_method(payjoin_directory: &url::Url) -> KeyBootstrapMethod {
    if is_onion(payjoin_directory) {
        KeyBootstrapMethod::Direct
    } else {
        KeyBootstrapMethod::RelayConnect
    }
}

fn transport_proxy_for_method(
    method: KeyBootstrapMethod,
    payjoin_directory: &url::Url,
    network_proxy: Option<&url::Url>,
) -> Result<Option<url::Url>> {
    match method {
        KeyBootstrapMethod::RelayConnect => Ok(None),
        KeyBootstrapMethod::Direct =>
            if let Some(proxy) = network_proxy.cloned() {
                Ok(Some(proxy))
            } else if is_onion(payjoin_directory) {
                Err(anyhow!(ONION_PROXY_REQUIRED_ERR))
            } else {
                Ok(None)
            },
    }
}

fn ensure_network_proxy_for_onion_directory(
    payjoin_directory: &url::Url,
    network_proxy: Option<&url::Url>,
) -> Result<()> {
    if is_onion(payjoin_directory) && network_proxy.is_none() {
        return Err(anyhow!(ONION_PROXY_REQUIRED_ERR));
    }

    Ok(())
}

fn is_onion(url: &url::Url) -> bool {
    url.domain().map(|domain| domain.to_ascii_lowercase().ends_with(".onion")).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_directory_uses_direct_bootstrap() {
        let directory = url::Url::parse("http://directoryexample1234567890.onion").unwrap();
        let method = select_bootstrap_method(&directory);

        assert_eq!(method, KeyBootstrapMethod::Direct);
    }

    #[test]
    fn non_onion_directory_uses_relay_connect_bootstrap() {
        let directory = url::Url::parse("https://payjo.in").unwrap();
        let method = select_bootstrap_method(&directory);

        assert_eq!(method, KeyBootstrapMethod::RelayConnect);
    }

    #[test]
    fn direct_bootstrap_requires_proxy_for_onion_directory() {
        let directory = url::Url::parse("http://directoryexample1234567890.onion").unwrap();
        let err =
            transport_proxy_for_method(KeyBootstrapMethod::Direct, &directory, None).unwrap_err();

        assert!(err.to_string().contains("v2.pj_directory is an onion endpoint"));
    }

    #[test]
    fn transport_proxy_only_used_for_direct_method() {
        let proxy = url::Url::parse("socks5h://127.0.0.1:9050").unwrap();
        let directory = url::Url::parse("http://directoryexample1234567890.onion").unwrap();

        assert_eq!(
            transport_proxy_for_method(KeyBootstrapMethod::RelayConnect, &directory, Some(&proxy))
                .unwrap(),
            None
        );
        assert_eq!(
            transport_proxy_for_method(KeyBootstrapMethod::Direct, &directory, Some(&proxy))
                .unwrap(),
            Some(proxy)
        );
    }

    #[test]
    fn direct_bootstrap_options_use_non_zero_timeout() {
        let proxy = url::Url::parse("socks5h://127.0.0.1:9050").unwrap();
        let directory = url::Url::parse("http://directoryexample1234567890.onion").unwrap();
        let options =
            build_ohttp_key_fetch_options(KeyBootstrapMethod::Direct, &directory, Some(&proxy))
                .unwrap();

        assert!(options.timeout > Duration::from_secs(0));
        assert_eq!(options.transport_proxy, Some(proxy));
    }

    #[test]
    fn onion_detection_is_case_insensitive() {
        let onion = url::Url::parse("http://EXAMPLE.onion").unwrap();
        let non_onion = url::Url::parse("https://payjo.in").unwrap();

        assert!(is_onion(&onion));
        assert!(!is_onion(&non_onion));
    }
}
