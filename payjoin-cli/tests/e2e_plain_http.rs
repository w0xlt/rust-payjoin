#[cfg(feature = "v2")]
#[allow(dead_code)]
mod e2e_helpers;

#[cfg(feature = "v2")]
mod e2e_plain_http {
    use std::path::Path;
    use std::process::Stdio;

    use payjoin_test_utils::{
        init_bitcoind_sender_receiver, init_tracing, BoxError, Socks5AuthMode, TestServices,
        TestSocks5Proxy,
    };
    use tempfile::{tempdir, TempDir};
    use tokio::process::Command;

    use crate::e2e_helpers::{
        assert_socks_proxy_usage, get_bip21_from_receiver, terminate, wait_for_stdout_match,
        V2NetworkConfig, RECEIVE_SATS,
    };

    struct CliCommonArgs<'a> {
        cert_path: Option<&'a Path>,
        pj_directory: Option<&'a str>,
        rpchost: &'a str,
        cookie_file: &'a Path,
        db_path: &'a Path,
        ohttp_relay: &'a str,
        network: &'a V2NetworkConfig,
    }

    fn add_common_args(command: &mut Command, args: CliCommonArgs<'_>) {
        if let Some(cert_path) = args.cert_path {
            command.arg("--root-certificate").arg(cert_path);
        }
        if let Some(pj_directory) = args.pj_directory {
            command.arg("--pj-directory").arg(pj_directory);
        }
        command
            .arg("--rpchost")
            .arg(args.rpchost)
            .arg("--cookie-file")
            .arg(args.cookie_file)
            .arg("--db-path")
            .arg(args.db_path)
            .arg("--ohttp-relays")
            .arg(args.ohttp_relay);
        args.network.apply(command);
    }

    async fn run_v2_e2e(
        services: &TestServices,
        temp_dir: &TempDir,
        network: &V2NetworkConfig,
    ) -> Result<(), BoxError> {
        let receiver_db_path = temp_dir.path().join("receiver_db");
        let sender_db_path = temp_dir.path().join("sender_db");
        let (bitcoind, _sender, _receiver) = init_bitcoind_sender_receiver(None, None)?;
        services.wait_for_services_ready().await?;

        let directory = services.directory_url();
        let cert_path = if directory.starts_with("https://") {
            let cert_path = temp_dir.path().join("localhost.der");
            tokio::fs::write(&cert_path, services.cert()).await?;
            Some(cert_path)
        } else {
            None
        };

        let ohttp_keys_path = if network.preload_ohttp_keys {
            let ohttp_keys = services.fetch_ohttp_keys().await?;
            let ohttp_keys_path = temp_dir.path().join("ohttp_keys");
            tokio::fs::write(&ohttp_keys_path, ohttp_keys.encode()?).await?;
            Some(ohttp_keys_path)
        } else {
            None
        };

        let receiver_rpchost = format!("http://{}/wallet/receiver", bitcoind.params.rpc_socket);
        let sender_rpchost = format!("http://{}/wallet/sender", bitcoind.params.rpc_socket);
        let cookie_file = &bitcoind.params.cookie_file;
        let payjoin_cli = env!("CARGO_BIN_EXE_payjoin-cli");
        let ohttp_relay = services.ohttp_relay_url();

        let mut cli_receive_initiator = Command::new(payjoin_cli);
        add_common_args(
            &mut cli_receive_initiator,
            CliCommonArgs {
                cert_path: cert_path.as_deref(),
                pj_directory: None,
                rpchost: &receiver_rpchost,
                cookie_file: cookie_file.as_path(),
                db_path: &receiver_db_path,
                ohttp_relay: &ohttp_relay,
                network,
            },
        );
        cli_receive_initiator
            .arg("receive")
            .arg(RECEIVE_SATS)
            .arg("--pj-directory")
            .arg(&directory);
        if let Some(ohttp_keys_path) = &ohttp_keys_path {
            cli_receive_initiator.arg("--ohttp-keys").arg(ohttp_keys_path);
        }
        let cli_receive_initiator = cli_receive_initiator
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to execute payjoin-cli");
        let bip21 = get_bip21_from_receiver(cli_receive_initiator).await;

        let mut cli_send_initiator = Command::new(payjoin_cli);
        add_common_args(
            &mut cli_send_initiator,
            CliCommonArgs {
                cert_path: cert_path.as_deref(),
                pj_directory: Some(&directory),
                rpchost: &sender_rpchost,
                cookie_file: cookie_file.as_path(),
                db_path: &sender_db_path,
                ohttp_relay: &ohttp_relay,
                network,
            },
        );
        let cli_send_initiator = cli_send_initiator
            .arg("send")
            .arg(&bip21)
            .arg("--fee-rate")
            .arg("1")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to execute payjoin-cli");
        send_until_request_timeout(cli_send_initiator).await?;

        let mut cli_receive_resumer = Command::new(payjoin_cli);
        add_common_args(
            &mut cli_receive_resumer,
            CliCommonArgs {
                cert_path: cert_path.as_deref(),
                pj_directory: Some(&directory),
                rpchost: &receiver_rpchost,
                cookie_file: cookie_file.as_path(),
                db_path: &receiver_db_path,
                ohttp_relay: &ohttp_relay,
                network,
            },
        );
        let cli_receive_resumer = cli_receive_resumer
            .arg("resume")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to execute payjoin-cli");
        respond_with_payjoin(cli_receive_resumer).await?;

        let mut cli_send_resumer = Command::new(payjoin_cli);
        add_common_args(
            &mut cli_send_resumer,
            CliCommonArgs {
                cert_path: cert_path.as_deref(),
                pj_directory: Some(&directory),
                rpchost: &sender_rpchost,
                cookie_file: cookie_file.as_path(),
                db_path: &sender_db_path,
                ohttp_relay: &ohttp_relay,
                network,
            },
        );
        let cli_send_resumer = cli_send_resumer
            .arg("send")
            .arg(&bip21)
            .arg("--fee-rate")
            .arg("1")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to execute payjoin-cli");
        check_payjoin_sent(cli_send_resumer).await?;

        let funding_address = bitcoind
            .client
            .get_new_address(None, None)?
            .address()
            .expect("address should be valid")
            .assume_checked();
        bitcoind.client.generate_to_address(1, &funding_address)?;

        let mut cli_receive_resumer = Command::new(payjoin_cli);
        add_common_args(
            &mut cli_receive_resumer,
            CliCommonArgs {
                cert_path: cert_path.as_deref(),
                pj_directory: Some(&directory),
                rpchost: &receiver_rpchost,
                cookie_file: cookie_file.as_path(),
                db_path: &receiver_db_path,
                ohttp_relay: &ohttp_relay,
                network,
            },
        );
        let cli_receive_resumer = cli_receive_resumer
            .arg("resume")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to execute payjoin-cli");
        check_resume_completed(cli_receive_resumer).await?;

        let mut cli_receive_resumer = Command::new(payjoin_cli);
        add_common_args(
            &mut cli_receive_resumer,
            CliCommonArgs {
                cert_path: cert_path.as_deref(),
                pj_directory: Some(&directory),
                rpchost: &receiver_rpchost,
                cookie_file: cookie_file.as_path(),
                db_path: &receiver_db_path,
                ohttp_relay: &ohttp_relay,
                network,
            },
        );
        let cli_receive_resumer = cli_receive_resumer
            .arg("resume")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to execute payjoin-cli");
        check_resume_has_no_sessions(cli_receive_resumer).await?;

        let mut cli_send_resumer = Command::new(payjoin_cli);
        add_common_args(
            &mut cli_send_resumer,
            CliCommonArgs {
                cert_path: cert_path.as_deref(),
                pj_directory: Some(&directory),
                rpchost: &sender_rpchost,
                cookie_file: cookie_file.as_path(),
                db_path: &sender_db_path,
                ohttp_relay: &ohttp_relay,
                network,
            },
        );
        let cli_send_resumer = cli_send_resumer
            .arg("resume")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to execute payjoin-cli");
        check_resume_has_no_sessions(cli_send_resumer).await?;

        Ok(())
    }

    async fn send_until_request_timeout(
        mut cli_sender: tokio::process::Child,
    ) -> Result<(), BoxError> {
        let mut stdout = cli_sender.stdout.take().expect("failed to take stdout of child process");
        let timeout = tokio::time::Duration::from_secs(35);
        let res = tokio::time::timeout(
            timeout,
            wait_for_stdout_match(&mut stdout, |line| line.contains("No response yet.")),
        )
        .await?;

        terminate(cli_sender).await.expect("Failed to kill payjoin-cli initial sender");
        assert!(res.is_some(), "Fallback send was not detected");
        Ok(())
    }

    async fn respond_with_payjoin(
        mut cli_receive_resumer: tokio::process::Child,
    ) -> Result<(), BoxError> {
        let mut stdout =
            cli_receive_resumer.stdout.take().expect("Failed to take stdout of child process");
        let timeout = tokio::time::Duration::from_secs(10);
        let res = tokio::time::timeout(
            timeout,
            wait_for_stdout_match(&mut stdout, |line| line.contains("Response successful")),
        )
        .await?;

        terminate(cli_receive_resumer).await.expect("Failed to kill payjoin-cli");
        assert!(res.is_some(), "Did not respond with Payjoin PSBT");
        Ok(())
    }

    async fn check_payjoin_sent(
        mut cli_send_resumer: tokio::process::Child,
    ) -> Result<(), BoxError> {
        let mut stdout =
            cli_send_resumer.stdout.take().expect("Failed to take stdout of child process");
        let timeout = tokio::time::Duration::from_secs(10);
        let res = tokio::time::timeout(
            timeout,
            wait_for_stdout_match(&mut stdout, |line| line.contains("Payjoin sent")),
        )
        .await?;

        terminate(cli_send_resumer).await.expect("Failed to kill payjoin-cli");
        assert!(res.is_some(), "Payjoin send was not detected");
        Ok(())
    }

    async fn check_resume_has_no_sessions(
        mut cli_resumer: tokio::process::Child,
    ) -> Result<(), BoxError> {
        let mut stdout = cli_resumer.stdout.take().expect("Failed to take stdout of child process");
        let timeout = tokio::time::Duration::from_secs(10);
        let res = tokio::time::timeout(
            timeout,
            wait_for_stdout_match(&mut stdout, |line| line.contains("No sessions to resume.")),
        )
        .await?;

        terminate(cli_resumer).await.expect("Failed to kill payjoin-cli");
        assert!(res.is_some(), "Expected no sessions to resume");
        Ok(())
    }

    async fn check_resume_completed(
        mut cli_resumer: tokio::process::Child,
    ) -> Result<(), BoxError> {
        let mut stdout = cli_resumer.stdout.take().expect("Failed to take stdout of child process");
        let timeout = tokio::time::Duration::from_secs(10);
        let res = tokio::time::timeout(
            timeout,
            wait_for_stdout_match(&mut stdout, |line| {
                line.contains("All resumed sessions completed.")
            }),
        )
        .await?;

        terminate(cli_resumer).await.expect("Failed to kill payjoin-cli");
        assert!(res.is_some(), "Expected all resumed sessions completed");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_receive_payjoin_v2_over_plain_http_socks_bootstrap(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        init_tracing();
        let mut services = TestServices::initialize_plain_http().await?;
        let temp_dir = tempdir()?;
        let mut socks_proxy = TestSocks5Proxy::start(Socks5AuthMode::NoAuth).await?;
        let network = V2NetworkConfig::socks(socks_proxy.url(), false);

        let result = tokio::select! {
            res = services.take_ohttp_relay_handle() => Err(format!("Ohttp relay is long running: {res:?}").into()),
            res = services.take_directory_handle() => Err(format!("Directory server is long running: {res:?}").into()),
            res = run_v2_e2e(&services, &temp_dir, &network) => res,
        };

        let proxy_records_result =
            assert_socks_proxy_usage(&socks_proxy, &services.ohttp_relay_url(), false).await;
        let proxy_handle = socks_proxy.take_handle();
        proxy_handle.abort();
        let _ = proxy_handle.await;

        assert!(
            proxy_records_result.is_ok(),
            "SOCKS proxy assertions failed: {:#?}",
            proxy_records_result.unwrap_err()
        );
        assert!(result.is_ok(), "send_receive failed: {:#?}", result.unwrap_err());
        Ok(())
    }
}
