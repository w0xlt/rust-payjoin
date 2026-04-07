#[cfg(feature = "_manual-tls")]
mod e2e {
    #[cfg(feature = "v2")]
    use std::collections::{HashMap, HashSet, VecDeque};
    #[cfg(feature = "v2")]
    use std::future::Future;
    #[cfg(feature = "v2")]
    use std::io::ErrorKind;
    use std::process::{ExitStatus, Stdio};
    #[cfg(feature = "v2")]
    use std::time::Instant;

    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    use payjoin_test_utils::{init_bitcoind_sender_receiver, BoxError};
    #[cfg(feature = "v2")]
    use payjoin_test_utils::{Socks5AuthMode, TestServices, TestSocks5Proxy};
    use tempfile::tempdir;
    #[cfg(feature = "v2")]
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::Command;
    #[cfg(feature = "v2")]
    use url::Url;

    async fn terminate(mut child: tokio::process::Child) -> tokio::io::Result<ExitStatus> {
        let pid = child.id().expect("Failed to get child PID");
        kill(Pid::from_raw(pid as i32), Signal::SIGINT)?;
        // wait for child process to exit completely
        child.wait().await
    }

    const RECEIVE_SATS: &str = "54321";
    #[cfg(feature = "v2")]
    const V2_E2E_STEP_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(60);
    #[cfg(feature = "v2")]
    const V2_E2E_LOCK_ADDR: &str = "127.0.0.1:42473";

    #[cfg(feature = "v2")]
    #[derive(Clone, Debug)]
    struct V2NetworkConfig {
        socks_proxy_url: Option<String>,
        tor_stream_isolation: bool,
        preload_ohttp_keys: bool,
    }

    #[cfg(feature = "v2")]
    impl V2NetworkConfig {
        fn direct() -> Self {
            Self { socks_proxy_url: None, tor_stream_isolation: false, preload_ohttp_keys: true }
        }

        fn socks(socks_proxy_url: String, tor_stream_isolation: bool) -> Self {
            Self {
                socks_proxy_url: Some(socks_proxy_url),
                tor_stream_isolation,
                preload_ohttp_keys: false,
            }
        }

        fn apply(&self, command: &mut Command) {
            if let Some(socks_proxy_url) = &self.socks_proxy_url {
                command.arg("--socks-proxy").arg(socks_proxy_url);
            }
            if self.tor_stream_isolation {
                command.arg("--tor-stream-isolation");
            }
        }
    }

    #[cfg(feature = "v2")]
    /// Helper function to extract BIP21 URI from receiver stdout
    async fn get_bip21_from_receiver(mut cli_receiver: tokio::process::Child) -> String {
        let mut stdout =
            cli_receiver.stdout.take().expect("failed to take stdout of child process");
        let bip21 = wait_for_stdout_match(&mut stdout, |line| {
            line.to_ascii_uppercase().starts_with("BITCOIN")
        })
        .await
        .expect("payjoin-cli receiver should output a bitcoin URI");
        tracing::debug!("Got bip21 {}", &bip21);

        terminate(cli_receiver).await.expect("Failed to kill payjoin-cli");
        bip21
    }

    #[cfg(feature = "v2")]
    async fn run_v2_stage<T, F>(stage: &'static str, future: F) -> Result<T, BoxError>
    where
        F: Future<Output = Result<T, BoxError>>,
    {
        let start = Instant::now();
        tracing::info!(stage, "v2 e2e stage started");

        match future.await {
            Ok(value) => {
                tracing::info!(
                    stage,
                    elapsed_ms = start.elapsed().as_millis(),
                    "v2 e2e stage completed"
                );
                Ok(value)
            }
            Err(err) => {
                tracing::error!(
                    stage,
                    elapsed_ms = start.elapsed().as_millis(),
                    error = %err,
                    "v2 e2e stage failed"
                );
                Err(format!(
                    "stage `{stage}` failed after {} ms: {err}",
                    start.elapsed().as_millis()
                )
                .into())
            }
        }
    }

    #[cfg(feature = "v2")]
    async fn acquire_v2_e2e_process_lock(
    ) -> Result<tokio::net::TcpListener, Box<dyn std::error::Error + Send + Sync>> {
        let start = Instant::now();
        let mut wait_logged = false;

        loop {
            match tokio::net::TcpListener::bind(V2_E2E_LOCK_ADDR).await {
                Ok(listener) => {
                    tracing::info!(
                        elapsed_ms = start.elapsed().as_millis(),
                        lock_addr = V2_E2E_LOCK_ADDR,
                        "acquired v2 e2e cross-process lock"
                    );
                    return Ok(listener);
                }
                Err(err) if err.kind() == ErrorKind::AddrInUse => {
                    if !wait_logged {
                        tracing::info!(
                            lock_addr = V2_E2E_LOCK_ADDR,
                            "waiting for v2 e2e cross-process lock"
                        );
                        wait_logged = true;
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
                }
                Err(err) => {
                    return Err(format!(
                        "failed to acquire v2 e2e cross-process lock on {}: {}",
                        V2_E2E_LOCK_ADDR, err
                    )
                    .into());
                }
            }
        }
    }

    #[cfg(feature = "v2")]
    /// Read lines from `child_stdout` until `match_pattern` is found and the corresponding
    /// line is returned.
    /// Also writes every read line to tokio::io::stdout();
    async fn wait_for_stdout_match<F>(
        child_stdout: &mut tokio::process::ChildStdout,
        match_pattern: F,
    ) -> Option<String>
    where
        F: Fn(&str) -> bool,
    {
        let reader = BufReader::new(child_stdout);
        let mut lines = reader.lines();
        let mut res = None;

        let mut stdout = tokio::io::stdout();
        while let Some(line) = lines.next_line().await.expect("Failed to read line from stdout") {
            // Write all output to tests stdout
            stdout
                .write_all(format!("{line}\n").as_bytes())
                .await
                .expect("Failed to write to stdout");

            if match_pattern(&line) {
                res = Some(line);
                break;
            }
        }

        res
    }

    #[cfg(feature = "v2")]
    async fn wait_for_stdout_match_with_timeout<F>(
        stage: &'static str,
        child_stdout: &mut tokio::process::ChildStdout,
        expected_output: &'static str,
        match_pattern: F,
    ) -> Result<String, BoxError>
    where
        F: Fn(&str) -> bool,
    {
        let start = Instant::now();
        let deadline = tokio::time::Instant::now() + V2_E2E_STEP_TIMEOUT;
        let reader = BufReader::new(child_stdout);
        let mut lines = reader.lines();
        let mut recent_lines = VecDeque::with_capacity(8);
        let mut stdout = tokio::io::stdout();

        let recent_output = |lines: &VecDeque<String>| -> String {
            if lines.is_empty() {
                "<no output captured>".to_string()
            } else {
                lines
                    .iter()
                    .enumerate()
                    .map(|(idx, line)| format!("[{idx}] {line}"))
                    .collect::<Vec<_>>()
                    .join(" | ")
            }
        };

        let matched_line = loop {
            match tokio::time::timeout_at(deadline, lines.next_line()).await {
                Err(_) => {
                    return Err(format!(
                        "stage `{stage}` timed out after {} s waiting for `{expected_output}`; recent output: {}",
                        V2_E2E_STEP_TIMEOUT.as_secs(),
                        recent_output(&recent_lines),
                    )
                    .into());
                }
                Ok(Ok(Some(line))) => {
                    if recent_lines.len() == recent_lines.capacity() {
                        let _ = recent_lines.pop_front();
                    }
                    recent_lines.push_back(line.clone());

                    stdout
                        .write_all(format!("{line}\n").as_bytes())
                        .await
                        .expect("Failed to write to stdout");

                    if match_pattern(&line) {
                        break line;
                    }
                }
                Ok(Ok(None)) => {
                    return Err(format!(
                        "stage `{stage}` reached EOF after {} ms waiting for `{expected_output}`; recent output: {}",
                        start.elapsed().as_millis(),
                        recent_output(&recent_lines),
                    )
                    .into());
                }
                Ok(Err(err)) => {
                    return Err(format!(
                        "stage `{stage}` failed reading stdout after {} ms while waiting for `{expected_output}`: {}; recent output: {}",
                        start.elapsed().as_millis(),
                        err,
                        recent_output(&recent_lines),
                    )
                    .into());
                }
            }
        };

        tracing::info!(
            stage,
            elapsed_ms = start.elapsed().as_millis(),
            matched_line = %matched_line,
            "v2 e2e stage observed expected output"
        );
        Ok(matched_line)
    }

    #[cfg(feature = "v2")]
    async fn run_v2_e2e(
        services: &TestServices,
        temp_dir: &TempDir,
        network: &V2NetworkConfig,
    ) -> Result<(), BoxError> {
        let receiver_db_path = temp_dir.path().join("receiver_db");
        let sender_db_path = temp_dir.path().join("sender_db");
        let (bitcoind, _sender, _receiver) = init_bitcoind_sender_receiver(None, None)?;
        let cert_path = &temp_dir.path().join("localhost.der");
        tokio::fs::write(cert_path, services.cert()).await?;
        services.wait_for_services_ready().await?;

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

        let directory = &services.directory_url();
        let ohttp_relay = &services.ohttp_relay_url();

        let mut cli_receive_initiator = Command::new(payjoin_cli);
        cli_receive_initiator
            .arg("--root-certificate")
            .arg(cert_path)
            .arg("--rpchost")
            .arg(&receiver_rpchost)
            .arg("--cookie-file")
            .arg(cookie_file)
            .arg("--db-path")
            .arg(&receiver_db_path)
            .arg("--ohttp-relays")
            .arg(ohttp_relay);
        network.apply(&mut cli_receive_initiator);
        cli_receive_initiator.arg("receive").arg(RECEIVE_SATS).arg("--pj-directory").arg(directory);
        if let Some(ohttp_keys_path) = &ohttp_keys_path {
            cli_receive_initiator.arg("--ohttp-keys").arg(ohttp_keys_path);
        }
        let cli_receive_initiator = cli_receive_initiator
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to execute payjoin-cli");
        let bip21 = run_v2_stage("receiver_emits_bip21", async move {
            Ok(get_bip21_from_receiver(cli_receive_initiator).await)
        })
        .await?;

        let mut cli_send_initiator = Command::new(payjoin_cli);
        cli_send_initiator
            .arg("--root-certificate")
            .arg(cert_path)
            .arg("--rpchost")
            .arg(&sender_rpchost)
            .arg("--cookie-file")
            .arg(cookie_file)
            .arg("--db-path")
            .arg(&sender_db_path)
            .arg("--ohttp-relays")
            .arg(ohttp_relay);
        network.apply(&mut cli_send_initiator);
        let cli_send_initiator = cli_send_initiator
            .arg("send")
            .arg(&bip21)
            .arg("--fee-rate")
            .arg("1")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to execute payjoin-cli");
        run_v2_stage(
            "sender_initial_waits_for_receiver_poll",
            send_until_request_timeout(
                "sender_initial_waits_for_receiver_poll",
                cli_send_initiator,
            ),
        )
        .await?;

        let mut cli_receive_resumer = Command::new(payjoin_cli);
        cli_receive_resumer
            .arg("--root-certificate")
            .arg(cert_path)
            .arg("--rpchost")
            .arg(&receiver_rpchost)
            .arg("--cookie-file")
            .arg(cookie_file)
            .arg("--db-path")
            .arg(&receiver_db_path)
            .arg("--ohttp-relays")
            .arg(ohttp_relay);
        network.apply(&mut cli_receive_resumer);
        let cli_receive_resumer = cli_receive_resumer
            .arg("resume")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to execute payjoin-cli");
        run_v2_stage(
            "receiver_resume_posts_payjoin_proposal",
            respond_with_payjoin("receiver_resume_posts_payjoin_proposal", cli_receive_resumer),
        )
        .await?;

        let mut cli_send_resumer = Command::new(payjoin_cli);
        cli_send_resumer
            .arg("--root-certificate")
            .arg(cert_path)
            .arg("--rpchost")
            .arg(&sender_rpchost)
            .arg("--cookie-file")
            .arg(cookie_file)
            .arg("--db-path")
            .arg(&sender_db_path)
            .arg("--ohttp-relays")
            .arg(ohttp_relay);
        network.apply(&mut cli_send_resumer);
        let cli_send_resumer = cli_send_resumer
            .arg("send")
            .arg(&bip21)
            .arg("--fee-rate")
            .arg("1")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to execute payjoin-cli");
        run_v2_stage(
            "sender_resume_broadcasts_payjoin",
            check_payjoin_sent("sender_resume_broadcasts_payjoin", cli_send_resumer),
        )
        .await?;

        let funding_address = bitcoind
            .client
            .get_new_address(None, None)?
            .address()
            .expect("address should be valid")
            .assume_checked();
        run_v2_stage("bitcoind_confirms_payjoin", async {
            bitcoind.client.generate_to_address(1, &funding_address)?;
            Ok(())
        })
        .await?;

        let mut cli_receive_resumer = Command::new(payjoin_cli);
        cli_receive_resumer
            .arg("--root-certificate")
            .arg(cert_path)
            .arg("--rpchost")
            .arg(&receiver_rpchost)
            .arg("--cookie-file")
            .arg(cookie_file)
            .arg("--db-path")
            .arg(&receiver_db_path)
            .arg("--ohttp-relays")
            .arg(ohttp_relay);
        network.apply(&mut cli_receive_resumer);
        let cli_receive_resumer = cli_receive_resumer
            .arg("resume")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to execute payjoin-cli");

        run_v2_stage(
            "receiver_resume_observes_confirmed_payjoin",
            check_resume_completed(
                "receiver_resume_observes_confirmed_payjoin",
                cli_receive_resumer,
            ),
        )
        .await?;

        let mut cli_receive_resumer = Command::new(payjoin_cli);
        cli_receive_resumer
            .arg("--root-certificate")
            .arg(cert_path)
            .arg("--rpchost")
            .arg(&receiver_rpchost)
            .arg("--cookie-file")
            .arg(cookie_file)
            .arg("--db-path")
            .arg(&receiver_db_path)
            .arg("--ohttp-relays")
            .arg(ohttp_relay);
        network.apply(&mut cli_receive_resumer);
        let cli_receive_resumer = cli_receive_resumer
            .arg("resume")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to execute payjoin-cli");
        run_v2_stage(
            "receiver_resume_reports_no_sessions",
            check_resume_has_no_sessions(
                "receiver_resume_reports_no_sessions",
                cli_receive_resumer,
            ),
        )
        .await?;

        let mut cli_send_resumer = Command::new(payjoin_cli);
        cli_send_resumer
            .arg("--root-certificate")
            .arg(cert_path)
            .arg("--rpchost")
            .arg(&sender_rpchost)
            .arg("--cookie-file")
            .arg(cookie_file)
            .arg("--db-path")
            .arg(&sender_db_path)
            .arg("--ohttp-relays")
            .arg(ohttp_relay);
        network.apply(&mut cli_send_resumer);
        let cli_send_resumer = cli_send_resumer
            .arg("resume")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to execute payjoin-cli");
        run_v2_stage(
            "sender_resume_reports_no_sessions",
            check_resume_has_no_sessions("sender_resume_reports_no_sessions", cli_send_resumer),
        )
        .await?;

        Ok(())
    }

    #[cfg(feature = "v2")]
    async fn send_until_request_timeout(
        stage: &'static str,
        mut cli_sender: tokio::process::Child,
    ) -> Result<(), BoxError> {
        let mut stdout = cli_sender.stdout.take().expect("failed to take stdout of child process");
        wait_for_stdout_match_with_timeout(stage, &mut stdout, "No response yet.", |line| {
            line.contains("No response yet.")
        })
        .await?;
        terminate(cli_sender).await.expect("Failed to kill payjoin-cli initial sender");
        Ok(())
    }

    #[cfg(feature = "v2")]
    async fn respond_with_payjoin(
        stage: &'static str,
        mut cli_receive_resumer: tokio::process::Child,
    ) -> Result<(), BoxError> {
        let mut stdout =
            cli_receive_resumer.stdout.take().expect("Failed to take stdout of child process");
        wait_for_stdout_match_with_timeout(stage, &mut stdout, "Response successful", |line| {
            line.contains("Response successful")
        })
        .await?;
        terminate(cli_receive_resumer).await.expect("Failed to kill payjoin-cli");
        Ok(())
    }

    #[cfg(feature = "v2")]
    async fn check_payjoin_sent(
        stage: &'static str,
        mut cli_send_resumer: tokio::process::Child,
    ) -> Result<(), BoxError> {
        let mut stdout =
            cli_send_resumer.stdout.take().expect("Failed to take stdout of child process");
        wait_for_stdout_match_with_timeout(stage, &mut stdout, "Payjoin sent", |line| {
            line.contains("Payjoin sent")
        })
        .await?;
        terminate(cli_send_resumer).await.expect("Failed to kill payjoin-cli");
        Ok(())
    }

    #[cfg(feature = "v2")]
    async fn check_resume_has_no_sessions(
        stage: &'static str,
        mut cli_resumer: tokio::process::Child,
    ) -> Result<(), BoxError> {
        let mut stdout = cli_resumer.stdout.take().expect("Failed to take stdout of child process");
        wait_for_stdout_match_with_timeout(stage, &mut stdout, "No sessions to resume.", |line| {
            line.contains("No sessions to resume.")
        })
        .await?;
        terminate(cli_resumer).await.expect("Failed to kill payjoin-cli");
        Ok(())
    }

    #[cfg(feature = "v2")]
    async fn check_resume_completed(
        stage: &'static str,
        mut cli_resumer: tokio::process::Child,
    ) -> Result<(), BoxError> {
        let mut stdout = cli_resumer.stdout.take().expect("Failed to take stdout of child process");
        wait_for_stdout_match_with_timeout(
            stage,
            &mut stdout,
            "All resumed sessions completed.",
            |line| line.contains("All resumed sessions completed."),
        )
        .await?;
        terminate(cli_resumer).await.expect("Failed to kill payjoin-cli");
        Ok(())
    }

    #[cfg(feature = "v2")]
    async fn assert_socks_proxy_usage(
        proxy: &TestSocks5Proxy,
        relay_url: &str,
        expect_auth: bool,
    ) -> Result<(), BoxError> {
        let relay_port =
            Url::parse(relay_url)?.port_or_known_default().expect("relay URL should have a port");
        let records = proxy.records().await;
        assert!(
            records.iter().any(|record| record.target_port == relay_port),
            "expected at least one SOCKS connection to the relay port {relay_port}, got {records:?}"
        );

        if expect_auth {
            let auth_records: Vec<_> = records
                .iter()
                .filter(|record| record.target_port == relay_port && record.username.is_some())
                .collect();
            assert!(
                !auth_records.is_empty(),
                "expected SOCKS username/password auth records, got {records:?}"
            );
            assert!(
                auth_records.iter().all(|record| record
                    .password
                    .as_deref()
                    .is_some_and(|password| !password.is_empty())),
                "expected every authenticated SOCKS record to include a password, got {records:?}"
            );
            let distinct_usernames = auth_records
                .iter()
                .filter_map(|record| record.username.clone())
                .collect::<HashSet<_>>();
            let username_counts =
                auth_records.iter().fold(HashMap::<String, usize>::new(), |mut counts, record| {
                    let username = record
                        .username
                        .clone()
                        .expect("authenticated records should have usernames");
                    *counts.entry(username).or_default() += 1;
                    counts
                });
            assert!(
                distinct_usernames.len() == 2,
                "expected one SOCKS username per sender/receiver session, got {distinct_usernames:?}"
            );
            assert!(
                username_counts.values().all(|count| *count > 1),
                "expected each session SOCKS username to be reused across multiple relay requests, got {username_counts:?}"
            );
        } else {
            assert!(
                records.iter().all(|record| record.username.is_none() && record.password.is_none()),
                "expected unauthenticated SOCKS connections, got {records:?}"
            );
        }

        Ok(())
    }

    #[cfg(feature = "v1")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_receive_payjoin_v1() -> Result<(), BoxError> {
        use payjoin_test_utils::local_cert_key;

        let (bitcoind, _sender, _receiver) = init_bitcoind_sender_receiver(None, None)?;
        let temp_dir = tempdir()?;
        let receiver_db_path = temp_dir.path().join("receiver_db");
        let sender_db_path = temp_dir.path().join("sender_db");

        let payjoin_sent = tokio::spawn(async move {
            let receiver_rpchost = format!("http://{}/wallet/receiver", bitcoind.params.rpc_socket);
            let sender_rpchost = format!("http://{}/wallet/sender", bitcoind.params.rpc_socket);
            let cookie_file = &bitcoind.params.cookie_file;
            let pj_endpoint = "https://localhost";
            let payjoin_cli = env!("CARGO_BIN_EXE_payjoin-cli");

            let cert = local_cert_key();
            let cert_path = &temp_dir.path().join("localhost.crt");
            tokio::fs::write(cert_path, cert.cert.der().to_vec())
                .await
                .expect("must be able to write self signed certificate");

            let key_path = &temp_dir.path().join("localhost.key");
            tokio::fs::write(key_path, cert.signing_key.serialize_der())
                .await
                .expect("must be able to write self signed certificate");

            let mut cli_receiver = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--certificate-key")
                .arg(key_path)
                .arg("--bip78")
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path)
                .arg("receive")
                .arg(RECEIVE_SATS)
                .arg("--port")
                .arg("0")
                .arg("--pj-endpoint")
                .arg(pj_endpoint)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");

            let stdout =
                cli_receiver.stdout.take().expect("Failed to take stdout of child process");
            let reader = BufReader::new(stdout);
            let mut stdout = tokio::io::stdout();
            let mut bip21 = String::new();

            let mut lines = reader.lines();

            while let Some(line) = lines.next_line().await.expect("Failed to read line from stdout")
            {
                // Write to stdout regardless
                stdout
                    .write_all(format!("{line}\n").as_bytes())
                    .await
                    .expect("Failed to write to stdout");

                if line.to_ascii_uppercase().starts_with("BITCOIN") {
                    bip21 = line;
                    break;
                }
            }
            tracing::debug!("Got bip21 {}", &bip21);

            let mut cli_sender = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--bip78")
                .arg("--rpchost")
                .arg(&sender_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&sender_db_path)
                .arg("send")
                .arg(&bip21)
                .arg("--fee-rate")
                .arg("1")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");

            let stdout = cli_sender.stdout.take().expect("Failed to take stdout of child process");
            let reader = BufReader::new(stdout);
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);

            let mut lines = reader.lines();
            tokio::spawn(async move {
                let mut stdout = tokio::io::stdout();
                while let Some(line) =
                    lines.next_line().await.expect("Failed to read line from stdout")
                {
                    stdout
                        .write_all(format!("{line}\n").as_bytes())
                        .await
                        .expect("Failed to write to stdout");
                    if line.contains("Payjoin sent") {
                        let _ = tx.send(true).await;
                        break;
                    }
                }
            });

            let timeout = tokio::time::Duration::from_secs(10);
            let payjoin_sent = tokio::time::timeout(timeout, rx.recv())
                .await
                .unwrap_or(Some(false)) // timed out
                .expect("rx channel closed prematurely"); // recv() returned None

            terminate(cli_receiver).await.expect("Failed to kill payjoin-cli");
            terminate(cli_sender).await.expect("Failed to kill payjoin-cli");

            payjoin_sent
        })
        .await?;

        assert!(payjoin_sent, "Payjoin send was not detected");

        Ok(())
    }

    #[cfg(feature = "v2")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_receive_payjoin_v2() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use payjoin_test_utils::init_tracing;

        init_tracing();
        let _serial_guard = acquire_v2_e2e_process_lock().await?;
        let mut services = TestServices::initialize().await?;
        let temp_dir = tempdir()?;
        let network = V2NetworkConfig::direct();

        let result = tokio::select! {
            res = services.take_ohttp_relay_handle() => Err(format!("Ohttp relay is long running: {res:?}").into()),
            res = services.take_directory_handle() => Err(format!("Directory server is long running: {res:?}").into()),
            res = run_v2_e2e(&services, &temp_dir, &network) => res,
        };

        assert!(result.is_ok(), "send_receive failed: {:#?}", result.unwrap_err());
        Ok(())
    }

    #[cfg(feature = "v2")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_receive_payjoin_v2_over_socks_bootstrap(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use payjoin_test_utils::init_tracing;

        init_tracing();
        let _serial_guard = acquire_v2_e2e_process_lock().await?;
        let mut services = TestServices::initialize().await?;
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

    #[cfg(feature = "v2")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_receive_payjoin_v2_over_socks_with_tor_stream_isolation(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use payjoin_test_utils::init_tracing;

        init_tracing();
        let _serial_guard = acquire_v2_e2e_process_lock().await?;
        let mut services = TestServices::initialize().await?;
        let temp_dir = tempdir()?;
        let mut socks_proxy = TestSocks5Proxy::start(Socks5AuthMode::UsernamePassword).await?;
        let network = V2NetworkConfig::socks(socks_proxy.url(), true);

        let result = tokio::select! {
            res = services.take_ohttp_relay_handle() => Err(format!("Ohttp relay is long running: {res:?}").into()),
            res = services.take_directory_handle() => Err(format!("Directory server is long running: {res:?}").into()),
            res = run_v2_e2e(&services, &temp_dir, &network) => res,
        };

        let proxy_records_result =
            assert_socks_proxy_usage(&socks_proxy, &services.ohttp_relay_url(), true).await;
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

    #[cfg(all(feature = "v1", feature = "v2", feature = "_manual-tls"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_receive_payjoin_v2_to_v1() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        use payjoin_test_utils::{init_tracing, local_cert_key, TestServices};
        use tempfile::TempDir;

        type Result<T> = std::result::Result<T, BoxError>;

        init_tracing();
        let _serial_guard = acquire_v2_e2e_process_lock().await?;
        let services = TestServices::initialize().await?;
        let temp_dir = tempdir()?;

        let result = send_v2_receive_v1_async(&services, &temp_dir).await;
        assert!(result.is_ok(), "v2-to-v1 test failed: {:#?}", result.unwrap_err());

        async fn send_v2_receive_v1_async(
            services: &TestServices,
            temp_dir: &TempDir,
        ) -> Result<()> {
            let receiver_db_path = temp_dir.path().join("receiver_db");
            let sender_db_path = temp_dir.path().join("sender_db");
            let (bitcoind, _sender, _receiver) = init_bitcoind_sender_receiver(None, None)?;

            // Set up certificates for v1 receiver (needs local HTTPS server)
            let cert = local_cert_key();
            let cert_path = &temp_dir.path().join("localhost.crt");
            tokio::fs::write(cert_path, cert.cert.der().to_vec())
                .await
                .expect("must be able to write self signed certificate");

            let key_path = &temp_dir.path().join("localhost.key");
            tokio::fs::write(key_path, cert.signing_key.serialize_der())
                .await
                .expect("must be able to write self signed certificate");

            // Set up v2 services certificates for v2 sender (even though it will fall back to v1)
            let v2_cert_path = &temp_dir.path().join("localhost.der");
            tokio::fs::write(v2_cert_path, services.cert()).await?;
            services.wait_for_services_ready().await?;

            let receiver_rpchost = format!("http://{}/wallet/receiver", bitcoind.params.rpc_socket);
            let sender_rpchost = format!("http://{}/wallet/sender", bitcoind.params.rpc_socket);
            let cookie_file = &bitcoind.params.cookie_file;

            let payjoin_cli = env!("CARGO_BIN_EXE_payjoin-cli");
            let pj_endpoint = "https://localhost";

            // Start v1 receiver with --bip78 flag and keep it running
            let mut cli_receive_v1 = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--certificate-key")
                .arg(key_path)
                .arg("--bip78") // Force BIP78 (v1) mode
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path)
                .arg("receive")
                .arg(RECEIVE_SATS)
                .arg("--port")
                .arg("0")
                .arg("--pj-endpoint")
                .arg(pj_endpoint)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli v1 receiver");

            // Extract BIP21 from receiver stdout without terminating the receiver
            let stdout =
                cli_receive_v1.stdout.take().expect("Failed to take stdout of child process");
            let reader = BufReader::new(stdout);
            let mut stdout_writer = tokio::io::stdout();
            let mut bip21 = String::new();
            let mut lines = reader.lines();

            while let Some(line) = lines.next_line().await.expect("Failed to read line from stdout")
            {
                // Write to stdout regardless
                stdout_writer
                    .write_all(format!("{line}\n").as_bytes())
                    .await
                    .expect("Failed to write to stdout");

                if line.to_ascii_uppercase().starts_with("BITCOIN") {
                    bip21 = line;
                    break;
                }
            }
            tracing::debug!("Got v1 bip21 from receiver: {}", &bip21);

            // Start v2 sender (default behavior without --bip78)
            // This will detect the v1 URI and automatically use v1 protocol
            let mut cli_send_v2 = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path) // Use same cert since v2 sender will fallback to v1 protocol
                .arg("--rpchost")
                .arg(&sender_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&sender_db_path)
                .arg("--ohttp-relays")
                .arg(services.ohttp_relay_url())
                .arg("send")
                .arg(&bip21)
                .arg("--fee-rate")
                .arg("1")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli v2 sender");

            // Check that v2 sender successfully completes the v1 payjoin
            let sender_stdout =
                cli_send_v2.stdout.take().expect("Failed to take stdout of child process");
            let sender_reader = BufReader::new(sender_stdout);
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);

            let mut sender_lines = sender_reader.lines();
            tokio::spawn(async move {
                let mut stdout = tokio::io::stdout();
                while let Some(line) =
                    sender_lines.next_line().await.expect("Failed to read line from stdout")
                {
                    stdout
                        .write_all(format!("{line}\n").as_bytes())
                        .await
                        .expect("Failed to write to stdout");
                    if line.contains("Payjoin sent") {
                        let _ = tx.send(true).await;
                        break;
                    }
                }
            });

            let timeout = tokio::time::Duration::from_secs(30);
            let payjoin_sent = tokio::time::timeout(timeout, rx.recv())
                .await
                .unwrap_or(Some(false)) // timed out
                .expect("rx channel closed prematurely"); // recv() returned None

            // Clean up both processes
            terminate(cli_receive_v1).await.expect("Failed to kill payjoin-cli v1 receiver");
            terminate(cli_send_v2).await.expect("Failed to kill payjoin-cli v2 sender");

            assert!(payjoin_sent, "Expected payjoin completion or fallback transaction");

            Ok(())
        }

        Ok(())
    }
}
