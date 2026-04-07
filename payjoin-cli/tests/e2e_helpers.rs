use std::collections::{HashMap, HashSet};
use std::process::ExitStatus;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use payjoin_test_utils::{BoxError, TestSocks5Proxy};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use url::Url;

pub const RECEIVE_SATS: &str = "54321";

pub async fn terminate(mut child: tokio::process::Child) -> tokio::io::Result<ExitStatus> {
    let pid = child.id().expect("Failed to get child PID");
    kill(Pid::from_raw(pid as i32), Signal::SIGINT)?;
    child.wait().await
}

#[derive(Clone, Debug)]
pub struct V2NetworkConfig {
    pub socks_proxy_url: Option<String>,
    pub tor_stream_isolation: bool,
    pub preload_ohttp_keys: bool,
}

impl V2NetworkConfig {
    pub fn direct() -> Self {
        Self { socks_proxy_url: None, tor_stream_isolation: false, preload_ohttp_keys: true }
    }

    pub fn socks(socks_proxy_url: String, tor_stream_isolation: bool) -> Self {
        Self {
            socks_proxy_url: Some(socks_proxy_url),
            tor_stream_isolation,
            preload_ohttp_keys: false,
        }
    }

    pub fn apply(&self, command: &mut Command) {
        if let Some(socks_proxy_url) = &self.socks_proxy_url {
            command.arg("--socks-proxy").arg(socks_proxy_url);
        }
        if self.tor_stream_isolation {
            command.arg("--tor-stream-isolation");
        }
    }
}

/// Read lines from `child_stdout` until `match_pattern` returns true.
/// Every line is echoed to the test's stdout.
pub async fn wait_for_stdout_match<F>(
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

pub async fn get_bip21_from_receiver(mut cli_receiver: tokio::process::Child) -> String {
    let mut stdout = cli_receiver.stdout.take().expect("failed to take stdout of child process");
    let bip21 = wait_for_stdout_match(&mut stdout, |line| {
        line.to_ascii_uppercase().starts_with("BITCOIN")
    })
    .await
    .expect("payjoin-cli receiver should output a bitcoin URI");
    tracing::debug!("Got bip21 {}", &bip21);

    terminate(cli_receiver).await.expect("Failed to kill payjoin-cli");
    bip21
}

pub async fn assert_socks_proxy_usage(
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
