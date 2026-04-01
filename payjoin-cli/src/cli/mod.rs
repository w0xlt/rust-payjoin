use std::path::PathBuf;

use clap::{value_parser, Parser, Subcommand};
use payjoin::bitcoin::amount::ParseAmountError;
use payjoin::bitcoin::{Amount, FeeRate};
use payjoin::Url;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Parser)]
pub struct Flags {
    #[arg(long = "bip77", help = "Use BIP77 (v2) protocol (default)", action = clap::ArgAction::SetTrue)]
    pub bip77: Option<bool>,
    #[arg(long = "bip78", help = "Use BIP78 (v1) protocol", action = clap::ArgAction::SetTrue)]
    pub bip78: Option<bool>,
}

#[derive(Debug, Parser)]
#[command(
    version = env!("CARGO_PKG_VERSION"),
    about = "Payjoin - bitcoin scaling, savings, and privacy by default",
    long_about = None,
    subcommand_required = true
)]
pub struct Cli {
    #[command(flatten)]
    pub flags: Flags,

    #[command(subcommand)]
    pub command: Commands,

    #[arg(long, short = 'd', help = "Sets a custom database path")]
    pub db_path: Option<PathBuf>,

    #[arg(long = "max-fee-rate", short = 'f', help = "The maximum fee rate to accept in sat/vB")]
    pub max_fee_rate: Option<FeeRate>,

    #[arg(
        long,
        short = 'r',
        num_args(1),
        help = "The URL of the Bitcoin RPC host, e.g. regtest default is http://localhost:18443"
    )]
    pub rpchost: Option<Url>,

    #[arg(
        long = "cookie-file",
        short = 'c',
        num_args(1),
        help = "Path to the cookie file of the bitcoin node"
    )]
    pub cookie_file: Option<PathBuf>,

    #[arg(long = "rpcuser", num_args(1), help = "The username for the bitcoin node")]
    pub rpcuser: Option<String>,

    #[arg(long = "rpcpassword", num_args(1), help = "The password for the bitcoin node")]
    pub rpcpassword: Option<String>,

    #[cfg(feature = "v1")]
    #[arg(long = "port", help = "The local port to listen on")]
    pub port: Option<u16>,

    #[cfg(feature = "v1")]
    #[arg(long = "pj-endpoint", help = "The `pj=` endpoint to receive the payjoin request", value_parser = value_parser!(Url))]
    pub pj_endpoint: Option<Url>,

    #[cfg(feature = "v2")]
    #[arg(long = "ohttp-relays", help = "One or more ohttp relay URLs, comma-separated", value_parser = value_parser!(Url), value_delimiter = ',', action = clap::ArgAction::Append)]
    pub ohttp_relays: Option<Vec<Url>>,

    #[cfg(feature = "v2")]
    #[arg(long = "ohttp-keys", help = "The ohttp key config file path", value_parser = value_parser!(PathBuf))]
    pub ohttp_keys: Option<PathBuf>,

    #[cfg(feature = "v2")]
    #[arg(long = "pj-directory", help = "The directory to store payjoin requests", value_parser = value_parser!(Url))]
    pub pj_directory: Option<Url>,

    #[cfg(feature = "v2")]
    #[arg(
        long = "socks-proxy",
        help = "SOCKS5h proxy URL for BIP77 relay traffic",
        value_parser = value_parser!(url::Url),
        global = true
    )]
    pub socks_proxy: Option<url::Url>,

    #[cfg(feature = "v2")]
    #[arg(
        long = "tor-stream-isolation",
        help = "Request Tor stream isolation by generating per-session SOCKS credentials",
        action = clap::ArgAction::Set,
        num_args(0),
        default_missing_value = "true",
        global = true
    )]
    pub tor_stream_isolation: Option<bool>,

    #[cfg(feature = "_manual-tls")]
    #[arg(long = "root-certificate", help = "Specify a TLS certificate to be added as a root", value_parser = value_parser!(PathBuf))]
    pub root_certificate: Option<PathBuf>,

    #[cfg(feature = "_manual-tls")]
    #[arg(long = "certificate-key", help = "Specify the certificate private key", value_parser = value_parser!(PathBuf))]
    pub certificate_key: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Send a payjoin payment
    Send {
        /// The `bitcoin:...` payjoin uri to send to
        #[arg(required = true)]
        bip21: String,

        /// Fee rate in sat/vB
        #[arg(required = true, short, long = "fee-rate", value_parser = parse_fee_rate_in_sat_per_vb)]
        fee_rate: FeeRate,
    },
    /// Receive a payjoin payment
    Receive {
        /// The amount to receive in satoshis
        #[arg(required = true, value_parser = parse_amount_in_sat)]
        amount: Amount,

        /// The maximum effective fee rate the receiver is willing to pay (in sat/vB)
        #[arg(short, long = "max-fee-rate", value_parser = parse_fee_rate_in_sat_per_vb)]
        max_fee_rate: Option<FeeRate>,

        #[cfg(feature = "v1")]
        /// The local port to listen on
        #[arg(short, long = "port")]
        port: Option<u16>,

        #[cfg(feature = "v1")]
        /// The `pj=` endpoint to receive the payjoin request
        #[arg(long = "pj-endpoint", value_parser = parse_boxed_url)]
        pj_endpoint: Option<Box<Url>>,

        #[cfg(feature = "v2")]
        /// The directory to store payjoin requests
        #[arg(long = "pj-directory", value_parser = parse_boxed_url)]
        pj_directory: Option<Box<Url>>,

        #[cfg(feature = "v2")]
        /// The path to the ohttp keys file
        #[arg(long = "ohttp-keys", value_parser = value_parser!(PathBuf))]
        ohttp_keys: Option<PathBuf>,
    },
    /// Resume pending payjoins (BIP77/v2 only)
    #[cfg(feature = "v2")]
    Resume,
    #[cfg(feature = "v2")]
    /// Show payjoin session history
    History,
}

pub fn parse_amount_in_sat(s: &str) -> Result<Amount, ParseAmountError> {
    Amount::from_str_in(s, payjoin::bitcoin::Denomination::Satoshi)
}

pub fn parse_fee_rate_in_sat_per_vb(s: &str) -> Result<FeeRate, std::num::ParseFloatError> {
    let fee_rate_sat_per_vb: f32 = s.parse()?;
    let fee_rate_sat_per_kwu = fee_rate_sat_per_vb * 250.0_f32;
    Ok(FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu.ceil() as u64))
}

fn parse_boxed_url(s: &str) -> Result<Box<Url>, String> {
    s.parse::<Url>().map(Box::new).map_err(|e| e.to_string())
}

#[cfg(all(test, feature = "v2"))]
mod tests {
    use clap::Parser;

    use super::{Cli, Commands};

    #[test]
    fn receive_accepts_socks_proxy_after_subcommand() {
        let cli = Cli::try_parse_from([
            "payjoin-cli",
            "receive",
            "--socks-proxy",
            "socks5h://127.0.0.1:9050",
            "1000",
        ])
        .expect("receive subcommand should accept global SOCKS proxy flag");

        assert_socks_proxy_endpoint(cli.socks_proxy.as_ref());
        assert!(matches!(cli.command, Commands::Receive { .. }));
    }

    #[test]
    fn send_accepts_socks_proxy_after_subcommand() {
        let cli = Cli::try_parse_from([
            "payjoin-cli",
            "send",
            "--socks-proxy",
            "socks5h://127.0.0.1:9050",
            "bitcoin:tb1qexample?amount=0.001",
            "--fee-rate",
            "1",
        ])
        .expect("send subcommand should accept global SOCKS proxy flag");

        assert_socks_proxy_endpoint(cli.socks_proxy.as_ref());
        assert!(matches!(cli.command, Commands::Send { .. }));
    }

    #[test]
    fn receive_accepts_tor_stream_isolation_after_subcommand() {
        let cli = Cli::try_parse_from([
            "payjoin-cli",
            "receive",
            "--tor-stream-isolation",
            "--socks-proxy",
            "socks5h://127.0.0.1:9050",
            "1000",
        ])
        .expect("receive subcommand should accept global Tor stream isolation flag");

        assert_eq!(cli.tor_stream_isolation, Some(true));
        assert_socks_proxy_endpoint(cli.socks_proxy.as_ref());
        assert!(matches!(cli.command, Commands::Receive { .. }));
    }

    #[test]
    fn omitted_tor_stream_isolation_remains_unset() {
        let cli = Cli::try_parse_from([
            "payjoin-cli",
            "receive",
            "--socks-proxy",
            "socks5h://127.0.0.1:9050",
            "1000",
        ])
        .expect("receive subcommand should parse without Tor stream isolation flag");

        assert_eq!(cli.tor_stream_isolation, None);
    }

    fn assert_socks_proxy_endpoint(socks_proxy: Option<&url::Url>) {
        let socks_proxy = socks_proxy.expect("SOCKS proxy should be parsed");
        assert_eq!(socks_proxy.scheme(), "socks5h");
        assert_eq!(socks_proxy.host_str(), Some("127.0.0.1"));
        assert_eq!(socks_proxy.port(), Some(9050));
    }
}
