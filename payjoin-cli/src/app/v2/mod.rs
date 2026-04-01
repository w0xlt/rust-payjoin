use std::fmt;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use payjoin::bitcoin::consensus::encode::serialize_hex;
use payjoin::bitcoin::{Amount, FeeRate};
use payjoin::persist::{OptionalTransitionOutcome, SessionPersister};
use payjoin::receive::v2::{
    replay_event_log as replay_receiver_event_log, HasReplyableError, Initialized,
    MaybeInputsOwned, MaybeInputsSeen, Monitor, OutputsUnknown, PayjoinProposal,
    ProvisionalProposal, ReceiveSession, Receiver, ReceiverBuilder,
    SessionOutcome as ReceiverSessionOutcome, UncheckedOriginalPayload, WantsFeeRange, WantsInputs,
    WantsOutputs,
};
use payjoin::send::v2::{
    replay_event_log as replay_sender_event_log, PollingForProposal, SendSession, Sender,
    SenderBuilder, SessionOutcome as SenderSessionOutcome, WithReplyKey,
};
use payjoin::{ImplementationError, PjParam, Uri};
use tokio::sync::watch;

use super::config::Config;
use super::wallet::BitcoindWallet;
use super::App as AppTrait;
#[cfg(feature = "v1")]
use crate::app::http_agent;
use crate::app::v2::ohttp::{
    unwrap_ohttp_keys_or_else_fetch, unwrap_relay_or_else_fetch as resolve_relay_or_else_fetch,
    RelayManager,
};
use crate::app::{handle_interrupt, v2_http_agent};
use crate::db::v2::{ReceiverPersister, SenderPersister, SessionId, SocksAuth};
use crate::db::Database;

mod bootstrap;
mod ohttp;

const W_ID: usize = 12;
const W_ROLE: usize = 25;
const W_DONE: usize = 15;
const W_STATUS: usize = 15;

async fn await_resume_tasks(tasks: Vec<tokio::task::JoinHandle<Result<()>>>) -> Result<()> {
    for task in tasks {
        task.await.context("resumed session task panicked")??;
    }
    Ok(())
}

async fn post_v2_request(
    config: &Config,
    req: payjoin::Request,
    session_socks_auth: Option<&SocksAuth>,
) -> Result<reqwest::Response> {
    let http = v2_http_agent(config, session_socks_auth)?;
    let response = http
        .post(req.url)
        .header("Content-Type", req.content_type)
        .body(req.body)
        .send()
        .await
        .map_err(anyhow::Error::from)?;
    if response.status().is_client_error() || response.status().is_server_error() {
        return response.error_for_status().map_err(anyhow::Error::from);
    }
    Ok(response)
}

fn should_fail_over_relay(err: &anyhow::Error) -> bool {
    err.chain().find_map(|cause| cause.downcast_ref::<reqwest::Error>()).is_some_and(
        |reqwest_err| {
            reqwest_err.status().is_none()
                || reqwest_err.status().is_some_and(|status| {
                    status == reqwest::StatusCode::NOT_FOUND || status.is_server_error()
                })
        },
    )
}

async fn post_v2_request_with_relay_failover<C, E, F>(
    config: &Config,
    relay_manager: Arc<Mutex<RelayManager>>,
    directory: Option<url::Url>,
    session_socks_auth: Option<&SocksAuth>,
    mut create_request: F,
) -> Result<(reqwest::Response, C)>
where
    F: FnMut(&url::Url) -> std::result::Result<(payjoin::Request, C), E>,
    E: Into<anyhow::Error>,
{
    loop {
        let relay = resolve_relay_or_else_fetch(
            config,
            directory.clone(),
            relay_manager.clone(),
            session_socks_auth,
        )
        .await?;
        let (req, ctx) = create_request(&relay).map_err(Into::into)?;
        match post_v2_request(config, req, session_socks_auth).await {
            Ok(response) => return Ok((response, ctx)),
            Err(err) if should_fail_over_relay(&err) => {
                tracing::warn!(
                    "Relay request through {relay} failed, retrying with another relay: {err}"
                );
                relay_manager.lock().expect("Lock should not be poisoned").mark_relay_failed(relay);
            }
            Err(err) => return Err(err),
        }
    }
}

#[derive(Clone)]
pub(crate) struct App {
    config: Config,
    db: Arc<Database>,
    wallet: BitcoindWallet,
    interrupt: watch::Receiver<()>,
}

trait StatusText {
    fn status_text(&self) -> &'static str;
}

impl StatusText for SendSession {
    fn status_text(&self) -> &'static str {
        match self {
            SendSession::WithReplyKey(_) | SendSession::PollingForProposal(_) =>
                "Waiting for proposal",
            SendSession::Closed(session_outcome) => match session_outcome {
                SenderSessionOutcome::Failure => "Session failure",
                SenderSessionOutcome::Success(_) => "Session success",
                SenderSessionOutcome::Cancel => "Session cancelled",
            },
        }
    }
}

impl StatusText for ReceiveSession {
    fn status_text(&self) -> &'static str {
        match self {
            ReceiveSession::Initialized(_) => "Waiting for original proposal",
            ReceiveSession::UncheckedOriginalPayload(_)
            | ReceiveSession::MaybeInputsOwned(_)
            | ReceiveSession::MaybeInputsSeen(_)
            | ReceiveSession::OutputsUnknown(_)
            | ReceiveSession::WantsOutputs(_)
            | ReceiveSession::WantsInputs(_)
            | ReceiveSession::WantsFeeRange(_)
            | ReceiveSession::ProvisionalProposal(_) => "Processing original proposal",
            ReceiveSession::PayjoinProposal(_) => "Payjoin proposal sent",
            ReceiveSession::HasReplyableError(_) =>
                "Session failure, waiting to post error response",
            ReceiveSession::Monitor(_) => "Monitoring payjoin proposal",
            ReceiveSession::Closed(session_outcome) => match session_outcome {
                ReceiverSessionOutcome::Failure => "Session failure",
                ReceiverSessionOutcome::Success(_) => "Session success, Payjoin proposal was broadcasted",
                ReceiverSessionOutcome::Cancel => "Session cancelled",
                ReceiverSessionOutcome::FallbackBroadcasted => "Fallback broadcasted",
                ReceiverSessionOutcome::PayjoinProposalSent =>
                    "Payjoin proposal sent, skipping monitoring as the sender is spending non-SegWit inputs",
            },
        }
    }
}

fn print_header() {
    println!(
        "{:<W_ID$} {:<W_ROLE$} {:<W_DONE$} {:<W_STATUS$}",
        "Session ID", "Sender/Receiver", "Completed At", "Status"
    );
}

enum Role {
    Sender,
    Receiver,
}
impl Role {
    fn as_str(&self) -> &'static str {
        match self {
            Role::Sender => "Sender",
            Role::Receiver => "Receiver",
        }
    }
}

struct SessionHistoryRow<Status> {
    session_id: SessionId,
    role: Role,
    status: Status,
    completed_at: Option<u64>,
    error_message: Option<String>,
}

impl<Status: StatusText> fmt::Display for SessionHistoryRow<Status> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<W_ID$} {:<W_ROLE$} {:<W_DONE$} {:<W_STATUS$}",
            self.session_id.to_string(),
            self.role.as_str(),
            match self.completed_at {
                None => "Not Completed".to_string(),
                Some(secs) => {
                    // TODO: human readable time
                    secs.to_string()
                }
            },
            self.error_message.as_deref().unwrap_or(self.status.status_text())
        )
    }
}

#[async_trait::async_trait]
impl AppTrait for App {
    async fn new(config: Config) -> Result<Self> {
        let db = Arc::new(Database::create(&config.db_path)?);
        let (interrupt_tx, interrupt_rx) = watch::channel(());
        tokio::spawn(handle_interrupt(interrupt_tx));
        let wallet = BitcoindWallet::new(&config.bitcoind).await?;
        let app = Self { config, db, wallet, interrupt: interrupt_rx };
        app.wallet()
            .network()
            .context("Failed to connect to bitcoind. Check config RPC connection.")?;
        Ok(app)
    }

    fn wallet(&self) -> BitcoindWallet { self.wallet.clone() }

    #[allow(clippy::incompatible_msrv)]
    async fn send_payjoin(&self, bip21: &str, fee_rate: FeeRate) -> Result<()> {
        use payjoin::UriExt;
        let uri = Uri::try_from(bip21)
            .map_err(|e| anyhow!("Failed to create URI from BIP21: {}", e))?
            .assume_checked()
            .check_pj_supported()
            .map_err(|_| anyhow!("URI does not support Payjoin"))?;
        let address = uri.address;
        let amount = uri.amount.ok_or_else(|| anyhow!("please specify the amount in the Uri"))?;
        match uri.extras.pj_param() {
            #[cfg(feature = "v1")]
            PjParam::V1(pj_param) => {
                use std::str::FromStr;

                let psbt = self.create_original_psbt(&address, amount, fee_rate)?;
                let (req, ctx) = payjoin::send::v1::SenderBuilder::from_parts(
                    psbt,
                    pj_param,
                    &address,
                    Some(amount),
                )
                .build_recommended(fee_rate)
                .with_context(|| "Failed to build payjoin request")?
                .create_v1_post_request();
                let http = http_agent(&self.config)?;
                let body = String::from_utf8(req.body.clone()).unwrap();
                println!("Sending fallback request to {}", &req.url);
                let response = http
                    .post(req.url)
                    .header("Content-Type", req.content_type)
                    .body(body.clone())
                    .send()
                    .await
                    .with_context(|| "HTTP request failed")?;
                let fallback_tx = payjoin::bitcoin::Psbt::from_str(&body)
                    .map_err(|e| anyhow!("Failed to load PSBT from base64: {}", e))?
                    .extract_tx()?;
                println!("Sent fallback transaction txid: {}", fallback_tx.compute_txid());
                println!(
                    "Sent fallback transaction hex: {:#}",
                    payjoin::bitcoin::consensus::encode::serialize_hex(&fallback_tx)
                );
                let response_bytes = response.bytes().await?;
                let psbt = ctx.process_response(response_bytes.as_ref()).map_err(|e| {
                    tracing::debug!("Error processing response: {e:?}");
                    anyhow!("Failed to process response {e}")
                })?;

                self.process_pj_response(psbt)?;
                Ok(())
            }
            PjParam::V2(pj_param) => {
                let receiver_pubkey = pj_param.receiver_pubkey();
                let sender_state =
                    self.db.get_send_session_ids()?.into_iter().find_map(|session_id| {
                        let session_receiver_pubkey = self
                            .db
                            .get_send_session_receiver_pk(&session_id)
                            .expect("Receiver pubkey should exist if session id exists");
                        if session_receiver_pubkey == *receiver_pubkey {
                            let sender_persister =
                                SenderPersister::from_id(self.db.clone(), session_id);
                            let (send_session, _) = replay_sender_event_log(&sender_persister)
                                .map_err(|e| anyhow!("Failed to replay sender event log: {:?}", e))
                                .ok()?;

                            Some((send_session, sender_persister))
                        } else {
                            None
                        }
                    });

                let (sender_state, persister) = match sender_state {
                    Some((sender_state, persister)) => (sender_state, persister),
                    None => {
                        let persister =
                            SenderPersister::new(self.db.clone(), receiver_pubkey.clone())?;
                        let psbt = self.create_original_psbt(&address, amount, fee_rate)?;
                        let sender =
                            SenderBuilder::from_parts(psbt, pj_param, &address, Some(amount))
                                .build_recommended(fee_rate)?
                                .save(&persister)?;

                        (SendSession::WithReplyKey(sender), persister)
                    }
                };
                let relay_manager = Self::new_relay_manager();
                let mut interrupt = self.interrupt.clone();
                tokio::select! {
                    _ = self.process_sender_session(sender_state, &persister, relay_manager) => return Ok(()),
                    _ = interrupt.changed() => {
                        println!("Interrupted. Call `send` with the same arguments to resume this session or `resume` to resume all sessions.");
                        return Err(anyhow!("Interrupted"))
                    }
                }
            }
            _ => unimplemented!("Unrecognized payjoin version"),
        }
    }

    async fn receive_payjoin(&self, amount: Amount) -> Result<()> {
        let relay_manager = Self::new_relay_manager();
        let persister = ReceiverPersister::new(self.db.clone())?;
        let session_socks_auth =
            Self::close_failed_receiver_init(self.receiver_socks_auth(&persister), &persister)?;
        let address =
            Self::close_failed_receiver_init(self.wallet().get_new_address(), &persister)?;
        let ohttp_keys = Self::close_failed_receiver_init(
            unwrap_ohttp_keys_or_else_fetch(
                &self.config,
                None,
                relay_manager.clone(),
                session_socks_auth.as_ref(),
            )
            .await
            .map(|validated| validated.ohttp_keys),
            &persister,
        )?;
        let pj_directory = Self::close_failed_receiver_init(
            self.config.v2().map(|v2| v2.pj_directory.clone()),
            &persister,
        )?;
        let receiver_builder = Self::close_failed_receiver_init(
            ReceiverBuilder::new(address, pj_directory.as_str(), ohttp_keys),
            &persister,
        )?;
        let session = Self::close_failed_receiver_init(
            receiver_builder
                .with_amount(amount)
                .with_max_fee_rate(self.config.max_fee_rate.unwrap_or(FeeRate::BROADCAST_MIN))
                .build()
                .save(&persister),
            &persister,
        )?;

        println!("Receive session established");
        let pj_uri = session.pj_uri();
        println!("Request Payjoin by sharing this Payjoin Uri:");
        println!("{pj_uri}");

        self.process_receiver_session(
            ReceiveSession::Initialized(session.clone()),
            &persister,
            relay_manager,
        )
        .await?;
        Ok(())
    }

    #[allow(clippy::incompatible_msrv)]
    async fn resume_payjoins(&self) -> Result<()> {
        let recv_session_ids = self.db.get_recv_session_ids()?;
        let send_session_ids = self.db.get_send_session_ids()?;

        if recv_session_ids.is_empty() && send_session_ids.is_empty() {
            println!("No sessions to resume.");
            return Ok(());
        }

        let mut tasks = Vec::new();

        // Process receiver sessions
        for session_id in recv_session_ids {
            let self_clone = self.clone();
            let recv_persister = ReceiverPersister::from_id(self.db.clone(), session_id.clone());
            match replay_receiver_event_log(&recv_persister) {
                Ok((receiver_state, _)) => {
                    let relay_manager = Self::new_relay_manager();
                    tasks.push(tokio::spawn(async move {
                        self_clone
                            .process_receiver_session(
                                receiver_state,
                                &recv_persister,
                                relay_manager,
                            )
                            .await
                    }));
                }
                Err(e) => {
                    tracing::error!("An error {:?} occurred while replaying receiver session", e);
                    Self::close_failed_session(&recv_persister, &session_id, "receiver");
                }
            }
        }

        // Process sender sessions
        for session_id in send_session_ids {
            let sender_persister = SenderPersister::from_id(self.db.clone(), session_id.clone());
            match replay_sender_event_log(&sender_persister) {
                Ok((sender_state, _)) => {
                    let self_clone = self.clone();
                    let relay_manager = Self::new_relay_manager();
                    tasks.push(tokio::spawn(async move {
                        self_clone
                            .process_sender_session(sender_state, &sender_persister, relay_manager)
                            .await
                    }));
                }
                Err(e) => {
                    tracing::error!("An error {:?} occurred while replaying Sender session", e);
                    Self::close_failed_session(&sender_persister, &session_id, "sender");
                }
            }
        }

        let mut interrupt = self.interrupt.clone();
        tokio::select! {
            result = await_resume_tasks(tasks) => {
                result?;
                println!("All resumed sessions completed.");
            }
            _ = interrupt.changed() => {
                println!("Resumed sessions were interrupted.");
            }
        }
        Ok(())
    }

    #[cfg(feature = "v2")]
    async fn history(&self) -> Result<()> {
        print_header();
        let mut send_rows = vec![];
        let mut recv_rows = vec![];
        self.db.get_send_session_ids()?.into_iter().for_each(|session_id| {
            let persister = SenderPersister::from_id(self.db.clone(), session_id.clone());
            match replay_sender_event_log(&persister) {
                Ok((sender_state, _)) => {
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Sender,
                        status: sender_state.clone(),
                        completed_at: None,
                        error_message: None,
                    };
                    send_rows.push(row);
                }
                Err(e) => {
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Sender,
                        status: SendSession::Closed(SenderSessionOutcome::Failure),
                        completed_at: None,
                        error_message: Some(e.to_string()),
                    };
                    send_rows.push(row);
                }
            }
        });

        self.db.get_recv_session_ids()?.into_iter().for_each(|session_id| {
            let persister = ReceiverPersister::from_id(self.db.clone(), session_id.clone());
            match replay_receiver_event_log(&persister) {
                Ok((receiver_state, _)) => {
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Receiver,
                        status: receiver_state.clone(),
                        completed_at: None,
                        error_message: None,
                    };
                    recv_rows.push(row);
                }
                Err(e) => {
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Receiver,
                        status: ReceiveSession::Closed(ReceiverSessionOutcome::Failure),
                        completed_at: None,
                        error_message: Some(e.to_string()),
                    };
                    recv_rows.push(row);
                }
            }
        });

        self.db.get_inactive_send_session_ids()?.into_iter().for_each(
            |(session_id, completed_at)| {
                let persister = SenderPersister::from_id(self.db.clone(), session_id.clone());
                match replay_sender_event_log(&persister) {
                    Ok((sender_state, _)) => {
                        let row = SessionHistoryRow {
                            session_id,
                            role: Role::Sender,
                            status: sender_state.clone(),
                            completed_at: Some(completed_at),
                            error_message: None,
                        };
                        send_rows.push(row);
                    }
                    Err(e) => {
                        let row = SessionHistoryRow {
                            session_id,
                            role: Role::Sender,
                            status: SendSession::Closed(SenderSessionOutcome::Failure),
                            completed_at: Some(completed_at),
                            error_message: Some(e.to_string()),
                        };
                        send_rows.push(row);
                    }
                }
            },
        );

        self.db.get_inactive_recv_session_ids()?.into_iter().for_each(
            |(session_id, completed_at)| {
                let persister = ReceiverPersister::from_id(self.db.clone(), session_id.clone());
                match replay_receiver_event_log(&persister) {
                    Ok((receiver_state, _)) => {
                        let row = SessionHistoryRow {
                            session_id,
                            role: Role::Receiver,
                            status: receiver_state.clone(),
                            completed_at: Some(completed_at),
                            error_message: None,
                        };
                        recv_rows.push(row);
                    }
                    Err(e) => {
                        let row = SessionHistoryRow {
                            session_id,
                            role: Role::Receiver,
                            status: ReceiveSession::Closed(ReceiverSessionOutcome::Failure),
                            completed_at: Some(completed_at),
                            error_message: Some(e.to_string()),
                        };
                        recv_rows.push(row);
                    }
                }
            },
        );

        // Print receiver and sender rows separately
        for row in send_rows {
            println!("{row}");
        }
        for row in recv_rows {
            println!("{row}");
        }

        Ok(())
    }
}

impl App {
    fn new_relay_manager() -> Arc<Mutex<RelayManager>> { Arc::new(Mutex::new(RelayManager::new())) }

    fn close_failed_session<P>(persister: &P, session_id: &SessionId, role: &str)
    where
        P: SessionPersister,
    {
        if let Err(close_err) = SessionPersister::close(persister) {
            tracing::error!("Failed to close {} session {}: {:?}", role, session_id, close_err);
        } else {
            tracing::error!("Closed failed {} session: {}", role, session_id);
        }
    }

    fn close_failed_receiver_init<T, E>(
        result: std::result::Result<T, E>,
        persister: &ReceiverPersister,
    ) -> Result<T>
    where
        E: Into<anyhow::Error>,
    {
        result.map_err(|err| {
            Self::close_failed_session(persister, persister.session_id(), "receiver");
            err.into()
        })
    }

    fn uses_tor_stream_isolation(&self) -> Result<bool> {
        let v2 = self.config.v2()?;
        Ok(v2.socks_proxy.is_some() && v2.tor_stream_isolation)
    }

    fn sender_socks_auth(&self, persister: &SenderPersister) -> Result<Option<SocksAuth>> {
        if self.uses_tor_stream_isolation()? {
            return Ok(Some(persister.get_or_create_socks_auth()?));
        }
        Ok(None)
    }

    fn receiver_socks_auth(&self, persister: &ReceiverPersister) -> Result<Option<SocksAuth>> {
        if self.uses_tor_stream_isolation()? {
            return Ok(Some(persister.get_or_create_socks_auth()?));
        }
        Ok(None)
    }

    async fn process_sender_session(
        &self,
        session: SendSession,
        persister: &SenderPersister,
        relay_manager: Arc<Mutex<RelayManager>>,
    ) -> Result<()> {
        match session {
            SendSession::WithReplyKey(context) =>
                self.post_original_proposal(context, persister, relay_manager).await?,
            SendSession::PollingForProposal(context) =>
                self.get_proposed_payjoin_psbt(context, persister, relay_manager).await?,
            SendSession::Closed(SenderSessionOutcome::Success(proposal)) => {
                self.process_pj_response(proposal)?;
                return Ok(());
            }
            _ => return Err(anyhow!("Unexpected sender state")),
        }
        Ok(())
    }

    async fn post_original_proposal(
        &self,
        sender: Sender<WithReplyKey>,
        persister: &SenderPersister,
        relay_manager: Arc<Mutex<RelayManager>>,
    ) -> Result<()> {
        let endpoint = url::Url::parse(&sender.endpoint())?;
        let session_socks_auth = self.sender_socks_auth(persister)?;
        let (response, ctx) = post_v2_request_with_relay_failover(
            &self.config,
            relay_manager.clone(),
            Some(endpoint),
            session_socks_auth.as_ref(),
            |relay| sender.create_v2_post_request(relay.as_str()),
        )
        .await?;
        println!("Posted original proposal...");
        let sender = sender.process_response(&response.bytes().await?, ctx).save(persister)?;
        self.get_proposed_payjoin_psbt(sender, persister, relay_manager).await
    }

    async fn get_proposed_payjoin_psbt(
        &self,
        sender: Sender<PollingForProposal>,
        persister: &SenderPersister,
        relay_manager: Arc<Mutex<RelayManager>>,
    ) -> Result<()> {
        let endpoint = url::Url::parse(&sender.endpoint())?;
        let session_socks_auth = self.sender_socks_auth(persister)?;
        let mut session = sender.clone();
        // Long poll until we get a response
        loop {
            let (response, ctx) = post_v2_request_with_relay_failover(
                &self.config,
                relay_manager.clone(),
                Some(endpoint.clone()),
                session_socks_auth.as_ref(),
                |relay| session.create_poll_request(relay.as_str()),
            )
            .await?;
            let res = session.process_response(&response.bytes().await?, ctx).save(persister);
            match res {
                Ok(OptionalTransitionOutcome::Progress(psbt)) => {
                    println!("Proposal received. Processing...");
                    self.process_pj_response(psbt)?;
                    return Ok(());
                }
                Ok(OptionalTransitionOutcome::Stasis(current_state)) => {
                    println!("No response yet.");
                    session = current_state;
                    continue;
                }
                Err(re) => {
                    println!("{re}");
                    tracing::debug!("{re:?}");
                    return Err(anyhow!("Response error").context(re));
                }
            }
        }
    }

    async fn long_poll_fallback(
        &self,
        session: Receiver<Initialized>,
        persister: &ReceiverPersister,
        relay_manager: Arc<Mutex<RelayManager>>,
    ) -> Result<Receiver<UncheckedOriginalPayload>> {
        let endpoint = url::Url::parse(&session.pj_uri().extras.endpoint())?;
        let session_socks_auth = self.receiver_socks_auth(persister)?;

        let mut session = session;
        loop {
            let (ohttp_response, context) = post_v2_request_with_relay_failover(
                &self.config,
                relay_manager.clone(),
                Some(endpoint.clone()),
                session_socks_auth.as_ref(),
                |relay| session.create_poll_request(relay.as_str()),
            )
            .await?;
            println!("Polling receive request...");
            let state_transition = session
                .process_response(ohttp_response.bytes().await?.to_vec().as_slice(), context)
                .save(persister);
            match state_transition {
                Ok(OptionalTransitionOutcome::Progress(next_state)) => {
                    println!("Got a request from the sender. Responding with a Payjoin proposal.");
                    return Ok(next_state);
                }
                Ok(OptionalTransitionOutcome::Stasis(current_state)) => {
                    session = current_state;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn process_receiver_session(
        &self,
        session: ReceiveSession,
        persister: &ReceiverPersister,
        relay_manager: Arc<Mutex<RelayManager>>,
    ) -> Result<()> {
        let res = {
            match session {
                ReceiveSession::Initialized(proposal) =>
                    self.read_from_directory(proposal, persister, relay_manager).await,
                ReceiveSession::UncheckedOriginalPayload(proposal) =>
                    self.check_proposal(proposal, persister).await,
                ReceiveSession::MaybeInputsOwned(proposal) =>
                    self.check_inputs_not_owned(proposal, persister).await,
                ReceiveSession::MaybeInputsSeen(proposal) =>
                    self.check_no_inputs_seen_before(proposal, persister).await,
                ReceiveSession::OutputsUnknown(proposal) =>
                    self.identify_receiver_outputs(proposal, persister).await,
                ReceiveSession::WantsOutputs(proposal) =>
                    self.commit_outputs(proposal, persister).await,
                ReceiveSession::WantsInputs(proposal) =>
                    self.contribute_inputs(proposal, persister).await,
                ReceiveSession::WantsFeeRange(proposal) =>
                    self.apply_fee_range(proposal, persister).await,
                ReceiveSession::ProvisionalProposal(proposal) =>
                    self.finalize_proposal(proposal, persister).await,
                ReceiveSession::PayjoinProposal(proposal) =>
                    self.send_payjoin_proposal(proposal, persister).await,
                ReceiveSession::HasReplyableError(error) =>
                    self.handle_error(error, persister).await,
                ReceiveSession::Monitor(proposal) =>
                    self.monitor_payjoin_proposal(proposal, persister).await,
                ReceiveSession::Closed(_) => return Err(anyhow!("Session closed")),
            }
        };
        res
    }

    #[allow(clippy::incompatible_msrv)]
    async fn read_from_directory(
        &self,
        session: Receiver<Initialized>,
        persister: &ReceiverPersister,
        relay_manager: Arc<Mutex<RelayManager>>,
    ) -> Result<()> {
        let mut interrupt = self.interrupt.clone();
        let receiver = tokio::select! {
            res = self.long_poll_fallback(session, persister, relay_manager) => res,
            _ = interrupt.changed() => {
                println!("Interrupted. Call the `resume` command to resume all sessions.");
                return Err(anyhow!("Interrupted"));
            }
        }?;
        self.check_proposal(receiver, persister).await
    }

    async fn check_proposal(
        &self,
        proposal: Receiver<UncheckedOriginalPayload>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let wallet = self.wallet();
        let proposal = proposal
            .check_broadcast_suitability(None, |tx| {
                wallet
                    .can_broadcast(tx)
                    .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
            })
            .save(persister)?;

        println!("Fallback transaction received. Consider broadcasting this to get paid if the Payjoin fails:");
        println!("{}", serialize_hex(&proposal.extract_tx_to_schedule_broadcast()));
        self.check_inputs_not_owned(proposal, persister).await
    }

    async fn check_inputs_not_owned(
        &self,
        proposal: Receiver<MaybeInputsOwned>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let wallet = self.wallet();
        let proposal = proposal
            .check_inputs_not_owned(&mut |input| {
                wallet
                    .is_mine(input)
                    .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
            })
            .save(persister)?;
        self.check_no_inputs_seen_before(proposal, persister).await
    }

    async fn check_no_inputs_seen_before(
        &self,
        proposal: Receiver<MaybeInputsSeen>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let proposal = proposal
            .check_no_inputs_seen_before(&mut |input| {
                Ok(self.db.insert_input_seen_before(*input)?)
            })
            .save(persister)?;
        self.identify_receiver_outputs(proposal, persister).await
    }

    async fn identify_receiver_outputs(
        &self,
        proposal: Receiver<OutputsUnknown>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let wallet = self.wallet();
        let proposal = proposal
            .identify_receiver_outputs(&mut |output_script| {
                wallet
                    .is_mine(output_script)
                    .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
            })
            .save(persister)?;
        self.commit_outputs(proposal, persister).await
    }

    async fn commit_outputs(
        &self,
        proposal: Receiver<WantsOutputs>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let proposal = proposal.commit_outputs().save(persister)?;
        self.contribute_inputs(proposal, persister).await
    }

    async fn contribute_inputs(
        &self,
        proposal: Receiver<WantsInputs>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let wallet = self.wallet();
        let candidate_inputs = wallet.list_unspent()?;

        if candidate_inputs.is_empty() {
            return Err(anyhow::anyhow!(
                "No spendable UTXOs available in wallet. Cannot contribute inputs to payjoin."
            ));
        }

        let selected_input = proposal.try_preserving_privacy(candidate_inputs)?;
        let proposal =
            proposal.contribute_inputs(vec![selected_input])?.commit_inputs().save(persister)?;
        self.apply_fee_range(proposal, persister).await
    }

    async fn apply_fee_range(
        &self,
        proposal: Receiver<WantsFeeRange>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let proposal = proposal.apply_fee_range(None, self.config.max_fee_rate).save(persister)?;
        self.finalize_proposal(proposal, persister).await
    }

    async fn finalize_proposal(
        &self,
        proposal: Receiver<ProvisionalProposal>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let wallet = self.wallet();
        let proposal = proposal
            .finalize_proposal(|psbt| {
                wallet
                    .process_psbt(psbt)
                    .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
            })
            .save(persister)?;
        self.send_payjoin_proposal(proposal, persister).await
    }

    async fn send_payjoin_proposal(
        &self,
        proposal: Receiver<PayjoinProposal>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let relay_manager = Self::new_relay_manager();
        let session_socks_auth = self.receiver_socks_auth(persister)?;
        let (res, ohttp_ctx) = post_v2_request_with_relay_failover(
            &self.config,
            relay_manager,
            None,
            session_socks_auth.as_ref(),
            |relay| {
                proposal
                    .create_post_request(relay.as_str())
                    .map_err(|e| anyhow!("v2 req extraction failed {}", e))
            },
        )
        .await?;
        let payjoin_psbt = proposal.psbt().clone();
        let session = proposal.process_response(&res.bytes().await?, ohttp_ctx).save(persister)?;
        println!(
            "Response successful. Watch mempool for successful Payjoin. TXID: {}",
            payjoin_psbt.extract_tx_unchecked_fee_rate().compute_txid()
        );

        return self.monitor_payjoin_proposal(session, persister).await;
    }

    async fn monitor_payjoin_proposal(
        &self,
        proposal: Receiver<Monitor>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        // On a session resumption, the receiver will resume again in this state.
        let poll_interval = tokio::time::Duration::from_millis(200);
        let timeout_duration = tokio::time::Duration::from_secs(5);

        let mut interval = tokio::time::interval(poll_interval);
        interval.tick().await;

        tracing::debug!("Polling for payment confirmation");

        let result = tokio::time::timeout(timeout_duration, async {
            loop {
                interval.tick().await;
                let check_result = proposal
                    .check_payment(|txid| {
                        self.wallet()
                            .get_raw_transaction(&txid)
                            .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
                    })
                    .save(persister);

                match check_result {
                    Ok(_) => {
                        println!("Payjoin transaction detected in the mempool!");
                        return Ok(());
                    }
                    Err(_) => {
                        // keep polling

                        continue;
                    }
                }
            }
        })
        .await;

        match result {
            Ok(ok) => ok,
            Err(_) => Err(anyhow!(
                "Timeout waiting for payment confirmation after {:?}",
                timeout_duration
            )),
        }
    }

    /// Handle error by attempting to send an error response over the directory
    async fn handle_error(
        &self,
        session: Receiver<HasReplyableError>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let relay_manager = Self::new_relay_manager();
        let session_socks_auth = self.receiver_socks_auth(persister)?;
        let (err_response, err_ctx) = post_v2_request_with_relay_failover(
            &self.config,
            relay_manager,
            None,
            session_socks_auth.as_ref(),
            |relay| session.create_error_request(relay.as_str()),
        )
        .await
        .map_err(|e| anyhow!("Failed to post error request: {}", e))?;

        let err_bytes = match err_response.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => return Err(anyhow!("Failed to get error response bytes: {}", e)),
        };

        if let Err(e) = session.process_error_response(&err_bytes, err_ctx).save(persister) {
            return Err(anyhow!("Failed to process error response: {}", e));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;

    use payjoin::bitcoin::bech32::primitives::decode::CheckedHrpstring;
    use payjoin::bitcoin::bech32::NoChecksum;
    use payjoin::bitcoin::{Address, Network};
    use payjoin::persist::NoopSessionPersister;
    use payjoin::receive::v2::ReceiverBuilder;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task;
    use url::Url;

    use super::*;
    use crate::app::config::{BitcoindConfig, V2Config, VersionConfig};
    use crate::db::v2::ReceiverPersister;
    use crate::db::Database;

    #[test]
    fn close_failed_receiver_init_closes_session() {
        let temp_dir = tempdir().expect("temp dir should be created");
        let db = Arc::new(
            Database::create(temp_dir.path().join("payjoin.sqlite"))
                .expect("database should initialize"),
        );
        let persister =
            ReceiverPersister::new(db.clone()).expect("receiver session should initialize");

        let err =
            App::close_failed_receiver_init::<(), anyhow::Error>(Err(anyhow!("boom")), &persister)
                .expect_err("failing receiver init should propagate an error");

        assert!(err.to_string().contains("boom"));
        assert!(
            db.get_recv_session_ids().expect("active sessions should load").is_empty(),
            "failed receiver init should not leave an active session behind"
        );
        let inactive = db.get_inactive_recv_session_ids().expect("inactive sessions should load");
        assert_eq!(inactive.len(), 1, "failed receiver init should close the session");
        assert_eq!(
            inactive[0].0.to_string(),
            persister.session_id().to_string(),
            "the receiver session created for initialization should be the one that was closed"
        );
    }

    #[test]
    fn close_failed_receiver_init_preserves_successful_session() {
        let temp_dir = tempdir().expect("temp dir should be created");
        let db = Arc::new(
            Database::create(temp_dir.path().join("payjoin.sqlite"))
                .expect("database should initialize"),
        );
        let persister =
            ReceiverPersister::new(db.clone()).expect("receiver session should initialize");

        let value = App::close_failed_receiver_init(Ok::<_, anyhow::Error>(7_u8), &persister)
            .expect("successful receiver init should pass through");

        assert_eq!(value, 7);
        assert_eq!(
            db.get_recv_session_ids().expect("active sessions should load").len(),
            1,
            "successful receiver init should keep the session active"
        );
        assert!(
            db.get_inactive_recv_session_ids().expect("inactive sessions should load").is_empty(),
            "successful receiver init should not close the session"
        );
    }

    #[tokio::test]
    async fn await_resume_tasks_propagates_task_errors() {
        let err = await_resume_tasks(vec![task::spawn(async { Err(anyhow!("boom")) })])
            .await
            .expect_err("failing resumed session task should propagate");

        assert!(
            err.to_string().contains("boom"),
            "resume helper should preserve the inner task error"
        );
    }

    #[tokio::test]
    async fn configured_ohttp_keys_fail_over_from_cached_dead_relay() {
        let bad_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("dead relay test listener should bind");
        let bad_port = bad_listener
            .local_addr()
            .expect("dead relay test listener should have a local address")
            .port();
        drop(bad_listener);

        let good_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("healthy relay test listener should bind");
        let good_port = good_listener
            .local_addr()
            .expect("healthy relay test listener should have a local address")
            .port();
        let good_handle = tokio::spawn(async move {
            let (mut stream, _) =
                good_listener.accept().await.expect("healthy relay should accept a client");
            read_http_request(&mut stream)
                .await
                .expect("healthy relay should read the full request");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await
                .expect("healthy relay should write a success response");
            stream.shutdown().await.expect("healthy relay should close the connection");
        });

        let bad_relay = Url::parse(&format!("http://127.0.0.1:{bad_port}"))
            .expect("dead relay URL should parse");
        let good_relay = Url::parse(&format!("http://127.0.0.1:{good_port}"))
            .expect("healthy relay URL should parse");
        let config = test_config(vec![bad_relay.clone(), good_relay.clone()]);
        let relay_manager = Arc::new(Mutex::new(RelayManager::new()));
        relay_manager
            .lock()
            .expect("Lock should not be poisoned")
            .set_selected_relay(bad_relay.clone());

        let receiver =
            ReceiverBuilder::new(test_address(), "https://directory.example", test_ohttp_keys())
                .expect("receiver builder should initialize")
                .build()
                .save(&NoopSessionPersister::default())
                .expect("receiver session should save");

        let (response, _) = post_v2_request_with_relay_failover(
            &config,
            relay_manager.clone(),
            None,
            None,
            |relay| receiver.create_poll_request(relay.as_str()),
        )
        .await
        .expect("healthy relay should be selected after failover");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let (selected_relay, failed_relays) = {
            let manager = relay_manager.lock().expect("Lock should not be poisoned");
            (manager.get_selected_relay(), manager.get_failed_relays())
        };
        assert_eq!(selected_relay, Some(good_relay));
        assert_eq!(failed_relays, vec![bad_relay]);

        good_handle.await.expect("healthy relay task should complete");
    }

    #[tokio::test]
    async fn configured_ohttp_keys_fail_over_from_cached_server_error_relay() {
        let bad_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failing relay test listener should bind");
        let bad_port = bad_listener
            .local_addr()
            .expect("failing relay test listener should have a local address")
            .port();
        let bad_handle = tokio::spawn(async move {
            let (mut stream, _) =
                bad_listener.accept().await.expect("failing relay should accept a client");
            read_http_request(&mut stream)
                .await
                .expect("failing relay should read the full request");
            stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await
                .expect("failing relay should write an error response");
            stream.shutdown().await.expect("failing relay should close the connection");
        });

        let good_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("healthy relay test listener should bind");
        let good_port = good_listener
            .local_addr()
            .expect("healthy relay test listener should have a local address")
            .port();
        let good_handle = tokio::spawn(async move {
            let (mut stream, _) =
                good_listener.accept().await.expect("healthy relay should accept a client");
            read_http_request(&mut stream)
                .await
                .expect("healthy relay should read the full request");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await
                .expect("healthy relay should write a success response");
            stream.shutdown().await.expect("healthy relay should close the connection");
        });

        let bad_relay = Url::parse(&format!("http://127.0.0.1:{bad_port}"))
            .expect("failing relay URL should parse");
        let good_relay = Url::parse(&format!("http://127.0.0.1:{good_port}"))
            .expect("healthy relay URL should parse");
        let config = test_config(vec![bad_relay.clone(), good_relay.clone()]);
        let relay_manager = Arc::new(Mutex::new(RelayManager::new()));
        relay_manager
            .lock()
            .expect("Lock should not be poisoned")
            .set_selected_relay(bad_relay.clone());

        let receiver =
            ReceiverBuilder::new(test_address(), "https://directory.example", test_ohttp_keys())
                .expect("receiver builder should initialize")
                .build()
                .save(&NoopSessionPersister::default())
                .expect("receiver session should save");

        let (response, _) = post_v2_request_with_relay_failover(
            &config,
            relay_manager.clone(),
            None,
            None,
            |relay| receiver.create_poll_request(relay.as_str()),
        )
        .await
        .expect("healthy relay should be selected after server-error failover");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let (selected_relay, failed_relays) = {
            let manager = relay_manager.lock().expect("Lock should not be poisoned");
            (manager.get_selected_relay(), manager.get_failed_relays())
        };
        assert_eq!(selected_relay, Some(good_relay));
        assert_eq!(failed_relays, vec![bad_relay]);

        bad_handle.await.expect("failing relay task should complete");
        good_handle.await.expect("healthy relay task should complete");
    }

    #[tokio::test]
    async fn configured_ohttp_keys_fail_over_from_cached_not_found_relay() {
        let bad_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("not-found relay test listener should bind");
        let bad_port = bad_listener
            .local_addr()
            .expect("not-found relay test listener should have a local address")
            .port();
        let bad_handle = tokio::spawn(async move {
            let (mut stream, _) =
                bad_listener.accept().await.expect("not-found relay should accept a client");
            read_http_request(&mut stream)
                .await
                .expect("not-found relay should read the full request");
            stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await
                .expect("not-found relay should write an error response");
            stream.shutdown().await.expect("not-found relay should close the connection");
        });

        let good_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("healthy relay test listener should bind");
        let good_port = good_listener
            .local_addr()
            .expect("healthy relay test listener should have a local address")
            .port();
        let good_handle = tokio::spawn(async move {
            let (mut stream, _) =
                good_listener.accept().await.expect("healthy relay should accept a client");
            read_http_request(&mut stream)
                .await
                .expect("healthy relay should read the full request");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await
                .expect("healthy relay should write a success response");
            stream.shutdown().await.expect("healthy relay should close the connection");
        });

        let bad_relay = Url::parse(&format!("http://127.0.0.1:{bad_port}"))
            .expect("not-found relay URL should parse");
        let good_relay = Url::parse(&format!("http://127.0.0.1:{good_port}"))
            .expect("healthy relay URL should parse");
        let config = test_config(vec![bad_relay.clone(), good_relay.clone()]);
        let relay_manager = Arc::new(Mutex::new(RelayManager::new()));
        relay_manager
            .lock()
            .expect("Lock should not be poisoned")
            .set_selected_relay(bad_relay.clone());

        let receiver =
            ReceiverBuilder::new(test_address(), "https://directory.example", test_ohttp_keys())
                .expect("receiver builder should initialize")
                .build()
                .save(&NoopSessionPersister::default())
                .expect("receiver session should save");

        let (response, _) = post_v2_request_with_relay_failover(
            &config,
            relay_manager.clone(),
            None,
            None,
            |relay| receiver.create_poll_request(relay.as_str()),
        )
        .await
        .expect("healthy relay should be selected after not-found failover");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let (selected_relay, failed_relays) = {
            let manager = relay_manager.lock().expect("Lock should not be poisoned");
            (manager.get_selected_relay(), manager.get_failed_relays())
        };
        assert_eq!(selected_relay, Some(good_relay));
        assert_eq!(failed_relays, vec![bad_relay]);

        bad_handle.await.expect("not-found relay task should complete");
        good_handle.await.expect("healthy relay task should complete");
    }

    #[tokio::test]
    async fn configured_ohttp_keys_do_not_fail_over_from_cached_bad_request_relay() {
        let bad_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bad-request relay test listener should bind");
        let bad_port = bad_listener
            .local_addr()
            .expect("bad-request relay test listener should have a local address")
            .port();
        let bad_handle = tokio::spawn(async move {
            let (mut stream, _) =
                bad_listener.accept().await.expect("bad-request relay should accept a client");
            read_http_request(&mut stream)
                .await
                .expect("bad-request relay should read the full request");
            stream
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await
                .expect("bad-request relay should write an error response");
            stream.shutdown().await.expect("bad-request relay should close the connection");
        });

        let good_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("healthy relay test listener should bind");
        let good_port = good_listener
            .local_addr()
            .expect("healthy relay test listener should have a local address")
            .port();

        let bad_relay = Url::parse(&format!("http://127.0.0.1:{bad_port}"))
            .expect("bad-request relay URL should parse");
        let good_relay = Url::parse(&format!("http://127.0.0.1:{good_port}"))
            .expect("healthy relay URL should parse");
        let config = test_config(vec![bad_relay.clone(), good_relay.clone()]);
        let relay_manager = Arc::new(Mutex::new(RelayManager::new()));
        relay_manager
            .lock()
            .expect("Lock should not be poisoned")
            .set_selected_relay(bad_relay.clone());

        let receiver =
            ReceiverBuilder::new(test_address(), "https://directory.example", test_ohttp_keys())
                .expect("receiver builder should initialize")
                .build()
                .save(&NoopSessionPersister::default())
                .expect("receiver session should save");

        let err = match post_v2_request_with_relay_failover(
            &config,
            relay_manager.clone(),
            None,
            None,
            |relay| receiver.create_poll_request(relay.as_str()),
        )
        .await
        {
            Ok(_) => panic!("bad request should not fail over to another relay"),
            Err(err) => err,
        };

        let reqwest_err = err
            .chain()
            .find_map(|cause| cause.downcast_ref::<reqwest::Error>())
            .expect("bad request should surface a reqwest status error");
        assert_eq!(reqwest_err.status(), Some(reqwest::StatusCode::BAD_REQUEST));

        let (selected_relay, failed_relays) = {
            let manager = relay_manager.lock().expect("Lock should not be poisoned");
            (manager.get_selected_relay(), manager.get_failed_relays())
        };
        assert_eq!(selected_relay, Some(bad_relay));
        assert!(failed_relays.is_empty());

        tokio::time::timeout(tokio::time::Duration::from_millis(100), good_listener.accept())
            .await
            .expect_err("healthy relay should not receive a request");

        bad_handle.await.expect("bad-request relay task should complete");
    }

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
        let mut request = Vec::new();
        let mut content_length = None;

        loop {
            let mut buf = [0u8; 4096];
            let bytes_read = stream.read(&mut buf).await?;
            if bytes_read == 0 {
                break;
            }
            request.extend_from_slice(&buf[..bytes_read]);

            if let Some(header_end) =
                request.windows(4).position(|window| window == b"\r\n\r\n").map(|idx| idx + 4)
            {
                if content_length.is_none() {
                    content_length =
                        std::str::from_utf8(&request[..header_end]).ok().and_then(|headers| {
                            headers.lines().find_map(|line| {
                                line.split_once(':').and_then(|(name, value)| {
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse::<usize>().ok())
                                        .flatten()
                                })
                            })
                        });
                }

                let body_len = request.len().saturating_sub(header_end);
                if body_len >= content_length.unwrap_or(0) {
                    break;
                }
            }
        }

        Ok(request)
    }

    fn test_config(ohttp_relays: Vec<Url>) -> Config {
        Config {
            db_path: std::path::PathBuf::from("unused-payjoin.sqlite"),
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
                pj_directory: Url::parse("https://directory.example")
                    .expect("static directory URL should parse"),
                socks_proxy: None,
                tor_stream_isolation: false,
            })),
            #[cfg(feature = "_manual-tls")]
            root_certificate: None,
            #[cfg(feature = "_manual-tls")]
            certificate_key: None,
        }
    }

    fn test_address() -> Address {
        Address::from_str("bcrt1qxjg7w7g5nwqv0u7lpaxxjfdall2k4f4k0yucj5")
            .expect("static address should parse")
            .require_network(Network::Regtest)
            .expect("static address should match regtest")
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
}
