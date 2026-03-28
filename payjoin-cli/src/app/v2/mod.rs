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

use super::config::{Config, SessionTransport, V2Transport};
use super::wallet::BitcoindWallet;
use super::App as AppTrait;
#[cfg(feature = "v1")]
use crate::app::http_agent;
use crate::app::v2::ohttp::{unwrap_ohttp_keys_or_else_fetch, RelayManager};
use crate::app::{handle_interrupt, v2_http_agent};
use crate::db::v2::{ReceiverPersister, SenderPersister, SessionId};
use crate::db::Database;

mod ohttp;

const W_ID: usize = 12;
const W_ROLE: usize = 25;
const W_DONE: usize = 15;
const W_STATUS: usize = 15;

#[derive(Clone)]
pub(crate) struct App {
    config: Config,
    db: Arc<Database>,
    wallet: BitcoindWallet,
    interrupt: watch::Receiver<()>,
    relay_manager: Arc<Mutex<RelayManager>>,
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
        let relay_manager = Arc::new(Mutex::new(RelayManager::new()));
        let (interrupt_tx, interrupt_rx) = watch::channel(());
        tokio::spawn(handle_interrupt(interrupt_tx));
        let wallet = BitcoindWallet::new(&config.bitcoind).await?;
        let app = Self { config, db, wallet, interrupt: interrupt_rx, relay_manager };
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
                let psbt = ctx.process_response(&response_bytes).map_err(|e| {
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
                let mut interrupt = self.interrupt.clone();
                tokio::select! {
                    _ = self.process_sender_session(sender_state, &persister) => return Ok(()),
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
        let address = self.wallet().get_new_address()?;
        let validated_transport =
            unwrap_ohttp_keys_or_else_fetch(&self.config, None, self.relay_manager.clone()).await?;
        let persister = ReceiverPersister::new(self.db.clone())?;
        let ohttp_keys = validated_transport.ohttp_keys;
        let session =
            ReceiverBuilder::new(address, self.config.v2()?.pj_directory.as_str(), ohttp_keys)?
                .with_amount(amount)
                .with_max_fee_rate(self.config.max_fee_rate.unwrap_or(FeeRate::BROADCAST_MIN))
                .build()
                .save(&persister)?;
        persister.set_transport(&validated_transport.transport)?;

        println!("Receive session established");
        let pj_uri = session.pj_uri();
        println!("Request Payjoin by sharing this Payjoin Uri:");
        println!("{pj_uri}");

        self.process_receiver_session(ReceiveSession::Initialized(session.clone()), &persister)
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
                    tasks.push(tokio::spawn(async move {
                        self_clone.process_receiver_session(receiver_state, &recv_persister).await
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
            let sender_persiter = SenderPersister::from_id(self.db.clone(), session_id.clone());
            match replay_sender_event_log(&sender_persiter) {
                Ok((sender_state, _)) => {
                    let self_clone = self.clone();
                    tasks.push(tokio::spawn(async move {
                        self_clone.process_sender_session(sender_state, &sender_persiter).await
                    }));
                }
                Err(e) => {
                    tracing::error!("An error {:?} occurred while replaying Sender session", e);
                    Self::close_failed_session(&sender_persiter, &session_id, "sender");
                }
            }
        }

        let mut interrupt = self.interrupt.clone();
        tokio::select! {
            _ = async {
                for task in tasks {
                    let _ = task.await;
                }
            } => {
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

    async fn process_sender_session(
        &self,
        session: SendSession,
        persister: &SenderPersister,
    ) -> Result<()> {
        match session {
            SendSession::WithReplyKey(context) =>
                self.post_original_proposal(context, persister).await?,
            SendSession::PollingForProposal(context) =>
                self.get_proposed_payjoin_psbt(context, persister).await?,
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
    ) -> Result<()> {
        let (session_transport, transport) =
            self.resolve_sender_transport_or_else_fetch(&sender, persister).await?;
        let (req, ctx) = sender.create_v2_post_request_with_transport(transport)?;
        let response = self.post_request(&session_transport, req).await?;
        println!("Posted original proposal...");
        let sender = sender.process_response(&response.bytes().await?, ctx).save(persister)?;
        self.get_proposed_payjoin_psbt(sender, persister).await
    }

    async fn get_proposed_payjoin_psbt(
        &self,
        sender: Sender<PollingForProposal>,
        persister: &SenderPersister,
    ) -> Result<()> {
        let (session_transport, transport) =
            self.resolve_sender_transport_or_else_fetch(&sender, persister).await?;
        let mut session = sender.clone();
        // Long poll until we get a response
        loop {
            let (req, ctx) = session.create_poll_request_with_transport(transport.clone())?;
            let response = self.post_request(&session_transport, req).await?;
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
    ) -> Result<Receiver<UncheckedOriginalPayload>> {
        let (session_transport, transport) =
            self.resolve_receiver_transport_or_else_fetch(&session, persister).await?;

        let mut session = session;
        loop {
            let (req, context) = session.create_poll_request_with_transport(transport.clone())?;
            println!("Polling receive request...");
            let ohttp_response = self.post_request(&session_transport, req).await?;
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
    ) -> Result<()> {
        let res = {
            match session {
                ReceiveSession::Initialized(proposal) =>
                    self.read_from_directory(proposal, persister).await,
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
    ) -> Result<()> {
        let mut interrupt = self.interrupt.clone();
        let receiver = tokio::select! {
            res = self.long_poll_fallback(session, persister) => res,
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
        let (session_transport, transport) =
            self.resolve_receiver_transport_or_else_fetch(&proposal, persister).await?;
        let (req, ohttp_ctx) = proposal
            .create_post_request_with_transport(transport)
            .map_err(|e| anyhow!("v2 req extraction failed {}", e))?;
        let res = self.post_request(&session_transport, req).await?;
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

    async fn unwrap_relay_or_else_fetch(
        &self,
        directory: Option<impl payjoin::IntoUrl>,
    ) -> Result<url::Url> {
        let directory = directory.map(|url| url.into_url()).transpose()?;
        let selected_relay =
            self.relay_manager.lock().expect("Lock should not be poisoned").get_selected_relay();
        let ohttp_relay = match selected_relay {
            Some(relay) => relay,
            None => match unwrap_ohttp_keys_or_else_fetch(
                &self.config,
                directory,
                self.relay_manager.clone(),
            )
            .await?
            .transport
            {
                SessionTransport::Relay { relay } => relay,
                SessionTransport::Direct { .. } =>
                    return Err(anyhow!("Direct transport selected where relay was required")),
            },
        };
        Ok(ohttp_relay)
    }

    async fn resolve_session_transport_or_else_fetch(
        &self,
        persisted_transport: Option<SessionTransport>,
        directory: Option<impl payjoin::IntoUrl>,
    ) -> Result<SessionTransport> {
        if let Some(transport) = persisted_transport {
            return Ok(transport);
        }

        let directory = directory.map(|url| url.into_url()).transpose()?;
        match self.config.v2()?.transport {
            V2Transport::Relay => {
                let relay = self
                    .unwrap_relay_or_else_fetch(directory.as_ref().map(url::Url::as_str))
                    .await?;
                Ok(SessionTransport::relay(relay))
            }
            V2Transport::Direct => {
                let socks_proxy = self
                    .config
                    .v2()?
                    .socks_proxy
                    .clone()
                    .expect("direct transport validation should guarantee a SOCKS proxy");
                Ok(SessionTransport::direct(socks_proxy))
            }
        }
    }

    async fn resolve_sender_transport_or_else_fetch<State>(
        &self,
        session: &Sender<State>,
        persister: &SenderPersister,
    ) -> Result<(SessionTransport, payjoin::OhttpTransport)> {
        let endpoint = url::Url::parse(&session.endpoint())?;
        let persisted_transport = persister.transport()?;
        let session_transport = self
            .resolve_session_transport_or_else_fetch(
                persisted_transport.clone(),
                Some(endpoint.as_str()),
            )
            .await?;
        if persisted_transport.is_none() {
            persister.set_transport(&session_transport)?;
        }

        Ok((session_transport.clone(), session_transport.as_ohttp_transport(&endpoint)?))
    }

    async fn resolve_receiver_transport_or_else_fetch<State>(
        &self,
        session: &Receiver<State>,
        persister: &ReceiverPersister,
    ) -> Result<(SessionTransport, payjoin::OhttpTransport)> {
        let endpoint = url::Url::parse(session.pj_uri().extras.endpoint().as_str())?;
        let persisted_transport = persister.transport()?;
        let session_transport = self
            .resolve_session_transport_or_else_fetch(
                persisted_transport.clone(),
                Some(endpoint.as_str()),
            )
            .await?;
        if persisted_transport.is_none() {
            persister.set_transport(&session_transport)?;
        }

        Ok((session_transport.clone(), session_transport.as_ohttp_transport(&endpoint)?))
    }

    /// Handle error by attempting to send an error response over the directory
    async fn handle_error(
        &self,
        session: Receiver<HasReplyableError>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let (session_transport, transport) =
            self.resolve_receiver_transport_or_else_fetch(&session, persister).await?;
        let (err_req, err_ctx) = session.create_error_request_with_transport(transport)?;

        let err_response = match self.post_request(&session_transport, err_req).await {
            Ok(response) => response,
            Err(e) => return Err(anyhow!("Failed to post error request: {}", e)),
        };

        let err_bytes = match err_response.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => return Err(anyhow!("Failed to get error response bytes: {}", e)),
        };

        if let Err(e) = session.process_error_response(&err_bytes, err_ctx).save(persister) {
            return Err(anyhow!("Failed to process error response: {}", e));
        }

        Ok(())
    }

    async fn post_request(
        &self,
        session_transport: &SessionTransport,
        req: payjoin::Request,
    ) -> Result<reqwest::Response> {
        let http = v2_http_agent(&self.config, session_transport)?;
        http.post(req.url)
            .header("Content-Type", req.content_type)
            .body(req.body)
            .send()
            .await
            .map_err(map_reqwest_err)
    }
}

fn map_reqwest_err(e: reqwest::Error) -> anyhow::Error {
    match e.status() {
        Some(status_code) => anyhow!("HTTP request failed: {} {}", status_code, e),
        None => anyhow!("No HTTP response: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    use payjoin::bitcoin::{Address, FeeRate};
    use payjoin::persist::NoopSessionPersister;
    use payjoin::receive::v2::{Initialized, Receiver, ReceiverBuilder};
    use payjoin::{OhttpKeys, OhttpTransport};
    use tempfile::TempDir;
    use tokio::sync::watch;
    use url::Url;

    use super::ohttp::RelayManager;
    use super::App;
    use crate::app::config::{
        BitcoindConfig, Config, SessionTransport, V2Config, V2Transport, VersionConfig,
    };
    use crate::app::wallet::BitcoindWallet;
    use crate::db::v2::ReceiverPersister;
    use crate::db::Database;

    const TEST_OHTTP_KEYS_BYTES: [u8; 34] = [
        0x01, 0x03, 0xba, 0x48, 0xc4, 0x9c, 0x3d, 0x4a, 0x92, 0xa3, 0xad, 0x00, 0xec, 0xc6, 0x3a,
        0x02, 0x4d, 0xa1, 0x0c, 0xed, 0x02, 0x18, 0x0c, 0x73, 0xec, 0x12, 0xd8, 0xa7, 0xad, 0x2c,
        0xc9, 0x1b, 0xb4, 0x83,
    ];

    fn test_bitcoind_config() -> BitcoindConfig {
        BitcoindConfig {
            rpchost: Url::parse("http://127.0.0.1:18443").expect("static URL is valid"),
            cookie: None,
            rpcuser: "bitcoin".to_owned(),
            rpcpassword: "bitcoin".to_owned(),
        }
    }

    fn test_v2_config(transport: V2Transport, pj_directory: Url) -> V2Config {
        V2Config {
            transport,
            ohttp_keys: None,
            ohttp_relays: if transport == V2Transport::Relay {
                vec![Url::parse("https://relay.example").expect("static relay URL is valid")]
            } else {
                Vec::new()
            },
            pj_directory,
            socks_proxy: Some(
                Url::parse("socks5h://127.0.0.1:9050").expect("static SOCKS proxy URL is valid"),
            ),
        }
    }

    async fn test_app(temp_dir: &TempDir, v2_config: V2Config) -> anyhow::Result<App> {
        let config = Config {
            db_path: temp_dir.path().join("payjoin.sqlite"),
            max_fee_rate: Some(FeeRate::BROADCAST_MIN),
            bitcoind: test_bitcoind_config(),
            version: Some(VersionConfig::V2(v2_config)),
            #[cfg(feature = "_manual-tls")]
            root_certificate: None,
            #[cfg(feature = "_manual-tls")]
            certificate_key: None,
        };
        let wallet = BitcoindWallet::new(&config.bitcoind).await?;
        let (_interrupt_tx, interrupt) = watch::channel(());
        Ok(App {
            db: Arc::new(Database::create(&config.db_path)?),
            config,
            wallet,
            interrupt,
            relay_manager: Arc::new(Mutex::new(RelayManager::new())),
        })
    }

    fn test_ohttp_keys() -> OhttpKeys {
        OhttpKeys::try_from(&TEST_OHTTP_KEYS_BYTES[..]).expect("static OHTTP key bytes are valid")
    }

    fn test_receiver(directory: &str) -> anyhow::Result<Receiver<Initialized>> {
        let address = Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")
            .expect("static address is valid")
            .assume_checked();
        let ohttp_keys = test_ohttp_keys();
        Ok(ReceiverBuilder::new(address, directory, ohttp_keys)?
            .build()
            .save(&NoopSessionPersister::default())?)
    }

    #[tokio::test]
    async fn resumed_receiver_uses_persisted_direct_transport() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let persisted_directory =
            Url::parse("https://persisted.example").expect("static URL is valid");
        let current_config_directory =
            Url::parse("https://current.example").expect("static URL is valid");
        let app = test_app(
            &temp_dir,
            test_v2_config(V2Transport::Relay, current_config_directory.clone()),
        )
        .await?;
        let receiver = test_receiver(persisted_directory.as_str())?;
        let persister = ReceiverPersister::new(app.db.clone())?;
        let socks_proxy = Url::parse("socks5h://user:pass@127.0.0.1:9050")
            .expect("static SOCKS proxy URL is valid");
        persister.set_transport(&SessionTransport::direct(socks_proxy.clone()))?;

        let (session_transport, transport) =
            app.resolve_receiver_transport_or_else_fetch(&receiver, &persister).await?;

        assert_eq!(session_transport, SessionTransport::direct(socks_proxy));

        match transport {
            OhttpTransport::Direct(directory) => {
                assert_eq!(directory, persisted_directory.join("/")?);
                assert_ne!(directory, current_config_directory.join("/")?);
            }
            OhttpTransport::Relay(_) => panic!("expected direct transport"),
        }

        Ok(())
    }
}
