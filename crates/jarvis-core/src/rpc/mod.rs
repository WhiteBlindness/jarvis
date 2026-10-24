//! The local RPC interface of the long-lived Core.
//!
//! One JSON request per line, one response per line, over a local transport
//! (see [`transport`]). Every connection is identified by the OS before any
//! request is read: connections from another user, from the worker process
//! (or anything in its job or process group), from a restricted token on
//! Windows (AppContainer or below medium integrity), and connections that
//! cannot be identified are refused and audited. Requests are size-limited, connections time out when
//! idle, and the number of concurrent connections is capped.

pub mod client;
pub mod transport;

use std::sync::Arc;
use std::time::{Duration, Instant};

use jarvis_protocol::{
    ApprovalView, AuditEventKind, DecodeError, HealthReport, JobView, ProtocolVersion, RpcError,
    RpcErrorCode, RpcRequest, RpcResponse, RpcVersion, WorkerState, decode_rpc_request,
    encode_rpc_response,
};
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::approval;
use crate::config::RpcConfig;
use crate::framing::{Frame, FrameReader};
use crate::hub::Hub;
use crate::inference::{Inference, InferenceError};
use crate::store::{ApprovalError, JobRecord, Store, StoreError, now_ms};
use transport::Stream;
pub use transport::{Endpoint, Listener, Peer};

const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_LIST: u32 = 200;

/// What the RPC server needs from the Core.
#[derive(Debug)]
pub struct RpcState {
    pub store: Store,
    pub hub: Arc<Hub>,
    pub config: RpcConfig,
    /// Cancelled by an authorised `shutdown` request.
    pub shutdown: CancellationToken,
    pub started: Instant,
    pub core_version: &'static str,
    /// The local model, when configured (ADR 0021).
    pub inference: Option<Arc<Inference>>,
}

/// Accept connections until `stop` is cancelled, then wait briefly for the
/// open ones to finish.
pub async fn serve(state: Arc<RpcState>, mut listener: Listener, stop: CancellationToken) {
    let slots = Arc::new(Semaphore::new(state.config.max_connections));
    let mut connections = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            biased;
            () = stop.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "RPC accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::warn!("RPC connection refused: too many open connections");
            continue;
        };
        let state = Arc::clone(&state);
        let stop = stop.clone();
        connections.spawn(async move {
            connection(&state, stream, peer, &stop).await;
            drop(slot);
        });
        while connections.try_join_next().is_some() {}
    }
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(2), drain)
        .await
        .is_err()
    {
        connections.abort_all();
    }
}

async fn connection<S: Stream>(state: &RpcState, stream: S, peer: Peer, stop: &CancellationToken) {
    let (reader, mut writer) = tokio::io::split(stream);
    if let Some(reason) = refusal(state, &peer) {
        reject(state, &peer, reason).await;
        let _ = write(
            &mut writer,
            &RpcResponse::Error(RpcError::new(RpcErrorCode::Forbidden, reason)),
        )
        .await;
        return;
    }

    let mut frames = FrameReader::new(reader, RpcConfig::MAX_REQUEST_BYTES);
    loop {
        let read = tokio::select! {
            biased;
            () = stop.cancelled() => return,
            read = tokio::time::timeout(state.config.idle_timeout, frames.next_frame()) => read,
        };
        let frame = match read {
            Err(_) | Ok(Err(_)) | Ok(Ok(None)) => return,
            Ok(Ok(Some(frame))) => frame,
        };
        let response = match frame {
            Frame::TooLarge => {
                let error = RpcError::new(
                    RpcErrorCode::RequestTooLarge,
                    format!(
                        "requests are limited to {} bytes",
                        RpcConfig::MAX_REQUEST_BYTES
                    ),
                );
                let _ = write(&mut writer, &RpcResponse::Error(error)).await;
                return;
            }
            Frame::Line(bytes) => {
                // Checked again for every request: a connection opened in
                // the moment between a worker starting and its containment
                // being registered must not stay usable.
                if let Some(reason) = refusal(state, &peer) {
                    reject(state, &peer, reason).await;
                    let error = RpcError::new(RpcErrorCode::Forbidden, reason);
                    let _ = write(&mut writer, &RpcResponse::Error(error)).await;
                    return;
                }
                match decode_rpc_request(&bytes) {
                    Ok(request) => handle(state, request, &peer).await,
                    Err(error) => RpcResponse::Error(decode_error(&error)),
                }
            }
        };
        if write(&mut writer, &response).await.is_err() {
            return;
        }
    }
}

/// Log and audit a refused peer.
async fn reject(state: &RpcState, peer: &Peer, reason: &'static str) {
    tracing::warn!(client = %peer.describe(), reason, "RPC connection refused");
    let event = AuditEventKind::RpcClientRejected {
        client: peer.describe(),
        reason: reason.to_owned(),
    };
    let _ = state
        .store
        .call(move |s| s.append(None, None, &event).map(|_| ()))
        .await;
}

/// Why a peer may not use the interface, if it may not.
fn refusal(state: &RpcState, peer: &Peer) -> Option<&'static str> {
    let Some(pid) = peer.pid else {
        return Some("the client process could not be identified");
    };
    if state.hub.is_worker_process(pid) {
        return Some("connections from the worker are not allowed");
    }
    if state
        .inference
        .as_ref()
        .is_some_and(|inference| inference.is_server_process(pid))
    {
        return Some("connections from the model server are not allowed");
    }
    #[cfg(unix)]
    if peer.uid != Some(jarvis_sandbox::current_uid()) {
        return Some("the client runs as a different user");
    }
    // The pipe's DACL already keeps other users and AppContainer processes
    // out. This is the Core's own check of the token the client connected
    // with, the counterpart of the user ID check on Unix.
    #[cfg(windows)]
    match peer.token {
        Some(jarvis_sandbox::PipeClient::SameUser) => {}
        Some(jarvis_sandbox::PipeClient::OtherUser) => {
            return Some("the client runs as a different user");
        }
        Some(jarvis_sandbox::PipeClient::Restricted) => {
            return Some("the client runs with a restricted token");
        }
        None => return Some("the client's token could not be read"),
    }
    // Checked through the process as well, for every request: this also
    // fails closed if the client process cannot be inspected.
    #[cfg(windows)]
    if !matches!(jarvis_sandbox::is_restricted_process(pid), Ok(false)) {
        return Some("the client runs with a restricted token, or could not be inspected");
    }
    None
}

fn decode_error(error: &DecodeError) -> RpcError {
    match error {
        DecodeError::UnsupportedVersion { .. } => {
            RpcError::new(RpcErrorCode::UnsupportedVersion, error.to_string())
        }
        DecodeError::Malformed { .. } => {
            RpcError::new(RpcErrorCode::MalformedRequest, error.to_string())
        }
    }
}

async fn write<S: Stream>(
    writer: &mut WriteHalf<S>,
    response: &RpcResponse,
) -> std::io::Result<()> {
    let mut bytes = encode_rpc_response(response).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    let write = async {
        writer.write_all(&bytes).await?;
        writer.flush().await
    };
    tokio::time::timeout(WRITE_TIMEOUT, write)
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
}

async fn handle(state: &RpcState, request: RpcRequest, peer: &Peer) -> RpcResponse {
    let result = match request {
        RpcRequest::Health {} => health(state).await,
        RpcRequest::SubmitJob { goal } => {
            submit(state, peer, move |s, client| s.submit_job(&goal, client)).await
        }
        // The text is kept as a temporary payload, never in the job (ADR 0022).
        RpcRequest::SubmitClipboardJob { text } => {
            submit(state, peer, move |s, client| {
                s.submit_clipboard_job(&text, client)
            })
            .await
        }
        RpcRequest::GetJob { job_id, wait_ms } => {
            wait_for(state, wait_ms, || {
                let store = state.store.clone();
                async move {
                    match store.call(move |s| s.job(job_id)).await {
                        Ok(Some(job)) => {
                            let done = job.status.is_terminal();
                            Ok((done, RpcResponse::Job(job_view(job))))
                        }
                        Ok(None) => Err(RpcError::new(RpcErrorCode::NotFound, "no such job")),
                        Err(error) => Err(internal(&error)),
                    }
                }
            })
            .await
        }
        RpcRequest::ListJobs { limit } => {
            let limit = limit.min(MAX_LIST);
            match state.store.call(move |s| s.jobs(limit)).await {
                Ok(jobs) => Ok(RpcResponse::Jobs {
                    jobs: jobs.into_iter().map(job_view).collect(),
                }),
                Err(error) => Err(internal(&error)),
            }
        }
        RpcRequest::ListApprovals { wait_ms } => {
            wait_for(state, wait_ms, || {
                let store = state.store.clone();
                async move {
                    let viewed = store
                        .call(|s| {
                            let now = now_ms();
                            Ok(s.pending_approvals()?
                                .iter()
                                .map(|record| approval::view(record, now, s))
                                .collect::<Vec<_>>())
                        })
                        .await;
                    match viewed {
                        Ok(approvals) => {
                            Ok((!approvals.is_empty(), RpcResponse::Approvals { approvals }))
                        }
                        Err(error) => Err(internal(&error)),
                    }
                }
            })
            .await
        }
        RpcRequest::GetApproval { approval_id } => {
            let viewed = state
                .store
                .call(move |s| {
                    Ok(s.approval(approval_id)?
                        .map(|record| approval::view(&record, now_ms(), s)))
                })
                .await;
            match viewed {
                Ok(Some(view)) => Ok(RpcResponse::Approval(view)),
                Ok(None) => Err(RpcError::new(RpcErrorCode::NotFound, "no such approval")),
                Err(error) => Err(internal(&error)),
            }
        }
        RpcRequest::Approve {
            approval_id,
            fingerprint,
        } => {
            let client = peer.describe();
            let granted = state
                .store
                .call(move |s| {
                    Ok(
                        s.grant_approval(approval_id, &fingerprint, &client, now_ms())
                            .map(|record| approval::view(&record, now_ms(), s)),
                    )
                })
                .await;
            decided(state, approval_id, granted, "approved")
        }
        RpcRequest::Deny {
            approval_id,
            reason,
        } => {
            let client = peer.describe();
            let denied = state
                .store
                .call(move |s| {
                    Ok(s.deny_approval(approval_id, &reason, &client, now_ms())
                        .map(|record| approval::view(&record, now_ms(), s)))
                })
                .await;
            decided(state, approval_id, denied, "denied")
        }
        RpcRequest::Shutdown {} => {
            if state.config.allow_shutdown {
                tracing::info!(client = %peer.describe(), "shutdown requested over RPC");
                state
                    .hub
                    .set_stop_reason(format!("shutdown requested by {}", peer.describe()));
                state.shutdown.cancel();
                Ok(RpcResponse::ShuttingDown {})
            } else {
                Err(RpcError::new(
                    RpcErrorCode::Forbidden,
                    "shutdown over RPC is disabled in the configuration",
                ))
            }
        }
        chat => chat_request(state, chat).await,
    };
    result.unwrap_or_else(RpcResponse::Error)
}

/// Queue a job, unless the worker has failed for good, and wake the session
/// that waits for one.
async fn submit<F>(state: &RpcState, peer: &Peer, queue: F) -> Result<RpcResponse, RpcError>
where
    F: FnOnce(&Store, &str) -> Result<JobRecord, StoreError> + Send + 'static,
{
    if state.hub.worker().state == WorkerState::Failed {
        return Err(RpcError::new(
            RpcErrorCode::Unavailable,
            "the worker failed and is no longer restarted",
        ));
    }
    let client = peer.describe();
    match state.store.call(move |s| queue(s, &client)).await {
        Ok(job) => {
            tracing::info!(job = %job.job_id, client = %peer.describe(), "job submitted");
            state.hub.jobs.notify_one();
            state.hub.changed();
            Ok(RpcResponse::Job(job_view(job)))
        }
        Err(error @ StoreError::TooManyPayloads(_)) => {
            Err(RpcError::new(RpcErrorCode::Unavailable, error.to_string()))
        }
        Err(error) => Err(internal(&error)),
    }
}

/// The conversation and model operations (ADR 0021). None of them runs a
/// tool: they reach the model, which only produces text.
async fn chat_request(state: &RpcState, request: RpcRequest) -> Result<RpcResponse, RpcError> {
    let Some(inference) = state.inference.as_ref() else {
        return Err(RpcError::new(
            RpcErrorCode::Unavailable,
            "the local model is not configured",
        ));
    };
    let response = match request {
        RpcRequest::ChatSend {
            conversation_id,
            text,
            language,
        } => RpcResponse::ChatTurn(inference.send(conversation_id, text, language).await?),
        RpcRequest::ChatRegenerate {
            conversation_id,
            language,
        } => RpcResponse::ChatTurn(inference.regenerate(conversation_id, language).await?),
        RpcRequest::ChatPoll {
            turn_id,
            cursor,
            wait_ms,
        } => {
            let wait = Duration::from_millis(u64::from(wait_ms)).min(RpcConfig::MAX_WAIT);
            RpcResponse::ChatDelta(inference.poll(turn_id, cursor, wait).await?)
        }
        RpcRequest::ChatCancel { turn_id } => {
            RpcResponse::ChatDelta(inference.cancel(turn_id).await?)
        }
        RpcRequest::ListConversations { query, limit } => RpcResponse::Conversations {
            conversations: inference.conversations(query, limit.min(MAX_LIST)).await?,
        },
        RpcRequest::GetConversation { conversation_id } => {
            RpcResponse::Conversation(inference.conversation(conversation_id).await?)
        }
        RpcRequest::DeleteConversation { conversation_id } => RpcResponse::Deleted {
            conversations: inference.delete_conversation(conversation_id).await?,
        },
        RpcRequest::DeleteAllConversations {} => RpcResponse::Deleted {
            conversations: inference.delete_all().await?,
        },
        RpcRequest::InferenceStatus {} => RpcResponse::Inference(inference.status()),
        RpcRequest::LoadModel {} => RpcResponse::Inference(inference.load()?),
        RpcRequest::UnloadModel {} => RpcResponse::Inference(inference.unload().await),
        RpcRequest::SetContextSize { context_size } => {
            RpcResponse::Inference(inference.set_context_size(context_size).await?)
        }
        RpcRequest::SetRetention { days } => {
            RpcResponse::Inference(inference.set_retention(days).await?)
        }
        _ => {
            return Err(RpcError::new(
                RpcErrorCode::Internal,
                "the Core could not complete the request",
            ));
        }
    };
    Ok(response)
}

impl From<InferenceError> for RpcError {
    fn from(error: InferenceError) -> Self {
        let code = match &error {
            InferenceError::Busy => RpcErrorCode::Conflict,
            InferenceError::NotFound(_) => RpcErrorCode::NotFound,
            InferenceError::Paused | InferenceError::Load(_) => RpcErrorCode::Unavailable,
            InferenceError::Invalid(_) => RpcErrorCode::MalformedRequest,
            InferenceError::Store(crate::inference::chat_store::ChatStoreError::ScrubPending) => {
                RpcErrorCode::Conflict
            }
            InferenceError::Store(store) => {
                tracing::error!(error = %store, "chat request failed");
                return RpcError::new(
                    RpcErrorCode::Internal,
                    "the Core could not complete the request",
                );
            }
        };
        RpcError::new(code, error.to_string())
    }
}

fn decided(
    state: &RpcState,
    approval_id: jarvis_protocol::ApprovalId,
    result: Result<Result<ApprovalView, ApprovalError>, StoreError>,
    verb: &str,
) -> Result<RpcResponse, RpcError> {
    // Whatever happened, the waiting session must look again.
    state.hub.approvals.notify(approval_id);
    state.hub.changed();
    match result {
        Ok(Ok(view)) => {
            tracing::info!(approval = %approval_id, "approval {verb}");
            Ok(RpcResponse::Approval(view))
        }
        Ok(Err(error)) => Err(approval_error(&error)),
        Err(error) => Err(internal(&error)),
    }
}

fn approval_error(error: &ApprovalError) -> RpcError {
    let code = match error {
        ApprovalError::NotFound(_) => RpcErrorCode::NotFound,
        ApprovalError::NotPending(_) | ApprovalError::NotGranted(_) => RpcErrorCode::Conflict,
        ApprovalError::Expired => RpcErrorCode::Expired,
        ApprovalError::FingerprintMismatch | ApprovalError::TaskChanged => {
            RpcErrorCode::FingerprintMismatch
        }
        ApprovalError::Store(error) => return internal(error),
    };
    RpcError::new(code, error.to_string())
}

async fn health(state: &RpcState) -> Result<RpcResponse, RpcError> {
    let counts = state
        .store
        .call(|s| Ok((s.queued_jobs()?, s.pending_approval_count()?)))
        .await;
    let (queued_jobs, pending_approvals) = counts.map_err(|error| internal(&error))?;
    let worker = state.hub.worker();
    Ok(RpcResponse::Health(HealthReport {
        ok: worker.state != WorkerState::Failed,
        core_version: state.core_version.to_owned(),
        worker_protocol: ProtocolVersion::CURRENT,
        rpc_protocol: RpcVersion::CURRENT,
        uptime_ms: u64::try_from(state.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        worker,
        governor: state
            .hub
            .governor_status()
            .view(tokio::time::Instant::now()),
        queued_jobs,
        pending_approvals,
    }))
}

/// Long-poll: re-evaluate `check` whenever the hub reports a change, until it
/// says done or `wait_ms` (capped) has passed.
async fn wait_for<F, Fut>(state: &RpcState, wait_ms: u32, check: F) -> Result<RpcResponse, RpcError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<(bool, RpcResponse), RpcError>>,
{
    let wait = Duration::from_millis(u64::from(wait_ms)).min(RpcConfig::MAX_WAIT);
    let deadline = tokio::time::Instant::now() + wait;
    let mut changes = state.hub.subscribe();
    loop {
        changes.borrow_and_update();
        let (done, response) = check().await?;
        if done || tokio::time::Instant::now() >= deadline {
            return Ok(response);
        }
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => {}
            changed = changes.changed() => if changed.is_err() { return Ok(response) },
        }
    }
}

fn job_view(job: JobRecord) -> JobView {
    JobView {
        job_id: job.job_id,
        status: job.status,
        goal: job.goal,
        summary: job.summary,
        submitted_at: job.created_at,
        updated_at: job.updated_at,
    }
}

fn internal(error: &StoreError) -> RpcError {
    tracing::error!(%error, "RPC request failed");
    RpcError::new(
        RpcErrorCode::Internal,
        "the Core could not complete the request",
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::config::WorkerConfig;
    use crate::isolation;

    fn state(dir: &Path) -> RpcState {
        RpcState {
            store: Store::open(&dir.join("jarvis.db")).unwrap(),
            hub: Arc::new(Hub::default()),
            config: RpcConfig {
                socket: dir.join("rpc.sock"),
                pipe: "jarvis-refusal-test".to_owned(),
                allow_shutdown: false,
                max_connections: 1,
                idle_timeout: Duration::from_secs(1),
            },
            shutdown: CancellationToken::new(),
            started: Instant::now(),
            core_version: "test",
            inference: None,
        }
    }

    fn this_process() -> Peer {
        Peer {
            pid: Some(std::process::id()),
            #[cfg(unix)]
            uid: Some(jarvis_sandbox::current_uid()),
            #[cfg(windows)]
            token: Some(jarvis_sandbox::PipeClient::SameUser),
        }
    }

    #[test]
    fn unidentified_peers_and_other_users_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        assert_eq!(refusal(&state, &this_process()), None);
        let unknown = Peer {
            pid: None,
            ..this_process()
        };
        assert!(refusal(&state, &unknown).is_some());
        #[cfg(unix)]
        {
            let other = Peer {
                uid: Some(jarvis_sandbox::current_uid().wrapping_add(1)),
                ..this_process()
            };
            assert!(refusal(&state, &other).is_some());
        }
        #[cfg(windows)]
        for (token, reason) in [
            (
                Some(jarvis_sandbox::PipeClient::OtherUser),
                "the client runs as a different user",
            ),
            (
                Some(jarvis_sandbox::PipeClient::Restricted),
                "the client runs with a restricted token",
            ),
            (None, "the client's token could not be read"),
        ] {
            let peer = Peer {
                token,
                ..this_process()
            };
            assert_eq!(refusal(&state, &peer), Some(reason));
        }
    }

    /// The second layer behind the OS boundary: even if the isolated worker
    /// could connect, the peer check would refuse it. Needs Python, like the
    /// other process tests.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_worker_is_refused_even_if_it_could_connect() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        let python = std::env::var("JARVIS_TEST_PYTHON")
            .unwrap_or_else(|_| if cfg!(windows) { "python" } else { "python3" }.to_owned());
        let config = WorkerConfig {
            program: python,
            args: ["-I", "-S", "-c", "import time; time.sleep(30)"]
                .into_iter()
                .map(String::from)
                .collect(),
            cwd: None,
            handshake_timeout: Duration::from_secs(5),
            memory_limit_bytes: 256 * 1024 * 1024,
        };
        let launch = isolation::launch(&config, &[]).unwrap();
        let spawned = jarvis_sandbox::spawn(&launch.command, &launch.confinement).unwrap();
        let worker = Peer {
            pid: Some(spawned.process.id()),
            ..this_process()
        };
        let contained = Arc::new(spawned.contained);
        state.hub.set_contained(Some(Arc::clone(&contained)));
        assert_eq!(
            refusal(&state, &worker),
            Some("connections from the worker are not allowed")
        );
        // Not registered as the worker: on Windows its AppContainer token is
        // still refused; on Linux the OS boundary is what keeps it out.
        state.hub.set_contained(None);
        #[cfg(windows)]
        assert!(refusal(&state, &worker).is_some());
        contained.kill_all().unwrap();
    }
}
