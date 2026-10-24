//! One worker session over a pair of byte streams.
//!
//! After the handshake the session hands the worker one queued job at a
//! time and turns each `tool_request` of that job into a durable task:
//!
//! ```text
//! frame ─► decode ─► create task ─► resolve tool + args ─► capabilities ─► policy
//!   allow:                 record decision ─► Gateway ─► verify ─► record ─► reply
//!   require_confirmation:  record approval request ─► wait for a person
//!                          ─► consume approval + record decision ─► Gateway ─► …
//! ```
//!
//! A job handed out again after its worker or the Core stopped is resumed:
//! a request for a position an earlier attempt completed is answered from
//! the stored result without creating a task (ADR 0015).
//!
//! Requests are handled one at a time, in order. That is the simplest
//! correct model for a single worker and doubles as a resource limit: a
//! worker can never have more than one tool running or more than one request
//! waiting for a person.
//!
//! The session works on any `AsyncRead`/`AsyncWrite` pair, so tests drive it
//! over in-memory pipes and the Core drives it over a child's stdio.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use jarvis_protocol::{
    AgentReceipt, ApprovalId, ApprovalStatus, AuditEventKind, CallError, ClipboardText,
    CoreMessage, DecodeError, ErrorCode, ErrorMessage, Fingerprint, JobId, JobStatus,
    PolicyDecision, RequestId, SessionId, SessionLimits, Summary, TaskId, TaskStatus, ToolCall,
    ToolName, ToolOutcome, ToolRequest, ToolResponse, ToolResult, Welcome, WireError,
    WorkerMessage, WorkerState, decode_worker_message, encode_core_message,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::approval::{self, Resolution};
use crate::config::Limits;
use crate::framing::{Frame, FrameReader};
use crate::gateway::{Execution, Gateway};
use crate::governor::Status as GovernorStatus;
use crate::hub::Hub;
use crate::policy::{Policy, required_capabilities};
use crate::session_agent::link::Performed;
use crate::session_agent::{Refusal, SessionAgent};
use crate::store::{
    ApprovalError, ConsumedApproval, JobStep, NewApproval, NewTask, Store, StoreError, TaskChange,
    now_ms,
};

mod job;
mod replay;

/// Frames a worker may send while one of its requests waits for a person.
const MAX_BACKLOG: usize = 16;

/// Everything a session needs from the Core.
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub store: Store,
    pub policy: Policy,
    pub gateway: Gateway,
    pub limits: Limits,
    pub handshake_timeout: Duration,
    pub approval_ttl: Duration,
    pub job_timeout: Duration,
    pub core_version: &'static str,
    pub hub: Arc<Hub>,
    /// Performs Session Agent operations. `None`: every such operation is
    /// refused before its approval is used.
    pub session_agent: Option<Arc<SessionAgent>>,
}

/// Why a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEnd {
    /// The worker closed its output stream.
    WorkerClosed,
    /// Reading from or writing to the worker failed or timed out.
    WorkerGone,
    /// The worker did not send `hello` in time.
    HandshakeTimeout,
    /// The worker did not finish a job in time.
    JobTimedOut(JobId),
    /// The Core is shutting down.
    Shutdown,
    /// The Core closed the session after a fatal protocol error or a limit.
    Terminated(WireError),
}

impl SessionEnd {
    pub fn describe(&self) -> String {
        match self {
            Self::WorkerClosed => "worker closed the session".into(),
            Self::WorkerGone => "worker stream failed".into(),
            Self::HandshakeTimeout => "worker did not complete the handshake in time".into(),
            Self::JobTimedOut(job) => format!("job {job} exceeded the job time limit"),
            Self::Shutdown => "Core shutdown".into(),
            Self::Terminated(error) => format!("terminated: {error}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionReport {
    pub session_id: SessionId,
    pub opened: bool,
    pub requests: u32,
    pub end: SessionEnd,
}

/// Failures that stop the Core, not just the session. If the store cannot
/// record a decision, nothing else may happen.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("cannot encode a Core message: {0}")]
    Encode(#[from] serde_json::Error),
}

/// Run one session to completion. Returns `Err` only when the Core itself
/// can no longer operate safely (the store failed).
pub async fn run_session<R, W>(
    ctx: &SessionContext,
    reader: R,
    writer: W,
    shutdown: &CancellationToken,
) -> Result<SessionReport, SessionError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut session = Session {
        ctx,
        id: SessionId::new(),
        reader: FrameReader::new(reader, ctx.limits.max_frame_bytes),
        writer,
        opened: false,
        requests: 0,
        errors: 0,
        job: None,
        used: HashSet::new(),
        backlog: VecDeque::new(),
        gate: ctx.hub.subscribe_governor(),
    };
    let result = async {
        match session.handshake(shutdown).await? {
            Some(end) => Ok(end),
            None => session.serve(shutdown).await,
        }
    }
    .await;
    let end = match result {
        Ok(end) => end,
        Err(error) => {
            // Tell the worker why the session is ending; the details stay in
            // the Core's log.
            let internal = CoreMessage::Error(ErrorMessage {
                request_id: None,
                error: WireError::new(ErrorCode::Internal, "the Core cannot continue safely"),
                fatal: true,
            });
            let _ = session.send(&internal).await;
            return Err(error);
        }
    };
    session.close(&end).await?;
    Ok(SessionReport {
        session_id: session.id,
        opened: session.opened,
        requests: session.requests,
        end,
    })
}

struct RunningJob {
    id: JobId,
    deadline: Instant,
    /// How many times the job has been claimed, this claim included.
    attempt: u32,
    /// Position of the last request that created a task or was replayed.
    seq: u32,
}

struct Session<'a, R, W> {
    ctx: &'a SessionContext,
    id: SessionId,
    reader: FrameReader<R>,
    writer: W,
    opened: bool,
    requests: u32,
    errors: u32,
    job: Option<RunningJob>,
    /// Request IDs this session has used for a task or a replay. A replay
    /// has no task, so the store alone cannot tell that its ID was used.
    used: HashSet<RequestId>,
    /// Frames read while a request waited for a person, handled afterwards.
    backlog: VecDeque<Frame>,
    /// Whether the gaming governor lets a job start (ADR 0016).
    gate: watch::Receiver<GovernorStatus>,
}

/// `None` means carry on; `Some` means the session is over.
type Step = Option<SessionEnd>;

/// What happened to one request.
enum Handled {
    Reply(ToolOutcome),
    /// The session ends; reply first if there is something to say.
    End(SessionEnd, Option<ToolOutcome>),
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Session<'_, R, W> {
    async fn handshake(&mut self, shutdown: &CancellationToken) -> Result<Step, SessionError> {
        let read = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(Some(SessionEnd::Shutdown)),
            read = tokio::time::timeout(self.ctx.handshake_timeout, self.reader.next_frame()) => read,
        };
        let frame = match read {
            Err(_) => return Ok(Some(SessionEnd::HandshakeTimeout)),
            Ok(Err(_)) => return Ok(Some(SessionEnd::WorkerGone)),
            Ok(Ok(None)) => return Ok(Some(SessionEnd::WorkerClosed)),
            Ok(Ok(Some(frame))) => frame,
        };
        let bytes = match frame {
            Frame::TooLarge => return self.terminate(None, self.too_large()).await,
            Frame::Line(bytes) => bytes,
        };
        match decode_worker_message(&bytes) {
            Err(error) => {
                self.terminate(error.request_id().cloned(), error.to_wire())
                    .await
            }
            Ok(WorkerMessage::ToolRequest(request)) => {
                let error = WireError::new(
                    ErrorCode::HandshakeRequired,
                    "the first message must be `hello`",
                );
                self.terminate(Some(request.request_id), error).await
            }
            Ok(WorkerMessage::JobResult(_)) => {
                let error = WireError::new(
                    ErrorCode::HandshakeRequired,
                    "the first message must be `hello`",
                );
                self.terminate(None, error).await
            }
            Ok(WorkerMessage::Hello(hello)) => {
                self.audit(
                    None,
                    AuditEventKind::SessionOpened {
                        worker: hello.worker.clone(),
                        worker_version: hello.worker_version.clone(),
                    },
                )
                .await?;
                self.opened = true;
                self.ctx.hub.set_worker_state(WorkerState::Idle);
                tracing::info!(session = %self.id, worker = %hello.worker, version = %hello.worker_version, "session opened");
                let welcome = CoreMessage::Welcome(Welcome {
                    session_id: self.id,
                    core_version: self.ctx.core_version.to_owned(),
                    tools: tool_names(),
                    limits: SessionLimits {
                        max_frame_bytes: u32::try_from(self.ctx.limits.max_frame_bytes)
                            .unwrap_or(u32::MAX),
                        tool_timeout_ms: millis(self.ctx.gateway.timeout()),
                        max_requests: self.ctx.limits.max_requests_per_session,
                    },
                });
                self.send(&welcome).await
            }
        }
    }

    async fn serve(&mut self, shutdown: &CancellationToken) -> Result<SessionEnd, SessionError> {
        loop {
            // The only place a job is claimed. While the gaming governor holds
            // jobs nothing is claimed, so no attempt is counted and no job
            // timer starts. Reading the gate marks its current value as seen,
            // so the wait below wakes for any later change and only for one.
            let held = self.job.is_none() && !self.gate.borrow_and_update().is_open();
            if self.job.is_none()
                && !held
                && let Some(end) = self.dispatch_next_job().await?
            {
                return Ok(end);
            }
            // Checked here as well as while reading: frames buffered during
            // an approval are handled without waiting on the reader.
            if self
                .job
                .as_ref()
                .is_some_and(|job| Instant::now() >= job.deadline)
            {
                return self.job_timed_out().await;
            }
            let frame = match self.backlog.pop_front() {
                Some(frame) => frame,
                None => {
                    let deadline = self.job.as_ref().map(|job| job.deadline);
                    let idle = self.job.is_none();
                    let read = tokio::select! {
                        biased;
                        () = shutdown.cancelled() => return Ok(SessionEnd::Shutdown),
                        () = sleep_until(deadline) => return self.job_timed_out().await,
                        () = self.ctx.hub.jobs.notified(), if idle => continue,
                        changed = self.gate.changed(), if held => match changed {
                            Ok(()) => continue,
                            // The hub owns the sender and outlives the session.
                            Err(_) => return Ok(SessionEnd::Shutdown),
                        },
                        read = self.reader.next_frame() => read,
                    };
                    match read {
                        Err(_) => return Ok(SessionEnd::WorkerGone),
                        Ok(None) => return Ok(SessionEnd::WorkerClosed),
                        Ok(Some(frame)) => frame,
                    }
                }
            };
            if let Some(end) = self.handle_frame(frame, shutdown).await? {
                return Ok(end);
            }
        }
    }

    async fn handle_frame(
        &mut self,
        frame: Frame,
        shutdown: &CancellationToken,
    ) -> Result<Step, SessionError> {
        let bytes = match frame {
            Frame::TooLarge => return self.reject_frame(None, self.too_large()).await,
            Frame::Line(bytes) => bytes,
        };
        match decode_worker_message(&bytes) {
            Err(error @ DecodeError::UnsupportedVersion { .. }) => {
                self.terminate(error.request_id().cloned(), error.to_wire())
                    .await
            }
            Err(error) => {
                self.reject_frame(error.request_id().cloned(), error.to_wire())
                    .await
            }
            Ok(WorkerMessage::Hello(_)) => {
                let error =
                    WireError::new(ErrorCode::UnexpectedMessage, "the session is already open");
                self.reject_frame(None, error).await
            }
            Ok(WorkerMessage::JobResult(result)) => self.handle_job_result(result).await,
            Ok(WorkerMessage::ToolRequest(request)) => {
                let Some(job) = self.job.as_ref().filter(|job| job.id == request.job_id) else {
                    let error = WireError::new(
                        ErrorCode::UnexpectedMessage,
                        "the request does not belong to the current job",
                    );
                    return self.reject_frame(Some(request.request_id), error).await;
                };
                let step = JobStep {
                    attempt: job.attempt,
                    seq: job.seq + 1,
                };
                self.handle_request(request, step, shutdown).await
            }
        }
    }

    /// `step` is the position this request would take in the job.
    async fn handle_request(
        &mut self,
        request: ToolRequest,
        step: JobStep,
        shutdown: &CancellationToken,
    ) -> Result<Step, SessionError> {
        if self.requests >= self.ctx.limits.max_requests_per_session {
            let error = WireError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "the session limit of {} requests was reached",
                    self.ctx.limits.max_requests_per_session
                ),
            );
            return self.terminate(Some(request.request_id), error).await;
        }

        if self.used.contains(&request.request_id) {
            return self.duplicate_request(request.request_id).await;
        }

        if let Some(done) = self.replay_if_completed(&request, step).await? {
            return Ok(done);
        }

        let task_id = TaskId::new();
        let new_task = NewTask {
            task_id,
            session_id: self.id,
            job_id: Some(request.job_id),
            step: Some(step),
            request_id: request.request_id.clone(),
            tool: request.tool.clone(),
            args: request.args.clone(),
        };
        match self.ctx.store.call(move |s| s.create_task(&new_task)).await {
            Ok(()) => {
                self.requests += 1;
                self.advance_to(step.seq);
                self.used.insert(request.request_id.clone());
            }
            Err(StoreError::DuplicateRequest(request_id)) => {
                return self.duplicate_request(request_id).await;
            }
            Err(error) => return Err(error.into()),
        }

        let (outcome, end) = match self.process(task_id, &request, shutdown).await? {
            Handled::Reply(outcome) => (Some(outcome), None),
            Handled::End(end, outcome) => (outcome, Some(end)),
        };
        if let Some(outcome) = outcome {
            tracing::info!(
                session = %self.id,
                task = %task_id,
                tool = %request.tool,
                outcome = outcome_name(&outcome),
                "request handled"
            );
            let response = CoreMessage::ToolResponse(ToolResponse {
                request_id: request.request_id,
                task_id,
                outcome,
            });
            if let Some(gone) = self.send(&response).await? {
                return Ok(Some(end.unwrap_or(gone)));
            }
        }
        match end {
            // A limit was broken while the request waited: say so, as for
            // any fatal error.
            Some(SessionEnd::Terminated(error)) => self.terminate(None, error).await,
            Some(SessionEnd::JobTimedOut(_)) => self.job_timed_out().await.map(Some),
            end => Ok(end),
        }
    }

    async fn duplicate_request(&mut self, request_id: RequestId) -> Result<Step, SessionError> {
        let error = WireError::new(
            ErrorCode::DuplicateRequest,
            format!("request_id `{request_id}` was already used in this session"),
        );
        self.reject_frame(Some(request_id), error).await
    }

    /// Validate, authorise and execute one request whose task exists in
    /// `received`. Every path ends the task in exactly one state.
    async fn process(
        &mut self,
        task_id: TaskId,
        request: &ToolRequest,
        shutdown: &CancellationToken,
    ) -> Result<Handled, SessionError> {
        let call = match ToolCall::from_request(&request.tool, &request.args) {
            Ok(call) => call,
            Err(error) => {
                let code = match error {
                    CallError::UnknownTool(_) => ErrorCode::UnknownTool,
                    CallError::InvalidArguments { .. } => ErrorCode::InvalidArguments,
                };
                let error = WireError::new(code, error.to_string());
                let change = TaskChange {
                    error: Some(error.clone()),
                    ..TaskChange::to(TaskStatus::Rejected)
                };
                let event = AuditEventKind::RequestRejected {
                    error: error.clone(),
                };
                self.transition(task_id, TaskStatus::Received, change, vec![event])
                    .await?;
                return Ok(Handled::Reply(ToolOutcome::Rejected { error }));
            }
        };

        let capabilities = required_capabilities(&call);
        let evaluation = self.ctx.policy.evaluate(&capabilities);
        let evaluated = AuditEventKind::PolicyEvaluated {
            capabilities: capabilities.clone(),
            decision: evaluation.decision,
        };
        let decided = |status| TaskChange {
            decision: Some(evaluation.decision),
            capabilities: Some(capabilities.clone()),
            ..TaskChange::to(status)
        };

        match evaluation.decision {
            PolicyDecision::Deny => {
                self.transition(
                    task_id,
                    TaskStatus::Received,
                    decided(TaskStatus::Denied),
                    vec![evaluated],
                )
                .await?;
                Ok(Handled::Reply(ToolOutcome::Denied {
                    capabilities,
                    reason: evaluation.reason,
                }))
            }
            PolicyDecision::Allow => {
                // Decide, record, then act: if this write fails, the tool
                // never runs.
                let started = AuditEventKind::ExecutionStarted {
                    tool: call.tool_name().to_owned(),
                };
                self.transition(
                    task_id,
                    TaskStatus::Received,
                    decided(TaskStatus::Executing),
                    vec![evaluated, started],
                )
                .await?;
                self.execute(task_id, &call, shutdown)
                    .await
                    .map(Handled::Reply)
            }
            PolicyDecision::RequireConfirmation => {
                let approval_id = ApprovalId::new();
                let fingerprint =
                    approval::fingerprint(task_id, &request.request_id, &call, &capabilities);
                let new = NewApproval {
                    approval_id,
                    task_id,
                    session_id: self.id,
                    request_id: request.request_id.clone(),
                    tool: request.tool.clone(),
                    capabilities: capabilities.clone(),
                    fingerprint: fingerprint.clone(),
                    expires_at_ms: now_ms().saturating_add(
                        i64::try_from(self.ctx.approval_ttl.as_millis()).unwrap_or(i64::MAX),
                    ),
                };
                // Register before the request is visible, so no decision is missed.
                let notify = self.ctx.hub.approvals.register(approval_id);
                let change = decided(TaskStatus::AwaitingConfirmation);
                let requested = self
                    .ctx
                    .store
                    .call(move |s| s.request_approval(&new, &change, &[evaluated]))
                    .await;
                if let Err(error) = requested {
                    self.ctx.hub.approvals.remove(approval_id);
                    return Err(error.into());
                }
                tracing::info!(session = %self.id, task = %task_id, approval = %approval_id, "waiting for a person");
                self.ctx.hub.changed();
                let handled = self
                    .await_decision(approval_id, task_id, &call, &fingerprint, &notify, shutdown)
                    .await;
                self.ctx.hub.approvals.remove(approval_id);
                handled
            }
        }
    }

    /// Wait until a person decides, the approval expires, the worker goes
    /// away or the Core shuts down. The store is re-read after every wake-up
    /// and is the only source of truth.
    async fn await_decision(
        &mut self,
        approval_id: ApprovalId,
        task_id: TaskId,
        call: &ToolCall,
        fingerprint: &Fingerprint,
        notify: &Notify,
        shutdown: &CancellationToken,
    ) -> Result<Handled, SessionError> {
        let expired = ToolOutcome::Expired { approval_id };
        loop {
            let record = self
                .ctx
                .store
                .call(move |s| s.approval(approval_id))
                .await?
                .ok_or_else(|| StoreError::Corrupt(format!("approval {approval_id} vanished")))?;
            match record.status {
                ApprovalStatus::Granted => {
                    return self
                        .consume_and_execute(approval_id, task_id, call, fingerprint, shutdown)
                        .await;
                }
                ApprovalStatus::Denied => {
                    let reason = Summary::lossy(record.reason.as_deref().unwrap_or(""));
                    return Ok(Handled::Reply(ToolOutcome::Declined {
                        approval_id,
                        reason,
                    }));
                }
                ApprovalStatus::Expired | ApprovalStatus::Consumed => {
                    return Ok(Handled::Reply(expired));
                }
                ApprovalStatus::Pending => {}
            }

            let remaining = record.expires_at_ms.saturating_sub(now_ms());
            if remaining <= 0 {
                self.expire(approval_id, "no decision before the approval expired")
                    .await?;
                continue;
            }
            let wait = Duration::from_millis(u64::try_from(remaining).unwrap_or(0));
            let job = self.job.as_ref().map(|job| (job.id, job.deadline));
            tokio::select! {
                biased;
                () = shutdown.cancelled() => {
                    self.expire(approval_id, "the Core is shutting down").await?;
                    return Ok(Handled::End(SessionEnd::Shutdown, Some(expired)));
                }
                () = sleep_until(job.map(|(_, deadline)| deadline)) => {
                    self.expire(approval_id, "the job exceeded its time limit").await?;
                    let end = job.map_or(SessionEnd::WorkerGone, |(id, _)| SessionEnd::JobTimedOut(id));
                    return Ok(Handled::End(end, Some(expired)));
                }
                () = notify.notified() => {}
                () = tokio::time::sleep(wait) => {}
                read = self.reader.next_frame() => match read {
                    Err(_) | Ok(None) => {
                        self.expire(approval_id, "the worker went away").await?;
                        let end = if read.is_err() { SessionEnd::WorkerGone } else { SessionEnd::WorkerClosed };
                        return Ok(Handled::End(end, None));
                    }
                    Ok(Some(frame)) => {
                        if self.backlog.len() >= MAX_BACKLOG {
                            self.expire(approval_id, "the worker sent too many requests while waiting").await?;
                            let error = WireError::new(
                                ErrorCode::LimitExceeded,
                                format!("more than {MAX_BACKLOG} frames while a request waited for a person"),
                            );
                            return Ok(Handled::End(SessionEnd::Terminated(error), Some(expired)));
                        }
                        self.backlog.push_back(frame);
                    }
                },
            }
        }
    }

    /// Use the granted approval and run the call. The approval is consumed,
    /// the task moves to `executing` and `execution_started` is recorded in one
    /// transaction before the tool runs; if any check fails, nothing runs.
    async fn consume_and_execute(
        &mut self,
        approval_id: ApprovalId,
        task_id: TaskId,
        call: &ToolCall,
        fingerprint: &Fingerprint,
        shutdown: &CancellationToken,
    ) -> Result<Handled, SessionError> {
        let mut events = vec![AuditEventKind::ExecutionStarted {
            tool: call.tool_name().to_owned(),
        }];
        // A clipboard write names its text by payload (ADR 0022). The text is
        // resolved and checked against the SHA-256 the person approved
        // before anything is consumed: a payload that is gone or was changed
        // is refused here and nothing is written.
        let text = match call {
            ToolCall::WriteClipboardText(args) => {
                let args = args.clone();
                let job_id = self.job.as_ref().map(|job| job.id);
                let resolved = self
                    .ctx
                    .store
                    .call(move |s| Ok(approval::resolve_payload(s, &args, job_id)))
                    .await?;
                match resolved {
                    Resolution::Text(text) => Some(text),
                    Resolution::Missing | Resolution::Changed => {
                        let refusal = Refusal::PayloadUnavailable;
                        tracing::warn!(session = %self.id, task = %task_id, approval = %approval_id, "clipboard text refused before consumption: {resolved:?}");
                        self.expire_with(
                            approval_id,
                            format!("the Session Agent cannot take this operation: {refusal}"),
                        )
                        .await?;
                        return Ok(Handled::Reply(ToolOutcome::Expired { approval_id }));
                    }
                }
            }
            _ => None,
        };
        if call.is_agent_operation() {
            // The grant checks run, and a live agent is started, before the
            // approval is used, so these refusals leave nothing consumed. A
            // race after this point is recorded as not performed.
            let ready = match &self.ctx.session_agent {
                None => Err(Refusal::Unavailable),
                Some(agent) => {
                    let (ready, lifecycle) = agent.prepare(call, text.as_ref()).await;
                    for event in lifecycle {
                        self.audit(Some(task_id), event).await?;
                    }
                    ready.map(|()| agent.grant_ttl_ms())
                }
            };
            match ready {
                Ok(ttl_ms) => events.push(AuditEventKind::SessionAgentDispatched {
                    grant_id: approval_id,
                    tool: call.tool_name().to_owned(),
                    ttl_ms,
                }),
                Err(refusal) => {
                    tracing::warn!(session = %self.id, task = %task_id, approval = %approval_id, "Session Agent refused before consumption: {refusal}");
                    self.expire_with(
                        approval_id,
                        format!("the Session Agent cannot take this operation: {refusal}"),
                    )
                    .await?;
                    return Ok(Handled::Reply(ToolOutcome::Expired { approval_id }));
                }
            }
        }
        let fingerprint = fingerprint.clone();
        let consumed = self
            .ctx
            .store
            .call(move |s| Ok(s.consume_approval(approval_id, &fingerprint, now_ms(), &events)))
            .await?;
        self.ctx.hub.changed();
        match consumed {
            Ok(consumed) if call.is_agent_operation() => {
                tracing::info!(session = %self.id, task = %task_id, approval = %approval_id, "approval consumed for the Session Agent");
                self.perform_agent(task_id, consumed, call, text.as_ref(), shutdown)
                    .await
                    .map(Handled::Reply)
            }
            Ok(_consumed) => {
                tracing::info!(session = %self.id, task = %task_id, approval = %approval_id, "approval consumed");
                self.execute(task_id, call, shutdown)
                    .await
                    .map(Handled::Reply)
            }
            Err(ApprovalError::Store(error)) => Err(error.into()),
            Err(ApprovalError::Expired) => Ok(Handled::Reply(ToolOutcome::Expired { approval_id })),
            Err(other) => {
                // The approval no longer matches what would run. Never run it.
                tracing::error!(session = %self.id, task = %task_id, approval = %approval_id, "refusing to use approval: {other}");
                self.expire(approval_id, "the approval did not match the request")
                    .await?;
                Ok(Handled::Reply(ToolOutcome::Expired { approval_id }))
            }
        }
    }

    async fn expire(
        &self,
        approval_id: ApprovalId,
        reason: &'static str,
    ) -> Result<(), SessionError> {
        self.expire_with(approval_id, reason.to_owned()).await
    }

    async fn expire_with(
        &self,
        approval_id: ApprovalId,
        reason: String,
    ) -> Result<(), SessionError> {
        self.ctx
            .store
            .call(move |s| s.expire_approval(approval_id, &reason))
            .await?;
        self.ctx.hub.changed();
        Ok(())
    }

    /// Issue a grant from the approval just consumed and have the Session
    /// Agent perform the call once. The task is `executing`, with
    /// `approval_consumed`, `execution_started` and `session_agent_dispatched`
    /// already committed. Every path ends it in exactly one state with its
    /// events in the same transaction:
    ///
    /// - performed: `completed`, and the worker gets a receipt only;
    /// - refused by the Core or the agent: `failed` with `tool_failed`, since
    ///   nothing happened;
    /// - no valid answer: `failed` with `internal`, so a job holding it is
    ///   never resumed (ADR 0015).
    async fn perform_agent(
        &self,
        task_id: TaskId,
        consumed: ConsumedApproval,
        call: &ToolCall,
        text: Option<&ClipboardText>,
        shutdown: &CancellationToken,
    ) -> Result<ToolOutcome, SessionError> {
        let started = std::time::Instant::now();
        let grant_id = consumed.approval_id();
        let (performed, mut events) = match &self.ctx.session_agent {
            None => (
                Performed::Refused(Refusal::Unavailable.to_string()),
                Vec::new(),
            ),
            Some(agent) => match agent.issue(consumed, call, text).await {
                Err(refusal) => (Performed::Refused(refusal.to_string()), Vec::new()),
                Ok(grant) => {
                    let report = agent.perform(grant, call, shutdown).await;
                    (report.performed, report.events)
                }
            },
        };
        let duration_ms = millis(started.elapsed());
        let (status, change, outcome, event) = match performed {
            Performed::Done(report) => {
                let result = ToolResult::AgentReceipt(AgentReceipt {
                    agent_operation: call.tool_name().to_owned(),
                });
                let json = serde_json::to_string(&result)?;
                let change = TaskChange {
                    result: Some(json),
                    ..TaskChange::to(TaskStatus::Completed)
                };
                let event = AuditEventKind::SessionAgentCompleted { grant_id, report };
                (
                    TaskStatus::Completed,
                    change,
                    ToolOutcome::Completed { result },
                    event,
                )
            }
            Performed::Refused(reason) => {
                // The reason stays in the audit log: it says whether the
                // agent runs, which is none of the worker's business.
                let error = WireError::new(
                    ErrorCode::ToolFailed,
                    "the Session Agent operation was not performed",
                );
                let event = AuditEventKind::SessionAgentRefused {
                    grant_id: Some(grant_id),
                    reason,
                };
                failed_agent(error, event)
            }
            Performed::Unknown(reason) => {
                let error = WireError::new(
                    ErrorCode::Internal,
                    "the Session Agent did not confirm the outcome; it is not retried",
                );
                let event = AuditEventKind::SessionAgentOutcomeUnknown { grant_id, reason };
                failed_agent(error, event)
            }
        };
        events.push(event);
        events.push(AuditEventKind::ExecutionFinished {
            status,
            duration_ms,
            error: change.error.clone(),
        });
        self.transition(task_id, TaskStatus::Executing, change, events)
            .await?;
        Ok(outcome)
    }

    /// Run a call whose task is already `executing` and record the outcome.
    async fn execute(
        &self,
        task_id: TaskId,
        call: &ToolCall,
        shutdown: &CancellationToken,
    ) -> Result<ToolOutcome, SessionError> {
        let executed = self.ctx.gateway.execute(call, shutdown).await;
        let duration_ms = millis(executed.duration);
        match executed.execution {
            Execution::Completed { result, json } => {
                let change = TaskChange {
                    result: Some(json),
                    ..TaskChange::to(TaskStatus::Completed)
                };
                let finished = AuditEventKind::ExecutionFinished {
                    status: TaskStatus::Completed,
                    duration_ms,
                    error: None,
                };
                self.transition(task_id, TaskStatus::Executing, change, vec![finished])
                    .await?;
                Ok(ToolOutcome::Completed { result })
            }
            Execution::Failed { status, error } => {
                let change = TaskChange {
                    error: Some(error.clone()),
                    ..TaskChange::to(status)
                };
                let finished = AuditEventKind::ExecutionFinished {
                    status,
                    duration_ms,
                    error: Some(error.clone()),
                };
                self.transition(task_id, TaskStatus::Executing, change, vec![finished])
                    .await?;
                Ok(ToolOutcome::Failed { error })
            }
        }
    }

    /// Record a frame that did not create a task and answer with a
    /// non-fatal error, unless the session's error budget is spent.
    async fn reject_frame(
        &mut self,
        request_id: Option<RequestId>,
        error: WireError,
    ) -> Result<Step, SessionError> {
        self.errors += 1;
        if self.errors > self.ctx.limits.max_protocol_errors {
            self.audit(
                None,
                AuditEventKind::FrameRejected {
                    request_id: request_id.clone(),
                    error,
                },
            )
            .await?;
            let limit = WireError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "more than {} protocol errors in this session",
                    self.ctx.limits.max_protocol_errors
                ),
            );
            return self.terminate(request_id, limit).await;
        }
        tracing::warn!(session = %self.id, code = %error.code, "frame rejected");
        self.audit(
            None,
            AuditEventKind::FrameRejected {
                request_id: request_id.clone(),
                error: error.clone(),
            },
        )
        .await?;
        let message = CoreMessage::Error(ErrorMessage {
            request_id,
            error,
            fatal: false,
        });
        self.send(&message).await
    }

    /// Record a fatal error, tell the worker (best effort) and end the session.
    async fn terminate(
        &mut self,
        request_id: Option<RequestId>,
        error: WireError,
    ) -> Result<Step, SessionError> {
        tracing::warn!(session = %self.id, code = %error.code, "closing session: {}", error.message);
        self.audit(
            None,
            AuditEventKind::FrameRejected {
                request_id: request_id.clone(),
                error: error.clone(),
            },
        )
        .await?;
        let message = CoreMessage::Error(ErrorMessage {
            request_id,
            error: error.clone(),
            fatal: true,
        });
        // The session ends either way; a failed write only means the worker
        // is already gone.
        let _ = self.send(&message).await?;
        Ok(Some(SessionEnd::Terminated(error)))
    }

    async fn close(&mut self, end: &SessionEnd) -> Result<(), SessionError> {
        if self.opened {
            let id = self.id;
            let expired = self
                .ctx
                .store
                .call(move |s| s.expire_awaiting(id, "the session closed before a decision"))
                .await?;
            if expired > 0 {
                tracing::info!(session = %self.id, expired, "pending approvals expired");
            }
        }
        if let Some(job) = self.job.take() {
            match end {
                // The worker or the Core stopped: the job may be resumed.
                SessionEnd::WorkerClosed | SessionEnd::WorkerGone | SessionEnd::Shutdown => {
                    self.requeue_or_close(job.id, end).await?;
                }
                // A protocol violation or a job past its time limit: retrying
                // would repeat it.
                SessionEnd::Terminated(_)
                | SessionEnd::JobTimedOut(_)
                | SessionEnd::HandshakeTimeout => {
                    let summary = Some(Summary::lossy(&format!(
                        "the worker stopped: {}",
                        end.describe()
                    )));
                    self.finish_job(job.id, JobStatus::Failed, summary).await?;
                }
            }
        }
        self.audit(
            None,
            AuditEventKind::SessionClosed {
                reason: end.describe(),
                requests: self.requests,
            },
        )
        .await?;
        self.ctx.hub.changed();
        tracing::info!(session = %self.id, requests = self.requests, "session closed: {}", end.describe());
        Ok(())
    }

    /// Write one frame. A worker that stops reading would otherwise block
    /// this write forever once the pipe fills, so the write is bounded by
    /// `write_timeout`; running out of time ends the session.
    async fn send(&mut self, message: &CoreMessage) -> Result<Step, SessionError> {
        let mut bytes = encode_core_message(message)?;
        bytes.push(b'\n');
        let write = async {
            self.writer.write_all(&bytes).await?;
            self.writer.flush().await
        };
        match tokio::time::timeout(self.ctx.limits.write_timeout, write).await {
            Ok(Ok(())) => Ok(None),
            Ok(Err(_)) => Ok(Some(SessionEnd::WorkerGone)),
            Err(_) => {
                tracing::warn!(session = %self.id, "worker stopped reading; closing the session");
                Ok(Some(SessionEnd::WorkerGone))
            }
        }
    }

    async fn audit(
        &self,
        task_id: Option<TaskId>,
        event: AuditEventKind,
    ) -> Result<(), SessionError> {
        let session_id = self.id;
        self.ctx
            .store
            .call(move |s| s.append(Some(session_id), task_id, &event))
            .await?;
        Ok(())
    }

    async fn transition(
        &self,
        task_id: TaskId,
        from: TaskStatus,
        change: TaskChange,
        events: Vec<AuditEventKind>,
    ) -> Result<(), SessionError> {
        self.ctx
            .store
            .call(move |s| s.transition(task_id, &[from], &change, &events))
            .await?;
        Ok(())
    }

    fn too_large(&self) -> WireError {
        WireError::new(
            ErrorCode::FrameTooLarge,
            format!(
                "frame exceeds the {}-byte limit",
                self.ctx.limits.max_frame_bytes
            ),
        )
    }
}

fn failed_agent(
    error: WireError,
    event: AuditEventKind,
) -> (TaskStatus, TaskChange, ToolOutcome, AuditEventKind) {
    let change = TaskChange {
        error: Some(error.clone()),
        ..TaskChange::to(TaskStatus::Failed)
    };
    (
        TaskStatus::Failed,
        change,
        ToolOutcome::Failed { error },
        event,
    )
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn tool_names() -> Vec<ToolName> {
    ToolCall::NAMES
        .iter()
        .filter_map(|name| ToolName::try_from((*name).to_owned()).ok())
        .collect()
}

fn outcome_name(outcome: &ToolOutcome) -> &'static str {
    match outcome {
        ToolOutcome::Completed { .. } => "completed",
        ToolOutcome::Denied { .. } => "denied",
        ToolOutcome::Declined { .. } => "declined",
        ToolOutcome::Expired { .. } => "expired",
        ToolOutcome::Rejected { .. } => "rejected",
        ToolOutcome::Failed { .. } => "failed",
    }
}
