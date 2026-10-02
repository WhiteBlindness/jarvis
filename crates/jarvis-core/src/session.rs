//! One worker session over a pair of byte streams.
//!
//! The session reads frames, enforces the handshake and the session limits,
//! and turns each well-formed `tool_request` into a durable task:
//!
//! ```text
//! frame ─► decode ─► create task ─► resolve tool + args ─► capabilities
//!       ─► policy ─► record decision ─► Gateway ─► verify ─► record ─► reply
//! ```
//!
//! Requests are handled one at a time, in order. That is the simplest
//! correct model for a single worker and doubles as a resource limit: a
//! worker can never have more than one tool running.
//!
//! The session works on any `AsyncRead`/`AsyncWrite` pair, so tests drive it
//! over in-memory pipes and the Core drives it over a child's stdio.

use std::time::Duration;

use jarvis_protocol::{
    AuditEventKind, CallError, CoreMessage, DecodeError, ErrorCode, ErrorMessage, PolicyDecision,
    RequestId, SessionId, SessionLimits, TaskId, TaskStatus, ToolCall, ToolName, ToolOutcome,
    ToolRequest, ToolResponse, Welcome, WireError, WorkerMessage, decode_worker_message,
    encode_core_message,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::config::Limits;
use crate::framing::{Frame, FrameReader};
use crate::gateway::{Execution, Gateway};
use crate::policy::{Policy, required_capabilities};
use crate::store::{NewTask, Store, StoreError, TaskChange};

/// Everything a session needs from the Core.
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub store: Store,
    pub policy: Policy,
    pub gateway: Gateway,
    pub limits: Limits,
    pub handshake_timeout: Duration,
    pub core_version: &'static str,
}

/// Why a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEnd {
    /// The worker closed its output stream.
    WorkerClosed,
    /// Reading from or writing to the worker failed.
    WorkerGone,
    /// The worker did not send `hello` in time.
    HandshakeTimeout,
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
    };
    let end = match session.handshake(shutdown).await? {
        Some(end) => end,
        None => session.serve(shutdown).await?,
    };
    session.close(&end).await?;
    Ok(SessionReport {
        session_id: session.id,
        opened: session.opened,
        requests: session.requests,
        end,
    })
}

struct Session<'a, R, W> {
    ctx: &'a SessionContext,
    id: SessionId,
    reader: FrameReader<R>,
    writer: W,
    opened: bool,
    requests: u32,
    errors: u32,
}

/// `None` means carry on; `Some` means the session is over.
type Step = Option<SessionEnd>;

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
                tracing::info!(session = %self.id, worker = %hello.worker, version = %hello.worker_version, "session opened");
                let welcome = CoreMessage::Welcome(Welcome {
                    session_id: self.id,
                    core_version: self.ctx.core_version.to_owned(),
                    tools: tool_names(),
                    limits: SessionLimits {
                        max_frame_bytes: u32::try_from(self.ctx.limits.max_frame_bytes)
                            .unwrap_or(u32::MAX),
                        tool_timeout_ms: u64::try_from(self.ctx.gateway.timeout().as_millis())
                            .unwrap_or(u64::MAX),
                        max_requests: self.ctx.limits.max_requests_per_session,
                    },
                });
                self.send(&welcome).await
            }
        }
    }

    async fn serve(&mut self, shutdown: &CancellationToken) -> Result<SessionEnd, SessionError> {
        loop {
            let read = tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(SessionEnd::Shutdown),
                read = self.reader.next_frame() => read,
            };
            let step = match read {
                Err(_) => Some(SessionEnd::WorkerGone),
                Ok(None) => Some(SessionEnd::WorkerClosed),
                Ok(Some(Frame::TooLarge)) => self.reject_frame(None, self.too_large()).await?,
                Ok(Some(Frame::Line(bytes))) => match decode_worker_message(&bytes) {
                    Err(error @ DecodeError::UnsupportedVersion { .. }) => {
                        self.terminate(error.request_id().cloned(), error.to_wire())
                            .await?
                    }
                    Err(error) => {
                        self.reject_frame(error.request_id().cloned(), error.to_wire())
                            .await?
                    }
                    Ok(WorkerMessage::Hello(_)) => {
                        let error = WireError::new(
                            ErrorCode::UnexpectedMessage,
                            "the session is already open",
                        );
                        self.reject_frame(None, error).await?
                    }
                    Ok(WorkerMessage::ToolRequest(request)) => {
                        self.handle_request(request, shutdown).await?
                    }
                },
            };
            if let Some(end) = step {
                return Ok(end);
            }
        }
    }

    async fn handle_request(
        &mut self,
        request: ToolRequest,
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

        let task_id = TaskId::new();
        let new_task = NewTask {
            task_id,
            session_id: self.id,
            request_id: request.request_id.clone(),
            tool: request.tool.clone(),
            args: request.args.clone(),
        };
        match self.ctx.store.call(move |s| s.create_task(&new_task)).await {
            Ok(()) => self.requests += 1,
            Err(StoreError::DuplicateRequest(request_id)) => {
                let error = WireError::new(
                    ErrorCode::DuplicateRequest,
                    format!("request_id `{request_id}` was already used in this session"),
                );
                return self.reject_frame(Some(request_id), error).await;
            }
            Err(error) => return Err(error.into()),
        }

        let outcome = self.process(task_id, &request, shutdown).await?;
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
        self.send(&response).await
    }

    /// Validate, authorise and execute one request whose task exists in
    /// `received`. Every path ends the task in exactly one state.
    async fn process(
        &self,
        task_id: TaskId,
        request: &ToolRequest,
        shutdown: &CancellationToken,
    ) -> Result<ToolOutcome, SessionError> {
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
                return Ok(ToolOutcome::Rejected { error });
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
                Ok(ToolOutcome::Denied {
                    capabilities,
                    reason: evaluation.reason,
                })
            }
            PolicyDecision::RequireConfirmation => {
                self.transition(
                    task_id,
                    TaskStatus::Received,
                    decided(TaskStatus::AwaitingConfirmation),
                    vec![evaluated],
                )
                .await?;
                Ok(ToolOutcome::ConfirmationRequired {
                    capabilities,
                    reason: evaluation.reason,
                })
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

                let executed = self.ctx.gateway.execute(&call, shutdown).await;
                let duration_ms = u64::try_from(executed.duration.as_millis()).unwrap_or(u64::MAX);
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
                .call(move |s| s.expire_awaiting(id, "the session closed before confirmation"))
                .await?;
            if expired > 0 {
                tracing::info!(session = %self.id, expired, "pending confirmations expired");
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
        tracing::info!(session = %self.id, requests = self.requests, "session closed: {}", end.describe());
        Ok(())
    }

    async fn send(&mut self, message: &CoreMessage) -> Result<Step, SessionError> {
        let mut bytes = encode_core_message(message)?;
        bytes.push(b'\n');
        let written = async {
            self.writer.write_all(&bytes).await?;
            self.writer.flush().await
        }
        .await;
        Ok(written.err().map(|_| SessionEnd::WorkerGone))
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
        ToolOutcome::ConfirmationRequired { .. } => "confirmation_required",
        ToolOutcome::Rejected { .. } => "rejected",
        ToolOutcome::Failed { .. } => "failed",
    }
}
