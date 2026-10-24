//! The Core's link to its Session Agent process.
//!
//! The Core starts the agent itself, on first use, through
//! [`jarvis_sandbox::spawn_helper`], and talks to it only over the stdio
//! pipes it created for that one child. There is no named endpoint: no
//! client, worker or other process can connect to the channel, and the
//! worker's own launch inherits only its own stdio (an explicit handle list
//! on Windows, close-on-exec descriptors on Linux). The agent's identity is
//! the channel itself, an OS object only the Core and that child hold, never
//! a field in a message.
//!
//! Every operation goes through [`SessionAgent::perform`], which needs a
//! grant from [`Grants`] and uses it up before anything is sent. Whatever
//! goes wrong after a `perform` was sent (a timeout, a malformed or wrong
//! reply, the agent reporting a fault, the agent exiting, the Core shutting
//! down) ends the agent: it is
//! killed, every grant is revoked and the outcome is reported as unknown,
//! never retried. A late reply cannot be accepted because the channel it
//! would arrive on no longer exists.

use std::any::Any;
use std::ffi::OsString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use jarvis_protocol::{
    AgentOperation, AgentOutcome, AgentReport, AgentToCore, AgentVersion, AuditEventKind,
    ClipboardText, CoreToAgent, Fingerprint, MAX_AGENT_FRAME_BYTES, ToolCall, decode_agent_to_core,
    encode_agent_frame,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::{GrantId, Grants, Refusal};
use crate::config::SessionAgentConfig;
use crate::framing::{Frame, FrameReader};
use crate::store::ConsumedApproval;

/// The agent's standard output, read by the Core.
pub type AgentReader = Box<dyn AsyncRead + Send + Unpin>;
/// The agent's standard input, written by the Core.
pub type AgentWriter = Box<dyn AsyncWrite + Send + Unpin>;

/// A started agent: its two pipes, and whatever keeps it alive. Dropping
/// `keep` ends the agent.
pub struct Launched {
    pub reader: AgentReader,
    pub writer: AgentWriter,
    pub pid: Option<u32>,
    /// SHA-256 of the executable that was started, if known.
    pub image_sha256: Option<Fingerprint>,
    pub keep: Box<dyn Any + Send>,
}

impl fmt::Debug for Launched {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Launched").field("pid", &self.pid).finish()
    }
}

/// Starts the agent. Production uses [`ProcessLauncher`]; tests substitute
/// agents that fail, hang or misbehave.
pub trait Launcher: Send + Sync + fmt::Debug {
    fn launch(&self) -> io::Result<Launched>;
}

/// Starts `jarvis-session-agent` as a trusted helper.
#[derive(Debug, Clone)]
pub struct ProcessLauncher {
    program: PathBuf,
}

/// The agent's memory limit. It holds a few kilobytes of state.
const AGENT_MEMORY_BYTES: u64 = 256 * 1024 * 1024;

impl ProcessLauncher {
    pub fn new(program: PathBuf) -> Self {
        Self { program }
    }

    /// `jarvis-session-agent` next to the running executable.
    pub fn beside_current_exe() -> io::Result<Self> {
        let exe = std::env::current_exe()?;
        let dir = exe
            .parent()
            .ok_or_else(|| io::Error::other("the Core's executable has no directory"))?;
        Ok(Self::new(dir.join(format!(
            "jarvis-session-agent{}",
            std::env::consts::EXE_SUFFIX
        ))))
    }
}

/// Resolve the agent's executable, open it so that it cannot be changed
/// while it is hashed and started, and return its resolved path, the handle
/// and the file's SHA-256.
///
/// On Windows the handle shares only reading, so no process can write,
/// rename or delete the file until it is dropped after the agent has
/// started. Links and junctions are resolved before the file is opened, so
/// changing one afterwards does not redirect the start; renaming a directory
/// on the resolved path still could. Elsewhere the hash is a record only: the
/// file can change between the hash and the start. In every case a same-user
/// process can replace the file before it is opened.
fn open_image(program: &Path) -> io::Result<(PathBuf, File, Fingerprint)> {
    // Resolve links and junctions first, then open, hash and start that one
    // path, so a link changed afterwards cannot point the start elsewhere.
    let program = std::fs::canonicalize(program)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        /// `FILE_SHARE_READ`.
        const SHARE_READ: u32 = 0x1;
        options.share_mode(SHARE_READ);
    }
    let mut file = options.open(&program)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok((program, file, Fingerprint::from_digest(&digest)))
}

impl Launcher for ProcessLauncher {
    fn launch(&self) -> io::Result<Launched> {
        let (program, image, image_sha256) = open_image(&self.program)?;
        // The agent gets no environment beyond what the OS needs to load it.
        let env: Vec<(OsString, OsString)> = ["SYSTEMROOT"]
            .into_iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (name.into(), value)))
            .collect();
        let command = jarvis_sandbox::WorkerCommand {
            program,
            args: Vec::new(),
            env,
            cwd: None,
        };
        let spawned = jarvis_sandbox::spawn_helper(&command, AGENT_MEMORY_BYTES)?;
        // The image is mapped now; the lock is no longer needed.
        drop(image);
        let pid = Some(spawned.process.id());
        // The agent writes nothing to standard error; closing it means a
        // stray write fails instead of filling a pipe nobody reads.
        drop(spawned.stderr);
        Ok(Launched {
            reader: Box::new(spawned.stdout),
            writer: Box::new(spawned.stdin),
            pid,
            image_sha256: Some(image_sha256),
            keep: Box::new((spawned.process, spawned.contained)),
        })
    }
}

struct Connection {
    reader: FrameReader<AgentReader>,
    writer: AgentWriter,
    _keep: Box<dyn Any + Send>,
}

#[derive(Default)]
struct State {
    grants: Grants,
    connection: Option<Connection>,
    starts: u32,
}

/// What became of one operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Performed {
    /// The agent performed it and reported this.
    Done(AgentReport),
    /// It was not performed: the Core refused before sending, or the agent
    /// refused. Nothing happened.
    Refused(String),
    /// It was sent and no valid answer came back. It may or may not have
    /// happened, and it is never sent again.
    Unknown(String),
}

/// The outcome of [`SessionAgent::perform`], with the agent lifecycle events
/// it caused, for the caller to record with the task's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub performed: Performed,
    pub events: Vec<AuditEventKind>,
}

/// The Core's Session Agent: its grants and its one connection.
pub struct SessionAgent {
    launcher: Arc<dyn Launcher>,
    timeout: Duration,
    grant_ttl_ms: u64,
    max_starts: u32,
    epoch: Instant,
    state: Mutex<State>,
}

impl fmt::Debug for SessionAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionAgent")
            .field("launcher", &self.launcher)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl SessionAgent {
    pub fn new(launcher: Arc<dyn Launcher>, config: &SessionAgentConfig) -> Self {
        Self {
            launcher,
            timeout: config.timeout,
            grant_ttl_ms: u64::try_from(config.grant_ttl.as_millis()).unwrap_or(u64::MAX),
            max_starts: config.max_starts,
            epoch: Instant::now(),
            state: Mutex::new(State::default()),
        }
    }

    /// Milliseconds on this link's monotonic clock.
    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    pub fn grant_ttl_ms(&self) -> u64 {
        self.grant_ttl_ms
    }

    /// Make sure a grant for `call` could be issued now and that a live
    /// agent is ready to take it, starting one if needed. Called before the
    /// approval is consumed, so a refusal leaves it unused. A race with
    /// another operation can still refuse later; that is recorded as not
    /// performed. `text` is the clipboard text the Core resolved for a
    /// clipboard write (ADR 0022). Returns the agent lifecycle events it
    /// caused.
    pub async fn prepare(
        &self,
        call: &ToolCall,
        text: Option<&ClipboardText>,
    ) -> (Result<(), Refusal>, Vec<AuditEventKind>) {
        let mut state = self.state.lock().await;
        let mut events = Vec::new();
        if let Err(refusal) = state.grants.check(call, text, self.now_ms()) {
            return (Err(refusal), events);
        }
        let ready = self
            .ensure_running(&mut state, &mut events)
            .await
            .map_err(|_| Refusal::Unavailable);
        (ready, events)
    }

    /// Drop a connection whose agent has exited, then start one if there is
    /// none and the start budget allows. Nothing has been sent when this
    /// fails.
    async fn ensure_running(
        &self,
        state: &mut State,
        events: &mut Vec<AuditEventKind>,
    ) -> Result<(), String> {
        if let Some(connection) = state.connection.as_mut()
            && !alive(connection).await
        {
            state.connection = None;
            state.grants.revoke_all();
            events.push(AuditEventKind::SessionAgentStopped {
                reason: "the Session Agent exited while idle".to_owned(),
            });
        }
        if state.connection.is_some() {
            return Ok(());
        }
        if state.starts >= self.max_starts {
            return Err(Refusal::Unavailable.as_str().to_owned());
        }
        state.starts += 1;
        match self.start().await {
            Ok((connection, pid, image_sha256)) => {
                events.push(AuditEventKind::SessionAgentStarted { pid, image_sha256 });
                state.connection = Some(connection);
                Ok(())
            }
            Err(reason) => {
                state.grants.revoke_all();
                events.push(AuditEventKind::SessionAgentStopped {
                    reason: reason.clone(),
                });
                Err(reason)
            }
        }
    }

    /// Issue a grant for `call` from its consumed approval. `text` is the
    /// resolved clipboard text of a clipboard write.
    pub async fn issue(
        &self,
        consumed: ConsumedApproval,
        call: &ToolCall,
        text: Option<&ClipboardText>,
    ) -> Result<GrantId, Refusal> {
        let mut state = self.state.lock().await;
        let now_ms = self.now_ms();
        state
            .grants
            .issue(consumed, call, text, now_ms, self.grant_ttl_ms)
    }

    /// Use grant `grant` for `call` and have the agent perform it once.
    pub async fn perform(
        &self,
        grant: GrantId,
        call: &ToolCall,
        shutdown: &CancellationToken,
    ) -> Report {
        let mut state = self.state.lock().await;
        let mut events = Vec::new();
        if shutdown.is_cancelled() {
            return refused("the Core is shutting down", events);
        }
        let now_ms = self.now_ms();
        let authorization = match state.grants.authorize(grant, call, now_ms) {
            Ok(authorization) => authorization,
            Err(refusal) => return refused(refusal.as_str(), events),
        };
        // Normally `prepare` already started it; the agent may have exited
        // since. Nothing is sent until a live agent is there.
        if let Err(reason) = self.ensure_running(&mut state, &mut events).await {
            return refused(&reason, events);
        }

        let remaining = authorization.expires_at_ms().saturating_sub(self.now_ms());
        if remaining == 0 {
            return refused(Refusal::Expired.as_str(), events);
        }
        let expected = authorization.grant().approval_id();
        let operation = authorization.operation().clone();
        let perform = CoreToAgent::Perform {
            v: AgentVersion::CURRENT,
            grant_id: expected,
            operation: operation.clone(),
            ttl_ms: remaining,
        };
        let Some(connection) = state.connection.as_mut() else {
            return refused("the Session Agent is not running", events);
        };
        let exchange = tokio::time::timeout(self.timeout, exchange(connection, &perform));
        let reply = tokio::select! {
            biased;
            () = shutdown.cancelled() => Err("the Core is shutting down".to_owned()),
            reply = exchange => reply
                .unwrap_or_else(|_| Err("the Session Agent did not answer in time".to_owned())),
        };
        let reason = match reply {
            Ok(AgentToCore::Result {
                grant_id, outcome, ..
            }) if grant_id == expected => match outcome {
                AgentOutcome::Done { report } if answers(&operation, &report) => {
                    return Report {
                        performed: Performed::Done(report),
                        events,
                    };
                }
                AgentOutcome::Done { .. } => {
                    "the Session Agent reported another operation".to_owned()
                }
                AgentOutcome::Refused { reason } => {
                    let reason = format!("the agent refused: {}", reason.as_str());
                    return refused(&reason, events);
                }
                AgentOutcome::Faulted { reason } => {
                    format!(
                        "the agent could not confirm the outcome: {}",
                        reason.as_str()
                    )
                }
            },
            Ok(AgentToCore::Result { .. }) => {
                "the Session Agent answered for another grant".to_owned()
            }
            Ok(AgentToCore::Ready { .. }) => {
                "the Session Agent sent an unexpected message".to_owned()
            }
            Err(reason) => reason,
        };
        // Sent, and no valid answer: stop the agent and trust nothing it
        // was given.
        state.connection = None;
        state.grants.revoke_all();
        events.push(AuditEventKind::SessionAgentStopped {
            reason: reason.clone(),
        });
        Report {
            performed: Performed::Unknown(reason),
            events,
        }
    }

    /// Stop the agent, if it runs, and revoke every grant.
    pub async fn stop(&self, reason: &str) -> Vec<AuditEventKind> {
        let mut state = self.state.lock().await;
        state.grants.revoke_all();
        match state.connection.take() {
            Some(_) => vec![AuditEventKind::SessionAgentStopped {
                reason: reason.to_owned(),
            }],
            None => Vec::new(),
        }
    }

    async fn start(&self) -> Result<(Connection, Option<u32>, Option<Fingerprint>), String> {
        let launched = self
            .launcher
            .launch()
            .map_err(|error| format!("the Session Agent could not start: {error}"))?;
        let pid = launched.pid;
        let image_sha256 = launched.image_sha256.clone();
        let mut connection = Connection {
            reader: FrameReader::new(launched.reader, MAX_AGENT_FRAME_BYTES),
            writer: launched.writer,
            _keep: launched.keep,
        };
        let ready = tokio::time::timeout(self.timeout, connection.reader.next_frame()).await;
        match ready {
            Ok(Ok(Some(Frame::Line(bytes)))) => match decode_agent_to_core(&bytes) {
                Ok(AgentToCore::Ready { .. }) => Ok((connection, pid, image_sha256)),
                _ => Err("the Session Agent did not announce itself".to_owned()),
            },
            _ => Err("the Session Agent did not announce itself in time".to_owned()),
        }
    }
}

/// Whether the agent is still there: an idle agent sends nothing, so end of
/// input or any frame means it has exited or misbehaved.
async fn alive(connection: &mut Connection) -> bool {
    let probe = tokio::time::timeout(Duration::from_millis(5), connection.reader.next_frame());
    probe.await.is_err()
}

fn refused(reason: &str, events: Vec<AuditEventKind>) -> Report {
    Report {
        performed: Performed::Refused(reason.to_owned()),
        events,
    }
}

/// Whether `report` is the report of `operation`.
fn answers(operation: &AgentOperation, report: &AgentReport) -> bool {
    match (operation, report) {
        (AgentOperation::Healthcheck { label }, AgentReport::Healthcheck(health)) => {
            *label == health.label
        }
        (AgentOperation::WriteClipboardText { text }, AgentReport::WriteClipboardText(written)) => {
            usize::try_from(written.utf16_units)
                .is_ok_and(|units| units == text.as_str().encode_utf16().count())
        }
        _ => false,
    }
}

/// Send one `perform` and read one reply.
async fn exchange(
    connection: &mut Connection,
    perform: &CoreToAgent,
) -> Result<AgentToCore, String> {
    let mut bytes = encode_agent_frame(perform).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    let sent = async {
        connection.writer.write_all(&bytes).await?;
        connection.writer.flush().await
    };
    sent.await
        .map_err(|_| "the Session Agent's input closed".to_owned())?;
    match connection.reader.next_frame().await {
        Ok(Some(Frame::Line(bytes))) => decode_agent_to_core(&bytes)
            .map_err(|error| format!("the Session Agent sent an invalid frame: {error}")),
        Ok(Some(Frame::TooLarge)) => Err("the Session Agent sent an oversized frame".to_owned()),
        Ok(None) => Err("the Session Agent exited".to_owned()),
        Err(_) => Err("the Session Agent's output failed".to_owned()),
    }
}
