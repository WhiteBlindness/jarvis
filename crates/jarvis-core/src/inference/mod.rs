//! The local model, brokered by the Core (ADR 0021).
//!
//! The Core starts a model server on loopback ([`server`]), sends it the
//! conversation and streams the reply into memory, where clients read it
//! with `chat_poll`. The model has no tools and no authority: its reply is
//! text for a person to read. The only thing read back from it is a
//! clipboard proposal ([`prompt::clipboard_proposal`]), which a person may
//! submit as an ordinary job, where policy and a single-use approval apply
//! as to any other.
//!
//! One reply is generated at a time. While the gaming governor reports a
//! game, the server is stopped (or replaced by the fallback model), so the
//! game has the GPU.

pub mod chat_store;
mod http;
pub mod prompt;
mod server;

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use jarvis_protocol::{
    AuditEventKind, CONTEXT_SIZES, ChatDelta, ChatLanguage, ChatRole, ChatText, ChatTurn,
    ClipboardProposal, ConversationId, ConversationSummary, ConversationView, GovernorPhase,
    GovernorReason, InferenceState, InferenceView, MessageId, MessageStatus, ModelProfile,
    RETENTION_DAYS, SearchQuery, TurnStats,
};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::config::{InferenceConfig, ModelConfig, OnGame};
use crate::governor::Status as GovernorStatus;
use crate::store::{Store, now_ms};
use chat_store::{ChatStore, ChatStoreError};

/// Largest persona file.
const MAX_PERSONA_BYTES: u64 = 16 * 1024;
/// Largest reply kept, whatever `max_reply_tokens` allows.
const MAX_REPLY_BYTES: usize = 64 * 1024;
/// How often old conversations are looked for when retention is set.
const RETENTION_SWEEP: Duration = Duration::from_secs(6 * 60 * 60);

#[derive(Debug, thiserror::Error)]
pub enum InferenceError {
    #[error("Donna is still answering; stop or wait for the current reply")]
    Busy,
    #[error("no such {0}")]
    NotFound(&'static str),
    #[error("the model is paused while a game runs")]
    Paused,
    #[error("{0}")]
    Invalid(String),
    #[error("the model could not be loaded: {0}")]
    Load(String),
    #[error(transparent)]
    Store(#[from] ChatStoreError),
}

/// A reply being generated, or the last one generated.
#[derive(Debug)]
struct Turn {
    id: MessageId,
    text: String,
    status: MessageStatus,
    error: Option<String>,
    stats: Option<TurnStats>,
    proposal: Option<ClipboardProposal>,
    /// Whether the person's message asked for a copy; without it, no
    /// proposal is read from the reply.
    copy_requested: bool,
    cancel: CancellationToken,
}

impl Turn {
    fn running(&self) -> bool {
        !self.status.is_final()
    }
}

#[derive(Debug)]
struct Inner {
    phase: InferenceState,
    profile: ModelProfile,
    context_size: u32,
    loaded: bool,
    /// The model server's process, refused by the RPC server like the
    /// worker, from the moment it is started.
    server_pid: Option<u32>,
    /// What the running server was started with; a server started for
    /// another profile or context size is not reused.
    server_runs: Option<(ModelProfile, u32)>,
    /// Cancels a load in progress (a game started, an unload, shutdown).
    load_cancel: CancellationToken,
    /// A send has passed its checks and is storing its message; another
    /// send must wait.
    starting: bool,
    last_error: Option<String>,
    load_ms: Option<u64>,
    last_stats: Option<TurnStats>,
    warmup_x10: Option<u32>,
    turn: Option<Turn>,
    game: bool,
    /// Load again when the game ends.
    reload_after_game: bool,
}

impl Inner {
    fn busy(&self) -> bool {
        self.starting || self.turn.as_ref().is_some_and(Turn::running)
    }
}

/// Puts the model state back if a load ends without settling it: the load's
/// future was dropped (its reply was cancelled or timed out, or its client
/// left) or cancelled.
struct LoadGuard<'a> {
    inference: &'a Inference,
    armed: bool,
}

impl Drop for LoadGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        {
            let mut inner = self.inference.inner();
            inner.server_pid = None;
            if inner.phase == InferenceState::Loading {
                inner.phase = if inner.game && self.inference.config.on_game == OnGame::Unload {
                    InferenceState::PausedForGame
                } else {
                    InferenceState::Unloaded
                };
            }
        }
        self.inference.changed();
    }
}

/// Clears `starting` however a send ends.
struct StartGuard<'a>(&'a Inference);

impl Drop for StartGuard<'_> {
    fn drop(&mut self) {
        self.0.inner().starting = false;
    }
}

#[derive(Debug)]
pub struct Inference {
    config: InferenceConfig,
    chats: ChatStore,
    audit: Store,
    persona: String,
    inner: Mutex<Inner>,
    /// Bumped on every change to a reply or the model state. Separate from
    /// the hub's counter so that streaming does not wake approval polls.
    changes: watch::Sender<u64>,
    /// The running server; held while loading or unloading.
    server: tokio::sync::Mutex<Option<server::Server>>,
    /// Days after which conversations are deleted (0: kept). A person's
    /// choice is stored in the chat database; the configuration is the
    /// default.
    retention: watch::Sender<u32>,
}

const RETENTION_KEY: &str = "retention_days";

impl Inference {
    pub fn open(config: InferenceConfig, audit: Store) -> Result<Arc<Self>, InferenceError> {
        let persona = read_persona(&config)?;
        let chats = ChatStore::open(&config.chat_database)?;
        let stored = chats.with(|conn| chat_store::setting(conn, RETENTION_KEY))?;
        let retention_days = stored
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|days| RETENTION_DAYS.contains(days))
            .unwrap_or(config.retention_days);
        let inner = Inner {
            phase: InferenceState::Unloaded,
            profile: ModelProfile::Primary,
            context_size: config.context_size,
            loaded: false,
            server_pid: None,
            server_runs: None,
            load_cancel: CancellationToken::new(),
            starting: false,
            last_error: None,
            load_ms: None,
            last_stats: None,
            warmup_x10: None,
            turn: None,
            game: false,
            reload_after_game: false,
        };
        Ok(Arc::new(Self {
            config,
            chats,
            audit,
            persona,
            inner: Mutex::new(inner),
            changes: watch::Sender::new(0),
            server: tokio::sync::Mutex::new(None),
            retention: watch::Sender::new(retention_days),
        }))
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn changed(&self) {
        self.changes.send_modify(|v| *v = v.wrapping_add(1));
    }

    fn model(&self, profile: ModelProfile) -> &ModelConfig {
        match (profile, &self.config.fallback) {
            (ModelProfile::Fallback, Some(fallback)) => fallback,
            _ => &self.config.primary,
        }
    }

    /// Whether `pid` is the model server. Its output derives from the
    /// model, so it must never reach the RPC interface.
    pub fn is_server_process(&self, pid: u32) -> bool {
        self.inner().server_pid == Some(pid)
    }

    pub fn status(&self) -> InferenceView {
        let inner = self.inner();
        let model = self.model(inner.profile);
        InferenceView {
            state: inner.phase,
            profile: inner.profile,
            model: model.name.clone(),
            model_sha256: model.sha256.clone(),
            context_size: inner.context_size,
            gpu_layers: model.gpu_layers,
            last_error: inner.last_error.clone(),
            load_ms: inner.load_ms,
            last_stats: inner.last_stats.clone(),
            retention_days: *self.retention.borrow(),
            warmup_tokens_per_second_x10: inner.warmup_x10,
            slow: inner.warmup_x10.is_some_and(|x10| {
                model.gpu_layers > 0
                    && self.config.slow_below_tokens_per_second > 0
                    && x10 < self.config.slow_below_tokens_per_second * 10
            }),
        }
    }

    /// Start the server unless it runs. Returns its port and key.
    ///
    /// Audit reasons are fixed strings: what the server logs may quote what
    /// it was sent, and the audit log cannot be deleted. Details go to the
    /// Core's log and to `last_error`, which is not stored.
    async fn ensure_loaded(&self) -> Result<(u16, String), InferenceError> {
        let mut slot = self.server.lock().await;
        let wanted = {
            let inner = self.inner();
            (inner.profile, inner.context_size)
        };
        if let Some(running) = slot.as_mut() {
            // A server killed a moment ago may not have been reaped yet, so
            // it must also answer.
            let current = self.inner().server_runs == Some(wanted);
            if current && !running.has_exited() && running.healthy().await {
                return Ok((running.port, running.key.clone()));
            }
            tracing::warn!(log = %running.recent_log(), current, "replacing the model server");
            *slot = None;
            {
                let mut inner = self.inner();
                inner.loaded = false;
                inner.server_pid = None;
                inner.server_runs = None;
                inner.warmup_x10 = None;
            }
            let reason = if current {
                "the model server stopped answering"
            } else {
                "the model server was started for other settings"
            };
            self.record(AuditEventKind::InferenceStopped {
                reason: reason.to_owned(),
            })
            .await;
        }
        let cancel = {
            let mut inner = self.inner();
            if inner.game && self.config.on_game == OnGame::Unload {
                return Err(InferenceError::Paused);
            }
            inner.phase = InferenceState::Loading;
            inner.last_error = None;
            inner.load_cancel = CancellationToken::new();
            inner.load_cancel.clone()
        };
        self.changed();
        let mut guard = LoadGuard {
            inference: self,
            armed: true,
        };
        let (profile, context_size) = wanted;
        let model = self.model(profile).clone();
        let started = Instant::now();
        let loaded = async {
            self.verify(&model).await?;
            let launch = server::Launch {
                program: self.config.server.clone(),
                model: model.path.clone(),
                context_size,
                gpu_layers: model.gpu_layers,
                threads: self.config.threads,
                timeout: self.config.load_timeout,
            };
            let mut running = server::Server::spawn(&launch)
                .map_err(|error| InferenceError::Load(error.to_string()))?;
            self.inner().server_pid = Some(running.pid());
            running
                .wait_ready(launch.timeout)
                .await
                .map_err(|error| InferenceError::Load(error.to_string()))?;
            Ok(running)
        };
        let loaded: Result<server::Server, InferenceError> = tokio::select! {
            loaded = loaded => loaded,
            () = cancel.cancelled() => {
                // The guard settles the state; whoever cancelled records why.
                return Err(InferenceError::Load("the load was cancelled".into()));
            }
        };
        match loaded {
            Ok(running) => {
                guard.armed = false;
                let load_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                let endpoint = (running.port, running.key.clone());
                // A pause or unload must not wait for the speed check.
                let warmup_x10 = tokio::select! {
                    measured = warm_up(endpoint.0, &endpoint.1) => measured,
                    () = cancel.cancelled() => None,
                };
                self.inner().warmup_x10 = warmup_x10;
                *slot = Some(running);
                {
                    let mut inner = self.inner();
                    inner.loaded = true;
                    inner.server_runs = Some(wanted);
                    inner.load_ms = Some(load_ms);
                    inner.phase = if inner.busy() {
                        InferenceState::Generating
                    } else {
                        InferenceState::Ready
                    };
                }
                tracing::info!(model = %model.name, load_ms, "model loaded");
                self.record(AuditEventKind::InferenceLoaded {
                    profile,
                    model_sha256: model.sha256.clone(),
                    context_size,
                    gpu_layers: model.gpu_layers,
                    load_ms,
                })
                .await;
                self.changed();
                Ok(endpoint)
            }
            Err(error) => {
                guard.armed = false;
                tracing::error!(%error, "model load failed");
                {
                    let mut inner = self.inner();
                    inner.phase = InferenceState::Failed;
                    inner.server_pid = None;
                    inner.warmup_x10 = None;
                    inner.last_error = Some(one_line(&error.to_string(), 400));
                }
                self.record(AuditEventKind::InferenceStopped {
                    reason: "the model could not be loaded".to_owned(),
                })
                .await;
                self.changed();
                Err(error)
            }
        }
    }

    /// Check the model file against its configured SHA-256. A file hashed
    /// before at the same size and modification time is not read again.
    async fn verify(&self, model: &ModelConfig) -> Result<(), InferenceError> {
        let path = model.path.clone();
        let expected = model.sha256.clone();
        let chats = self.chats.clone();
        let checked = tokio::task::spawn_blocking(move || -> Result<(), String> {
            let meta = std::fs::metadata(&path)
                .map_err(|error| format!("cannot read the model file: {error}"))?;
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .and_then(|d| i64::try_from(d.as_nanos()).ok())
                .unwrap_or(0);
            let key = path.to_string_lossy().into_owned();
            let known = chats
                .with(|conn| chat_store::verified_sha256(conn, &key, meta.len(), modified))
                .map_err(|error| error.to_string())?;
            if known.as_deref() == Some(expected.as_str()) {
                return Ok(());
            }
            let actual = sha256_file(&path).map_err(|error| error.to_string())?;
            if actual != expected {
                return Err(format!(
                    "the model file's SHA-256 is {actual}, not the configured {expected}"
                ));
            }
            chats
                .with(|conn| chat_store::record_verified(conn, &key, meta.len(), modified, &actual))
                .map_err(|error| error.to_string())
        })
        .await
        .map_err(|_| InferenceError::Load("the model check failed".into()))?;
        checked.map_err(InferenceError::Load)
    }

    /// Stop the server. A reply being generated is cancelled.
    async fn stop_server(&self, reason: &'static str, next: InferenceState) {
        {
            let inner = self.inner();
            if let Some(turn) = inner.turn.as_ref() {
                turn.cancel.cancel();
            }
            // A load holds the server lock until it ends; cancel it first.
            inner.load_cancel.cancel();
        }
        let mut slot = self.server.lock().await;
        let was_running = slot.take().is_some();
        {
            let mut inner = self.inner();
            inner.loaded = false;
            inner.server_pid = None;
            inner.server_runs = None;
            inner.warmup_x10 = None;
            inner.phase = next;
        }
        if was_running {
            tracing::info!(reason, "model unloaded");
            self.record(AuditEventKind::InferenceStopped {
                reason: reason.to_owned(),
            })
            .await;
        }
        self.changed();
    }

    /// Start loading the model and answer at once: a load (with a first
    /// hash of the file) can outlast a client's request time. Clients
    /// follow it through `inference_status`.
    pub fn load(self: &Arc<Self>) -> Result<InferenceView, InferenceError> {
        if self.inner().game && self.config.on_game == OnGame::Unload {
            return Err(InferenceError::Paused);
        }
        self.spawn_load();
        Ok(self.status())
    }

    pub async fn unload(&self) -> InferenceView {
        let next = if self.inner().game && self.config.on_game == OnGame::Unload {
            InferenceState::PausedForGame
        } else {
            InferenceState::Unloaded
        };
        self.stop_server("unloaded on request", next).await;
        self.status()
    }

    pub async fn set_context_size(
        self: &Arc<Self>,
        context_size: u32,
    ) -> Result<InferenceView, InferenceError> {
        if !CONTEXT_SIZES.contains(&context_size) {
            return Err(InferenceError::Invalid(format!(
                "context size must be one of {CONTEXT_SIZES:?}"
            )));
        }
        let reload = {
            let mut inner = self.inner();
            if inner.busy() {
                return Err(InferenceError::Busy);
            }
            if inner.phase == InferenceState::Loading {
                return Err(InferenceError::Busy);
            }
            let changed = inner.context_size != context_size;
            inner.context_size = context_size;
            changed && inner.loaded
        };
        if reload {
            self.stop_server("context size changed", InferenceState::Unloaded)
                .await;
            self.spawn_load();
        } else {
            self.changed();
        }
        Ok(self.status())
    }

    fn spawn_load(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let _ = this.ensure_loaded().await;
        });
    }

    pub async fn shutdown(&self) {
        self.stop_server("the Core is stopping", InferenceState::Unloaded)
            .await;
    }

    pub async fn send(
        self: &Arc<Self>,
        conversation: Option<ConversationId>,
        text: ChatText,
        language: ChatLanguage,
    ) -> Result<ChatTurn, InferenceError> {
        let _reserved = self.reserve()?;
        let body = text.as_str().to_owned();
        let begun = self
            .chats
            .call(move |conn| chat_store::begin_turn(conn, conversation, &body))
            .await;
        let (conversation_id, user, reply) = match begun {
            Err(ChatStoreError::NoConversation) => {
                return Err(InferenceError::NotFound("conversation"));
            }
            other => other?,
        };
        self.start_turn(reply, language)?;
        Ok(ChatTurn {
            conversation_id,
            user_message_id: Some(user),
            turn_id: reply,
        })
    }

    pub async fn regenerate(
        self: &Arc<Self>,
        conversation: ConversationId,
        language: ChatLanguage,
    ) -> Result<ChatTurn, InferenceError> {
        let _reserved = self.reserve()?;
        let begun = self
            .chats
            .call(move |conn| chat_store::begin_regenerate(conn, conversation))
            .await;
        let reply = match begun {
            Err(ChatStoreError::NoConversation) => {
                return Err(InferenceError::NotFound("conversation"));
            }
            Err(error) => return Err(error.into()),
            Ok(None) => {
                return Err(InferenceError::Invalid(
                    "there is no finished reply to regenerate".into(),
                ));
            }
            Ok(Some(reply)) => reply,
        };
        self.start_turn(reply, language)?;
        Ok(ChatTurn {
            conversation_id: conversation,
            user_message_id: None,
            turn_id: reply,
        })
    }

    /// Check that a turn may start and hold the place until it has, so that
    /// a second send cannot store its message and then be refused.
    fn reserve(&self) -> Result<StartGuard<'_>, InferenceError> {
        let mut inner = self.inner();
        if inner.busy() {
            return Err(InferenceError::Busy);
        }
        if inner.game && self.config.on_game == OnGame::Unload {
            return Err(InferenceError::Paused);
        }
        inner.starting = true;
        Ok(StartGuard(self))
    }

    /// Start generating `reply`. Called while the place is reserved.
    fn start_turn(
        self: &Arc<Self>,
        reply: MessageId,
        language: ChatLanguage,
    ) -> Result<(), InferenceError> {
        let cancel = CancellationToken::new();
        {
            let mut inner = self.inner();
            inner.starting = false;
            inner.turn = Some(Turn {
                id: reply,
                text: String::new(),
                status: MessageStatus::Streaming,
                error: None,
                stats: None,
                proposal: None,
                copy_requested: false,
                cancel: cancel.clone(),
            });
            if inner.loaded {
                inner.phase = InferenceState::Generating;
            }
        }
        self.changed();
        let this = Arc::clone(self);
        tokio::spawn(async move { this.generate(reply, language, cancel).await });
        Ok(())
    }

    async fn generate(&self, reply: MessageId, language: ChatLanguage, cancel: CancellationToken) {
        let outcome = tokio::select! {
            // A cancel wins over the error it causes, so the reply ends
            // `cancelled`, not `failed`.
            biased;
            () = cancel.cancelled() => Err(None),
            outcome = self.stream_reply(reply, language, &cancel) => outcome,
            () = tokio::time::sleep(self.config.reply_timeout) => {
                Err(Some("the reply took too long and was stopped".to_owned()))
            }
        };
        let (status, error) = match outcome {
            Ok(()) => (MessageStatus::Complete, None),
            Err(None) => (MessageStatus::Cancelled, None),
            Err(Some(error)) => (MessageStatus::Failed, Some(error)),
        };
        let snapshot = {
            let mut inner = self.inner();
            let Some(turn) = inner.turn.as_mut().filter(|t| t.id == reply) else {
                return;
            };
            if status == MessageStatus::Complete && turn.copy_requested {
                turn.proposal = prompt::clipboard_proposal(&turn.text);
            }
            let snapshot = (turn.text.clone(), turn.stats.clone(), turn.proposal.clone());
            if let Some(stats) = &turn.stats {
                inner.last_stats = Some(stats.clone());
            }
            snapshot
        };
        let (text, stats, proposal) = snapshot;
        let saved = self
            .chats
            .call(move |conn| {
                chat_store::finish_reply(
                    conn,
                    reply,
                    &text,
                    status,
                    stats.as_ref(),
                    proposal.as_ref(),
                )
            })
            .await;
        {
            let mut inner = self.inner();
            if let Some(turn) = inner.turn.as_mut().filter(|t| t.id == reply) {
                turn.status = status;
                turn.error = match saved {
                    Err(store) => Some(format!("the reply could not be saved: {store}")),
                    Ok(()) => error,
                };
            }
            if inner.phase == InferenceState::Generating {
                inner.phase = InferenceState::Ready;
            }
        }
        self.changed();
    }

    /// Load the model if needed and stream the reply into the turn. `Err`
    /// carries a message for a person; `Err(None)` means cancelled.
    async fn stream_reply(
        &self,
        reply: MessageId,
        language: ChatLanguage,
        cancel: &CancellationToken,
    ) -> Result<(), Option<String>> {
        let (port, key) = self
            .ensure_loaded()
            .await
            .map_err(|e| Some(e.to_string()))?;
        if cancel.is_cancelled() {
            return Err(None);
        }
        self.inner().phase = InferenceState::Generating;
        self.changed();
        let history = self
            .chats
            .call(move |conn| chat_store::history_before(conn, reply))
            .await
            .map_err(|e| Some(e.to_string()))?;
        let context_size = self.inner().context_size;
        let last = history
            .iter()
            .rev()
            .find(|m| m.role == ChatRole::User)
            .map_or("", |m| m.content.as_str());
        let language = prompt::resolve_language(language, last);
        let copy_requested = prompt::asks_for_copy(last);
        let crisis = prompt::crisis_signals(last);
        let opening = prompt::crisis_opening(last, language);
        if let Some(opening) = opening
            && let Some(turn) = self.inner().turn.as_mut().filter(|t| t.id == reply)
        {
            turn.text.push_str(opening);
        }
        if let Some(turn) = self.inner().turn.as_mut().filter(|t| t.id == reply) {
            turn.copy_requested = copy_requested;
        }
        let system =
            prompt::system_prompt(&self.persona, language, &today(), copy_requested, crisis);
        let history = prompt::fit_history(
            &system,
            &history,
            context_size,
            self.config.max_reply_tokens,
        );
        let body = serde_json::to_vec(&prompt::request_body(
            &system,
            &history,
            self.config.max_reply_tokens,
            self.config.presence_penalty,
            prompt::temperature(crisis),
            opening,
        ))
        .map_err(|e| Some(e.to_string()))?;
        let sent = Instant::now();
        let request = http::Request {
            method: "POST",
            path: "/v1/chat/completions",
            key: &key,
            body: Some(&body),
        };
        let mut response = http::send(port, &request)
            .await
            .map_err(|e| Some(e.to_string()))?
            .ok()
            .await
            .map_err(|e| Some(e.to_string()))?;
        let mut first_token = None;
        let (mut finished, mut truncated) = (false, false);
        let (mut prompt_tokens, mut completion_tokens, mut speed) = (0u32, 0u32, 0f64);
        while let Some(line) = response
            .next_line()
            .await
            .map_err(|e| Some(e.to_string()))?
        {
            let Some(event) = prompt::parse_event(&line) else {
                continue;
            };
            let event = event.map_err(Some)?;
            finished |= event.finished;
            truncated |= event.truncated;
            // Model text may hold terminal escapes or invisible characters;
            // neither reaches a client, the store or a person.
            let content = event.content.map(|c| jarvis_protocol::strip_hidden(&c));
            if let Some(content) = content.filter(|c| !c.is_empty()) {
                let first = first_token.is_none();
                first_token.get_or_insert_with(|| sent.elapsed());
                let mut inner = self.inner();
                let Some(turn) = inner.turn.as_mut().filter(|t| t.id == reply) else {
                    return Err(None);
                };
                // The continuation of a Core-written opening may lack the
                // space after its full stop.
                if first && opening.is_some() && !content.starts_with(char::is_whitespace) {
                    turn.text.push(' ');
                }
                if turn.text.len() + content.len() > MAX_REPLY_BYTES {
                    return Err(Some("the reply was too long and was cut".into()));
                }
                turn.text.push_str(&content);
                drop(inner);
                self.changed();
            }
            prompt_tokens = event.prompt_tokens.unwrap_or(prompt_tokens);
            completion_tokens = event.completion_tokens.unwrap_or(completion_tokens);
            speed = event.tokens_per_second.unwrap_or(speed);
        }
        if truncated {
            return Err(Some(
                "the reply reached the length limit and was cut short".into(),
            ));
        }
        // A server that dies can close the connection cleanly (it does on
        // Linux); without its end marker the reply is cut, not complete.
        if !finished {
            return Err(Some(
                "the model server stopped before the reply was finished".into(),
            ));
        }
        let first_token = first_token.unwrap_or_else(|| sent.elapsed());
        let stats = TurnStats {
            prompt_tokens,
            completion_tokens,
            first_token_ms: u32::try_from(first_token.as_millis()).unwrap_or(u32::MAX),
            tokens_per_second_x10: tenths(speed),
        };
        if let Some(turn) = self.inner().turn.as_mut().filter(|t| t.id == reply) {
            turn.stats = Some(stats);
        }
        Ok(())
    }

    /// The reply text after `cursor`, waiting up to `wait` for more.
    pub async fn poll(
        &self,
        turn: MessageId,
        cursor: u32,
        wait: Duration,
    ) -> Result<ChatDelta, InferenceError> {
        let deadline = tokio::time::Instant::now() + wait;
        let mut changes = self.changes.subscribe();
        loop {
            changes.borrow_and_update();
            let delta = self.delta(turn, cursor).await?;
            if delta.status.is_final()
                || !delta.text.is_empty()
                || tokio::time::Instant::now() >= deadline
            {
                return Ok(delta);
            }
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => {}
                changed = changes.changed() => if changed.is_err() { return Ok(delta) },
            }
        }
    }

    async fn delta(&self, turn: MessageId, cursor: u32) -> Result<ChatDelta, InferenceError> {
        let cursor = usize::try_from(cursor).unwrap_or(usize::MAX);
        let after = |text: &str| -> Result<String, InferenceError> {
            text.get(cursor..).map(str::to_owned).ok_or_else(|| {
                InferenceError::Invalid("the cursor is not a position in the reply".into())
            })
        };
        {
            let inner = self.inner();
            if let Some(active) = inner.turn.as_ref().filter(|t| t.id == turn) {
                let done = !active.running();
                return Ok(ChatDelta {
                    turn_id: turn,
                    text: after(&active.text)?,
                    next_cursor: len32(&active.text),
                    status: active.status,
                    error: active.error.clone(),
                    stats: active.stats.clone().filter(|_| done),
                    proposal: active.proposal.clone().filter(|_| done),
                });
            }
        }
        let stored = self
            .chats
            .call(move |conn| chat_store::reply(conn, turn))
            .await?
            .ok_or(InferenceError::NotFound("reply"))?;
        Ok(ChatDelta {
            turn_id: turn,
            text: after(&stored.content)?,
            next_cursor: len32(&stored.content),
            status: stored.status,
            error: None,
            stats: stored.stats,
            proposal: stored.proposal,
        })
    }

    pub async fn cancel(&self, turn: MessageId) -> Result<ChatDelta, InferenceError> {
        if let Some(active) = self.inner().turn.as_ref().filter(|t| t.id == turn) {
            active.cancel.cancel();
        }
        // Wait briefly for the cancelled reply to be recorded.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let delta = self.delta(turn, 0).await?;
            if delta.status.is_final() || tokio::time::Instant::now() >= deadline {
                return Ok(delta);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub async fn conversations(
        &self,
        query: Option<SearchQuery>,
        limit: u32,
    ) -> Result<Vec<ConversationSummary>, InferenceError> {
        Ok(self
            .chats
            .call(move |conn| {
                chat_store::conversations(conn, query.as_ref().map(SearchQuery::as_str), limit)
            })
            .await?)
    }

    pub async fn conversation(
        &self,
        id: ConversationId,
    ) -> Result<ConversationView, InferenceError> {
        let mut view = self
            .chats
            .call(move |conn| chat_store::conversation(conn, id))
            .await?
            .ok_or(InferenceError::NotFound("conversation"))?;
        // A reply still being written is in memory, not yet in the database.
        let inner = self.inner();
        if let Some(active) = inner.turn.as_ref().filter(|t| t.running())
            && let Some(message) = view.messages.iter_mut().find(|m| m.message_id == active.id)
        {
            message.content.clone_from(&active.text);
        }
        Ok(view)
    }

    pub async fn delete_conversation(&self, id: ConversationId) -> Result<u32, InferenceError> {
        self.forget_turn(Some(id)).await;
        let deleted = self
            .chats
            .call(move |conn| chat_store::delete_conversation(conn, id))
            .await?;
        if !deleted {
            return Err(InferenceError::NotFound("conversation"));
        }
        self.changed();
        Ok(1)
    }

    pub async fn delete_all(&self) -> Result<u32, InferenceError> {
        self.forget_turn(None).await;
        let deleted = self.chats.call(chat_store::delete_all).await?;
        self.changed();
        Ok(deleted)
    }

    /// Before deleting a conversation (every conversation when `None`): stop
    /// a reply being written into it and drop its text from memory.
    async fn forget_turn(&self, conversation: Option<ConversationId>) {
        let Some(turn) = self.inner().turn.as_ref().map(|t| t.id) else {
            return;
        };
        let belongs = match conversation {
            None => true,
            Some(id) => self
                .chats
                .call(move |conn| {
                    Ok(chat_store::conversation(conn, id)?
                        .is_some_and(|c| c.messages.iter().any(|m| m.message_id == turn)))
                })
                .await
                .unwrap_or(true),
        };
        if belongs {
            let _ = self.cancel(turn).await;
            let mut inner = self.inner();
            if inner.turn.as_ref().is_some_and(|t| t.id == turn) {
                inner.turn = None;
            }
        }
    }

    /// Follow the gaming governor: stop the model (or switch to the
    /// fallback) while a game runs, and restore it afterwards. Also loads
    /// the model at start when configured, once the governor has looked.
    pub async fn follow_governor(
        self: Arc<Self>,
        mut governor: watch::Receiver<GovernorStatus>,
        stop: CancellationToken,
    ) {
        let mut started = false;
        loop {
            let status = governor.borrow_and_update().clone();
            if let Some(game) = game_running(&status) {
                self.set_game(game).await;
                if !started {
                    started = true;
                    if self.config.load_on_start && !game {
                        self.spawn_load();
                    }
                }
            }
            tokio::select! {
                () = stop.cancelled() => return,
                changed = governor.changed() => if changed.is_err() { return },
            }
        }
    }

    async fn set_game(self: &Arc<Self>, game: bool) {
        let was_loaded = {
            let mut inner = self.inner();
            if inner.game == game {
                return;
            }
            inner.game = game;
            inner.loaded || inner.phase == InferenceState::Loading
        };
        if game {
            self.inner().reload_after_game = was_loaded;
            match self.config.on_game {
                OnGame::Unload => {
                    self.stop_server("a game is running", InferenceState::PausedForGame)
                        .await;
                }
                OnGame::Fallback => {
                    // Switch first, so that a message sent meanwhile cannot
                    // load the primary model during the game.
                    self.inner().profile = ModelProfile::Fallback;
                    self.stop_server("a game is running", InferenceState::Unloaded)
                        .await;
                }
            }
        } else {
            let reload = {
                let mut inner = self.inner();
                let on_fallback = inner.profile == ModelProfile::Fallback;
                inner.profile = ModelProfile::Primary;
                std::mem::take(&mut inner.reload_after_game) || (on_fallback && inner.loaded)
            };
            self.stop_server("the game has ended", InferenceState::Unloaded)
                .await;
            if reload {
                self.spawn_load();
            }
        }
    }

    /// Delete conversations older than the retention period, now and then
    /// every few hours. Does nothing when retention is 0.
    pub async fn enforce_retention(self: Arc<Self>, stop: CancellationToken) {
        let mut retention = self.retention.subscribe();
        loop {
            let days = *retention.borrow_and_update();
            if days > 0 {
                let cutoff = now_ms() - i64::from(days) * 86_400_000;
                match self
                    .chats
                    .call(move |conn| chat_store::delete_older_than(conn, cutoff))
                    .await
                {
                    Ok(0) => {}
                    Ok(n) => {
                        tracing::info!(deleted = n, days, "old conversations deleted");
                        self.changed();
                    }
                    Err(error) => tracing::warn!(%error, "retention sweep failed"),
                }
            }
            tokio::select! {
                () = stop.cancelled() => return,
                changed = retention.changed() => if changed.is_err() { return },
                () = tokio::time::sleep(RETENTION_SWEEP) => {}
            }
        }
    }

    /// Change the retention period, remember it, and apply it at once.
    pub async fn set_retention(&self, days: u32) -> Result<InferenceView, InferenceError> {
        if !RETENTION_DAYS.contains(&days) {
            return Err(InferenceError::Invalid(format!(
                "retention must be one of {RETENTION_DAYS:?} days"
            )));
        }
        self.chats
            .call(move |conn| chat_store::set_setting(conn, RETENTION_KEY, &days.to_string()))
            .await?;
        self.retention.send_replace(days);
        self.changed();
        Ok(self.status())
    }

    async fn record(&self, event: AuditEventKind) {
        if let Err(error) = self
            .audit
            .call(move |s| s.append(None, None, &event).map(|_| ()))
            .await
        {
            tracing::error!(%error, "audit write failed");
        }
    }
}

/// Generate a few tokens and return the speed the server reports, in tenths
/// of a token per second. A slow result usually means part of the model is
/// not in video memory, which the server's own checks do not see.
async fn warm_up(port: u16, key: &str) -> Option<u32> {
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": "Conta de 1 a 30, separado por vírgulas."}],
        "max_tokens": 32,
        "temperature": 0.0,
        "stream": false,
        "cache_prompt": false,
    });
    let body = serde_json::to_vec(&body).ok()?;
    let request = http::Request {
        method: "POST",
        path: "/v1/chat/completions",
        key,
        body: Some(&body),
    };
    let measured = async {
        let response = http::send(port, &request).await.ok()?.ok().await.ok()?;
        let text = response.text(64 * 1024).await.ok()?;
        let value: serde_json::Value = serde_json::from_str(&text).ok()?;
        value
            .get("timings")?
            .get("predicted_per_second")?
            .as_f64()
            .filter(|n| n.is_finite() && *n > 0.0)
    };
    match tokio::time::timeout(Duration::from_secs(30), measured).await {
        Ok(Some(speed)) => {
            tracing::info!(tokens_per_second = speed, "warm-up measured");
            Some(tenths(speed))
        }
        _ => {
            tracing::warn!("warm-up measurement failed");
            None
        }
    }
}

/// Whether the governor reports a game: `None` until its first check.
fn game_running(status: &GovernorStatus) -> Option<bool> {
    match (status.phase, status.reason) {
        (GovernorPhase::Held, Some(GovernorReason::Starting)) => None,
        (GovernorPhase::Off | GovernorPhase::Open, _) => Some(false),
        (GovernorPhase::Held | GovernorPhase::Releasing, _) => Some(true),
    }
}

fn read_persona(config: &InferenceConfig) -> Result<String, InferenceError> {
    let unreadable = |error: std::io::Error| {
        InferenceError::Invalid(format!("cannot read the persona file: {error}"))
    };
    let meta = std::fs::metadata(&config.persona).map_err(unreadable)?;
    if meta.len() > MAX_PERSONA_BYTES {
        return Err(InferenceError::Invalid(format!(
            "the persona file is larger than {MAX_PERSONA_BYTES} bytes"
        )));
    }
    std::fs::read_to_string(&config.persona).map_err(unreadable)
}

fn sha256_file(path: &std::path::Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(jarvis_protocol::Fingerprint::from_digest(&digest)
        .as_str()
        .to_owned())
}

fn len32(text: &str) -> u32 {
    u32::try_from(text.len()).unwrap_or(u32::MAX)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn tenths(per_second: f64) -> u32 {
    (per_second * 10.0).round().clamp(0.0, 1_000_000.0) as u32
}

/// Today's date (UTC) as `YYYY-MM-DD`, for the system prompt.
fn today() -> String {
    humantime::format_rfc3339_seconds(SystemTime::now())
        .to_string()
        .chars()
        .take(10)
        .collect()
}

/// `text` on one line: invisible characters and control characters other
/// than line breaks and tabs are dropped, whitespace runs become one space,
/// and the result is cut to `max` characters.
pub(crate) fn one_line(text: &str, max: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    let mut space = false;
    // Server text can quote model text: no invisible characters either.
    for c in jarvis_protocol::strip_hidden(text).chars() {
        if count >= max {
            break;
        }
        if c.is_control() || c.is_whitespace() {
            if !space && count > 0 {
                out.push(' ');
                count += 1;
            }
            space = true;
        } else {
            out.push(c);
            count += 1;
            space = false;
        }
    }
    out.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_governor_counts_a_game_only_after_its_first_check() {
        let mut status = GovernorStatus::OFF;
        assert_eq!(game_running(&status), Some(false));
        status.phase = GovernorPhase::Held;
        status.reason = Some(GovernorReason::Starting);
        assert_eq!(game_running(&status), None);
        status.reason = Some(GovernorReason::Game);
        assert_eq!(game_running(&status), Some(true));
        status.reason = Some(GovernorReason::DetectionFailed);
        assert_eq!(game_running(&status), Some(true));
        status.phase = GovernorPhase::Releasing;
        status.reason = None;
        assert_eq!(game_running(&status), Some(true));
        status.phase = GovernorPhase::Open;
        assert_eq!(game_running(&status), Some(false));
    }

    #[test]
    fn one_line_flattens_and_bounds() {
        assert_eq!(one_line("a\n\n b\u{1b}c\u{202e}d", 100), "a bcd");
        assert_eq!(one_line(&"x".repeat(50), 10).chars().count(), 10);
        assert_eq!(tenths(55.55), 556);
        assert_eq!(tenths(f64::NAN), 0);
    }
}
