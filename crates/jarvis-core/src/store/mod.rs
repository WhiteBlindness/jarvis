//! Durable state in SQLite: tasks, the audit log and schema migrations.
//!
//! The store is synchronous and owns a single connection. Async callers go
//! through [`Store::call`], which runs the work on Tokio's blocking pool.
//!
//! Integrity rules are enforced twice: here (expected source states for
//! every transition, one transaction per transition and its audit events)
//! and in the schema (status `CHECK`, unique request IDs per session,
//! append-only audit triggers, immutable terminal tasks).

use std::ffi::OsString;
use std::fs::{self, File, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use jarvis_protocol::{
    AuditEvent, AuditEventKind, Capability, ErrorCode, PolicyDecision, RequestId, SessionId,
    TaskId, TaskStatus, ToolName, WireError,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "initial",
    sql: include_str!("migrations/0001_initial.sql"),
}];

const OPEN_STATES: [TaskStatus; 3] = [
    TaskStatus::Received,
    TaskStatus::Executing,
    TaskStatus::AwaitingConfirmation,
];

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("cannot prepare {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("database {0} is in use by another Core")]
    Locked(PathBuf),
    #[error("{0} is not a JARVIS database")]
    NotInitialised(PathBuf),
    #[error("database schema version {found} is newer than this Core supports ({supported})")]
    SchemaTooNew { found: i64, supported: i64 },
    #[error("request_id `{0}` was already used in this session")]
    DuplicateRequest(RequestId),
    #[error("task {task_id} cannot move to `{to}` from `{from}`")]
    IllegalTransition {
        task_id: TaskId,
        from: TaskStatus,
        to: TaskStatus,
    },
    #[error("task {0} does not exist")]
    UnknownTask(TaskId),
    #[error("stored data is corrupt: {0}")]
    Corrupt(String),
    #[error("database task did not complete")]
    Join,
    #[error("database connection is unusable after a panic")]
    Poisoned,
}

/// A task to insert in the `received` state.
#[derive(Debug, Clone)]
pub struct NewTask {
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub request_id: RequestId,
    pub tool: ToolName,
    pub args: serde_json::Value,
}

/// A state change and the fields it sets. Fields left as `None` keep their
/// current value.
#[derive(Debug, Clone)]
pub struct TaskChange {
    pub to: TaskStatus,
    pub decision: Option<PolicyDecision>,
    pub capabilities: Option<Vec<Capability>>,
    pub result: Option<String>,
    pub error: Option<WireError>,
}

impl TaskChange {
    pub fn to(status: TaskStatus) -> Self {
        Self {
            to: status,
            decision: None,
            capabilities: None,
            result: None,
            error: None,
        }
    }
}

/// A task as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecord {
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub request_id: RequestId,
    pub tool: String,
    pub args: String,
    pub status: TaskStatus,
    pub decision: Option<PolicyDecision>,
    pub capabilities: Option<Vec<Capability>>,
    pub result: Option<String>,
    pub error: Option<WireError>,
    pub created_at: String,
    pub updated_at: String,
}

/// Handle to the database. Cheap to clone; all clones share one connection
/// and, for a writable store, the lock file.
#[derive(Debug, Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    conn: Mutex<Connection>,
    // Held for the store's lifetime. Released when the file is closed.
    _lock: Option<File>,
}

impl Store {
    /// Open or create the database, take the exclusive lock and apply
    /// pending migrations.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|source| StoreError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let lock = acquire_lock(path)?;
        let mut conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        let mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::Corrupt(format!(
                "could not enable WAL, journal mode is {mode}"
            )));
        }
        // FULL makes every commit durable across power loss, not just
        // process crashes. Worth an fsync per commit for an audit log.
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&mut conn)?;
        Ok(Self::wrap(conn, Some(lock)))
    }

    /// Open an existing database for inspection, without taking the lock or
    /// changing anything. Safe to use while a Core is running.
    pub fn open_read_only(path: &Path) -> Result<Self, StoreError> {
        if !path.is_file() {
            return Err(StoreError::NotInitialised(path.to_path_buf()));
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(Duration::from_secs(5))?;
        let found = current_version(&conn)?;
        if found == 0 {
            return Err(StoreError::NotInitialised(path.to_path_buf()));
        }
        check_supported(found)?;
        Ok(Self::wrap(conn, None))
    }

    fn wrap(conn: Connection, lock: Option<File>) -> Self {
        Self {
            inner: Arc::new(Inner {
                conn: Mutex::new(conn),
                _lock: lock,
            }),
        }
    }

    fn conn(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.inner.conn.lock().map_err(|_| StoreError::Poisoned)
    }

    /// Run store work on the blocking pool so disk latency never stalls the
    /// async runtime.
    pub async fn call<T, F>(&self, work: F) -> Result<T, StoreError>
    where
        F: FnOnce(&Store) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        let store = self.clone();
        tokio::task::spawn_blocking(move || work(&store))
            .await
            .map_err(|_| StoreError::Join)?
    }

    pub fn schema_version(&self) -> Result<i64, StoreError> {
        current_version(&*self.conn()?)
    }

    /// Append one audit event that is not part of a task transition.
    pub fn append(
        &self,
        session_id: Option<SessionId>,
        task_id: Option<TaskId>,
        event: &AuditEventKind,
    ) -> Result<i64, StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let seq = insert_event(&tx, session_id, task_id, event)?;
        tx.commit()?;
        Ok(seq)
    }

    /// Insert a task in `received` together with its `request_received`
    /// event. A repeated `(session_id, request_id)` is refused.
    pub fn create_task(&self, task: &NewTask) -> Result<(), StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let now = now();
        let inserted = tx.execute(
            "INSERT INTO tasks (task_id, session_id, request_id, tool, args, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'received', ?6, ?6)",
            params![
                task.task_id.to_string(),
                task.session_id.to_string(),
                task.request_id.as_str(),
                task.tool.as_str(),
                task.args.to_string(),
                now,
            ],
        );
        match inserted {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE =>
            {
                return Err(StoreError::DuplicateRequest(task.request_id.clone()));
            }
            Err(error) => return Err(error.into()),
        }
        insert_event(
            &tx,
            Some(task.session_id),
            Some(task.task_id),
            &AuditEventKind::RequestReceived {
                request_id: task.request_id.clone(),
                tool: task.tool.clone(),
            },
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Move a task from one of `from` to `change.to` and append `events`, in
    /// one transaction. Any other source state is an error and changes
    /// nothing.
    pub fn transition(
        &self,
        task_id: TaskId,
        from: &[TaskStatus],
        change: &TaskChange,
        events: &[AuditEventKind],
    ) -> Result<(), StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let session_id = apply_transition(&tx, task_id, from, change)?;
        for event in events {
            insert_event(&tx, Some(session_id), Some(task_id), event)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Expire the session's tasks that still wait for confirmation. Approvals
    /// never outlive the session that asked for them.
    pub fn expire_awaiting(&self, session_id: SessionId, reason: &str) -> Result<u32, StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let ids = task_ids(
            &tx,
            "SELECT task_id FROM tasks WHERE session_id = ?1 AND status = 'awaiting_confirmation'",
            params![session_id.to_string()],
        )?;
        for &task_id in &ids {
            let change = TaskChange {
                error: Some(WireError::new(ErrorCode::Cancelled, reason)),
                ..TaskChange::to(TaskStatus::Expired)
            };
            apply_transition(&tx, task_id, &[TaskStatus::AwaitingConfirmation], &change)?;
            insert_event(
                &tx,
                Some(session_id),
                Some(task_id),
                &AuditEventKind::TaskExpired {
                    reason: reason.to_owned(),
                },
            )?;
        }
        tx.commit()?;
        Ok(u32::try_from(ids.len()).unwrap_or(u32::MAX))
    }

    /// Close every task left open by a previous run. Tasks that were received
    /// or executing become `interrupted`; tasks waiting for confirmation
    /// become `expired`. Returns how many tasks were closed.
    pub fn recover(&self) -> Result<u32, StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let open: Vec<(TaskId, SessionId, TaskStatus)> = {
            let mut statement = tx.prepare(
                "SELECT task_id, session_id, status FROM tasks
                 WHERE status IN ('received', 'executing', 'awaiting_confirmation')
                 ORDER BY created_at, task_id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            rows.map(|row| {
                let (task, session, status) = row?;
                Ok((parse(&task)?, parse(&session)?, parse(&status)?))
            })
            .collect::<Result<_, StoreError>>()?
        };
        for &(task_id, session_id, from) in &open {
            let (to, message) = if from == TaskStatus::AwaitingConfirmation {
                (
                    TaskStatus::Expired,
                    "confirmation lapsed when the Core stopped",
                )
            } else {
                (
                    TaskStatus::Interrupted,
                    "the Core stopped before the task finished",
                )
            };
            let change = TaskChange {
                error: Some(WireError::new(ErrorCode::Cancelled, message)),
                ..TaskChange::to(to)
            };
            apply_transition(&tx, task_id, &[from], &change)?;
            insert_event(
                &tx,
                Some(session_id),
                Some(task_id),
                &AuditEventKind::TaskRecovered { from, to },
            )?;
        }
        tx.commit()?;
        Ok(u32::try_from(open.len()).unwrap_or(u32::MAX))
    }

    pub fn task(&self, task_id: TaskId) -> Result<Option<TaskRecord>, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            &format!("{TASK_COLUMNS} WHERE task_id = ?1"),
            params![task_id.to_string()],
            raw_task,
        )
        .optional()?
        .map(TaskRecord::try_from)
        .transpose()
    }

    /// Most recent tasks first.
    pub fn tasks(&self, limit: u32) -> Result<Vec<TaskRecord>, StoreError> {
        let conn = self.conn()?;
        let mut statement = conn.prepare(&format!(
            "{TASK_COLUMNS} ORDER BY created_at DESC, task_id DESC LIMIT ?1"
        ))?;
        let rows = statement.query_map(params![limit], raw_task)?;
        rows.map(|row| TaskRecord::try_from(row?)).collect()
    }

    /// Audit events in sequence order, optionally for one task.
    pub fn audit_events(
        &self,
        task_id: Option<TaskId>,
        limit: u32,
    ) -> Result<Vec<AuditEvent>, StoreError> {
        let conn = self.conn()?;
        let mut statement = conn.prepare(
            "SELECT seq, at, session_id, task_id, kind, detail FROM audit_events
             WHERE ?1 IS NULL OR task_id = ?1
             ORDER BY seq LIMIT ?2",
        )?;
        let rows =
            statement.query_map(params![task_id.map(|id| id.to_string()), limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?;
        rows.map(|row| {
            let (seq, at, session_id, task_id, kind, detail) = row?;
            let event: AuditEventKind = serde_json::from_str(&detail)
                .map_err(|error| StoreError::Corrupt(format!("audit event {seq}: {error}")))?;
            if event.name() != kind {
                return Err(StoreError::Corrupt(format!(
                    "audit event {seq}: kind column `{kind}` does not match detail"
                )));
            }
            Ok(AuditEvent {
                seq,
                at,
                session_id: session_id.as_deref().map(parse).transpose()?,
                task_id: task_id.as_deref().map(parse).transpose()?,
                event,
            })
        })
        .collect()
    }
}

fn acquire_lock(path: &Path) -> Result<File, StoreError> {
    let mut lock_path = OsString::from(path.as_os_str());
    lock_path.push(".lock");
    let lock_path = PathBuf::from(lock_path);
    let file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|source| StoreError::Io {
            path: lock_path.clone(),
            source,
        })?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(StoreError::Locked(path.to_path_buf())),
        Err(TryLockError::Error(source)) => Err(StoreError::Io {
            path: lock_path,
            source,
        }),
    }
}

fn current_version(conn: &Connection) -> Result<i64, StoreError> {
    let has_table: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations')",
        [],
        |row| row.get(0),
    )?;
    if !has_table {
        return Ok(0);
    }
    Ok(conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )?)
}

fn latest_version() -> i64 {
    MIGRATIONS.last().map_or(0, |migration| migration.version)
}

fn check_supported(found: i64) -> Result<(), StoreError> {
    let supported = latest_version();
    if found > supported {
        return Err(StoreError::SchemaTooNew { found, supported });
    }
    Ok(())
}

/// Apply pending migrations, each in its own transaction together with its
/// `schema_migrations` row. Refuses a database from a newer Core.
fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             version    INTEGER PRIMARY KEY NOT NULL,
             name       TEXT NOT NULL,
             applied_at TEXT NOT NULL
         ) STRICT;",
    )?;
    let current = current_version(conn)?;
    check_supported(current)?;
    for migration in MIGRATIONS.iter().filter(|m| m.version > current) {
        let tx = conn.transaction()?;
        tx.execute_batch(migration.sql)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
            params![migration.version, migration.name, now()],
        )?;
        tx.commit()?;
        tracing::info!(
            version = migration.version,
            name = migration.name,
            "applied migration"
        );
    }
    Ok(())
}

fn insert_event(
    tx: &Transaction<'_>,
    session_id: Option<SessionId>,
    task_id: Option<TaskId>,
    event: &AuditEventKind,
) -> Result<i64, StoreError> {
    let detail = serde_json::to_string(event)
        .map_err(|error| StoreError::Corrupt(format!("cannot encode audit event: {error}")))?;
    tx.execute(
        "INSERT INTO audit_events (at, session_id, task_id, kind, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            now(),
            session_id.map(|id| id.to_string()),
            task_id.map(|id| id.to_string()),
            event.name(),
            detail,
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

fn apply_transition(
    tx: &Transaction<'_>,
    task_id: TaskId,
    from: &[TaskStatus],
    change: &TaskChange,
) -> Result<SessionId, StoreError> {
    let current: Option<(String, String)> = tx
        .query_row(
            "SELECT status, session_id FROM tasks WHERE task_id = ?1",
            params![task_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((status, session_id)) = current else {
        return Err(StoreError::UnknownTask(task_id));
    };
    let status: TaskStatus = parse(&status)?;
    if !from.contains(&status) || !OPEN_STATES.contains(&status) {
        return Err(StoreError::IllegalTransition {
            task_id,
            from: status,
            to: change.to,
        });
    }
    let capabilities = change
        .capabilities
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| StoreError::Corrupt(error.to_string()))?;
    tx.execute(
        "UPDATE tasks SET
             status = ?1,
             decision = COALESCE(?2, decision),
             capabilities = COALESCE(?3, capabilities),
             result = COALESCE(?4, result),
             error_code = COALESCE(?5, error_code),
             error_message = COALESCE(?6, error_message),
             updated_at = ?7
         WHERE task_id = ?8",
        params![
            change.to.as_str(),
            change.decision.map(PolicyDecision::as_str),
            capabilities,
            change.result,
            change.error.as_ref().map(|error| error.code.as_str()),
            change.error.as_ref().map(|error| error.message.as_str()),
            now(),
            task_id.to_string(),
        ],
    )?;
    parse(&session_id)
}

fn task_ids(
    tx: &Transaction<'_>,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<TaskId>, StoreError> {
    let mut statement = tx.prepare(sql)?;
    let rows = statement.query_map(params, |row| row.get::<_, String>(0))?;
    rows.map(|row| parse(&row?)).collect()
}

const TASK_COLUMNS: &str = "SELECT task_id, session_id, request_id, tool, args, status, decision,
    capabilities, result, error_code, error_message, created_at, updated_at FROM tasks";

type RawTask = (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    String,
);

fn raw_task(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawTask> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
    ))
}

impl TryFrom<RawTask> for TaskRecord {
    type Error = StoreError;

    fn try_from(raw: RawTask) -> Result<Self, Self::Error> {
        let (
            task_id,
            session_id,
            request_id,
            tool,
            args,
            status,
            decision,
            capabilities,
            result,
            error_code,
            error_message,
            created_at,
            updated_at,
        ) = raw;
        let decision = decision
            .map(|value| serde_json::from_value(serde_json::Value::String(value)))
            .transpose()
            .map_err(|error| StoreError::Corrupt(format!("decision: {error}")))?;
        let capabilities = capabilities
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(|error| StoreError::Corrupt(format!("capabilities: {error}")))?;
        let error = match error_code {
            None => None,
            Some(code) => Some(WireError {
                code: serde_json::from_value(serde_json::Value::String(code))
                    .map_err(|error| StoreError::Corrupt(format!("error_code: {error}")))?,
                message: error_message.unwrap_or_default(),
            }),
        };
        Ok(Self {
            task_id: parse(&task_id)?,
            session_id: parse(&session_id)?,
            request_id: RequestId::try_from(request_id)
                .map_err(|error| StoreError::Corrupt(error.to_string()))?,
            tool,
            args,
            status: parse(&status)?,
            decision,
            capabilities,
            result,
            error,
            created_at,
            updated_at,
        })
    }
}

fn parse<T>(value: &str) -> Result<T, StoreError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value
        .parse()
        .map_err(|error| StoreError::Corrupt(format!("`{value}`: {error}")))
}

fn now() -> String {
    humantime::format_rfc3339_millis(SystemTime::now()).to_string()
}

#[cfg(test)]
mod tests;
