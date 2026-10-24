//! Conversations with the assistant, in their own SQLite file (ADR 0021).
//!
//! This is deliberately not the audit database: a person must be able to
//! delete what they said, and the audit log is append-only. Nothing here is
//! a source of truth for any decision the Core makes. Deleted rows are
//! overwritten (`secure_delete`) and the write-ahead log is truncated after
//! a deletion, so deleted text does not linger in either file.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use jarvis_protocol::{
    ChatRole, ClipboardProposal, ConversationId, ConversationSummary, ConversationView, MessageId,
    MessageStatus, MessageView, TurnStats,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::store::{format_ms, now_ms};

#[derive(Debug, thiserror::Error)]
pub enum ChatStoreError {
    #[error("chat database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("cannot create the chat database directory: {0}")]
    Io(#[from] std::io::Error),
    #[error("chat database task failed")]
    Join,
    #[error("no such conversation")]
    NoConversation,
    #[error(
        "the conversation was deleted, but another program holds the database open, so its \
         text may remain in the database log until the next deletion or restart"
    )]
    ScrubPending,
    #[error("the chat database holds an invalid row: {0}")]
    Corrupt(String),
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS conversations (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    created_ms  INTEGER NOT NULL,
    updated_ms  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id              TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    seq             INTEGER NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
    content         TEXT NOT NULL,
    status          TEXT NOT NULL
                    CHECK (status IN ('streaming', 'complete', 'cancelled', 'failed', 'interrupted')),
    created_ms      INTEGER NOT NULL,
    stats           TEXT,
    proposal        TEXT,
    UNIQUE (conversation_id, seq)
);
CREATE INDEX IF NOT EXISTS messages_by_conversation ON messages (conversation_id, seq);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verified_models (
    path        TEXT PRIMARY KEY,
    size        INTEGER NOT NULL,
    modified_ns INTEGER NOT NULL,
    sha256      TEXT NOT NULL
);
";

/// Longest title derived from a first message.
const TITLE_CHARS: usize = 60;
const SNIPPET_CHARS: usize = 120;

/// A message to give the model as context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryMessage {
    pub role: ChatRole,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct ChatStore {
    conn: Arc<Mutex<Connection>>,
}

impl ChatStore {
    pub fn open(path: &Path) -> Result<Self, ChatStoreError> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let store = Self::init(conn)?;
        restrict_to_owner(path)?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, ChatStoreError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, ChatStoreError> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.execute_batch(SCHEMA)?;
        // Replies that were being written when the Core stopped.
        conn.execute(
            "UPDATE messages SET status = 'interrupted' WHERE status = 'streaming'",
            [],
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Run `f` on the blocking pool.
    pub async fn call<T, F>(&self, f: F) -> Result<T, ChatStoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, ChatStoreError> + Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || f(&mut lock(&conn)))
            .await
            .map_err(|_| ChatStoreError::Join)?
    }

    pub fn with<T>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T, ChatStoreError>,
    ) -> Result<T, ChatStoreError> {
        f(&mut lock(&self.conn))
    }
}

/// Conversations are personal text: on Unix the database and its sidecar
/// files are readable by their owner only, whatever the umask. On Windows
/// the files inherit the per-user profile folder's access list.
#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> Result<(), ChatStoreError> {
    use std::os::unix::fs::PermissionsExt;
    for suffix in ["", "-wal", "-shm"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        let file = Path::new(&file);
        if file.exists() {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path) -> Result<(), ChatStoreError> {
    Ok(())
}

fn lock(conn: &Mutex<Connection>) -> MutexGuard<'_, Connection> {
    conn.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Start a turn: store the person's message (in a new conversation when
/// `conversation` is `None`) and an empty assistant message being written.
pub fn begin_turn(
    conn: &mut Connection,
    conversation: Option<ConversationId>,
    text: &str,
) -> Result<(ConversationId, MessageId, MessageId), ChatStoreError> {
    let tx = conn.transaction()?;
    let now = now_ms();
    let conversation_id = match conversation {
        Some(id) => {
            if !exists(&tx, id)? {
                return Err(ChatStoreError::NoConversation);
            }
            id
        }
        None => {
            let id = ConversationId::new();
            tx.execute(
                "INSERT INTO conversations (id, title, created_ms, updated_ms)
                 VALUES (?1, ?2, ?3, ?3)",
                params![id.to_string(), title_from(text), now],
            )?;
            id
        }
    };
    let user = MessageId::new();
    let reply = MessageId::new();
    let seq = next_seq(&tx, conversation_id)?;
    let new = NewMessage {
        conversation: conversation_id,
        id: user,
        seq,
        role: ChatRole::User,
        content: text,
        status: MessageStatus::Complete,
        now,
    };
    insert_message(&tx, &new)?;
    insert_message(
        &tx,
        &NewMessage {
            id: reply,
            seq: seq + 1,
            role: ChatRole::Assistant,
            content: "",
            status: MessageStatus::Streaming,
            ..new
        },
    )?;
    touch(&tx, conversation_id, now)?;
    tx.commit()?;
    Ok((conversation_id, user, reply))
}

/// Start a regenerated reply: delete the conversation's last assistant
/// message (if the last message is one) and add an empty one being written.
/// `None` when there is nothing to regenerate from.
pub fn begin_regenerate(
    conn: &mut Connection,
    conversation: ConversationId,
) -> Result<Option<MessageId>, ChatStoreError> {
    let tx = conn.transaction()?;
    if !exists(&tx, conversation)? {
        return Err(ChatStoreError::NoConversation);
    }
    let last: Option<(String, String, String)> = tx
        .query_row(
            "SELECT id, role, status FROM messages WHERE conversation_id = ?1
             ORDER BY seq DESC LIMIT 1",
            [conversation.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((last_id, role, status)) = last else {
        return Ok(None);
    };
    if status == MessageStatus::Streaming.as_str() {
        return Ok(None);
    }
    if role == "assistant" {
        tx.execute("DELETE FROM messages WHERE id = ?1", [last_id])?;
    }
    let reply = MessageId::new();
    let seq = next_seq(&tx, conversation)?;
    let now = now_ms();
    insert_message(
        &tx,
        &NewMessage {
            conversation,
            id: reply,
            seq,
            role: ChatRole::Assistant,
            content: "",
            status: MessageStatus::Streaming,
            now,
        },
    )?;
    touch(&tx, conversation, now)?;
    tx.commit()?;
    if role == "assistant" {
        // Best effort: the replaced reply is gone from the database; a busy
        // log is scrubbed by the next deletion.
        if let Err(error) = scrub(conn) {
            tracing::warn!(%error, "replaced reply not yet scrubbed from the log");
        }
    }
    Ok(Some(reply))
}

/// Record the final state of a reply. A reply that is already final is left
/// as it is.
pub fn finish_reply(
    conn: &mut Connection,
    reply: MessageId,
    content: &str,
    status: MessageStatus,
    stats: Option<&TurnStats>,
    proposal: Option<&ClipboardProposal>,
) -> Result<(), ChatStoreError> {
    let stats = stats
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| ChatStoreError::Corrupt(error.to_string()))?;
    conn.execute(
        "UPDATE messages SET content = ?2, status = ?3, stats = ?4, proposal = ?5
         WHERE id = ?1 AND status = 'streaming'",
        params![
            reply.to_string(),
            content,
            status.as_str(),
            stats,
            proposal.map(ClipboardProposal::as_str)
        ],
    )?;
    Ok(())
}

/// The messages before `reply` in its conversation, oldest first, for the
/// model's context. Only finished messages with text are included.
pub fn history_before(
    conn: &Connection,
    reply: MessageId,
) -> Result<Vec<HistoryMessage>, ChatStoreError> {
    let mut statement = conn.prepare(
        "SELECT m.role, m.content FROM messages m
         JOIN messages r ON r.id = ?1 AND r.conversation_id = m.conversation_id
         WHERE m.seq < r.seq AND m.status IN ('complete', 'cancelled') AND m.content <> ''
         ORDER BY m.seq",
    )?;
    let rows = statement.query_map([reply.to_string()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut history = Vec::new();
    for row in rows {
        let (role, content) = row?;
        history.push(HistoryMessage {
            role: parse_role(&role)?,
            content,
        });
    }
    Ok(history)
}

/// A stored reply.
pub fn reply(conn: &Connection, reply: MessageId) -> Result<Option<MessageView>, ChatStoreError> {
    conn.query_row(
        "SELECT id, role, content, status, created_ms, stats, proposal FROM messages
         WHERE id = ?1 AND role = 'assistant'",
        [reply.to_string()],
        message_row,
    )
    .optional()?
    .transpose()
}

pub fn conversation(
    conn: &Connection,
    id: ConversationId,
) -> Result<Option<ConversationView>, ChatStoreError> {
    let head: Option<(String, i64, i64)> = conn
        .query_row(
            "SELECT title, created_ms, updated_ms FROM conversations WHERE id = ?1",
            [id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((title, created, updated)) = head else {
        return Ok(None);
    };
    let mut statement = conn.prepare(
        "SELECT id, role, content, status, created_ms, stats, proposal FROM messages
         WHERE conversation_id = ?1 ORDER BY seq",
    )?;
    let messages = statement
        .query_map([id.to_string()], message_row)?
        .map(|row| row?)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(ConversationView {
        conversation_id: id,
        title,
        created_at: format_ms(created),
        updated_at: format_ms(updated),
        messages,
    }))
}

/// Conversations, most recently updated first. With `query`, only those
/// whose title or a message contains it (SQLite folds ASCII case only), with
/// an excerpt around the first matching message.
pub fn conversations(
    conn: &Connection,
    query: Option<&str>,
    limit: u32,
) -> Result<Vec<ConversationSummary>, ChatStoreError> {
    let pattern = query.map(|q| format!("%{}%", escape_like(q)));
    let mut statement = conn.prepare(
        "SELECT c.id, c.title, c.created_ms, c.updated_ms,
                (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id),
                (SELECT m.content FROM messages m
                 WHERE ?1 IS NOT NULL AND m.conversation_id = c.id
                   AND m.content LIKE ?1 ESCAPE '\\'
                 ORDER BY m.seq LIMIT 1)
         FROM conversations c
         WHERE ?1 IS NULL
            OR c.title LIKE ?1 ESCAPE '\\'
            OR EXISTS (SELECT 1 FROM messages m WHERE m.conversation_id = c.id
                       AND m.content LIKE ?1 ESCAPE '\\')
         ORDER BY c.updated_ms DESC
         LIMIT ?2",
    )?;
    let rows = statement.query_map(params![pattern, limit], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, Option<String>>(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, title, created, updated, count, matched) = row?;
        out.push(ConversationSummary {
            conversation_id: id
                .parse()
                .map_err(|_| ChatStoreError::Corrupt("conversation id".into()))?,
            title,
            created_at: format_ms(created),
            updated_at: format_ms(updated),
            message_count: u32::try_from(count).unwrap_or(u32::MAX),
            snippet: match (matched, query) {
                (Some(text), Some(query)) => Some(snippet(&text, query)),
                _ => None,
            },
        });
    }
    Ok(out)
}

/// Delete one conversation; whether it existed.
pub fn delete_conversation(
    conn: &mut Connection,
    id: ConversationId,
) -> Result<bool, ChatStoreError> {
    let deleted = conn.execute("DELETE FROM conversations WHERE id = ?1", [id.to_string()])?;
    scrub(conn)?;
    Ok(deleted > 0)
}

/// Delete every conversation; how many there were.
pub fn delete_all(conn: &mut Connection) -> Result<u32, ChatStoreError> {
    let deleted = conn.execute("DELETE FROM conversations", [])?;
    scrub(conn)?;
    Ok(u32::try_from(deleted).unwrap_or(u32::MAX))
}

/// Delete conversations not updated since `cutoff_ms`; how many.
pub fn delete_older_than(conn: &mut Connection, cutoff_ms: i64) -> Result<u32, ChatStoreError> {
    let deleted = conn.execute(
        "DELETE FROM conversations WHERE updated_ms < ?1",
        [cutoff_ms],
    )?;
    if deleted > 0 {
        scrub(conn)?;
    }
    Ok(u32::try_from(deleted).unwrap_or(u32::MAX))
}

/// The recorded SHA-256 of a model file, if it was hashed at this size and
/// modification time.
pub fn verified_sha256(
    conn: &Connection,
    path: &str,
    size: u64,
    modified_ns: i64,
) -> Result<Option<String>, ChatStoreError> {
    Ok(conn
        .query_row(
            "SELECT sha256 FROM verified_models WHERE path = ?1 AND size = ?2 AND modified_ns = ?3",
            params![path, i64::try_from(size).unwrap_or(i64::MAX), modified_ns],
            |row| row.get(0),
        )
        .optional()?)
}

/// A setting a person chose, if any.
pub fn setting(conn: &Connection, key: &str) -> Result<Option<String>, ChatStoreError> {
    Ok(conn
        .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .optional()?)
}

pub fn set_setting(conn: &Connection, key: &str, value: &str) -> Result<(), ChatStoreError> {
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn record_verified(
    conn: &Connection,
    path: &str,
    size: u64,
    modified_ns: i64,
    sha256: &str,
) -> Result<(), ChatStoreError> {
    conn.execute(
        "INSERT OR REPLACE INTO verified_models (path, size, modified_ns, sha256)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            path,
            i64::try_from(size).unwrap_or(i64::MAX),
            modified_ns,
            sha256
        ],
    )?;
    Ok(())
}

/// Copy the write-ahead log into the database (where `secure_delete` has
/// overwritten the deleted rows) and truncate it. Another program reading
/// the file can make the checkpoint report itself busy; it is retried
/// briefly, and failing that the deletion is reported as not yet scrubbed.
fn scrub(conn: &Connection) -> Result<(), ChatStoreError> {
    for attempt in 0..10 {
        let busy: i64 = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
        if busy == 0 {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20 * (attempt + 1)));
    }
    Err(ChatStoreError::ScrubPending)
}

fn exists(conn: &Connection, id: ConversationId) -> Result<bool, ChatStoreError> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM conversations WHERE id = ?1",
            [id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

#[derive(Clone, Copy)]
struct NewMessage<'a> {
    conversation: ConversationId,
    id: MessageId,
    seq: i64,
    role: ChatRole,
    content: &'a str,
    status: MessageStatus,
    now: i64,
}

fn insert_message(tx: &Connection, message: &NewMessage<'_>) -> Result<(), ChatStoreError> {
    let role = match message.role {
        ChatRole::User => "user",
        ChatRole::Assistant => "assistant",
    };
    tx.execute(
        "INSERT INTO messages (id, conversation_id, seq, role, content, status, created_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            message.id.to_string(),
            message.conversation.to_string(),
            message.seq,
            role,
            message.content,
            message.status.as_str(),
            message.now
        ],
    )?;
    Ok(())
}

fn next_seq(tx: &Connection, conversation: ConversationId) -> Result<i64, ChatStoreError> {
    Ok(tx.query_row(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM messages WHERE conversation_id = ?1",
        [conversation.to_string()],
        |row| row.get(0),
    )?)
}

fn touch(tx: &Connection, conversation: ConversationId, now: i64) -> Result<(), ChatStoreError> {
    tx.execute(
        "UPDATE conversations SET updated_ms = ?2 WHERE id = ?1",
        params![conversation.to_string(), now],
    )?;
    Ok(())
}

fn message_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<MessageView, ChatStoreError>> {
    let id: String = row.get(0)?;
    let role: String = row.get(1)?;
    let content: String = row.get(2)?;
    let status: String = row.get(3)?;
    let created: i64 = row.get(4)?;
    let stats: Option<String> = row.get(5)?;
    let proposal: Option<String> = row.get(6)?;
    Ok(build_message(
        id, &role, content, &status, created, stats, proposal,
    ))
}

fn build_message(
    id: String,
    role: &str,
    content: String,
    status: &str,
    created: i64,
    stats: Option<String>,
    proposal: Option<String>,
) -> Result<MessageView, ChatStoreError> {
    Ok(MessageView {
        message_id: id
            .parse()
            .map_err(|_| ChatStoreError::Corrupt("message id".into()))?,
        role: parse_role(role)?,
        content,
        status: parse_status(status)?,
        created_at: format_ms(created),
        stats: stats
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(|_| ChatStoreError::Corrupt("stats".into()))?,
        // A proposal stored under an older, looser allowlist is dropped, not
        // fatal: the conversation stays readable.
        proposal: proposal.and_then(|p| ClipboardProposal::try_from(p).ok()),
    })
}

fn parse_role(role: &str) -> Result<ChatRole, ChatStoreError> {
    match role {
        "user" => Ok(ChatRole::User),
        "assistant" => Ok(ChatRole::Assistant),
        other => Err(ChatStoreError::Corrupt(format!("role {other}"))),
    }
}

fn parse_status(status: &str) -> Result<MessageStatus, ChatStoreError> {
    Ok(match status {
        "streaming" => MessageStatus::Streaming,
        "complete" => MessageStatus::Complete,
        "cancelled" => MessageStatus::Cancelled,
        "failed" => MessageStatus::Failed,
        "interrupted" => MessageStatus::Interrupted,
        other => return Err(ChatStoreError::Corrupt(format!("status {other}"))),
    })
}

fn escape_like(query: &str) -> String {
    let mut out = String::with_capacity(query.len());
    for c in query.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The first line of a message, shortened, as a conversation title.
fn title_from(text: &str) -> String {
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or(text)
        .trim();
    shorten(line, TITLE_CHARS)
}

fn shorten(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max - 1).collect();
    out.push('…');
    out
}

/// An excerpt of `text` around the first ASCII-case-insensitive match of
/// `query`, on one line.
fn snippet(text: &str, query: &str) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    let lower = flat.to_ascii_lowercase();
    let at = lower.find(&query.to_ascii_lowercase()).unwrap_or(0);
    let start = flat[..at].chars().count().saturating_sub(SNIPPET_CHARS / 3);
    let excerpt: String = flat.chars().skip(start).collect();
    let mut out = shorten(excerpt.trim(), SNIPPET_CHARS);
    if start > 0 {
        out.insert(0, '…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> ChatStore {
        ChatStore::open_in_memory().unwrap()
    }

    #[test]
    fn a_turn_stores_the_message_and_a_reply_being_written() {
        store()
            .with(|conn| {
                let (conversation, user, reply) =
                    begin_turn(conn, None, "Olá Donna\nsegunda linha")?;
                let view = super::conversation(conn, conversation)?.unwrap();
                assert_eq!(view.title, "Olá Donna");
                assert_eq!(view.messages.len(), 2);
                assert_eq!(view.messages[0].message_id, user);
                assert_eq!(view.messages[1].status, MessageStatus::Streaming);
                finish_reply(conn, reply, "Olá!", MessageStatus::Complete, None, None)?;
                // A final reply is not rewritten.
                finish_reply(conn, reply, "outra", MessageStatus::Failed, None, None)?;
                let stored = super::reply(conn, reply)?.unwrap();
                assert_eq!(stored.content, "Olá!");
                assert_eq!(stored.status, MessageStatus::Complete);
                assert!(matches!(
                    begin_turn(conn, Some(ConversationId::new()), "x"),
                    Err(ChatStoreError::NoConversation)
                ));
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn history_is_the_finished_messages_before_the_reply() {
        store()
            .with(|conn| {
                let (c, _, r1) = begin_turn(conn, None, "um")?;
                finish_reply(conn, r1, "resposta um", MessageStatus::Complete, None, None)?;
                let (_, _, r2) = begin_turn(conn, Some(c), "dois")?;
                let history = history_before(conn, r2)?;
                let texts: Vec<_> = history.iter().map(|m| m.content.as_str()).collect();
                assert_eq!(texts, ["um", "resposta um", "dois"]);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn regenerate_replaces_the_last_reply() {
        store()
            .with(|conn| {
                let (c, _, r1) = begin_turn(conn, None, "um")?;
                assert_eq!(begin_regenerate(conn, c)?, None, "not while streaming");
                finish_reply(conn, r1, "má", MessageStatus::Complete, None, None)?;
                let r2 = begin_regenerate(conn, c)?.unwrap();
                let view = super::conversation(conn, c)?.unwrap();
                assert_eq!(view.messages.len(), 2);
                assert_eq!(view.messages[1].message_id, r2);
                assert!(super::reply(conn, r1)?.is_none());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn search_matches_messages_and_escapes_wildcards() {
        store()
            .with(|conn| {
                let (a, _, ra) = begin_turn(conn, None, "planear férias na Madeira")?;
                finish_reply(
                    conn,
                    ra,
                    "Levada do Caldeirão Verde",
                    MessageStatus::Complete,
                    None,
                    None,
                )?;
                let (b, _, _) = begin_turn(conn, None, "100% certo")?;
                let found = conversations(conn, Some("caldeirão"), 10)?;
                assert_eq!(found.len(), 1);
                assert_eq!(found[0].conversation_id, a);
                assert!(found[0].snippet.as_deref().unwrap().contains("Caldeirão"));
                let found = conversations(conn, Some("%"), 10)?;
                assert_eq!(found.len(), 1);
                assert_eq!(found[0].conversation_id, b);
                assert_eq!(conversations(conn, None, 10)?.len(), 2);
                assert_eq!(conversations(conn, None, 1)?.len(), 1);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn deletion_removes_messages_and_retention_removes_old_conversations() {
        store()
            .with(|conn| {
                let (a, _, ra) = begin_turn(conn, None, "segredo")?;
                begin_turn(conn, None, "outro")?;
                assert!(delete_conversation(conn, a)?);
                assert!(!delete_conversation(conn, a)?);
                assert!(super::reply(conn, ra)?.is_none());
                let left: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM messages WHERE content = 'segredo'",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(left, 0);
                assert_eq!(delete_older_than(conn, 0)?, 0);
                assert_eq!(delete_older_than(conn, now_ms() + 1)?, 1);
                assert_eq!(delete_all(conn)?, 0);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn deleted_text_does_not_remain_in_the_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let store = ChatStore::open(&path).unwrap();
        let marker = "MARCADOR-SECRETO-4711";
        store
            .with(|conn| {
                let (c, _, r) = begin_turn(conn, None, marker)?;
                finish_reply(conn, r, marker, MessageStatus::Complete, None, None)?;
                delete_conversation(conn, c)?;
                Ok(())
            })
            .unwrap();
        drop(store);
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(
                !bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
                "deleted text found on disk"
            );
        }
    }

    #[test]
    fn unfinished_replies_are_interrupted_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let reply = {
            let store = ChatStore::open(&path).unwrap();
            store
                .with(|conn| Ok(begin_turn(conn, None, "olá")?.2))
                .unwrap()
        };
        let store = ChatStore::open(&path).unwrap();
        let view = store
            .with(|conn| super::reply(conn, reply))
            .unwrap()
            .unwrap();
        assert_eq!(view.status, MessageStatus::Interrupted);
    }

    #[test]
    fn settings_are_remembered_and_replaced() {
        store()
            .with(|conn| {
                assert_eq!(setting(conn, "retention_days")?, None);
                set_setting(conn, "retention_days", "30")?;
                set_setting(conn, "retention_days", "7")?;
                assert_eq!(setting(conn, "retention_days")?.as_deref(), Some("7"));
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn snippets_are_one_short_line() {
        let text = format!(
            "{}\nagulha no palheiro{}",
            "a ".repeat(200),
            " b".repeat(200)
        );
        let s = snippet(&text, "AGULHA");
        assert!(s.contains("agulha"));
        assert!(!s.contains('\n'));
        assert!(s.chars().count() <= SNIPPET_CHARS + 1);
    }
}
