//! Clipboard payloads (ADR 0022): the text of a clipboard job, held in a
//! working table for as long as the job exists and never copied into the
//! immutable records (jobs, tasks, approvals, audit events).

use std::time::Duration;

use jarvis_protocol::{AuditEventKind, ClipboardText, Fingerprint, Goal, JobId, PayloadId};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::jobs::{self, JobRecord};
use super::{Store, StoreError, insert_event, now, parse};

/// Clipboard texts that may wait at once (invariant 9: everything a client
/// can influence is bounded). Each is at most 1024 characters.
pub const MAX_PENDING_PAYLOADS: u32 = 16;

/// SHA-256 of a text, as the Core shows it to a person.
pub fn text_sha256(text: &str) -> Fingerprint {
    let digest: [u8; 32] = Sha256::digest(text.as_bytes()).into();
    Fingerprint::from_digest(&digest)
}

/// Bytes of random salt kept with a payload.
pub const SALT_BYTES: usize = 16;

/// SHA-256 of a payload's salt followed by its text: the value a clipboard
/// request binds. The salt is deleted with the payload, so the value left in
/// the immutable records cannot be matched against guesses of a short text.
pub fn salted_sha256(salt: &[u8], text: &str) -> Fingerprint {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(salt)
        .chain_update(text.as_bytes())
        .finalize()
        .into();
    Fingerprint::from_digest(&digest)
}

/// A payload as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// The job the payload belongs to.
    pub job_id: JobId,
    /// The salted SHA-256 recorded when the payload was stored. The text may
    /// have been changed since by a program that can write the database
    /// file, so a consumer checks it with [`Payload::is_intact`].
    pub sha256: Fingerprint,
    pub salt: Vec<u8>,
    pub text: String,
}

impl Payload {
    /// Whether the text still hashes to `expected`, the value the request
    /// names, and to the value recorded with it.
    pub fn is_intact(&self, expected: &Fingerprint) -> bool {
        self.sha256 == *expected && salted_sha256(&self.salt, &self.text) == *expected
    }
}

impl Store {
    /// Queue a job that copies `text` to the clipboard once a person
    /// approves it. In one transaction: the payload, the job (its goal names
    /// the payload and its salted SHA-256, never the text) and
    /// `job_submitted`.
    pub fn submit_clipboard_job(
        &self,
        text: &ClipboardText,
        client: &str,
    ) -> Result<JobRecord, StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let waiting: u32 = tx.query_row("SELECT COUNT(*) FROM payloads", [], |row| row.get(0))?;
        if waiting >= MAX_PENDING_PAYLOADS {
            return Err(StoreError::TooManyPayloads(MAX_PENDING_PAYLOADS));
        }
        let payload_id = PayloadId::new();
        // 122 random bits from the operating system's generator.
        let salt: [u8; SALT_BYTES] = uuid::Uuid::new_v4().into_bytes();
        let sha256 = salted_sha256(&salt, text.as_str());
        let goal = Goal::try_from(format!("copy payload:{payload_id}:{sha256}"))
            .map_err(|error| StoreError::Corrupt(format!("clipboard goal: {error}")))?;
        let job = jobs::insert_job(&tx, &goal, client)?;
        tx.execute(
            "INSERT INTO payloads (payload_id, job_id, sha256, salt, text, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                payload_id.to_string(),
                job.job_id.to_string(),
                sha256.as_str(),
                &salt[..],
                text.as_str(),
                now(),
            ],
        )?;
        insert_event(
            &tx,
            None,
            None,
            &AuditEventKind::JobSubmitted {
                job_id: job.job_id,
                client: client.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(job)
    }

    /// The payload stored under `payload_id`, if it still exists.
    pub fn payload(&self, payload_id: PayloadId) -> Result<Option<Payload>, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT job_id, sha256, salt, text FROM payloads WHERE payload_id = ?1",
            params![payload_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .map(|(job_id, sha256, salt, text)| {
            Ok(Payload {
                job_id: parse(&job_id)?,
                sha256: parse(&sha256)?,
                salt,
                text,
            })
        })
        .transpose()
    }
}

/// Delete the payload of a job that has just ended, inside the transaction
/// that ended it. Returns whether there was one.
pub(super) fn delete_for_job(tx: &Transaction<'_>, job_id: JobId) -> Result<bool, StoreError> {
    let deleted = tx.execute(
        "DELETE FROM payloads WHERE job_id = ?1",
        params![job_id.to_string()],
    )?;
    Ok(deleted > 0)
}

/// Delete the payloads of jobs that are no longer open. A payload outlives
/// its job only if something other than this Core wrote it there; either
/// way nothing can use it.
pub(super) fn delete_orphans(tx: &Transaction<'_>) -> Result<bool, StoreError> {
    let deleted = tx.execute(
        "DELETE FROM payloads WHERE job_id NOT IN
             (SELECT job_id FROM jobs WHERE status IN ('queued', 'running'))",
        [],
    )?;
    Ok(deleted > 0)
}

/// Copy the write-ahead log into the database, where `secure_delete` has
/// overwritten the deleted rows, and truncate it, so the text is in neither
/// file. Another program reading the file can make the checkpoint report
/// itself busy; it is retried briefly, and failing that the text is reported
/// as not yet scrubbed (the next checkpoint removes it).
pub(super) fn scrub(conn: &Connection) {
    for attempt in 0..10 {
        match conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            row.get::<_, i64>(0)
        }) {
            Ok(0) => return,
            Ok(_) => std::thread::sleep(Duration::from_millis(20 * (attempt + 1))),
            Err(error) => {
                tracing::warn!(%error, "deleted clipboard text not yet scrubbed from the log");
                return;
            }
        }
    }
    tracing::warn!("deleted clipboard text not yet scrubbed from the log");
}
