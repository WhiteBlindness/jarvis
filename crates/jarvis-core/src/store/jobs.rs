//! Jobs: goals submitted by local clients.

use jarvis_protocol::{AuditEventKind, Goal, JobId, JobStatus, SessionId, Summary};
use rusqlite::{OptionalExtension, Transaction, params};

use super::{Store, StoreError, count, insert_event, now, parse};

/// A job as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRecord {
    pub job_id: JobId,
    pub goal: Goal,
    pub submitted_by: String,
    pub status: JobStatus,
    pub summary: Option<Summary>,
    pub created_at: String,
    pub updated_at: String,
}

const JOB_COLUMNS: &str =
    "SELECT job_id, goal, submitted_by, status, summary, created_at, updated_at FROM jobs";

type RawJob = (
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    String,
);

fn raw_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawJob> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    ))
}

impl TryFrom<RawJob> for JobRecord {
    type Error = StoreError;

    fn try_from(raw: RawJob) -> Result<Self, Self::Error> {
        let (job_id, goal, submitted_by, status, summary, created_at, updated_at) = raw;
        Ok(Self {
            job_id: parse(&job_id)?,
            goal: parse(&goal)?,
            submitted_by,
            status: parse(&status)?,
            summary: summary.as_deref().map(parse).transpose()?,
            created_at,
            updated_at,
        })
    }
}

impl Store {
    /// Queue a job and record who asked for it.
    pub fn submit_job(&self, goal: &Goal, client: &str) -> Result<JobRecord, StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let job_id = JobId::new();
        let at = now();
        tx.execute(
            "INSERT INTO jobs (job_id, goal, submitted_by, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, 'queued', ?4, ?4)",
            params![job_id.to_string(), goal.as_str(), client, at],
        )?;
        insert_event(
            &tx,
            None,
            None,
            &AuditEventKind::JobSubmitted {
                job_id,
                client: client.to_owned(),
            },
        )?;
        let job = load(&tx, job_id)?.ok_or(StoreError::Corrupt("job vanished".into()))?;
        tx.commit()?;
        Ok(job)
    }

    /// Move the oldest queued job to `running` for this session.
    pub fn claim_next_job(&self, session_id: SessionId) -> Result<Option<JobRecord>, StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let next: Option<String> = tx
            .query_row(
                "SELECT job_id FROM jobs WHERE status = 'queued'
                 ORDER BY created_at, job_id LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(job_id) = next else {
            return Ok(None);
        };
        let job_id: JobId = parse(&job_id)?;
        tx.execute(
            "UPDATE jobs SET status = 'running', updated_at = ?1
             WHERE job_id = ?2 AND status = 'queued'",
            params![now(), job_id.to_string()],
        )?;
        insert_event(
            &tx,
            Some(session_id),
            None,
            &AuditEventKind::JobStarted { job_id },
        )?;
        let job = load(&tx, job_id)?;
        tx.commit()?;
        Ok(job)
    }

    /// End a running job. Any other source state is an error.
    pub fn finish_job(
        &self,
        job_id: JobId,
        status: JobStatus,
        summary: Option<&Summary>,
        session_id: Option<SessionId>,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE jobs SET status = ?1, summary = ?2, updated_at = ?3
             WHERE job_id = ?4 AND status = 'running'",
            params![
                status.as_str(),
                summary.map(Summary::as_str),
                now(),
                job_id.to_string()
            ],
        )?;
        if changed != 1 || !status.is_terminal() {
            return Err(StoreError::Corrupt(format!(
                "job {job_id} is not running or `{status}` is not terminal"
            )));
        }
        insert_event(
            &tx,
            session_id,
            None,
            &AuditEventKind::JobFinished { job_id, status },
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn job(&self, job_id: JobId) -> Result<Option<JobRecord>, StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        load(&tx, job_id)
    }

    /// Most recent jobs first.
    pub fn jobs(&self, limit: u32) -> Result<Vec<JobRecord>, StoreError> {
        let conn = self.conn()?;
        let mut statement = conn.prepare(&format!(
            "{JOB_COLUMNS} ORDER BY created_at DESC, job_id DESC LIMIT ?1"
        ))?;
        let rows = statement.query_map(params![limit], raw_job)?;
        rows.map(|row| JobRecord::try_from(row?)).collect()
    }

    pub fn queued_jobs(&self) -> Result<u32, StoreError> {
        let conn = self.conn()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM jobs WHERE status = 'queued'",
            [],
            |row| row.get(0),
        )?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }
}

fn load(tx: &Transaction<'_>, job_id: JobId) -> Result<Option<JobRecord>, StoreError> {
    tx.query_row(
        &format!("{JOB_COLUMNS} WHERE job_id = ?1"),
        params![job_id.to_string()],
        raw_job,
    )
    .optional()?
    .map(JobRecord::try_from)
    .transpose()
}

/// Start-up recovery: running jobs were interrupted, queued jobs are
/// cancelled rather than carried into a new run.
pub(super) fn close_all_open(tx: &Transaction<'_>) -> Result<u32, StoreError> {
    let open: Vec<(String, String)> = {
        let mut statement = tx.prepare(
            "SELECT job_id, status FROM jobs WHERE status IN ('queued', 'running')
             ORDER BY created_at, job_id",
        )?;
        let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    for (job_id, status) in &open {
        let job_id: JobId = parse(job_id)?;
        let to = if status == "running" {
            JobStatus::Interrupted
        } else {
            JobStatus::Cancelled
        };
        tx.execute(
            "UPDATE jobs SET status = ?1, summary = ?2, updated_at = ?3 WHERE job_id = ?4",
            params![
                to.as_str(),
                "the Core stopped before the job finished",
                now(),
                job_id.to_string()
            ],
        )?;
        insert_event(
            tx,
            None,
            None,
            &AuditEventKind::JobFinished { job_id, status: to },
        )?;
    }
    Ok(count(open.len()))
}
