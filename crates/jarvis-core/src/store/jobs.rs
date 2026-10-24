//! Jobs: goals submitted by local clients.

use jarvis_protocol::{
    AuditEventKind, Goal, JobId, JobStatus, RequestId, SessionId, Summary, TaskId,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::{
    JobStep, Store, StoreError, TASK_COLUMNS, TaskRecord, count, insert_event, now, parse,
    payloads, raw_task,
};

/// A job as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRecord {
    pub job_id: JobId,
    pub goal: Goal,
    pub submitted_by: String,
    pub status: JobStatus,
    pub summary: Option<Summary>,
    /// How many times a session has claimed the job.
    pub attempts: u32,
    pub created_at: String,
    pub updated_at: String,
}

const JOB_COLUMNS: &str = "SELECT job_id, goal, submitted_by, status, summary, created_at,
    updated_at, attempts FROM jobs";

type RawJob = (
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    String,
    u32,
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
        row.get(7)?,
    ))
}

impl TryFrom<RawJob> for JobRecord {
    type Error = StoreError;

    fn try_from(raw: RawJob) -> Result<Self, Self::Error> {
        let (job_id, goal, submitted_by, status, summary, created_at, updated_at, attempts) = raw;
        Ok(Self {
            job_id: parse(&job_id)?,
            goal: parse(&goal)?,
            submitted_by,
            status: parse(&status)?,
            summary: summary.as_deref().map(parse).transpose()?,
            attempts,
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
        let job = insert_job(&tx, goal, client)?;
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

    /// Move the oldest queued job to `running` for this session and count the
    /// attempt.
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
            "UPDATE jobs SET status = 'running', attempts = attempts + 1, updated_at = ?1
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
        if !status.is_terminal() {
            return Err(StoreError::Corrupt(format!(
                "job {job_id} cannot finish as `{status}`, which is not terminal"
            )));
        }
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        // A job that ends without a retry still says if a task of it may have
        // acted without a recorded result.
        let uncertain = match status {
            JobStatus::Failed | JobStatus::Interrupted => uncertain_task(&tx, job_id)?,
            _ => None,
        };
        let had_payload = close(&tx, job_id, status, summary, uncertain, session_id)?;
        tx.commit()?;
        if had_payload {
            payloads::scrub(&conn);
        }
        Ok(())
    }

    /// Decide what becomes of a running job whose worker or Core stopped:
    /// back to the queue, or `interrupted` when a task of it has an unknown
    /// outcome or `max_attempts` is spent. Returns the job's new status. One
    /// transaction covers the status change and its audit events.
    pub fn requeue_or_close(
        &self,
        job_id: JobId,
        max_attempts: u32,
        session_id: Option<SessionId>,
        reason: &str,
    ) -> Result<JobStatus, StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let (status, had_payload) = settle(&tx, job_id, max_attempts, session_id, reason)?;
        tx.commit()?;
        if had_payload {
            payloads::scrub(&conn);
        }
        Ok(status)
    }

    /// The task that completed position `seq` of the job in an attempt before
    /// `attempt`, if there is one. The session never creates a task at a
    /// completed position and no schema constraint enforces it, so the query
    /// takes the oldest (ADR 0015).
    pub fn completed_step(
        &self,
        job_id: JobId,
        seq: u32,
        attempt: u32,
    ) -> Result<Option<TaskRecord>, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            &format!(
                "{TASK_COLUMNS} WHERE status = 'completed' AND task_id IN (
                     SELECT task_id FROM job_steps
                     WHERE job_id = ?1 AND seq = ?2 AND attempt < ?3)
                 ORDER BY created_at, task_id LIMIT 1"
            ),
            params![job_id.to_string(), seq, attempt],
            raw_task,
        )
        .optional()?
        .map(TaskRecord::try_from)
        .transpose()
    }

    /// Record that a request was answered with the stored result of `task_id`
    /// instead of running anything. Refused when the session already used
    /// `request_id` for a task.
    pub fn replay_step(
        &self,
        session_id: SessionId,
        job_id: JobId,
        seq: u32,
        task_id: TaskId,
        request_id: &RequestId,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let used: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM tasks WHERE session_id = ?1 AND request_id = ?2)",
            params![session_id.to_string(), request_id.as_str()],
            |row| row.get(0),
        )?;
        if used {
            return Err(StoreError::DuplicateRequest(request_id.clone()));
        }
        insert_event(
            &tx,
            Some(session_id),
            Some(task_id),
            &AuditEventKind::StepReplayed {
                job_id,
                seq,
                task_id,
            },
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

/// Insert a queued job. The caller records `job_submitted` in the same
/// transaction.
pub(super) fn insert_job(
    tx: &Transaction<'_>,
    goal: &Goal,
    client: &str,
) -> Result<JobRecord, StoreError> {
    let job_id = JobId::new();
    tx.execute(
        "INSERT INTO jobs (job_id, goal, submitted_by, status, created_at, updated_at)
         VALUES (?1, ?2, ?3, 'queued', ?4, ?4)",
        params![job_id.to_string(), goal.as_str(), client, now()],
    )?;
    load(tx, job_id)?.ok_or(StoreError::Corrupt("job vanished".into()))
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

/// Start-up recovery for jobs: queued jobs stay as they are, and every job
/// found running is settled like one whose session just ended. Returns how
/// many were settled, and whether any of them lost a payload.
pub(super) fn settle_running(
    tx: &Transaction<'_>,
    max_attempts: u32,
) -> Result<(u32, bool), StoreError> {
    let running: Vec<String> = {
        let mut statement = tx.prepare(
            "SELECT job_id FROM jobs WHERE status = 'running' ORDER BY created_at, job_id",
        )?;
        let rows = statement.query_map([], |row| row.get(0))?;
        rows.collect::<Result<_, _>>()?
    };
    let mut had_payload = false;
    for job_id in &running {
        let reason = "the Core restarted while the job was running";
        had_payload |= settle(tx, parse(job_id)?, max_attempts, None, reason)?.1;
    }
    Ok((count(running.len()), had_payload))
}

/// Decide what becomes of a running job whose worker or Core stopped. The one
/// place that makes this decision, for session close and for start-up
/// recovery alike.
///
/// - A task of the job started executing and did not end `completed` or
///   `failed`: the tool may have acted without a recorded result, so the job
///   is quarantined (`interrupted`) and never resumed.
/// - The job was running before attempts were counted (`attempts` is 0, a
///   job left over from before migration 0003): it has no ledger of steps, so
///   it cannot be resumed safely and ends `interrupted`.
/// - The job has been claimed `max_attempts` times: `interrupted`.
/// - Otherwise it goes back to the queue, with its payload (ADR 0022).
///
/// Returns the job's new status and whether closing it deleted a payload.
fn settle(
    tx: &Transaction<'_>,
    job_id: JobId,
    max_attempts: u32,
    session_id: Option<SessionId>,
    reason: &str,
) -> Result<(JobStatus, bool), StoreError> {
    let current: Option<(String, u32)> = tx
        .query_row(
            "SELECT status, attempts FROM jobs WHERE job_id = ?1",
            params![job_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let attempts = match current {
        Some((status, attempts)) if status == "running" => attempts,
        _ => return Err(StoreError::Corrupt(format!("job {job_id} is not running"))),
    };

    let uncertain = uncertain_task(tx, job_id)?;
    let summary = if let Some(task_id) = uncertain {
        format!("not resumed: task {task_id} started and its outcome was not recorded ({reason})")
    } else if attempts == 0 {
        format!("the job predates the step ledger and cannot be resumed safely ({reason})")
    } else if attempts >= max_attempts {
        format!("attempt limit of {max_attempts} reached ({reason})")
    } else {
        set_status(tx, job_id, JobStatus::Queued, None)?;
        insert_event(
            tx,
            session_id,
            None,
            &AuditEventKind::JobRequeued {
                job_id,
                attempts,
                reason: reason.to_owned(),
            },
        )?;
        return Ok((JobStatus::Queued, false));
    };
    let summary = Summary::lossy(&summary);
    let had_payload = close(
        tx,
        job_id,
        JobStatus::Interrupted,
        Some(&summary),
        uncertain,
        session_id,
    )?;
    Ok((JobStatus::Interrupted, had_payload))
}

/// A task of the job that started executing and whose outcome is not known.
/// Known means `completed`, or `failed` with an error the tool itself
/// reported. A tool that panicked, a result the Core rejected after the tool
/// ran, and anything that did not end are unknown.
fn uncertain_task(tx: &Transaction<'_>, job_id: JobId) -> Result<Option<TaskId>, StoreError> {
    tx.query_row(
        "SELECT t.task_id FROM tasks t
         WHERE t.job_id = ?1
           AND NOT (t.status = 'completed'
                    OR (t.status = 'failed' AND COALESCE(t.error_code, '') = 'tool_failed'))
           AND EXISTS (SELECT 1 FROM audit_events e
                       WHERE e.task_id = t.task_id AND e.kind = 'execution_started')
         ORDER BY t.created_at, t.task_id LIMIT 1",
        params![job_id.to_string()],
        |row| row.get::<_, String>(0),
    )
    .optional()?
    .map(|id| parse(&id))
    .transpose()
}

/// Change a running job's status. `None` leaves the summary as it is, and a
/// running job has none: a summary is only ever written as a job ends.
fn set_status(
    tx: &Transaction<'_>,
    job_id: JobId,
    to: JobStatus,
    summary: Option<&Summary>,
) -> Result<(), StoreError> {
    let changed = tx.execute(
        "UPDATE jobs SET status = ?1, summary = COALESCE(?2, summary), updated_at = ?3
         WHERE job_id = ?4 AND status = 'running'",
        params![
            to.as_str(),
            summary.map(Summary::as_str),
            now(),
            job_id.to_string()
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::Corrupt(format!("job {job_id} is not running")));
    }
    Ok(())
}

/// End a running job in `status`. The one place that does it: the status
/// change, then `job_quarantined` when `uncertain` names a task that may have
/// acted without a recorded result, then `job_finished`. The job's clipboard
/// payload, if it has one, is deleted in the same transaction (ADR 0022);
/// the result says whether there was one, so the caller can scrub the log.
fn close(
    tx: &Transaction<'_>,
    job_id: JobId,
    status: JobStatus,
    summary: Option<&Summary>,
    uncertain: Option<TaskId>,
    session_id: Option<SessionId>,
) -> Result<bool, StoreError> {
    set_status(tx, job_id, status, summary)?;
    let had_payload = payloads::delete_for_job(tx, job_id)?;
    if let Some(task_id) = uncertain {
        insert_event(
            tx,
            session_id,
            None,
            &AuditEventKind::JobQuarantined { job_id, task_id },
        )?;
    }
    insert_event(
        tx,
        session_id,
        None,
        &AuditEventKind::JobFinished { job_id, status },
    )?;
    Ok(had_payload)
}

/// Put a task in the job's ledger. Runs inside the transaction that creates
/// the task.
pub(super) fn record_step(
    tx: &Transaction<'_>,
    task_id: TaskId,
    job_id: JobId,
    step: JobStep,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO job_steps (task_id, job_id, attempt, seq) VALUES (?1, ?2, ?3, ?4)",
        params![
            task_id.to_string(),
            job_id.to_string(),
            step.attempt,
            step.seq
        ],
    )?;
    Ok(())
}
