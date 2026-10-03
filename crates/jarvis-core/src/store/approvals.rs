//! Approvals: a person's decision on one request that policy sent for
//! confirmation.
//!
//! Every operation is one transaction, and every state change is a
//! conditional update on the current status, so two decisions can never both
//! win. The schema backs this up with triggers (see migration 0002).
//!
//! Granting only records the decision. The approval is used by
//! [`Store::consume_approval`], in the same transaction that moves the task
//! to `executing` and records `execution_started`. If that transaction does
//! not commit, the tool does not run; once it has committed, the approval can
//! never be used again, whatever happens next.

use jarvis_protocol::{
    ApprovalId, ApprovalStatus, AuditEventKind, Capability, ErrorCode, Fingerprint, JobId,
    RequestId, SessionId, Summary, TaskId, TaskStatus, ToolName, WireError,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::{
    Store, StoreError, TaskChange, apply_transition, count, format_ms, insert_event, now, parse,
};

/// An approval to record together with its task's move to
/// `awaiting_confirmation`.
#[derive(Debug, Clone)]
pub struct NewApproval {
    pub approval_id: ApprovalId,
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub request_id: RequestId,
    pub tool: ToolName,
    pub capabilities: Vec<Capability>,
    pub fingerprint: Fingerprint,
    pub expires_at_ms: i64,
}

/// An approval as stored, with the task fields a person needs to see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRecord {
    pub approval_id: ApprovalId,
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub job_id: Option<JobId>,
    pub request_id: RequestId,
    pub tool: ToolName,
    /// The task's arguments, exactly as stored.
    pub args: String,
    pub capabilities: Vec<Capability>,
    pub fingerprint: Fingerprint,
    pub status: ApprovalStatus,
    pub requested_at: String,
    pub expires_at: String,
    pub expires_at_ms: i64,
    pub decided_by: Option<String>,
    pub reason: Option<String>,
}

/// Why a decision or a consumption was refused.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    #[error("approval {0} does not exist")]
    NotFound(ApprovalId),
    #[error("approval is {0}, not pending")]
    NotPending(ApprovalStatus),
    #[error("approval is {0}, not granted")]
    NotGranted(ApprovalStatus),
    #[error("approval expired")]
    Expired,
    #[error("the approval does not match the reviewed request")]
    FingerprintMismatch,
    #[error("the task no longer matches the approval")]
    TaskChanged,
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<rusqlite::Error> for ApprovalError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(error.into())
    }
}

const APPROVAL_COLUMNS: &str = "SELECT a.approval_id, a.task_id, a.session_id, t.job_id,
    a.request_id, a.tool, t.args, a.capabilities, a.fingerprint, a.status, a.requested_at,
    a.expires_at, a.expires_at_ms, a.decided_by, a.reason
    FROM approvals a JOIN tasks t ON t.task_id = a.task_id";

fn read_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<ApprovalRecord, StoreError>> {
    let raw = (
        row.get::<_, String>(0)?,
        row.get::<_, String>(1)?,
        row.get::<_, String>(2)?,
        row.get::<_, Option<String>>(3)?,
        row.get::<_, String>(4)?,
        row.get::<_, String>(5)?,
        row.get::<_, String>(6)?,
        row.get::<_, String>(7)?,
        row.get::<_, String>(8)?,
        row.get::<_, String>(9)?,
        row.get::<_, String>(10)?,
        row.get::<_, String>(11)?,
        row.get::<_, i64>(12)?,
        row.get::<_, Option<String>>(13)?,
        row.get::<_, Option<String>>(14)?,
    );
    Ok((|| {
        let (
            approval_id,
            task_id,
            session_id,
            job_id,
            request_id,
            tool,
            args,
            capabilities,
            fingerprint,
            status,
            requested_at,
            expires_at,
            expires_at_ms,
            decided_by,
            reason,
        ) = raw;
        Ok(ApprovalRecord {
            approval_id: parse(&approval_id)?,
            task_id: parse(&task_id)?,
            session_id: parse(&session_id)?,
            job_id: job_id.as_deref().map(parse).transpose()?,
            request_id: RequestId::try_from(request_id)
                .map_err(|error| StoreError::Corrupt(error.to_string()))?,
            tool: ToolName::try_from(tool)
                .map_err(|error| StoreError::Corrupt(error.to_string()))?,
            args,
            capabilities: serde_json::from_str(&capabilities)
                .map_err(|error| StoreError::Corrupt(format!("capabilities: {error}")))?,
            fingerprint: parse(&fingerprint)?,
            status: parse(&status)?,
            requested_at,
            expires_at,
            expires_at_ms,
            decided_by,
            reason,
        })
    })())
}

fn load(
    tx: &Transaction<'_>,
    approval_id: ApprovalId,
) -> Result<Option<ApprovalRecord>, StoreError> {
    tx.query_row(
        &format!("{APPROVAL_COLUMNS} WHERE a.approval_id = ?1"),
        params![approval_id.to_string()],
        read_record,
    )
    .optional()?
    .transpose()
}

/// Conditional status change; true if this call made it.
fn set_status(
    tx: &Transaction<'_>,
    approval_id: ApprovalId,
    from: &[ApprovalStatus],
    to: ApprovalStatus,
    decided_by: Option<&str>,
    reason: Option<&str>,
) -> Result<bool, StoreError> {
    let from: Vec<&str> = from.iter().map(|status| status.as_str()).collect();
    let changed = tx.execute(
        "UPDATE approvals SET status = ?1, decided_by = COALESCE(?2, decided_by),
             reason = COALESCE(?3, reason), updated_at = ?4
         WHERE approval_id = ?5 AND status IN (SELECT value FROM json_each(?6))",
        params![
            to.as_str(),
            decided_by,
            reason,
            now(),
            approval_id.to_string(),
            serde_json::to_string(&from).unwrap_or_else(|_| "[]".into()),
        ],
    )?;
    Ok(changed == 1)
}

/// Expire one approval and its task, if both are still open.
fn expire(tx: &Transaction<'_>, record: &ApprovalRecord, reason: &str) -> Result<bool, StoreError> {
    if !set_status(
        tx,
        record.approval_id,
        &[ApprovalStatus::Pending, ApprovalStatus::Granted],
        ApprovalStatus::Expired,
        None,
        None,
    )? {
        return Ok(false);
    }
    insert_event(
        tx,
        Some(record.session_id),
        Some(record.task_id),
        &AuditEventKind::ApprovalExpired {
            approval_id: record.approval_id,
            reason: reason.to_owned(),
        },
    )?;
    let change = TaskChange {
        error: Some(WireError::new(ErrorCode::Cancelled, reason)),
        ..TaskChange::to(TaskStatus::Expired)
    };
    match apply_transition(
        tx,
        record.task_id,
        &[TaskStatus::AwaitingConfirmation],
        &change,
    ) {
        Ok(_) => {
            insert_event(
                tx,
                Some(record.session_id),
                Some(record.task_id),
                &AuditEventKind::TaskExpired {
                    reason: reason.to_owned(),
                },
            )?;
        }
        // A granted approval whose consumption failed leaves the task
        // waiting; anything else has already moved on.
        Err(StoreError::IllegalTransition { .. }) => {}
        Err(error) => return Err(error),
    }
    Ok(true)
}

impl Store {
    /// Move the task to `awaiting_confirmation` and record the approval
    /// request, with `events` (the policy decision) before
    /// `approval_requested`, in one transaction.
    pub fn request_approval(
        &self,
        approval: &NewApproval,
        change: &TaskChange,
        events: &[AuditEventKind],
    ) -> Result<ApprovalRecord, StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        apply_transition(&tx, approval.task_id, &[TaskStatus::Received], change)?;
        let requested_at = now();
        let expires_at = format_ms(approval.expires_at_ms);
        let capabilities = serde_json::to_string(&approval.capabilities)
            .map_err(|error| StoreError::Corrupt(error.to_string()))?;
        tx.execute(
            "INSERT INTO approvals (approval_id, task_id, session_id, request_id, tool,
                 capabilities, fingerprint, status, requested_at, expires_at, expires_at_ms,
                 updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9, ?10, ?8)",
            params![
                approval.approval_id.to_string(),
                approval.task_id.to_string(),
                approval.session_id.to_string(),
                approval.request_id.as_str(),
                approval.tool.as_str(),
                capabilities,
                approval.fingerprint.as_str(),
                requested_at,
                expires_at,
                approval.expires_at_ms,
            ],
        )?;
        for event in events {
            insert_event(
                &tx,
                Some(approval.session_id),
                Some(approval.task_id),
                event,
            )?;
        }
        insert_event(
            &tx,
            Some(approval.session_id),
            Some(approval.task_id),
            &AuditEventKind::ApprovalRequested {
                approval_id: approval.approval_id,
                tool: approval.tool.clone(),
                capabilities: approval.capabilities.clone(),
                fingerprint: approval.fingerprint.clone(),
                expires_at,
            },
        )?;
        let record = load(&tx, approval.approval_id)?
            .ok_or_else(|| StoreError::Corrupt("approval vanished".into()))?;
        tx.commit()?;
        Ok(record)
    }

    pub fn approval(&self, approval_id: ApprovalId) -> Result<Option<ApprovalRecord>, StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        load(&tx, approval_id)
    }

    /// Pending approvals, oldest first.
    pub fn pending_approvals(&self) -> Result<Vec<ApprovalRecord>, StoreError> {
        let conn = self.conn()?;
        let mut statement = conn.prepare(&format!(
            "{APPROVAL_COLUMNS} WHERE a.status = 'pending' ORDER BY a.requested_at, a.approval_id"
        ))?;
        let rows = statement.query_map([], read_record)?;
        rows.map(|row| row?).collect()
    }

    /// Record a person's approval. Refused unless the approval is pending,
    /// has not expired at `now_ms`, and `fingerprint` is the one stored. An
    /// approval found expired is marked so, together with its task.
    pub fn grant_approval(
        &self,
        approval_id: ApprovalId,
        fingerprint: &Fingerprint,
        client: &str,
        now_ms: i64,
    ) -> Result<ApprovalRecord, ApprovalError> {
        self.decide(approval_id, now_ms, |tx, record| {
            if &record.fingerprint != fingerprint {
                return Err(ApprovalError::FingerprintMismatch);
            }
            set_status(
                tx,
                approval_id,
                &[ApprovalStatus::Pending],
                ApprovalStatus::Granted,
                Some(client),
                None,
            )?;
            insert_event(
                tx,
                Some(record.session_id),
                Some(record.task_id),
                &AuditEventKind::ApprovalGranted {
                    approval_id,
                    client: client.to_owned(),
                },
            )?;
            Ok(())
        })
    }

    /// Record a person's refusal. The task becomes `denied` in the same
    /// transaction; nothing ran and nothing will.
    pub fn deny_approval(
        &self,
        approval_id: ApprovalId,
        reason: &Summary,
        client: &str,
        now_ms: i64,
    ) -> Result<ApprovalRecord, ApprovalError> {
        self.decide(approval_id, now_ms, |tx, record| {
            set_status(
                tx,
                approval_id,
                &[ApprovalStatus::Pending],
                ApprovalStatus::Denied,
                Some(client),
                Some(reason.as_str()),
            )?;
            insert_event(
                tx,
                Some(record.session_id),
                Some(record.task_id),
                &AuditEventKind::ApprovalDenied {
                    approval_id,
                    client: client.to_owned(),
                },
            )?;
            let change = TaskChange {
                error: Some(WireError::new(
                    ErrorCode::Cancelled,
                    format!("declined by a person: {reason}"),
                )),
                ..TaskChange::to(TaskStatus::Denied)
            };
            apply_transition(
                tx,
                record.task_id,
                &[TaskStatus::AwaitingConfirmation],
                &change,
            )?;
            Ok(())
        })
    }

    fn decide(
        &self,
        approval_id: ApprovalId,
        now_ms: i64,
        apply: impl FnOnce(&Transaction<'_>, &ApprovalRecord) -> Result<(), ApprovalError>,
    ) -> Result<ApprovalRecord, ApprovalError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let record = load(&tx, approval_id)?.ok_or(ApprovalError::NotFound(approval_id))?;
        if record.status != ApprovalStatus::Pending {
            return Err(ApprovalError::NotPending(record.status));
        }
        if now_ms >= record.expires_at_ms {
            expire(&tx, &record, "no decision before the approval expired")?;
            tx.commit()?;
            return Err(ApprovalError::Expired);
        }
        apply(&tx, &record)?;
        let updated = load(&tx, approval_id)?.ok_or(ApprovalError::NotFound(approval_id))?;
        tx.commit()?;
        Ok(updated)
    }

    /// Use a granted approval. In one transaction: check that it is granted,
    /// unexpired and bound to `fingerprint` (which the caller recomputes from
    /// the call it is about to run), mark it consumed, move the task from
    /// `awaiting_confirmation` to `executing`, and record
    /// `approval_consumed` followed by `events`. Only one call can ever
    /// succeed for a given approval.
    pub fn consume_approval(
        &self,
        approval_id: ApprovalId,
        fingerprint: &Fingerprint,
        now_ms: i64,
        events: &[AuditEventKind],
    ) -> Result<(), ApprovalError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let record = load(&tx, approval_id)?.ok_or(ApprovalError::NotFound(approval_id))?;
        if record.status != ApprovalStatus::Granted {
            return Err(ApprovalError::NotGranted(record.status));
        }
        if now_ms >= record.expires_at_ms {
            expire(&tx, &record, "approved too late to use")?;
            tx.commit()?;
            return Err(ApprovalError::Expired);
        }
        if &record.fingerprint != fingerprint {
            return Err(ApprovalError::TaskChanged);
        }
        if !set_status(
            &tx,
            approval_id,
            &[ApprovalStatus::Granted],
            ApprovalStatus::Consumed,
            None,
            None,
        )? {
            return Err(ApprovalError::NotGranted(record.status));
        }
        apply_transition(
            &tx,
            record.task_id,
            &[TaskStatus::AwaitingConfirmation],
            &TaskChange::to(TaskStatus::Executing),
        )?;
        insert_event(
            &tx,
            Some(record.session_id),
            Some(record.task_id),
            &AuditEventKind::ApprovalConsumed { approval_id },
        )?;
        for event in events {
            insert_event(&tx, Some(record.session_id), Some(record.task_id), event)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Expire one approval (pending or granted) and its waiting task.
    /// Returns false if it had already been decided or used.
    pub fn expire_approval(
        &self,
        approval_id: ApprovalId,
        reason: &str,
    ) -> Result<bool, StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let Some(record) = load(&tx, approval_id)? else {
            return Ok(false);
        };
        let changed = expire(&tx, &record, reason)?;
        tx.commit()?;
        Ok(changed)
    }

    pub fn pending_approval_count(&self) -> Result<u32, StoreError> {
        let conn = self.conn()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM approvals WHERE status = 'pending'",
            [],
            |row| row.get(0),
        )?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }
}

/// Expire the open approval of one task, if any (used when a session closes).
pub(super) fn expire_open_for_task(
    tx: &Transaction<'_>,
    task_id: TaskId,
    session_id: SessionId,
    reason: &str,
) -> Result<(), StoreError> {
    let record = tx
        .query_row(
            &format!("{APPROVAL_COLUMNS} WHERE a.task_id = ?1 AND a.session_id = ?2"),
            params![task_id.to_string(), session_id.to_string()],
            read_record,
        )
        .optional()?
        .transpose()?;
    if let Some(record) = record
        && !record.status.is_terminal()
    {
        set_status(
            tx,
            record.approval_id,
            &[ApprovalStatus::Pending, ApprovalStatus::Granted],
            ApprovalStatus::Expired,
            None,
            None,
        )?;
        insert_event(
            tx,
            Some(session_id),
            Some(task_id),
            &AuditEventKind::ApprovalExpired {
                approval_id: record.approval_id,
                reason: reason.to_owned(),
            },
        )?;
    }
    Ok(())
}

/// Start-up recovery: no approval survives a restart.
pub(super) fn expire_all_open(tx: &Transaction<'_>, reason: &str) -> Result<u32, StoreError> {
    let open: Vec<ApprovalRecord> = {
        let mut statement = tx.prepare(&format!(
            "{APPROVAL_COLUMNS} WHERE a.status IN ('pending', 'granted')
             ORDER BY a.requested_at, a.approval_id"
        ))?;
        let rows = statement.query_map([], read_record)?;
        rows.map(|row| row?).collect::<Result<_, StoreError>>()?
    };
    for record in &open {
        set_status(
            tx,
            record.approval_id,
            &[ApprovalStatus::Pending, ApprovalStatus::Granted],
            ApprovalStatus::Expired,
            None,
            None,
        )?;
        insert_event(
            tx,
            Some(record.session_id),
            Some(record.task_id),
            &AuditEventKind::ApprovalExpired {
                approval_id: record.approval_id,
                reason: reason.to_owned(),
            },
        )?;
    }
    Ok(count(open.len()))
}
