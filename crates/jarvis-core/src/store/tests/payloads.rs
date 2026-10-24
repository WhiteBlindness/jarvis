//! Clipboard payloads (ADR 0022): the text lives in a working table for as
//! long as its job does, and nowhere in the immutable records.

use jarvis_protocol::{ClipboardText, PayloadId};
use rusqlite::types::ValueRef;

use super::*;

fn status_of(store: &Store, job: JobId) -> JobStatus {
    store.job(job).unwrap().unwrap().status
}

const SECRET: &str = "payload-canary-7f3a9c";

fn text(value: &str) -> ClipboardText {
    ClipboardText::try_from(value.to_owned()).unwrap()
}

/// The payload id and SHA-256 named by a clipboard job's goal.
fn named(goal: &str) -> (PayloadId, Fingerprint) {
    let rest = goal.strip_prefix("copy payload:").unwrap();
    let (id, sha256) = rest.split_once(':').unwrap();
    (id.parse().unwrap(), sha256.parse().unwrap())
}

fn payload_of(store: &Store, job: &JobRecord) -> Option<Payload> {
    let (id, _) = named(job.goal.as_str());
    store.payload(id).unwrap()
}

/// Every value of every table except `payloads`, as text.
fn immutable_records(store: &Store) -> String {
    let conn = store.conn().unwrap();
    let tables: Vec<String> = {
        let mut statement = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table'
                 AND name NOT LIKE 'sqlite_%' AND name <> 'payloads'",
            )
            .unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let mut dump = String::new();
    for table in tables {
        let mut statement = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
        let columns = statement.column_count();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for column in 0..columns {
                match row.get_ref(column).unwrap() {
                    ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
                        dump.push_str(&String::from_utf8_lossy(bytes));
                    }
                    ValueRef::Integer(value) => dump.push_str(&value.to_string()),
                    ValueRef::Real(value) => dump.push_str(&value.to_string()),
                    ValueRef::Null => {}
                }
                dump.push('|');
            }
            dump.push('\n');
        }
    }
    dump
}

/// Whether `needle` appears anywhere in the database file or its log.
fn on_disk(dir: &tempfile::TempDir, needle: &str) -> bool {
    ["jarvis.db", "jarvis.db-wal"].iter().any(|name| {
        std::fs::read(dir.path().join(name))
            .map(|bytes| {
                bytes
                    .windows(needle.len())
                    .any(|window| window == needle.as_bytes())
            })
            .unwrap_or(false)
    })
}

fn payload_count(store: &Store) -> i64 {
    store
        .conn()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM payloads", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn a_clipboard_job_holds_the_text_only_in_its_payload() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let text = text(&format!("hello {SECRET}\nsecond line"));
    let job = store.submit_clipboard_job(&text, "client").unwrap();

    let (id, sha256) = named(job.goal.as_str());
    assert_eq!(job.status, JobStatus::Queued);
    let payload = store.payload(id).unwrap().unwrap();
    assert_eq!(sha256, salted_sha256(&payload.salt, text.as_str()));
    // Salted: the records never hold the plain hash of the text.
    assert_ne!(sha256, text_sha256(text.as_str()));
    assert!(!immutable_records(&store).contains(text_sha256(text.as_str()).as_str()));
    assert_eq!(payload.job_id, job.job_id);
    assert_eq!(payload.sha256, sha256);
    assert_eq!(payload.text, text.as_str());

    // The job, its audit event and every other record carry no text.
    assert!(!immutable_records(&store).contains(SECRET));
    assert!(!job.goal.as_str().contains(SECRET));
    let submitted = store.audit_events(None, 10).unwrap();
    assert_eq!(submitted.len(), 1);
    assert_eq!(
        submitted[0].event,
        AuditEventKind::JobSubmitted {
            job_id: job.job_id,
            client: "client".into()
        }
    );
    // The job is an ordinary queued job.
    let claimed = store.claim_next_job(SessionId::new()).unwrap().unwrap();
    assert_eq!(claimed.job_id, job.job_id);
}

#[test]
fn an_unknown_payload_resolves_to_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    assert!(store.payload(PayloadId::new()).unwrap().is_none());
}

#[test]
fn the_number_of_waiting_payloads_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let session = SessionId::new();
    let mut jobs = Vec::new();
    for n in 0..MAX_PENDING_PAYLOADS {
        jobs.push(
            store
                .submit_clipboard_job(&text(&format!("text {n}")), "client")
                .unwrap(),
        );
    }
    let refused = store.submit_clipboard_job(&text("one too many"), "client");
    assert!(
        matches!(
            refused,
            Err(StoreError::TooManyPayloads(MAX_PENDING_PAYLOADS))
        ),
        "{refused:?}"
    );
    // Nothing of the refused submission was kept.
    assert_eq!(payload_count(&store), i64::from(MAX_PENDING_PAYLOADS));
    assert_eq!(store.jobs(100).unwrap().len(), jobs.len());

    // A finished job frees its place.
    let first = store.claim_next_job(session).unwrap().unwrap();
    store
        .finish_job(first.job_id, JobStatus::Completed, None, Some(session))
        .unwrap();
    store
        .submit_clipboard_job(&text("room again"), "client")
        .unwrap();
}

#[test]
fn the_payload_is_deleted_when_its_job_ends_however_it_ends() {
    for end in [
        JobStatus::Completed,
        JobStatus::Failed,
        JobStatus::Cancelled,
        JobStatus::Interrupted,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        let session = SessionId::new();
        let job = store
            .submit_clipboard_job(&text(&format!("bye {SECRET}")), "client")
            .unwrap();
        store.claim_next_job(session).unwrap().unwrap();
        assert!(payload_of(&store, &job).is_some(), "{end:?}");
        assert!(on_disk(&dir, SECRET), "the text is held while the job runs");
        store
            .finish_job(job.job_id, end, None, Some(session))
            .unwrap();
        assert!(payload_of(&store, &job).is_none(), "{end:?}");
        assert_eq!(payload_count(&store), 0, "{end:?}");
        assert!(
            !on_disk(&dir, SECRET),
            "{end:?}: the text is gone from the database file and its log"
        );
        assert!(!immutable_records(&store).contains(SECRET));
    }
}

#[test]
fn a_job_that_ends_with_a_payload_waiting_elsewhere_keeps_the_other_payload() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let session = SessionId::new();
    let first = store.submit_clipboard_job(&text("first"), "c").unwrap();
    let second = store.submit_clipboard_job(&text("second"), "c").unwrap();
    store.claim_next_job(session).unwrap().unwrap();
    store
        .finish_job(first.job_id, JobStatus::Completed, None, Some(session))
        .unwrap();
    assert!(payload_of(&store, &first).is_none());
    assert_eq!(payload_of(&store, &second).unwrap().text, "second");
}

#[test]
fn a_requeued_job_keeps_its_payload_and_a_closed_one_loses_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let session = SessionId::new();
    let job = store
        .submit_clipboard_job(&text(&format!("again {SECRET}")), "c")
        .unwrap();

    store.claim_next_job(session).unwrap().unwrap();
    let status = store
        .requeue_or_close(job.job_id, MAX_ATTEMPTS, Some(session), "worker gone")
        .unwrap();
    assert_eq!(status, JobStatus::Queued);
    let kept = payload_of(&store, &job).unwrap();
    assert_eq!(
        kept.sha256,
        salted_sha256(&kept.salt, &format!("again {SECRET}"))
    );

    // It resumes with the same payload.
    let claimed = store.claim_next_job(session).unwrap().unwrap();
    assert_eq!(claimed.goal, job.goal);
    assert!(payload_of(&store, &job).is_some());

    // Out of attempts: the job is closed and the text goes with it.
    store.claim_next_job(session).unwrap();
    store
        .requeue_or_close(job.job_id, MAX_ATTEMPTS, Some(session), "worker gone")
        .unwrap();
    let claimed = store.claim_next_job(session).unwrap().unwrap();
    assert_eq!(claimed.attempts, MAX_ATTEMPTS);
    let status = store
        .requeue_or_close(job.job_id, MAX_ATTEMPTS, Some(session), "worker gone")
        .unwrap();
    assert_eq!(status, JobStatus::Interrupted);
    assert!(payload_of(&store, &job).is_none());
    assert!(!on_disk(&dir, SECRET));
}

#[test]
fn a_job_quarantined_by_an_unknown_outcome_loses_its_payload() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let session = SessionId::new();
    let job = store
        .submit_clipboard_job(&text(&format!("quarantine {SECRET}")), "c")
        .unwrap();
    store.claim_next_job(session).unwrap().unwrap();
    let started = AuditEventKind::ExecutionStarted {
        tool: "desktop.write_clipboard_text".into(),
    };
    let task = NewTask {
        job_id: Some(job.job_id),
        step: Some(JobStep { attempt: 1, seq: 1 }),
        ..new_task(session, "r1")
    };
    store.create_task(&task).unwrap();
    store
        .transition(
            task.task_id,
            &[TaskStatus::Received],
            &TaskChange::to(TaskStatus::Executing),
            &[started],
        )
        .unwrap();
    let status = store
        .requeue_or_close(
            job.job_id,
            MAX_ATTEMPTS,
            Some(session),
            "the worker went away",
        )
        .unwrap();
    assert_eq!(status, JobStatus::Interrupted);
    assert!(payload_of(&store, &job).is_none());
    assert!(!on_disk(&dir, SECRET));
}

#[test]
fn recovery_keeps_the_payload_of_a_job_it_requeues_and_drops_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let session = SessionId::new();
    let (spent, resumed, queued);
    {
        let store = open(&dir);
        // `spent` has used all its attempts and is running; `resumed` is
        // running too; `queued` was never started.
        spent = store
            .submit_clipboard_job(&text(&format!("spent {SECRET}")), "c")
            .unwrap();
        for _ in 1..MAX_ATTEMPTS {
            store.claim_next_job(session).unwrap().unwrap();
            store
                .requeue_or_close(spent.job_id, MAX_ATTEMPTS, Some(session), "test")
                .unwrap();
        }
        store.claim_next_job(session).unwrap().unwrap();
        resumed = store
            .submit_clipboard_job(&text(&format!("resumed {SECRET}")), "c")
            .unwrap();
        assert_eq!(
            store.claim_next_job(session).unwrap().unwrap().job_id,
            resumed.job_id
        );
        queued = store
            .submit_clipboard_job(&text(&format!("queued {SECRET}")), "c")
            .unwrap();
    }
    let store = open(&dir);
    assert_eq!(store.recover(MAX_ATTEMPTS).unwrap().jobs, 2);
    assert_eq!(status_of(&store, spent.job_id), JobStatus::Interrupted);
    assert!(payload_of(&store, &spent).is_none());
    for kept in [&resumed, &queued] {
        assert_eq!(status_of(&store, kept.job_id), JobStatus::Queued);
        assert!(payload_of(&store, kept).is_some());
    }
    assert!(!on_disk(&dir, "spent payload-canary"));
}

#[test]
fn recovery_drops_a_payload_whose_job_already_ended() {
    let dir = tempfile::tempdir().unwrap();
    let session = SessionId::new();
    let job;
    {
        let store = open(&dir);
        job = store
            .submit_clipboard_job(&text(&format!("leftover {SECRET}")), "c")
            .unwrap();
        store.claim_next_job(session).unwrap().unwrap();
        // A crash between the job's end and the payload's deletion cannot
        // happen through the API, so put the leftover back by hand: a
        // payload row on a finished job.
        let copy = payload_of(&store, &job).unwrap();
        store
            .finish_job(job.job_id, JobStatus::Completed, None, Some(session))
            .unwrap();
        store
            .conn()
            .unwrap()
            .execute(
                "INSERT INTO payloads (payload_id, job_id, sha256, salt, text, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'now')",
                params![
                    PayloadId::new().to_string(),
                    job.job_id.to_string(),
                    copy.sha256.as_str(),
                    copy.salt,
                    copy.text
                ],
            )
            .unwrap();
        assert_eq!(payload_count(&store), 1);
    }
    let store = open(&dir);
    store.recover(MAX_ATTEMPTS).unwrap();
    assert_eq!(payload_count(&store), 0);
    assert!(!on_disk(&dir, SECRET));
}

#[test]
fn historical_rows_that_hold_text_stay_readable() {
    // A job and a task written before ADR 0022 hold the text itself. Nothing
    // rewrites them, and the store still reads them.
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let old = store
        .submit_job(&goal(&format!("copy \"old {SECRET}\"")), "client")
        .unwrap();
    let session = SessionId::new();
    let task = NewTask {
        job_id: Some(old.job_id),
        tool: ToolName::try_from("desktop.write_clipboard_text".to_owned()).unwrap(),
        args: json!({"text": format!("old {SECRET}")}),
        ..new_task(session, "old")
    };
    store.create_task(&task).unwrap();
    let kept = store.task(task.task_id).unwrap().unwrap();
    assert!(kept.args.contains(SECRET));
    assert!(
        store
            .job(old.job_id)
            .unwrap()
            .unwrap()
            .goal
            .as_str()
            .contains(SECRET)
    );
    drop(store);
    let store = open(&dir);
    store.recover(MAX_ATTEMPTS).unwrap();
    assert!(
        store
            .task(task.task_id)
            .unwrap()
            .unwrap()
            .args
            .contains(SECRET)
    );
}

#[test]
fn the_payload_table_is_a_working_table_the_immutable_records_do_not_depend_on() {
    // Deleting a payload fires no trigger and the job is untouched.
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let job = store.submit_clipboard_job(&text("temporary"), "c").unwrap();
    let before = store.job(job.job_id).unwrap().unwrap();
    store
        .conn()
        .unwrap()
        .execute("DELETE FROM payloads", [])
        .unwrap();
    assert_eq!(store.job(job.job_id).unwrap().unwrap(), before);
    // A payload belongs to exactly one job, and to one that exists.
    let other = store.submit_clipboard_job(&text("other"), "c").unwrap();
    let (id, sha256) = named(other.goal.as_str());
    let twice = store.conn().unwrap().execute(
        "INSERT INTO payloads (payload_id, job_id, sha256, text, created_at)
         VALUES (?1, ?2, ?3, 'again', 'now')",
        params![
            PayloadId::new().to_string(),
            other.job_id.to_string(),
            sha256.as_str()
        ],
    );
    assert!(twice.is_err(), "one payload per job");
    let orphan = store.conn().unwrap().execute(
        "INSERT INTO payloads (payload_id, job_id, sha256, text, created_at)
         VALUES (?1, ?2, ?3, 'orphan', 'now')",
        params![
            PayloadId::new().to_string(),
            JobId::new().to_string(),
            sha256.as_str()
        ],
    );
    assert!(orphan.is_err(), "a payload needs a job");
    assert!(store.payload(id).unwrap().is_some());
}

#[test]
fn the_same_text_submitted_twice_is_bound_to_different_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let pin = text("1234");
    let (_, first) = named(store.submit_clipboard_job(&pin, "c").unwrap().goal.as_str());
    let (_, second) = named(store.submit_clipboard_job(&pin, "c").unwrap().goal.as_str());
    assert_ne!(first, second);
}
