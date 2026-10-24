//! Durable jobs: attempts, the step ledger, replay, quarantine and recovery.

use super::*;

/// Where a task of a job stopped.
#[derive(Clone, Copy)]
enum Stop {
    /// Created, never decided.
    Received,
    /// Waiting for a person; never started.
    Awaiting,
    /// `execution_started` was recorded, then the task ended like this
    /// (`None`: it never ended).
    Started(Option<TaskStatus>),
    /// `execution_started` was recorded, then the task ended `failed` with
    /// this error code (`None`: no error was recorded).
    Failed(Option<ErrorCode>),
}

/// Create the task for position `seq` of `attempt` and leave it as `stop`.
fn step(
    store: &Store,
    session: SessionId,
    job: JobId,
    (attempt, seq): (u32, u32),
    stop: Stop,
) -> TaskId {
    let task = NewTask {
        job_id: Some(job),
        step: Some(JobStep { attempt, seq }),
        ..new_task(session, &format!("a{attempt}s{seq}"))
    };
    store.create_task(&task).unwrap();
    match stop {
        Stop::Received => {}
        Stop::Awaiting => store
            .transition(
                task.task_id,
                &[TaskStatus::Received],
                &TaskChange::to(TaskStatus::AwaitingConfirmation),
                &[],
            )
            .unwrap(),
        Stop::Started(_) | Stop::Failed(_) => {
            let end = match stop {
                Stop::Started(end) => end,
                _ => Some(TaskStatus::Failed),
            };
            let started = AuditEventKind::ExecutionStarted {
                tool: "system.info".into(),
            };
            store
                .transition(
                    task.task_id,
                    &[TaskStatus::Received],
                    &TaskChange::to(TaskStatus::Executing),
                    &[started],
                )
                .unwrap();
            if let Some(end) = end {
                let error = match stop {
                    Stop::Failed(code) => code.map(|code| WireError::new(code, "failed")),
                    _ => None,
                };
                let change = TaskChange {
                    result: (end == TaskStatus::Completed).then(|| "{}".to_owned()),
                    error,
                    ..TaskChange::to(end)
                };
                store
                    .transition(task.task_id, &[TaskStatus::Executing], &change, &[])
                    .unwrap();
            }
        }
    }
    task.task_id
}

fn running_job(store: &Store, session: SessionId) -> JobId {
    let job = store.submit_job(&goal("durable"), "client").unwrap();
    let claimed = store.claim_next_job(session).unwrap().unwrap();
    assert_eq!(claimed.job_id, job.job_id);
    job.job_id
}

fn job_kinds(store: &Store) -> Vec<&'static str> {
    store
        .audit_events(None, 1000)
        .unwrap()
        .into_iter()
        .map(|event| event.event.name())
        .filter(|kind| kind.starts_with("job_"))
        .collect()
}

fn status_of(store: &Store, job: JobId) -> JobStatus {
    store.job(job).unwrap().unwrap().status
}

#[test]
fn claiming_a_job_counts_an_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let session = SessionId::new();
    let job = store.submit_job(&goal("g"), "client").unwrap();
    assert_eq!(job.attempts, 0);
    let claimed = store.claim_next_job(session).unwrap().unwrap();
    assert_eq!(claimed.attempts, 1);
    assert_eq!(
        store
            .requeue_or_close(job.job_id, MAX_ATTEMPTS, Some(session), "test")
            .unwrap(),
        JobStatus::Queued
    );
    assert_eq!(store.job(job.job_id).unwrap().unwrap().attempts, 1);
    assert_eq!(store.claim_next_job(session).unwrap().unwrap().attempts, 2);
}

#[test]
fn a_queued_job_stays_queued_across_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let job = {
        let store = open(&dir);
        store.submit_job(&goal("waiting"), "client").unwrap().job_id
    };
    let store = open(&dir);
    assert!(store.recover(MAX_ATTEMPTS).unwrap().is_empty());
    assert_eq!(status_of(&store, job), JobStatus::Queued);
    assert_eq!(job_kinds(&store), ["job_submitted"]);
    let claimed = store.claim_next_job(SessionId::new()).unwrap().unwrap();
    assert_eq!(claimed.job_id, job);
}

#[test]
fn recovery_requeues_a_running_job_until_its_attempts_are_spent() {
    const LIMIT: u32 = 2;
    let dir = tempfile::tempdir().unwrap();
    let session = SessionId::new();
    let job = {
        let store = open(&dir);
        let job = running_job(&store, session);
        // A step that ended with a known outcome does not stop a resume.
        let done = Stop::Started(Some(TaskStatus::Completed));
        step(&store, session, job, (1, 1), done);
        job
    };

    // Attempt 1 of 2 was running when the Core stopped.
    let store = open(&dir);
    assert_eq!(store.recover(LIMIT).unwrap().jobs, 1);
    assert_eq!(status_of(&store, job), JobStatus::Queued);
    let requeued: Vec<_> = store
        .audit_events(None, 1000)
        .unwrap()
        .into_iter()
        .filter_map(|event| match event.event {
            AuditEventKind::JobRequeued {
                job_id,
                attempts,
                reason,
            } if job_id == job => Some((attempts, reason)),
            _ => None,
        })
        .collect();
    assert_eq!(requeued.len(), 1);
    assert_eq!(requeued[0].0, 1);
    assert!(requeued[0].1.contains("restarted"), "{}", requeued[0].1);
    assert_eq!(store.claim_next_job(session).unwrap().unwrap().attempts, 2);
    drop(store);

    // Attempt 2 of 2 was running when the Core stopped again: no third try.
    let store = open(&dir);
    assert_eq!(store.recover(LIMIT).unwrap().jobs, 1);
    let done = store.job(job).unwrap().unwrap();
    assert_eq!(done.status, JobStatus::Interrupted);
    assert!(done.summary.unwrap().as_str().contains("attempt limit"));
    assert_eq!(job_kinds(&store).last(), Some(&"job_finished"));
    assert!(store.recover(LIMIT).unwrap().is_empty(), "idempotent");
}

#[test]
fn a_task_with_an_unknown_outcome_quarantines_its_job() {
    // Started, and not known to have completed or failed.
    let unknown = [
        None,
        Some(TaskStatus::TimedOut),
        Some(TaskStatus::Cancelled),
        Some(TaskStatus::Interrupted),
    ];
    for end in unknown {
        for at_recovery in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let store = open(&dir);
            let session = SessionId::new();
            let job = running_job(&store, session);
            let done = Stop::Started(Some(TaskStatus::Completed));
            step(&store, session, job, (1, 1), done);
            let task = step(&store, session, job, (1, 2), Stop::Started(end));
            let status = if at_recovery {
                store.recover(MAX_ATTEMPTS).unwrap();
                status_of(&store, job)
            } else {
                store
                    .requeue_or_close(job, MAX_ATTEMPTS, Some(session), "worker stopped")
                    .unwrap()
            };
            let which = format!("{end:?} at_recovery={at_recovery}");
            assert_eq!(status, JobStatus::Interrupted, "{which}");
            let record = store.job(job).unwrap().unwrap();
            assert!(
                record.summary.unwrap().as_str().contains(&task.to_string()),
                "the summary names the task: {which}"
            );
            let quarantined = AuditEventKind::JobQuarantined {
                job_id: job,
                task_id: task,
            };
            assert!(
                store
                    .audit_events(None, 1000)
                    .unwrap()
                    .iter()
                    .any(|event| event.event == quarantined),
                "{which}"
            );
            assert_eq!(job_kinds(&store).last(), Some(&"job_finished"), "{which}");
            assert!(!job_kinds(&store).contains(&"job_requeued"), "{which}");
        }
    }
}

#[test]
fn a_known_outcome_does_not_quarantine_a_job() {
    let stops = [
        (Stop::Received, "received"),
        (Stop::Awaiting, "awaiting confirmation"),
        (
            Stop::Failed(Some(ErrorCode::ToolFailed)),
            "failed by the tool",
        ),
        (Stop::Started(Some(TaskStatus::Completed)), "completed"),
    ];
    for (stop, name) in stops {
        for at_recovery in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let store = open(&dir);
            let session = SessionId::new();
            let job = running_job(&store, session);
            step(&store, session, job, (1, 1), stop);
            let status = if at_recovery {
                store.recover(MAX_ATTEMPTS).unwrap();
                status_of(&store, job)
            } else {
                store
                    .requeue_or_close(job, MAX_ATTEMPTS, Some(session), "worker stopped")
                    .unwrap()
            };
            let which = format!("{name} at_recovery={at_recovery}");
            assert_eq!(status, JobStatus::Queued, "{which}");
            assert!(!job_kinds(&store).contains(&"job_quarantined"), "{which}");
            assert!(job_kinds(&store).contains(&"job_requeued"), "{which}");
        }
    }
}

#[test]
fn only_a_running_job_can_be_requeued_or_closed() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let running = running_job(&store, SessionId::new());
    let queued = store.submit_job(&goal("g"), "client").unwrap().job_id;
    assert!(
        store
            .requeue_or_close(queued, MAX_ATTEMPTS, None, "test")
            .is_err()
    );
    store
        .finish_job(running, JobStatus::Completed, None, None)
        .unwrap();
    assert!(
        store
            .requeue_or_close(running, MAX_ATTEMPTS, None, "test")
            .is_err()
    );
}

#[test]
fn job_steps_are_insert_only() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let session = SessionId::new();
    let job = running_job(&store, session);
    let task = step(&store, session, job, (1, 1), Stop::Received);
    let conn = store.conn().unwrap();
    let error = conn
        .execute("UPDATE job_steps SET seq = 9", [])
        .unwrap_err();
    assert!(error.to_string().contains("insert-only"), "{error}");
    let error = conn.execute("DELETE FROM job_steps", []).unwrap_err();
    assert!(error.to_string().contains("insert-only"), "{error}");
    let error = conn
        .execute(
            "INSERT OR REPLACE INTO job_steps (task_id, job_id, attempt, seq)
             VALUES (?1, ?2, 1, 1)",
            params![task.to_string(), job.to_string()],
        )
        .unwrap_err();
    assert!(error.to_string().contains("insert-only"), "{error}");
    let error = conn
        .execute("UPDATE jobs SET attempts = 0", [])
        .unwrap_err();
    assert!(error.to_string().contains("never decrease"), "{error}");
}

#[test]
fn a_position_holds_one_task_per_attempt_and_the_task_must_belong_to_the_job() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let session = SessionId::new();
    let job = running_job(&store, session);
    step(&store, session, job, (1, 1), Stop::Received);
    let again = NewTask {
        job_id: Some(job),
        step: Some(JobStep { attempt: 1, seq: 1 }),
        ..new_task(session, "other")
    };
    assert!(store.create_task(&again).is_err());
    let orphan = NewTask {
        step: Some(JobStep { attempt: 1, seq: 2 }),
        ..new_task(session, "orphan")
    };
    assert!(store.create_task(&orphan).is_err(), "a step needs a job");
    assert_eq!(
        store.tasks(10).unwrap().len(),
        1,
        "a refused step leaves no task behind"
    );
}

#[test]
fn a_completed_step_is_found_for_later_attempts_only() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let session = SessionId::new();
    let job = running_job(&store, session);
    let ok = Stop::Started(Some(TaskStatus::Completed));
    let done = step(&store, session, job, (1, 1), ok);
    let failed = Stop::Failed(Some(ErrorCode::ToolFailed));
    step(&store, session, job, (1, 2), failed);
    step(&store, session, job, (1, 3), Stop::Awaiting);
    let found = |seq, attempt| store.completed_step(job, seq, attempt).unwrap();
    assert_eq!(found(1, 2).unwrap().task_id, done);
    assert_eq!(
        found(1, 3).unwrap().task_id,
        done,
        "still found in attempt 3"
    );
    assert!(found(1, 1).is_none(), "not from the same attempt");
    assert!(found(2, 2).is_none(), "a failed step is not completed");
    assert!(found(3, 2).is_none(), "an unfinished step is not completed");
    assert!(found(4, 2).is_none());
    assert!(store.completed_step(JobId::new(), 1, 2).unwrap().is_none());
}

#[test]
fn replaying_a_step_is_one_audit_event_and_no_task() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let first = SessionId::new();
    let job = running_job(&store, first);
    let ok = Stop::Started(Some(TaskStatus::Completed));
    let done = step(&store, first, job, (1, 1), ok);
    let second = SessionId::new();
    let request = RequestId::try_from("a2s1".to_owned()).unwrap();
    store.replay_step(second, job, 1, done, &request).unwrap();
    assert_eq!(store.tasks(10).unwrap().len(), 1, "no task was created");
    let events = store.audit_events(Some(done), 100).unwrap();
    let replayed = events.last().unwrap();
    assert_eq!(
        replayed.event,
        AuditEventKind::StepReplayed {
            job_id: job,
            seq: 1,
            task_id: done
        }
    );
    assert_eq!(replayed.session_id, Some(second));
    let started = events
        .iter()
        .filter(|event| event.event.name() == "execution_started")
        .count();
    assert_eq!(started, 1);
    // A request_id already used by a task of the session cannot be replayed.
    let used = RequestId::try_from("a1s1".to_owned()).unwrap();
    assert!(matches!(
        store.replay_step(first, job, 1, done, &used),
        Err(StoreError::DuplicateRequest(_))
    ));
}

#[test]
fn a_failure_the_tool_did_not_report_quarantines_its_job() {
    // The tool may have acted before the Core's own check or the tool itself
    // went wrong, so these are not known outcomes.
    let stops = [
        (
            Stop::Failed(Some(ErrorCode::ResultRejected)),
            "result rejected",
        ),
        (Stop::Failed(Some(ErrorCode::Internal)), "internal"),
        (Stop::Failed(None), "no error recorded"),
    ];
    for (stop, name) in stops {
        for at_recovery in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let store = open(&dir);
            let session = SessionId::new();
            let job = running_job(&store, session);
            let task = step(&store, session, job, (1, 1), stop);
            let status = if at_recovery {
                store.recover(MAX_ATTEMPTS).unwrap();
                status_of(&store, job)
            } else {
                store
                    .requeue_or_close(job, MAX_ATTEMPTS, Some(session), "worker stopped")
                    .unwrap()
            };
            let which = format!("{name} at_recovery={at_recovery}");
            assert_eq!(status, JobStatus::Interrupted, "{which}");
            let quarantined = AuditEventKind::JobQuarantined {
                job_id: job,
                task_id: task,
            };
            assert!(
                store
                    .audit_events(None, 1000)
                    .unwrap()
                    .iter()
                    .any(|event| event.event == quarantined),
                "{which}"
            );
        }
    }
}

#[test]
fn a_job_from_before_the_ledger_is_never_requeued() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let job = store.submit_job(&goal("old"), "client").unwrap().job_id;
    // As migration 0003 leaves a job that was running when the Core stopped.
    store
        .conn()
        .unwrap()
        .execute("UPDATE jobs SET status = 'running'", [])
        .unwrap();
    assert_eq!(store.recover(MAX_ATTEMPTS).unwrap().jobs, 1);
    let done = store.job(job).unwrap().unwrap();
    assert_eq!(done.status, JobStatus::Interrupted);
    assert!(done.summary.unwrap().as_str().contains("step ledger"));
    assert_eq!(job_kinds(&store).last(), Some(&"job_finished"));
    assert!(!job_kinds(&store).contains(&"job_requeued"));
}

/// No other test opens a database that a Core at migration 0002 wrote, so the
/// upgrade over real rows is only proved here.
#[test]
fn a_database_written_at_migration_two_upgrades_to_the_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jarvis.db");
    let running = JobId::new();
    let queued = JobId::new();
    let task = TaskId::new();
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (
                 version    INTEGER PRIMARY KEY NOT NULL,
                 name       TEXT NOT NULL,
                 applied_at TEXT NOT NULL
             ) STRICT;",
        )
        .unwrap();
        for migration in MIGRATIONS.iter().filter(|m| m.version <= 2) {
            conn.execute_batch(migration.sql).unwrap();
            conn.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
                params![migration.version, migration.name, "2026-01-01T00:00:00Z"],
            )
            .unwrap();
        }
        for (id, status, goal) in [(running, "running", "old"), (queued, "queued", "waiting")] {
            conn.execute(
                "INSERT INTO jobs (job_id, goal, submitted_by, status, created_at, updated_at)
                 VALUES (?1, ?2, 'client', ?3, ?4, ?4)",
                params![id.to_string(), goal, status, "2026-01-01T00:00:00Z"],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO tasks (task_id, session_id, request_id, tool, args, status, job_id,
                                created_at, updated_at)
             VALUES (?1, ?2, 'r1', 'system.info', '{}', 'completed', ?3, ?4, ?4)",
            params![
                task.to_string(),
                SessionId::new().to_string(),
                running.to_string(),
                "2026-01-01T00:00:00Z"
            ],
        )
        .unwrap();
    }

    let store = Store::open(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), latest_version());
    assert_eq!(latest_version(), 4);

    let before = store.job(running).unwrap().unwrap();
    assert_eq!(before.status, JobStatus::Running);
    assert_eq!(before.attempts, 0);
    assert_eq!(before.goal.as_str(), "old");
    assert_eq!(
        store.job(queued).unwrap().unwrap().status,
        JobStatus::Queued
    );
    let kept = store.task(task).unwrap().unwrap();
    assert_eq!(kept.status, TaskStatus::Completed);
    assert_eq!(kept.job_id, Some(running));

    // Without a ledger the running job cannot be resumed, so it is ended.
    assert_eq!(store.recover(MAX_ATTEMPTS).unwrap().jobs, 1);
    let done = store.job(running).unwrap().unwrap();
    assert_eq!(done.status, JobStatus::Interrupted);
    assert!(!job_kinds(&store).contains(&"job_requeued"));

    let claimed = store.claim_next_job(SessionId::new()).unwrap().unwrap();
    assert_eq!(claimed.job_id, queued);
    assert_eq!(claimed.status, JobStatus::Running);
    assert_eq!(claimed.attempts, 1);
}

/// Recovery settles a job before it rewrites its open tasks, so the audit
/// trail shows the quarantine before the task recovery. The decision itself
/// does not depend on the order.
#[test]
fn recovery_settles_a_job_before_it_rewrites_its_tasks() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let session = SessionId::new();
    let job = running_job(&store, session);
    let task = step(&store, session, job, (1, 1), Stop::Started(None));
    assert_eq!(
        store.task(task).unwrap().unwrap().status,
        TaskStatus::Executing
    );
    store.recover(MAX_ATTEMPTS).unwrap();
    assert_eq!(status_of(&store, job), JobStatus::Interrupted);
    let seq_of = |wanted: &dyn Fn(&AuditEventKind) -> bool| {
        store
            .audit_events(None, 1000)
            .unwrap()
            .into_iter()
            .find(|event| wanted(&event.event))
            .map(|event| event.seq)
            .unwrap()
    };
    let quarantined = seq_of(&|event| {
        *event
            == AuditEventKind::JobQuarantined {
                job_id: job,
                task_id: task,
            }
    });
    let rewritten = seq_of(&|event| matches!(event, AuditEventKind::TaskRecovered { .. }));
    assert!(quarantined < rewritten, "the job was settled first");
}

#[test]
fn a_job_ended_without_a_retry_still_records_an_unknown_outcome() {
    let ends = [JobStatus::Failed, JobStatus::Interrupted];
    for end in ends {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        let session = SessionId::new();
        let job = running_job(&store, session);
        let task = step(
            &store,
            session,
            job,
            (1, 1),
            Stop::Started(Some(TaskStatus::TimedOut)),
        );
        store.finish_job(job, end, None, Some(session)).unwrap();
        assert_eq!(status_of(&store, job), end);
        let kinds = job_kinds(&store);
        assert_eq!(
            &kinds[kinds.len() - 2..],
            ["job_quarantined", "job_finished"],
            "{end:?}"
        );
        let quarantined = AuditEventKind::JobQuarantined {
            job_id: job,
            task_id: task,
        };
        assert!(
            store
                .audit_events(None, 1000)
                .unwrap()
                .iter()
                .any(|event| event.event == quarantined)
        );
    }
    // Known outcomes, and a job that completed, leave no such record.
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let session = SessionId::new();
    let job = running_job(&store, session);
    let failed = Stop::Failed(Some(ErrorCode::ToolFailed));
    step(&store, session, job, (1, 1), failed);
    store
        .finish_job(job, JobStatus::Failed, None, Some(session))
        .unwrap();
    assert!(!job_kinds(&store).contains(&"job_quarantined"));
}
