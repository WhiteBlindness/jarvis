use jarvis_protocol::{AuditEventKind, ErrorCode, PolicyDecision, TaskStatus, WireError};
use serde_json::json;

use super::*;

fn new_task(session_id: SessionId, request_id: &str) -> NewTask {
    NewTask {
        task_id: TaskId::new(),
        session_id,
        request_id: RequestId::try_from(request_id.to_owned()).unwrap(),
        tool: ToolName::try_from("system.info".to_owned()).unwrap(),
        args: json!({}),
    }
}

fn open(dir: &tempfile::TempDir) -> Store {
    Store::open(&dir.path().join("jarvis.db")).unwrap()
}

#[test]
fn migrations_are_recorded_and_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    assert_eq!(store.schema_version().unwrap(), latest_version());
    drop(store);
    let store = open(&dir);
    assert_eq!(store.schema_version().unwrap(), latest_version());
    let rows: i64 = store
        .conn()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rows, i64::try_from(MIGRATIONS.len()).unwrap());
}

#[test]
fn completed_task_and_audit_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let session = SessionId::new();
    let task = new_task(session, "r1");
    {
        let store = open(&dir);
        store.create_task(&task).unwrap();
        store
            .transition(
                task.task_id,
                &[TaskStatus::Received],
                &TaskChange {
                    decision: Some(PolicyDecision::Allow),
                    capabilities: Some(vec![Capability::SystemInfo]),
                    ..TaskChange::to(TaskStatus::Executing)
                },
                &[AuditEventKind::ExecutionStarted {
                    tool: "system.info".into(),
                }],
            )
            .unwrap();
        store
            .transition(
                task.task_id,
                &[TaskStatus::Executing],
                &TaskChange {
                    result: Some(r#"{"ok":true}"#.into()),
                    ..TaskChange::to(TaskStatus::Completed)
                },
                &[],
            )
            .unwrap();
    }

    let store = open(&dir);
    let record = store.task(task.task_id).unwrap().unwrap();
    assert_eq!(record.status, TaskStatus::Completed);
    assert_eq!(record.decision, Some(PolicyDecision::Allow));
    assert_eq!(record.capabilities, Some(vec![Capability::SystemInfo]));
    assert_eq!(record.result.as_deref(), Some(r#"{"ok":true}"#));

    let kinds: Vec<_> = store
        .audit_events(Some(task.task_id), 100)
        .unwrap()
        .into_iter()
        .map(|event| event.event.name())
        .collect();
    assert_eq!(kinds, ["request_received", "execution_started"]);
}

#[test]
fn duplicate_request_id_in_a_session_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let session = SessionId::new();
    store.create_task(&new_task(session, "r1")).unwrap();
    assert!(matches!(
        store.create_task(&new_task(session, "r1")),
        Err(StoreError::DuplicateRequest(_))
    ));
    // The same request ID in another session is a different request.
    store
        .create_task(&new_task(SessionId::new(), "r1"))
        .unwrap();
}

#[test]
fn transitions_from_unexpected_states_change_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let task = new_task(SessionId::new(), "r1");
    store.create_task(&task).unwrap();
    let error = store
        .transition(
            task.task_id,
            &[TaskStatus::Executing],
            &TaskChange::to(TaskStatus::Completed),
            &[AuditEventKind::ExecutionStarted { tool: "x".into() }],
        )
        .unwrap_err();
    assert!(matches!(error, StoreError::IllegalTransition { .. }));
    assert_eq!(
        store.task(task.task_id).unwrap().unwrap().status,
        TaskStatus::Received
    );
    // The audit event in the failed transaction was rolled back too.
    assert_eq!(store.audit_events(Some(task.task_id), 10).unwrap().len(), 1);
}

#[test]
fn terminal_tasks_cannot_be_changed_even_by_direct_sql() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let task = new_task(SessionId::new(), "r1");
    store.create_task(&task).unwrap();
    let failed = TaskChange {
        error: Some(WireError::new(ErrorCode::ToolFailed, "boom")),
        ..TaskChange::to(TaskStatus::Failed)
    };
    store
        .transition(task.task_id, &[TaskStatus::Received], &failed, &[])
        .unwrap();

    assert!(matches!(
        store.transition(
            task.task_id,
            &[TaskStatus::Failed],
            &TaskChange::to(TaskStatus::Completed),
            &[]
        ),
        Err(StoreError::IllegalTransition { .. })
    ));
    let conn = store.conn().unwrap();
    let error = conn
        .execute("UPDATE tasks SET status = 'completed'", [])
        .unwrap_err();
    assert!(error.to_string().contains("terminal tasks are immutable"));
    let error = conn.execute("DELETE FROM tasks", []).unwrap_err();
    assert!(error.to_string().contains("never deleted"));
}

#[test]
fn audit_log_is_append_only() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    store
        .append(
            None,
            None,
            &AuditEventKind::CoreStopped {
                reason: "test".into(),
            },
        )
        .unwrap();
    let conn = store.conn().unwrap();
    for sql in [
        "UPDATE audit_events SET kind = 'forged'",
        "DELETE FROM audit_events",
    ] {
        let error = conn.execute(sql, []).unwrap_err();
        assert!(error.to_string().contains("append-only"), "{sql}: {error}");
    }
}

#[test]
fn task_identity_is_immutable() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    store
        .create_task(&new_task(SessionId::new(), "r1"))
        .unwrap();
    let error = store
        .conn()
        .unwrap()
        .execute("UPDATE tasks SET tool = 'shell.exec'", [])
        .unwrap_err();
    assert!(error.to_string().contains("identity is immutable"));
}

#[test]
fn recovery_marks_unfinished_tasks() {
    let dir = tempfile::tempdir().unwrap();
    let session = SessionId::new();
    let received = new_task(session, "r1");
    let executing = new_task(session, "r2");
    let awaiting = new_task(session, "r3");
    let done = new_task(session, "r4");
    {
        let store = open(&dir);
        for task in [&received, &executing, &awaiting, &done] {
            store.create_task(task).unwrap();
        }
        store
            .transition(
                executing.task_id,
                &[TaskStatus::Received],
                &TaskChange::to(TaskStatus::Executing),
                &[],
            )
            .unwrap();
        store
            .transition(
                awaiting.task_id,
                &[TaskStatus::Received],
                &TaskChange::to(TaskStatus::AwaitingConfirmation),
                &[],
            )
            .unwrap();
        store
            .transition(
                done.task_id,
                &[TaskStatus::Received],
                &TaskChange::to(TaskStatus::Denied),
                &[],
            )
            .unwrap();
        // Dropped without closing the tasks, as after a crash.
    }

    let store = open(&dir);
    assert_eq!(store.recover().unwrap(), 3);
    let status = |task: &NewTask| store.task(task.task_id).unwrap().unwrap().status;
    assert_eq!(status(&received), TaskStatus::Interrupted);
    assert_eq!(status(&executing), TaskStatus::Interrupted);
    assert_eq!(status(&awaiting), TaskStatus::Expired);
    assert_eq!(status(&done), TaskStatus::Denied);

    let recovered: Vec<_> = store
        .audit_events(None, 100)
        .unwrap()
        .into_iter()
        .filter(|event| matches!(event.event, AuditEventKind::TaskRecovered { .. }))
        .collect();
    assert_eq!(recovered.len(), 3);
    assert_eq!(store.recover().unwrap(), 0, "recovery is idempotent");
}

#[test]
fn expiring_a_session_only_touches_its_own_pending_confirmations() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let mine = SessionId::new();
    let other = SessionId::new();
    let a = new_task(mine, "r1");
    let b = new_task(other, "r1");
    for task in [&a, &b] {
        store.create_task(task).unwrap();
        store
            .transition(
                task.task_id,
                &[TaskStatus::Received],
                &TaskChange::to(TaskStatus::AwaitingConfirmation),
                &[],
            )
            .unwrap();
    }
    assert_eq!(store.expire_awaiting(mine, "session closed").unwrap(), 1);
    assert_eq!(
        store.task(a.task_id).unwrap().unwrap().status,
        TaskStatus::Expired
    );
    assert_eq!(
        store.task(b.task_id).unwrap().unwrap().status,
        TaskStatus::AwaitingConfirmation
    );
}

#[test]
fn second_core_cannot_open_same_database() {
    let dir = tempfile::tempdir().unwrap();
    let first = open(&dir);
    assert!(matches!(
        Store::open(&dir.path().join("jarvis.db")),
        Err(StoreError::Locked(_))
    ));
    // Read-only inspection does not need the lock.
    let reader = Store::open_read_only(&dir.path().join("jarvis.db")).unwrap();
    assert_eq!(reader.schema_version().unwrap(), latest_version());
    drop(first);
    open(&dir);
}

#[test]
fn newer_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jarvis.db");
    {
        let store = Store::open(&path).unwrap();
        store
            .conn()
            .unwrap()
            .execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (999, 'future', 'now')",
                [],
            )
            .unwrap();
    }
    assert!(matches!(
        Store::open(&path),
        Err(StoreError::SchemaTooNew { found: 999, .. })
    ));
    assert!(matches!(
        Store::open_read_only(&path),
        Err(StoreError::SchemaTooNew { .. })
    ));
}

#[test]
fn read_only_open_refuses_missing_or_foreign_files() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        Store::open_read_only(&dir.path().join("missing.db")),
        Err(StoreError::NotInitialised(_))
    ));
    let foreign = dir.path().join("foreign.db");
    Connection::open(&foreign)
        .unwrap()
        .execute_batch("CREATE TABLE t (x INTEGER);")
        .unwrap();
    assert!(matches!(
        Store::open_read_only(&foreign),
        Err(StoreError::NotInitialised(_))
    ));
}

#[tokio::test]
async fn async_bridge_runs_on_the_blocking_pool() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let task = new_task(SessionId::new(), "r1");
    let id = task.task_id;
    store.call(move |s| s.create_task(&task)).await.unwrap();
    let record = store.call(move |s| s.task(id)).await.unwrap().unwrap();
    assert_eq!(record.status, TaskStatus::Received);
}
