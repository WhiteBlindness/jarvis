-- Tasks: one row per well-formed tool request. Identity columns never
-- change, and a task in a terminal state never changes again.
CREATE TABLE tasks (
    task_id       TEXT PRIMARY KEY NOT NULL,
    session_id    TEXT NOT NULL,
    request_id    TEXT NOT NULL,
    tool          TEXT NOT NULL,
    args          TEXT NOT NULL CHECK (json_valid(args)),
    status        TEXT NOT NULL CHECK (status IN (
                      'received', 'executing', 'awaiting_confirmation',
                      'completed', 'failed', 'timed_out', 'cancelled',
                      'denied', 'rejected', 'expired', 'interrupted')),
    decision      TEXT CHECK (decision IN ('allow', 'require_confirmation', 'deny')),
    capabilities  TEXT CHECK (capabilities IS NULL OR json_valid(capabilities)),
    result        TEXT CHECK (result IS NULL OR json_valid(result)),
    error_code    TEXT,
    error_message TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (session_id, request_id)
) STRICT;

CREATE INDEX tasks_open ON tasks (status)
    WHERE status IN ('received', 'executing', 'awaiting_confirmation');

CREATE TRIGGER tasks_identity_immutable
BEFORE UPDATE OF task_id, session_id, request_id, tool, args, created_at ON tasks
BEGIN
    SELECT RAISE(ABORT, 'task identity is immutable');
END;

CREATE TRIGGER tasks_terminal_immutable
BEFORE UPDATE ON tasks
WHEN OLD.status NOT IN ('received', 'executing', 'awaiting_confirmation')
BEGIN
    SELECT RAISE(ABORT, 'terminal tasks are immutable');
END;

CREATE TRIGGER tasks_no_delete
BEFORE DELETE ON tasks
BEGIN
    SELECT RAISE(ABORT, 'tasks are never deleted');
END;

-- Audit: append-only. `seq` is never reused (AUTOINCREMENT), so gaps would
-- be visible.
CREATE TABLE audit_events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TEXT NOT NULL,
    session_id TEXT,
    task_id    TEXT REFERENCES tasks (task_id),
    kind       TEXT NOT NULL,
    detail     TEXT NOT NULL CHECK (json_valid(detail))
) STRICT;

CREATE INDEX audit_events_task ON audit_events (task_id);

CREATE TRIGGER audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
