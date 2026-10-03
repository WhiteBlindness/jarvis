-- Jobs: goals submitted by local clients. Identity never changes, and a job
-- in a terminal state never changes again.
CREATE TABLE jobs (
    job_id       TEXT PRIMARY KEY NOT NULL,
    goal         TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (status IN (
                     'queued', 'running', 'completed', 'failed', 'cancelled', 'interrupted')),
    summary      TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
) STRICT;

CREATE INDEX jobs_open ON jobs (status) WHERE status IN ('queued', 'running');

CREATE TRIGGER jobs_identity_immutable
BEFORE UPDATE OF job_id, goal, submitted_by, created_at ON jobs
BEGIN
    SELECT RAISE(ABORT, 'job identity is immutable');
END;

CREATE TRIGGER jobs_terminal_immutable
BEFORE UPDATE ON jobs
WHEN OLD.status NOT IN ('queued', 'running')
BEGIN
    SELECT RAISE(ABORT, 'terminal jobs are immutable');
END;

CREATE TRIGGER jobs_no_delete
BEFORE DELETE ON jobs
BEGIN
    SELECT RAISE(ABORT, 'jobs are never deleted');
END;

-- Tasks created while working on a job record it. Tasks from before this
-- migration have no job.
ALTER TABLE tasks ADD COLUMN job_id TEXT REFERENCES jobs (job_id);

CREATE TRIGGER tasks_job_immutable
BEFORE UPDATE OF job_id ON tasks
WHEN OLD.job_id IS NOT NEW.job_id
BEGIN
    SELECT RAISE(ABORT, 'task identity is immutable');
END;

-- Approvals: one per task that policy sent to a person. Everything that
-- binds the approval to a request is immutable, the status can only move
-- along pending -> granted -> consumed (or to denied / expired), and a
-- decided approval never changes again.
CREATE TABLE approvals (
    approval_id   TEXT PRIMARY KEY NOT NULL,
    task_id       TEXT NOT NULL UNIQUE REFERENCES tasks (task_id),
    session_id    TEXT NOT NULL,
    request_id    TEXT NOT NULL,
    tool          TEXT NOT NULL,
    capabilities  TEXT NOT NULL CHECK (json_valid(capabilities)),
    fingerprint   TEXT NOT NULL CHECK (length(fingerprint) = 64),
    status        TEXT NOT NULL CHECK (status IN (
                      'pending', 'granted', 'denied', 'expired', 'consumed')),
    requested_at  TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    decided_by    TEXT,
    reason        TEXT,
    updated_at    TEXT NOT NULL
) STRICT;

CREATE INDEX approvals_open ON approvals (status) WHERE status IN ('pending', 'granted');

CREATE TRIGGER approvals_identity_immutable
BEFORE UPDATE OF approval_id, task_id, session_id, request_id, tool, capabilities,
                 fingerprint, requested_at, expires_at, expires_at_ms ON approvals
BEGIN
    SELECT RAISE(ABORT, 'approval identity is immutable');
END;

CREATE TRIGGER approvals_terminal_immutable
BEFORE UPDATE ON approvals
WHEN OLD.status IN ('denied', 'expired', 'consumed')
BEGIN
    SELECT RAISE(ABORT, 'decided approvals are immutable');
END;

CREATE TRIGGER approvals_transition
BEFORE UPDATE OF status ON approvals
WHEN NOT (
    (OLD.status = 'pending' AND NEW.status IN ('granted', 'denied', 'expired'))
    OR (OLD.status = 'granted' AND NEW.status IN ('consumed', 'expired'))
)
BEGIN
    SELECT RAISE(ABORT, 'illegal approval transition');
END;

CREATE TRIGGER approvals_no_delete
BEFORE DELETE ON approvals
BEGIN
    SELECT RAISE(ABORT, 'approvals are never deleted');
END;
