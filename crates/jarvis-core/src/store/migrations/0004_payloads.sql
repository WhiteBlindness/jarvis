-- Clipboard payloads (ADR 0022): the text a person is asked to approve for
-- the clipboard. A working table like pending approvals, not evidence: a
-- payload belongs to one job and is deleted in the transaction that ends the
-- job. The immutable tables only ever hold the payload's identifier and the
-- SHA-256 of salt and text, never the text or the salt, so no trigger guards
-- this table.
CREATE TABLE payloads (
    payload_id TEXT PRIMARY KEY NOT NULL,
    job_id     TEXT NOT NULL UNIQUE REFERENCES jobs (job_id),
    sha256     TEXT NOT NULL CHECK (length(sha256) = 64),
    salt       BLOB NOT NULL CHECK (length(salt) = 16),
    text       TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;
