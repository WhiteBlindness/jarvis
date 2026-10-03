//! Approval support: the fingerprint that binds an approval to a request,
//! the display-safe description a person decides on, and the in-memory
//! signal that wakes a waiting session.
//!
//! The database is the source of truth for every decision. The broker only
//! says "look again"; a session always re-reads the approval before acting.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use jarvis_protocol::{
    ApprovalId, ApprovalView, Capability, Fingerprint, RequestId, TaskId, ToolCall,
};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use crate::store::{ApprovalRecord, format_ms};

/// SHA-256 over a canonical encoding of everything an approval authorises:
/// the task, the request, the tool, the normalised arguments and the
/// capabilities. Any difference in any of them gives a different value.
pub fn fingerprint(
    task_id: TaskId,
    request_id: &RequestId,
    call: &ToolCall,
    capabilities: &[Capability],
) -> Fingerprint {
    let mut capabilities = capabilities.to_vec();
    capabilities.sort();
    capabilities.dedup();
    // serde_json keeps object keys sorted, so this encoding is canonical.
    let canonical = serde_json::json!({
        "v": 1,
        "task_id": task_id,
        "request_id": request_id,
        "tool": call.tool_name(),
        "args": call.arguments(),
        "capabilities": capabilities,
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    Fingerprint::from_digest(&digest)
}

/// What a person needs to see to decide on a call, with every value made
/// safe to print: control characters escaped and long text shortened.
pub fn describe(call: &ToolCall) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    match call {
        ToolCall::SystemInfo(_) => {}
        ToolCall::ReadFixture(args) => {
            out.insert("path".into(), display_safe(args.path.as_str(), 255));
        }
        ToolCall::WriteFile(args) => {
            out.insert("path".into(), display_safe(args.path.as_str(), 255));
            out.insert("bytes".into(), args.content.len().to_string());
            let digest: [u8; 32] = Sha256::digest(args.content.as_bytes()).into();
            out.insert(
                "sha256".into(),
                Fingerprint::from_digest(&digest).as_str().to_owned(),
            );
            out.insert("preview".into(), display_safe(&args.content, 160));
        }
    }
    out
}

/// Escape control characters and cut to `max_chars`, marking the cut.
pub fn display_safe(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (count, c) in text.chars().enumerate() {
        if count == max_chars {
            out.push('…');
            break;
        }
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// The view a client gets of a stored approval.
pub fn view(record: &ApprovalRecord, now_ms: i64) -> ApprovalView {
    let arguments = serde_json::from_str(&record.args)
        .ok()
        .and_then(|args| ToolCall::from_request(&record.tool, &args).ok())
        .map(|call| describe(&call))
        .unwrap_or_else(|| BTreeMap::from([("raw".to_owned(), display_safe(&record.args, 160))]));
    ApprovalView {
        approval_id: record.approval_id,
        status: record.status,
        task_id: record.task_id,
        job_id: record.job_id,
        request_id: record.request_id.clone(),
        tool: record.tool.clone(),
        capabilities: record.capabilities.clone(),
        arguments,
        fingerprint: record.fingerprint.clone(),
        requested_at: record.requested_at.clone(),
        expires_at: format_ms(record.expires_at_ms),
        expires_in_ms: u64::try_from(record.expires_at_ms.saturating_sub(now_ms)).unwrap_or(0),
    }
}

/// Wakes the session that waits on an approval when a decision lands.
///
/// `Notify::notify_one` stores a permit when nobody is waiting yet, so a
/// decision that arrives between registration and the wait is not lost.
#[derive(Debug, Default)]
pub struct ApprovalBroker {
    waiters: Mutex<HashMap<ApprovalId, Arc<Notify>>>,
}

impl ApprovalBroker {
    pub fn register(&self, approval_id: ApprovalId) -> Arc<Notify> {
        let mut waiters = self
            .waiters
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        Arc::clone(waiters.entry(approval_id).or_default())
    }

    pub fn notify(&self, approval_id: ApprovalId) {
        let waiters = self
            .waiters
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(notify) = waiters.get(&approval_id) {
            notify.notify_one();
        }
    }

    pub fn remove(&self, approval_id: ApprovalId) {
        let mut waiters = self
            .waiters
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        waiters.remove(&approval_id);
    }
}

#[cfg(test)]
mod tests {
    use jarvis_protocol::{RelativePath, WriteFileArgs};

    use super::*;

    fn write(path: &str, content: &str) -> ToolCall {
        ToolCall::WriteFile(WriteFileArgs {
            path: RelativePath::try_from(path.to_owned()).unwrap(),
            content: content.to_owned(),
        })
    }

    fn request(id: &str) -> RequestId {
        RequestId::try_from(id.to_owned()).unwrap()
    }

    #[test]
    fn fingerprint_changes_with_anything_it_binds() {
        let task = TaskId::new();
        let caps = [Capability::WorkspaceWrite];
        let base = fingerprint(task, &request("r1"), &write("a.txt", "x"), &caps);
        assert_eq!(
            base,
            fingerprint(task, &request("r1"), &write("a.txt", "x"), &caps),
            "deterministic"
        );
        for other in [
            fingerprint(TaskId::new(), &request("r1"), &write("a.txt", "x"), &caps),
            fingerprint(task, &request("r2"), &write("a.txt", "x"), &caps),
            fingerprint(task, &request("r1"), &write("b.txt", "x"), &caps),
            fingerprint(task, &request("r1"), &write("a.txt", "y"), &caps),
            fingerprint(task, &request("r1"), &write("a.txt", "x"), &[]),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn capability_order_does_not_matter() {
        let task = TaskId::new();
        let call = write("a.txt", "x");
        assert_eq!(
            fingerprint(
                task,
                &request("r"),
                &call,
                &[Capability::SystemInfo, Capability::WorkspaceWrite]
            ),
            fingerprint(
                task,
                &request("r"),
                &call,
                &[Capability::WorkspaceWrite, Capability::SystemInfo]
            ),
        );
    }

    #[test]
    fn description_is_safe_to_print() {
        let described = describe(&write("a.txt", "line one\n\u{1b}[2Jline two"));
        let preview = &described["preview"];
        assert!(!preview.chars().any(char::is_control), "{preview}");
        assert!(preview.contains("\\n"));
        assert_eq!(described["bytes"], "21");
        assert_eq!(described["sha256"].len(), 64);
        let long = describe(&write("a.txt", &"x".repeat(500)));
        assert!(long["preview"].ends_with('…'));
        assert_eq!(long["preview"].chars().count(), 161);
    }

    #[tokio::test]
    async fn decision_before_the_wait_is_not_lost() {
        let broker = ApprovalBroker::default();
        let id = ApprovalId::new();
        let notify = broker.register(id);
        broker.notify(id);
        tokio::time::timeout(std::time::Duration::from_secs(1), notify.notified())
            .await
            .expect("stored permit");
        broker.remove(id);
        broker.notify(id);
    }
}
