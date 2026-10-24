//! Approval support: the fingerprint that binds an approval to a request,
//! the display-safe description a person decides on, and the in-memory
//! signal that wakes a waiting session.
//!
//! The database is the source of truth for every decision. The broker only
//! says "look again"; a session always re-reads the approval before acting.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use jarvis_protocol::{
    ApprovalId, ApprovalView, Capability, ClipboardText, Fingerprint, JobId, RequestId, TaskId,
    ToolCall, WriteClipboardTextArgs,
};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use crate::store::{ApprovalRecord, Store, format_ms, text_sha256};

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

/// What the Core finds when it resolves the text a clipboard request names
/// (ADR 0022).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The payload exists, belongs to the request's job and still has the
    /// SHA-256 the request binds.
    Text(ClipboardText),
    /// There is no such payload for this job: its job ended and it was
    /// deleted, or the request names one that never existed.
    Missing,
    /// The stored text no longer has the SHA-256 the request binds.
    Changed,
}

/// Resolve the payload a clipboard request names, for the request of
/// `job_id`. Never trusts the stored text: it must hash to the value the
/// request carries. A payload of another job counts as missing. A storage
/// failure also counts as missing, so a request is refused, never run on a
/// guess.
pub fn resolve_payload(
    store: &Store,
    args: &WriteClipboardTextArgs,
    job_id: Option<JobId>,
) -> Resolution {
    match store.payload(args.payload_id) {
        Ok(Some(payload)) if Some(payload.job_id) == job_id => {
            if !payload.is_intact(&args.sha256) {
                return Resolution::Changed;
            }
            // Intact text that is not valid clipboard text was not stored by
            // this Core either.
            ClipboardText::try_from(payload.text).map_or(Resolution::Changed, Resolution::Text)
        }
        Ok(_) => Resolution::Missing,
        Err(error) => {
            tracing::error!(%error, "cannot read a clipboard payload");
            Resolution::Missing
        }
    }
}

/// What a person needs to see to decide on a call, with every value made
/// safe to print: control characters escaped and long text shortened. Every
/// Session Agent operation states its action in words, so a person never
/// decides on a fingerprint alone; text that may be cut in the preview also
/// carries its size and SHA-256, which the fingerprint binds. A clipboard
/// write shows the text in full while its payload exists (`clipboard`), and
/// otherwise says that it does not.
pub fn describe(call: &ToolCall, clipboard: Option<&Resolution>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    match call {
        ToolCall::SessionAgentHealthcheck(args) => {
            out.insert(
                "action".into(),
                "Run the Session Agent's health check. It reads nothing from the desktop.".into(),
            );
            out.insert("label".into(), display_safe(args.label.as_str(), 64));
        }
        ToolCall::CaptureWindow(args) => {
            out.insert(
                "action".into(),
                "Capture one image of one window (not available yet).".into(),
            );
            out.insert("target".into(), args.target.to_string());
        }
        ToolCall::ReadClipboardText(_) => {
            out.insert(
                "action".into(),
                "Read the text on the clipboard (not available yet).".into(),
            );
        }
        ToolCall::WriteClipboardText(args) => {
            out.insert(
                "action".into(),
                "Replace the clipboard's content with exactly this text. Nothing is read from \
                 the clipboard; any program can paste it."
                    .into(),
            );
            out.insert("destination".into(), "the clipboard".into());
            match clipboard {
                Some(Resolution::Text(text)) => {
                    // Short enough to show in full: the person approves every
                    // character, with line ends and tabs made visible.
                    let text = text.as_str();
                    out.insert("text".into(), display_safe(text, usize::MAX));
                    out.insert("characters".into(), text.chars().count().to_string());
                    out.insert("lines".into(), text.split('\n').count().to_string());
                    describe_text(&mut out, text);
                    out.remove("preview");
                    // The salted value the request binds, as shown once the
                    // text is gone; the plain hash would outlive nothing.
                    out.insert("sha256".into(), args.sha256.as_str().to_owned());
                }
                Some(Resolution::Changed) => {
                    out.insert(
                        "text".into(),
                        "the stored text was changed after it was submitted; refuse this request"
                            .into(),
                    );
                    out.insert("sha256".into(), args.sha256.as_str().to_owned());
                }
                Some(Resolution::Missing) | None => {
                    out.insert("text".into(), "the text is no longer kept".into());
                    out.insert("sha256".into(), args.sha256.as_str().to_owned());
                }
            }
        }
        ToolCall::TypeText(args) => {
            out.insert(
                "action".into(),
                "Type text into one window (not available yet).".into(),
            );
            out.insert("target".into(), args.target.to_string());
            describe_text(&mut out, args.text.as_str());
        }
        ToolCall::SystemInfo(_) => {}
        ToolCall::ReadFixture(args) => {
            out.insert("path".into(), display_safe(args.path.as_str(), 255));
        }
        ToolCall::WriteFile(args) => {
            out.insert("path".into(), display_safe(args.path.as_str(), 255));
            describe_text(&mut out, &args.content);
        }
    }
    out
}

/// Size, SHA-256 and a display-safe preview of text a call would write or
/// type.
fn describe_text(out: &mut BTreeMap<String, String>, text: &str) {
    out.insert("bytes".into(), text.len().to_string());
    out.insert("sha256".into(), text_sha256(text).as_str().to_owned());
    out.insert("preview".into(), display_safe(text, 160));
}

/// Escape control characters and backslashes and cut to `max_chars`,
/// marking the cut. A backslash is shown as `\\`, so a newline (`\n`) and a
/// backslash followed by `n` (`\\n`) never look the same.
pub fn display_safe(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (count, c) in text.chars().enumerate() {
        if count == max_chars {
            out.push('…');
            break;
        }
        if c.is_control() || c == '\\' {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// The view a client gets of a stored approval. A clipboard write resolves
/// its payload through `store`.
pub fn view(record: &ApprovalRecord, now_ms: i64, store: &Store) -> ApprovalView {
    let arguments = serde_json::from_str(&record.args)
        .ok()
        .and_then(|args| ToolCall::from_request(&record.tool, &args).ok())
        .map(|call| {
            let clipboard = match &call {
                ToolCall::WriteClipboardText(args) => {
                    Some(resolve_payload(store, args, record.job_id))
                }
                _ => None,
            };
            describe(&call, clipboard.as_ref())
        })
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

    use crate::store::Store;

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
        let described = describe(&write("a.txt", "line one\n\u{1b}[2Jline two"), None);
        let preview = &described["preview"];
        assert!(!preview.chars().any(char::is_control), "{preview}");
        assert!(preview.contains("\\n"));
        assert_eq!(described["bytes"], "21");
        assert_eq!(described["sha256"].len(), 64);
        let long = describe(&write("a.txt", &"x".repeat(500)), None);
        assert!(long["preview"].ends_with('…'));
        assert_eq!(long["preview"].chars().count(), 161);
    }

    #[test]
    fn a_person_never_decides_on_a_hash_alone() {
        for call in crate::policy::tests::one_of_each() {
            let clipboard = found("hello");
            let described = describe(&call, Some(&clipboard));
            if call.is_agent_operation() {
                let action = described.get("action").expect("an action in words");
                assert!(!action.is_empty());
            }
            for value in described.values() {
                assert!(!value.chars().any(char::is_control), "{value}");
            }
            match &call {
                ToolCall::CaptureWindow(_) | ToolCall::TypeText(_) => {
                    assert_eq!(described["target"], "window #7");
                }
                ToolCall::SessionAgentHealthcheck(_) => assert_eq!(described["label"], "ping"),
                _ => {}
            }
            if let ToolCall::WriteClipboardText(_) = call {
                assert_eq!(described["text"], "hello");
                assert_eq!(described["characters"], "5");
                assert_eq!(described["destination"], "the clipboard");
                assert!(!described.contains_key("preview"));
            }
            if let ToolCall::TypeText(_) = call {
                assert_eq!(described["preview"], "hello");
            }
            if let ToolCall::TypeText(_) | ToolCall::WriteClipboardText(_) = call {
                assert_eq!(described["bytes"], "5");
                assert_eq!(described["sha256"].len(), 64);
            }
        }
    }

    #[test]
    fn different_texts_never_display_the_same() {
        // A real newline and a backslash followed by `n`.
        assert_eq!(display_safe("a\nb", 10), "a\\nb");
        assert_eq!(display_safe("a\\nb", 10), "a\\\\nb");
        assert_eq!(display_safe("a\tb", 10), "a\\tb");
        assert_eq!(display_safe("a\\tb", 10), "a\\\\tb");
        let call = ToolCall::WriteClipboardText(clipboard_args());
        let show = |text: &str| describe(&call, Some(&found(text)));
        let newline = show("ls\nrm -rf ~");
        let literal = show("ls\\nrm -rf ~");
        assert_ne!(newline["text"], literal["text"]);
        assert_eq!(newline["lines"], "2");
        assert_eq!(literal["lines"], "1");
    }

    fn found(text: &str) -> Resolution {
        Resolution::Text(ClipboardText::try_from(text.to_owned()).unwrap())
    }

    fn clipboard_args() -> WriteClipboardTextArgs {
        WriteClipboardTextArgs {
            payload_id: jarvis_protocol::PayloadId::new(),
            sha256: text_sha256("hello"),
        }
    }

    #[test]
    fn a_clipboard_request_without_its_text_says_so_and_shows_the_hash() {
        let args = clipboard_args();
        let call = ToolCall::WriteClipboardText(args.clone());
        for gone in [None, Some(&Resolution::Missing)] {
            let described = describe(&call, gone);
            assert_eq!(described["text"], "the text is no longer kept");
            assert_eq!(described["sha256"], args.sha256.as_str());
            assert_eq!(described["destination"], "the clipboard");
            assert!(!described.contains_key("characters"));
        }
        let changed = describe(&call, Some(&Resolution::Changed));
        assert!(changed["text"].contains("changed"), "{changed:?}");
        assert!(changed["text"].contains("refuse"), "{changed:?}");
        assert_eq!(changed["sha256"], args.sha256.as_str());
    }

    #[test]
    fn a_payload_resolves_only_for_its_own_job_and_only_if_intact() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("jarvis.db")).unwrap();
        let text = jarvis_protocol::ClipboardText::try_from("hello".to_owned()).unwrap();
        let job = store.submit_clipboard_job(&text, "client").unwrap();
        let rest = job.goal.as_str().strip_prefix("copy payload:").unwrap();
        let (id, sha256) = rest.split_once(':').unwrap();
        let args = WriteClipboardTextArgs {
            payload_id: id.parse().unwrap(),
            sha256: sha256.parse().unwrap(),
        };
        let resolve = |args: &WriteClipboardTextArgs, job| resolve_payload(&store, args, job);

        assert_eq!(resolve(&args, Some(job.job_id)), found("hello"));
        // Another job, or none, never gets the text.
        assert_eq!(resolve(&args, Some(JobId::new())), Resolution::Missing);
        assert_eq!(resolve(&args, None), Resolution::Missing);
        // A request that binds other text is not this payload.
        let other = WriteClipboardTextArgs {
            sha256: text_sha256("other"),
            ..args.clone()
        };
        assert_eq!(resolve(&other, Some(job.job_id)), Resolution::Changed);
        // A payload that never existed.
        let unknown = WriteClipboardTextArgs {
            payload_id: jarvis_protocol::PayloadId::new(),
            ..args.clone()
        };
        assert_eq!(resolve(&unknown, Some(job.job_id)), Resolution::Missing);
    }

    #[test]
    fn an_approval_written_before_payloads_stays_viewable() {
        // Rows from before ADR 0022 hold the clipboard text itself in the
        // task's arguments. They are not rewritten and not hidden: the view
        // shows them as stored.
        use crate::store::{NewApproval, NewTask, TaskChange, now_ms};
        use jarvis_protocol::{ApprovalId, PolicyDecision, SessionId, TaskStatus, ToolName};

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("jarvis.db")).unwrap();
        let session = SessionId::new();
        let task = NewTask {
            task_id: TaskId::new(),
            session_id: session,
            job_id: None,
            step: None,
            request_id: request("old"),
            tool: ToolName::try_from("desktop.write_clipboard_text".to_owned()).unwrap(),
            args: serde_json::json!({"text": "text kept by an older Core"}),
        };
        store.create_task(&task).unwrap();
        let new = NewApproval {
            approval_id: ApprovalId::new(),
            task_id: task.task_id,
            session_id: session,
            request_id: task.request_id.clone(),
            tool: task.tool.clone(),
            capabilities: vec![Capability::DesktopClipboardWrite],
            fingerprint: text_sha256("older fingerprint"),
            expires_at_ms: now_ms() + 60_000,
        };
        let change = TaskChange {
            decision: Some(PolicyDecision::RequireConfirmation),
            capabilities: Some(vec![Capability::DesktopClipboardWrite]),
            ..TaskChange::to(TaskStatus::AwaitingConfirmation)
        };
        let record = store.request_approval(&new, &change, &[]).unwrap();

        let shown = view(&record, now_ms(), &store);
        assert!(
            shown.arguments["raw"].contains("text kept by an older Core"),
            "{shown:?}"
        );
        assert_eq!(shown.tool.as_str(), "desktop.write_clipboard_text");
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
