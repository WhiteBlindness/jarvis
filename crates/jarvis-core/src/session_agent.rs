//! The Session Agent boundary: single-use grants in the Core ([`Grants`]),
//! the Core's link to the agent process ([`link`]) and the agent's own loop
//! ([`serve`]). See ADRs 0017 and 0019.
//!
//! A Session Agent operation is an ordinary typed tool call. Policy derives
//! its class B capability, a person approves the exact call, and the session
//! consumes the approval. Only then can a grant exist:
//!
//! ```text
//! consume_approval ─► Grants::issue(ConsumedApproval, call) ─► Grants::authorize
//!   ─► Authorization ─► SessionAgent::perform ─► agent ─► result to the Core
//! ```
//!
//! - [`Grants::issue`] takes the store's [`ConsumedApproval`] by move. Only the
//!   store makes one, once per approval, and it cannot be copied, so one
//!   approval backs at most one grant. Its fingerprint must be the
//!   fingerprint of this exact call ([`approval::fingerprint`]).
//! - [`Grants::authorize`] uses a grant up and returns an [`Authorization`],
//!   which nothing else can make. The link sends an operation only for one.
//! - Grants live in the Core's memory. They are named by their approval, so a
//!   grant from an earlier run names nothing after a restart, and the Core
//!   revokes every grant whenever the agent stops.
//! - Time is the link's monotonic clock in milliseconds. A clock reading
//!   earlier than one already seen is refused anyway.
//! - Of the desktop calls, only `desktop.write_clipboard_text` has an agent
//!   operation (ADR 0020). The others are typed and approvable but are
//!   refused before a grant is issued.

pub mod link;
pub mod serve;

use std::collections::BTreeMap;

use jarvis_protocol::{AgentOperation, ApprovalId, ClipboardText, MAX_GRANT_TTL_MS, ToolCall};

use crate::approval;
use crate::policy::required_capabilities;
use crate::store::ConsumedApproval;

pub use link::{Launched, Launcher, Performed, ProcessLauncher, SessionAgent};

/// Live grants the Core may hold at once (invariant 9: everything bounded).
pub const MAX_LIVE_GRANTS: usize = 16;

/// Grants remembered after they are used, revoked or expired, so that a late
/// check is refused with its real reason. Forgetting one cannot let its
/// approval back a second grant: the store consumes an approval at most once
/// and never deletes its row.
pub const MAX_TRACKED_GRANTS: usize = 256;

/// A grant's identity: the approval behind it. Approval IDs are unique and
/// never reused, including across restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GrantId(ApprovalId);

impl GrantId {
    pub fn approval_id(self) -> ApprovalId {
        self.0
    }
}

/// Permission for the Session Agent to perform one exact call once.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Grant {
    call: ToolCall,
    operation: AgentOperation,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

/// A grant that has just been used up for its exact call. Not `Clone`, and
/// made only by [`Grants::authorize`]: holding one is the only way to have an
/// operation sent to the agent.
#[derive(Debug)]
pub struct Authorization {
    grant: GrantId,
    operation: AgentOperation,
    expires_at_ms: u64,
}

impl Authorization {
    pub fn grant(&self) -> GrantId {
        self.grant
    }

    pub fn operation(&self) -> &AgentOperation {
        &self.operation
    }

    /// When the grant runs out, on the clock the grants were given.
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

/// Why a Session Agent operation was not authorised. Each one means nothing
/// was sent to the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("the call is not a Session Agent operation")]
    NotAnAgentOperation,
    #[error("this desktop operation is not available")]
    NotAvailable,
    #[error("the approval is not for this call")]
    NotApproved,
    #[error("no such grant")]
    UnknownGrant,
    #[error("the grant has expired")]
    Expired,
    #[error("the clock went back")]
    ClockWentBack,
    #[error("the grant was revoked")]
    Revoked,
    #[error("the grant was already used")]
    AlreadyUsed,
    #[error("the call is not the one that was approved")]
    ScopeMismatch,
    #[error("the grant lifetime is out of range")]
    InvalidLifetime,
    #[error("too many live grants")]
    TooManyGrants,
    #[error("that approval already backs a grant")]
    ApprovalReused,
    #[error("the Session Agent is not available")]
    Unavailable,
    #[error("the text of the request is no longer available or was changed")]
    PayloadUnavailable,
}

impl Refusal {
    /// A stable name for the audit log.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAnAgentOperation => "not_an_agent_operation",
            Self::NotAvailable => "not_available",
            Self::NotApproved => "not_approved",
            Self::UnknownGrant => "unknown_grant",
            Self::Expired => "expired",
            Self::ClockWentBack => "clock_went_back",
            Self::Revoked => "revoked",
            Self::AlreadyUsed => "already_used",
            Self::ScopeMismatch => "scope_mismatch",
            Self::InvalidLifetime => "invalid_lifetime",
            Self::TooManyGrants => "too_many_grants",
            Self::ApprovalReused => "approval_reused",
            Self::Unavailable => "unavailable",
            Self::PayloadUnavailable => "payload_unavailable",
        }
    }
}

/// The agent operation that performs `call`, if there is one. A clipboard
/// write names its text by payload (ADR 0022); `text` is that payload as the
/// Core resolved and verified it, and without it there is no operation.
pub fn operation_for(
    call: &ToolCall,
    text: Option<&ClipboardText>,
) -> Result<AgentOperation, Refusal> {
    match call {
        ToolCall::SessionAgentHealthcheck(args) => Ok(AgentOperation::Healthcheck {
            label: args.label.clone(),
        }),
        ToolCall::WriteClipboardText(_) => text
            .map(|text| AgentOperation::WriteClipboardText { text: text.clone() })
            .ok_or(Refusal::PayloadUnavailable),
        ToolCall::CaptureWindow(_) | ToolCall::ReadClipboardText(_) | ToolCall::TypeText(_) => {
            Err(Refusal::NotAvailable)
        }
        ToolCall::SystemInfo(_) | ToolCall::ReadFixture(_) | ToolCall::WriteFile(_) => {
            Err(Refusal::NotAnAgentOperation)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Live,
    Used,
    Revoked,
}

/// The grants one Core has issued. Held in memory only: like approvals
/// (ADR 0009), no grant survives a restart.
#[derive(Debug, Default)]
pub struct Grants {
    grants: BTreeMap<GrantId, (Grant, State)>,
    /// The latest time an issue or a check was given, even one that was then
    /// refused. It only rises.
    latest_ms: u64,
}

fn is_live(grant: &Grant, state: State, now_ms: u64) -> bool {
    state == State::Live && grant.expires_at_ms > now_ms
}

impl Grants {
    /// Refuse a reading earlier than any seen before; otherwise remember it.
    fn observe(&mut self, now_ms: u64) -> Result<(), Refusal> {
        if now_ms < self.latest_ms {
            return Err(Refusal::ClockWentBack);
        }
        self.latest_ms = now_ms;
        Ok(())
    }

    fn live(&self, now_ms: u64) -> usize {
        self.grants
            .values()
            .filter(|(grant, state)| is_live(grant, *state, now_ms))
            .count()
    }

    /// Whether a grant for `call` could be issued now. Checked before an
    /// approval is consumed, so that a refusal never uses one up.
    pub fn check(
        &self,
        call: &ToolCall,
        text: Option<&ClipboardText>,
        now_ms: u64,
    ) -> Result<(), Refusal> {
        operation_for(call, text)?;
        if now_ms < self.latest_ms {
            return Err(Refusal::ClockWentBack);
        }
        if self.live(now_ms) >= MAX_LIVE_GRANTS {
            return Err(Refusal::TooManyGrants);
        }
        Ok(())
    }

    /// Issue a grant for `call` from the approval `consumed`, which must be
    /// the approval of exactly this call.
    pub fn issue(
        &mut self,
        consumed: ConsumedApproval,
        call: &ToolCall,
        text: Option<&ClipboardText>,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<GrantId, Refusal> {
        if ttl_ms == 0 || ttl_ms > MAX_GRANT_TTL_MS {
            return Err(Refusal::InvalidLifetime);
        }
        self.observe(now_ms)?;
        let operation = operation_for(call, text)?;
        let expected = approval::fingerprint(
            consumed.task_id(),
            consumed.request_id(),
            call,
            &required_capabilities(call),
        );
        if consumed.fingerprint() != &expected {
            return Err(Refusal::NotApproved);
        }
        let id = GrantId(consumed.approval_id());
        if self.grants.contains_key(&id) {
            return Err(Refusal::ApprovalReused);
        }
        if self.live(now_ms) >= MAX_LIVE_GRANTS {
            return Err(Refusal::TooManyGrants);
        }
        // Forget the oldest finished grants beyond the bound.
        while self.grants.len() >= MAX_TRACKED_GRANTS {
            let oldest = self
                .grants
                .iter()
                .filter(|(_, (grant, state))| !is_live(grant, *state, now_ms))
                .min_by_key(|(_, (grant, _))| grant.issued_at_ms)
                .map(|(id, _)| *id);
            match oldest {
                Some(id) => self.grants.remove(&id),
                None => return Err(Refusal::TooManyGrants),
            };
        }
        let grant = Grant {
            call: call.clone(),
            operation,
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(ttl_ms),
        };
        self.grants.insert(id, (grant, State::Live));
        Ok(id)
    }

    /// Revoke one grant. Revoking an unknown, used or revoked grant changes
    /// nothing.
    pub fn revoke(&mut self, id: GrantId) {
        if let Some((_, state)) = self.grants.get_mut(&id)
            && *state == State::Live
        {
            *state = State::Revoked;
        }
    }

    /// Revoke every live grant: whenever the agent stops, and on shutdown.
    pub fn revoke_all(&mut self) {
        for (_, state) in self.grants.values_mut() {
            if *state == State::Live {
                *state = State::Revoked;
            }
        }
    }

    /// Use grant `id` up for exactly `call`, now. Only an authorised check
    /// changes the grant; a refused one leaves it as it was.
    pub fn authorize(
        &mut self,
        id: GrantId,
        call: &ToolCall,
        now_ms: u64,
    ) -> Result<Authorization, Refusal> {
        self.observe(now_ms)?;
        let Some((grant, state)) = self.grants.get_mut(&id) else {
            return Err(Refusal::UnknownGrant);
        };
        match *state {
            State::Used => return Err(Refusal::AlreadyUsed),
            State::Revoked => return Err(Refusal::Revoked),
            State::Live if now_ms >= grant.expires_at_ms => return Err(Refusal::Expired),
            State::Live if grant.call != *call => return Err(Refusal::ScopeMismatch),
            State::Live => {}
        }
        *state = State::Used;
        Ok(Authorization {
            grant: id,
            operation: grant.operation.clone(),
            expires_at_ms: grant.expires_at_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use jarvis_protocol::{
        AgentLabel, Capability, CaptureWindowArgs, ClipboardText, HealthcheckArgs, PayloadId,
        ReadClipboardTextArgs, RelativePath, RequestId, TaskId, TypeTextArgs, TypedText,
        WindowTarget, WriteClipboardTextArgs, WriteFileArgs,
    };

    use super::*;

    fn request_id() -> RequestId {
        RequestId::try_from("r1".to_owned()).unwrap()
    }

    fn check(label: &str) -> ToolCall {
        ToolCall::SessionAgentHealthcheck(HealthcheckArgs {
            label: AgentLabel::try_from(label.to_owned()).unwrap(),
        })
    }

    /// A consumed approval whose fingerprint is that of `call`, as the
    /// session computes it.
    fn consumed_for(call: &ToolCall) -> ConsumedApproval {
        let task = TaskId::new();
        let fingerprint =
            approval::fingerprint(task, &request_id(), call, &required_capabilities(call));
        ConsumedApproval::for_tests(ApprovalId::new(), task, request_id(), fingerprint, 0)
    }

    fn issue(grants: &mut Grants, call: &ToolCall, now_ms: u64) -> GrantId {
        grants
            .issue(consumed_for(call), call, None, now_ms, 5_000)
            .unwrap()
    }

    #[test]
    fn a_grant_needs_the_approval_of_this_exact_call() {
        let mut grants = Grants::default();
        // Approved: "a". Asked: "b".
        assert_eq!(
            grants.issue(consumed_for(&check("a")), &check("b"), None, 0, 5_000),
            Err(Refusal::NotApproved)
        );
        // An approval for a different tool is not consent either.
        let write = ToolCall::WriteFile(WriteFileArgs {
            path: RelativePath::try_from("notes.txt".to_owned()).unwrap(),
            content: "hi".to_owned(),
        });
        assert_eq!(
            grants.issue(consumed_for(&write), &check("a"), None, 0, 5_000),
            Err(Refusal::NotApproved)
        );
        // The capabilities are bound too.
        let task = TaskId::new();
        let fingerprint =
            approval::fingerprint(task, &request_id(), &check("a"), &[Capability::SystemInfo]);
        let other_caps =
            ConsumedApproval::for_tests(ApprovalId::new(), task, request_id(), fingerprint, 0);
        assert_eq!(
            grants.issue(other_caps, &check("a"), None, 0, 5_000),
            Err(Refusal::NotApproved)
        );
    }

    #[test]
    fn desktop_calls_get_no_grant() {
        let capture = ToolCall::CaptureWindow(CaptureWindowArgs {
            target: WindowTarget(1),
        });
        let read = ToolCall::ReadClipboardText(ReadClipboardTextArgs {});
        let typing = ToolCall::TypeText(TypeTextArgs {
            target: WindowTarget(1),
            text: TypedText::try_from("hi".to_owned()).unwrap(),
        });
        let mut grants = Grants::default();
        for call in [&capture, &read, &typing] {
            assert_eq!(grants.check(call, None, 0), Err(Refusal::NotAvailable));
            assert_eq!(
                grants.issue(consumed_for(call), call, None, 0, 5_000),
                Err(Refusal::NotAvailable)
            );
        }
        // Writing the clipboard has an operation, carrying the exact text the
        // Core resolved for the payload the request names (ADR 0022).
        let text = ClipboardText::try_from("hello\nworld".to_owned()).unwrap();
        let clipboard = ToolCall::WriteClipboardText(WriteClipboardTextArgs {
            payload_id: PayloadId::new(),
            sha256: crate::store::text_sha256(text.as_str()),
        });
        assert_eq!(grants.check(&clipboard, Some(&text), 0), Ok(()));
        let id = grants
            .issue(consumed_for(&clipboard), &clipboard, Some(&text), 0, 5_000)
            .unwrap();
        let authorization = grants.authorize(id, &clipboard, 1).unwrap();
        assert_eq!(
            authorization.operation(),
            &AgentOperation::WriteClipboardText { text: text.clone() }
        );
        let other = ToolCall::WriteClipboardText(WriteClipboardTextArgs {
            payload_id: PayloadId::new(),
            sha256: crate::store::text_sha256("hello world"),
        });
        let id = grants
            .issue(consumed_for(&clipboard), &clipboard, Some(&text), 2, 5_000)
            .unwrap();
        assert_eq!(
            grants.authorize(id, &other, 3).map(|_| ()),
            Err(Refusal::ScopeMismatch)
        );
        // Without a resolved text there is nothing to send: no check passes
        // and no grant is issued.
        assert_eq!(
            grants.check(&clipboard, None, 4),
            Err(Refusal::PayloadUnavailable)
        );
        assert_eq!(
            grants.issue(consumed_for(&clipboard), &clipboard, None, 4, 5_000),
            Err(Refusal::PayloadUnavailable)
        );
        let write = ToolCall::WriteFile(WriteFileArgs {
            path: RelativePath::try_from("a.txt".to_owned()).unwrap(),
            content: String::new(),
        });
        assert_eq!(
            grants.check(&write, None, 0),
            Err(Refusal::NotAnAgentOperation)
        );
    }

    #[test]
    fn a_grant_authorises_its_exact_call_once() {
        let mut grants = Grants::default();
        let id = issue(&mut grants, &check("a"), 1_000);
        let authorization = grants.authorize(id, &check("a"), 2_000).unwrap();
        assert_eq!(authorization.grant(), id);
        assert_eq!(authorization.expires_at_ms(), 6_000);
        assert_eq!(
            grants.authorize(id, &check("a"), 2_001).err(),
            Some(Refusal::AlreadyUsed)
        );
        grants.revoke(id);
        assert_eq!(
            grants.authorize(id, &check("a"), 2_002).err(),
            Some(Refusal::AlreadyUsed)
        );
    }

    #[test]
    fn one_approval_backs_one_grant() {
        let mut grants = Grants::default();
        let call = check("a");
        let consumed = consumed_for(&call);
        let (approval, task, fingerprint) = (
            consumed.approval_id(),
            consumed.task_id(),
            consumed.fingerprint().clone(),
        );
        grants.issue(consumed, &call, None, 0, 5_000).unwrap();
        // The store never makes a second one; this is the defence behind it.
        let twin = ConsumedApproval::for_tests(approval, task, request_id(), fingerprint, 0);
        assert_eq!(
            grants.issue(twin, &call, None, 0, 5_000),
            Err(Refusal::ApprovalReused)
        );
    }

    #[test]
    fn a_grant_id_from_an_earlier_run_names_nothing() {
        let mut before = Grants::default();
        let stale = issue(&mut before, &check("a"), 0);
        let mut after = Grants::default();
        issue(&mut after, &check("a"), 0);
        assert_eq!(
            after.authorize(stale, &check("a"), 1).err(),
            Some(Refusal::UnknownGrant)
        );
    }

    #[test]
    fn expired_revoked_and_mismatched_grants_are_refused() {
        let mut grants = Grants::default();
        let expired = issue(&mut grants, &check("a"), 1_000);
        assert_eq!(
            grants.authorize(expired, &check("a"), 6_000).err(),
            Some(Refusal::Expired)
        );
        let one = issue(&mut grants, &check("b"), 6_000);
        let two = issue(&mut grants, &check("c"), 6_000);
        grants.revoke(one);
        assert_eq!(
            grants.authorize(one, &check("b"), 6_001).err(),
            Some(Refusal::Revoked)
        );
        // A refused check leaves the grant live.
        assert_eq!(
            grants.authorize(two, &check("other"), 6_001).err(),
            Some(Refusal::ScopeMismatch)
        );
        grants.revoke_all();
        assert_eq!(
            grants.authorize(two, &check("c"), 6_002).err(),
            Some(Refusal::Revoked)
        );
    }

    #[test]
    fn the_clock_never_goes_back_and_a_jump_forward_only_ends_grants() {
        let mut grants = Grants::default();
        let id = issue(&mut grants, &check("a"), 10_000);
        // A refused check at 12 000 still records the time.
        assert_eq!(
            grants.authorize(id, &check("x"), 12_000).err(),
            Some(Refusal::ScopeMismatch)
        );
        assert_eq!(
            grants.authorize(id, &check("a"), 10_001).err(),
            Some(Refusal::ClockWentBack)
        );
        assert_eq!(
            grants.check(&check("b"), None, 10_001),
            Err(Refusal::ClockWentBack)
        );
        // A large jump forward expires the grant; it never extends it.
        let later = issue(&mut grants, &check("b"), 12_000);
        assert_eq!(
            grants
                .authorize(later, &check("b"), 12_000 + 3_600_000)
                .err(),
            Some(Refusal::Expired)
        );
    }

    #[test]
    fn grant_lifetimes_and_counts_are_bounded() {
        let mut grants = Grants::default();
        for ttl in [0, MAX_GRANT_TTL_MS + 1] {
            assert_eq!(
                grants.issue(consumed_for(&check("a")), &check("a"), None, 0, ttl),
                Err(Refusal::InvalidLifetime)
            );
        }
        for _ in 0..MAX_LIVE_GRANTS {
            issue(&mut grants, &check("a"), 0);
        }
        assert_eq!(
            grants.check(&check("a"), None, 0),
            Err(Refusal::TooManyGrants)
        );
        assert_eq!(
            grants.issue(consumed_for(&check("a")), &check("a"), None, 0, 5_000),
            Err(Refusal::TooManyGrants)
        );
        // Expired grants no longer count as live.
        assert!(grants.check(&check("a"), None, 5_000).is_ok());
        for i in 0..(MAX_TRACKED_GRANTS as u64 * 2) {
            let id = issue(&mut grants, &check("a"), 5_000 + i);
            grants.authorize(id, &check("a"), 5_000 + i).unwrap();
        }
        assert!(grants.grants.len() <= MAX_TRACKED_GRANTS);
    }

    #[test]
    fn concurrent_checks_of_one_grant_authorise_it_once() {
        use std::sync::{Arc, Mutex};
        let grants = Arc::new(Mutex::new(Grants::default()));
        let id = issue(&mut grants.lock().unwrap(), &check("a"), 0);
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let grants = Arc::clone(&grants);
                std::thread::spawn(move || grants.lock().unwrap().authorize(id, &check("a"), 1))
            })
            .collect();
        let granted = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(Result::is_ok)
            .count();
        assert_eq!(granted, 1);
    }
}
