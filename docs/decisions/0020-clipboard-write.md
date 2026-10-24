# 0020. The first desktop operation: writing approved text to the clipboard

**Status:** Accepted. Makes `desktop.write_clipboard_text` performable through the Session Agent of ADR 0019. The other desktop operations of ADR 0017, including typing, stay closed; the reasons for typing are recorded below. Amended by ADR 0022: the request names the text by a payload and its SHA-256 instead of carrying it, so the text is no longer kept in the job or the task.

## Context

ADR 0019 built an authenticated path from a person's approval to one operation in the Session Agent, and proved it with a synthetic health check. The first operation with a real effect should be useful, have a small blast radius, and be one whose outcome the agent can tell apart from a refusal. Writing text to the clipboard meets all three: a person can paste a drafted text where they choose, the agent never reads anything back, and the Win32 calls separate "nothing changed" from "something may have changed". Any same-user process can already write the clipboard, so the operation adds no authority that the user's account lacks; what matters is that the worker can only ask for it, and only for text a person saw in full.

## Decision

**Opt-in, then per write.** `desktop.clipboard.write` is class B. The configuration may set it to `deny` (the default, and the example configuration) or `require_confirmation`, never `allow`. The other desktop capabilities can still only be `deny`. With the capability enabled, every write is a separate approval for one exact text.

**What a person sees.** The text is at most 1,024 characters and is decoded against an allowlist: newline, tab, space, printable ASCII, letters and digits of any script (by their Unicode properties) and common typographic punctuation. Everything else is refused, so it cannot hide content or change how the text reads: format characters (bidirectional controls, zero-width characters, tag characters), line and paragraph separators, variation selectors, private-use and unassigned characters, spaces other than U+0020, combining marks that are not letters, and the Hangul fillers. Because the text is that short, `approvals show` prints all of it, with newline, tab and backslash shown as `\n`, `\t` and `\\` so that two different texts never display the same, plus its length in characters and lines, size in bytes, SHA-256, the destination ("the clipboard") and the action in words. Letters from different scripts that look alike remain possible; they are visible, and the SHA-256 tells two texts apart. The approval's fingerprint covers the arguments, so the text shown is the text authorised. The largest permitted text, in its widest encoding, fits in one 16 KiB agent frame (a test checks this).

**What the agent writes.** Exactly the approved text as `CF_UNICODETEXT`: line ends stay `\n`, nothing is added or converted. It also sets the formats Windows reads to keep content out of clipboard history and cloud sync (`ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory = 0`, `CanUploadToCloudClipboard = 0`). The primitive lives in `jarvis-sandbox`, the only crate allowed `unsafe` code; it has no read function. Every allocation and the owner window (a message-only window) are prepared before the clipboard is opened.

**One attempt, three outcomes.**

| What happened | Agent outcome | Task | Error code | Event |
| --- | --- | --- | --- | --- |
| Written, and the reported UTF-16 length equals the approved text's | `done` | `completed` | none | `session_agent_completed` (length only) |
| `OpenClipboard` failed: another program holds it | `refused: clipboard_busy` | `failed` | `tool_failed` | `session_agent_refused` |
| Failed before the clipboard was opened, or no clipboard on this platform | `refused: clipboard_unavailable` | `failed` | `tool_failed` | `session_agent_refused` |
| `EmptyClipboard`, `SetClipboardData` or `CloseClipboard` failed | `faulted: clipboard_incomplete` | `failed` | `internal` | `session_agent_outcome_unknown` |
| A reported length that does not match, or any outcome of ADR 0019 that is unknown | none trusted | `failed` | `internal` | `session_agent_outcome_unknown` |
| The Core stopped after `perform` was sent, before an outcome was recorded | none | `interrupted` | `cancelled` | `session_agent_outcome_unknown`, written by start-up recovery |

The length check catches a reply for another operation or a framing fault; the agent computes it from the text it was sent, so it does not prove what the clipboard holds. The agent opens the clipboard once and never waits or retries; clipboard managers can make a write fail as busy, and the person then approves a fresh request. A fault is treated like any other unknown outcome: the agent is stopped, every grant is revoked, and the operation is never sent again. The worker receives a receipt naming the operation, or a fixed error, and never the text's fate beyond that. Its error code does tell it which of three things happened: the approval expired unused (the agent was not available), the operation was not performed (`tool_failed`, which includes a busy clipboard), or the outcome is unknown (`internal`). The `job`, `tasks` and `audit` commands show the person `COMPLETED`, `REFUSED (not performed)` or `OUTCOME UNKNOWN (may have happened; not retried)`. The interactive `approvals approve` asks for `yes` to approve, `no` to deny, or nothing to leave the request pending.

**Nothing is read.** No code path reads the clipboard: not the agent, not the Core, not the worker. The agent's report holds only a length. The tests that check what was written run in a separate window station, so they never touch the person's clipboard; the end-to-end demonstration reads it only through a disposable editor that pastes, as a person would.

## Typing into a window (`desktop.type_text`): not enabled

Typing needs a target the person picked. The design considered binds a picker session to a window handle, the owning process ID and its creation time, and an expiry; before each character it would re-check that the handle still names a live window of that process and that the window has the foreground. It stays disabled because of what cannot be checked without elevation:

- **The focus race.** Input from `SendInput` goes to whatever has focus when the system delivers it, not to the window that was checked. Another program, or the person, can change focus between the check and the delivery. Blocking input while typing (`BlockInput`) needs elevation. Checking between characters narrows the window but cannot close it, so text can land in a window nobody approved.
- **Silent drops.** User Interface Privilege Isolation discards input sent to a window of a higher integrity level, and `SendInput` does not say which characters were delivered. A partial delivery is an unknown outcome on every attempt to an elevated window.
- **Focus within the window.** Even with the right top-level window in front, the focused control inside it (a search box, an address bar, a chat field that sends on input) is not something a picker can bind.

`desktop.type_text` therefore keeps no agent operation, its capability can only be `deny`, and the Core refuses it before a grant could exist. Copying approved text and letting the person paste it where they choose covers the same need without any of these races.

## Consequences

- A person can approve one genuinely useful desktop action: placing a drafted text on the clipboard, seen in full first, written once, with a recorded outcome that is completed, refused or unknown.
- The approval and grant path of ADR 0019 is unchanged: a consumed approval backs one grant, used once, on a channel only the Core holds.
- The audit report type is now a per-operation enum (`op` tag); the worker protocol gains no new message type.

The allowlist also refuses some ordinary text, such as emoji and accents written as a separate combining mark. That is deliberate: what cannot be shown exactly is not written.

## Not claimed

- Same-user processes at medium integrity remain trusted. One can write the clipboard itself, read it, replace it straight after the agent writes it, or replace the agent's executable before the Core opens it (see the threat model). The Core resolves links in the executable's path, holds the file open without write or delete sharing while it hashes and starts it, and records the SHA-256 in `session_agent_started`; there is no trusted value to compare it with.
- Clipboard history and cloud sync honour the exclusion formats in current Windows releases; other clipboard managers may ignore them.
- Only Windows has a clipboard implementation. On Linux the agent refuses the write as unavailable.
- There is no GitHub Actions run of this operation; the real-clipboard path is demonstrated on a desktop only.
