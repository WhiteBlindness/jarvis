# 0013. Isolate the Windows worker with an AppContainer

**Status:** Accepted

## Context

Phase 2 contained the worker with a job object and a low-integrity token (ADR 0012). That stops the worker writing to the user's files and opening the Core's pipe, but it does **not** stop the worker *reading* the user's profile, and it does **not** stop the worker opening network connections. A compromised or hallucinating worker could still read `C:\Users\<user>\Documents`, exfiltrate over the network, or call a model API directly. Phase 3's objective is to make the Rust Core the meaningful broker of authority, so that a worker calling `open`, `socket` or the Windows API directly is denied by the operating system.

Windows is the real deployment target, so it gets the stronger boundary. The options evaluated against authoritative Microsoft documentation were: restricted token + low integrity (the Phase 2 baseline), AppContainer, less-privileged AppContainer (LPAC), a dedicated local account, and hybrids.

| Option | Profile reads | Network | No admin | CPython | Overhead |
| --- | --- | --- | --- | --- | --- |
| Restricted token + low IL (Phase 2) | open (MIC blocks writes only) | open | yes | fine | ~0 |
| **AppContainer** | denied by default | denied by default | yes | fine once the runtime is granted | very low |
| LPAC | stricter | denied by default | yes | registry/COM denied, needs tuning | very low |
| Dedicated account | strong | open without an admin firewall rule | needs admin + a stored password | fine | logon + profile |

An AppContainer process has a package SID and runs at low integrity. File access is a *dual check*: both the user's SID and the package SID must grant access, and legacy ACLs do not name the package SID, so the user's profile is unreadable by default. With no capabilities declared, the Windows Filtering Platform blocks all of its network traffic, including loopback. It needs no administrator rights, no second account and no password. It is the cleanest strong boundary, so it is preferred over a dedicated account (owner decision 2 allows an account only if it is *stronger*; it is not).

## Decision

On Windows the worker runs inside an AppContainer with **no capabilities**, created and torn down by the Core per run, with no administrator rights for normal use. All of the controls below are applied atomically in one `CreateProcessW` call (via `STARTUPINFOEXW` and a proc-thread attribute list), because `std`/`tokio` `Command` cannot carry an attribute list:

1. **Identity.** `CreateAppContainerProfile` (idempotent; `ERROR_ALREADY_EXISTS` is treated as success) and `DeriveAppContainerSidFromAppContainerName` give a stable per-user package SID. `SECURITY_CAPABILITIES` with that SID and zero capabilities is passed as `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`.
2. **Filesystem.** The worker gets read+execute on the Python runtime directory and the worker package, and read+write on a per-run workspace and temp directory, granted to the package SID with inheritable ACEs (`SetEntriesInAclW` + `SetNamedSecurityInfoW`). `TEMP`/`TMP` point at the granted temp directory. Nothing else is granted, so the user's profile is unreadable (ADR 0015 covers the filesystem model for both platforms).
3. **Network.** Zero capabilities means the Filtering Platform denies all traffic, loopback included. This is not left to trust: the worker runs a startup self-test against a Core-held loopback listener and a DNS lookup, and **fails closed** if either succeeds (the firewall service could be off; see residual risk).
4. **Child processes.** `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`, backed by a job object (`JOB_LIST` attribute, atomic at creation) with an active-process limit of one, no breakaway, a commit limit, and kill-on-close.
5. **Handles.** `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` names only the three stdio pipe ends; `bInheritHandles = TRUE` with everything else non-inheritable, so no stray handle reaches the worker.
6. **Mitigations.** `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` enables extension-point disable, no-remote image loads, no-low-label image loads, font disable, heap-terminate and ASLR. `BLOCK_NON_MICROSOFT_BINARIES` is **never** set: CPython and its `.pyd` files are PSF-signed and it would break them.
7. **RPC.** The owner-only pipe DACL already excludes the package SID by the dual check; a `NO_READ_UP` mandatory label is added so a low-IL worker cannot even read Core process or pipe objects (ADR 0016).

The worker must be the base `python.exe`, not `py.exe` or a venv launcher, because those spawn a child process that the child-process policy would block.

## Consequences

- The worker cannot read the user's profile, cannot reach the network, cannot start a child process, and cannot open the Core's pipe or process, all enforced by the OS rather than by trust.
- The normal user notices nothing: no account, no password, no second session, no admin prompt during use. Creating the AppContainer profile and granting the runtime ACLs happen in-process at start-up as the ordinary user.
- The implementation is substantial unsafe FFI in `jarvis-sandbox`, compiled only on Windows and exercised by adversarial probes on CI; some properties need a real desktop (ADR 0017, `docs/windows-validation.md`).
- An **optional** one-time administrator step can add a Windows Firewall rule keyed on the package SID as defence in depth for the network block. It is never required.

## Residual risk

- Network enforcement is the Filtering Platform's. If the Base Filtering Engine or the firewall service is disabled, the WFP block may not apply; the worker's fail-closed self-test is the compensating control, and the optional firewall rule is defence in depth.
- Whether a standard user can create an AppContainer profile, whether DNS resolution is possible with no capabilities, and whether loopback is fully blocked in every configuration are not all confirmable from documentation alone; the Windows validation guide lists them as **LOCAL WINDOWS VERIFICATION REQUIRED**, and the runtime self-test fails closed regardless.
- A kernel-level or Windows-API escape from an AppContainer is outside this project's threat model (ADR 0012 and the threat model say so).
- This is isolation of an untrusted local process, not a guarantee against all malicious code. The README and threat model avoid the word "sandbox" for properties the implementation does not provide.
