# 0013. Isolate the Windows worker in an AppContainer, and prove it at start-up

**Status:** Accepted

## Context

Phase 2 contained the worker with a job object and a low-integrity token (ADR 0012). Low integrity stops the worker writing the user's files and opening the Core's pipe, but it does **not** stop the worker reading the user's profile, and it does **not** stop network access. A compromised worker could read `Documents`, send it anywhere, or call a model API directly. Phase 3 makes the Rust Core the only broker of authority: a worker that calls `open`, `socket` or the Windows API directly must be refused by the operating system.

Windows is the real deployment target, so it gets the strongest boundary that needs no administrator rights for normal use, no second account and no visible session (owner decisions 1 and 2). The options evaluated:

| Option | Profile reads | Network | Admin needed | Second identity | Overhead |
| --- | --- | --- | --- | --- | --- |
| Restricted token + low integrity (Phase 2) | allowed (integrity checks block writes only) | allowed | no | no | ~0 |
| **AppContainer, no capabilities** | denied unless granted | denied, loopback included | no | no (a package SID, not an account) | very low |
| Less-privileged AppContainer (LPAC) | stricter | denied | no | no | very low; registry, COM and some system files need extra grants |
| Dedicated local account | denied by ACLs | allowed unless an administrator adds firewall rules | yes, plus a stored password | yes | logon session and profile |

An AppContainer process carries a package SID and runs at low integrity. Every file access is checked twice, once for the user and once for the package SID, and ordinary ACLs never name the package SID, so the user's profile is unreadable by default. With no capabilities, the Windows Filtering Platform blocks all of its network traffic, including loopback. It is the strongest option that keeps normal use free of administrator rights and of a second identity to manage, so it is preferred over a dedicated account, which would be weaker on the network without administrator help and heavier to run. LPAC would be stricter still, but needs per-machine tuning that CI cannot validate; it is a candidate for later.

## Decision

On Windows the worker runs in an AppContainer with **no capabilities**. `std` and Tokio cannot pass a process-thread attribute list, so `jarvis-sandbox` creates the process itself, with every control in one `CreateProcessW` call (`STARTUPINFOEXW` with a proc-thread attribute list):

1. **Identity.** `CreateAppContainerProfile("JARVIS.Worker")`, per user, as the user; an existing profile is reused (`DeriveAppContainerSidFromAppContainerName`). `SECURITY_CAPABILITIES` with that package SID and zero capabilities.
2. **Filesystem.** The package SID is granted read and execute on the interpreter's directory and read on the worker's source directory, as inherited entries (`SetEntriesInAclW`, `SetNamedSecurityInfoW`). A path that already grants it, or grants "ALL APPLICATION PACKAGES" (a Python under `Program Files`), is not touched, so later starts change nothing. No grant may be a drive root or contain the user's profile, the database directory or the workspace. Windows gives an AppContainer full control of its own folder (`%LOCALAPPDATA%\Packages\<name>\AC`, where `TEMP` points) through a critical access entry, which no deny entry can override; this is the one place the worker can write. The Core empties that folder before every start (links and junctions are removed, never followed), so nothing one worker writes reaches the next. Windows system directories stay readable because they grant "ALL APPLICATION PACKAGES".
3. **Network.** Zero capabilities: the Filtering Platform drops all traffic. This is not taken on trust (see "Start-up proof").
4. **Child processes.** `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`, backed by the job's active-process limit of one.
5. **Job.** `PROC_THREAD_ATTRIBUTE_JOB_LIST` puts the worker in a job at creation: kill on job close, one active process, a commit limit, die on unhandled exception, no breakaway, and UI restrictions unless the Core itself runs inside a job (Windows refuses to nest a UI-restricted job).
6. **Handles.** `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` names only the three stdio pipe ends. The Core's ends are overlapped named-pipe servers whose DACL admits only the current user; the worker's ends are synchronous and inherited.
7. **Mitigations.** Heap terminate, bottom-up and high-entropy ASLR, extension points disabled, non-system fonts disabled, no images from remote shares or with a low integrity label. `BLOCK_NON_MICROSOFT_BINARIES` is never set (CPython is not Microsoft-signed), nor `PROHIBIT_DYNAMIC_CODE` (ctypes callbacks). `WIN32K_SYSTEM_CALL_DISABLE` and `STRICT_HANDLE_CHECKS` are not yet validated with CPython.
8. **Token check.** The process is created suspended. Before it runs, the Core confirms its token is an AppContainer token for exactly the package SID, with no capabilities, at low integrity, and that it is inside the job; removes every privilege except `SeChangeNotifyPrivilege`; and only then resumes it. Any failure terminates it.
9. **Environment.** The Core passes `PATH` and `SYSTEMROOT`. `CreateProcessW` also reads `LOCALAPPDATA`, `APPDATA`, `USERPROFILE`, `HOMEDRIVE` and `HOMEPATH` from the block to set up an AppContainer, and fails without them, so the launcher adds them from the Core's environment. They name directories the worker cannot open.

The worker must be a real `python.exe`. The `py` launcher and virtual-environment shims start a second process, which the child-process policy refuses.

**RPC.** The Core's pipe DACL names only the user, so the package SID fails the second access check and the worker cannot open it. The RPC server additionally refuses any client whose token is an AppContainer token or below medium integrity, and refuses clients it cannot inspect.

**Start-up proof (both platforms).** Before the first worker starts, the Core runs a probe under the identical isolation: same program, environment, working directory and confinement, with a short script instead of the worker. The Core checks from its own side that its loopback TCP listener accepted nothing, its loopback UDP socket received nothing, a file it wrote next to its database was not read (only a permission error counts), and no process could be started. If any check fails, or the probe cannot run, the Core records why and does not start. `jarvis-core isolation check` runs the same probe on demand.

## Consequences

- The worker cannot read the user's profile, write anywhere but its own AppContainer folder, reach the network, start a process, or open the Core's pipe or process, enforced by Windows and proved by the probes in `crates/jarvis-sandbox/tests/contain.rs` on CI.
- Nothing changes for the person using it: no account, password, second session, desktop switch or administrator prompt. The first start grants the interpreter's directory to the package SID; with a large Python installation that takes a few seconds once.
- What the Core changes on the machine is small and reversible: an AppContainer profile (a registry mapping and a folder under `%LOCALAPPDATA%\Packages`, emptied before every start) and access entries for the package SID on two directories. `jarvis-core isolation remove` undoes both.
- An **optional**, one-time administrator step (`scripts/windows/isolation.ps1 -Action Install`) adds Windows Firewall block rules keyed on the package SID as defence in depth and, with `-GrantPath`, grants an interpreter directory the user may not change (a Python installed for all users outside `Program Files`). It derives the package SID itself and never runs `jarvis-core.exe` elevated, so a binary in the user's checkout is never given administrator rights. It is never needed for normal use.

## Residual risk

- Network enforcement belongs to the Filtering Platform. If the Base Filtering Engine were stopped, the block might not apply; the start-up proof would then fail and the Core would not run a worker.
- The worker can write in its own AppContainer folder while it runs. It cannot read anything there but what it wrote itself, and the folder is emptied before the next start, but disk use is bounded only by free space. Two Cores of the same user share the AppContainer, so one Core's start empties the folder under the other's running worker.
- The worker learns the user's profile path (and so the user name) from the profile variables Windows requires. It cannot open those directories.
- Some properties need a real desktop session to observe (UI restrictions, behaviour under a standard, non-administrator account, and Windows editions other than the CI image); `docs/windows-validation.md` lists them as **LOCAL WINDOWS VERIFICATION REQUIRED**.
- The worker's three pipe ends are inheritable for the moment between their creation and the `CreateProcessW` that hands them over. Launches in one Core are serialised, and the Core starts no other process; code that called `CreateProcess` with inheritance in the same process during that moment could also receive them.
- `isolation remove` revokes the entries on the paths the current configuration grants. Entries made for an interpreter or source directory that has since been removed from the configuration stay until removed by hand (`icacls <dir> /remove:g *<package SID>`, or the script's `-GrantPath`).
- A kernel or Windows-component vulnerability that escapes an AppContainer is out of scope.
