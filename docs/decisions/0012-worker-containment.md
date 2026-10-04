# 0012. OS containment of the worker, without claiming a sandbox

**Status:** Accepted; superseded in part by [0013](0013-windows-appcontainer.md) (Windows) and [0014](0014-linux-landlock-seccomp.md) (Linux), which replace the low-integrity token with an AppContainer and add Landlock and seccomp. The process-lifetime controls described here remain.

## Context

The protocol stops a worker from bypassing policy through the Core, but a compromised worker could call the operating system directly with the user's rights. Phase 2 adds the containment that the OS offers without extra privileges or services, and states what remains.

## Decision

Containment lives in one crate, `jarvis-sandbox`, the only crate allowed to contain `unsafe` code; each block states why it is sound. It is applied before the worker runs any code, and if any step fails the worker is killed and the start fails.

**Windows.** The worker is created suspended and without a console. A job object is created with kill-on-close, an active-process limit of one (no child processes), a per-process memory limit and die-on-unhandled-exception, without breakaway. UI restrictions (clipboard, desktop, global atoms and so on) are added unless the worker is already inside another job, where Windows does not allow them. The worker is assigned to the job, its primary token is lowered to Low integrity and every privilege except change-notify is removed, the integrity level is read back, and only then is the thread resumed. Low integrity stops the worker writing to the user's files, registry keys and the Core's named pipe.

**Linux.** The worker gets its own process group (so the whole tree can be killed at once), `PR_SET_PDEATHSIG` (it dies with the Core), `PR_SET_NO_NEW_PRIVS`, an address-space limit and no core dumps.

**Both.** No shell and an environment cleared apart from `PATH` and `SYSTEMROOT`. The Core opens its own files, sockets and pipes as non-inheritable. On Unix every other descriptor, including any the Core itself inherited from whatever started it, is marked close-on-exec in the child before exec, so only the three stdio pipes reach the worker; a test checks this on Linux. On Windows a handle the Core inherited as inheritable would pass on; the Windows validation guide checks the worker's handles.

## Consequences

- This is not a sandbox. On both platforms the worker can still read any file the user can read and open network connections. On Linux it can also write the user's files, and it can start processes (which stay in its process group unless they leave it).
- Some properties can only be checked on a real Windows desktop session: UI restrictions, the behaviour of the low-integrity token against the user's profile, and handle inheritance. `docs/windows-validation.md` lists them, marked **LOCAL WINDOWS VERIFICATION REQUIRED**. CI checks the rest on Windows runners.
- A stronger boundary (a separate account, AppContainer on Windows, namespaces with Landlock and seccomp on Linux) is the next step, and needs its own decision.
