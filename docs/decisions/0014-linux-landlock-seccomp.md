# 0014. Isolate the Linux worker with Landlock and seccomp

**Status:** Accepted

## Context

Phase 2's Linux containment (ADR 0012) gave the worker its own process group, `PR_SET_PDEATHSIG`, `no_new_privs`, an address-space limit and stdio-only descriptors. It did not stop the worker reading the user's files, opening network connections, starting other programs or signalling other processes. Windows is the first-class platform and gets an AppContainer (ADR 0013); Linux is hardened as far as an unprivileged process can go, without root, a VM, a container runtime or new services (owner decisions 1 and 5).

Two kernel mechanisms cover the goals, and testing on the development kernel (6.18, Landlock ABI 7) confirmed that **both are needed**:

- **Landlock**, a stackable LSM that an unprivileged process can apply to itself under `no_new_privs`, enforces a default-deny filesystem boundary. Its network rules, where the kernel has them, cover TCP only, so UDP, raw, netlink and `AF_UNIX` sockets would leak through Landlock alone.
- **seccomp-bpf** closes the rest: no socket of any kind, no child processes, no signals to other processes, and no namespace, mount, tracing, module or metadata syscalls.

## Decision

On Linux the worker is confined with Landlock **and** seccomp, built in the parent and applied in the child between fork and exec. If either cannot be applied, the spawn fails; there is no silent fallback. Before the first worker starts, the Core proves the boundary with a probe (ADR 0013, "start-up proof"; it is the same on both platforms).

**Filesystem (Landlock).** The Core grants the least right each path needs:

- read and execute beneath the interpreter's directory, its install prefix, and the standard runtime roots that exist (`/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/opt`), so the interpreter, the dynamic loader, the C library and the standard library load;
- read beneath the worker's own source directory.

Nothing is writable. The worker needs no scratch space today (the protocol carries everything, and Python runs with bytecode writing disabled), so the user's home, `/tmp`, `/dev/shm`, `/etc`, `/proc`, `/run` and everything else are unreachable without being named. The ruleset is created in the parent (`landlock_create_ruleset`, `landlock_add_rule` with `O_PATH | O_CLOEXEC` descriptors); the child calls only `landlock_restrict_self`. The handled-rights mask follows the ABI the kernel reports, so the same binary works on older and newer kernels.

**Syscalls (seccomp).** A classic BPF program, built in the parent and installed by the child as its last step before exec, kills the process on a foreign architecture (and, on x86-64, the x32 ABI), then denies with `EPERM`:

- `socket`, `socketpair` and `io_uring_*`: no network of any kind, and the worker cannot even create the socket it would need to reach the Core's RPC endpoint;
- `fork`, `vfork`, and `clone` unless it creates a thread without new namespaces; `clone3` returns `ENOSYS` so the C library falls back to `clone`: no child processes;
- `kill`, `tkill`, `tgkill`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`, `pidfd_send_signal`: the kernel would otherwise let the worker signal, and so kill, every process of the user, the Core included;
- `ptrace`, `process_vm_readv`/`writev`, `process_madvise`, `process_mrelease`, `kcmp`, `pidfd_getfd`, `unshare`, `setns`, `mount`, `umount2`, `pivot_root`, `chroot`, `bpf`, `perf_event_open`, `userfaultfd`, `keyctl`, `add_key`, `request_key`, module and `kexec_load` syscalls, `open_by_handle_at`, `name_to_handle_at`, `memfd_create`;
- `chmod`/`fchmod`/`fchmodat`, `chown` family, `utime`/`utimes`/`utimensat` and the `setxattr`/`removexattr` family, which Landlock does not mediate.

`execve` is not denied: the filter is installed before the worker's own exec. Executing anything else is bounded by Landlock, which grants execute only beneath the runtime roots.

**Process controls kept from ADR 0012**, plus two additions: a Core running as root drops every capability (bounding, ambient, effective, permitted, inheritable) in the child before exec, and `RLIMIT_NPROC` is set to 1 as a backstop behind the seccomp process denial. For a non-root user that limit also prevents thread creation, because the kernel counts threads; the worker is single-threaded. Root is exempt from it, which is why the capability drop and seccomp matter more.

## Consequences

- A compromised Linux worker cannot read the user's files, write anywhere, open any network connection, start another program, signal or read another process, or reach the Core's socket. These are enforced by the kernel and covered by the probes in `crates/jarvis-sandbox/tests/contain.rs`, which CI runs on the GitHub Linux runner.
- Because it cannot create sockets, the worker is removed from the RPC attack surface structurally; the Core's peer check (ADR 0010) remains as a second layer.
- No root, no services, and no dependency beyond `libc`. It does not use namespaces and is not a container.
- A kernel without Landlock (or with it disabled at boot) makes the Core refuse to start a worker.
- Symmetry with Windows is not required: the platforms reach the same goals by different mechanisms.

## Residual risk

- The seccomp program is a denylist of dangerous groups, not an allowlist, so a syscall added to a future kernel is allowed until it is listed.
- Exec is bounded, not forbidden: the worker could execute another binary under a granted runtime root in place of itself (it cannot create a child process to do so alongside). Every such binary inherits the same Landlock domain and seccomp filter.
- Verified on x86-64 (the development kernel and the GitHub runner). `aarch64` uses the same design with its own syscall table and is compiled but not runtime-tested.
- A kernel vulnerability, or a local attacker already running as the same user, is out of scope (threat model).
