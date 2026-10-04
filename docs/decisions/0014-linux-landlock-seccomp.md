# 0014. Harden the Linux worker with Landlock and seccomp

**Status:** Accepted

## Context

Phase 2's Linux containment (ADR 0012) gave the worker its own process group, `PR_SET_PDEATHSIG`, `no_new_privs`, an address-space limit and stdio-only descriptors. Like the Windows baseline, it did not stop the worker reading the user's files or opening the network. Windows is first-class and gets an AppContainer (ADR 0013); Linux is meaningfully hardened as best-effort, without requiring root and without a VM, a container runtime or new always-on services (owner decisions 1, 5, and 3G).

Two kernel mechanisms cover the goals, and lab testing on the development kernel (6.18, Landlock ABI 7) confirmed that **both are needed**:

- **Landlock** (a stackable LSM usable by an unprivileged process under `no_new_privs`) enforces a filesystem boundary: the worker can read and execute only its runtime, read its own source, and read/write its workspace and temp. Everything else, including `$HOME`, `/tmp`, `/etc` and other processes' `/proc/<pid>/environ`, is denied. Landlock also denies `ptrace` into another domain. But its network hooks on this kernel cover only TCP, so UDP, raw, netlink and `AF_UNIX` sockets leak through Landlock alone.
- **seccomp-bpf** closes the rest: it denies creating any socket at all (so there is no network of any kind, and the worker cannot even open the Core's Unix socket), denies creating child processes, denies the metadata syscalls Landlock cannot mediate (`chmod`, `chown`, `utime`, `setxattr`), and denies namespace, mount, `ptrace`, `process_vm_readv`, `io_uring_setup`, `bpf`, `memfd_create` and similar escape surfaces.

## Decision

On Linux the worker is confined with Landlock **and** seccomp, built in the parent and applied in the child between fork and exec. If either cannot be applied, the spawn fails (fail closed); there is no silent degrade.

**Filesystem (Landlock).** The Core grants, beneath each path, the least right the worker needs:

- read+execute beneath the interpreter's install prefix and the standard runtime roots that exist (`/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/opt`), so the interpreter, the dynamic loader, the C library and the standard library load;
- read beneath the worker's own source directory;
- read+write beneath the per-run workspace and temp directories.

Landlock is default-deny, so the user's home, `/tmp`, `/etc`, `/proc`, `/run` and everything else are unreadable without being named. The ruleset is built with `landlock_create_ruleset` + `landlock_add_rule` in the parent (path fds opened `O_PATH|O_CLOEXEC`), and the child calls only `landlock_restrict_self` — one syscall, async-signal-safe. The handled-rights mask is computed from the kernel's reported ABI so the call does not fail on older or newer kernels.

**Network, child processes, escape surface (seccomp).** A classic BPF filter, built in the parent and installed by the child with `seccomp(SECCOMP_SET_MODE_FILTER)` as its last step, checks the architecture and then denies, with `EPERM` (or `ENOSYS` for `clone3`, so glibc falls back cleanly):

- all socket creation and `io_uring_setup` — no network of any kind;
- `fork`, `vfork`, and `clone`/`clone3` except thread creation (`CLONE_THREAD` without namespace flags) — no child processes;
- `execve`/`execveat` are **not** denied (the filter is installed just before the final exec of the interpreter); exec of other programs is instead blocked by granting Landlock EXECUTE only on the interpreter and loader;
- namespace and mount syscalls, `chroot`, `ptrace`, `process_vm_readv`/`writev`, `kcmp`, `pidfd_getfd`, the `kill`/`tgkill` family, `bpf`, `perf_event_open`, `userfaultfd`, `keyctl`, module and kexec syscalls, `open_by_handle_at`, `memfd_create`/`memfd_secret`, and the file-metadata syscalls Landlock does not mediate.

`RLIMIT_NPROC` is lowered as a coarse backstop behind the seccomp child-process denial. The existing `PR_SET_PDEATHSIG`, `no_new_privs`, address-space and core-dump limits and the stdio-only descriptor sweep stay.

## Consequences

- A compromised Linux worker cannot read the user's files, open any network connection, start another program, read another process's memory or environment, or reach the Core's socket — enforced by the kernel. Because it has no sockets at all, the worker is structurally removed from the RPC attack surface (ADR 0016).
- Exec is bounded, not forbidden: the worker can still re-exec the interpreter, or have the loader run an ELF readable under a granted runtime root. This is accepted; the runtime roots hold no untrusted code and the worker cannot write there or fetch new code (no network).
- This needs no root, no new services and no new runtime dependency beyond `libc`. It is best-effort: it does not use namespaces and does not claim to be a container.
- Landlock's net hooks are not relied on for the network block (seccomp is), so the worker works the same on kernels without Landlock networking. A kernel without Landlock at all, or with it disabled at boot, makes the spawn fail closed.
- Symmetry with Windows is deliberately not required (owner decision 1): the two platforms reach the same security goals by different mechanisms.

## Residual risk

- Not all syscalls are denied (the filter is a denylist of dangerous groups, not an allowlist), so a future-added syscall defaults to allowed; the dangerous families above are covered explicitly.
- Behaviour was lab-verified on one kernel and architecture (x86_64, 6.18); other kernels and `aarch64` use the same syscall numbers and masks but are not runtime-verified here. CI exercises it on the GitHub Linux runner.
- A local attacker already running as the same user is out of scope, as before.
