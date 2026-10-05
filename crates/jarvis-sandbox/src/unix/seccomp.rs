//! A seccomp-bpf filter for the worker (Linux).
//!
//! Landlock gives the filesystem boundary; this filter closes what Landlock
//! on this kernel cannot: it denies creating any socket (so there is no
//! network of any kind, and the worker cannot open the Core's Unix socket),
//! denies creating child processes, denies every way of signalling or
//! changing another process that does not need a capability, denies System
//! V IPC and file watches, and denies a group of escape and metadata
//! syscalls. The program is assembled in the parent and installed by
//! the child with one `seccomp` syscall as its last pre-exec step, so only
//! the final `execve` of the interpreter runs afterwards. See ADR 0014.

use std::io;

use crate::Confinement;

// Classic BPF opcodes (stable kernel ABI).
const LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const JMP_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const JMP_JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
const ALU_AND_K: u16 = 0x54; // BPF_ALU | BPF_AND | BPF_K
const RET_K: u16 = 0x06; // BPF_RET | BPF_K

// seccomp_data field offsets (the low 32 bits of each argument on the
// little-endian architectures supported here).
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0_LOW: u32 = 16;
const OFF_ARG1_LOW: u32 = 24;

// Syscalls newer than the `libc` constants, numbered alike on x86-64 and
// aarch64 (the unified table that starts at 403).
const SYS_FCHMODAT2: libc::c_long = 452;
const SYS_SETXATTRAT: libc::c_long = 463;
const SYS_REMOVEXATTRAT: libc::c_long = 466;
const SYS_OPEN_TREE_ATTR: libc::c_long = 467;
const SYS_FILE_SETATTR: libc::c_long = 469;

// fcntl commands that set the owner who receives SIGIO/SIGURG, or the
// signal sent: with them a process could make the kernel signal any process
// of the same user.
const F_SETOWN: u32 = 8;
const F_SETSIG: u32 = 10;
const F_SETOWN_EX: u32 = 15;
// ioctl requests with the same effect, and the one that enables async I/O.
const FIOSETOWN: u32 = 0x8901;
const SIOCSPGRP: u32 = 0x8902;
const FIOASYNC: u32 = 0x5452;

// seccomp return actions.
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_ERRNO: u32 = 0x0005_0000;

#[cfg(target_arch = "x86_64")]
const NATIVE_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const NATIVE_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const NATIVE_ARCH: u32 = 0;

const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// clone(2) flags.
const CLONE_THREAD: u32 = 0x0001_0000;
/// Any flag that would create a new namespace.
const CLONE_NEW_NS: u32 = 0x0002_0000  // NEWNS
    | 0x0000_0080  // NEWTIME
    | 0x0200_0000  // NEWCGROUP
    | 0x0400_0000  // NEWUTS
    | 0x0800_0000  // NEWIPC
    | 0x1000_0000  // NEWUSER
    | 0x2000_0000  // NEWPID
    | 0x4000_0000; // NEWNET

fn errno(code: i32) -> u32 {
    RET_ERRNO | (code as u32 & 0x0000_ffff)
}

/// A built seccomp program, ready to install in the child.
#[derive(Debug, Clone)]
pub(crate) struct Filter {
    program: Vec<libc::sock_filter>,
}

impl Filter {
    pub(crate) fn build(confinement: &Confinement) -> Self {
        let mut p = Program::new();

        // Reject any architecture but the native one, then (x86_64) the x32
        // ABI, so a syscall number cannot be smuggled under a foreign table.
        p.stmt(LD_W_ABS, OFF_ARCH);
        p.jump(JMP_JEQ_K, NATIVE_ARCH, 1, 0);
        p.stmt(RET_K, RET_KILL_PROCESS);
        p.stmt(LD_W_ABS, OFF_NR);
        #[cfg(target_arch = "x86_64")]
        {
            p.jump(JMP_JGE_K, X32_SYSCALL_BIT, 0, 1);
            p.stmt(RET_K, RET_KILL_PROCESS);
        }
        #[cfg(not(target_arch = "x86_64"))]
        let _ = X32_SYSCALL_BIT;

        // A is the syscall number from here. Simple denials do not touch A.
        let eperm = errno(libc::EPERM);
        if confinement.deny_network {
            for nr in NETWORK {
                p.deny(*nr, eperm);
            }
        }
        if confinement.deny_child_processes {
            for nr in CHILD {
                p.deny(*nr, eperm);
            }
            // glibc falls back to clone when clone3 returns ENOSYS.
            p.deny(libc::SYS_clone3, errno(libc::ENOSYS));
        }
        for nr in ESCAPE {
            p.deny(*nr, eperm);
        }
        for nr in SIGNAL.iter().chain(OTHER_PROCESSES).chain(IPC).chain(WATCH) {
            p.deny(*nr, eperm);
        }
        for nr in METADATA {
            p.deny(*nr, eperm);
        }

        // Argument checks clobber A and restore it, so they come after the
        // plain denials. Signal ownership through fcntl and ioctl:
        p.deny_if_arg(
            libc::SYS_fcntl,
            OFF_ARG1_LOW,
            &[F_SETOWN, F_SETSIG, F_SETOWN_EX],
            eperm,
        );
        p.deny_if_arg(
            libc::SYS_ioctl,
            OFF_ARG1_LOW,
            &[FIOSETOWN, SIOCSPGRP, FIOASYNC],
            eperm,
        );
        // Resource limits of any process but itself (the C library reads
        // its own with pid 0).
        p.deny_unless_arg_zero(libc::SYS_prlimit64, OFF_ARG0_LOW, eperm);

        // clone is allowed only to create a thread (no new process, no new
        // namespace); this clobbers A, so it comes last.
        if confinement.deny_child_processes {
            p.clone_thread_only(eperm);
        }

        p.stmt(RET_K, RET_ALLOW);
        Self { program: p.0 }
    }

    /// Install the filter on the calling (child) process. One syscall.
    pub(crate) fn install(&self) -> io::Result<()> {
        let prog = libc::sock_fprog {
            len: self.program.len() as u16,
            filter: self.program.as_ptr().cast_mut(),
        };
        // SAFETY: a well-formed classic-BPF program of `len` instructions;
        // SET_MODE_FILTER only narrows this thread's syscall access and needs
        // the no_new_privs bit, which the caller set earlier.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0,
                &prog as *const libc::sock_fprog,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

struct Program(Vec<libc::sock_filter>);

impl Program {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn stmt(&mut self, code: u16, k: u32) {
        self.0.push(libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        });
    }

    fn jump(&mut self, code: u16, k: u32, jt: u8, jf: u8) {
        self.0.push(libc::sock_filter { code, jt, jf, k });
    }

    /// If A equals `nr`, return `action`; otherwise fall through. Uses only
    /// skip-0/skip-1 jumps, so no instruction-offset ever overflows.
    fn deny(&mut self, nr: libc::c_long, action: u32) {
        self.jump(JMP_JEQ_K, nr as u32, 0, 1);
        self.stmt(RET_K, action);
    }

    /// If the syscall is `nr` and the 32-bit argument at `offset` is one of
    /// `values`, return `action`. Restores A to the syscall number.
    fn deny_if_arg(&mut self, nr: libc::c_long, offset: u32, values: &[u32], action: u32) {
        // Skip the whole block when the syscall differs: one load, a
        // compare-and-return pair per value, one reload.
        let block = u8::try_from(2 * values.len() + 2).unwrap_or(u8::MAX);
        self.jump(JMP_JEQ_K, nr as u32, 0, block);
        self.stmt(LD_W_ABS, offset);
        for value in values {
            self.jump(JMP_JEQ_K, *value, 0, 1);
            self.stmt(RET_K, action);
        }
        self.stmt(LD_W_ABS, OFF_NR);
    }

    /// If the syscall is `nr` and the 32-bit argument at `offset` is not
    /// zero, return `action`. Restores A to the syscall number.
    fn deny_unless_arg_zero(&mut self, nr: libc::c_long, offset: u32, action: u32) {
        self.jump(JMP_JEQ_K, nr as u32, 0, 4);
        self.stmt(LD_W_ABS, offset);
        self.jump(JMP_JEQ_K, 0, 1, 0); // zero: skip the return
        self.stmt(RET_K, action);
        self.stmt(LD_W_ABS, OFF_NR);
    }

    /// Allow `clone` only when it creates a thread with no new namespace;
    /// deny every other `clone` with `action`.
    fn clone_thread_only(&mut self, action: u32) {
        // if nr != clone, skip this whole block (8 instructions).
        self.jump(JMP_JEQ_K, libc::SYS_clone as u32, 0, 8);
        self.stmt(LD_W_ABS, OFF_ARG0_LOW); // A = flags
        self.stmt(ALU_AND_K, CLONE_THREAD);
        self.jump(JMP_JEQ_K, CLONE_THREAD, 0, 4); // thread bit set? else deny
        self.stmt(LD_W_ABS, OFF_ARG0_LOW); // reload flags
        self.stmt(ALU_AND_K, CLONE_NEW_NS);
        self.jump(JMP_JEQ_K, 0, 0, 1); // no namespace bits? else deny
        self.stmt(RET_K, RET_ALLOW);
        self.stmt(RET_K, action);
        self.stmt(LD_W_ABS, OFF_NR); // restore A = nr for the final allow
    }
}

// Socket creation and io_uring: with none of these the worker has no network
// of any kind (TCP, UDP, raw, netlink or AF_UNIX).
const NETWORK: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
];

// New-process creation other than clone (handled separately). execve is not
// listed: the filter is installed just before the worker's own exec.
const CHILD: &[libc::c_long] = &[
    #[cfg(target_arch = "x86_64")]
    libc::SYS_fork,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_vfork,
];

// Reading or tracing other processes, namespaces and mounts, and kernel
// surfaces that have been used to escape a sandbox.
const ESCAPE: &[libc::c_long] = &[
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_kcmp,
    libc::SYS_pidfd_getfd,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_kexec_load,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    libc::SYS_memfd_create,
    libc::SYS_process_madvise,
    libc::SYS_process_mrelease,
    // The mount API (it also needs a namespace the worker cannot create).
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_open_tree,
    SYS_OPEN_TREE_ATTR,
    libc::SYS_move_mount,
    libc::SYS_mount_setattr,
];

// Changing another process's scheduling, I/O priority or memory placement.
// (Resource limits are checked by argument, in `build`.)
const OTHER_PROCESSES: &[libc::c_long] = &[
    libc::SYS_setpriority,
    libc::SYS_ioprio_set,
    libc::SYS_sched_setscheduler,
    libc::SYS_sched_setparam,
    libc::SYS_sched_setaffinity,
    libc::SYS_sched_setattr,
    libc::SYS_migrate_pages,
    libc::SYS_move_pages,
];

// System V IPC, which Landlock does not mediate: shared memory, message
// queues and semaphores of other processes of the same user.
const IPC: &[libc::c_long] = &[
    libc::SYS_shmget,
    libc::SYS_shmat,
    libc::SYS_shmctl,
    libc::SYS_shmdt,
    libc::SYS_msgget,
    libc::SYS_msgsnd,
    libc::SYS_msgrcv,
    libc::SYS_msgctl,
    libc::SYS_semget,
    libc::SYS_semop,
    libc::SYS_semtimedop,
    libc::SYS_semctl,
];

// Watching files and directories outside the grants for activity (Landlock
// does not mediate watches).
const WATCH: &[libc::c_long] = &[
    #[cfg(target_arch = "x86_64")]
    libc::SYS_inotify_init,
    libc::SYS_inotify_init1,
    libc::SYS_fanotify_init,
];

// Sending signals. The kernel lets a process signal every other process of
// the same user, so without this the worker could kill the Core (or anything
// else the user runs). Its own fatal errors still end it: glibc's abort()
// falls back to a direct exit when raising the signal fails.
const SIGNAL: &[libc::c_long] = &[
    libc::SYS_kill,
    libc::SYS_tkill,
    libc::SYS_tgkill,
    libc::SYS_rt_sigqueueinfo,
    libc::SYS_rt_tgsigqueueinfo,
    libc::SYS_pidfd_send_signal,
];

// File-metadata syscalls Landlock does not mediate, so a confined worker
// cannot change ownership, mode, times, attributes or (on kernels whose
// Landlock predates truncation rights) length.
const METADATA: &[libc::c_long] = &[
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    SYS_FCHMODAT2,
    SYS_SETXATTRAT,
    SYS_REMOVEXATTRAT,
    SYS_FILE_SETATTR,
    libc::SYS_truncate,
    libc::SYS_fchown,
    libc::SYS_fchownat,
    libc::SYS_setxattr,
    libc::SYS_lsetxattr,
    libc::SYS_fsetxattr,
    libc::SYS_removexattr,
    libc::SYS_lremovexattr,
    libc::SYS_fremovexattr,
    libc::SYS_utimensat,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_chmod,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_chown,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_lchown,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_utime,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_utimes,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_futimesat,
];
