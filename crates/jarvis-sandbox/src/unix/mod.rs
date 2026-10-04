//! Linux (and other Unix) containment of the worker.
//!
//! The process-lifetime controls (own process group, death with the Core,
//! `no_new_privs`, resource limits, stdio-only descriptors) are applied on
//! every Unix. On Linux the worker is additionally confined by Landlock (a
//! filesystem boundary, see [`landlock`]) and seccomp (no network, no child
//! processes, no escape syscalls, see [`seccomp`]). Everything that must run
//! in the child is built in the parent and applied with raw syscalls between
//! fork and exec, so the pre-exec step allocates nothing and is
//! async-signal-safe.

use std::io;
use std::process::{ExitStatus, Stdio};

use crate::{Confinement, Contained, Report, Spawned, WorkerCommand};

#[cfg(target_os = "linux")]
mod landlock;
#[cfg(target_os = "linux")]
mod seccomp;

pub(crate) type Stdin = tokio::process::ChildStdin;
pub(crate) type Stdout = tokio::process::ChildStdout;
pub(crate) type Stderr = tokio::process::ChildStderr;

pub(crate) fn spawn(command: &WorkerCommand, confinement: &Confinement) -> io::Result<Spawned> {
    // Only Linux has the filesystem, network and process boundary. Elsewhere
    // the worker would run with the user's full authority, so it does not
    // run at all.
    if cfg!(not(target_os = "linux")) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "worker isolation is implemented for Linux and Windows only",
        ));
    }
    let mut cmd = tokio::process::Command::new(&command.program);
    cmd.args(&command.args)
        .env_clear()
        .envs(command.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(cwd) = &command.cwd {
        cmd.current_dir(cwd);
    }
    prepare(&mut cmd, confinement)?;
    // Every control is applied in the child before exec; if any fails, the
    // exec does not happen and spawn returns the error.
    let mut child = cmd.spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| io::Error::other("worker exited before it could be contained"))?;
    let contained = describe(pid, confinement);
    let pipes = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    let (Some(stdin), Some(stdout), Some(stderr)) = pipes else {
        let _ = contained.kill_all();
        return Err(io::Error::other("worker pipes were not created"));
    };
    Ok(Spawned {
        process: crate::Process {
            inner: Process { child, pid },
        },
        contained,
        stdin,
        stdout,
        stderr,
    })
}

#[derive(Debug)]
pub(crate) struct Process {
    child: tokio::process::Child,
    pid: u32,
}

impl Process {
    pub(crate) fn id(&self) -> u32 {
        self.pid
    }

    pub(crate) async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.child.wait().await
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    pub(crate) fn start_kill(&mut self) -> io::Result<()> {
        self.child.start_kill()
    }
}

pub(crate) fn report(confinement: &Confinement) -> io::Result<Report> {
    #[cfg(target_os = "linux")]
    {
        let abi = landlock::abi_version()?;
        let _ = confinement;
        Ok(Report {
            mechanism: format!("landlock (ABI {abi}) + seccomp-bpf + rlimits"),
            identity: vec![("user".to_owned(), current_uid().to_string())],
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = confinement;
        Ok(Report {
            mechanism: "process group + rlimits (no filesystem or network boundary)".to_owned(),
            identity: vec![("user".to_owned(), current_uid().to_string())],
        })
    }
}

pub(crate) fn remove(_confinement: &Confinement) -> io::Result<Vec<String>> {
    // Landlock and seccomp leave nothing behind.
    Ok(Vec::new())
}

fn prepare(command: &mut tokio::process::Command, confinement: &Confinement) -> io::Result<()> {
    // Own process group: the whole tree can be signalled at once.
    command.process_group(0);
    let parent = std::process::id();
    let memory = confinement.limits.memory_bytes;
    let max_fd = open_file_limit();

    // Built in the parent so the child only makes single syscalls.
    #[cfg(target_os = "linux")]
    let ruleset = landlock::Ruleset::build(&confinement.filesystem)?;
    #[cfg(target_os = "linux")]
    let filter = seccomp::Filter::build(confinement);
    // A coarse backstop behind the seccomp child-process denial.
    #[cfg(target_os = "linux")]
    let max_procs = if confinement.deny_child_processes {
        Some(1)
    } else {
        None
    };

    // SAFETY: the closure runs in the child between fork and exec, so it may
    // only use async-signal-safe functions. It calls prctl, getppid,
    // geteuid, capset, setrlimit, close_range, fcntl, the landlock and
    // seccomp syscalls, and _exit, which are all plain system calls over
    // memory prepared in the parent; it allocates nothing and takes no locks.
    unsafe {
        command.pre_exec(move || {
            // Only stdin, stdout and stderr may reach the worker. The Core
            // opens its own descriptors close-on-exec, but it may have
            // inherited others from whatever started it (a shell, a service
            // manager, a build tool's jobserver).
            mark_close_on_exec_from(3, max_fd);
            #[cfg(target_os = "linux")]
            {
                // Die with the thread that spawned us. Tokio spawns from a
                // runtime worker thread, which lives as long as the runtime.
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // The parent may have died before the call above.
                if libc::getppid() != parent as libc::pid_t {
                    libc::_exit(1);
                }
                // No privilege gain through setuid binaries or file
                // capabilities. Landlock and seccomp both require this.
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            #[cfg(not(target_os = "linux"))]
            let _ = parent;
            let no_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0 {
                return Err(io::Error::last_os_error());
            }
            let address_space = libc::rlimit {
                rlim_cur: memory as libc::rlim_t,
                rlim_max: memory as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &address_space) != 0 {
                return Err(io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            {
                if let Some(max) = max_procs {
                    let procs = libc::rlimit {
                        rlim_cur: max,
                        rlim_max: max,
                    };
                    if libc::setrlimit(libc::RLIMIT_NPROC, &procs) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                // The worker gets no capabilities, whoever runs the Core.
                // After the limits above, which root may set above the
                // current hard limit.
                drop_capabilities()?;
                // Filesystem boundary, then the syscall filter last: once the
                // filter is installed, only the final execve of the worker
                // may run.
                ruleset.restrict_self()?;
                filter.install()?;
            }
            Ok(())
        });
    }
    Ok(())
}

/// `struct __user_cap_header_struct` and `__user_cap_data_struct`.
#[cfg(target_os = "linux")]
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Remove every capability from the ambient, effective, permitted and
/// inheritable sets, and (for root, the only case where it matters and is
/// possible) from the bounding set, so the interpreter runs with none.
/// Runs between fork and exec: system calls only.
#[cfg(target_os = "linux")]
fn drop_capabilities() -> io::Result<()> {
    // SAFETY: geteuid has no side effects.
    let root = unsafe { libc::geteuid() } == 0;
    for cap in 0..64 {
        if !root {
            // Emptying the bounding set needs CAP_SETPCAP. Without root,
            // no_new_privs already stops exec from adding capabilities.
            break;
        }
        // SAFETY: PR_CAPBSET_DROP only narrows this process's bounding set;
        // EINVAL marks a capability number this kernel does not know.
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(error);
            }
        }
    }
    // SAFETY: clearing the ambient set only removes capabilities; kernels
    // without ambient capabilities answer EINVAL, which is harmless.
    unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    let header = CapHeader {
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let none = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: a valid version-3 header and two data words; capset with all
    // zeroes only drops capabilities from the calling thread.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, none.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Highest descriptor number worth visiting when `close_range` is missing:
/// the soft open-file limit, capped.
fn open_file_limit() -> libc::c_int {
    const CAP: libc::c_int = 1 << 20;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes into the structure it is given.
    let ok = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0;
    if ok && limit.rlim_cur != libc::RLIM_INFINITY {
        libc::c_int::try_from(limit.rlim_cur).map_or(CAP, |n| n.min(CAP))
    } else {
        CAP
    }
}

/// Set close-on-exec on every descriptor from `first` up. Runs between fork
/// and exec, so it only makes system calls. Closing instead would break the
/// standard library's own close-on-exec pipe that reports exec failures.
fn mark_close_on_exec_from(first: libc::c_int, max_fd: libc::c_int) {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range with CLOSE_RANGE_CLOEXEC only changes
        // descriptor flags (Linux 5.11 and later).
        let done = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                first as libc::c_uint,
                libc::c_uint::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        } == 0;
        if done {
            return;
        }
    }
    for fd in first..max_fd {
        // SAFETY: setting a descriptor flag; EBADF for unused numbers is
        // expected and harmless.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
}

fn describe(pid: u32, confinement: &Confinement) -> Contained {
    let mut controls = vec![
        "own process group".to_owned(),
        "stdio only".to_owned(),
        format!(
            "address space {} MiB",
            confinement.limits.memory_bytes / (1024 * 1024)
        ),
        "no core dumps".to_owned(),
    ];
    if cfg!(target_os = "linux") {
        controls.push("dies with the Core".to_owned());
        controls.push("no_new_privs".to_owned());
        controls.push("no capabilities".to_owned());
        controls.push("no signals to other processes".to_owned());
        controls.push("landlock filesystem".to_owned());
        if confinement.deny_network {
            controls.push("no network".to_owned());
        }
        if confinement.deny_child_processes {
            controls.push("no child processes".to_owned());
        }
    }
    Contained {
        inner: Guard { pgid: pid },
        description: controls.join(", "),
    }
}

#[derive(Debug)]
pub(crate) struct Guard {
    /// The worker's pid, which is also its process group ID.
    pgid: u32,
}

impl Guard {
    pub(crate) fn kill_all(&self) -> io::Result<()> {
        // SAFETY: killpg only sends a signal; the group ID is the worker's
        // own, created by `process_group(0)`.
        let result = unsafe { libc::killpg(self.pgid as libc::pid_t, libc::SIGKILL) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }

    /// The worker itself, anything still in its process group, and (on
    /// Linux) any process that has the worker as an ancestor, which catches
    /// a descendant that left the group with `setsid` or `setpgid`. A
    /// descendant whose parent exited is re-parented away from the worker
    /// and is no longer recognised.
    pub(crate) fn contains(&self, pid: u32) -> bool {
        if pid == self.pgid {
            return true;
        }
        // SAFETY: getpgid only reads the process table.
        let group = unsafe { libc::getpgid(pid as libc::pid_t) };
        if group >= 0 && group as u32 == self.pgid {
            return true;
        }
        #[cfg(target_os = "linux")]
        {
            let mut current = pid;
            for _ in 0..64 {
                match parent_of(current) {
                    Some(parent) if parent == self.pgid => return true,
                    Some(parent) if parent > 1 => current = parent,
                    _ => break,
                }
            }
        }
        false
    }
}

/// The parent of `pid`, from `/proc/<pid>/stat`.
#[cfg(target_os = "linux")]
fn parent_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `pid (comm) state ppid ...`; comm may itself contain spaces and `)`.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

pub(crate) fn process_exists(pid: u32) -> bool {
    // SAFETY: signal 0 performs only the existence and permission check.
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

pub(crate) fn current_uid() -> u32 {
    // SAFETY: getuid cannot fail and has no side effects.
    unsafe { libc::getuid() }
}
