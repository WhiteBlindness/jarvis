use std::io;

use crate::{Contained, Limits};

pub(crate) fn prepare(command: &mut tokio::process::Command, limits: &Limits) {
    // Own process group: the whole tree can be signalled at once.
    command.process_group(0);
    let parent = std::process::id();
    let memory = limits.memory_bytes;
    // SAFETY: the closure runs in the child between fork and exec, so it may
    // only use async-signal-safe functions. It calls prctl, getppid, setrlimit
    // and _exit, which are all plain system calls, and touches no locks or
    // heap memory.
    unsafe {
        command.pre_exec(move || {
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
                // No privilege gain through setuid binaries or file capabilities.
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
            Ok(())
        });
    }
}

pub(crate) fn contain(child: &tokio::process::Child, limits: &Limits) -> io::Result<Contained> {
    let pid = child
        .id()
        .ok_or_else(|| io::Error::other("worker exited before it could be contained"))?;
    let mut controls = vec![
        "own process group".to_owned(),
        format!("address space {} MiB", limits.memory_bytes / (1024 * 1024)),
        "no core dumps".to_owned(),
    ];
    if cfg!(target_os = "linux") {
        controls.push("dies with the Core".to_owned());
        controls.push("no_new_privs".to_owned());
    }
    Ok(Contained {
        inner: Guard { pgid: pid },
        description: controls.join(", "),
    })
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
