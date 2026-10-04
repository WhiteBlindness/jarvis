//! A Landlock filesystem boundary for the worker (Linux).
//!
//! The ruleset is created and populated in the parent, where allocation is
//! allowed; the child calls only `landlock_restrict_self`, a single syscall.
//! Landlock is default-deny: once restricted, the worker may touch only the
//! directory trees named in [`Grant`]s, with the least right each needs.
//! Everything else — the user's home, `/tmp`, `/etc`, `/proc`, every other
//! process — is denied. See ADR 0014.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;

use crate::{Access, Grant};

// Landlock filesystem access-right bits (uapi/linux/landlock.h).
const EXECUTE: u64 = 1 << 0;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const REMOVE_DIR: u64 = 1 << 4;
const REMOVE_FILE: u64 = 1 << 5;
const MAKE_REG: u64 = 1 << 8;
const REFER: u64 = 1 << 13;
const TRUNCATE: u64 = 1 << 14;
const IOCTL_DEV: u64 = 1 << 15;

const RULE_PATH_BENEATH: libc::c_int = 1;
const CREATE_RULESET_VERSION: u32 = 1 << 0;

/// `struct landlock_ruleset_attr` (we set only the filesystem field, so the
/// 8-byte form is passed and the kernel zero-fills the rest).
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

/// `struct landlock_path_beneath_attr`, which the kernel declares packed.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// A built Landlock ruleset, ready to be applied in the child. `None` when no
/// grants were given (the caller opted out of a filesystem boundary).
#[derive(Debug, Clone)]
pub(crate) struct Ruleset {
    fd: Option<Arc<OwnedFd>>,
}

impl Ruleset {
    /// Build the ruleset in the parent. Fails closed if grants were requested
    /// but Landlock is unavailable or the ruleset cannot be created.
    pub(crate) fn build(grants: &[Grant]) -> io::Result<Self> {
        if grants.is_empty() {
            return Ok(Self { fd: None });
        }
        let abi = abi_version()?;
        let handled = handled_access_fs(abi);

        let attr = RulesetAttr {
            handled_access_fs: handled,
        };
        // SAFETY: create a ruleset from a valid attr of the given size; flags
        // 0. Returns an O_CLOEXEC fd or -1.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                size_of::<RulesetAttr>(),
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh owned fd returned by the kernel.
        let fd = unsafe { OwnedFd::from_raw_fd(raw as RawFd) };

        for grant in grants {
            let allowed = access_rights(grant.access) & handled;
            add_path_rule(fd.as_raw_fd(), &grant.path, allowed)?;
        }
        Ok(Self {
            fd: Some(Arc::new(fd)),
        })
    }

    /// Apply the ruleset to the calling (child) process. One syscall; safe to
    /// call between fork and exec.
    pub(crate) fn restrict_self(&self) -> io::Result<()> {
        let Some(fd) = &self.fd else {
            return Ok(());
        };
        // SAFETY: restrict_self takes a valid ruleset fd and a flags word; it
        // only narrows this thread's access and cannot fail from memory.
        let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd.as_raw_fd(), 0) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

use std::os::fd::FromRawFd;

/// The kernel's Landlock ABI version, or an error if Landlock is unavailable
/// (not built in, or disabled at boot).
fn abi_version() -> io::Result<i64> {
    // SAFETY: the version query takes a null attr, zero size and the version
    // flag; it returns the ABI number or -1.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            0,
            0,
            CREATE_RULESET_VERSION,
        )
    };
    if abi <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Landlock is not available on this kernel",
        ));
    }
    Ok(abi)
}

/// Every filesystem right the kernel of this ABI knows, so that granting a
/// subset per path denies the rest everywhere.
fn handled_access_fs(abi: i64) -> u64 {
    let mut mask = 0x1fff; // ABI 1: the 13 base rights.
    if abi >= 2 {
        mask |= REFER;
    }
    if abi >= 3 {
        mask |= TRUNCATE;
    }
    if abi >= 5 {
        mask |= IOCTL_DEV;
    }
    mask
}

/// The rights a grant needs (before masking to the handled set).
fn access_rights(access: Access) -> u64 {
    match access {
        Access::ReadExecute => EXECUTE | READ_FILE | READ_DIR,
        Access::Read => READ_FILE | READ_DIR,
        Access::ReadWrite => {
            READ_FILE | READ_DIR | WRITE_FILE | MAKE_REG | REMOVE_FILE | REMOVE_DIR | TRUNCATE
        }
    }
}

/// Open `path` and add a `PATH_BENEATH` rule granting `allowed`. A path that
/// does not exist is skipped, so the grant list may name optional roots.
fn add_path_rule(ruleset_fd: RawFd, path: &std::path::Path, allowed: u64) -> io::Result<()> {
    let mut c_path: Vec<u8> = path.as_os_str().as_bytes().to_vec();
    c_path.push(0);
    // SAFETY: a NUL-terminated path; O_PATH|O_CLOEXEC opens a reference
    // without reading, and never follows into the file's contents.
    let fd = unsafe { libc::open(c_path.as_ptr().cast(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(()); // An optional runtime root that is not present.
        }
        return Err(error);
    }
    // SAFETY: `fd` is a fresh owned fd.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let attr = PathBeneathAttr {
        allowed_access: allowed,
        parent_fd: fd.as_raw_fd(),
    };
    // SAFETY: a valid ruleset fd, the documented rule type, a correctly sized
    // packed attr, flags 0.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            RULE_PATH_BENEATH,
            &attr as *const PathBeneathAttr,
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
