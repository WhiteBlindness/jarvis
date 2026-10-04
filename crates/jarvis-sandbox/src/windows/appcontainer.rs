//! The worker's AppContainer identity and its filesystem grants.
//!
//! An AppContainer process has a package SID. Every file access is checked
//! twice: once for the user and once for the package SID, and both must be
//! granted. Ordinary ACLs never name the package SID, so the user's profile,
//! other drives and the Core's own data are unreadable to the worker unless
//! a path is granted here. System directories that grant "ALL APPLICATION
//! PACKAGES" (Windows, System32, Program Files) stay readable, which is what
//! lets the interpreter load system libraries.
//!
//! The profile is created per user with no administrator rights. Creating it
//! again is a no-op, so starting the Core twice changes nothing.

use std::io;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS,
    SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID,
    TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
    EqualSid, FreeSid, GetAce, NO_INHERITANCE, OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

use super::{wide, wide_str};
use crate::{Access, Grant};

/// The per-user AppContainer profile the worker runs in. The name fits the
/// documented pattern `[-_. A-Za-z0-9]+`, up to 64 characters.
pub(crate) const PROFILE_NAME: &str = "JARVIS.Worker";
const DISPLAY_NAME: &str = "JARVIS worker";
const DESCRIPTION: &str = "Runs the JARVIS worker with no network and no access to user files";

/// `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)`.
const HRESULT_ALREADY_EXISTS: i32 = 0x8007_00B7_u32 as i32;
/// `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)` and `(ERROR_NOT_FOUND)`.
const HRESULT_NOT_FOUND: [i32; 2] = [0x8007_0002_u32 as i32, 0x8007_0490_u32 as i32];

/// The worker's package SID, freed on drop.
#[derive(Debug)]
pub(crate) struct PackageSid(PSID);

// SAFETY: the SID is immutable memory owned by this value.
unsafe impl Send for PackageSid {}
// SAFETY: as above; it is only read.
unsafe impl Sync for PackageSid {}

impl PackageSid {
    /// Create the profile if needed and return its SID.
    pub(crate) fn ensure() -> io::Result<Self> {
        let name = wide_str(PROFILE_NAME);
        let display = wide_str(DISPLAY_NAME);
        let description = wide_str(DESCRIPTION);
        let mut sid: PSID = null_mut();
        // SAFETY: NUL-terminated strings, no capabilities, and an out pointer
        // for the SID, which is freed with FreeSid.
        let result = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                display.as_ptr(),
                description.as_ptr(),
                null(),
                0,
                &mut sid,
            )
        };
        if result == 0 {
            return Ok(Self(sid));
        }
        if result != HRESULT_ALREADY_EXISTS {
            return Err(hresult_error("CreateAppContainerProfile", result));
        }
        Self::derive()
    }

    /// The SID for the profile name, whether or not the profile exists.
    pub(crate) fn derive() -> io::Result<Self> {
        let name = wide_str(PROFILE_NAME);
        let mut sid: PSID = null_mut();
        // SAFETY: a NUL-terminated name and an out pointer for the SID, which
        // is freed with FreeSid.
        let result = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
        if result != 0 {
            return Err(hresult_error(
                "DeriveAppContainerSidFromAppContainerName",
                result,
            ));
        }
        Ok(Self(sid))
    }

    pub(crate) fn as_psid(&self) -> PSID {
        self.0
    }

    /// The SID in `S-1-15-2-...` form.
    pub(crate) fn to_sddl(&self) -> io::Result<String> {
        super::sid_to_string(self.0)
    }
}

impl Drop for PackageSid {
    fn drop(&mut self) {
        // SAFETY: allocated by the AppContainer functions, freed once.
        unsafe { FreeSid(self.0) };
    }
}

/// Delete the profile. Returns whether one existed.
pub(crate) fn delete_profile() -> io::Result<bool> {
    let name = wide_str(PROFILE_NAME);
    // SAFETY: a NUL-terminated profile name.
    let result = unsafe { DeleteAppContainerProfile(name.as_ptr()) };
    match result {
        0 => Ok(true),
        code if HRESULT_NOT_FOUND.contains(&code) => Ok(false),
        code => Err(hresult_error("DeleteAppContainerProfile", code)),
    }
}

/// The rights a grant gives the package SID.
fn rights(access: Access) -> u32 {
    match access {
        Access::ReadExecute => FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        Access::Read => FILE_GENERIC_READ,
        Access::ReadWrite => FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
    }
}

/// Grant the package SID each path's rights, inherited by everything below a
/// directory. A path that already grants them (directly or by inheritance)
/// is left untouched, so this is cheap after the first start. Fails closed:
/// if a grant cannot be made, the worker is not started.
pub(crate) fn grant_paths(sid: &PackageSid, grants: &[Grant]) -> io::Result<()> {
    for grant in grants {
        if !grant.path.exists() {
            continue;
        }
        let wanted = rights(grant.access);
        let directory = grant.path.is_dir();
        let dacl = Dacl::read(&grant.path)?;
        if dacl.grants(sid, wanted, directory) {
            continue;
        }
        let inheritance = if directory {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        };
        dacl.apply(&grant.path, sid, GRANT_ACCESS, wanted, inheritance)
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "cannot grant the worker access to {} ({error}); \
                         see docs/windows-validation.md for the one-time setup",
                        grant.path.display()
                    ),
                )
            })?;
    }
    Ok(())
}

/// Remove every explicit entry for the package SID from each path. Returns
/// the paths that changed.
pub(crate) fn revoke_paths(sid: &PackageSid, grants: &[Grant]) -> io::Result<Vec<String>> {
    let mut changed = Vec::new();
    for grant in grants {
        if !grant.path.exists() {
            continue;
        }
        let dacl = Dacl::read(&grant.path)?;
        if !dacl.names(sid) {
            continue;
        }
        dacl.apply(&grant.path, sid, REVOKE_ACCESS, 0, NO_INHERITANCE)?;
        changed.push(grant.path.display().to_string());
    }
    Ok(changed)
}

/// A file or directory's DACL, read with `GetNamedSecurityInfoW`. The
/// security descriptor that owns it is freed on drop.
struct Dacl {
    descriptor: PSECURITY_DESCRIPTOR,
    acl: *mut ACL,
}

impl Dacl {
    fn read(path: &Path) -> io::Result<Self> {
        let name = wide(path.as_os_str());
        let mut acl: *mut ACL = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: a NUL-terminated path; the DACL pointer points into the
        // returned descriptor, which is freed with LocalFree on drop.
        let status = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(win32_error("GetNamedSecurityInfoW", status));
        }
        Ok(Self { descriptor, acl })
    }

    /// Every allow entry, as (SID pointer, mask, flags).
    fn entries(&self) -> Vec<(PSID, u32, u8)> {
        if self.acl.is_null() {
            return Vec::new();
        }
        // SAFETY: a valid ACL returned by GetNamedSecurityInfoW.
        let count = unsafe { (*self.acl).AceCount };
        let mut entries = Vec::with_capacity(usize::from(count));
        for index in 0..u32::from(count) {
            let mut ace = null_mut();
            // SAFETY: the index is below AceCount; GetAce returns a pointer
            // into the ACL.
            if unsafe { GetAce(self.acl, index, &mut ace) } == 0 {
                continue;
            }
            // SAFETY: every ACE starts with an ACE_HEADER.
            let header = unsafe { *ace.cast::<ACE_HEADER>() };
            if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
                continue;
            }
            let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
            // SAFETY: an ACCESS_ALLOWED_ACE whose SID starts at SidStart and
            // lies within AceSize bytes, inside the ACL.
            let (mask, sid) = unsafe {
                (
                    (*allowed).Mask,
                    (&raw mut (*allowed).SidStart).cast::<core::ffi::c_void>(),
                )
            };
            entries.push((sid, mask, header.AceFlags));
        }
        entries
    }

    /// Whether an allow entry for `sid` grants all of `wanted` (and, for a
    /// directory, is inherited by files and subdirectories). A missing DACL
    /// means unrestricted access, which also counts.
    fn grants(&self, sid: &PackageSid, wanted: u32, directory: bool) -> bool {
        if self.acl.is_null() {
            return true;
        }
        let inherit = (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE) as u8;
        self.entries().into_iter().any(|(entry, mask, flags)| {
            // SAFETY: both are valid SIDs.
            let same = unsafe { EqualSid(entry, sid.as_psid()) } != 0;
            same && mask & wanted == wanted && (!directory || flags & inherit == inherit)
        })
    }

    /// Whether any allow entry names `sid`.
    fn names(&self, sid: &PackageSid) -> bool {
        self.entries()
            .into_iter()
            // SAFETY: both are valid SIDs.
            .any(|(entry, _, _)| unsafe { EqualSid(entry, sid.as_psid()) } != 0)
    }

    /// Merge one entry for `sid` into this DACL and write it back.
    /// `SetNamedSecurityInfoW` recomputes inherited entries from the parent,
    /// keeps the object's protection state, and propagates inheritable
    /// entries to the tree below.
    fn apply(
        &self,
        path: &Path,
        sid: &PackageSid,
        mode: i32,
        rights: u32,
        inheritance: u32,
    ) -> io::Result<()> {
        if self.acl.is_null() {
            // Never replace "no DACL" (everyone allowed) with a one-entry
            // DACL that would lock everyone else out.
            return Ok(());
        }
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: rights,
            grfAccessMode: mode,
            grfInheritance: inheritance,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: sid.as_psid().cast(),
            },
        };
        let mut merged: *mut ACL = null_mut();
        // SAFETY: one well-formed entry, the current DACL, and an out
        // pointer for a new ACL that is freed with LocalFree below.
        let status = unsafe { SetEntriesInAclW(1, &entry, self.acl, &mut merged) };
        if status != ERROR_SUCCESS {
            return Err(win32_error("SetEntriesInAclW", status));
        }
        let name = wide(path.as_os_str());
        // SAFETY: a NUL-terminated path and a valid ACL; only the DACL is
        // written.
        let status = unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                merged,
                null(),
            )
        };
        // SAFETY: allocated by SetEntriesInAclW.
        unsafe { LocalFree(merged.cast()) };
        if status != ERROR_SUCCESS {
            return Err(win32_error("SetNamedSecurityInfoW", status));
        }
        Ok(())
    }
}

impl Drop for Dacl {
    fn drop(&mut self) {
        // SAFETY: allocated by GetNamedSecurityInfoW, freed once.
        unsafe { LocalFree(self.descriptor) };
    }
}

fn win32_error(what: &str, status: u32) -> io::Error {
    let error = io::Error::from_raw_os_error(status as i32);
    io::Error::new(error.kind(), format!("{what}: {error}"))
}

fn hresult_error(what: &str, result: i32) -> io::Error {
    // A Win32 error wrapped in an HRESULT (facility 7) maps back to it.
    let code = result as u32;
    if code & 0xFFFF_0000 == 0x8007_0000 {
        return win32_error(what, code & 0xFFFF);
    }
    io::Error::other(format!("{what}: HRESULT {code:#010x}"))
}
