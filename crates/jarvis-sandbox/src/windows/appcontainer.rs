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

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW,
    NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW,
    TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
    DeriveAppContainerSidFromAppContainerName, GetAppContainerFolderPath,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
    EqualSid, FreeSid, GetAce, INHERIT_ONLY_ACE, INHERITED_ACE, NO_INHERITANCE, OBJECT_INHERIT_ACE,
    PSECURITY_DESCRIPTOR, PSID, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
    WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};
use windows_sys::core::PWSTR;

use super::{wide, wide_str};
use crate::{Access, Grant};

/// The per-user AppContainer profile the worker runs in. The name fits the
/// documented pattern `[-_. A-Za-z0-9]+`, up to 64 characters.
pub(crate) const PROFILE_NAME: &str = "JARVIS.Worker";
const DISPLAY_NAME: &str = "JARVIS worker";
const DESCRIPTION: &str = "Runs the JARVIS worker with no network and no access to user files";

/// "ALL APPLICATION PACKAGES": system directories grant it, and with it
/// every AppContainer.
const ALL_APPLICATION_PACKAGES: &str = "S-1-15-2-1";

/// Every right that changes a file or directory, without the
/// synchronisation and read-control bits that reading also needs.
const WRITE_RIGHTS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER;

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

/// Delete the profile. Returns whether one existed: `DeleteAppContainerProfile`
/// itself reports success either way, so existence is checked first.
pub(crate) fn delete_profile(sid: &PackageSid) -> io::Result<bool> {
    if !profile_exists(sid)? {
        return Ok(false);
    }
    let name = wide_str(PROFILE_NAME);
    // SAFETY: a NUL-terminated profile name.
    let result = unsafe { DeleteAppContainerProfile(name.as_ptr()) };
    match result {
        0 => Ok(true),
        code if HRESULT_NOT_FOUND.contains(&code) => Ok(false),
        code => Err(hresult_error("DeleteAppContainerProfile", code)),
    }
}

/// Whether the profile's folder exists. Any answer other than "not found"
/// counts as existing, so a deletion is still attempted.
fn profile_exists(sid: &PackageSid) -> io::Result<bool> {
    match container_folder(sid)? {
        Ok(_) => Ok(true),
        Err(code) => Ok(!HRESULT_NOT_FOUND.contains(&code)),
    }
}

/// The AppContainer's own folder (`...\Packages\<name>\AC`), or the HRESULT
/// `GetAppContainerFolderPath` failed with.
fn container_folder(sid: &PackageSid) -> io::Result<Result<PathBuf, i32>> {
    let text = wide_str(&sid.to_sddl()?);
    let mut path: PWSTR = null_mut();
    // SAFETY: a NUL-terminated SID string and an out pointer that, on
    // success, receives a CoTaskMemAlloc'd string freed below.
    let result = unsafe { GetAppContainerFolderPath(text.as_ptr(), &mut path) };
    if result != 0 {
        return Ok(Err(result));
    }
    // SAFETY: `path` is a NUL-terminated UTF-16 string from the call above.
    let folder = unsafe {
        let mut len = 0;
        while *path.add(len) != 0 {
            len += 1;
        }
        PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(path, len)))
    };
    // SAFETY: allocated by GetAppContainerFolderPath with CoTaskMemAlloc.
    unsafe { CoTaskMemFree(path.cast()) };
    Ok(Ok(folder))
}

/// Deny the package SID every write in its own AppContainer folder, which
/// Windows otherwise gives it in full (it is where `TEMP` points). With
/// this, the worker can write nowhere: it cannot fill the disk or keep
/// state across restarts.
///
/// Windows gives the subfolders their own explicit allow entries, and an
/// explicit allow is weighed before an inherited deny, so the deny is set
/// explicitly on the folder and on every directory below it. Done once;
/// later starts find the entries.
pub(crate) fn deny_container_writes(sid: &PackageSid) -> io::Result<()> {
    const MAX_DIRECTORIES: usize = 256;
    let folder =
        container_folder(sid)?.map_err(|code| hresult_error("GetAppContainerFolderPath", code))?;
    let mut pending = vec![folder];
    let mut visited = 0;
    while let Some(dir) = pending.pop() {
        visited += 1;
        if visited > MAX_DIRECTORIES {
            return Err(io::Error::other(
                "the AppContainer folder holds more directories than expected",
            ));
        }
        let dacl = Dacl::read(&dir)?;
        if !dacl.denies_explicitly(sid, WRITE_RIGHTS) {
            dacl.apply(
                &dir,
                sid,
                DENY_ACCESS,
                WRITE_RIGHTS,
                SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            )?;
        }
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            // Directories only; links and junctions are not followed.
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(())
}

/// The rights a grant gives the package SID. Every grant includes
/// `FILE_TRAVERSE`: a directory must grant it to be opened as a working
/// directory or walked into. On a file the same bit means execute, which
/// for a read-only source tree of Python files is harmless (the worker can
/// neither start a process nor write a file there).
fn rights(access: Access) -> u32 {
    match access {
        Access::ReadExecute => FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        Access::Read => FILE_GENERIC_READ | FILE_TRAVERSE,
        Access::ReadWrite => FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_TRAVERSE | DELETE,
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

    /// Every allow and deny entry, as (type, SID pointer, mask, flags).
    fn entries(&self) -> Vec<(u32, PSID, u32, u8)> {
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
            let kind = u32::from(header.AceType);
            if kind != ACCESS_ALLOWED_ACE_TYPE && kind != ACCESS_DENIED_ACE_TYPE {
                continue;
            }
            // An ACCESS_DENIED_ACE has the same layout as ACCESS_ALLOWED_ACE.
            let entry = ace.cast::<ACCESS_ALLOWED_ACE>();
            // SAFETY: an allow or deny ACE whose SID starts at SidStart and
            // lies within AceSize bytes, inside the ACL.
            let (mask, sid) = unsafe {
                (
                    (*entry).Mask,
                    (&raw mut (*entry).SidStart).cast::<core::ffi::c_void>(),
                )
            };
            entries.push((kind, sid, mask, header.AceFlags));
        }
        entries
    }

    /// Whether an allow entry for `sid`, or for ALL APPLICATION PACKAGES
    /// (as on system directories such as `Program Files`), grants all of
    /// `wanted` to this object (and, for a directory, to files and
    /// subdirectories below it). A missing DACL means unrestricted access,
    /// which also counts. Deny entries are not weighed here: one would make
    /// the worker fail to start, not run with more access.
    fn grants(&self, sid: &PackageSid, wanted: u32, directory: bool) -> bool {
        if self.acl.is_null() {
            return true;
        }
        let any_package = LocalSid::parse(ALL_APPLICATION_PACKAGES).ok();
        let inherit = (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE) as u8;
        self.entries()
            .into_iter()
            .any(|(kind, entry, mask, flags)| {
                // SAFETY: valid SIDs.
                let ours = unsafe { EqualSid(entry, sid.as_psid()) } != 0;
                // SAFETY: valid SIDs.
                let everyone = any_package
                    .as_ref()
                    .is_some_and(|any| unsafe { EqualSid(entry, any.0) } != 0);
                kind == ACCESS_ALLOWED_ACE_TYPE
                    && (ours || everyone)
                    && flags & INHERIT_ONLY_ACE as u8 == 0
                    && mask & wanted == wanted
                    && (!directory || flags & inherit == inherit)
            })
    }

    /// Whether an explicit (not inherited) deny entry for `sid` covers all
    /// of `rights`.
    fn denies_explicitly(&self, sid: &PackageSid, rights: u32) -> bool {
        self.entries()
            .into_iter()
            .any(|(kind, entry, mask, flags)| {
                kind == ACCESS_DENIED_ACE_TYPE
                && flags & INHERITED_ACE as u8 == 0
                // SAFETY: valid SIDs.
                && unsafe { EqualSid(entry, sid.as_psid()) } != 0
                && mask & rights == rights
            })
    }

    /// Whether any allow entry names `sid`.
    fn names(&self, sid: &PackageSid) -> bool {
        self.entries().into_iter().any(|(kind, entry, _, _)| {
            kind == ACCESS_ALLOWED_ACE_TYPE
                // SAFETY: both are valid SIDs.
                && unsafe { EqualSid(entry, sid.as_psid()) } != 0
        })
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

/// A SID parsed from its string form, freed on drop.
struct LocalSid(PSID);

impl LocalSid {
    fn parse(text: &str) -> io::Result<Self> {
        let text = wide_str(text);
        let mut sid: PSID = null_mut();
        // SAFETY: a NUL-terminated SID string; the SID is freed on drop.
        let ok = unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sid))
    }
}

impl Drop for LocalSid {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSidToSidW.
        unsafe { LocalFree(self.0) };
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
