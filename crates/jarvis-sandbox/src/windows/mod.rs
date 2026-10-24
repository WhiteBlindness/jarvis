//! Windows isolation: the worker runs in an AppContainer with no
//! capabilities, inside a job object, with a child-process policy, an
//! explicit handle list and process mitigations, all applied by the single
//! `CreateProcessW` call in [`launch`]. See ADR 0013.
//!
//! What each control stops:
//!
//! - **AppContainer, no capabilities.** File access needs the package SID to
//!   be granted as well as the user, so the user's profile and the Core's
//!   data are unreadable; the Windows Filtering Platform blocks all network
//!   traffic, loopback included; the worker runs at low integrity.
//! - **Child-process policy and a one-process job.** The worker cannot start
//!   another program, so it cannot hand work to an unconfined process.
//! - **Job object.** Kill-on-close ties the worker's life to the Core; a
//!   commit limit caps its memory; UI restrictions apply when the Core is not
//!   itself in a job.
//! - **Handle list.** Only the three stdio pipe ends are inherited.
//! - **Token check.** Before the suspended worker runs, the Core confirms it
//!   is an AppContainer at low integrity inside the job and removes every
//!   privilege except `SeChangeNotifyPrivilege`.

use std::ffi::{OsStr, c_void};
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::RawHandle;
use std::ptr::{null, null_mut};

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_CANNOT_IMPERSONATE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID,
    LocalFree, STILL_ACTIVE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACE_HEADER, ACL, AdjustTokenPrivileges, EqualSid, GetAce, GetSidSubAuthority,
    GetSidSubAuthorityCount, GetTokenInformation, INHERIT_ONLY_ACE, IsValidSid,
    LABEL_SECURITY_INFORMATION, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, RevertToSelf, SE_CHANGE_NOTIFY_NAME,
    SE_PRIVILEGE_REMOVED, SECURITY_ATTRIBUTES, SYSTEM_MANDATORY_LABEL_ACE, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_APPCONTAINER_INFORMATION, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES,
    TOKEN_QUERY, TOKEN_USER, TokenAppContainerSid, TokenCapabilities, TokenIntegrityLevel,
    TokenIsAppContainer, TokenPrivileges, TokenUser,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_BASIC_UI_RESTRICTIONS,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicUIRestrictions,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};
use windows_sys::Win32::System::SystemServices::{
    JOB_OBJECT_UILIMIT_ALL, PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY,
    SECURITY_MANDATORY_LOW_RID, SECURITY_MANDATORY_MEDIUM_RID, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, GetExitCodeProcess, GetProcessMitigationPolicy,
    OpenProcess, OpenProcessToken, OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, ProcessSystemCallDisablePolicy, WaitForSingleObject,
};

use crate::{Confinement, PipeClient, Report};

mod appcontainer;
pub(crate) mod clipboard;
mod launch;
mod processes;

pub(crate) use launch::{Process, Stderr, Stdin, Stdout, spawn, spawn_helper};
pub(crate) use processes::{PROCESS_NAME_LIMIT, visit_process_names};

/// Describe the AppContainer the worker would run in, without creating it.
pub(crate) fn report(_confinement: &Confinement) -> io::Result<Report> {
    let sid = appcontainer::PackageSid::derive()?;
    let in_job = current_process_in_job()?;
    Ok(Report {
        mechanism: format!(
            "AppContainer (no capabilities) + job object + child-process policy + mitigations ({})",
            launch::MITIGATION_NAMES
        ),
        identity: vec![
            (
                "appcontainer".to_owned(),
                appcontainer::PROFILE_NAME.to_owned(),
            ),
            ("package_sid".to_owned(), sid.to_sddl()?),
            (
                "ui_restrictions".to_owned(),
                if in_job {
                    "no (the Core runs inside a job)".to_owned()
                } else {
                    "yes".to_owned()
                },
            ),
        ],
    })
}

/// Remove the package SID's entries from every granted path, then delete
/// the AppContainer profile.
pub(crate) fn remove(confinement: &Confinement) -> io::Result<Vec<String>> {
    // Not while another Core launches a worker in the same profile.
    let _removing = launch::LaunchLock::acquire()?;
    let sid = appcontainer::PackageSid::derive()?;
    let mut done: Vec<String> = appcontainer::revoke_paths(&sid, &confinement.filesystem)?
        .into_iter()
        .map(|path| format!("removed the worker's access entry from {path}"))
        .collect();
    if appcontainer::delete_profile(&sid)? {
        done.push(format!(
            "deleted the AppContainer profile {}",
            appcontainer::PROFILE_NAME
        ));
    }
    Ok(done)
}

/// Whether the Core itself runs inside a job object.
fn current_process_in_job() -> io::Result<bool> {
    let mut in_job = 0;
    // SAFETY: the current-process pseudo-handle and a null job handle ask
    // whether this process is in any job.
    let ok = unsafe { IsProcessInJob(GetCurrentProcess(), null_mut(), &mut in_job) };
    check(ok, "IsProcessInJob(self)")?;
    Ok(in_job != 0)
}

/// A job that kills its processes when the Core closes it, admits one
/// active process when child processes are denied, caps committed memory,
/// and turns an unhandled exception into an exit instead of a dialog.
fn create_job(confinement: &Confinement, ui_restricted: bool) -> io::Result<Handle> {
    let job = Handle::new(
        // SAFETY: no security attributes, unnamed job; the result is checked.
        unsafe { CreateJobObjectW(null(), null()) },
    )
    .ok_or_else(|| last_error("CreateJobObjectW"))?;

    // SAFETY: an all-zero JOBOBJECT_EXTENDED_LIMIT_INFORMATION is a valid
    // value of this plain C struct.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    if confinement.deny_child_processes {
        limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
    }
    limits.ProcessMemoryLimit =
        usize::try_from(confinement.limits.memory_bytes).unwrap_or(usize::MAX);
    // SAFETY: `job` is a valid job handle and the pointer and size describe
    // the structure that matches JobObjectExtendedLimitInformation.
    let ok = unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast::<c_void>(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    check(ok, "SetInformationJobObject(limits)")?;

    if ui_restricted {
        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_ALL,
        };
        // SAFETY: as above, with the UI restrictions structure.
        let ok = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectBasicUIRestrictions,
                (&raw const ui).cast::<c_void>(),
                size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )
        };
        check(ok, "SetInformationJobObject(ui)")?;
    }
    Ok(job)
}

/// Confirm the suspended worker's token is an AppContainer token for
/// exactly our package SID, with no capabilities, at low integrity; then
/// remove its privileges. Fails closed.
fn verify_worker_token(process: HANDLE, sid: &appcontainer::PackageSid) -> io::Result<()> {
    let mut raw = null_mut();
    // SAFETY: a valid process handle; `raw` receives a token handle that
    // `Handle` closes.
    let ok = unsafe { OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut raw) };
    check(ok, "OpenProcessToken(worker)")?;
    let token = Handle::new(raw).ok_or_else(|| last_error("OpenProcessToken(worker)"))?;

    if !is_app_container(&token)? {
        return Err(io::Error::other(
            "the worker is not running in an AppContainer",
        ));
    }
    let container = token_information(&token, TokenAppContainerSid)?;
    // SAFETY: the buffer holds a TOKEN_APPCONTAINER_INFORMATION whose SID
    // points into the same buffer.
    let token_sid =
        unsafe { (*container.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()).TokenAppContainer };
    // SAFETY: both are valid SIDs (checked non-null first).
    if token_sid.is_null() || unsafe { EqualSid(token_sid, sid.as_psid()) } == 0 {
        return Err(io::Error::other(
            "the worker runs in a different AppContainer",
        ));
    }
    let capabilities = token_information(&token, TokenCapabilities)?;
    // SAFETY: the buffer holds a TOKEN_GROUPS header.
    let count = unsafe { (*capabilities.as_ptr().cast::<TOKEN_GROUPS>()).GroupCount };
    if count != 0 {
        return Err(io::Error::other(format!(
            "the worker's token carries {count} capabilities, expected none"
        )));
    }
    let level = integrity_rid(&token)?;
    if level > SECURITY_MANDATORY_LOW_RID as u32 {
        return Err(io::Error::other(format!(
            "worker integrity level is {level:#x}, expected low or below"
        )));
    }
    remove_privileges(&token)
}

/// Confirm the worker was placed in its job at creation.
fn require_in_job(process: HANDLE, job: &Handle) -> io::Result<()> {
    let mut in_job = 0;
    // SAFETY: valid process and job handles.
    let ok = unsafe { IsProcessInJob(process, job.0, &mut in_job) };
    check(ok, "IsProcessInJob(worker)")?;
    if in_job == 0 {
        return Err(io::Error::other("the worker is not inside its job object"));
    }
    Ok(())
}

/// Confirm, as the kernel reports it, that the suspended worker cannot make
/// win32k system calls. This holds whether or not the job's UI restrictions
/// apply, but it is one property: it does not by itself prove every desktop
/// channel closed.
fn require_win32k_disabled(process: HANDLE) -> io::Result<()> {
    // SAFETY: an all-zero policy is a valid value of this plain C struct.
    let mut policy: PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY = unsafe { zeroed() };
    // SAFETY: a valid process handle and a buffer of the policy's size.
    let ok = unsafe {
        GetProcessMitigationPolicy(
            process,
            ProcessSystemCallDisablePolicy,
            (&raw mut policy).cast::<c_void>(),
            size_of::<PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY>(),
        )
    };
    check(ok, "GetProcessMitigationPolicy(worker)")?;
    // SAFETY: every bit pattern of the flags union is a valid u32.
    let flags = unsafe { policy.Anonymous.Flags };
    // Bit 0: DisallowWin32kSystemCalls.
    if flags & 1 == 0 {
        return Err(io::Error::other("the worker can make win32k system calls"));
    }
    Ok(())
}

fn is_app_container(token: &Handle) -> io::Result<bool> {
    let mut value = 0u32;
    let mut needed = 0u32;
    // SAFETY: TokenIsAppContainer is a DWORD; the buffer is exactly that.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenIsAppContainer,
            (&raw mut value).cast::<c_void>(),
            size_of::<u32>() as u32,
            &mut needed,
        )
    };
    check(ok, "GetTokenInformation(TokenIsAppContainer)")?;
    Ok(value != 0)
}

/// Whether the process `pid` runs with an AppContainer token or below
/// medium integrity. Used by the RPC server to refuse any client that is
/// not the interactive user at normal integrity.
pub(crate) fn is_restricted_process(pid: u32) -> io::Result<bool> {
    let process = Handle::new(
        // SAFETY: opens the process for a query only.
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) },
    )
    .ok_or_else(|| last_error("OpenProcess(client)"))?;
    let mut raw = null_mut();
    // SAFETY: a valid process handle; the token handle is owned by `Handle`.
    let ok = unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut raw) };
    check(ok, "OpenProcessToken(client)")?;
    let token = Handle::new(raw).ok_or_else(|| last_error("OpenProcessToken(client)"))?;
    Ok(is_app_container(&token)? || integrity_rid(&token)? < SECURITY_MANDATORY_MEDIUM_RID as u32)
}

/// A NUL-terminated UTF-16 copy of `value`.
fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn wide_str(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

/// A SID in its `S-1-...` string form.
fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut text = null_mut();
    // SAFETY: a valid SID; `text` receives a LocalAlloc'd string freed below.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut text) };
    check(ok, "ConvertSidToStringSidW")?;
    // SAFETY: `text` is a NUL-terminated UTF-16 string from the call above.
    let value = unsafe {
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
    };
    // SAFETY: allocated by ConvertSidToStringSidW.
    unsafe { LocalFree(text.cast::<c_void>()) };
    Ok(value)
}

fn remove_privileges(token: &Handle) -> io::Result<()> {
    let buffer = token_information(token, TokenPrivileges)?;
    // SAFETY: GetTokenInformation(TokenPrivileges) fills the buffer with a
    // TOKEN_PRIVILEGES header followed by PrivilegeCount entries; the buffer
    // is u64-aligned and large enough, as reported by the system.
    let count = unsafe { (*buffer.as_ptr().cast::<TOKEN_PRIVILEGES>()).PrivilegeCount } as usize;
    // SAFETY: as above; the entries start at the `Privileges` field.
    let entries: &[LUID_AND_ATTRIBUTES] = unsafe {
        std::slice::from_raw_parts(
            (&raw const (*buffer.as_ptr().cast::<TOKEN_PRIVILEGES>()).Privileges)
                .cast::<LUID_AND_ATTRIBUTES>(),
            count,
        )
    };
    let mut keep = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: looks up a well-known privilege name on the local system.
    let ok = unsafe { LookupPrivilegeValueW(null(), SE_CHANGE_NOTIFY_NAME, &mut keep) };
    check(ok, "LookupPrivilegeValueW")?;
    let removed: Vec<LUID_AND_ATTRIBUTES> = entries
        .iter()
        .filter(|entry| entry.Luid.LowPart != keep.LowPart || entry.Luid.HighPart != keep.HighPart)
        .map(|entry| LUID_AND_ATTRIBUTES {
            Luid: entry.Luid,
            Attributes: SE_PRIVILEGE_REMOVED,
        })
        .collect();
    if removed.is_empty() {
        return Ok(());
    }
    // TOKEN_PRIVILEGES has a one-element array; build a buffer of the right
    // size with the header followed by every entry.
    let mut request: Vec<u64> = vec![
        0;
        (size_of::<TOKEN_PRIVILEGES>()
            + removed.len() * size_of::<LUID_AND_ATTRIBUTES>())
        .div_ceil(8)
    ];
    let header = request.as_mut_ptr().cast::<TOKEN_PRIVILEGES>();
    // SAFETY: the buffer is zeroed, u64-aligned and large enough for the
    // header and `removed.len()` entries starting at `Privileges`.
    unsafe {
        (*header).PrivilegeCount = removed.len() as u32;
        let first = (&raw mut (*header).Privileges).cast::<LUID_AND_ATTRIBUTES>();
        for (index, entry) in removed.iter().enumerate() {
            first.add(index).write(*entry);
        }
    }
    // SAFETY: valid token handle and a well-formed TOKEN_PRIVILEGES buffer.
    let ok = unsafe { AdjustTokenPrivileges(token.0, 0, header, 0, null_mut(), null_mut()) };
    check(ok, "AdjustTokenPrivileges")?;
    // AdjustTokenPrivileges reports partial failure through GetLastError.
    // SAFETY: reads the calling thread's last-error value.
    let status = unsafe { GetLastError() };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

fn integrity_rid(token: &Handle) -> io::Result<u32> {
    let buffer = token_information(token, TokenIntegrityLevel)?;
    // SAFETY: the buffer holds a TOKEN_MANDATORY_LABEL whose SID points into
    // the same buffer; GetSidSubAuthority* read within that SID.
    unsafe {
        let label = &*buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>();
        let count = *GetSidSubAuthorityCount(label.Label.Sid);
        if count == 0 {
            return Err(io::Error::other("integrity SID has no sub-authority"));
        }
        Ok(*GetSidSubAuthority(label.Label.Sid, u32::from(count) - 1))
    }
}

/// Read variable-size token information into a u64-aligned buffer.
fn token_information(token: &Handle, class: i32) -> io::Result<Vec<u64>> {
    let mut needed = 0u32;
    // SAFETY: a size query with a null buffer; it fails with
    // ERROR_INSUFFICIENT_BUFFER and reports the size.
    unsafe { GetTokenInformation(token.0, class, null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(last_error("GetTokenInformation(size)"));
    }
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: the buffer is at least `needed` bytes long.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            class,
            buffer.as_mut_ptr().cast::<c_void>(),
            (buffer.len() * 8) as u32,
            &mut needed,
        )
    };
    check(ok, "GetTokenInformation")?;
    Ok(buffer)
}

#[derive(Debug)]
pub(crate) struct Guard {
    job: Handle,
    pid: u32,
}

impl Guard {
    pub(crate) fn kill_all(&self) -> io::Result<()> {
        // SAFETY: valid job handle owned by this guard.
        check(
            unsafe { TerminateJobObject(self.job.0, 1) },
            "TerminateJobObject",
        )
    }

    pub(crate) fn contains(&self, pid: u32) -> bool {
        if pid == self.pid {
            return true;
        }
        let Some(process) = Handle::new(
            // SAFETY: opens the process for a query only.
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) },
        ) else {
            return false;
        };
        let mut result = 0;
        // SAFETY: valid process and job handles.
        let ok = unsafe { IsProcessInJob(process.0, self.job.0, &mut result) };
        ok != 0 && result != 0
    }
}

/// A process watched through a handle, so that a reused process ID can never
/// be mistaken for it.
#[derive(Debug)]
pub(crate) struct Watched(Handle);

pub(crate) fn watch_process(pid: u32) -> io::Result<Watched> {
    // SAFETY: opens the process only to wait for its end.
    let raw = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    Handle::new(raw)
        .map(Watched)
        .ok_or_else(io::Error::last_os_error)
}

impl Watched {
    pub(crate) fn has_exited(&self) -> bool {
        // SAFETY: valid process handle; a zero timeout only polls.
        unsafe { WaitForSingleObject(self.0.0, 0) == WAIT_OBJECT_0 }
    }
}

pub(crate) fn process_exists(pid: u32) -> bool {
    let Some(process) = Handle::new(
        // SAFETY: opens the process for a query only.
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) },
    ) else {
        return false;
    };
    let mut code = 0u32;
    // SAFETY: valid process handle.
    let ok = unsafe { GetExitCodeProcess(process.0, &mut code) };
    ok != 0 && code == STILL_ACTIVE as u32
}

pub(crate) fn named_pipe_client_pid(pipe: RawHandle) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: `pipe` is a connected named pipe server handle owned by the
    // caller for the duration of the call.
    let ok = unsafe { GetNamedPipeClientProcessId(pipe as HANDLE, &mut pid) };
    check(ok, "GetNamedPipeClientProcessId")?;
    Ok(pid)
}

/// Read the token of the client connected to a named pipe server handle by
/// impersonating it, and classify it. The token is the client's own, so a
/// process ID that was reused after the client exited cannot be mistaken
/// for it. A client that connected at anonymous impersonation level has no
/// token to read, and that is an error.
pub(crate) fn inspect_pipe_client(pipe: RawHandle) -> io::Result<PipeClient> {
    let token = pipe_client_token(pipe)?;
    let client = token_information(&token, TokenUser)?;
    let own = current_user()?;
    // SAFETY: both SIDs point into buffers that live until the end of this
    // function.
    if unsafe { EqualSid(user_sid(&client), user_sid(&own)) } == 0 {
        return Ok(PipeClient::OtherUser);
    }
    if is_app_container(&token)? || integrity_rid(&token)? < SECURITY_MANDATORY_MEDIUM_RID as u32 {
        return Ok(PipeClient::Restricted);
    }
    Ok(PipeClient::SameUser)
}

fn pipe_client_token(pipe: RawHandle) -> io::Result<Handle> {
    // SAFETY: `pipe` is a connected named pipe server handle owned by the
    // caller for the duration of the call.
    let ok = unsafe { ImpersonateNamedPipeClient(pipe as HANDLE) };
    if ok == 0 && io::Error::last_os_error().raw_os_error() == Some(ERROR_CANNOT_IMPERSONATE as i32)
    {
        // A client that opened the pipe without security flags can be
        // impersonated only once something has been read from the pipe.
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "the client has not sent anything yet",
        ));
    }
    check(ok, "ImpersonateNamedPipeClient")?;
    let _revert = Revert;
    let mut raw = null_mut();
    // SAFETY: GetCurrentThread returns a pseudo-handle that needs no
    // closing; the access check uses the Core's own token (OpenAsSelf), and
    // the token handle is owned by `Handle`.
    let ok = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) };
    check(ok, "OpenThreadToken(client)")?;
    Handle::new(raw).ok_or_else(|| last_error("OpenThreadToken(client)"))
}

/// Ends the impersonation started in [`pipe_client_token`] on every path.
/// A thread of the Core's runtime left running as the client would be worse
/// than stopping, so a failure to revert aborts the process.
struct Revert;

impl Drop for Revert {
    fn drop(&mut self) {
        // SAFETY: ends impersonation on the calling thread.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

/// Whether the named pipe behind a client handle belongs to the current
/// user at medium integrity or above: owned by that user's SID, with no
/// mandatory label below medium. A pipe created by another account, or by a
/// low-integrity process of the same user, under the Core's name does not.
pub(crate) fn pipe_belongs_to_current_user(pipe: RawHandle) -> io::Result<bool> {
    let mut owner: PSID = null_mut();
    let mut label: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `pipe` is an open handle owned by the caller; `owner` and
    // `label` point into `descriptor`, which the system allocates and is
    // freed below.
    let status = unsafe {
        GetSecurityInfo(
            pipe as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            &mut label,
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let belongs = current_user().and_then(|own| {
        // SAFETY: `owner` points into `descriptor`, still allocated, and the
        // user SID into `own`.
        let owned = !owner.is_null() && unsafe { EqualSid(owner, user_sid(&own)) } != 0;
        // SAFETY: `label` is null or points into `descriptor`.
        Ok(owned && unsafe { label_rid(label) }? >= SECURITY_MANDATORY_MEDIUM_RID as u32)
    });
    // SAFETY: allocated by GetSecurityInfo.
    unsafe { LocalFree(descriptor) };
    belongs
}

/// The integrity level in a label SACL. An object without a mandatory label
/// is treated by Windows as medium.
///
/// # Safety
///
/// `label` is null or points to a valid ACL.
unsafe fn label_rid(label: *const ACL) -> io::Result<u32> {
    if label.is_null() {
        return Ok(SECURITY_MANDATORY_MEDIUM_RID as u32);
    }
    // SAFETY: the caller guarantees a valid ACL.
    let count = unsafe { (*label).AceCount };
    // The lowest label that applies to the object itself counts; an
    // inherit-only entry labels only children.
    let mut lowest: Option<u32> = None;
    for index in 0..u32::from(count) {
        let mut ace = null_mut();
        // SAFETY: `index` is below the ACL's entry count.
        let ok = unsafe { GetAce(label, index, &mut ace) };
        check(ok, "GetAce")?;
        // SAFETY: GetAce returned a pointer to an entry inside the ACL; a
        // mandatory label entry is a SYSTEM_MANDATORY_LABEL_ACE whose SID
        // starts at `SidStart`.
        unsafe {
            let header = &*ace.cast::<ACE_HEADER>();
            if u32::from(header.AceType) != SYSTEM_MANDATORY_LABEL_ACE_TYPE
                || u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0
            {
                continue;
            }
            let sid = (&raw mut (*ace.cast::<SYSTEM_MANDATORY_LABEL_ACE>()).SidStart).cast();
            if IsValidSid(sid) == 0 {
                return Err(io::Error::other("label entry holds an invalid SID"));
            }
            let count = *GetSidSubAuthorityCount(sid);
            if count == 0 {
                return Err(io::Error::other("label SID has no sub-authority"));
            }
            let rid = *GetSidSubAuthority(sid, u32::from(count) - 1);
            lowest = Some(lowest.map_or(rid, |seen| seen.min(rid)));
        }
    }
    Ok(lowest.unwrap_or(SECURITY_MANDATORY_MEDIUM_RID as u32))
}

/// The current process's TOKEN_USER, in a buffer for [`user_sid`].
fn current_user() -> io::Result<Vec<u64>> {
    let mut raw = null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
    // closing; the token handle is owned by `Handle`.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) };
    check(ok, "OpenProcessToken(self)")?;
    let token = Handle::new(raw).ok_or_else(|| last_error("OpenProcessToken(self)"))?;
    token_information(&token, TokenUser)
}

/// The user SID inside a TOKEN_USER buffer. The SID points into `buffer`
/// and is valid only while it lives.
fn user_sid(buffer: &[u64]) -> PSID {
    // SAFETY: the buffer holds a TOKEN_USER filled by GetTokenInformation.
    unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid }
}

/// Create a named pipe instance whose DACL grants access to the current user
/// only. Without an explicit descriptor Windows applies a default one that
/// also lets every account open the pipe for reading. The worker, which runs
/// as the same user at low integrity, is kept out by the medium label.
pub(crate) fn create_owner_only_pipe(
    options: &ServerOptions,
    name: &str,
) -> io::Result<NamedPipeServer> {
    let descriptor = OwnerOnlyDescriptor::new()?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: `attributes` is a valid SECURITY_ATTRIBUTES whose descriptor
    // outlives the call; CreateNamedPipeW copies what it needs.
    unsafe {
        options.create_with_security_attributes_raw(name, (&raw mut attributes).cast::<c_void>())
    }
}

/// A self-relative security descriptor owned by the current user, with a
/// protected DACL holding one entry, full access for that user, and a medium
/// mandatory label that refuses lower integrity levels. Freed on drop.
struct OwnerOnlyDescriptor(PSECURITY_DESCRIPTOR);

impl OwnerOnlyDescriptor {
    fn new() -> io::Result<Self> {
        let buffer = current_user()?;
        let sid_text = sid_to_string(user_sid(&buffer))?;

        // The owner is set explicitly: from an elevated token the default
        // owner would be the Administrators group, and clients check that
        // the pipe they open is owned by their own user. The medium label
        // with no-read-up, no-write-up and no-execute-up keeps every
        // process below medium integrity from opening the pipe at all.
        let sddl: Vec<u16> = format!("O:{sid_text}D:P(A;;GA;;;{sid_text})S:(ML;;NWNRNX;;;ME)")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: NUL-terminated SDDL string; the descriptor is freed on drop.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        check(ok, "ConvertStringSecurityDescriptorToSecurityDescriptorW")?;
        Ok(Self(descriptor))
    }
}

impl Drop for OwnerOnlyDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(self.0) };
    }
}

/// An owned Win32 handle, closed on drop.
#[derive(Debug)]
struct Handle(HANDLE);

// SAFETY: kernel handles may be used from any thread.
unsafe impl Send for Handle {}
// SAFETY: the wrapped handle is only passed to thread-safe Win32 calls.
unsafe impl Sync for Handle {}

impl Handle {
    fn new(raw: HANDLE) -> Option<Self> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Self(raw))
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is valid and owned by this value.
        unsafe { CloseHandle(self.0) };
    }
}

fn check(result: i32, what: &str) -> io::Result<()> {
    if result == 0 {
        Err(last_error(what))
    } else {
        Ok(())
    }
}

fn last_error(what: &str) -> io::Error {
    let error = io::Error::last_os_error();
    io::Error::new(error.kind(), format!("{what}: {error}"))
}
