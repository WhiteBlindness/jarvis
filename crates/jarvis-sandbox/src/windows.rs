//! Windows containment: a job object, a low-integrity token without
//! privileges, and UI restrictions, all applied while the worker is still
//! suspended.
//!
//! Sequence (each step fails closed; on error the caller kills the still
//! suspended child):
//!
//! 1. The child is created with `CREATE_SUSPENDED | DETACHED_PROCESS`: it
//!    gets no console, so no console host process has to start inside the
//!    job (which would count against the process limit).
//! 2. A job object is created with kill-on-close, an active-process limit of
//!    one (no child processes), a per-process memory limit and
//!    die-on-unhandled-exception; breakaway is not allowed.
//! 3. If the child is not already in a job, the job also gets UI
//!    restrictions. (Windows refuses to nest a job that has UI restrictions
//!    under an existing job, which is the case under some terminals and CI
//!    runners.)
//! 4. The child is assigned to the job.
//! 5. The child's primary token is lowered to Low integrity and every
//!    privilege except `SeChangeNotifyPrivilege` is removed. Lowering the
//!    integrity of a token is always permitted; doing it before the first
//!    thread runs means no code in the worker ever runs with more.
//! 6. The integrity level is read back to confirm it took effect.
//! 7. The child's thread is resumed.

use std::ffi::c_void;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::io::RawHandle;
use std::ptr::{null, null_mut};

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID, LocalFree, STILL_ACTIVE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, AllocateAndInitializeSid, FreeSid, GetLengthSid, GetSidSubAuthority,
    GetSidSubAuthorityCount, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    PSECURITY_DESCRIPTOR, PSID, SE_CHANGE_NOTIFY_NAME, SE_PRIVILEGE_REMOVED, SECURITY_ATTRIBUTES,
    SECURITY_MANDATORY_LABEL_AUTHORITY, SID_AND_ATTRIBUTES, SetTokenInformation,
    TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES,
    TOKEN_QUERY, TOKEN_USER, TokenIntegrityLevel, TokenPrivileges, TokenUser,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_BASIC_UI_RESTRICTIONS,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicUIRestrictions,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::SystemServices::{
    JOB_OBJECT_UILIMIT_ALL, SE_GROUP_INTEGRITY, SECURITY_MANDATORY_LOW_RID,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, DETACHED_PROCESS, GetCurrentProcess, GetExitCodeProcess, OpenProcess,
    OpenProcessToken, OpenThread, PROCESS_QUERY_LIMITED_INFORMATION, ResumeThread,
    THREAD_SUSPEND_RESUME,
};

use crate::{Confinement, Contained};

pub(crate) fn prepare(
    command: &mut tokio::process::Command,
    _confinement: &Confinement,
) -> io::Result<()> {
    command.creation_flags(CREATE_SUSPENDED | DETACHED_PROCESS);
    Ok(())
}

pub(crate) fn contain(
    child: &tokio::process::Child,
    confinement: &Confinement,
) -> io::Result<Contained> {
    let limits = &confinement.limits;
    let pid = child
        .id()
        .ok_or_else(|| io::Error::other("worker exited before it could be contained"))?;
    let process = child
        .raw_handle()
        .ok_or_else(|| io::Error::other("worker has no process handle"))?
        as HANDLE;

    let job = Handle::new(
        // SAFETY: no security attributes, unnamed job; the result is checked.
        unsafe { CreateJobObjectW(null(), null()) },
    )
    .ok_or_else(|| last_error("CreateJobObjectW"))?;

    // SAFETY: an all-zero JOBOBJECT_EXTENDED_LIMIT_INFORMATION is a valid
    // value of this plain C struct.
    let mut limits_info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits_info.BasicLimitInformation.ActiveProcessLimit = 1;
    limits_info.ProcessMemoryLimit = usize::try_from(limits.memory_bytes).unwrap_or(usize::MAX);
    // SAFETY: `job` is a valid job handle and the pointer and size describe
    // the structure that matches JobObjectExtendedLimitInformation.
    let ok = unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&raw const limits_info).cast::<c_void>(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    check(ok, "SetInformationJobObject(limits)")?;

    let mut already_in_job = 0;
    // SAFETY: a null job handle asks whether the process is in any job.
    let ok = unsafe { IsProcessInJob(process, null_mut(), &mut already_in_job) };
    check(ok, "IsProcessInJob")?;
    let ui_restricted = already_in_job == 0;
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

    // SAFETY: both handles are valid; the process is suspended.
    let ok = unsafe { AssignProcessToJobObject(job.0, process) };
    check(ok, "AssignProcessToJobObject")?;

    lower_token(process)?;
    resume_threads(pid)?;

    let mut controls = vec![
        "job object (killed with the Core, no child processes)".to_owned(),
        format!("commit limit {} MiB", limits.memory_bytes / (1024 * 1024)),
        "low integrity".to_owned(),
        "privileges removed".to_owned(),
    ];
    if ui_restricted {
        controls.push("UI restrictions".to_owned());
    } else {
        controls.push("no UI restrictions (already inside a job)".to_owned());
    }
    Ok(Contained {
        inner: Guard { job, pid },
        description: controls.join(", "),
    })
}

/// Lower the child's primary token to Low integrity and remove its
/// privileges, then read the integrity level back.
fn lower_token(process: HANDLE) -> io::Result<()> {
    let mut raw = null_mut();
    // SAFETY: `process` is a valid process handle; `raw` receives a token
    // handle that `Handle` closes.
    let ok = unsafe {
        OpenProcessToken(
            process,
            TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut raw,
        )
    };
    check(ok, "OpenProcessToken")?;
    let token = Handle::new(raw).ok_or_else(|| last_error("OpenProcessToken"))?;

    let low = LowSid::new()?;
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: low.0,
            Attributes: SE_GROUP_INTEGRITY as u32,
        },
    };
    // SAFETY: the label points at a valid SID that outlives the call; the
    // length covers the structure and the SID.
    let ok = unsafe {
        SetTokenInformation(
            token.0,
            TokenIntegrityLevel,
            (&raw const label).cast::<c_void>(),
            size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(low.0),
        )
    };
    check(ok, "SetTokenInformation(TokenIntegrityLevel)")?;

    remove_privileges(&token)?;

    let level = integrity_rid(&token)?;
    if level != SECURITY_MANDATORY_LOW_RID as u32 {
        return Err(io::Error::other(format!(
            "worker integrity level is {level:#x}, expected low"
        )));
    }
    Ok(())
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

/// Resume every thread of the (suspended, single-threaded) child.
fn resume_threads(pid: u32) -> io::Result<()> {
    let snapshot = Handle::new(
        // SAFETY: a thread snapshot of the whole system; checked below.
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) },
    )
    .ok_or_else(|| last_error("CreateToolhelp32Snapshot"))?;
    // SAFETY: an all-zero THREADENTRY32 is valid; dwSize is set as required.
    let mut entry: THREADENTRY32 = unsafe { zeroed() };
    entry.dwSize = size_of::<THREADENTRY32>() as u32;
    let mut resumed = 0;
    // SAFETY: valid snapshot handle and a correctly sized entry.
    let mut more = unsafe { Thread32First(snapshot.0, &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid {
            let thread = Handle::new(
                // SAFETY: opens the thread by ID with only the resume right.
                unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) },
            )
            .ok_or_else(|| last_error("OpenThread"))?;
            // SAFETY: valid thread handle with THREAD_SUSPEND_RESUME.
            if unsafe { ResumeThread(thread.0) } == u32::MAX {
                return Err(last_error("ResumeThread"));
            }
            resumed += 1;
        }
        // SAFETY: as for Thread32First.
        more = unsafe { Thread32Next(snapshot.0, &mut entry) } != 0;
    }
    if resumed == 0 {
        return Err(io::Error::other("no thread found to resume"));
    }
    Ok(())
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

/// Create a named pipe instance whose DACL grants access to the current user
/// only. Without an explicit descriptor Windows applies a default one that
/// also lets every account open the pipe for reading. The worker, which runs
/// as the same user at low integrity, is still kept out by the pipe's default
/// medium integrity label.
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

/// A self-relative security descriptor with a protected DACL holding one
/// entry: full access for the current user. Freed on drop.
struct OwnerOnlyDescriptor(PSECURITY_DESCRIPTOR);

impl OwnerOnlyDescriptor {
    fn new() -> io::Result<Self> {
        let mut raw = null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
        // closing; the token handle is owned by `Handle`.
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) };
        check(ok, "OpenProcessToken(self)")?;
        let token = Handle::new(raw).ok_or_else(|| last_error("OpenProcessToken(self)"))?;
        let buffer = token_information(&token, TokenUser)?;
        // SAFETY: the buffer holds a TOKEN_USER whose SID points into the
        // same buffer, which lives until the end of this function.
        let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut text = null_mut();
        // SAFETY: valid SID; `text` receives a LocalAlloc'd string freed below.
        let ok = unsafe { ConvertSidToStringSidW(sid, &mut text) };
        check(ok, "ConvertSidToStringSidW")?;
        // SAFETY: `text` is a NUL-terminated UTF-16 string from the call above.
        let sid_text = unsafe {
            let mut len = 0;
            while *text.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
        };
        // SAFETY: allocated by ConvertSidToStringSidW.
        unsafe { LocalFree(text.cast::<c_void>()) };

        let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid_text})")
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

/// The Low mandatory label SID (S-1-16-4096), freed on drop.
struct LowSid(PSID);

impl LowSid {
    fn new() -> io::Result<Self> {
        let mut sid: PSID = null_mut();
        // SAFETY: builds a SID with one sub-authority; `sid` is freed by Drop.
        let ok = unsafe {
            AllocateAndInitializeSid(
                &SECURITY_MANDATORY_LABEL_AUTHORITY,
                1,
                SECURITY_MANDATORY_LOW_RID as u32,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut sid,
            )
        };
        check(ok, "AllocateAndInitializeSid")?;
        Ok(Self(sid))
    }
}

impl Drop for LowSid {
    fn drop(&mut self) {
        // SAFETY: allocated by AllocateAndInitializeSid.
        unsafe { FreeSid(self.0) };
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
