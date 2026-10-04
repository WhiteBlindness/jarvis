//! Starting the worker inside its AppContainer with one `CreateProcessW`.
//!
//! `std` and Tokio cannot pass a process-thread attribute list, so the worker
//! is created here. Every control is part of that one call, so there is no
//! moment in which the worker exists without them:
//!
//! - `SECURITY_CAPABILITIES`: the AppContainer, with no capabilities, so the
//!   Windows Filtering Platform blocks all of its network traffic, loopback
//!   included, and the package SID must be granted every file it opens.
//! - `CHILD_PROCESS_POLICY`: the worker may not create processes.
//! - `JOB_LIST`: the worker starts inside a job that kills it with the Core,
//!   allows one active process and caps its committed memory.
//! - `HANDLE_LIST`: only the three stdio pipe ends are inherited.
//! - `MITIGATION_POLICY`: process mitigations that need no code changes in
//!   CPython (see [`MITIGATIONS`]).
//!
//! The process is created suspended. Before its first thread runs, the Core
//! reads its token back (an AppContainer at low integrity, inside the job),
//! removes every privilege it does not need, and only then resumes it. Any
//! failure terminates the suspended process, which has run no code.

use std::ffi::OsStr;
use std::io;
use std::marker::PhantomData;
use std::mem::{size_of, size_of_val, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitStatus;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::watch;
use windows_sys::Win32::Foundation::{
    ERROR_ENVVAR_NOT_FOUND, GENERIC_READ, GENERIC_WRITE, HANDLE, STILL_ACTIVE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::{SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    GetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX,
    SetErrorMode,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DETACHED_PROCESS,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

use super::appcontainer::{self, PackageSid};
use super::{Guard, Handle, check, last_error, wide};
use crate::{Confinement, Contained, Spawned, WorkerCommand};

pub(crate) type Stdin = NamedPipeServer;
pub(crate) type Stdout = NamedPipeServer;
pub(crate) type Stderr = NamedPipeServer;

/// `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`: the new process (and its
/// token) may not create child processes.
const CHILD_PROCESS_RESTRICTED: u32 = 0x01;

/// Process mitigations, as `PROCESS_CREATION_MITIGATION_POLICY_*_ALWAYS_ON`
/// bits. Chosen so that a stock CPython still starts. Not set:
/// `BLOCK_NON_MICROSOFT_BINARIES` (CPython is not Microsoft-signed),
/// `PROHIBIT_DYNAMIC_CODE` (ctypes callbacks need it), `WIN32K_SYSTEM_CALL_
/// DISABLE` and `STRICT_HANDLE_CHECKS` (not yet validated with CPython).
const MITIGATIONS: u64 = (1 << 12) // HEAP_TERMINATE
    | (1 << 16) // BOTTOM_UP_ASLR
    | (1 << 20) // HIGH_ENTROPY_ASLR
    | (1 << 32) // EXTENSION_POINT_DISABLE (AppInit DLLs, legacy hooks)
    | (1 << 48) // FONT_DISABLE (no non-system fonts)
    | (1 << 52) // IMAGE_LOAD_NO_REMOTE (no DLLs from network shares)
    | (1 << 56); // IMAGE_LOAD_NO_LOW_LABEL (no DLLs written at low integrity)

pub(crate) const MITIGATION_NAMES: &str = "heap terminate, ASLR, no extension points, no \
     non-system fonts, no remote or low-label images";

pub(crate) fn spawn(command: &WorkerCommand, confinement: &Confinement) -> io::Result<Spawned> {
    if !confinement.deny_network {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a Windows worker always runs without network access",
        ));
    }
    let sid = PackageSid::ensure()?;
    appcontainer::grant_paths(&sid, &confinement.filesystem)?;

    // A job with UI restrictions cannot be nested under another job; the
    // Core may itself run inside one (some terminals and CI runners).
    let ui_restricted = !super::current_process_in_job()?;
    let job = super::create_job(confinement, ui_restricted)?;

    let (stdin, child_stdin) = pipe(Direction::ToChild)?;
    let (stdout, child_stdout) = pipe(Direction::FromChild)?;
    let (stderr, child_stderr) = pipe(Direction::FromChild)?;

    // Values the attribute list points at; they outlive the CreateProcessW
    // call, which the list's lifetime enforces.
    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: sid.as_psid(),
        Capabilities: null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let child_policy = CHILD_PROCESS_RESTRICTED;
    let mitigations = MITIGATIONS;
    let jobs = [job.0];
    let inherited = [child_stdin.0, child_stdout.0, child_stderr.0];

    let mut attributes = AttributeList::new(5)?;
    attributes.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities)?;
    if confinement.deny_child_processes {
        attributes.set(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &child_policy)?;
    }
    attributes.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
    attributes.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherited)?;
    attributes.set(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigations)?;

    // SAFETY: an all-zero STARTUPINFOEXW is valid; the fields that matter
    // are set below.
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = child_stdin.0;
    startup.StartupInfo.hStdOutput = child_stdout.0;
    startup.StartupInfo.hStdError = child_stderr.0;
    startup.lpAttributeList = attributes.as_ptr();

    let application = wide(command.program.as_os_str());
    let mut command_line = command_line(&command.program, &command.args)?;
    let environment = environment_block(&with_profile_variables(&command.env))?;
    let cwd = command.cwd.as_ref().map(|dir| wide(dir.as_os_str()));
    let flags = CREATE_SUSPENDED
        | DETACHED_PROCESS
        | EXTENDED_STARTUPINFO_PRESENT
        | CREATE_UNICODE_ENVIRONMENT;

    // The worker inherits the Core's error mode. Without these flags a
    // loader failure in the worker (a missing or unreadable DLL) would wait
    // on a system dialog nobody sees, instead of ending the process.
    // SAFETY: reads and sets this process's error mode; no memory involved.
    unsafe {
        SetErrorMode(
            GetErrorMode()
                | SEM_FAILCRITICALERRORS
                | SEM_NOGPFAULTERRORBOX
                | SEM_NOOPENFILEERRORBOX,
        )
    };

    // SAFETY: an all-zero PROCESS_INFORMATION is valid; CreateProcessW fills it.
    let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
    // SAFETY: every string is NUL-terminated (the command line is mutable,
    // as CreateProcessW requires), the environment block is a valid UTF-16
    // block, and the startup information carries an initialised attribute
    // list whose values are alive for the call. bInheritHandles is TRUE, but
    // the handle list limits inheritance to the three child pipe ends.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            1,
            flags,
            environment.as_ptr().cast(),
            cwd.as_ref().map_or(null(), |dir| dir.as_ptr()),
            (&raw const startup).cast::<STARTUPINFOW>(),
            &mut info,
        )
    };
    let created = check(created, "CreateProcessW").map_err(|error| {
        let mut context = launch_context(command);
        if error.raw_os_error() == Some(ERROR_ENVVAR_NOT_FOUND as i32) {
            context.push_str(&format!(
                "; starting an AppContainer needs {} in the Core's environment",
                PROFILE_VARIABLES.join(", ")
            ));
        }
        io::Error::new(error.kind(), format!("{error} ({context})"))
    });
    // The child holds its own copies now. Ours must close, or the Core would
    // never see end-of-file on the worker's output.
    drop(attributes);
    drop((child_stdin, child_stdout, child_stderr));
    created?;

    let process = Arc::new(Handle(info.hProcess));
    let thread = Handle(info.hThread);
    let pid = info.dwProcessId;

    // The worker is suspended and has run no code. Check what it got, strip
    // its privileges, then let it run. Any failure kills it.
    let started = super::verify_worker_token(process.0)
        .and_then(|()| super::require_in_job(process.0, &job))
        .and_then(|()| resume(&thread))
        .and_then(|()| Waiter::start(Arc::clone(&process)));
    let exit = match started {
        Ok(exit) => exit,
        Err(error) => {
            // SAFETY: a valid process handle with terminate access.
            unsafe { TerminateProcess(process.0, 1) };
            return Err(error);
        }
    };

    let mut controls = vec![
        format!(
            "AppContainer {} with no capabilities (no network)",
            appcontainer::PROFILE_NAME
        ),
        "low integrity".to_owned(),
        "privileges removed".to_owned(),
        "job object (killed with the Core)".to_owned(),
        format!(
            "commit limit {} MiB",
            confinement.limits.memory_bytes / (1024 * 1024)
        ),
        "stdio-only handle list".to_owned(),
        format!("mitigations: {MITIGATION_NAMES}"),
    ];
    if confinement.deny_child_processes {
        controls.push("no child processes".to_owned());
    }
    controls.push(if ui_restricted {
        "UI restrictions".to_owned()
    } else {
        "no UI restrictions (the Core is already inside a job)".to_owned()
    });

    Ok(Spawned {
        process: crate::Process {
            inner: Process {
                handle: process,
                pid,
                exit,
            },
        },
        contained: Contained {
            inner: Guard { job, pid },
            description: controls.join(", "),
        },
        stdin,
        stdout,
        stderr,
    })
}

fn resume(thread: &Handle) -> io::Result<()> {
    // SAFETY: the primary thread handle returned by CreateProcessW.
    if unsafe { ResumeThread(thread.0) } == u32::MAX {
        return Err(last_error("ResumeThread"));
    }
    Ok(())
}

/// A process-thread attribute list. The values given to [`set`] are stored
/// by pointer, so they must outlive the list: the `'a` lifetime makes the
/// compiler check that.
///
/// [`set`]: AttributeList::set
struct AttributeList<'a> {
    buffer: Vec<u64>,
    _values: PhantomData<&'a ()>,
}

impl<'a> AttributeList<'a> {
    fn new(count: u32) -> io::Result<Self> {
        let mut size = 0usize;
        // SAFETY: a size query with a null list; it fails and reports the
        // size needed.
        unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size) };
        if size == 0 {
            return Err(last_error("InitializeProcThreadAttributeList(size)"));
        }
        let mut buffer = vec![0u64; size.div_ceil(8)];
        // SAFETY: the buffer is at least `size` bytes and 8-byte aligned.
        let ok = unsafe {
            InitializeProcThreadAttributeList(buffer.as_mut_ptr().cast(), count, 0, &mut size)
        };
        check(ok, "InitializeProcThreadAttributeList")?;
        Ok(Self {
            buffer,
            _values: PhantomData,
        })
    }

    fn as_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buffer.as_mut_ptr().cast()
    }

    fn set<T>(&mut self, attribute: u32, value: &'a T) -> io::Result<()> {
        // SAFETY: an initialised list; `value` lives as long as the list, and
        // its size is passed exactly.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                attribute as usize,
                (value as *const T).cast(),
                size_of_val(value),
                null_mut(),
                null(),
            )
        };
        check(ok, "UpdateProcThreadAttribute")
    }
}

impl Drop for AttributeList<'_> {
    fn drop(&mut self) {
        // SAFETY: initialised by InitializeProcThreadAttributeList.
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
    }
}

#[derive(Clone, Copy)]
enum Direction {
    /// The Core writes, the worker reads (stdin).
    ToChild,
    /// The worker writes, the Core reads (stdout, stderr).
    FromChild,
}

/// One stdio pipe: the Core's overlapped server end, registered with Tokio,
/// and the worker's synchronous, inheritable client end. The server's DACL
/// admits only the current user, so the worker (whose package SID it does
/// not name) could not open another connection even if it learned the name;
/// it holds the one end it is given, by inheritance.
fn pipe(direction: Direction) -> io::Result<(NamedPipeServer, Handle)> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    let name = format!(
        r"\\.\pipe\jarvis-worker-{}-{}-{nanos:08x}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(1)
        .access_inbound(matches!(direction, Direction::FromChild))
        .access_outbound(matches!(direction, Direction::ToChild));
    let server = super::create_owner_only_pipe(&options, &name)?;

    let access = match direction {
        Direction::ToChild => GENERIC_READ | FILE_WRITE_ATTRIBUTES,
        Direction::FromChild => GENERIC_WRITE | FILE_READ_ATTRIBUTES,
    };
    let inheritable = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let path = wide(OsStr::new(&name));
    // SAFETY: a NUL-terminated pipe name; synchronous I/O (no overlapped
    // flag) for the child; the handle is owned by `Handle`.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            0,
            &inheritable,
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    let client = Handle::new(raw).ok_or_else(|| last_error("CreateFileW(worker pipe)"))?;
    // The server was registered with Tokio before the client connected, so
    // no read was scheduled and no write readiness reported. Completing the
    // (already satisfied) connect does both.
    connect_now(&server)?;
    Ok((server, client))
}

/// Complete `connect` on a server whose client has already opened it.
/// `ConnectNamedPipe` then succeeds at once, so one poll finishes it.
fn connect_now(server: &NamedPipeServer) -> io::Result<()> {
    let mut connect = std::pin::pin!(server.connect());
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match connect.as_mut().poll(&mut context) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => Err(io::Error::other(
            "the worker's pipe did not connect immediately",
        )),
    }
}

/// Build a command line that the Microsoft C runtime (and so CPython) splits
/// back into exactly `program` and `args`.
fn command_line(program: &Path, args: &[std::ffi::OsString]) -> io::Result<Vec<u16>> {
    let mut line = Vec::new();
    let program: Vec<u16> = program.as_os_str().encode_wide().collect();
    if program.contains(&u16::from(b'"')) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the worker program path contains a quote",
        ));
    }
    line.push(u16::from(b'"'));
    line.extend_from_slice(&program);
    line.push(u16::from(b'"'));
    for arg in args {
        line.push(u16::from(b' '));
        append_argument(&mut line, arg)?;
    }
    if line.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a worker argument contains a NUL character",
        ));
    }
    line.push(0);
    Ok(line)
}

fn append_argument(line: &mut Vec<u16>, arg: &OsStr) -> io::Result<()> {
    let arg: Vec<u16> = arg.encode_wide().collect();
    let quote = arg.is_empty()
        || arg
            .iter()
            .any(|&c| c == u16::from(b' ') || c == u16::from(b'\t'));
    if quote {
        line.push(u16::from(b'"'));
    }
    let mut backslashes = 0usize;
    for c in arg {
        if c == u16::from(b'\\') {
            backslashes += 1;
        } else {
            if c == u16::from(b'"') {
                // Escape the preceding backslashes and the quote itself.
                line.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes + 1));
            }
            backslashes = 0;
        }
        line.push(c);
    }
    if quote {
        // Backslashes before the closing quote must be doubled.
        line.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
        line.push(u16::from(b'"'));
    }
    Ok(())
}

/// Profile variables `CreateProcessW` reads from the supplied environment
/// block to set up an AppContainer process; without them it fails with
/// `ERROR_ENVVAR_NOT_FOUND`. They name directories in the user's profile,
/// which the worker cannot open.
const PROFILE_VARIABLES: [&str; 5] = [
    "APPDATA",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "USERPROFILE",
];

/// What a failed launch had to work with, for the error message: whether the
/// program and working directory exist, and which profile variables the
/// Core's environment lacks.
fn launch_context(command: &WorkerCommand) -> String {
    let missing: Vec<&str> = PROFILE_VARIABLES
        .into_iter()
        .filter(|name| std::env::var_os(name).is_none())
        .collect();
    format!(
        "program exists: {}, working directory exists: {}, missing profile variables: {}",
        command.program.is_file(),
        command.cwd.as_ref().is_none_or(|dir| dir.is_dir()),
        if missing.is_empty() {
            "none".to_owned()
        } else {
            missing.join(", ")
        }
    )
}

/// `env` plus the profile variables an AppContainer launch needs, taken
/// from the Core's environment when `env` does not set them.
fn with_profile_variables(
    env: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    let mut env = env.to_vec();
    for name in PROFILE_VARIABLES {
        let present = env
            .iter()
            .any(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case(name));
        if !present && let Some(value) = std::env::var_os(name) {
            env.push((name.into(), value));
        }
    }
    env
}

/// A sorted, double-NUL-terminated UTF-16 environment block holding exactly
/// `env`: nothing else is inherited from the Core.
fn environment_block(env: &[(std::ffi::OsString, std::ffi::OsString)]) -> io::Result<Vec<u16>> {
    let mut pairs: Vec<(Vec<u16>, Vec<u16>)> = Vec::with_capacity(env.len());
    for (key, value) in env {
        let key: Vec<u16> = key.encode_wide().collect();
        let value: Vec<u16> = value.encode_wide().collect();
        let invalid_key = key.is_empty() || key.contains(&0) || key[1..].contains(&u16::from(b'='));
        if invalid_key || value.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid worker environment variable",
            ));
        }
        pairs.push((key, value));
    }
    // Windows expects the block sorted case-insensitively by name.
    pairs.sort_by_key(|(key, _)| String::from_utf16_lossy(key).to_uppercase());
    let mut block = Vec::new();
    for (key, value) in pairs {
        block.extend_from_slice(&key);
        block.push(u16::from(b'='));
        block.extend_from_slice(&value);
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

/// Waits for the worker on a dedicated thread (one per worker) and
/// publishes its exit code.
struct Waiter;

impl Waiter {
    fn start(process: Arc<Handle>) -> io::Result<watch::Receiver<Option<u32>>> {
        let (sender, receiver) = watch::channel(None);
        std::thread::Builder::new()
            .name("jarvis-worker-exit".to_owned())
            .spawn(move || {
                // SAFETY: a valid process handle kept alive by the Arc.
                let exited = unsafe { WaitForSingleObject(process.0, INFINITE) } == WAIT_OBJECT_0;
                if exited && let Some(code) = exit_code(process.0) {
                    let _ = sender.send(Some(code));
                }
            })?;
        Ok(receiver)
    }
}

/// The exit code of a process that has exited, or `None` if it is running.
fn exit_code(process: HANDLE) -> Option<u32> {
    // SAFETY: a valid process handle; a zero timeout only polls.
    if unsafe { WaitForSingleObject(process, 0) } != WAIT_OBJECT_0 {
        return None;
    }
    let mut code = STILL_ACTIVE as u32;
    // SAFETY: a valid process handle.
    let ok = unsafe { GetExitCodeProcess(process, &mut code) };
    (ok != 0).then_some(code)
}

#[derive(Debug)]
pub(crate) struct Process {
    handle: Arc<Handle>,
    pid: u32,
    exit: watch::Receiver<Option<u32>>,
}

impl Process {
    pub(crate) fn id(&self) -> u32 {
        self.pid
    }

    pub(crate) async fn wait(&mut self) -> io::Result<ExitStatus> {
        loop {
            if let Some(code) = *self.exit.borrow_and_update() {
                return Ok(ExitStatus::from_raw(code));
            }
            if self.exit.changed().await.is_err() {
                // The waiting thread ended without a result; ask directly.
                return exit_code(self.handle.0)
                    .map(ExitStatus::from_raw)
                    .ok_or_else(|| io::Error::other("lost track of the worker process"));
            }
        }
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        Ok(exit_code(self.handle.0).map(ExitStatus::from_raw))
    }

    pub(crate) fn start_kill(&mut self) -> io::Result<()> {
        if exit_code(self.handle.0).is_some() {
            return Ok(());
        }
        // SAFETY: a valid process handle with terminate access.
        check(
            unsafe { TerminateProcess(self.handle.0, 1) },
            "TerminateProcess",
        )
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // Like `kill_on_drop`: a worker nobody holds any more must not run.
        let _ = self.start_kill();
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    fn line(args: &[&str]) -> String {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let mut line =
            command_line(Path::new(r"C:\Program Files\Python\python.exe"), &args).unwrap();
        line.pop();
        String::from_utf16(&line).unwrap()
    }

    #[test]
    fn arguments_are_quoted_for_the_c_runtime() {
        assert_eq!(
            line(&["-m", "jarvis_worker"]),
            r#""C:\Program Files\Python\python.exe" -m jarvis_worker"#
        );
        assert_eq!(
            line(&["a b", ""]),
            r#""C:\Program Files\Python\python.exe" "a b" """#
        );
        assert_eq!(
            line(&[r#"say "hi""#, r"a b\", r#"a\"b"#]),
            r#""C:\Program Files\Python\python.exe" "say \"hi\"" "a b\\" a\\\"b"#
        );
    }

    #[test]
    fn the_environment_block_holds_only_what_was_given() {
        let env = vec![
            (OsString::from("SYSTEMROOT"), OsString::from(r"C:\Windows")),
            (OsString::from("PATH"), OsString::from(r"C:\Python")),
        ];
        let block = environment_block(&env).unwrap();
        let text = String::from_utf16(&block).unwrap();
        assert_eq!(text, "PATH=C:\\Python\0SYSTEMROOT=C:\\Windows\0\0");
        assert_eq!(environment_block(&[]).unwrap(), vec![0, 0]);
        let bad = vec![(OsString::from("A=B"), OsString::from("x"))];
        assert!(environment_block(&bad).is_err());
    }
}
