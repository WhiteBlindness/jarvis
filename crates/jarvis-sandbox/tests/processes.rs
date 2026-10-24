//! Process detection against the real OS: no fake process list, no game.
//!
//! The exit test copies a small system binary to a unique name, runs the
//! copy, and checks that the production function sees it while it runs and
//! stops seeing it once it has exited.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use jarvis_sandbox::processes::find_running;

/// A name nothing else on the machine uses. At most 15 bytes without the
/// extension, so that a Linux `comm` holds all of it.
fn unique_stem() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mixed = nanos ^ (u128::from(std::process::id()) << 40);
    format!("jv{:012x}", mixed & 0xffff_ffff_ffff)
}

fn exe_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_owned()
    }
}

/// Copy a small system binary to `dir/<file_name>` and start it for 30 s.
fn start_copy(dir: &Path, file_name: &str) -> (Child, PathBuf) {
    let target = dir.join(file_name);
    let (source, args): (&str, &[&str]) = if cfg!(windows) {
        (r"C:\Windows\System32\PING.EXE", &["-n", "30", "127.0.0.1"])
    } else {
        ("/bin/sleep", &["30"])
    };
    std::fs::copy(source, &target).unwrap();
    let child = Command::new(&target)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    (child, target)
}

fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn the_test_binarys_own_name_is_found() {
    let exe = std::env::current_exe().unwrap();
    let name = exe.file_name().unwrap().to_str().unwrap().to_owned();
    // Another name first, to show that the configured name that matched is
    // the one returned.
    let found = find_running(&["not-a-running-process.exe", &name]).unwrap();
    assert_eq!(found.as_deref(), Some(name.as_str()));
}

#[test]
fn matching_ignores_ascii_case_and_returns_the_configured_spelling() {
    let exe = std::env::current_exe().unwrap();
    let name = exe
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_ascii_uppercase();
    let found = find_running(&[&name]).unwrap();
    assert_eq!(found.as_deref(), Some(name.as_str()));
}

#[test]
fn a_name_nobody_runs_is_not_found() {
    let name = exe_name(&unique_stem());
    assert_eq!(find_running(&[&name]).unwrap(), None);
    assert_eq!(find_running(&[]).unwrap(), None);
}

#[test]
fn a_process_is_found_while_it_runs_and_not_after_it_exits() {
    let stem = unique_stem();
    let name = exe_name(&stem);
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(find_running(&[&name]).unwrap(), None, "not started yet");

    let (mut child, _target) = start_copy(dir.path(), &name);
    let seen = wait_until(|| find_running(&[&name]).unwrap().is_some());
    let found = find_running(&[&name]).unwrap();

    child.kill().unwrap();
    child.wait().unwrap();
    let gone = wait_until(|| find_running(&[&name]).unwrap().is_none());

    assert!(seen, "the running process was never detected");
    assert_eq!(found.as_deref(), Some(name.as_str()));
    assert!(gone, "the process was still reported after it exited");
}

#[cfg(target_os = "linux")]
#[test]
fn a_linux_name_is_compared_as_the_kernel_keeps_it() {
    // `comm` keeps 15 bytes, so the configured name is cut the same way.
    // The price is that two names with the same first 15 bytes are equal.
    let long = format!("{}-and-a-long-tail", unique_stem());
    assert!(long.len() > 15);
    let dir = tempfile::tempdir().unwrap();
    let (mut child, _target) = start_copy(dir.path(), &long);

    let same_start = format!("{}-a-different-tail", &long[..15]);
    let seen = wait_until(|| find_running(&[&long]).unwrap().is_some());
    let lookalike = find_running(&[&same_start]).unwrap();
    let shorter = find_running(&[&long[..14]]).unwrap();

    child.kill().unwrap();
    child.wait().unwrap();
    assert!(seen, "the long name was not found");
    assert_eq!(
        lookalike.as_deref(),
        Some(same_start.as_str()),
        "documented false positive"
    );
    assert_eq!(shorter, None, "14 bytes is not the 15 the kernel kept");
}

#[test]
fn a_watched_process_is_seen_to_exit() {
    // The system binary itself, not a fresh copy: running a file just
    // written can fail with "text file busy" on Linux while other tests fork.
    let (program, args): (&str, &[&str]) = if cfg!(windows) {
        (r"C:\Windows\System32\PING.EXE", &["-n", "30", "127.0.0.1"])
    } else {
        ("/bin/sleep", &["30"])
    };
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let watched = jarvis_sandbox::WatchedProcess::new(child.id()).unwrap();
    assert!(!watched.has_exited());
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(wait_until(|| watched.has_exited()));
}
