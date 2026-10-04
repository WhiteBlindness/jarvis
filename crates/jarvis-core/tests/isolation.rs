//! The start-up isolation check: it passes under the real confinement and
//! fails, closed, when a boundary is missing. Needs a Python 3.11+
//! interpreter, named by `JARVIS_TEST_PYTHON` or found as `python3`
//! (`python` on Windows).

use std::path::{Path, PathBuf};
use std::time::Duration;

use jarvis_core::config::WorkerConfig;
use jarvis_core::isolation::{self, IsolationError};

fn python() -> String {
    std::env::var("JARVIS_TEST_PYTHON")
        .unwrap_or_else(|_| if cfg!(windows) { "python" } else { "python3" }.to_owned())
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives two levels below the repository root")
        .to_path_buf()
}

fn worker() -> WorkerConfig {
    WorkerConfig {
        program: python(),
        args: vec!["-m".to_owned(), "jarvis_worker".to_owned()],
        cwd: Some(repo().join("services/intelligence-python/src")),
        handshake_timeout: Duration::from_secs(10),
        memory_limit_bytes: 512 * 1024 * 1024,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_real_confinement_passes_every_check() {
    let scratch = tempfile::tempdir().unwrap();
    let launch = isolation::launch(&worker()).unwrap();
    let verification = isolation::verify(&launch, scratch.path())
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let names: Vec<_> = verification.checks.iter().map(|c| c.name).collect();
    assert_eq!(
        names,
        [
            "no loopback TCP",
            "no loopback UDP",
            "no access to the Core's files",
            "no child processes"
        ]
    );
    assert!(verification.checks.iter().all(|c| c.passed));
    // The canary is gone again.
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_missing_boundary_is_detected() {
    let scratch = tempfile::tempdir().unwrap();
    let mut launch = isolation::launch(&worker()).unwrap();
    // No filesystem boundary and network allowed: the probe can read the
    // canary and reach the Core's listener, and the check must say so.
    launch.confinement.filesystem.clear();
    launch.confinement.deny_network = false;
    match isolation::verify(&launch, scratch.path()).await {
        Err(IsolationError::NotEnforced(checks)) => {
            let failed: Vec<_> = checks
                .iter()
                .filter(|c| !c.passed)
                .map(|c| c.name)
                .collect();
            assert_eq!(
                failed,
                [
                    "no loopback TCP",
                    "no loopback UDP",
                    "no access to the Core's files"
                ]
            );
        }
        other => panic!("expected the check to fail, got {other:?}"),
    }
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_with_network_access_is_refused() {
    // An AppContainer worker always runs without network; asking for
    // network access is refused rather than silently ignored.
    let scratch = tempfile::tempdir().unwrap();
    let mut launch = isolation::launch(&worker()).unwrap();
    launch.confinement.deny_network = false;
    assert!(matches!(
        isolation::verify(&launch, scratch.path()).await,
        Err(IsolationError::Spawn(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_probe_that_cannot_run_fails_closed() {
    // A program that is not an interpreter produces no report.
    let scratch = tempfile::tempdir().unwrap();
    let mut launch = isolation::launch(&worker()).unwrap();
    launch.command.program = isolation::resolve_program(if cfg!(windows) { "cmd" } else { "true" })
        .expect("a basic system program");
    let result = isolation::verify(&launch, scratch.path()).await;
    assert!(
        matches!(
            result,
            Err(IsolationError::Probe(_) | IsolationError::Spawn(_))
        ),
        "{result:?}"
    );
}
