//! Build the worker's [`Confinement`] from configuration.
//!
//! The Core decides what the worker legitimately needs — read+execute on its
//! interpreter and the shared libraries that load it, read on its own source
//! — and nothing else: no network, no child processes, and no access to the
//! user's files. [`jarvis_sandbox`] enforces it per OS (ADRs 0013, 0014).

use std::path::{Path, PathBuf};

use jarvis_sandbox::{Confinement, Grant};

use crate::config::WorkerConfig;

/// Standard directories that hold an interpreter, its dynamic loader and the
/// C library across common Linux layouts. Granted read+execute only if they
/// exist; the user's profile is never among them.
#[cfg(target_os = "linux")]
const RUNTIME_ROOTS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/opt"];

/// Build the confinement for the worker described by `config`.
///
/// On Linux the filesystem grants drive Landlock; on Windows they drive the
/// AppContainer ACLs. On platforms without a filesystem mechanism the grants
/// are ignored and only the process-lifetime controls apply.
pub fn for_worker(config: &WorkerConfig) -> Confinement {
    let mut confinement = Confinement::locked_down(config.memory_limit_bytes);

    // The interpreter and the directories that hold it and its libraries.
    for root in runtime_roots(config) {
        confinement = confinement.grant(Grant::read_execute(root));
    }
    // The worker's own source tree (code, not user data).
    if let Some(cwd) = &config.cwd {
        confinement = confinement.grant(Grant::read(cwd.clone()));
    }
    confinement
}

/// The directory trees the worker may read and execute from.
fn runtime_roots(config: &WorkerConfig) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(program) = resolve_program(&config.program) {
        // The interpreter's own install prefix, wherever it lives (system,
        // a toolcache, or a per-user build), so only that subtree is exposed.
        if let Some(bin) = program.parent() {
            roots.push(bin.to_path_buf());
            if let Some(prefix) = bin.parent() {
                roots.push(prefix.to_path_buf());
            }
        }
    }
    #[cfg(target_os = "linux")]
    for root in RUNTIME_ROOTS {
        roots.push(PathBuf::from(root));
    }
    roots.sort();
    roots.dedup();
    roots.retain(|root| root.exists());
    roots
}

/// Resolve the worker program to an absolute, symlink-free path: a path with
/// a separator is canonicalised directly, a bare name is looked up on `PATH`.
fn resolve_program(program: &str) -> Option<PathBuf> {
    let direct = Path::new(program);
    if direct.components().count() > 1 || direct.is_absolute() {
        return direct.canonicalize().ok();
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find_map(|candidate| candidate.canonicalize().ok())
}
