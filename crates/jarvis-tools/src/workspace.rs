use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use jarvis_protocol::{RelativePath, WriteOutcome};

use crate::{ToolError, ToolErrorKind};

/// The only directory `workspace.write_file` can write into.
///
/// The root is opened once, as a directory handle, and every operation is
/// resolved beneath that handle by `cap-std`, which refuses absolute paths,
/// `..` past the root, and symlinks or junctions that lead outside it. So the
/// writer is structurally unable to reach a file outside the root, whatever
/// the path says and whatever is swapped on disk in between.
///
/// A write never goes through an existing file: the content is written to a
/// fresh temporary file (created with `create_new`) and renamed over the
/// target. Rename replaces the directory entry, so an existing symlink or hard
/// link at the target is replaced, not written through, and a reader sees
/// either the old or the new content.
#[derive(Debug, Clone)]
pub struct WorkspaceRoot {
    dir: Arc<Dir>,
    max_bytes: u64,
}

impl WorkspaceRoot {
    pub fn open(root: &Path, max_bytes: u64) -> io::Result<Self> {
        let dir = Dir::open_ambient_dir(root, ambient_authority())?;
        Ok(Self {
            dir: Arc::new(dir),
            max_bytes,
        })
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Write on Tokio's blocking pool.
    pub async fn write(
        &self,
        path: &RelativePath,
        content: &str,
    ) -> Result<WriteOutcome, ToolError> {
        let dir = Arc::clone(&self.dir);
        let path = path.clone();
        let content = content.to_owned();
        let max_bytes = self.max_bytes;
        tokio::task::spawn_blocking(move || write_blocking(&dir, &path, &content, max_bytes))
            .await
            .map_err(|_| ToolError::new(ToolErrorKind::Io, "workspace write did not complete"))?
    }
}

fn write_blocking(
    root: &Dir,
    path: &RelativePath,
    content: &str,
    max_bytes: u64,
) -> Result<WriteOutcome, ToolError> {
    if content.len() as u64 > max_bytes {
        return Err(ToolError::new(
            ToolErrorKind::TooLarge,
            format!("content for `{path}` exceeds the {max_bytes}-byte limit"),
        ));
    }
    let mut components: Vec<&str> = path.components().collect();
    let Some(name) = components.pop() else {
        return Err(ToolError::new(ToolErrorKind::AccessDenied, "empty path"));
    };

    // Walk to the parent one component at a time, beneath the root handle.
    let mut parent = root.try_clone().map_err(|error| io_error(path, &error))?;
    for component in components {
        parent = parent
            .open_dir(component)
            .map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => ToolError::new(
                    ToolErrorKind::NotFound,
                    format!("the parent directory of `{path}` does not exist in the workspace"),
                ),
                _ => resolve_error(path, &error),
            })?;
    }

    let created = match parent.symlink_metadata(name) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(denied(path, "is a symbolic link"));
        }
        Ok(meta) if meta.is_dir() => return Err(denied(path, "is a directory")),
        Ok(meta) if !meta.is_file() => return Err(denied(path, "is not a regular file")),
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => return Err(resolve_error(path, &error)),
    };

    // Starts with '.', so no tool path can ever name it.
    let temporary = format!(".jarvis-write-{}", uuid::Uuid::now_v7().simple());
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = parent
        .open_with(&temporary, &options)
        .map_err(|error| io_error(path, &error))?;
    let written = file
        .write_all(content.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written.and_then(|()| parent.rename(&temporary, &parent, name)) {
        let _ = parent.remove_file(&temporary);
        return Err(io_error(path, &error));
    }

    Ok(WriteOutcome {
        path: path.clone(),
        bytes: content.len() as u64,
        created,
    })
}

fn denied(path: &RelativePath, what: &str) -> ToolError {
    ToolError::new(
        ToolErrorKind::AccessDenied,
        format!("workspace target `{path}` {what}"),
    )
}

/// `cap-std` reports an attempt to leave the root as permission denied.
fn resolve_error(path: &RelativePath, error: &io::Error) -> ToolError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => ToolError::new(
            ToolErrorKind::AccessDenied,
            format!("`{path}` resolves outside the workspace or is not accessible"),
        ),
        io::ErrorKind::NotFound => ToolError::new(
            ToolErrorKind::NotFound,
            format!("`{path}` does not exist in the workspace"),
        ),
        _ => io_error(path, error),
    }
}

fn io_error(path: &RelativePath, error: &io::Error) -> ToolError {
    ToolError::new(
        ToolErrorKind::Io,
        format!("cannot write `{path}`: {}", error.kind()),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn path(value: &str) -> RelativePath {
        RelativePath::try_from(value.to_owned()).unwrap()
    }

    fn setup() -> (tempfile::TempDir, WorkspaceRoot) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("workspace");
        fs::create_dir_all(root.join("notes")).unwrap();
        fs::write(dir.path().join("outside.txt"), "outside").unwrap();
        let workspace = WorkspaceRoot::open(&root, 64).unwrap();
        (dir, workspace)
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".jarvis-write-"))
            .collect()
    }

    #[tokio::test]
    async fn creates_then_replaces_a_file() {
        let (dir, workspace) = setup();
        let first = workspace.write(&path("notes/a.txt"), "one").await.unwrap();
        assert!(first.created);
        assert_eq!(first.bytes, 3);
        let second = workspace.write(&path("notes/a.txt"), "two!").await.unwrap();
        assert!(!second.created);
        let target = dir.path().join("workspace/notes/a.txt");
        assert_eq!(fs::read_to_string(target).unwrap(), "two!");
        assert!(leftovers(&dir.path().join("workspace/notes")).is_empty());
    }

    #[tokio::test]
    async fn refuses_missing_parents_large_content_and_directories() {
        let (_dir, workspace) = setup();
        let kind = |p: &'static str, content: String| {
            let workspace = workspace.clone();
            async move { workspace.write(&path(p), &content).await.unwrap_err().kind }
        };
        assert_eq!(
            kind("missing/a.txt", "x".into()).await,
            ToolErrorKind::NotFound
        );
        assert_eq!(kind("a.txt", "x".repeat(65)).await, ToolErrorKind::TooLarge);
        assert_eq!(kind("notes", "x".into()).await, ToolErrorKind::AccessDenied);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_directory_leading_outside_is_refused() {
        let (dir, workspace) = setup();
        std::os::unix::fs::symlink(dir.path(), dir.path().join("workspace/escape")).unwrap();
        let error = workspace
            .write(&path("escape/outside.txt"), "pwned")
            .await
            .unwrap_err();
        assert_eq!(error.kind, ToolErrorKind::AccessDenied, "{error}");
        assert_eq!(
            fs::read_to_string(dir.path().join("outside.txt")).unwrap(),
            "outside"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_at_the_target_is_refused() {
        let (dir, workspace) = setup();
        std::os::unix::fs::symlink(
            dir.path().join("outside.txt"),
            dir.path().join("workspace/link.txt"),
        )
        .unwrap();
        let error = workspace
            .write(&path("link.txt"), "pwned")
            .await
            .unwrap_err();
        assert_eq!(error.kind, ToolErrorKind::AccessDenied);
        assert_eq!(
            fs::read_to_string(dir.path().join("outside.txt")).unwrap(),
            "outside"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hard_link_at_the_target_is_replaced_not_written_through() {
        let (dir, workspace) = setup();
        fs::hard_link(
            dir.path().join("outside.txt"),
            dir.path().join("workspace/hard.txt"),
        )
        .unwrap();
        workspace.write(&path("hard.txt"), "inside").await.unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("outside.txt")).unwrap(),
            "outside",
            "the other link keeps its content"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("workspace/hard.txt")).unwrap(),
            "inside"
        );
    }

    /// A directory swapped for a symlink while writes are in flight: every
    /// component is opened beneath the handle of the one before it, so no
    /// interleaving can send a write outside the root.
    #[cfg(unix)]
    #[tokio::test]
    async fn swapping_a_directory_for_a_symlink_mid_write_cannot_escape() {
        let (dir, workspace) = setup();
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let notes = dir.path().join("workspace/notes");
        let parked = dir.path().join("workspace/parked");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let swapper = {
            let stop = Arc::clone(&stop);
            let (notes, parked, outside) = (notes.clone(), parked.clone(), outside.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = fs::rename(&notes, &parked);
                    let _ = std::os::unix::fs::symlink(&outside, &notes);
                    let _ = fs::remove_file(&notes);
                    let _ = fs::rename(&parked, &notes);
                }
            })
        };
        for _ in 0..300 {
            let _ = workspace.write(&path("notes/race.txt"), "x").await;
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        swapper.join().unwrap();
        assert!(
            fs::read_dir(&outside).unwrap().next().is_none(),
            "a write escaped the workspace"
        );
    }

    // Windows refuses to rename a directory while a handle to it is open.
    #[cfg(unix)]
    #[tokio::test]
    async fn root_handle_survives_the_root_path_being_renamed() {
        let (dir, workspace) = setup();
        fs::rename(dir.path().join("workspace"), dir.path().join("moved")).unwrap();
        fs::create_dir_all(dir.path().join("workspace/notes")).unwrap();
        workspace.write(&path("notes/a.txt"), "x").await.unwrap();
        assert!(dir.path().join("moved/notes/a.txt").exists());
        assert!(!dir.path().join("workspace/notes/a.txt").exists());
    }

    /// A Windows junction is a reparse point that `cap-std` must not follow
    /// out of the root. Junctions need no special privilege to create.
    #[cfg(windows)]
    #[tokio::test]
    async fn junction_leading_outside_is_refused() {
        let (dir, workspace) = setup();
        let link = dir.path().join("workspace").join("junction");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(dir.path())
            .status()
            .unwrap();
        assert!(status.success(), "could not create the junction");
        let error = workspace
            .write(&path("junction/outside.txt"), "pwned")
            .await
            .unwrap_err();
        assert_eq!(error.kind, ToolErrorKind::AccessDenied, "{error}");
        assert_eq!(
            fs::read_to_string(dir.path().join("outside.txt")).unwrap(),
            "outside"
        );
    }
}
