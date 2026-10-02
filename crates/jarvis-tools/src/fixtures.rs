use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use jarvis_protocol::{FixtureContent, FixturePath};

use crate::{ToolError, ToolErrorKind};

/// The only directory `filesystem.read_fixture` can read from.
///
/// [`FixturePath`] already guarantees a plain relative path. This type adds
/// the filesystem checks: the target is resolved with symlinks followed and
/// must still be inside the canonical root, must be a regular file, must fit
/// the size limit and must be UTF-8.
#[derive(Debug, Clone)]
pub struct FixtureRoot {
    root: PathBuf,
    max_bytes: u64,
}

impl FixtureRoot {
    pub fn open(root: &Path, max_bytes: u64) -> io::Result<Self> {
        let root = root.canonicalize()?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fixture root is not a directory",
            ));
        }
        Ok(Self { root, max_bytes })
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Read a fixture on Tokio's blocking pool, so filesystem latency never
    /// stalls the async runtime.
    pub async fn read(&self, path: &FixturePath) -> Result<FixtureContent, ToolError> {
        let root = self.root.clone();
        let path = path.clone();
        let max_bytes = self.max_bytes;
        tokio::task::spawn_blocking(move || read_blocking(&root, &path, max_bytes))
            .await
            .map_err(|_| ToolError::new(ToolErrorKind::Io, "fixture read did not complete"))?
    }
}

fn read_blocking(
    root: &Path,
    path: &FixturePath,
    max_bytes: u64,
) -> Result<FixtureContent, ToolError> {
    let mut candidate = root.to_path_buf();
    candidate.extend(path.components());

    let resolved = candidate
        .canonicalize()
        .map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => ToolError::new(
                ToolErrorKind::NotFound,
                format!("fixture `{path}` does not exist"),
            ),
            _ => io_error(path, &error),
        })?;
    if !resolved.starts_with(root) {
        return Err(ToolError::new(
            ToolErrorKind::AccessDenied,
            format!("fixture `{path}` resolves outside the fixture directory"),
        ));
    }

    let not_a_file = || {
        ToolError::new(
            ToolErrorKind::AccessDenied,
            format!("fixture `{path}` is not a regular file"),
        )
    };
    // Check before opening: Windows refuses to open a directory as a file,
    // which would otherwise surface as an I/O error.
    let target = fs::metadata(&resolved).map_err(|error| io_error(path, &error))?;
    if !target.is_file() {
        return Err(not_a_file());
    }
    let file = File::open(&resolved).map_err(|error| io_error(path, &error))?;
    // Check the opened handle as well, in case the path changed in between.
    let metadata = file.metadata().map_err(|error| io_error(path, &error))?;
    if !metadata.is_file() {
        return Err(not_a_file());
    }
    let too_large = || {
        ToolError::new(
            ToolErrorKind::TooLarge,
            format!("fixture `{path}` exceeds the {max_bytes}-byte limit"),
        )
    };
    if metadata.len() > max_bytes {
        return Err(too_large());
    }

    // Read at most one byte past the limit, in case the file grew after the
    // metadata check.
    let mut buffer = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buffer)
        .map_err(|error| io_error(path, &error))?;
    if buffer.len() as u64 > max_bytes {
        return Err(too_large());
    }

    let content = String::from_utf8(buffer).map_err(|_| {
        ToolError::new(
            ToolErrorKind::NotText,
            format!("fixture `{path}` is not UTF-8 text"),
        )
    })?;
    Ok(FixtureContent {
        path: path.clone(),
        bytes: content.len() as u64,
        content,
    })
}

fn io_error(path: &FixturePath, error: &io::Error) -> ToolError {
    ToolError::new(
        ToolErrorKind::Io,
        format!("cannot read fixture `{path}`: {}", error.kind()),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn path(value: &str) -> FixturePath {
        FixturePath::try_from(value.to_owned()).unwrap()
    }

    fn setup() -> (tempfile::TempDir, FixtureRoot) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("fixtures");
        fs::create_dir_all(root.join("notes")).unwrap();
        fs::write(root.join("welcome.txt"), "hello\n").unwrap();
        fs::write(root.join("notes/today.md"), "# today\n").unwrap();
        fs::write(root.join("big.txt"), "x".repeat(64)).unwrap();
        fs::write(root.join("binary.bin"), [0xff, 0xfe, 0x00]).unwrap();
        fs::write(dir.path().join("outside.txt"), "secret").unwrap();
        let fixtures = FixtureRoot::open(&root, 32).unwrap();
        (dir, fixtures)
    }

    #[tokio::test]
    async fn reads_files_inside_the_root() {
        let (_dir, fixtures) = setup();
        let content = fixtures.read(&path("welcome.txt")).await.unwrap();
        assert_eq!(content.content, "hello\n");
        assert_eq!(content.bytes, 6);
        let nested = fixtures.read(&path("notes/today.md")).await.unwrap();
        assert_eq!(nested.content, "# today\n");
    }

    #[tokio::test]
    async fn reports_missing_large_binary_and_directory_targets() {
        let (_dir, fixtures) = setup();
        let kind = |p: &'static str| {
            let fixtures = fixtures.clone();
            async move { fixtures.read(&path(p)).await.unwrap_err().kind }
        };
        assert_eq!(kind("missing.txt").await, ToolErrorKind::NotFound);
        assert_eq!(kind("big.txt").await, ToolErrorKind::TooLarge);
        assert_eq!(kind("binary.bin").await, ToolErrorKind::NotText);
        assert_eq!(kind("notes").await, ToolErrorKind::AccessDenied);
    }

    #[tokio::test]
    async fn errors_do_not_reveal_host_paths() {
        let (dir, fixtures) = setup();
        let error = fixtures.read(&path("missing.txt")).await.unwrap_err();
        let host = dir.path().to_string_lossy().to_string();
        assert!(!error.message.contains(&host), "{}", error.message);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_escaping_the_root_is_denied() {
        let (dir, fixtures) = setup();
        std::os::unix::fs::symlink(
            dir.path().join("outside.txt"),
            dir.path().join("fixtures/escape.txt"),
        )
        .unwrap();
        let error = fixtures.read(&path("escape.txt")).await.unwrap_err();
        assert_eq!(error.kind, ToolErrorKind::AccessDenied);
    }

    #[test]
    fn root_must_be_a_directory() {
        let (dir, _) = setup();
        assert!(FixtureRoot::open(&dir.path().join("outside.txt"), 1).is_err());
        assert!(FixtureRoot::open(&dir.path().join("nope"), 1).is_err());
    }
}
