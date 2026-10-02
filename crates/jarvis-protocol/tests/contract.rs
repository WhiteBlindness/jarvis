//! Contract tests against the shared fixtures in `tests/protocol/`. The
//! Python worker's test suite checks the same files.

use std::fs;
use std::path::{Path, PathBuf};

use jarvis_protocol::{
    DecodeError, decode_core_message, decode_worker_message, encode_core_message,
    encode_worker_message,
};
use serde_json::Value;

fn fixtures(subdir: &str) -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/protocol")
        .join(subdir);
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no fixtures in {}", dir.display());
    files
}

fn compact(path: &Path) -> (Value, Vec<u8>) {
    let value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let bytes = serde_json::to_vec(&value).unwrap();
    (value, bytes)
}

#[test]
fn worker_fixtures_decode_and_reencode_identically() {
    for path in fixtures("worker") {
        let (value, bytes) = compact(&path);
        let message = decode_worker_message(&bytes)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let encoded: Value =
            serde_json::from_slice(&encode_worker_message(&message).unwrap()).unwrap();
        assert_eq!(encoded, value, "{}", path.display());
    }
}

#[test]
fn core_fixtures_decode_and_reencode_identically() {
    for path in fixtures("core") {
        let (value, bytes) = compact(&path);
        let message = decode_core_message(&bytes)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let encoded: Value =
            serde_json::from_slice(&encode_core_message(&message).unwrap()).unwrap();
        assert_eq!(encoded, value, "{}", path.display());
    }
}

fn check_invalid(subdir: &str, decode: fn(&[u8]) -> Result<(), DecodeError>) {
    for path in fixtures(subdir) {
        let (case, _) = compact(&path);
        let frame = case["frame"].as_str().expect("frame must be a string");
        let expected = case["error"].as_str().expect("error must be a string");
        let error = decode(frame.as_bytes())
            .expect_err(&format!("{} decoded but must fail", path.display()));
        assert_eq!(error.code().as_str(), expected, "{}", path.display());
    }
}

#[test]
fn invalid_worker_frames_are_rejected_with_expected_code() {
    check_invalid("invalid/worker", |frame| {
        decode_worker_message(frame).map(|_| ())
    });
}

#[test]
fn invalid_core_frames_are_rejected_with_expected_code() {
    check_invalid("invalid/core", |frame| {
        decode_core_message(frame).map(|_| ())
    });
}
