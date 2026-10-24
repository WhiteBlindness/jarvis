//! What a client sees when the Core it talks to speaks another RPC version.
//!
//! A stand-in for the Core listens on the real endpoint type (a Unix socket
//! or a named pipe) and answers every request with a fixed line. The real
//! `jarvis-core` binary then runs against it.

use std::path::PathBuf;

use jarvis_core::config::Config;
use jarvis_core::rpc::client::{Client, ClientError};
use jarvis_core::rpc::{Endpoint, Listener};
use jarvis_protocol::{RpcRequest, TaskId};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::task::JoinHandle;

const CORE: &str = env!("CARGO_BIN_EXE_jarvis-core");

struct StandIn {
    _dir: tempfile::TempDir,
    config: PathBuf,
    endpoint: Endpoint,
    server: JoinHandle<()>,
}

impl Drop for StandIn {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// A listener that answers every request with `reply`.
fn stand_in_core(reply: &'static str) -> StandIn {
    let dir = tempfile::tempdir().unwrap();
    let pipe = format!("jarvis-test-{}", TaskId::new());
    let config = dir.path().join("jarvis.toml");
    let text = format!(
        r#"
database = {database:?}

[worker]
program = "python"

[fixtures]
root = {fixtures:?}

[workspace]
root = {workspace:?}

[rpc]
socket = {socket:?}
pipe = {pipe:?}

[policy]
"system.info" = "allow"
"#,
        database = dir.path().join("jarvis.db"),
        fixtures = dir.path().join("fixtures"),
        workspace = dir.path().join("workspace"),
        socket = dir.path().join("rpc").join("jarvis.sock"),
    );
    std::fs::write(&config, text).unwrap();
    let endpoint = Endpoint::from_config(&Config::load(&config).unwrap().rpc);
    let mut listener = Listener::bind(&endpoint).unwrap();
    let server = tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            tokio::spawn(async move {
                let (reader, mut writer) = tokio::io::split(stream);
                let mut lines = BufReader::new(reader).lines();
                while let Ok(Some(_request)) = lines.next_line().await {
                    if writer.write_all(reply.as_bytes()).await.is_err()
                        || writer.write_all(b"\n").await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    StandIn {
        _dir: dir,
        config,
        endpoint,
        server,
    }
}

/// A reply from a Core of the previous RPC version.
const OLD_CORE_REPLY: &str = r#"{"rpc":3,"type":"shutting_down"}"#;

#[tokio::test(flavor = "multi_thread")]
async fn the_cli_tells_a_person_which_versions_disagree() {
    let core = stand_in_core(OLD_CORE_REPLY);
    let output = tokio::process::Command::new(CORE)
        .args(["health", "--config"])
        .arg(&core.config)
        .output()
        .await
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(output.stdout.is_empty());
    assert!(
        stderr.contains("speaks RPC version 3") && stderr.contains("version 4"),
        "{stderr}"
    );
    assert!(stderr.contains("same build"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_names_both_versions_and_does_not_downgrade() {
    let core = stand_in_core(OLD_CORE_REPLY);
    let mut client = Client::connect(&core.endpoint).await.unwrap();
    let error = client.call(&RpcRequest::Health {}).await.unwrap_err();
    assert!(
        matches!(
            error,
            ClientError::VersionMismatch {
                found: 3,
                expected: 4
            }
        ),
        "{error:?}"
    );
    // The connection is still usable, and the answer is still refused.
    let again = client.call(&RpcRequest::Health {}).await.unwrap_err();
    assert!(matches!(again, ClientError::VersionMismatch { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn decoding_stays_strict_at_the_right_version() {
    for reply in [
        r#"{"rpc":4,"type":"shutting_down","extra":true}"#,
        r#"{"rpc":4,"type":"something_new"}"#,
        r#"{"type":"shutting_down"}"#,
    ] {
        let core = stand_in_core(reply);
        let mut client = Client::connect(&core.endpoint).await.unwrap();
        let error = client.call(&RpcRequest::Health {}).await.unwrap_err();
        assert!(
            matches!(error, ClientError::Invalid(_)),
            "{reply}: {error:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reply_of_the_right_version_is_accepted() {
    let core = stand_in_core(r#"{"rpc":4,"type":"shutting_down"}"#);
    let mut client = Client::connect(&core.endpoint).await.unwrap();
    let reply = client.call(&RpcRequest::Health {}).await.unwrap();
    assert_eq!(reply, jarvis_protocol::RpcResponse::ShuttingDown {});
}
