//! End-to-end tests of the model broker: the real `jarvis-core` binary with
//! `examples/fake_model_server.rs` in place of `llama-server`, driven by raw
//! RPC frames. The fake server plays hostile, broken and dying servers, so
//! these tests check that model output stays untrusted and bounded, that a
//! reply can be cancelled, that a dead server is replaced, and that the chat
//! operations decode strictly. They need Python 3.11+ for the Core's worker,
//! as `tests/process.rs` does.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use jarvis_core::config::Config;
use jarvis_core::rpc::Endpoint;
use jarvis_core::store::{Store, text_sha256};
use jarvis_protocol::TaskId;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

const CORE: &str = env!("CARGO_BIN_EXE_jarvis-core");
const WAIT: Duration = Duration::from_secs(30);
/// The largest reply the Core keeps (`inference::MAX_REPLY_BYTES`).
const MAX_REPLY_BYTES: usize = 64 * 1024;

fn repo() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .expect("crate lives two levels below the repository root")
        .to_path_buf()
}

fn python() -> String {
    std::env::var("JARVIS_TEST_PYTHON")
        .unwrap_or_else(|_| if cfg!(windows) { "python" } else { "python3" }.to_owned())
}

/// `cargo test` builds the examples next to the test binaries' directory.
fn fake_server() -> PathBuf {
    let core = Path::new(CORE);
    let name = format!("fake_model_server{}", std::env::consts::EXE_SUFFIX);
    let path = core.parent().unwrap().join("examples").join(name);
    assert!(
        path.exists(),
        "build the examples first (`cargo test` without `--test`, or `cargo build --examples`): {}",
        path.display()
    );
    path
}

struct Chat {
    dir: tempfile::TempDir,
    endpoint: Endpoint,
    core: Child,
    runtime: tokio::runtime::Runtime,
}

impl Chat {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let model = dir.path().join("model.gguf");
        std::fs::write(&model, b"not a model").unwrap();
        let sha256 = text_sha256("not a model").as_str().to_owned();
        let pipe = format!("jarvis-chat-test-{}", TaskId::new());
        let text = format!(
            r#"
database = {database:?}

[worker]
program = {python:?}
args = ["-m", "jarvis_worker"]
cwd = {cwd:?}

[fixtures]
root = {fixtures:?}

[workspace]
root = {workspace:?}

[rpc]
socket = {socket:?}
pipe = {pipe:?}
allow_shutdown = true

[policy]
"system.info" = "allow"

[inference]
server = {server:?}
persona = {persona:?}
chat_database = {chats:?}
context_size = 4096
max_reply_tokens = 256
load_on_start = false
load_timeout_ms = 20000
reply_timeout_ms = 60000

[inference.primary]
name = "fake"
path = {model:?}
sha256 = {sha256:?}
gpu_layers = 0
"#,
            database = dir.path().join("jarvis.db"),
            python = python(),
            cwd = repo().join("services/intelligence-python/src"),
            fixtures = repo().join("tests/fixtures/files"),
            workspace = dir.path().join("workspace"),
            socket = dir.path().join("rpc").join("jarvis.sock"),
            server = fake_server(),
            persona = repo().join("config/donna/persona.md"),
            chats = dir.path().join("chat.db"),
        );
        let config = dir.path().join("jarvis.toml");
        std::fs::write(&config, text).unwrap();
        let endpoint = Endpoint::from_config(&Config::load(&config).unwrap().rpc);
        let log = std::fs::File::create(dir.path().join("core.log")).unwrap();
        let mut core = Command::new(CORE)
            .args(["serve", "--config"])
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(log)
            .spawn()
            .unwrap();
        let stdout = core.stdout.take().unwrap();
        let (lines, ready) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if lines.send(line).is_err() {
                    return;
                }
            }
        });
        let first = ready.recv_timeout(WAIT);
        let chat = Self {
            dir,
            endpoint,
            core,
            runtime: tokio::runtime::Runtime::new().unwrap(),
        };
        assert!(
            first
                .as_deref()
                .is_ok_and(|line| line.starts_with("ready ")),
            "the Core did not become ready: {}",
            chat.log()
        );
        chat
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("core.log")).unwrap_or_default()
    }

    /// Send one raw frame and read the one reply.
    fn raw(&self, frame: &str) -> Value {
        self.runtime.block_on(async {
            let stream = jarvis_core::rpc::transport::connect(&self.endpoint)
                .await
                .unwrap();
            let (reader, mut writer) = tokio::io::split(stream);
            writer.write_all(frame.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            let mut lines = tokio::io::BufReader::new(reader).lines();
            let line = tokio::time::timeout(WAIT, lines.next_line())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            serde_json::from_str(&line).unwrap()
        })
    }

    fn call(&self, mut request: Value) -> Value {
        request["rpc"] = json!(4);
        self.raw(&request.to_string())
    }

    fn send(&self, text: &str) -> String {
        let turn = self.call(json!({
            "type": "chat_send", "conversation_id": null, "text": text, "language": "en"
        }));
        assert_eq!(turn["type"], "chat_turn", "{turn}");
        turn["turn_id"].as_str().unwrap().to_owned()
    }

    fn poll(&self, turn: &str, cursor: u64) -> Value {
        self.call(json!({"type": "chat_poll", "turn_id": turn, "cursor": cursor, "wait_ms": 2000}))
    }

    /// Poll until the reply ends; the whole text and the final delta.
    fn finish(&self, turn: &str) -> (String, Value) {
        let deadline = Instant::now() + WAIT;
        let (mut text, mut cursor) = (String::new(), 0);
        loop {
            let delta = self.poll(turn, cursor);
            assert_eq!(delta["type"], "chat_delta", "{delta}");
            text.push_str(delta["text"].as_str().unwrap());
            cursor = delta["next_cursor"].as_u64().unwrap();
            if delta["status"] != "streaming" {
                return (text, delta);
            }
            assert!(
                Instant::now() < deadline,
                "the reply never ended: {}",
                self.log()
            );
        }
    }

    fn state(&self) -> Value {
        self.call(json!({"type": "inference_status"}))["state"].clone()
    }

    fn loads(&self) -> usize {
        Store::open_read_only(&self.dir.path().join("jarvis.db"))
            .unwrap()
            .audit_events(None, 10_000)
            .unwrap()
            .iter()
            .filter(|e| e.event.name() == "inference_loaded")
            .count()
    }
}

impl Drop for Chat {
    fn drop(&mut self) {
        let _ = self.call(json!({"type": "shutdown"}));
        let deadline = Instant::now() + WAIT;
        while self.core.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.core.kill();
        let _ = self.core.wait();
    }
}

#[test]
fn model_output_is_untrusted_and_bounded() {
    let chat = Chat::start();

    let (text, done) = chat.finish(&chat.send("hello"));
    assert_eq!(done["status"], "complete", "{done}");
    assert_eq!(text, "Olá mundo");

    // Terminal escapes and invisible characters never reach a client.
    let (text, done) = chat.finish(&chat.send("SCENARIO:hostile"));
    assert_eq!(done["status"], "complete", "{done}");
    assert!(text.contains("red") && text.contains("hidden"), "{text:?}");
    for hidden in ['\u{1b}', '\u{202e}', '\u{200b}'] {
        assert!(!text.contains(hidden), "{text:?}");
    }

    // An unreadable event fails the reply, keeps what came before, and the
    // server stays in use.
    let (text, done) = chat.finish(&chat.send("SCENARIO:garbage"));
    assert_eq!(done["status"], "failed", "{done}");
    assert!(
        done["error"].as_str().unwrap().contains("unreadable"),
        "{done}"
    );
    assert_eq!(text, "first");

    // A server error is shown on one line, without control characters.
    let (_, done) = chat.finish(&chat.send("SCENARIO:error"));
    assert_eq!(done["status"], "failed", "{done}");
    let error = done["error"].as_str().unwrap();
    assert!(error.contains("boom"), "{error:?}");
    assert!(!error.chars().any(char::is_control), "{error:?}");

    // A stream that ends without its end marker is cut, not complete.
    let (text, done) = chat.finish(&chat.send("SCENARIO:cut"));
    assert_eq!(done["status"], "failed", "{done}");
    assert!(
        done["error"]
            .as_str()
            .unwrap()
            .contains("before the reply was finished"),
        "{done}"
    );
    assert_eq!(text, "half");

    // A reply stopped by the token limit is cut short, not complete, even
    // though the server ends the stream normally.
    let (text, done) = chat.finish(&chat.send("SCENARIO:length"));
    assert_eq!(done["status"], "failed", "{done}");
    assert!(
        done["error"].as_str().unwrap().contains("length limit"),
        "{done}"
    );
    assert_eq!(text, "partial");
    assert!(done["proposal"].is_null(), "{done}");

    // A reply that grows past the limit is cut and fails.
    let (text, done) = chat.finish(&chat.send("SCENARIO:huge"));
    assert_eq!(done["status"], "failed", "{done}");
    assert!(
        done["error"].as_str().unwrap().contains("too long"),
        "{done}"
    );
    assert!(text.len() <= MAX_REPLY_BYTES, "{}", text.len());

    let (text, done) = chat.finish(&chat.send("hello again"));
    assert_eq!(done["status"], "complete", "{done}");
    assert_eq!(text, "Olá mundo");
    assert_eq!(chat.loads(), 1, "{}", chat.log());
}

#[test]
fn a_reply_can_be_cancelled_and_a_dead_server_is_replaced() {
    let chat = Chat::start();

    let turn = chat.send("SCENARIO:slow");
    let deadline = Instant::now() + WAIT;
    while chat.poll(&turn, 0)["text"].as_str().unwrap().is_empty() {
        assert!(Instant::now() < deadline, "no text: {}", chat.log());
    }
    let cancelled = chat.call(json!({"type": "chat_cancel", "turn_id": turn}));
    assert_eq!(cancelled["status"], "cancelled", "{cancelled}");
    let kept = cancelled["text"].as_str().unwrap().to_owned();
    assert!(kept.starts_with("lento"), "{kept:?}");
    // Cancelling again changes nothing, and the stored reply keeps its text.
    let again = chat.call(json!({"type": "chat_cancel", "turn_id": turn}));
    assert_eq!(again["status"], "cancelled", "{again}");
    assert_eq!(chat.poll(&turn, 0)["text"], kept.as_str());
    assert_eq!(chat.state(), "ready");

    // A turn that never existed.
    let unknown = chat.call(json!({
        "type": "chat_cancel", "turn_id": "01928f5e-7c41-7a80-a192-adbecfd0e1f2"
    }));
    assert_eq!(unknown["code"], "not_found", "{unknown}");

    // The server dies in the middle of a reply: the reply fails, and the next
    // message starts a new server.
    let (text, done) = chat.finish(&chat.send("SCENARIO:die"));
    assert_eq!(done["status"], "failed", "{done}");
    assert!(text.starts_with("about to"), "{text:?}");
    let (text, done) = chat.finish(&chat.send("hello"));
    assert_eq!(done["status"], "complete", "{done}: {}", chat.log());
    assert_eq!(text, "Olá mundo");
    assert_eq!(chat.loads(), 2, "{}", chat.log());
}

#[test]
fn the_chat_operations_decode_strictly() {
    let chat = Chat::start();
    let turn = chat.send("hello");
    let (text, _) = chat.finish(&turn);
    assert_eq!(text, "Olá mundo");

    // A cursor inside a character, or past the end, is refused.
    for cursor in [3, 1_000] {
        let reply = chat.poll(&turn, cursor);
        assert_eq!(reply["code"], "malformed_request", "{cursor}: {reply}");
    }
    assert_eq!(chat.poll(&turn, 4)["text"], " mundo");

    // Retention takes only the listed periods.
    for days in [1, 5, 366] {
        let reply = chat.call(json!({"type": "set_retention", "days": days}));
        assert_eq!(reply["code"], "malformed_request", "{days}: {reply}");
    }
    let set = chat.call(json!({"type": "set_retention", "days": 7}));
    assert_eq!(set["retention_days"], 7, "{set}");

    let refused = [
        // Unknown fields, missing fields, wrong types and empty text.
        r#"{"rpc":4,"type":"chat_send","conversation_id":null,"text":"hi","language":"en","tools":[]}"#,
        r#"{"rpc":4,"type":"chat_send","text":"hi","language":"en"}"#,
        r#"{"rpc":4,"type":"chat_send","conversation_id":null,"text":"","language":"en"}"#,
        r#"{"rpc":4,"type":"chat_send","conversation_id":null,"text":"hi","language":"klingon"}"#,
        r#"{"rpc":4,"type":"chat_poll","turn_id":"x","cursor":0,"wait_ms":0}"#,
        r#"{"rpc":4,"type":"chat_poll","turn_id":"01928f5e-7c41-7a80-a192-adbecfd0e1f2","cursor":-1,"wait_ms":0}"#,
        r#"{"rpc":4,"type":"set_retention","days":"7"}"#,
        r#"{"rpc":4,"type":"set_retention","days":7,"force":true}"#,
        r#"{"rpc":4,"type":"chat_cancel","turn_id":null}"#,
    ];
    for frame in refused {
        let reply = chat.raw(frame);
        assert_eq!(reply["type"], "error", "{frame}: {reply}");
    }
    // The previous protocol version is refused, not guessed at.
    let old = chat.raw(r#"{"rpc":3,"type":"inference_status"}"#);
    assert_eq!(old["type"], "error", "{old}");

    // None of it disturbed the model.
    assert_eq!(chat.state(), "ready");
}
