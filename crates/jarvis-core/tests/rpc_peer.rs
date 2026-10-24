//! The RPC server's peer checks over the real transport: a named pipe on
//! Windows, a Unix socket elsewhere. A refused client gets one `forbidden`
//! answer and is audited, and refusing it leaves the interface usable for
//! the next client; a Core that stops closes its connections, and one that
//! starts again on the same endpoint serves new clients.

use std::sync::Arc;
use std::time::{Duration, Instant};

use jarvis_core::config::RpcConfig;
use jarvis_core::hub::Hub;
use jarvis_core::rpc::client::Client;
use jarvis_core::rpc::{self, Endpoint, Listener, RpcState};
use jarvis_core::store::Store;
use jarvis_protocol::{AuditEventKind, RpcRequest, RpcResponse};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

struct Core {
    state: Arc<RpcState>,
    endpoint: Endpoint,
    stop: CancellationToken,
    server: JoinHandle<()>,
}

fn rpc_state(dir: &std::path::Path, pipe: &str) -> RpcState {
    RpcState {
        store: Store::open(&dir.join("jarvis.db")).unwrap(),
        hub: Arc::new(Hub::default()),
        config: RpcConfig {
            socket: dir.join("rpc").join("rpc.sock"),
            pipe: pipe.to_owned(),
            allow_shutdown: false,
            max_connections: 4,
            idle_timeout: Duration::from_secs(10),
        },
        shutdown: CancellationToken::new(),
        started: Instant::now(),
        core_version: "test",
        inference: None,
    }
}

fn start(state: RpcState) -> Core {
    let endpoint = Endpoint::from_config(&state.config);
    let listener = Listener::bind(&endpoint).unwrap();
    let state = Arc::new(state);
    let stop = CancellationToken::new();
    let server = tokio::spawn(rpc::serve(Arc::clone(&state), listener, stop.clone()));
    Core {
        state,
        endpoint,
        stop,
        server,
    }
}

fn unique_pipe(test: &str) -> String {
    format!("jarvis-peer-{test}-{}", std::process::id())
}

async fn health(client: &mut Client) -> Result<(), String> {
    match client.call(&RpcRequest::Health {}).await {
        Ok(RpcResponse::Health(_)) => Ok(()),
        other => Err(format!("{other:?}")),
    }
}

async fn rejections(state: &RpcState) -> Vec<String> {
    state
        .store
        .call(|s| s.audit_events(None, 100))
        .await
        .unwrap()
        .into_iter()
        .filter_map(|event| match event.event {
            AuditEventKind::RpcClientRejected { reason, .. } => Some(reason),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_same_user_client_is_served() {
    let dir = tempfile::tempdir().unwrap();
    let core = start(rpc_state(dir.path(), &unique_pipe("served")));
    let mut client = Client::connect(&core.endpoint).await.unwrap();
    health(&mut client).await.unwrap();
    health(&mut client).await.unwrap();
    assert!(rejections(&core.state).await.is_empty());
    core.stop.cancel();
    core.server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_close_when_the_core_stops_and_a_restarted_core_serves_new_clients() {
    let dir = tempfile::tempdir().unwrap();
    let pipe = unique_pipe("restart");
    let first = start(rpc_state(dir.path(), &pipe));
    let mut old = Client::connect(&first.endpoint).await.unwrap();
    health(&mut old).await.unwrap();

    first.stop.cancel();
    tokio::time::timeout(Duration::from_secs(5), first.server)
        .await
        .unwrap()
        .unwrap();
    // The connection from before the stop is closed, not left half-open.
    assert!(health(&mut old).await.is_err());
    assert!(Client::connect(&first.endpoint).await.is_err());
    // Releases the database lock, as a Core process that exits does.
    drop(first.state);

    // Same endpoint, same database: a new Core serves new clients, and the
    // old connection stays dead.
    let second = start(rpc_state(dir.path(), &pipe));
    let mut fresh = Client::connect(&second.endpoint).await.unwrap();
    health(&mut fresh).await.unwrap();
    assert!(health(&mut old).await.is_err());
    second.stop.cancel();
    second.server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_live_endpoint_cannot_be_taken_by_a_second_listener() {
    let dir = tempfile::tempdir().unwrap();
    let core = start(rpc_state(dir.path(), &unique_pipe("taken")));
    assert!(Listener::bind(&core.endpoint).is_err());
    // The first Core is unaffected.
    let mut client = Client::connect(&core.endpoint).await.unwrap();
    health(&mut client).await.unwrap();
    core.stop.cancel();
    core.server.await.unwrap();
}

/// A client that opens the pipe at anonymous impersonation level hides its
/// token. The Core cannot tell who it is, so it refuses it before reading a
/// request, audits the refusal, and keeps serving everyone else.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_hides_its_token_is_refused_audited_and_does_not_block_others() {
    use jarvis_protocol::{RpcErrorCode, decode_rpc_response};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;

    // SECURITY_ANONYMOUS is 0; tokio adds SECURITY_SQOS_PRESENT.
    const SECURITY_ANONYMOUS: u32 = 0;

    let dir = tempfile::tempdir().unwrap();
    let core = start(rpc_state(dir.path(), &unique_pipe("anonymous")));
    let Endpoint::Pipe(name) = &core.endpoint;

    for _ in 0..2 {
        let anonymous = ClientOptions::new()
            .security_qos_flags(SECURITY_ANONYMOUS)
            .open(name)
            .unwrap();
        let (reader, mut writer) = tokio::io::split(anonymous);
        let mut line = String::new();
        BufReader::new(reader).read_line(&mut line).await.unwrap();
        match decode_rpc_response(line.trim_end().as_bytes()).unwrap() {
            RpcResponse::Error(error) => assert_eq!(error.code, RpcErrorCode::Forbidden),
            other => panic!("expected forbidden, got {other:?}"),
        }
        // The connection is closed: a request sent now is never answered.
        let _ = writer.write_all(b"{\"rpc\":1,\"op\":\"health\"}\n").await;
    }
    assert_eq!(
        rejections(&core.state).await,
        vec!["the client's token could not be read"; 2]
    );

    let mut client = Client::connect(&core.endpoint).await.unwrap();
    health(&mut client).await.unwrap();
    assert_eq!(rejections(&core.state).await.len(), 2);
    core.stop.cancel();
    core.server.await.unwrap();
}

/// Windows lets a pipe server impersonate a client that opened the pipe
/// without security flags (as a plain file open does) only after it has
/// read from the pipe. Such a client that is slow to send its first request,
/// as a client can be just after the computer resumes, is still served.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_writes_late_is_still_served() {
    use std::io::{BufRead, Write};

    use jarvis_protocol::decode_rpc_response;

    let dir = tempfile::tempdir().unwrap();
    let core = start(rpc_state(dir.path(), &unique_pipe("late")));
    let Endpoint::Pipe(name) = core.endpoint.clone();
    for _ in 0..3 {
        let name = name.clone();
        let line = tokio::task::spawn_blocking(move || {
            let mut pipe = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&name)
                .unwrap();
            std::thread::sleep(Duration::from_millis(300));
            pipe.write_all(b"{\"rpc\":4,\"type\":\"health\"}\n")
                .unwrap();
            let mut line = String::new();
            std::io::BufReader::new(pipe).read_line(&mut line).unwrap();
            line
        })
        .await
        .unwrap();
        match decode_rpc_response(line.trim_end().as_bytes()).unwrap() {
            RpcResponse::Health(_) => {}
            other => panic!("expected health, got {other:?}"),
        }
    }
    assert!(rejections(&core.state).await.is_empty());

    // One that sends nothing cannot be identified and is still refused.
    let silent = tokio::task::spawn_blocking(move || {
        let pipe = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
            .unwrap();
        let mut line = String::new();
        std::io::BufReader::new(pipe).read_line(&mut line).unwrap();
        line
    })
    .await
    .unwrap();
    match decode_rpc_response(silent.trim_end().as_bytes()).unwrap() {
        RpcResponse::Error(error) => {
            assert_eq!(error.code, jarvis_protocol::RpcErrorCode::Forbidden);
        }
        other => panic!("expected forbidden, got {other:?}"),
    }
    assert_eq!(rejections(&core.state).await.len(), 1);
    core.stop.cancel();
    core.server.await.unwrap();
}

/// The Core's pipe is owned by the user who started it, at medium
/// integrity, which is what the client checks before it sends anything.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn the_core_pipe_is_owned_by_its_user() {
    use std::os::windows::io::AsRawHandle;
    use tokio::net::windows::named_pipe::ClientOptions;

    let dir = tempfile::tempdir().unwrap();
    let core = start(rpc_state(dir.path(), &unique_pipe("owner")));
    let Endpoint::Pipe(name) = &core.endpoint;
    let raw = ClientOptions::new().open(name).unwrap();
    assert!(jarvis_sandbox::pipe_belongs_to_current_user(raw.as_raw_handle()).unwrap());
    drop(raw);
    core.stop.cancel();
    core.server.await.unwrap();
}
