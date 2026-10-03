//! The Tool Gateway: runs an allowed call under a timeout and a cancellation
//! signal, contains panics, and verifies the result before anything is
//! stored or returned.
//!
//! The Gateway only ever sees a typed [`ToolCall`] that policy has already
//! allowed. It never decides whether a call may run.

use std::sync::Arc;
use std::time::{Duration, Instant};

use jarvis_protocol::{ErrorCode, TaskStatus, ToolCall, ToolResult, WireError};
use jarvis_tools::ToolExecutor;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub struct Gateway {
    executor: Arc<dyn ToolExecutor>,
    timeout: Duration,
    max_result_bytes: usize,
}

/// What happened when a call ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Execution {
    /// The result passed verification. `json` is exactly what is stored and
    /// sent.
    Completed { result: ToolResult, json: String },
    /// `status` is `failed`, `timed_out` or `cancelled`.
    Failed {
        status: TaskStatus,
        error: WireError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executed {
    pub execution: Execution,
    pub duration: Duration,
}

impl Gateway {
    pub fn new(
        executor: Arc<dyn ToolExecutor>,
        timeout: Duration,
        max_result_bytes: usize,
    ) -> Self {
        Self {
            executor,
            timeout,
            max_result_bytes,
        }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Run `call`. The tool runs in its own task, so a panic is contained
    /// and a timeout or cancellation aborts it instead of leaving it behind.
    /// Blocking work a tool has already handed to the blocking pool (a file
    /// read, for example) finishes in the background, and its result is
    /// discarded.
    pub async fn execute(&self, call: &ToolCall, cancel: &CancellationToken) -> Executed {
        let started = Instant::now();
        let executor = Arc::clone(&self.executor);
        let owned = call.clone();
        let mut handle = tokio::spawn(async move { executor.execute(owned).await });

        let execution = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                handle.abort();
                failed(TaskStatus::Cancelled, ErrorCode::Cancelled, "cancelled by Core shutdown".into())
            }
            joined = &mut handle => match joined {
                Ok(Ok(result)) => self.verify(call, result),
                Ok(Err(error)) => failed(TaskStatus::Failed, ErrorCode::ToolFailed, error.to_string()),
                Err(join) if join.is_panic() => {
                    tracing::error!(tool = call.tool_name(), "tool panicked");
                    failed(TaskStatus::Failed, ErrorCode::ToolFailed, "tool failed unexpectedly".into())
                }
                Err(_) => failed(TaskStatus::Cancelled, ErrorCode::Cancelled, "tool task was aborted".into()),
            },
            () = tokio::time::sleep(self.timeout) => {
                handle.abort();
                failed(
                    TaskStatus::TimedOut,
                    ErrorCode::Timeout,
                    format!("tool did not finish within {} ms", self.timeout.as_millis()),
                )
            }
        };
        Executed {
            execution,
            duration: started.elapsed(),
        }
    }

    /// A result is accepted only if it is the right kind for the call, fits
    /// in a frame, and is internally consistent.
    fn verify(&self, call: &ToolCall, result: ToolResult) -> Execution {
        if !result.answers(call) {
            return rejected("tool returned a result of the wrong type".into());
        }
        if let (ToolCall::ReadFixture(args), ToolResult::Fixture(content)) = (call, &result) {
            if content.path != args.path {
                return rejected("fixture result names a different path".into());
            }
            if content.bytes != content.content.len() as u64 {
                return rejected("fixture result size does not match its content".into());
            }
        }
        let json = match serde_json::to_string(&result) {
            Ok(json) => json,
            Err(_) => return rejected("tool result cannot be encoded".into()),
        };
        if json.len() > self.max_result_bytes {
            return rejected(format!(
                "tool result is {} bytes; the limit is {}",
                json.len(),
                self.max_result_bytes
            ));
        }
        Execution::Completed { result, json }
    }
}

fn failed(status: TaskStatus, code: ErrorCode, message: String) -> Execution {
    Execution::Failed {
        status,
        error: WireError::new(code, message),
    }
}

fn rejected(message: String) -> Execution {
    failed(TaskStatus::Failed, ErrorCode::ResultRejected, message)
}

#[cfg(test)]
mod tests {
    use jarvis_protocol::{
        FixtureContent, FixturePath, ProtocolVersion, ReadFixtureArgs, SystemInfo, SystemInfoArgs,
    };
    use jarvis_tools::{ToolError, ToolErrorKind, ToolFuture};

    use super::*;

    #[derive(Debug)]
    struct Returns(ToolResult);
    impl ToolExecutor for Returns {
        fn execute(&self, _: ToolCall) -> ToolFuture<'_> {
            let result = self.0.clone();
            Box::pin(async move { Ok(result) })
        }
    }

    #[derive(Debug)]
    struct Fails;
    impl ToolExecutor for Fails {
        fn execute(&self, _: ToolCall) -> ToolFuture<'_> {
            Box::pin(async { Err(ToolError::new(ToolErrorKind::Io, "disk on fire")) })
        }
    }

    #[derive(Debug)]
    struct Hangs;
    impl ToolExecutor for Hangs {
        fn execute(&self, _: ToolCall) -> ToolFuture<'_> {
            Box::pin(std::future::pending())
        }
    }

    #[derive(Debug)]
    struct Panics;
    impl ToolExecutor for Panics {
        fn execute(&self, _: ToolCall) -> ToolFuture<'_> {
            Box::pin(async { panic!("bug in tool") })
        }
    }

    fn info() -> ToolResult {
        ToolResult::SystemInfo(SystemInfo {
            os: "linux".into(),
            os_family: "unix".into(),
            arch: "x86_64".into(),
            logical_cpus: 2,
            core_version: "0.1.0".into(),
            protocol_version: ProtocolVersion::CURRENT,
            core_uptime_ms: 1,
        })
    }

    fn system_info_call() -> ToolCall {
        ToolCall::SystemInfo(SystemInfoArgs {})
    }

    fn gateway(executor: impl ToolExecutor + 'static) -> Gateway {
        Gateway::new(Arc::new(executor), Duration::from_millis(100), 4096)
    }

    fn error_code(executed: &Executed) -> (TaskStatus, ErrorCode) {
        match &executed.execution {
            Execution::Failed { status, error } => (*status, error.code),
            Execution::Completed { .. } => panic!("expected failure"),
        }
    }

    #[tokio::test]
    async fn verified_result_is_completed() {
        let executed = gateway(Returns(info()))
            .execute(&system_info_call(), &CancellationToken::new())
            .await;
        let Execution::Completed { result, json } = executed.execution else {
            panic!("expected completion");
        };
        assert_eq!(result, info());
        assert_eq!(json, serde_json::to_string(&info()).unwrap());
    }

    #[tokio::test]
    async fn tool_error_is_a_failed_task() {
        let executed = gateway(Fails)
            .execute(&system_info_call(), &CancellationToken::new())
            .await;
        assert_eq!(
            error_code(&executed),
            (TaskStatus::Failed, ErrorCode::ToolFailed)
        );
    }

    #[tokio::test]
    async fn hanging_tool_times_out() {
        let executed = gateway(Hangs)
            .execute(&system_info_call(), &CancellationToken::new())
            .await;
        assert_eq!(
            error_code(&executed),
            (TaskStatus::TimedOut, ErrorCode::Timeout)
        );
        assert!(executed.duration >= Duration::from_millis(100));
    }

    #[tokio::test]
    async fn cancellation_wins_over_a_running_tool() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let executed = gateway(Hangs).execute(&system_info_call(), &cancel).await;
        assert_eq!(
            error_code(&executed),
            (TaskStatus::Cancelled, ErrorCode::Cancelled)
        );
    }

    #[tokio::test]
    async fn panicking_tool_is_contained() {
        // Generous timeout: the panic hook may spend a while printing a
        // backtrace in debug builds.
        let gateway = Gateway::new(Arc::new(Panics), Duration::from_secs(30), 4096);
        let executed = gateway
            .execute(&system_info_call(), &CancellationToken::new())
            .await;
        assert_eq!(
            error_code(&executed),
            (TaskStatus::Failed, ErrorCode::ToolFailed)
        );
    }

    #[tokio::test]
    async fn mismatched_result_is_rejected() {
        let call = ToolCall::ReadFixture(ReadFixtureArgs {
            path: FixturePath::try_from("a.txt".to_owned()).unwrap(),
        });
        let executed = gateway(Returns(info()))
            .execute(&call, &CancellationToken::new())
            .await;
        assert_eq!(
            error_code(&executed),
            (TaskStatus::Failed, ErrorCode::ResultRejected)
        );
    }

    #[tokio::test]
    async fn inconsistent_fixture_result_is_rejected() {
        let path = FixturePath::try_from("a.txt".to_owned()).unwrap();
        let other = FixturePath::try_from("b.txt".to_owned()).unwrap();
        let call = ToolCall::ReadFixture(ReadFixtureArgs { path: path.clone() });
        for content in [
            FixtureContent {
                path: other,
                bytes: 2,
                content: "hi".into(),
            },
            FixtureContent {
                path,
                bytes: 99,
                content: "hi".into(),
            },
        ] {
            let executed = gateway(Returns(ToolResult::Fixture(content)))
                .execute(&call, &CancellationToken::new())
                .await;
            assert_eq!(
                error_code(&executed),
                (TaskStatus::Failed, ErrorCode::ResultRejected)
            );
        }
    }

    #[tokio::test]
    async fn oversized_result_is_rejected() {
        let path = FixturePath::try_from("a.txt".to_owned()).unwrap();
        let call = ToolCall::ReadFixture(ReadFixtureArgs { path: path.clone() });
        let content = "\u{1}".repeat(1000); // 6 bytes each once JSON-escaped
        let result = ToolResult::Fixture(FixtureContent {
            path,
            bytes: content.len() as u64,
            content,
        });
        let executed = gateway(Returns(result))
            .execute(&call, &CancellationToken::new())
            .await;
        assert_eq!(
            error_code(&executed),
            (TaskStatus::Failed, ErrorCode::ResultRejected)
        );
    }
}
