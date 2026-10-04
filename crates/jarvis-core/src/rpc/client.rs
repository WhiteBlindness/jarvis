//! A small client for the local RPC interface, used by the CLI and tests.

use std::time::Duration;

use jarvis_protocol::{RpcRequest, RpcResponse, decode_rpc_response, encode_rpc_request};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::transport::{self, Endpoint};
use crate::framing::{Frame, FrameReader};

/// Largest response the client accepts.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Time allowed on top of any long-poll wait.
const SLACK: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("cannot reach the Core at {endpoint}: {source}")]
    Connect {
        endpoint: String,
        source: std::io::Error,
    },
    #[error("connection to the Core failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("the Core did not answer in time")]
    Timeout,
    #[error("the Core closed the connection")]
    Closed,
    #[error("invalid response from the Core: {0}")]
    Invalid(String),
}

pub struct Client {
    reader: FrameReader<Box<dyn AsyncRead + Send + Unpin>>,
    writer: Box<dyn AsyncWrite + Send + Unpin>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl Client {
    pub async fn connect(endpoint: &Endpoint) -> Result<Self, ClientError> {
        let stream = transport::connect(endpoint)
            .await
            .map_err(|source| ClientError::Connect {
                endpoint: endpoint.to_string(),
                source,
            })?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(Self {
            reader: FrameReader::new(Box::new(reader), MAX_RESPONSE_BYTES),
            writer: Box::new(writer),
        })
    }

    /// Send one request and wait for its response.
    pub async fn call(&mut self, request: &RpcRequest) -> Result<RpcResponse, ClientError> {
        let wait = match request {
            RpcRequest::GetJob { wait_ms, .. } | RpcRequest::ListApprovals { wait_ms } => {
                Duration::from_millis(u64::from(*wait_ms))
            }
            _ => Duration::ZERO,
        };
        let exchange = async {
            let mut bytes = encode_rpc_request(request)
                .map_err(|error| ClientError::Invalid(error.to_string()))?;
            bytes.push(b'\n');
            self.writer.write_all(&bytes).await?;
            self.writer.flush().await?;
            match self.reader.next_frame().await? {
                None => Err(ClientError::Closed),
                Some(Frame::TooLarge) => Err(ClientError::Invalid("response too large".into())),
                Some(Frame::Line(line)) => decode_rpc_response(&line)
                    .map_err(|error| ClientError::Invalid(error.to_string())),
            }
        };
        tokio::time::timeout(wait + SLACK, exchange)
            .await
            .map_err(|_| ClientError::Timeout)?
    }
}
