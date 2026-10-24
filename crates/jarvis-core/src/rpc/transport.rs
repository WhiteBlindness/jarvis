//! Platform transports for the local RPC interface: a Unix domain socket in
//! an owner-only directory, or a Windows named pipe that only the current
//! user can open, that refuses remote clients and that cannot be pre-created
//! by another process. On Windows the client also checks that the pipe it
//! opened is owned by its own user at medium integrity or above before
//! sending anything.

use std::fmt;
use std::io;
#[cfg(unix)]
use std::path::PathBuf;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::RpcConfig;

/// Where the Core listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    #[cfg(unix)]
    Socket(PathBuf),
    #[cfg(windows)]
    Pipe(String),
}

impl Endpoint {
    pub fn from_config(config: &RpcConfig) -> Self {
        #[cfg(unix)]
        {
            Self::Socket(config.socket.clone())
        }
        #[cfg(windows)]
        {
            Self::Pipe(format!(r"\\.\pipe\{}", config.pipe))
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(unix)]
            Self::Socket(path) => write!(f, "{}", path.display()),
            #[cfg(windows)]
            Self::Pipe(name) => f.write_str(name),
        }
    }
}

/// Who is on the other end of a connection, as reported by the OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub pid: Option<u32>,
    /// The peer's user ID, from `SO_PEERCRED`.
    #[cfg(unix)]
    pub uid: Option<u32>,
    /// What the client's own token says, read by impersonating it once it
    /// connected. `None` if it could not be read.
    #[cfg(windows)]
    pub token: Option<jarvis_sandbox::PipeClient>,
}

impl Peer {
    pub fn describe(&self) -> String {
        match self.pid {
            Some(pid) => format!("local client pid {pid}"),
            None => "unidentified local client".to_owned(),
        }
    }
}

pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

#[cfg(unix)]
pub use unix::Listener;
#[cfg(windows)]
pub use windows::Listener;

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    use tokio::net::{UnixListener, UnixStream};

    use super::{Endpoint, Peer, io};

    #[derive(Debug)]
    pub struct Listener {
        inner: UnixListener,
        path: PathBuf,
    }

    impl Listener {
        /// Bind the socket inside a directory only the owner can enter.
        pub fn bind(endpoint: &Endpoint) -> io::Result<Self> {
            let Endpoint::Socket(path) = endpoint;
            let dir = path
                .parent()
                .filter(|dir| !dir.as_os_str().is_empty())
                .ok_or_else(|| io::Error::other("the RPC socket needs a parent directory"))?;
            if !dir.exists() {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)?;
            }
            // Never loosen or tighten an existing directory; refuse one that
            // other users could enter or that someone else owns.
            let meta = fs::metadata(dir)?;
            if meta.permissions().mode() & 0o077 != 0 || meta.uid() != jarvis_sandbox::current_uid()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "the RPC socket directory {} must be owned by this user with mode 0700",
                        dir.display()
                    ),
                ));
            }
            // A socket left here by a Core that stopped is stale and can go;
            // one that still answers belongs to another running Core.
            match fs::symlink_metadata(path) {
                Ok(meta) if meta.file_type().is_socket() => {
                    if std::os::unix::net::UnixStream::connect(path).is_ok() {
                        return Err(io::Error::new(
                            io::ErrorKind::AddrInUse,
                            format!("another Core is listening on {}", path.display()),
                        ));
                    }
                    fs::remove_file(path)?;
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("{} exists and is not a socket", path.display()),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let inner = UnixListener::bind(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            Ok(Self {
                inner,
                path: path.clone(),
            })
        }

        pub async fn accept(&mut self) -> io::Result<(UnixStream, Peer)> {
            let (stream, _) = self.inner.accept().await?;
            let peer = match stream.peer_cred() {
                Ok(cred) => Peer {
                    pid: cred.pid().and_then(|pid| u32::try_from(pid).ok()),
                    uid: Some(cred.uid()),
                },
                Err(_) => Peer {
                    pid: None,
                    uid: None,
                },
            };
            Ok((stream, peer))
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    pub async fn connect(endpoint: &Endpoint) -> io::Result<UnixStream> {
        let Endpoint::Socket(path) = endpoint;
        UnixStream::connect(path).await
    }
}

#[cfg(unix)]
pub use unix::connect;

#[cfg(windows)]
mod windows {
    use std::os::windows::io::AsRawHandle;
    use std::time::Duration;

    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };

    use super::{Endpoint, Peer, io};

    /// `ERROR_PIPE_BUSY`: every instance is in use; try again shortly.
    const ERROR_PIPE_BUSY: i32 = 231;

    /// How long a client that must send before it can be identified gets.
    /// Accepting waits for it, so it stays short.
    const FIRST_BYTES: Duration = Duration::from_secs(1);

    #[derive(Debug)]
    pub struct Listener {
        name: String,
        next: NamedPipeServer,
    }

    impl Listener {
        /// Create the first instance of the pipe. Fails if any process
        /// already owns the name, so a squatter cannot impersonate the Core.
        pub fn bind(endpoint: &Endpoint) -> io::Result<Self> {
            let Endpoint::Pipe(name) = endpoint;
            let mut options = ServerOptions::new();
            options
                .first_pipe_instance(true)
                .reject_remote_clients(true);
            let next = jarvis_sandbox::create_owner_only_pipe(&options, name)?;
            Ok(Self {
                name: name.clone(),
                next,
            })
        }

        pub async fn accept(&mut self) -> io::Result<(NamedPipeServer, Peer)> {
            self.next.connect().await?;
            let mut options = ServerOptions::new();
            options.reject_remote_clients(true);
            let fresh = jarvis_sandbox::create_owner_only_pipe(&options, &self.name)?;
            let connected = std::mem::replace(&mut self.next, fresh);
            let pid = jarvis_sandbox::named_pipe_client_pid(connected.as_raw_handle()).ok();
            let mut token = jarvis_sandbox::inspect_pipe_client(connected.as_raw_handle());
            if token
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
            {
                // Some clients can be identified only after they have sent
                // something; wait briefly for it. A client that sends nothing
                // is refused as before.
                if tokio::time::timeout(FIRST_BYTES, connected.readable())
                    .await
                    .is_ok_and(|ready| ready.is_ok())
                {
                    token = jarvis_sandbox::inspect_pipe_client(connected.as_raw_handle());
                }
            }
            let token = token
                .inspect_err(|error| tracing::warn!(%error, "cannot read the RPC client's token"))
                .ok();
            Ok((connected, Peer { pid, token }))
        }
    }

    /// Open the Core's pipe, and refuse it unless it is owned by this user
    /// at medium integrity or above: while the Core is stopped, another
    /// account or a low-integrity process could create a pipe under the
    /// same name and collect what the client sends.
    pub async fn connect(endpoint: &Endpoint) -> io::Result<NamedPipeClient> {
        let Endpoint::Pipe(name) = endpoint;
        let mut attempts = 0;
        let client = loop {
            match ClientOptions::new().open(name) {
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < 50 => {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                other => break other?,
            }
        };
        if !jarvis_sandbox::pipe_belongs_to_current_user(client.as_raw_handle())? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{name} belongs to another user or to a low-integrity process, so it is not this user's Core"
                ),
            ));
        }
        Ok(client)
    }
}

#[cfg(windows)]
pub use windows::connect;
