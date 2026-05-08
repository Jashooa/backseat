//! Session management — payload extraction, injection, IPC handshake, and
//! cleanup.
//!
//! A [`Session`] represents a single target process.  It owns the Unix socket
//! connection to the injected payload and provides [`Mouse`](crate::Mouse) and
//! [`Keyboard`](crate::Keyboard) handles that share the same connection.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::error::{Error, SocketPhase};
use crate::injector;
use crate::keyboard::Keyboard;
use crate::mouse::Mouse;

/// IPC protocol version shared between host and payload.
const PROTOCOL_VERSION: u32 = 1;

/// Default timeout for socket operations.
const TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// IPC wire types
// ---------------------------------------------------------------------------

/// Host → payload handshake request.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct HelloRequest {
    #[serde(rename = "type")]
    ty: String,
    protocol_version: u32,
    crate_version: String,
}

/// Payload → host handshake response.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HelloResponse {
    #[serde(rename = "type")]
    ty: String,
    protocol_version: u32,
    payload_version: String,
}

/// Generic JSON command sent over the Unix socket.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Command {
    #[serde(rename = "type")]
    pub(crate) ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) x: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) y: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) button: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) key: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) axis: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) value: Option<f64>,
}

impl Command {
    pub(crate) fn new(ty: &str) -> Self {
        Self {
            ty: ty.to_string(),
            x: None,
            y: None,
            button: None,
            state: None,
            key: None,
            axis: None,
            value: None,
        }
    }
}

/// Generic JSON response received from the payload.
#[derive(Debug, Deserialize)]
pub(crate) struct Response {
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) width: Option<u32>,
    #[serde(default)]
    pub(crate) height: Option<u32>,
    #[serde(default)]
    pub(crate) code: Option<String>,
    #[serde(default)]
    pub(crate) message: Option<String>,
    #[serde(default)]
    pub(crate) kind: Option<String>,
    #[serde(default)]
    pub(crate) dispatch_hook_installed: Option<bool>,
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// A handle to an injected target process.
///
/// `Session` is `Send + Sync` and can be moved across `tokio::spawn`
/// boundaries.  The underlying IPC socket is protected by a `tokio::sync::Mutex`
/// so concurrent calls on [`Mouse`] and [`Keyboard`] are serialised.
///
/// # Cleanup
///
/// Always prefer calling [`Session::unload`].await explicitly.  The [`Drop`]
/// implementation spawns a best-effort blocking task to clean up, but if the
/// Tokio runtime is already shutting down the payload may leak.
#[derive(Debug)]
pub struct Session {
    /// Mouse input API.
    pub mouse: Mouse,
    /// Keyboard input API.
    pub keyboard: Keyboard,
    pid: u32,
    stream: Arc<Mutex<UnixStream>>,
}

impl Session {
    /// Inject the payload into `pid` and perform the IPC handshake.
    ///
    /// # Errors
    ///
    /// Returns structured errors for every phase: permission denied, ptrace
    /// failure, socket timeout, protocol mismatch, etc.
    pub async fn new(pid: u32) -> Result<Self, Error> {
        let payload_path = extract_payload().await?;

        // ptrace is entirely synchronous — run it in a blocking task.
        let pid_for_inject = pid;
        let path_for_inject = payload_path.clone();
        tokio::task::spawn_blocking(move || {
            injector::inject_payload(pid_for_inject, &path_for_inject)
        })
        .await
        .map_err(|e| Error::PayloadExtractFailed(format!("inject task panicked: {e}")))??;

        // Give the payload's IPC thread a moment to bind its socket.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let sock_path = runtime_dir().join(format!("backseat-{}.sock", pid));
        let stream = timeout(TIMEOUT, UnixStream::connect(&sock_path))
            .await
            .map_err(|_| Error::SocketTimeout {
                phase: SocketPhase::Connect,
            })?
            .map_err(|e| Error::SocketError(e.to_string()))?;

        let stream = Arc::new(Mutex::new(stream));

        // Handshake
        let hello = HelloRequest {
            ty: "hello".to_string(),
            protocol_version: PROTOCOL_VERSION,
            crate_version: env!("CARGO_PKG_VERSION").to_string(),
        };
        {
            let mut s = stream.lock().await;
            send_line(&mut s, &hello).await?;
            let line = read_line(&mut s).await?;
            let ack: HelloResponse = serde_json::from_str(&line)
                .map_err(|e| Error::SocketError(format!("invalid hello ack: {e}")))?;
            if ack.protocol_version != PROTOCOL_VERSION {
                return Err(Error::ProtocolMismatch {
                    expected: PROTOCOL_VERSION,
                    got: ack.protocol_version,
                });
            }
        }

        // Assert the dispatch hook has actually fired.  If the target was
        // linked BIND_NOW / -Bsymbolic, PLT shadowing may not take effect.
        {
            let mut s = stream.lock().await;
            send_line(&mut s, &Command::new("status")).await?;
            let line = read_line(&mut s).await?;
            let status: Response = serde_json::from_str(&line)
                .map_err(|e| Error::SocketError(format!("invalid status: {e}")))?;
            if status.status != "ok" {
                return Err(map_ipc_error(
                    &status.code.unwrap_or_default(),
                    &status.message.unwrap_or_default(),
                    status.kind.as_deref(),
                ));
            }
            if status.dispatch_hook_installed == Some(false) {
                return Err(Error::DispatchHookNotInstalled);
            }
        }

        Ok(Session {
            mouse: Mouse::new(stream.clone()),
            keyboard: Keyboard::new(stream.clone()),
            pid,
            stream,
        })
    }

    /// Find a process by name and inject into it.
    ///
    /// Returns [`Error::AmbiguousProcessName`](crate::Error::AmbiguousProcessName)
    /// if more than one running process matches.
    pub async fn from_name(name: &str) -> Result<Self, Error> {
        let pid = tokio::task::spawn_blocking({
            let name = name.to_string();
            move || injector::from_name(&name)
        })
        .await
        .map_err(|e| Error::PayloadExtractFailed(format!("from_name task panicked: {e}")))??;
        Self::new(pid).await
    }

    /// Explicitly unload the payload and remove the per-PID socket file.
    ///
    /// Consumes `self` so the session cannot be used after unloading.
    ///
    /// # Caveat
    ///
    /// The payload `.so` is *not* `dlclose`'d — the IPC thread would need to
    /// shut down first and there is no portable way to wait for a thread in
    /// another process.  Re-injecting the same PID loads a second copy.
    pub async fn unload(self) -> Result<(), Error> {
        let mut s = self.stream.lock().await;
        send_line(&mut s, &Command::new("unload")).await?;
        let _ = read_line(&mut s).await?;
        let _ = s.shutdown().await;
        drop(s);

        let sock_path = runtime_dir().join(format!("backseat-{}.sock", self.pid));
        let _ = tokio::fs::remove_file(&sock_path).await;

        if let Ok(path) = extract_payload().await {
            let _ = tokio::fs::remove_file(&path).await;
        }

        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let pid = self.pid;
        let stream = self.stream.clone();
        // Best-effort async cleanup in a blocking task.
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new();
            if let Ok(rt) = rt {
                rt.block_on(async {
                    let mut s = stream.lock().await;
                    let _ = send_line(&mut s, &Command::new("unload")).await;
                    let _ = s.shutdown().await;
                    let sock_path = runtime_dir().join(format!("backseat-{}.sock", pid));
                    let _ = tokio::fs::remove_file(&sock_path).await;
                });
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Send a command and wait for its response on the given stream.
pub(crate) async fn send_command(stream: &mut UnixStream, cmd: Command) -> Result<Response, Error> {
    send_line(stream, &cmd).await?;
    let line = read_line(stream).await?;
    let resp: Response = serde_json::from_str(&line)
        .map_err(|e| Error::SocketError(format!("invalid response: {e}")))?;
    if resp.status == "error" {
        let code = resp.code.clone().unwrap_or_default();
        return Err(map_ipc_error(
            &code,
            &resp.message.unwrap_or_default(),
            resp.kind.as_deref(),
        ));
    }
    Ok(resp)
}

/// Map payload error codes back to structured `Error` variants.
fn map_ipc_error(code: &str, message: &str, kind: Option<&str>) -> Error {
    match code {
        "proxy_not_found" => {
            let proxy_kind = kind.and_then(|k| match k {
                "pointer" => Some(crate::error::ProxyKind::Pointer),
                "keyboard" => Some(crate::error::ProxyKind::Keyboard),
                "seat" => Some(crate::error::ProxyKind::Seat),
                "xdg_surface" => Some(crate::error::ProxyKind::XdgSurface),
                "xdg_toplevel" => Some(crate::error::ProxyKind::XdgToplevel),
                _ => None,
            });
            match proxy_kind {
                Some(k) => Error::ProxyNotFound { kind: k },
                None => Error::SocketError(format!("proxy_not_found: {message}")),
            }
        }
        "dispatch_hook_not_installed" => Error::DispatchHookNotInstalled,
        _ => Error::SocketError(message.to_string()),
    }
}

/// Serialize `obj` as JSON and write it to `s` followed by a newline.
async fn send_line(s: &mut UnixStream, obj: impl Serialize) -> Result<(), Error> {
    let mut json = serde_json::to_vec(&obj).map_err(|e| Error::SocketError(e.to_string()))?;
    json.push(b'\n');
    timeout(TIMEOUT, s.write_all(&json))
        .await
        .map_err(|_| Error::SocketTimeout {
            phase: SocketPhase::Call,
        })?
        .map_err(|e| Error::SocketError(e.to_string()))?;
    Ok(())
}

/// Read a single newline-delimited JSON line from `s`.
async fn read_line(s: &mut UnixStream) -> Result<String, Error> {
    let mut reader = BufReader::new(s);
    let mut line = String::new();
    let n = timeout(TIMEOUT, reader.read_line(&mut line))
        .await
        .map_err(|_| Error::SocketTimeout {
            phase: SocketPhase::Call,
        })?
        .map_err(|e| Error::SocketError(e.to_string()))?;
    if n == 0 {
        return Err(Error::Disconnected);
    }
    Ok(line.trim().to_string())
}

/// Return a suitable runtime directory for temporary files.
///
/// Prefers `$XDG_RUNTIME_DIR` (user-owned, typically `/run/user/<uid>`),
/// falling back to `/tmp`.
fn runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// Extract the embedded payload `.so` to the runtime directory.
///
/// The filename includes an 8-byte SHA-256 prefix so that different crate
/// versions never reuse stale payloads.  The file is created with
/// `O_CREAT | O_EXCL | O_NOFOLLOW` and mode `0600` so a pre-existing
/// attacker-controlled file cannot be raced.
async fn extract_payload() -> Result<PathBuf, Error> {
    tokio::task::spawn_blocking(|| {
        // The build script sets BACKSEAT_PAYLOAD_PATH to the compiled
        // cdylib artifact path.
        let bytes = include_bytes!(env!("BACKSEAT_PAYLOAD_PATH"));
        let hash = sha2::Sha256::digest(bytes);
        let prefix = hex::encode(&hash[..8]);
        let dir = runtime_dir();
        let path = dir.join(format!("backseat-payload-{}.so", prefix));

        // Atomic create with O_CREAT | O_EXCL | O_NOFOLLOW and mode 0600.
        // If the file already exists (legitimately from a previous run),
        // treat AlreadyExists as success.
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Ok(path);
            }
            Err(e) => {
                return Err(Error::PayloadExtractFailed(format!("open payload: {e}")));
            }
        };
        file.write_all(bytes.as_slice())
            .map_err(|e| Error::PayloadExtractFailed(format!("write payload: {e}")))?;
        drop(file);
        Ok(path)
    })
    .await
    .map_err(|e| Error::PayloadExtractFailed(format!("extract task panicked: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_serialization() {
        let cmd = Command {
            ty: "mouse_move".to_string(),
            x: Some(100.0),
            y: Some(200.0),
            ..Command::new("mouse_move")
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"mouse_move\""));
        assert!(json.contains("\"x\":100.0"));
        assert!(json.contains("\"y\":200.0"));
        assert!(!json.contains("button"));
    }

    #[test]
    fn response_deserialization_ok() {
        let json = r#"{"status":"ok","width":1920,"height":1080}"#;
        let resp: Response = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.width, Some(1920));
        assert_eq!(resp.height, Some(1080));
    }

    #[test]
    fn response_deserialization_error() {
        let json = r#"{"status":"error","code":"proxy_not_found","message":"nope"}"#;
        let resp: Response = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "error");
        assert_eq!(resp.code, Some("proxy_not_found".to_string()));
        assert_eq!(resp.message, Some("nope".to_string()));
    }

    #[test]
    fn hello_request_serialization() {
        let req = HelloRequest {
            ty: "hello".to_string(),
            protocol_version: 1,
            crate_version: "0.2.2".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"hello\""));
        assert!(json.contains("\"protocol_version\":1"));
    }

    #[test]
    fn response_deserialization_with_kind() {
        let json =
            r#"{"status":"error","code":"proxy_not_found","message":"nope","kind":"keyboard"}"#;
        let resp: Response = serde_json::from_str(json).unwrap();
        assert_eq!(resp.kind, Some("keyboard".to_string()));
    }

    #[test]
    fn response_deserialization_status_with_dispatch_hook() {
        let json = r#"{"status":"ok","dispatch_hook_installed":false}"#;
        let resp: Response = serde_json::from_str(json).unwrap();
        assert_eq!(resp.dispatch_hook_installed, Some(false));
    }

    #[test]
    fn map_ipc_error_proxy_not_found_with_kind() {
        use crate::error::ProxyKind;
        let e = map_ipc_error("proxy_not_found", "msg", Some("keyboard"));
        assert!(matches!(
            e,
            crate::error::Error::ProxyNotFound {
                kind: ProxyKind::Keyboard
            }
        ));
    }

    #[test]
    fn map_ipc_error_proxy_not_found_without_kind() {
        let e = map_ipc_error("proxy_not_found", "msg", None);
        assert!(matches!(e, crate::error::Error::SocketError(_)));
    }
}
