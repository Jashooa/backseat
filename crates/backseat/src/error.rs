//! Structured error types for `backseat`.
//!
//! Every failure mode is represented as a distinct enum variant so that
//! callers can distinguish transient errors (e.g. `ProxyNotFound`) from
//! fatal ones (e.g. `Disconnected`) without string parsing.

use std::fmt;

/// The primary error type returned by all public APIs.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No running process matched the requested name.
    #[error("process not found: {0}")]
    ProcessNotFound(String),

    /// More than one running process matched the requested name.
    #[error("ambiguous process name '{name}': multiple matches {pids:?}")]
    AmbiguousProcessName { name: String, pids: Vec<u32> },

    /// The caller lacks `ptrace` permission for the target PID.
    #[error("permission denied for PID {0}")]
    PermissionDenied(u32),

    /// The injected `dlopen` call returned `NULL` (payload could not be
    /// loaded inside the target).
    #[error("dlopen returned null in PID {pid}")]
    DlopenReturnedNull { pid: u32 },

    /// A ptrace operation failed.
    #[error("ptrace failed for PID {pid}: op={op:?}, errno={errno}")]
    PtraceFailed { pid: u32, op: PtraceOp, errno: i32 },

    /// Writing shellcode or path data into the target process failed.
    #[error("shellcode write failed for PID {pid} at addr={addr:#x}, errno={errno}")]
    ShellcodeWriteFailed { pid: u32, addr: u64, errno: i32 },

    /// Extracting the embedded payload to disk failed.
    #[error("payload extract failed: {0}")]
    PayloadExtractFailed(String),

    /// Could not locate `libc.so` or the `dlopen` symbol inside the target.
    #[error("libc resolution failed for PID {pid}")]
    LibcResolutionFailed { pid: u32 },

    /// A socket operation timed out.
    #[error("socket timeout during {phase:?}")]
    SocketTimeout { phase: SocketPhase },

    /// A low-level socket I/O error occurred.
    #[error("socket error: {0}")]
    SocketError(String),

    /// The payload speaks a different IPC protocol version.
    #[error("protocol mismatch: expected {expected}, got {got}")]
    ProtocolMismatch { expected: u32, got: u32 },

    /// The payload disconnected (target process likely exited).
    #[error("disconnected")]
    Disconnected,

    /// A required Wayland proxy has not yet been captured by the payload.
    #[error("{kind:?} proxy not found")]
    ProxyNotFound { kind: ProxyKind },

    /// A proxy was found but its listener table is null.
    #[error("{kind:?} listener is null")]
    ListenerNull { kind: ProxyKind },

    /// The target application never calls `wl_display_dispatch` (or
    /// `_pending`), so the dispatch hook cannot fire.
    #[error("dispatch hook not installed")]
    DispatchHookNotInstalled,

    /// The payload failed to unload cleanly.
    #[error("unload failed: {0}")]
    UnloadFailed(String),

    /// `waitpid` returned an unexpected status during ptrace flow.
    #[error("unexpected wait status during {op:?} for PID {pid}: {status}")]
    UnexpectedWaitStatus {
        pid: u32,
        op: PtraceOp,
        status: String,
    },
}

/// Ptrace operations that can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PtraceOp {
    Attach,
    Detach,
    GetRegs,
    SetRegs,
    Cont,
    PokeData,
    PokeText,
}

/// Phases of socket setup at which a timeout can occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketPhase {
    Bind,
    Connect,
    Handshake,
    Call,
}

/// Kinds of Wayland proxies that the payload tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyKind {
    Pointer,
    Keyboard,
    Seat,
    XdgSurface,
    XdgToplevel,
}

impl fmt::Display for PtraceOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PtraceOp::Attach => write!(f, "attach"),
            PtraceOp::Detach => write!(f, "detach"),
            PtraceOp::GetRegs => write!(f, "getregs"),
            PtraceOp::SetRegs => write!(f, "setregs"),
            PtraceOp::Cont => write!(f, "cont"),
            PtraceOp::PokeData => write!(f, "pokedata"),
            PtraceOp::PokeText => write!(f, "poketext"),
        }
    }
}

impl fmt::Display for SocketPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketPhase::Bind => write!(f, "bind"),
            SocketPhase::Connect => write!(f, "connect"),
            SocketPhase::Handshake => write!(f, "handshake"),
            SocketPhase::Call => write!(f, "call"),
        }
    }
}

impl fmt::Display for ProxyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyKind::Pointer => write!(f, "pointer"),
            ProxyKind::Keyboard => write!(f, "keyboard"),
            ProxyKind::Seat => write!(f, "seat"),
            ProxyKind::XdgSurface => write!(f, "xdg_surface"),
            ProxyKind::XdgToplevel => write!(f, "xdg_toplevel"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_variants() {
        let e = Error::ProcessNotFound("firefox".into());
        assert!(e.to_string().contains("firefox"));

        let e = Error::AmbiguousProcessName {
            name: "foo".into(),
            pids: vec![1, 2],
        };
        assert!(e.to_string().contains("foo"));
        assert!(e.to_string().contains("1, 2"));

        let e = Error::ProtocolMismatch {
            expected: 1,
            got: 2,
        };
        assert!(e.to_string().contains("expected 1, got 2"));
    }

    #[test]
    fn ptrace_op_display() {
        assert_eq!(PtraceOp::Attach.to_string(), "attach");
        assert_eq!(PtraceOp::PokeData.to_string(), "pokedata");
    }

    #[test]
    fn socket_phase_display() {
        assert_eq!(SocketPhase::Connect.to_string(), "connect");
        assert_eq!(SocketPhase::Handshake.to_string(), "handshake");
    }

    #[test]
    fn unexpected_wait_status_display() {
        let e = Error::UnexpectedWaitStatus {
            pid: 1234,
            op: PtraceOp::Attach,
            status: "Stopped(Pid(1234), SIGUSR1)".to_string(),
        };
        assert!(e.to_string().contains("Attach"));
        assert!(e.to_string().contains("1234"));
        assert!(e.to_string().contains("SIGUSR1"));
    }
}
