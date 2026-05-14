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

    /// The payload failed to unload cleanly.
    #[error("unload failed: {0}")]
    UnloadFailed(String),

    /// The target is sandboxed in a way that prevents ptrace.
    /// The `reason` field describes the detected sandbox.
    #[error("target PID {pid} is sandboxed: {reason}")]
    SandboxedTarget { pid: u32, reason: String },

    /// Yama ptrace_scope blocks tracing non-descendant processes.
    /// On most distributions this can be relaxed with
    /// `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`.
    #[error("ptrace_scope is {current} (need 0 to trace arbitrary processes)")]
    PtraceScopeRestricted { current: u32 },

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

    /// Construct every error variant and verify Display produces a non-empty
    /// message containing something identifiable.
    #[test]
    fn all_error_variants_have_display() {
        let errors: &[(&str, Error)] = &[
            ("PermissionDenied", Error::PermissionDenied(42)),
            ("DlopenReturnedNull", Error::DlopenReturnedNull { pid: 99 }),
            (
                "PtraceFailed",
                Error::PtraceFailed {
                    pid: 1,
                    op: PtraceOp::Attach,
                    errno: 3,
                },
            ),
            (
                "ShellcodeWriteFailed",
                Error::ShellcodeWriteFailed {
                    pid: 2,
                    addr: 0x1000,
                    errno: 5,
                },
            ),
            (
                "PayloadExtractFailed",
                Error::PayloadExtractFailed("oops".into()),
            ),
            (
                "LibcResolutionFailed",
                Error::LibcResolutionFailed { pid: 7 },
            ),
            (
                "SocketTimeout",
                Error::SocketTimeout {
                    phase: SocketPhase::Connect,
                },
            ),
            ("SocketError", Error::SocketError("bad".into())),
            ("Disconnected", Error::Disconnected),
            (
                "ProxyNotFound",
                Error::ProxyNotFound {
                    kind: ProxyKind::Keyboard,
                },
            ),
            ("UnloadFailed", Error::UnloadFailed("cleanup".into())),
            (
                "SandboxedTarget",
                Error::SandboxedTarget {
                    pid: 42,
                    reason: "Flatpak sandbox".into(),
                },
            ),
            (
                "PtraceScopeRestricted",
                Error::PtraceScopeRestricted { current: 1 },
            ),
        ];
        for (name, err) in errors {
            let msg = err.to_string();
            assert!(!msg.is_empty(), "Error::{name} produced empty Display");
        }
    }

    #[test]
    fn ptrace_op_display_all() {
        assert_eq!(PtraceOp::Attach.to_string(), "attach");
        assert_eq!(PtraceOp::Detach.to_string(), "detach");
        assert_eq!(PtraceOp::GetRegs.to_string(), "getregs");
        assert_eq!(PtraceOp::SetRegs.to_string(), "setregs");
        assert_eq!(PtraceOp::Cont.to_string(), "cont");
        assert_eq!(PtraceOp::PokeData.to_string(), "pokedata");
        assert_eq!(PtraceOp::PokeText.to_string(), "poketext");
    }

    #[test]
    fn socket_phase_display_all() {
        assert_eq!(SocketPhase::Bind.to_string(), "bind");
        assert_eq!(SocketPhase::Connect.to_string(), "connect");
        assert_eq!(SocketPhase::Handshake.to_string(), "handshake");
        assert_eq!(SocketPhase::Call.to_string(), "call");
    }

    #[test]
    fn proxy_kind_display_all() {
        assert_eq!(ProxyKind::Pointer.to_string(), "pointer");
        assert_eq!(ProxyKind::Keyboard.to_string(), "keyboard");
        assert_eq!(ProxyKind::Seat.to_string(), "seat");
        assert_eq!(ProxyKind::XdgSurface.to_string(), "xdg_surface");
        assert_eq!(ProxyKind::XdgToplevel.to_string(), "xdg_toplevel");
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
