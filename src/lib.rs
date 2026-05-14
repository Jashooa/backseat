//! backseat — Wayland background input injection via ptrace.
//!
//! This crate injects a shared-library payload into a target Wayland
//! application and communicates with that payload over a per-process Unix
//! socket to synthesise mouse and keyboard events.  Because the events are
//! delivered inside the target's own `wl_display_dispatch` call, the
//! compositor never sees them — the application treats them as genuine
//! input.
//!
//! # Quick start
//!
//! ```no_run
//! use backseat::{Session, Button, Key, Axis};
//!
//! # tokio_test::block_on(async {
//! let session = Session::new(12345).await.unwrap();
//! session.mouse.click(Button::Left).await.unwrap();
//! session.keyboard.type_text("hello world").await.unwrap();
//! session.unload().await.unwrap();
//! # });
//! ```
//!
//! # Requirements
//!
//! - Linux x86_64
//! - Target application must use a dynamically-linked `libwayland-client`
//! - Caller must have `ptrace` permission over the target process
//!
//! # Architecture
//!
//! The crate builds an injected shared library (the "payload") from vendored
//! source at compile time and handles ptrace injection / IPC.

pub mod error;
pub mod keys;

mod injector;
mod keyboard;
mod mouse;
mod session;

pub use error::{Error, ProxyKind, PtraceOp, SocketPhase};
pub use keyboard::Keyboard;
pub use keys::{Axis, Button, Key};
pub use mouse::Mouse;
pub use session::Session;
