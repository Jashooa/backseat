//! Headless Weston compositor management for integration tests.
//!
//! Spins up `weston --backend=headless` in a dedicated runtime directory
//! with a custom socket name so tests don't collide with each other or
//! the host's Wayland session.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// A running headless Weston compositor.
///
/// On drop the compositor process is killed (SIGKILL if SIGTERM doesn't
/// work within a timeout).
pub struct Compositor {
    child: Child,
    runtime_dir: PathBuf,
    socket_name: String,
}

impl Compositor {
    /// Start a headless Weston compositor.
    ///
    /// # Panics
    /// Panics if `weston` is not installed or fails to start.
    pub fn start() -> Self {
        let runtime_dir =
            std::env::temp_dir().join(format!("backseat-weston-{}", std::process::id()));
        std::fs::create_dir_all(&runtime_dir).expect("create runtime dir");

        let socket_name = format!("wayland-backseat-test-{}", std::process::id());

        let child = Command::new("weston")
            .args([
                "--backend=headless",
                &format!("--socket={socket_name}"),
                "--config=/dev/null",
                "--no-config",
            ])
            .env("XDG_RUNTIME_DIR", &runtime_dir)
            .env("WAYLAND_DISPLAY", &socket_name)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start weston -- is it installed?");

        // Give weston a moment to create the socket.
        std::thread::sleep(std::time::Duration::from_millis(500));

        Self {
            child,
            runtime_dir,
            socket_name,
        }
    }

    /// Return the `WAYLAND_DISPLAY` value that clients must use.
    pub fn wayland_display(&self) -> &str {
        &self.socket_name
    }

    /// Return the `XDG_RUNTIME_DIR` that clients must use.
    pub fn runtime_dir(&self) -> &PathBuf {
        &self.runtime_dir
    }
}

impl Drop for Compositor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.runtime_dir);
    }
}
