//! Test fixture process management.
//!
//! Spawns the `backseat-test-fixture` or `backseat-test-fixture-c` binary,
//! captures its stdout, and provides helpers to wait for specific events.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::Duration;

/// Which fixture binary and registration mode to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum FixtureKind {
    /// Existing Rust dispatcher-style fixture (wayland-rs `Dispatch`).
    RustDispatcher,
    /// C fixture in dispatcher mode (hand-rolled `wl_proxy_add_dispatcher`).
    CDispatcher,
    /// C fixture in listener mode (`wl_proxy_add_listener`).
    CListener,
}

impl FixtureKind {
    /// Returns `(binary_path_env, binary_fallback_name, mode_arg)` for this
    /// fixture kind.  `mode_arg` is `None` for RustDispatcher (no mode
    /// argument), and `Some("dispatcher")` or `Some("listener")` for the
    /// C binary modes.
    pub fn spawn_args(&self) -> (&str, &str, Option<&str>) {
        match self {
            FixtureKind::RustDispatcher => (
                "CARGO_BIN_EXE_backseat_test_fixture",
                "backseat-test-fixture",
                None,
            ),
            FixtureKind::CDispatcher => (
                "BACKSEAT_FIXTURE_C_PATH",
                "backseat-test-fixture-c",
                Some("dispatcher"),
            ),
            FixtureKind::CListener => (
                "BACKSEAT_FIXTURE_C_PATH",
                "backseat-test-fixture-c",
                Some("listener"),
            ),
        }
    }
}

/// A running test fixture application.
///
/// On drop the process is killed (SIGKILL if SIGTERM doesn't work
/// within a timeout).
pub struct TargetApp {
    child: Child,
    stdout: BufReader<ChildStdout>,
}

impl TargetApp {
    /// Start the given fixture kind against the compositor.
    ///
    /// # Panics
    /// Panics if the fixture binary cannot be found or spawned.
    pub fn start(compositor: &super::compositor::Compositor, kind: FixtureKind) -> Self {
        let (env_var, fallback_name, mode_arg) = kind.spawn_args();

        let fixture_path = std::env::var(env_var).unwrap_or_else(|_| {
            // Fallback when running the test binary directly without cargo.
            let mut path = std::env::current_exe().unwrap();
            path.pop(); // deps or debug
            if path.file_name() == Some("deps".as_ref()) {
                path.pop();
            }
            path.push(fallback_name);
            path.to_string_lossy().into_owned()
        });

        let fixture_path = PathBuf::from(fixture_path);
        if !fixture_path.exists() {
            panic!(
                "Fixture binary not found: {}. Build with --features fixture or set {}.",
                fixture_path.display(),
                env_var
            );
        }

        let mut cmd = Command::new(&fixture_path);
        cmd.env("WAYLAND_DISPLAY", compositor.wayland_display())
            .env("XDG_RUNTIME_DIR", compositor.runtime_dir())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        // Pass mode argument for C fixtures.
        if let Some(mode) = mode_arg {
            cmd.arg(mode);
        }

        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to start {}: {e}", fixture_path.display()));

        let stdout = BufReader::new(child.stdout.take().expect("stdout not captured"));

        Self { child, stdout }
    }

    /// Return the PID of the fixture process.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Wait for a line matching `EVENT: {event}` on stdout.
    ///
    /// Returns the full line (e.g. `EVENT: key pressed 30`).
    ///
    /// # Panics
    /// Panics if the timeout expires or the fixture exits.
    pub fn wait_for_event(&mut self, event: &str, timeout: Duration) -> String {
        let deadline = std::time::Instant::now() + timeout;
        let prefix = format!("EVENT: {event}");

        while std::time::Instant::now() < deadline {
            let mut line = String::new();
            match self.stdout.read_line(&mut line) {
                Ok(0) => panic!("Fixture exited while waiting for '{event}'"),
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.starts_with(&prefix) {
                        return trimmed.to_string();
                    }
                }
                Err(e) => panic!("Error reading fixture stdout: {e}"),
            }
        }
        panic!("Timeout waiting for '{event}' from fixture");
    }

    /// Read the next event line from stdout.
    ///
    /// Skips non-event output.  Returns the full line.
    ///
    /// # Panics
    /// Panics if the timeout expires or the fixture exits.
    #[allow(dead_code)]
    pub fn next_event(&mut self, timeout: Duration) -> String {
        let deadline = std::time::Instant::now() + timeout;

        while std::time::Instant::now() < deadline {
            let mut line = String::new();
            match self.stdout.read_line(&mut line) {
                Ok(0) => panic!("Fixture exited while waiting for next event"),
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.starts_with("EVENT: ") {
                        return trimmed.to_string();
                    }
                }
                Err(e) => panic!("Error reading fixture stdout: {e}"),
            }
        }
        panic!("Timeout waiting for next event from fixture");
    }

    /// Send SIGUSR1 to trigger a reset and wait for `EVENT: ready`.
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        unsafe {
            libc::kill(self.pid() as i32, libc::SIGUSR1);
        }
        self.wait_for_event("ready", Duration::from_secs(5));
    }
}

impl Drop for TargetApp {
    fn drop(&mut self) {
        // Try SIGTERM first, then SIGKILL after a short timeout.
        // Always try_wait/wait regardless of kill() outcome so we
        // don't leak zombie processes.
        let _ = self.child.kill();
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = unsafe { libc::kill(self.child.id() as i32, libc::SIGKILL) };
        let _ = self.child.wait();
    }
}
