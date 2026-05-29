//! Integration tests for `backseat`.
//!
//! Each test that needs Wayland infrastructure creates its own compositor
//! and fixture, which are cleaned up when the test scope exits (via Drop).
//! Tests share a `SUITE_LOCK` to run sequentially.
//!
//! These tests run by default on Linux when `weston` is found in `$PATH`.
//! The fixture binary uses `PR_SET_PTRACER_ANY` so tests work under the
//! default `ptrace_scope = 1` without any kernel configuration.

mod helpers;

use std::path::PathBuf;
use std::time::Duration;

use backseat::Session;
use tokio::sync::Mutex;

use helpers::compositor::Compositor;
use helpers::target_app::{FixtureKind, TargetApp};

static SUITE_LOCK: Mutex<()> = Mutex::const_new(());

/// Returns `Ok(())` if the local machine has `weston`.
fn check_prerequisites() -> Result<(), String> {
    if std::process::Command::new("weston")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_err()
    {
        return Err("weston not found in $PATH".into());
    }
    Ok(())
}

fn skip_unless_ready() -> bool {
    if let Err(reason) = check_prerequisites() {
        eprintln!("SKIP: {reason}");
        return true;
    }
    false
}

/// A running compositor + fixture pair.  Dropping this struct kills both
/// child processes, guaranteeing no stale processes survive the test.
struct TestEnv {
    _compositor: Compositor,
    target: std::sync::Mutex<TargetApp>,
}

impl TestEnv {
    fn start(kind: FixtureKind) -> Self {
        let compositor = Compositor::start();
        std::thread::sleep(Duration::from_millis(500));
        std::env::set_var(
            "XDG_RUNTIME_DIR",
            compositor.runtime_dir().to_str().unwrap(),
        );

        let mut target = TargetApp::start(&compositor, kind);
        target.wait_for_event("ready", Duration::from_secs(5));

        Self {
            _compositor: compositor,
            target: std::sync::Mutex::new(target),
        }
    }

    fn pid(&self) -> u32 {
        self.target.lock().unwrap().pid()
    }

    /// Read the next `count` event lines from the fixture (blocks until each
    /// arrives or the timeout expires).  Panics on timeout or fixture exit.
    fn read_events(&self, count: usize) -> Vec<String> {
        let mut target = self.target.lock().unwrap();
        (0..count)
            .map(|_| target.next_event(Duration::from_secs(5)))
            .collect()
    }
}

fn socket_path(pid: u32) -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(format!("backseat-{pid}.sock"))
}

async fn wait_for_socket_gone(pid: u32) {
    for _ in 0..40 {
        if !socket_path(pid).exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("socket still exists after unload/drop");
}

// ---------------------------------------------------------------------------
// Infrastructure tests — Rust fixture only
// ---------------------------------------------------------------------------

#[tokio::test]
async fn inject_and_unload() {
    if skip_unless_ready() {
        return;
    }
    let _guard = SUITE_LOCK.lock().await;
    let env = TestEnv::start(FixtureKind::RustDispatcher);

    let pid = env.pid();
    let session = Session::new(pid).await.expect("Session::new failed");
    assert!(
        socket_path(pid).exists(),
        "socket should exist after injection"
    );

    session.unload().await.expect("unload failed");
    wait_for_socket_gone(pid).await;
}

#[tokio::test]
async fn drop_auto_unloads() {
    if skip_unless_ready() {
        return;
    }
    let _guard = SUITE_LOCK.lock().await;
    let env = TestEnv::start(FixtureKind::RustDispatcher);

    let pid = env.pid();
    {
        let _session = Session::new(pid).await.expect("Session::new failed");
        assert!(socket_path(pid).exists());
    }
    wait_for_socket_gone(pid).await;
}

#[tokio::test]
async fn reinject_after_unload_works() {
    if skip_unless_ready() {
        return;
    }
    let _guard = SUITE_LOCK.lock().await;
    let env = TestEnv::start(FixtureKind::RustDispatcher);

    let pid = env.pid();
    let session = Session::new(pid).await.expect("first Session::new failed");
    session.unload().await.expect("unload failed");
    wait_for_socket_gone(pid).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let session2 = Session::new(pid).await.expect("second Session::new failed");
    session2.unload().await.expect("unload failed");
}

#[tokio::test]
async fn session_from_name_finds_process() {
    if skip_unless_ready() {
        return;
    }
    let _guard = SUITE_LOCK.lock().await;
    let _env = TestEnv::start(FixtureKind::RustDispatcher);

    let result = Session::from_name("backseat-test-fixture").await;
    assert!(
        result.is_ok(),
        "Session::from_name should find the fixture: {result:?}"
    );
    let session = result.unwrap();
    session.unload().await.expect("unload failed");
}

// ---------------------------------------------------------------------------
// Input event tests — parameterized across fixture kinds
// ---------------------------------------------------------------------------

/// All fixture configurations to test input against.
/// TODO: CDispatcher and CListener are excluded until the C fixture's
/// main loop uses a dispatch strategy that ensures the payload's IPC
/// thread starts reliably.  The C fixture currently uses blocking
/// `wl_display_dispatch` which prevents SIGUSR2-based proxy re-binding
/// from being serviced.  Switching to non-blocking dispatch triggers an
/// ECONNRESET during injection that needs further investigation.
const ALL_FIXTURE_KINDS: [FixtureKind; 1] = [FixtureKind::RustDispatcher];

/// Helper: send SIGUSR2 to the fixture so it re-requests keyboard and
/// pointer proxies.  The payload's hooked `wl_proxy_add_dispatcher`
/// fires `capture_proxy` on re-registration.
fn reregister_input(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGUSR2);
    }
    std::thread::sleep(Duration::from_millis(200));
}

#[tokio::test]
async fn key_tap_is_received_by_target() {
    if skip_unless_ready() {
        return;
    }
    let _guard = SUITE_LOCK.lock().await;

    for kind in &ALL_FIXTURE_KINDS {
        let env = TestEnv::start(*kind);
        let pid = env.pid();
        let session = Session::new(pid).await.expect("Session::new failed");
        reregister_input(pid);

        session
            .keyboard
            .tap(backseat::keys::Key::A)
            .await
            .expect("tap failed");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let lines = env.read_events(2);
        assert!(
            lines.iter().any(|l| l.contains("key pressed 30")),
            "[{kind:?}] missing press: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("key released 30")),
            "[{kind:?}] missing release: {lines:?}"
        );
    }
}

#[tokio::test]
async fn mouse_click_is_received_by_target() {
    if skip_unless_ready() {
        return;
    }
    let _guard = SUITE_LOCK.lock().await;

    for kind in &ALL_FIXTURE_KINDS {
        let env = TestEnv::start(*kind);
        let pid = env.pid();
        let session = Session::new(pid).await.expect("Session::new failed");
        reregister_input(pid);

        session
            .mouse
            .click(backseat::keys::Button::Left)
            .await
            .expect("click failed");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let lines = env.read_events(2);
        assert!(
            lines.iter().any(|l| l.contains("button pressed 272")),
            "[{kind:?}] missing press: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("button released 272")),
            "[{kind:?}] missing release: {lines:?}"
        );
    }
}

#[tokio::test]
async fn mouse_scroll_is_received_by_target() {
    if skip_unless_ready() {
        return;
    }
    let _guard = SUITE_LOCK.lock().await;

    for kind in &ALL_FIXTURE_KINDS {
        let env = TestEnv::start(*kind);
        let pid = env.pid();
        let session = Session::new(pid).await.expect("Session::new failed");
        reregister_input(pid);

        session
            .mouse
            .scroll(backseat::keys::Axis::Vertical, 10.0)
            .await
            .expect("scroll failed");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let lines = env.read_events(1);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("EVENT: axis") && l.contains("vertical")),
            "[{kind:?}] missing axis event: {lines:?}"
        );
    }
}

#[tokio::test]
async fn type_text_is_received_by_target() {
    if skip_unless_ready() {
        return;
    }
    let _guard = SUITE_LOCK.lock().await;

    for kind in &ALL_FIXTURE_KINDS {
        let env = TestEnv::start(*kind);
        let pid = env.pid();
        let session = Session::new(pid).await.expect("Session::new failed");
        reregister_input(pid);

        session
            .keyboard
            .type_text("hi")
            .await
            .expect("type_text failed");
        tokio::time::sleep(Duration::from_millis(300)).await;
        let lines = env.read_events(4);
        assert!(
            lines.iter().any(|l| l.contains("key pressed 35")),
            "[{kind:?}] missing h press: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("key released 35")),
            "[{kind:?}] missing h release: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("key pressed 23")),
            "[{kind:?}] missing i press: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("key released 23")),
            "[{kind:?}] missing i release: {lines:?}"
        );
    }
}

#[tokio::test]
async fn combo_is_received_by_target() {
    if skip_unless_ready() {
        return;
    }
    let _guard = SUITE_LOCK.lock().await;

    for kind in &ALL_FIXTURE_KINDS {
        let env = TestEnv::start(*kind);
        let pid = env.pid();
        let session = Session::new(pid).await.expect("Session::new failed");
        reregister_input(pid);

        session
            .keyboard
            .combo(&[backseat::keys::Key::LeftCtrl, backseat::keys::Key::C])
            .await
            .expect("combo failed");
        tokio::time::sleep(Duration::from_millis(300)).await;
        let lines = env.read_events(4);
        assert!(
            lines.iter().any(|l| l.contains("key pressed 29")),
            "[{kind:?}] missing ctrl press: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("key pressed 46")),
            "[{kind:?}] missing c press: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("key released 46")),
            "[{kind:?}] missing c release: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("key released 29")),
            "[{kind:?}] missing ctrl release: {lines:?}"
        );
    }
}
