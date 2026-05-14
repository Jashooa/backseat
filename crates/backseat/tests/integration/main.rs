//! Integration tests for `backseat`.
//!
//! Each test that needs Wayland infrastructure creates its own compositor
//! and fixture, which are cleaned up when the test scope exits (via Drop).
//! Tests share a `SUITE_LOCK` to run sequentially.
//!
//! These tests run by default on Linux when `weston` is found in `$PATH`
//! and `/proc/sys/kernel/yama/ptrace_scope` is 0.  On systems missing
//! either prerequisite the tests pass trivially (they do not fail).

mod helpers;

use std::path::PathBuf;
use std::time::Duration;

use backseat::Session;
use tokio::sync::Mutex;

use helpers::compositor::Compositor;
use helpers::target_app::TargetApp;

static SUITE_LOCK: Mutex<()> = Mutex::const_new(());

/// Returns `Ok(())` if the local machine has `weston` and ptrace
/// available, or `Err(reason)` describing what's missing.
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
    match std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        Ok(s) if s.trim() == "0" => {}
        Ok(s) => return Err(format!("ptrace_scope is {}, need 0", s.trim())),
        Err(_) => {} // no yama, ptrace unrestricted
    }
    Ok(())
}

/// A running compositor + fixture pair.  Dropping this struct kills both
/// child processes, guaranteeing no stale processes survive the test.
struct TestEnv {
    _compositor: Compositor,
    target: std::sync::Mutex<TargetApp>,
}

impl TestEnv {
    fn start() -> Self {
        let compositor = Compositor::start();
        std::thread::sleep(Duration::from_millis(500));
        std::env::set_var(
            "XDG_RUNTIME_DIR",
            compositor.runtime_dir().to_str().unwrap(),
        );

        let mut target = TargetApp::start(&compositor);
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
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn inject_and_unload() {
    if let Err(reason) = check_prerequisites() {
        eprintln!("SKIP: {reason}");
        return;
    }
    let _guard = SUITE_LOCK.lock().await;
    let env = TestEnv::start();

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
    if let Err(reason) = check_prerequisites() {
        eprintln!("SKIP: {reason}");
        return;
    }
    let _guard = SUITE_LOCK.lock().await;
    let env = TestEnv::start();

    let pid = env.pid();
    {
        let _session = Session::new(pid).await.expect("Session::new failed");
        assert!(socket_path(pid).exists());
    }
    wait_for_socket_gone(pid).await;
}

#[tokio::test]
async fn reinject_after_unload_works() {
    if let Err(reason) = check_prerequisites() {
        eprintln!("SKIP: {reason}");
        return;
    }
    let _guard = SUITE_LOCK.lock().await;
    let env = TestEnv::start();

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
    if let Err(reason) = check_prerequisites() {
        eprintln!("SKIP: {reason}");
        return;
    }
    let _guard = SUITE_LOCK.lock().await;
    let _env = TestEnv::start();

    let result = Session::from_name("backseat-test-fixture").await;
    assert!(
        result.is_ok(),
        "Session::from_name should find the fixture: {result:?}"
    );
    let session = result.unwrap();
    session.unload().await.expect("unload failed");
}

// ---------------------------------------------------------------------------
// Input event tests
// ---------------------------------------------------------------------------

/// Helper: send SIGUSR2 to the fixture so it re-requests keyboard and
/// pointer proxies.  The payload's hooked `wl_proxy_add_dispatcher` will
/// capture them.
fn reregister_input(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGUSR2);
    }
    // Give the fixture a moment to process the signal in its next
    // dispatch cycle and for the payload's hook to fire.
    std::thread::sleep(Duration::from_millis(200));
}

#[tokio::test]
async fn key_tap_is_received_by_target() {
    if let Err(reason) = check_prerequisites() {
        eprintln!("SKIP: {reason}");
        return;
    }
    let _guard = SUITE_LOCK.lock().await;
    let env = TestEnv::start();
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
        "missing press: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("key released 30")),
        "missing release: {lines:?}"
    );
}

#[tokio::test]
async fn mouse_click_is_received_by_target() {
    if let Err(reason) = check_prerequisites() {
        eprintln!("SKIP: {reason}");
        return;
    }
    let _guard = SUITE_LOCK.lock().await;
    let env = TestEnv::start();
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
        "missing press: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("button released 272")),
        "missing release: {lines:?}"
    );
}

#[tokio::test]
async fn type_text_is_received_by_target() {
    if let Err(reason) = check_prerequisites() {
        eprintln!("SKIP: {reason}");
        return;
    }
    let _guard = SUITE_LOCK.lock().await;
    let env = TestEnv::start();
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
        "missing h press: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("key released 35")),
        "missing h release: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("key pressed 23")),
        "missing i press: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("key released 23")),
        "missing i release: {lines:?}"
    );
}

#[tokio::test]
async fn combo_is_received_by_target() {
    if let Err(reason) = check_prerequisites() {
        eprintln!("SKIP: {reason}");
        return;
    }
    let _guard = SUITE_LOCK.lock().await;
    let env = TestEnv::start();
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
        "missing ctrl press: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("key pressed 46")),
        "missing c press: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("key released 46")),
        "missing c release: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("key released 29")),
        "missing ctrl release: {lines:?}"
    );
}
