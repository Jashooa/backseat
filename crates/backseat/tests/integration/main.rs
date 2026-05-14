//! Integration tests for `backseat`.
//!
//! Each test that needs Wayland infrastructure creates its own compositor
//! and fixture, which are cleaned up when the test scope exits (via Drop).
//! Tests share a `SUITE_LOCK` to run sequentially.

mod helpers;

use std::path::PathBuf;
use std::time::Duration;

use backseat::Session;
use tokio::sync::Mutex;

use helpers::compositor::Compositor;
use helpers::target_app::TargetApp;

static SUITE_LOCK: Mutex<()> = Mutex::const_new(());

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
#[ignore = "requires Wayland + ptrace"]
async fn inject_and_unload() {
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
    // env dropped here → compositor + fixture killed
}

#[tokio::test]
#[ignore = "requires Wayland + ptrace"]
async fn drop_auto_unloads() {
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
#[ignore = "requires Wayland + ptrace"]
async fn reinject_after_unload_works() {
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
#[ignore = "requires Wayland + ptrace"]
async fn session_from_name_finds_process() {
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
// Input event tests — skipped pending dispatcher support in the payload.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires dispatcher support in payload"]
async fn key_tap_is_received_by_target() {}

#[tokio::test]
#[ignore = "requires dispatcher support in payload"]
async fn mouse_click_is_received_by_target() {}

#[tokio::test]
#[ignore = "requires dispatcher support in payload"]
async fn type_text_is_received_by_target() {}

#[tokio::test]
#[ignore = "requires dispatcher support in payload"]
async fn combo_is_received_by_target() {}
