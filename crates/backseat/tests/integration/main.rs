//! Integration tests for `backseat`.
//!
//! These tests require:
//! - A running Wayland session (we spin up `weston --backend=headless`).
//! - `ptrace` permission over the target process.
//!
//! Tests share a single compositor and fixture process across the suite
//! (via `std::sync::OnceLock`) and run sequentially (via
//! `tokio::sync::Mutex`).  Each test resets the fixture between runs.
//!
//! Run locally with:
//! ```bash
//! cargo test -p backseat --test integration -- --ignored --test-threads=1
//! ```

mod helpers;

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use backseat::{Button, Key, Session};
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Shared suite state
// ---------------------------------------------------------------------------

/// Serialises test execution so only one test runs at a time.
static SUITE_LOCK: Mutex<()> = Mutex::const_new(());

/// Shared headless compositor — initialised once for the whole suite.
static COMPOSITOR: OnceLock<helpers::compositor::Compositor> = OnceLock::new();

/// Shared test fixture — initialised once, reset between tests via SIGUSR1.
static TARGET: OnceLock<std::sync::Mutex<helpers::target_app::TargetApp>> = OnceLock::new();

/// Ensure the compositor and fixture are running.
fn ensure_setup() {
    let compositor = COMPOSITOR.get_or_init(|| {
        let c = helpers::compositor::Compositor::start();
        // Weston needs a moment to create the socket.
        std::thread::sleep(Duration::from_millis(500));
        c
    });

    TARGET.get_or_init(|| {
        let mut target = helpers::target_app::TargetApp::start(compositor);
        target.wait_for_event("ready", Duration::from_secs(5));
        std::sync::Mutex::new(target)
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Poll `surface_size` with retries until the payload has captured the
/// toplevel proxy and received a configure event.
async fn wait_for_surface_size(session: &Session) -> (u32, u32) {
    for _ in 0..20 {
        match tokio::time::timeout(Duration::from_millis(100), session.mouse.surface_size()).await {
            Ok(Ok(size)) => return size,
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    panic!("surface_size never returned a value");
}

/// Return the path to the per-PID Unix socket.
fn socket_path(pid: u32) -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(format!("backseat-{pid}.sock"))
}

/// Poll until the socket file no longer exists.
async fn wait_for_socket_gone(pid: u32) {
    for _ in 0..40 {
        if !socket_path(pid).exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("socket still exists after unload/drop");
}

/// Read the next event line from the fixture's stdout.
async fn next_event(timeout: Duration) -> String {
    tokio::task::spawn_blocking(move || {
        let mut target = TARGET.get().unwrap().lock().unwrap();
        target.next_event(timeout)
    })
    .await
    .unwrap()
}

/// Wait for a specific event prefix on the fixture's stdout.
async fn wait_for_event(event: &str, timeout: Duration) -> String {
    let event = event.to_string();
    tokio::task::spawn_blocking(move || {
        let mut target = TARGET.get().unwrap().lock().unwrap();
        target.wait_for_event(&event, timeout)
    })
    .await
    .unwrap()
}

/// Get the fixture's PID.
fn target_pid() -> u32 {
    TARGET.get().unwrap().lock().unwrap().pid()
}

/// Reset the fixture between tests (SIGUSR1 + wait for ready).
async fn reset_fixture() {
    tokio::task::spawn_blocking(|| {
        let mut target = TARGET.get().unwrap().lock().unwrap();
        target.reset();
    })
    .await
    .unwrap();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires Wayland + ptrace"]
async fn key_tap_is_received_by_target() {
    let _guard = SUITE_LOCK.lock().await;
    ensure_setup();

    let session = Session::new(target_pid())
        .await
        .expect("Session::new failed");
    wait_for_surface_size(&session).await;

    wait_for_event("keyboard_enter", Duration::from_secs(2)).await;

    session.keyboard.tap(Key::A).await.expect("tap failed");

    let events = vec![
        next_event(Duration::from_secs(2)).await,
        next_event(Duration::from_secs(2)).await,
    ];

    assert!(
        events.iter().any(|e| e.contains("key pressed 30")),
        "missing pressed event: {events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("key released 30")),
        "missing released event: {events:?}"
    );

    session.unload().await.expect("unload failed");
    reset_fixture().await;
}

#[tokio::test]
#[ignore = "requires Wayland + ptrace"]
async fn mouse_click_is_received_by_target() {
    let _guard = SUITE_LOCK.lock().await;
    ensure_setup();

    let session = Session::new(target_pid())
        .await
        .expect("Session::new failed");
    let (w, h) = wait_for_surface_size(&session).await;

    wait_for_event("pointer_enter", Duration::from_secs(2)).await;

    session
        .mouse
        .move_to((w / 2) as f64, (h / 2) as f64)
        .await
        .expect("move_to failed");

    // Wait for the motion event to arrive.
    let motion = next_event(Duration::from_secs(2)).await;
    assert!(
        motion.starts_with("EVENT: motion"),
        "unexpected event: {motion}"
    );

    session
        .mouse
        .click(Button::Left)
        .await
        .expect("click failed");

    let events = vec![
        next_event(Duration::from_secs(2)).await,
        next_event(Duration::from_secs(2)).await,
    ];

    assert!(
        events.iter().any(|e| e.contains("button pressed 272")),
        "missing button press: {events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("button released 272")),
        "missing button release: {events:?}"
    );

    session.unload().await.expect("unload failed");
    reset_fixture().await;
}

#[tokio::test]
#[ignore = "requires Wayland + ptrace"]
async fn type_text_is_received_by_target() {
    let _guard = SUITE_LOCK.lock().await;
    ensure_setup();

    let session = Session::new(target_pid())
        .await
        .expect("Session::new failed");
    wait_for_surface_size(&session).await;

    wait_for_event("keyboard_enter", Duration::from_secs(2)).await;

    session
        .keyboard
        .type_text("Hi")
        .await
        .expect("type_text failed");

    // Collect events until we see the last key release.
    let mut events = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        events.push(next_event(Duration::from_millis(200)).await);
        // 'H' produces: modifiers 1, key pressed 35, key released 35, modifiers 0
        // 'i' produces: key pressed 23, key released 23
        // We stop once we have at least the 'i' released event.
        if events.iter().any(|e| e.contains("key released 23")) {
            break;
        }
    }

    assert!(
        events.iter().any(|e| e.contains("modifiers 1")),
        "missing shift depressed: {events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("key pressed 35")),
        "missing 'H' press: {events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("key pressed 23")),
        "missing 'i' press: {events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("modifiers 0")),
        "missing shift released: {events:?}"
    );

    session.unload().await.expect("unload failed");
    reset_fixture().await;
}

#[tokio::test]
#[ignore = "requires Wayland + ptrace"]
async fn combo_is_received_by_target() {
    let _guard = SUITE_LOCK.lock().await;
    ensure_setup();

    let session = Session::new(target_pid())
        .await
        .expect("Session::new failed");
    wait_for_surface_size(&session).await;

    wait_for_event("keyboard_enter", Duration::from_secs(2)).await;

    session
        .keyboard
        .combo(&[Key::LeftCtrl, Key::C])
        .await
        .expect("combo failed");

    let events = vec![
        next_event(Duration::from_secs(2)).await,
        next_event(Duration::from_secs(2)).await,
        next_event(Duration::from_secs(2)).await,
        next_event(Duration::from_secs(2)).await,
    ];

    // Both keys pressed, then released in reverse order.
    assert!(
        events.iter().any(|e| e.contains("key pressed 29")),
        "missing LeftCtrl press: {events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("key pressed 46")),
        "missing 'C' press: {events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("key released 46")),
        "missing 'C' release: {events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("key released 29")),
        "missing LeftCtrl release: {events:?}"
    );

    session.unload().await.expect("unload failed");
    reset_fixture().await;
}

#[tokio::test]
#[ignore = "requires Wayland + ptrace"]
async fn session_from_name_finds_process() {
    let _guard = SUITE_LOCK.lock().await;
    ensure_setup();

    // from_name searches by cmdline; the fixture binary path contains
    // "backseat-test-fixture".
    let result = Session::from_name("backseat-test-fixture").await;
    assert!(
        result.is_ok(),
        "Session::from_name should find the fixture: {result:?}"
    );

    let session = result.unwrap();
    session.unload().await.expect("unload failed");
    reset_fixture().await;
}

#[tokio::test]
#[ignore = "requires Wayland + ptrace"]
async fn unload_cleans_up_socket() {
    let _guard = SUITE_LOCK.lock().await;
    ensure_setup();

    let pid = target_pid();
    let session = Session::new(pid).await.expect("Session::new failed");
    wait_for_surface_size(&session).await;

    assert!(
        socket_path(pid).exists(),
        "socket should exist after Session::new"
    );

    session.unload().await.expect("unload failed");
    wait_for_socket_gone(pid).await;

    reset_fixture().await;
}

#[tokio::test]
#[ignore = "requires Wayland + ptrace"]
async fn drop_auto_unloads() {
    let _guard = SUITE_LOCK.lock().await;
    ensure_setup();

    let pid = target_pid();
    {
        let session = Session::new(pid).await.expect("Session::new failed");
        wait_for_surface_size(&session).await;
        assert!(
            socket_path(pid).exists(),
            "socket should exist after Session::new"
        );
        // session is dropped here — Drop should send unload and clean up.
    }

    wait_for_socket_gone(pid).await;
    reset_fixture().await;
}

#[tokio::test]
#[ignore = "requires Wayland + ptrace"]
async fn reinject_after_unload_works() {
    let _guard = SUITE_LOCK.lock().await;
    ensure_setup();

    let pid = target_pid();

    // First session.
    let session = Session::new(pid).await.expect("first Session::new failed");
    wait_for_surface_size(&session).await;
    session.unload().await.expect("unload failed");
    wait_for_socket_gone(pid).await;

    // Give the payload's IPC thread time to wind down fully.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Second session on the same PID.
    let session2 = Session::new(pid).await.expect("second Session::new failed");
    wait_for_surface_size(&session2).await;
    session2.unload().await.expect("unload failed");

    reset_fixture().await;
}
