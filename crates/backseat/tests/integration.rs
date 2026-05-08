//! Integration tests for `backseat`.
//!
//! These tests require:
//! - A running Wayland session (`WAYLAND_DISPLAY` must be set).
//! - `ptrace` permission over the target process.
//!
//! Tests are marked `#[ignore]` so that `cargo test` passes on CI and machines
//! without Wayland.  Run them locally with:
//!
//! ```bash
//! cargo test -p backseat --test integration -- --ignored
//! ```

use std::time::Duration;

use backseat::{Error, Session};

/// Detect whether the current environment supports integration tests.
fn have_wayland_and_ptrace() -> bool {
    if std::env::var("WAYLAND_DISPLAY").is_err() {
        return false;
    }
    // Check Yama ptrace_scope. 0 = permissive, 1 = restricted (same user OK).
    if let Ok(scope) = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        let scope: i32 = scope.trim().parse().unwrap_or(1);
        if scope > 1 {
            return false;
        }
    }
    true
}

/// Spawn a simple GTK4 or Qt6 test application.  For this test we just
/// validate that `Session::new` on our own PID fails gracefully because
/// we cannot ptrace ourselves while running normally.
#[tokio::test]
#[ignore = "requires Wayland + ptrace"]
async fn test_self_injection_fails_gracefully() {
    if !have_wayland_and_ptrace() {
        eprintln!("Skipping integration test: no Wayland or ptrace permission");
        return;
    }

    let own_pid = std::process::id();
    let result = Session::new(own_pid).await;
    // ptrace attach on self returns EPERM on Linux.
    assert!(
        matches!(result, Err(Error::PermissionDenied(pid)) if pid == own_pid),
        "expected PermissionDenied for self-ptrace, got {result:?}"
    );
}

/// Validate `Session::from_name` with a name that definitely does not exist.
#[tokio::test]
#[ignore = "requires Wayland + ptrace"]
async fn test_from_name_not_found() {
    if !have_wayland_and_ptrace() {
        eprintln!("Skipping integration test: no Wayland or ptrace permission");
        return;
    }

    let result = Session::from_name("definitely_not_a_real_process_name_12345").await;
    assert!(
        matches!(result, Err(Error::ProcessNotFound(name)) if name == "definitely_not_a_real_process_name_12345")
    );
}

/// Full end-to-end smoke test against a real Wayland application.
///
/// This test tries to find a running `weston-terminal` or `gtk4-demo` and
/// inject into it.  If no suitable target is found, the test is skipped.
#[tokio::test]
#[ignore = "requires Wayland + ptrace + a target app"]
async fn test_smoke_inject_and_surface_size() {
    if !have_wayland_and_ptrace() {
        eprintln!("Skipping integration test: no Wayland or ptrace permission");
        return;
    }

    // Try a few common demo app names.
    let candidates = &["weston-terminal", "gtk4-demo", "qt6-demo", "sdl2-test"];
    let mut session = None;
    for &name in candidates {
        if let Ok(s) = Session::from_name(name).await {
            session = Some(s);
            break;
        }
    }
    let Some(session) = session else {
        eprintln!("No suitable target application found — skipping smoke test");
        return;
    };

    // Query surface size (non-blocking, IPC-thread only).
    let size = tokio::time::timeout(Duration::from_secs(3), session.mouse.surface_size()).await;
    match size {
        Ok(Ok((w, h))) => {
            assert!(w > 0);
            assert!(h > 0);
        }
        Ok(Err(Error::ProxyNotFound { .. })) => {
            // Surface not yet configured — acceptable for a freshly-mapped window.
        }
        Err(_) => panic!("surface_size timed out"),
        other => panic!("unexpected result: {:?}", other),
    }

    // Send a harmless mouse move to the centre of the surface.
    if let Ok((w, h)) = session.mouse.surface_size().await {
        session
            .mouse
            .move_to((w / 2) as f64, (h / 2) as f64)
            .await
            .expect("mouse_move failed");
    }

    // Type a short string.
    session
        .keyboard
        .type_text("hi")
        .await
        .expect("type_text failed");

    // Explicit cleanup.
    session.unload().await.expect("unload failed");
}
