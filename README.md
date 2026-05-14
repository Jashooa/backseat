# backseat

**Wayland Background Input Injection**

`backseat` injects a shared library into a running Wayland application and
communicates with it over a Unix socket to synthesise mouse and keyboard
events. Because the events are delivered inside the target's own
`wl_display_dispatch` call, the compositor never sees them — the application
treats them as genuine input.

## Why

Wayland has no equivalent of X11's `XTest` extension — there is no global,
unprivileged API for injecting input across arbitrary applications. The
`virtual-keyboard-unstable-v1` and `wlr-virtual-pointer-unstable-v1` protocols
exist, but they require the compositor to implement them and to trust the
calling client.  You can't `xdotool click 1` on Wayland.

`backseat` solves this from the other direction.  Instead of asking the
compositor for permission, it injects a payload directly into the target
application's process.  The payload hooks the app's own Wayland event loop and
synthesises input events that are indistinguishable from real hardware input.
The compositor never knows the difference.

This makes `backseat` useful for:

- **Test automation** — drive Wayland-native apps without instrumenting them
- **Accessibility tooling** — emulate keyboard and mouse for users who need it
- **Scripting / macros** — automate repetitive interactions in any Wayland app

[![CI](https://github.com/Jashooa/backseat/actions/workflows/ci.yml/badge.svg)](https://github.com/Jashooa/backseat/actions/workflows/ci.yml)

## Quick start

```rust
use backseat::{Session, Button, Key, Axis};

#[tokio::main]
async fn main() -> Result<(), backseat::Error> {
    let session = Session::new(12345).await?;

    let (w, h) = session.mouse.surface_size().await?;
    session.mouse.move_to((w / 2) as f64, (h / 2) as f64).await?;
    session.mouse.click(Button::Left).await?;
    session.keyboard.type_text("hello world").await?;

    session.unload().await?;
    Ok(())
}
```

## Requirements

- **OS:** Linux x86_64
- **Runtime:** Target application must use dynamically-linked `libwayland-client`
- **Permissions:** Caller must have `ptrace` permission over the target process
  (same UID, `CAP_SYS_PTRACE`, or Yama `ptrace_scope = 0/1`)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
backseat = "0.2"
tokio = { version = "1", features = ["full"] }
```

## Usage

### By PID

```rust
let session = Session::new(12345).await?;
```

### By process name

```rust
let session = Session::from_name("firefox").await?;
```

Returns `Err(AmbiguousProcessName)` if more than one process matches — use
`Session::new(pid)` to disambiguate.

### Mouse

```rust
session.mouse.move_to(500.0, 300.0).await?;
session.mouse.click(Button::Left).await?;
session.mouse.scroll(Axis::Vertical, 3.0).await?;
```

Coordinates are **window-local** (relative to the app's primary surface).
Use `surface_size()` to derive absolute coordinates.

### Keyboard

```rust
session.keyboard.tap(Key::Enter).await?;
session.keyboard.type_text("hello world").await?;
session.keyboard.combo(&[Key::LeftCtrl, Key::C]).await?;
```

`type_text` is ASCII-only. Non-ASCII / CJK input requires `zwp_text_input_v3`
(deferred to a later version).

### Cleanup

Always prefer explicit cleanup:

```rust
session.unload().await?;
```

`Drop` attempts best-effort cleanup in a background thread, but may leak if the
Tokio runtime is already shutting down.

## Error handling

`backseat::Error` is fully structured — no string parsing required:

```rust
match Session::from_name("myapp").await {
    Err(backseat::Error::ProcessNotFound(name)) =>
        eprintln!("Process '{}' not running", name),
    Err(backseat::Error::AmbiguousProcessName { name, pids }) =>
        eprintln!("Multiple '{}' processes: {:?}", name, pids),
    Err(backseat::Error::PermissionDenied(pid)) =>
        eprintln!("Need ptrace permission for PID {}", pid),
    Err(backseat::Error::ProxyNotFound { kind }) =>
        eprintln!("App didn't have a {:?} proxy yet — try after it initializes", kind),
    Err(e) => eprintln!("Unexpected error: {}", e),
    Ok(session) => { /* ... */ }
}
```

## Architecture

The crate is a Cargo workspace with two crates:

- **`backseat-payload`** — a `cdylib` that is injected into the target process.
  It patches GOT entries to intercept `wl_display_dispatch*` functions, captures
  Wayland proxies from the C library's `wl_map`, and dispatches synthetic input
  on the application's own event thread.
- **`backseat`** — the published API crate. It embeds the payload at compile
  time, performs ptrace injection, and handles IPC over a per-process Unix
  socket.

## Security

`backseat` requires `ptrace` capability over the target process. It is intended
for automation, testing, and accessibility tooling — not for use against
processes the operator does not own. The payload is visible in `/proc/PID/maps`
and no attempt is made to conceal the injection.

## Limitations

- x86-64 only (AArch64 deferred)
- Dynamically-linked `libwayland-client` only
- `wl_display_dispatch` / `wl_display_dispatch_pending` hook only — apps using
  `wl_display_roundtrip` exclusively won't trigger the hook
- `move_by` is not supported in v0.2 (no cursor position tracking)
- ASCII-only text input
- No XWayland support (deferred to v0.3)
- Multithreaded targets: injection attaches the thread group leader while
  other threads continue running.  This can deadlock the dynamic loader if
  another thread is inside `dlopen`/`dlsym` at the moment of injection.
- PID reuse is possible (but unlikely) between `Session::from_name` resolution
  and `ptrace::attach`.  Use `Session::new(pid)` when stability is critical.
- Dispatcher-style proxies (`wl_proxy_add_dispatcher`, used by `wayland-rs`
  v0.31+, winit, iced, COSMIC, etc.) are not yet supported.  The payload's
  `initial_sweep` cannot find dispatcher proxies in the C library's `wl_map`,
  so `surface_size()`, `G_POINTER`, and `G_KEYBOARD` remain unset.  Synthetic
  events silently fail for these clients.  Use `wl_proxy_add_listener`-based
  clients (raw libwayland, `wayland-rs` v0.30, GTK3) for full functionality.

## Development

```bash
# Set up the pre-commit hook (fmt → clippy → test)
make setup-hooks

# Everything in one go: format, lint, and test
make all

# Individual steps
make fmt          # apply formatting
make clippy       # lint with clippy
make test         # unit + doc tests
make test-all     # test entire workspace
make integration  # integration tests (requires Wayland + ptrace)
```

Integration tests require `weston` (headless compositor) and
`ptrace_scope = 0`:

```bash
sudo apt-get install weston
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
cargo test -p backseat --test integration -- --ignored --test-threads=1
```

Each test starts its own headless compositor and fixture, so no state
leaks between tests.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
