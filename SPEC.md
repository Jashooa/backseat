# backseat

**Wayland Background Input Injection — Technical Specification**
`v0.2.2 · Rust Crate`

---

## 1. Overview

Wayland's security model deliberately prevents applications from sending input to other windows. **backseat** works around this at the process level rather than the compositor level: it uses `ptrace` to inject a shared library (the payload) into the target process, then communicates with that payload over a Unix socket to invoke Wayland input listener callbacks directly inside the target's own event loop.

Because the callbacks are invoked from within the process itself — on the app's own event thread — the compositor never sees the input at all. It is indistinguishable from real input as far as the application is concerned.

**Primary use case:** background automation — scripting input to an application while the user does other things on the same desktop. The target may be unfocused, minimized, or behind other windows.

> **Scope:** backseat targets Linux x86-64 with Wayland and dynamically-linked libwayland-client. Apps using GTK4, Qt6, SDL2, or raw libwayland-client are supported. XWayland support is deferred to v0.3 (see §10). Statically-linked libwayland is out of scope.

---

## 2. Architecture

The crate is structured as a Cargo workspace with two internal crates. Only the top-level crate is published.

```
backseat/                    ← workspace root
├── Cargo.toml               ← workspace
├── crates/
│   ├── backseat/            ← published API crate
│   │   ├── build.rs         ← reads compiled payload from sibling crate
│   │   └── src/
│   │       ├── lib.rs               ← public API
│   │       ├── session.rs           ← Session struct
│   │       ├── injector.rs          ← ptrace injection logic
│   │       ├── mouse.rs             ← Mouse API
│   │       ├── keyboard.rs          ← Keyboard API
│   │       ├── keys.rs              ← Key / Button / Axis enums
│   │       └── error.rs             ← Error type
│   └── backseat-payload/    ← cdylib, compiled normally as workspace member
│       ├── Cargo.toml       ← crate-type = ["cdylib"]
│       └── src/lib.rs       ← injected .so: proxy capture, IPC, dispatch hook
```

### 2.1 Payload embedding

`backseat-payload` builds as a normal cdylib workspace member, producing `libbackseat_payload.so` in `target/<profile>/`. The published `backseat` crate's `build.rs` reads that file at compile time:

```rust
include_bytes!(concat!(env!("BACKSEAT_PAYLOAD_PATH"), "/libbackseat_payload.so"))
```

Cargo handles the dependency ordering. No invocation of `rustc` from `build.rs` — that pattern is brittle across toolchain changes.

At runtime, `Session::new()` writes the embedded bytes to `/tmp/backseat-payload-<sha256_prefix>.so` if not already present. The SHA-256 prefix ensures stale payloads from old crate versions are never reused.

---

## 3. Public API

### 3.1 Session

```rust
pub struct Session {
    pub mouse:    Mouse,
    pub keyboard: Keyboard,
    // Internal: Arc<Mutex<UnixStream>> shared with Mouse and Keyboard.
}

impl Session {
    /// Find process by PID and inject.
    pub async fn new(pid: u32) -> Result<Self, Error>;

    /// Find process by name. Returns Err(AmbiguousProcessName) if more than
    /// one process matches — caller must use Session::new(pid) to disambiguate.
    /// Process matching uses /proc/<PID>/comm (truncated to 15 bytes) and
    /// /proc/<PID>/cmdline[0] basename, in that order.
    pub async fn from_name(name: &str) -> Result<Self, Error>;

    /// Explicitly unload the payload and clean up.
    /// PREFERRED over relying on Drop — see Drop semantics below.
    pub async fn unload(self) -> Result<(), Error>;
}

/// Drop is best-effort: spawns a blocking task to unload, but if the tokio
/// runtime is shutting down the payload may leak. Always prefer explicit
/// `.unload().await` in production code; Drop is for ergonomics in REPLs/tests.
impl Drop for Session { ... }
```

`Session: Send + Sync` (so it can move across `tokio::spawn` boundaries).

### 3.2 Mouse

```rust
pub struct Mouse {
    // Holds Arc<Mutex<UnixStream>> shared with Keyboard via Session.
}

impl Mouse {
    /// Coordinates are WINDOW-LOCAL (relative to the app's primary surface,
    /// origin top-left). Backgrounded apps have no concept of "screen
    /// coordinates" so screen-global mapping is impossible — use
    /// `surface_size()` to derive coordinates relative to the current logical
    /// surface size.
    pub async fn move_to(&self, x: f64, y: f64) -> Result<(), Error>;
    pub async fn move_by(&self, dx: f64, dy: f64) -> Result<(), Error>;

    pub async fn click(&self, button: Button) -> Result<(), Error>;
    pub async fn double_click(&self, button: Button) -> Result<(), Error>;
    pub async fn down(&self, button: Button) -> Result<(), Error>;
    pub async fn up(&self, button: Button) -> Result<(), Error>;

    pub async fn scroll(&self, axis: Axis, amount: f64) -> Result<(), Error>;

    /// Report the surface's current logical size in window-local pixel units.
    /// Tracked by the payload via xdg_surface/xdg_toplevel configure events
    /// (see §5.5). Returns the most recent (width, height) the compositor
    /// has acknowledged for the target's primary surface.
    pub async fn surface_size(&self) -> Result<(u32, u32), Error>;
}
```

`Mouse: Send + Sync`.

### 3.3 Keyboard

```rust
pub struct Keyboard {
    // Holds Arc<Mutex<UnixStream>> shared with Mouse via Session.
}

impl Keyboard {
    pub async fn tap(&self, key: Key) -> Result<(), Error>;
    pub async fn down(&self, key: Key) -> Result<(), Error>;
    pub async fn up(&self, key: Key) -> Result<(), Error>;

    /// Sends key_down + key_up for each character.
    /// ASCII only — for IME / CJK / non-ASCII, the zwp_text_input_v3
    /// protocol is required (deferred to a later version, §10).
    pub async fn type_text(&self, text: &str) -> Result<(), Error>;

    /// Holds all keys simultaneously, releases in reverse order.
    pub async fn combo(&self, keys: &[Key]) -> Result<(), Error>;
}
```

`Keyboard: Send + Sync`.

### 3.4 Concurrency model

`Session` owns a single `Arc<Mutex<tokio::net::UnixStream>>` representing the IPC connection to the payload. `Mouse` and `Keyboard` each hold a clone of that `Arc`. There is one socket per Session — `Mouse` and `Keyboard` are not independent connections.

Concurrent calls on `Mouse` and `Keyboard` from different tasks are serialized at the mutex. Each call sends one JSON request and awaits its `{"status":"ok"}` (or error) reply before releasing the mutex; requests cannot interleave on the wire. This matters because the payload's IPC thread processes commands sequentially — overlapping requests would lose response ordering.

Throughput characteristics in §7.3.

### 3.5 Enums

```rust
pub enum Button { Left, Right, Middle, Back, Forward }

pub enum Axis { Vertical, Horizontal }

pub enum Key {
    // Alphabet
    A, B, C, D, E, F, G, H, I, J, K, L, M,
    N, O, P, Q, R, S, T, U, V, W, X, Y, Z,

    // Digits
    Num0, Num1, Num2, Num3, Num4,
    Num5, Num6, Num7, Num8, Num9,

    // Function keys
    F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12,

    // Navigation
    Up, Down, Left, Right,
    Home, End, PageUp, PageDown,
    Insert, Delete,

    // Modifiers
    LeftShift, RightShift,
    LeftCtrl, RightCtrl,
    LeftAlt, RightAlt,
    LeftMeta, RightMeta,

    // Common
    Enter, Escape, Tab, Backspace, Space,
    CapsLock, PrintScreen, ScrollLock, Pause,

    // Punctuation
    Minus, Equal, LeftBrace, RightBrace,
    Backslash, Semicolon, Apostrophe,
    Grave, Comma, Dot, Slash,

    // Raw fallback for anything not in the enum
    Raw(u32),
}
```

All enums derive `Debug, Clone, Copy, PartialEq, Eq, Hash`.

### 3.6 Error

```rust
pub enum Error {
    // Process lookup
    ProcessNotFound(String),
    AmbiguousProcessName { name: String, pids: Vec<u32> },  // multiple matches
    PermissionDenied(u32),

    // Injection — fully structured
    DlopenReturnedNull { pid: u32 },
    PtraceFailed { pid: u32, op: PtraceOp, errno: i32 },
    ShellcodeWriteFailed { pid: u32, addr: u64, errno: i32 },
    PayloadExtractFailed(io::Error),
    LibcResolutionFailed { pid: u32 },          // couldn't find libc/dlopen in target

    // IPC
    SocketTimeout { phase: SocketPhase },       // bind / connect / handshake / call
    SocketError(io::Error),
    ProtocolMismatch { expected: u32, got: u32 },
    Disconnected,                                // process exited after injection

    // Input — structured by failure mode
    ProxyNotFound { kind: ProxyKind },           // pointer/keyboard/seat/xdg surface/toplevel
    ListenerNull { kind: ProxyKind },            // proxy found but no listener attached
    DispatchHookNotInstalled,                    // app doesn't use wl_display_dispatch

    // Unload
    UnloadFailed(String),
}

pub enum PtraceOp { Attach, Detach, GetRegs, SetRegs, Cont, PokeData, PokeText }
pub enum SocketPhase { Bind, Connect, Handshake, Call }
pub enum ProxyKind { Pointer, Keyboard, Seat, XdgSurface, XdgToplevel }

impl std::error::Error for Error {}
impl std::fmt::Display for Error {}
```

All variants are matchable; downstream code can distinguish transient (`ProxyNotFound` → rescan) from fatal (`Disconnected` → process died) without string parsing.

---

## 4. Usage Examples

### 4.1 Basic

```rust
use backseat::{Session, Key, Button, Axis};

#[tokio::main]
async fn main() -> Result<(), backseat::Error> {
    // By PID
    let session = Session::new(12345).await?;

    // Or by process name (errors with AmbiguousProcessName if multiple match)
    let session = Session::from_name("firefox").await?;

    // Coordinates are window-local
    let (w, h) = session.mouse.surface_size().await?;
    session.mouse.move_to((w / 2) as f64, (h / 2) as f64).await?;

    session.mouse.click(Button::Left).await?;
    session.mouse.scroll(Axis::Vertical, 3.0).await?;

    session.keyboard.tap(Key::Enter).await?;
    session.keyboard.type_text("hello world").await?;
    session.keyboard.combo(&[Key::LeftCtrl, Key::C]).await?;

    session.unload().await?;  // explicit cleanup preferred
    Ok(())
}
```

### 4.2 Error handling

```rust
match Session::from_name("myapp").await {
    Err(backseat::Error::ProcessNotFound(name)) =>
        eprintln!("Process '{}' not running", name),
    Err(backseat::Error::AmbiguousProcessName { name, pids }) =>
        eprintln!("Multiple '{}' processes: {:?} — use Session::new(pid)", name, pids),
    Err(backseat::Error::PermissionDenied(pid)) =>
        eprintln!("Need ptrace permission for PID {}", pid),
    Err(backseat::Error::DlopenReturnedNull { pid }) =>
        eprintln!("Injection reached target but dlopen failed in PID {}", pid),
    Err(backseat::Error::ProxyNotFound { kind }) =>
        eprintln!("App didn't have a {:?} proxy yet — try after it initializes", kind),
    Err(backseat::Error::ProtocolMismatch { expected, got }) =>
        eprintln!("Crate version mismatch — expected v{}, payload speaks v{}", expected, got),
    Err(e) => eprintln!("Unexpected error: {}", e),
    Ok(session) => { /* ... */ }
}
```

### 4.3 Cargo.toml

```toml
[dependencies]
backseat = "0.2"
tokio = { version = "1", features = ["full"] }
```

---

## 5. Payload Internals

This section documents what the injected `.so` does. Users of the crate do not need to understand this; it is relevant for contributors and auditors.

### 5.1 Startup sequence

When the payload `.so` is loaded via `dlopen`, its `.init_array` constructor runs:

1. Creates a self-pipe for cross-thread wakeup
2. Installs the PLT-shadow set documented in §5.2
3. Performs an initial sweep of libwayland's internal proxy table to capture proxies that already exist at injection time (§5.3)
4. Spawns an IPC thread that binds a Unix socket at `/tmp/backseat-<PID>.sock`, performs a version handshake (§7.1), and listens for JSON commands

There is no fixed startup wait. Hooks fire as the app continues normal operation.

### 5.2 PLT-shadow set

All hooks use the same PLT-shadowing mechanism: the payload `.so` exports symbols with names matching libwayland-client exports. Because the payload loads *after* libwayland-client at runtime, its symbols shadow the originals in the PLT of any code linked against libwayland.

**All exported libwayland symbols are stable, exported public API in libwayland-client.so**, which is what makes this technique work without per-version brittleness.

| Hooked symbol | Purpose | Behavior |
|---|---|---|
| `wl_display_dispatch` | Drain the host command queue on the app's event thread | Drain queue, then call real via `RTLD_NEXT` |
| `wl_display_dispatch_pending` | Same as above, for the pending variant | Same |
| `wl_registry_bind` | Capture `wl_seat` proxy when bound from the registry | Detect interface == `"wl_seat"`, store proxy atomically, call real via `RTLD_NEXT` |
| `wl_seat_get_pointer` | Capture `wl_pointer` when the app requests one from a seat | Store new proxy atomically, call real via `RTLD_NEXT` |
| `wl_seat_get_keyboard` | Capture `wl_keyboard` similarly | Store new proxy atomically, call real via `RTLD_NEXT` |
| `xdg_surface_add_listener` | Wrap configure callback for surface lifecycle | Swap in shim listener that updates atomic state then calls original |
| `xdg_toplevel_add_listener` | Wrap configure callback for size tracking (§5.5) | Swap in shim listener that updates `g_surface_w`/`g_surface_h` then calls original |

**Why these instead of generic `wl_proxy_create`?** `wl_proxy_create` fires for every proxy in the system — surfaces, buffers, callbacks, all of them — and would force interface-name filtering on every call. The targeted hooks above fire only for the specific creation paths we care about, eliminating filter overhead and making the intent obvious in code.

All hooks call the real implementation via `dlsym(RTLD_NEXT, ...)` — none fully replace behavior. The payload is purely additive.

### 5.3 Proxy capture

Two complementary mechanisms:

**Hook on creation.** The PLT shadows in §5.2 (`wl_registry_bind`, `wl_seat_get_pointer`, `wl_seat_get_keyboard`) capture proxies as they are created during normal app operation. Each hook stores the new proxy pointer in atomic global state.

**Initial sweep.** For proxies that already exist at injection time (the common case for a long-running app), the payload walks `wl_display->proxy_table` (an internal libwayland data structure that has been ABI-stable across libwayland 1.x). For each entry, `wl_proxy_get_interface(proxy)->name` is checked against `"wl_seat"` / `"wl_pointer"` / `"wl_keyboard"` and stored if matched.

Global state in the payload:

```c
static atomic_ptr<wl_proxy>     g_pointer       = NULL;
static atomic_ptr<wl_proxy>     g_keyboard      = NULL;
static atomic_ptr<wl_proxy>     g_seat          = NULL;
static atomic_ptr<xdg_surface>  g_xdg_surface   = NULL;
static atomic_ptr<xdg_toplevel> g_xdg_toplevel  = NULL;
static atomic<uint32_t>         g_surface_w     = 0;
static atomic<uint32_t>         g_surface_h     = 0;
```

Reads from the dispatch hook use `atomic_load_acquire`. Writes from creation/configure hooks use `atomic_store_release`. This is sufficient: the dispatch hook only needs a consistent (proxy, listener) pair at the moment of dispatch, and libwayland's API ordering guarantees listener pointers are written before the proxy is exposed to the application.

### 5.4 Dispatch hook

`wl_display_dispatch` and `wl_display_dispatch_pending` shadows have the same signatures as the real libwayland exports. On entry, each hook:

1. Drains the pending command queue (§7) on the app's event thread, ensuring callbacks are invoked from a thread the app's listener code expects
2. Calls the real libwayland function via `dlsym(RTLD_NEXT, ...)` to preserve normal behavior

This piggybacks on the app's natural dispatch cycle — input is delivered exactly when the app would process real events. The hook adds at most a few microseconds of overhead per dispatch when the queue is empty.

### 5.5 Surface size tracking

`Mouse::surface_size()` returns the most recent logical (width, height) of the target's primary surface. The payload tracks this via the `xdg_surface_add_listener` and `xdg_toplevel_add_listener` shadows (§5.2).

**Mechanism.** When the app calls `xdg_toplevel_add_listener(toplevel, listener, data)`, the payload allocates a shim listener struct and substitutes its `configure` callback. The shim invokes the original callback first (preserving app behavior), then updates `g_surface_w` / `g_surface_h` atomically.

`xdg_toplevel.configure` is the authoritative source for surface size — it fires whenever the compositor changes the configured size and the app must ack. Reading `g_surface_w` / `g_surface_h` therefore returns the size the compositor and app currently agree on.

For surfaces created via `wl_shell_surface` (legacy) the `configure` event has the same semantics, hooked the same way.

If no configure has been received yet (surface not mapped), `surface_size()` returns `Error::ProxyNotFound { kind: XdgToplevel }`.

### 5.6 Input dispatch

Commands drained from the queue are dispatched by calling listener function pointers directly:

| Command | Callback invoked |
|---|---|
| `mouse_move` | `wl_pointer_listener.motion(data, proxy, time, x_fixed, y_fixed)` |
| `mouse_button` | `wl_pointer_listener.button(data, proxy, serial, time, btn, state)` |
| `key` | `wl_keyboard_listener.key(data, proxy, serial, time, keycode, state)` |
| `scroll` | `wl_pointer_listener.axis(data, proxy, time, axis, value_fixed)` |

Coordinates and scroll values use Wayland's signed 24.8 fixed-point format (`wl_fixed_t`). Serials are sourced from the per-display serial counter via `wl_display_get_serial()` when available, otherwise a monotonic counter seeded at 1. Apps that strictly validate serials against the seat's last-seen serial will reject monotonic-counter serials — known impact: ~5–10% of strict apps (notably some IME implementations and certain games). The session emits a warning at creation time if the seat is detected as strict.

### 5.7 Unload

Unloading reverses injection: the IPC thread receives a `{"type":"unload"}` command, calls `dlclose` on itself (triggering `.fini_array` which restores PLT entries, cleans up the socket, closes the self-pipe, and joins worker threads), and exits. The session then removes the socket file.

---

## 6. Injection Mechanism

### 6.1 Process matching (`from_name`)

`Session::from_name(name)` scans `/proc` and matches against:

1. `/proc/<PID>/comm` (truncated to 15 bytes; matches the kernel's TASK_COMM_LEN)
2. If no match, the basename of `/proc/<PID>/cmdline` field 0

Iteration is in `readdir` order over `/proc`. Multiple matches return `Error::AmbiguousProcessName { name, pids: Vec<u32> }` — the caller must use `Session::new(pid)` to disambiguate. This is intentional: PID-order or start-time disambiguation would silently pick a target that may not be what the caller intended.

### 6.2 ptrace flow

The injector performs the following steps, all reversible if any step fails:

1. `PTRACE_ATTACH` — attach to target PID and wait for SIGSTOP
2. `PTRACE_GETREGS` — save all registers
3. **Resolve target's libc and `dlopen`** — see §6.3
4. Write the payload `.so` path string onto the target stack (below the red zone)
5. Write shellcode (`mov rax, <dlopen_addr>; call rax; int3`) below the path string
6. `PTRACE_SETREGS` — set RIP to shellcode, RDI = path addr, RSI = `RTLD_NOW|RTLD_GLOBAL`
7. `PTRACE_CONT` — run until INT3 (SIGTRAP)
8. Read RAX — if NULL, return `Error::DlopenReturnedNull { pid }`
9. Restore original bytes and registers
10. `PTRACE_DETACH` — resume normal execution

### 6.3 libc and dlopen resolution

1. Parse `/proc/<PID>/maps` to find the libc mapped in the target — match against `/lib*/libc.so*`, `/lib*/ld-musl-*`, `/usr/lib*/libc.so*`, etc.
2. Read the matched libc binary from disk; locate `dlopen` (or `__libc_dlopen_mode` on glibc when `dlopen` isn't directly exported) via ELF symbol table lookup.
3. Compute the absolute address as `target_libc_base + symbol_offset`.
4. Verify by reading a few bytes at that address via `PTRACE_PEEKTEXT` and matching against the on-disk libc bytes — catches partial-corrupt mappings or wrong-libc situations.

If no dynamically-linked libc is found, return `Error::LibcResolutionFailed { pid }`. Statically-linked binaries (rare in modern desktop apps) are not supported.

### 6.4 Limitations

| Limitation | Detail |
|---|---|
| seccomp | Processes with seccomp filters blocking `PTRACE_ATTACH` (Firefox content processes, Chromium renderers, hardened Electron) return `PermissionDenied`. Inject the parent process when possible. |
| Event loop variants | Apps using `wl_display_roundtrip` exclusively or a custom epoll loop won't trigger the dispatch hook. Surfaced as `DispatchHookNotInstalled`. |
| Static libwayland | Statically-linked libwayland-client cannot be hooked via PLT shadowing. Out of scope; surfaced as `ProxyNotFound`. |
| ASLR / PIE | Injection uses `/proc/PID/maps` offset calculation — fully ASLR-safe. |
| Architecture | x86-64 only. AArch64 needs a separate code path (open question §10). |
| Throttled apps | Apps that gate input processing on visibility (some Electron, some GTK) may ignore injected events when not visible. Tracked per-toolkit in `tests/visibility/`. |

---

## 7. IPC Protocol

Communication between the host crate and the injected payload uses newline-delimited JSON over a Unix socket at `/tmp/backseat-<PID>.sock`. This is an internal protocol; consumers use the Rust API only.

### 7.1 Handshake

First exchange after `connect()`:

```jsonc
// Host → payload
{"type":"hello","protocol_version":1,"crate_version":"0.2.2"}

// Payload → host
{"type":"hello_ack","protocol_version":1,"payload_version":"0.2.2"}
```

If the payload's `protocol_version` doesn't match, the host returns `Error::ProtocolMismatch { expected, got }`. This allows the protocol to evolve without breaking pinned-version users.

### 7.2 Commands

```jsonc
{"type":"mouse_move","x":500.0,"y":300.0}
{"type":"mouse_button","button":0,"state":"pressed"}
{"type":"key","key":30,"state":"released"}
{"type":"scroll","axis":0,"value":3.0}
{"type":"surface_size"}
// → {"status":"ok","width":1920,"height":1080}

{"type":"rescan"}    // manual proxy rescan, rarely needed in v0.2.x
{"type":"unload"}    // payload exits cleanly

// Response envelope
{"status":"ok"}
{"status":"error","code":"proxy_not_found","kind":"pointer","message":"..."}
```

### 7.3 Performance

**Round-trip latency target** (host send → dispatch on app thread → ack): **< 200μs** for **active apps**. Idle apps may have unbounded dispatch latency until the app's epoll loop wakes — in pathological cases (idle apps with multi-second epoll timeouts) a single command can sit pending for the duration of that timeout.

For automation use cases that need bounded latency on idle apps, the host can send a `wl_display.sync` request to the compositor before the next dispatch to wake the app's event loop. This generates compositor-side traffic and slightly defeats the bypass-the-compositor design, but is the only general fix when the target is genuinely idle. Documented as a workaround pattern, not the default.

**Throughput target**: **> 5,000 commands/sec** sustained for keystroke streams against an active app. Benchmarks in `bench/` enforce this on CI against weston + a sample GTK app driven into a busy state.

---

## 8. Security Considerations

backseat requires ptrace capability over the target process. On a standard Linux desktop this means one of:

- Same UID as the target, or
- `CAP_SYS_PTRACE`, or
- Yama `ptrace_scope = 0` (permissive mode)

The crate is intended for automation, testing, and accessibility tooling — not for use against processes the operator does not own. The payload is visible in `/proc/PID/maps` and no attempt is made to conceal the injection.

backseat is, by design, a generic process-takeover primitive with a Wayland-flavored API. A malicious user with ptrace capability could rewrite the payload to do anything; the Wayland-input layer is just the surface API. This is not a backseat-specific risk — it is inherent to ptrace.

---

## 9. Implementation Plan

| Phase | Deliverable | Notes |
|---|---|---|
| 1 | `payload/lib.rs` — PLT-shadow hooks (registry/seat/xdg listeners + dispatch), IPC listener, JSON parser | cdylib, minimal deps |
| 2 | `build.rs` — read compiled payload from sibling cdylib crate, SHA-256 stamp | no rustc invocation |
| 3 | `injector.rs` — ptrace injection, libc-resolution-via-procmaps, unload | x86-64 only |
| 4 | `keys.rs` — Key / Button / Axis enums with linux keycode mapping | derive Debug, Clone, Copy, PartialEq, Eq, Hash |
| 4b | Threading sync model: atomics on global proxy state, `Arc<Mutex<UnixStream>>` shared across Mouse/Keyboard | |
| 5 | `error.rs` — structured Error variants (no string-typed) | including `AmbiguousProcessName` |
| 6 | `mouse.rs` + `keyboard.rs` — async wrappers over IPC | tokio::net::UnixStream |
| 7 | `session.rs` — `Session::new`, `from_name` (with ambiguity detection), `unload`, `Drop` | |
| 7b | IPC handshake + protocol versioning | |
| 8 | `lib.rs` — re-exports, crate docs, examples | docs.rs friendly |
| 9 | Integration tests against weston + GTK4, Qt6, SDL2, Electron sample apps | per-toolkit visibility-throttling matrix |
| 10 | Latency + throughput benchmarks under criterion | enforces §7.3 targets |

---

## 10. Open Questions

- **Multi-seat support:** Apps with more than one `wl_seat` are rare but exist. Current design captures the first seat found. Should all seats be captured?
- **zwp_text_input_v3:** For IME-aware text input (non-ASCII, CJK) the text-input protocol is needed alongside `wl_keyboard`. Deferred to a later version.
- **ARM64 support:** Injector shellcode is x86-64 specific. AArch64 calling convention and instruction encoding need a separate code path.
- **XWayland support (v0.3 target):** Inject into the X11 app and synthesize via `XTestFakeKeyEvent`/`XTestFakeButtonEvent`/`XTestFakeMotionEvent`. Different proxy capture (hook `XOpenDisplay`/`xcb_connect`), different IPC dispatch, but the same overall architecture.

  **Auto-detection logic** (refined): inspect `/proc/<PID>/maps`. Decision:
    - `libwayland-client.so` present + a Wayland surface detected via initial sweep → **Wayland path**
    - `libwayland-client.so` absent, `libX11.so` or `libxcb.so` present → **X11 path**
    - **Both** present (common for Electron and toolkits with X11 fallback) → **Wayland path by default**; X11 path requires explicit `Session::new_x11(pid)` opt-in or a feature-flag

  Feature gating: `features = ["xwayland"]` enabled by default in the published crate; downstream can disable for size if needed.
