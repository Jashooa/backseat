//! backseat-payload — injected shared library for Wayland input injection.
//!
//! This crate is compiled as a `cdylib` and injected into a target process via
//! `dlopen`. Once loaded, it:
//!
//! 1. Spawns an IPC thread listening on a per-PID Unix socket.
//! 2. Shadows libwayland-client PLT entries (`wl_display_dispatch`,
//!    `wl_registry_bind`, `wl_seat_get_pointer`, etc.) to capture Wayland
//!    proxies as they are created.
//! 3. Walks libwayland's internal proxy table once to capture proxies that
//!    already exist at injection time.
//! 4. Queues synthetic input commands received over the IPC socket and
//!    dispatches them inside the app's natural `wl_display_dispatch` calls,
//!    ensuring the compositor never sees the events.
//!
//! # Safety
//!
//! This crate makes heavy use of `unsafe` because it must:
//!
//! - Interact with raw C pointers and libwayland internal data structures.
//! - Use `dlsym(RTLD_NEXT, ...)` to call the real libwayland functions.
//! - Transmute function pointers to match Wayland listener signatures.
//! - Walk internal libwayland structs whose layout is assumed ABI-stable.

use std::collections::VecDeque;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::io::{BufRead, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// libwayland internal structures (ABI-stable across libwayland 1.x)
// ---------------------------------------------------------------------------

/// Doubly-linked list used throughout libwayland.
#[repr(C)]
struct wl_list {
    prev: *mut wl_list,
    next: *mut wl_list,
}

/// Growable array used by libwayland for proxy tables and other collections.
#[repr(C)]
struct wl_array {
    size: usize,
    alloc: usize,
    data: *mut c_void,
}

/// Describes a Wayland interface (name, version, method/event counts).
///
/// Every proxy has a pointer to its interface, which lets us identify the
/// protocol object type (e.g. `"wl_seat"`, `"wl_pointer"`, etc.).
#[repr(C)]
pub struct wl_interface {
    name: *const c_char,
    version: c_int,
    method_count: c_int,
    methods: *const c_void,
    event_count: c_int,
    events: *const c_void,
}

/// Base object inside every `wl_proxy`. Contains the interface, implementation
/// (listener struct pointer), and object ID.
#[repr(C)]
struct wl_object {
    interface: *const wl_interface,
    implementation: *const c_void,
    id: u32,
    _pad: u32,
}

/// libwayland client proxy. The `implementation` field (via `wl_object`) points
/// to the application's listener function table, which we invoke directly to
/// inject synthetic events.
#[repr(C)]
struct wl_proxy {
    object: wl_object,
    display: *mut c_void,
    queue: *mut c_void,
    flags: u32,
    refcount: c_int,
    user_data: *mut c_void,
    dispatcher: *mut c_void,
    version: u32,
    _pad: u32,
}

/// libwayland event queue. Part of `wl_display` layout calculation.
#[repr(C)]
struct wl_event_queue {
    event_list: wl_list,
    display: *mut c_void,
    link: wl_list,
    name: *mut c_char,
}

/// libwayland ID-to-proxy map. `client_entries` is an array of `wl_proxy *`
/// indexed by Wayland object ID.
#[repr(C)]
struct wl_map {
    client_entries: wl_array,
    server_entries: wl_array,
    free_list: u32,
    side: u32,
}

/// Partial definition of `struct wl_display` up to the `objects` field.
///
/// We only need the offset of `objects` (168 bytes on x86-64) so we can walk
/// the proxy table and capture existing proxies at injection time.
#[repr(C)]
struct wl_display_header {
    proxy: wl_proxy,
    display_queue: wl_event_queue,
    default_queue: wl_event_queue,
    objects: wl_map,
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

/// Captured `wl_pointer` proxy (or `NULL` if not yet seen).
static G_POINTER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Captured `wl_keyboard` proxy (or `NULL` if not yet seen).
static G_KEYBOARD: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Captured `wl_seat` proxy (or `NULL` if not yet seen).
static G_SEAT: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Captured `xdg_toplevel` proxy for surface size tracking.
static G_XDG_TOPLEVEL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Most recent configured surface width (pixels).
static G_SURFACE_W: AtomicU32 = AtomicU32::new(0);

/// Most recent configured surface height (pixels).
static G_SURFACE_H: AtomicU32 = AtomicU32::new(0);

/// First `wl_display *` seen by the dispatch hook.
static G_DISPLAY: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Set to `true` the first time `wl_display_dispatch` (or `_pending`) is
/// called, so the host can detect whether the dispatch hook is active.
static G_DISPATCH_CALLED: AtomicBool = AtomicBool::new(false);

/// Set to `true` after the one-time initial proxy sweep.
static G_INITIAL_SWEEP_DONE: AtomicBool = AtomicBool::new(false);

/// Commands received from the host that have not yet been dispatched on the
/// app's event thread.
static COMMAND_QUEUE: Mutex<VecDeque<IpcCommand>> = Mutex::new(VecDeque::new());

/// Prevents the IPC thread from being spawned more than once (e.g. if the
/// payload is accidentally loaded twice).
static IPC_THREAD_STARTED: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Look up the *real* libwayland symbol via `dlsym(RTLD_NEXT, …)`.
///
/// # Safety
/// `name` must be a null-terminated byte slice.
unsafe fn get_real(name: &[u8]) -> Option<*mut c_void> {
    let sym = CStr::from_bytes_with_nul(name).unwrap();
    let ptr = libc::dlsym(libc::RTLD_NEXT, sym.as_ptr());
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

/// Return the interface name of a `wl_proxy` (e.g. `b"wl_seat"`).
///
/// # Safety
/// `proxy` must be a valid `wl_proxy *`.
unsafe fn proxy_interface_name(proxy: *mut c_void) -> Option<&'static [u8]> {
    let p = proxy as *mut wl_proxy;
    let iface = (*p).object.interface;
    if iface.is_null() {
        return None;
    }
    let name = (*iface).name;
    if name.is_null() {
        return None;
    }
    Some(CStr::from_ptr(name).to_bytes())
}

// ---------------------------------------------------------------------------
// PLT-shadow hooks
// ---------------------------------------------------------------------------

/// Common work executed inside every dispatch hook.
///
/// 1. Records the display pointer.
/// 2. Marks that the hook has been called.
/// 3. Performs a one-time initial sweep of existing proxies.
/// 4. Drains any queued synthetic input commands and dispatches them.
///
/// # Safety
/// `display` must be a valid `wl_display *`.
unsafe fn run_hooks(display: *mut c_void) {
    G_DISPLAY.store(display, Ordering::Release);
    G_DISPATCH_CALLED.store(true, Ordering::Release);

    if !G_INITIAL_SWEEP_DONE.swap(true, Ordering::SeqCst) {
        initial_sweep(display);
    }

    // Drain queued async commands.
    let cmds = {
        let mut q = COMMAND_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *q)
    };
    for cmd in cmds {
        dispatch_event(display, cmd);
    }
}

/// Shadow for `wl_display_dispatch`. Runs hooks, then forwards to the real
/// libwayland function.
///
/// # Safety
/// `display` must be a valid `wl_display *`.
#[no_mangle]
pub unsafe extern "C" fn wl_display_dispatch(display: *mut c_void) -> c_int {
    run_hooks(display);
    let real = get_real(b"wl_display_dispatch\0");
    match real {
        Some(f) => {
            std::mem::transmute::<*mut c_void, extern "C" fn(*mut c_void) -> c_int>(f)(display)
        }
        None => -1,
    }
}

/// Shadow for `wl_display_dispatch_pending`. Identical behaviour to
/// `wl_display_dispatch`.
///
/// # Safety
/// `display` must be a valid `wl_display *`.
#[no_mangle]
pub unsafe extern "C" fn wl_display_dispatch_pending(display: *mut c_void) -> c_int {
    run_hooks(display);
    let real = get_real(b"wl_display_dispatch_pending\0");
    match real {
        Some(f) => {
            std::mem::transmute::<*mut c_void, extern "C" fn(*mut c_void) -> c_int>(f)(display)
        }
        None => -1,
    }
}

/// Shadow for `wl_registry_bind`. Intercepts `wl_seat` bindings so we can
/// capture the seat proxy immediately.
///
/// # Safety
/// `registry` and `interface` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn wl_registry_bind(
    registry: *mut c_void,
    name: u32,
    interface: *const wl_interface,
    version: u32,
) -> *mut c_void {
    let real = get_real(b"wl_registry_bind\0");
    let proxy = match real {
        Some(f) => {
            let func = std::mem::transmute::<
                *mut c_void,
                extern "C" fn(*mut c_void, u32, *const wl_interface, u32) -> *mut c_void,
            >(f);
            func(registry, name, interface, version)
        }
        None => std::ptr::null_mut(),
    };

    if !proxy.is_null() && !interface.is_null() {
        let iface_name = CStr::from_ptr((*interface).name).to_bytes();
        if iface_name == b"wl_seat" {
            G_SEAT.store(proxy, Ordering::Release);
        }
    }
    proxy
}

/// Shadow for `wl_seat_get_pointer`. Captures the newly-created pointer proxy.
///
/// # Safety
/// `seat` must be a valid `wl_seat *`.
#[no_mangle]
pub unsafe extern "C" fn wl_seat_get_pointer(seat: *mut c_void) -> *mut c_void {
    let real = get_real(b"wl_seat_get_pointer\0");
    let proxy = match real {
        Some(f) => {
            let func =
                std::mem::transmute::<*mut c_void, extern "C" fn(*mut c_void) -> *mut c_void>(f);
            func(seat)
        }
        None => std::ptr::null_mut(),
    };
    if !proxy.is_null() {
        G_POINTER.store(proxy, Ordering::Release);
    }
    proxy
}

/// Shadow for `wl_seat_get_keyboard`. Captures the newly-created keyboard proxy.
///
/// # Safety
/// `seat` must be a valid `wl_seat *`.
#[no_mangle]
pub unsafe extern "C" fn wl_seat_get_keyboard(seat: *mut c_void) -> *mut c_void {
    let real = get_real(b"wl_seat_get_keyboard\0");
    let proxy = match real {
        Some(f) => {
            let func =
                std::mem::transmute::<*mut c_void, extern "C" fn(*mut c_void) -> *mut c_void>(f);
            func(seat)
        }
        None => std::ptr::null_mut(),
    };
    if !proxy.is_null() {
        G_KEYBOARD.store(proxy, Ordering::Release);
    }
    proxy
}

// ---------------------------------------------------------------------------
// xdg_toplevel configure shim
// ---------------------------------------------------------------------------

/// Per-toplevel saved listener state: `(original_configure_fn, user_data)`.
/// Stored as `usize` because raw pointers are not `Send`.
static TOPLEVEL_LISTENERS: Mutex<Vec<(usize, usize, usize)>> = Mutex::new(Vec::new());

/// Shim that wraps the app's `xdg_toplevel_listener.configure`.
///
/// Updates `G_SURFACE_W` / `G_SURFACE_H` atomically, then forwards to the
/// original listener so the application continues to work normally.
extern "C" fn toplevel_configure_shim(
    _data: *mut c_void,
    toplevel: *mut c_void,
    width: i32,
    height: i32,
    states: *mut c_void,
) {
    if width > 0 {
        G_SURFACE_W.store(width as u32, Ordering::Release);
    }
    if height > 0 {
        G_SURFACE_H.store(height as u32, Ordering::Release);
    }
    let key = toplevel as usize;
    // Clone the entry while holding the lock, then drop the guard before
    // calling the app's callback to avoid deadlock if the callback re-enters
    // any code that also takes the TOPLEVEL_LISTENERS lock.
    let entry = TOPLEVEL_LISTENERS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .find(|(k, _, _)| *k == key)
        .copied();
    if let Some((_, orig, orig_data)) = entry {
        if orig != 0 {
            // SAFETY: `orig` was saved from a valid listener function pointer.
            let func = unsafe {
                std::mem::transmute::<
                    usize,
                    extern "C" fn(*mut c_void, *mut c_void, i32, i32, *mut c_void),
                >(orig)
            };
            func(orig_data as *mut c_void, toplevel, width, height, states);
        }
    }
}

/// Shadow for `wl_proxy_add_listener`.
///
/// We intercept this rather than the generated `xdg_toplevel_add_listener`
/// wrapper because `wl_proxy_add_listener` is the actual libwayland-client
/// symbol and is therefore always dynamically linked.  When the interface
/// name is `"xdg_toplevel"` we allocate a shim listener that records surface
/// size and forwards to the original.
///
/// # Safety
/// `proxy` and `implementation` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn wl_proxy_add_listener(
    proxy: *mut c_void,
    implementation: *mut *mut c_void,
    data: *mut c_void,
) -> c_int {
    let real = get_real(b"wl_proxy_add_listener\0");

    let iface_name = proxy_interface_name(proxy);
    if let Some(name) = iface_name {
        if name == b"xdg_toplevel" && !implementation.is_null() {
            G_XDG_TOPLEVEL.store(proxy, Ordering::Release);

            // The listener struct is an array of function pointers whose
            // length equals the interface's event count.
            let p = proxy as *mut wl_proxy;
            let event_count = (*(*p).object.interface).event_count as usize;
            let shim_size = event_count * std::mem::size_of::<*mut c_void>();
            let shim = libc::malloc(shim_size) as *mut *mut c_void;
            if !shim.is_null() {
                std::ptr::copy_nonoverlapping(implementation, shim, event_count);
                let orig_configure = *shim;
                if !orig_configure.is_null() {
                    TOPLEVEL_LISTENERS
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push((proxy as usize, orig_configure as usize, data as usize));
                    *shim = toplevel_configure_shim as *mut c_void;
                }
                let result = match real {
                    Some(f) => {
                        let func = std::mem::transmute::<
                            *mut c_void,
                            extern "C" fn(*mut c_void, *mut *mut c_void, *mut c_void) -> c_int,
                        >(f);
                        func(proxy, shim, data)
                    }
                    None => -1,
                };
                // Intentionally leak `shim` — it must outlive the proxy.
                return result;
            }
        }
    }

    if let Some(f) = real {
        let func = std::mem::transmute::<
            *mut c_void,
            extern "C" fn(*mut c_void, *mut *mut c_void, *mut c_void) -> c_int,
        >(f);
        func(proxy, implementation, data)
    } else {
        -1
    }
}

/// Shadow for `wl_proxy_destroy`.
///
/// Removes the proxy from `TOPLEVEL_LISTENERS` so that destroyed toplevels
/// do not leak entries or cause stale-pointer routing when the heap address
/// is reused for a new toplevel.
///
/// # Safety
/// `proxy` must be a valid `wl_proxy *`.
#[no_mangle]
pub unsafe extern "C" fn wl_proxy_destroy(proxy: *mut c_void) {
    let real = get_real(b"wl_proxy_destroy\0");
    // Prune our listener table before the proxy is freed.
    TOPLEVEL_LISTENERS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(k, _, _)| *k != proxy as usize);
    if let Some(f) = real {
        let func = std::mem::transmute::<*mut c_void, extern "C" fn(*mut c_void)>(f);
        func(proxy)
    }
}

const WL_MARSHAL_FLAG_DESTROY: u32 = 1 << 0;

/// Shadow for `wl_proxy_marshal_flags`.
///
/// Modern apps destroy xdg_toplevel via `wl_proxy_marshal_flags(..., WL_MARSHAL_FLAG_DESTROY)`,
/// which routes through an internal `wl_proxy_destroy_caller_locks` path that
/// bypasses the public `wl_proxy_destroy` PLT entry.  We shadow this too so
/// that destroyed toplevels are pruned from `TOPLEVEL_LISTENERS`.
///
/// On x86-64 the System-V ABI places all fixed arguments in registers; any
/// variadic arguments remain in registers / on the stack and are forwarded
/// to the real function unchanged.
///
/// # Safety
/// `proxy` must be a valid `wl_proxy *`.
#[no_mangle]
pub unsafe extern "C" fn wl_proxy_marshal_flags(
    proxy: *mut c_void,
    opcode: u32,
    interface: *const c_void,
    version: u32,
    flags: u32,
) -> *mut c_void {
    if flags & WL_MARSHAL_FLAG_DESTROY != 0 {
        TOPLEVEL_LISTENERS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(k, _, _)| *k != proxy as usize);
    }
    let real = get_real(b"wl_proxy_marshal_flags\0");
    if let Some(f) = real {
        let func = std::mem::transmute::<
            *mut c_void,
            unsafe extern "C" fn(*mut c_void, u32, *const c_void, u32, u32) -> *mut c_void,
        >(f);
        func(proxy, opcode, interface, version, flags)
    } else {
        std::ptr::null_mut()
    }
}

// ---------------------------------------------------------------------------
// Initial sweep
// ---------------------------------------------------------------------------

/// Walk libwayland's internal `wl_display.objects` proxy table and capture
/// any `wl_seat`, `wl_pointer`, `wl_keyboard`, or `xdg_toplevel` proxies
/// that already exist at injection time.
///
/// # Safety
/// `display` must be a valid `wl_display *`.
unsafe fn initial_sweep(display: *mut c_void) {
    let d = display as *mut wl_display_header;
    let map = &(*d).objects;
    let entries = map.client_entries.data as *const *mut c_void;
    if entries.is_null() {
        return;
    }
    let count = map.client_entries.size / std::mem::size_of::<*mut c_void>();
    if count == 0 {
        return;
    }
    let slice = std::slice::from_raw_parts(entries, count);
    for &proxy_ptr in slice {
        if proxy_ptr.is_null() {
            continue;
        }
        if let Some(name) = proxy_interface_name(proxy_ptr) {
            match name {
                b"wl_seat" => {
                    G_SEAT.store(proxy_ptr, Ordering::Release);
                }
                b"wl_pointer" => {
                    G_POINTER.store(proxy_ptr, Ordering::Release);
                }
                b"wl_keyboard" => {
                    G_KEYBOARD.store(proxy_ptr, Ordering::Release);
                }
                b"xdg_toplevel" => {
                    G_XDG_TOPLEVEL.store(proxy_ptr, Ordering::Release);
                }
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IPC types
// ---------------------------------------------------------------------------

/// Request deserialized from the Unix socket (one line of JSON per request).
#[derive(Debug, serde::Deserialize)]
struct IpcRequest {
    #[serde(rename = "type")]
    ty: String,
    #[serde(default)]
    x: Option<f64>,
    #[serde(default)]
    y: Option<f64>,
    #[serde(default)]
    button: Option<u32>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    key: Option<u32>,
    #[serde(default)]
    axis: Option<u32>,
    #[serde(default)]
    value: Option<f64>,
}

/// Parsed command ready to be queued for dispatch on the app's event thread.
#[derive(Debug, Clone)]
enum IpcCommand {
    MouseMove { x: f64, y: f64 },
    MouseButton { button: u32, pressed: bool },
    Key { key: u32, pressed: bool },
    Scroll { axis: u32, value: f64 },
}

/// Build a generic `{"status":"ok"}` response.
fn make_ok() -> String {
    r#"{"status":"ok"}"#.to_string() + "\n"
}

/// Build a `{"status":"ok","width":w,"height":h}` response.
fn make_ok_size(w: u32, h: u32) -> String {
    format!(r#"{{"status":"ok","width":{},"height":{}}}"#, w, h) + "\n"
}

/// Build a `{"status":"error","code":...,"message":...}` response.
///
/// # Safety
/// `kind` is only ever passed `&'static str` literals (e.g. `"pointer"`,
/// `"keyboard"`) so no JSON escaping is required.  If dynamic strings are
/// ever passed, switch to `serde_json::json!`.
fn make_error(code: &str, message: &str, kind: Option<&str>) -> String {
    let kind_json = kind.map_or(String::new(), |k| format!(",\"kind\":\"{}\"", k));
    format!(
        "{{\"status\":\"error\",\"code\":\"{}\",\"message\":\"{}\"{}}}",
        code,
        message.replace('"', "\\\""),
        kind_json
    ) + "\n"
}

/// Build the handshake acknowledgement line.
fn make_hello_ack() -> String {
    r#"{"type":"hello_ack","protocol_version":1,"payload_version":"0.2.2"}"#.to_string() + "\n"
}

/// Build the status response used to report whether PLT interposition is
/// active.
///
/// Reports `G_DISPATCH_CALLED` — the only definitive signal that the
/// dispatch hook has actually fired (as opposed to `G_INTERPOSITION_OK`,
/// which may be true for BIND_NOW targets even when the hook never runs).
fn make_status() -> String {
    format!(
        r#"{{"status":"ok","dispatch_hook_installed":{}}}"#,
        G_DISPATCH_CALLED.load(Ordering::Acquire)
    ) + "\n"
}

// ---------------------------------------------------------------------------
// Wayland fixed-point and serial helpers
// ---------------------------------------------------------------------------

/// Convert a floating-point value to Wayland's signed 24.8 fixed-point
/// (`wl_fixed_t`).
fn to_fixed(v: f64) -> i32 {
    (v * 256.0).round() as i32
}

/// Monotonically-increasing serial counter used for synthetic button/key
/// events when `wl_display_get_serial` is not available.
static SERIAL_COUNTER: AtomicU32 = AtomicU32::new(1);

fn next_serial() -> u32 {
    SERIAL_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Return a `CLOCK_MONOTONIC` timestamp in milliseconds, suitable for
/// Wayland event timestamps.
fn monotonic_ms() -> u32 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out-param.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add(ts.tv_nsec as u64 / 1_000_000) as u32
}

// ---------------------------------------------------------------------------
// Event dispatch on app thread
// ---------------------------------------------------------------------------

/// Dispatch a single queued command by calling the application's listener
/// callback directly.
///
/// # Safety
/// Must run on the application's Wayland event thread (i.e. inside
/// `wl_display_dispatch`).
unsafe fn dispatch_event(_display: *mut c_void, cmd: IpcCommand) {
    match cmd {
        IpcCommand::MouseMove { x, y } => dispatch_mouse_move(x, y),
        IpcCommand::MouseButton { button, pressed } => dispatch_mouse_button(button, pressed),
        IpcCommand::Key { key, pressed } => dispatch_key(key, pressed),
        IpcCommand::Scroll { axis, value } => dispatch_scroll(axis, value),
    }
}

/// Retrieve a function pointer from a `wl_proxy`'s listener struct at the
/// given `offset` (in pointer-sized units).
///
/// # Safety
/// `proxy` must be a valid `wl_proxy *` with a non-null listener.
unsafe fn get_listener_func(proxy: *mut c_void, offset: usize) -> Option<*mut c_void> {
    if proxy.is_null() {
        return None;
    }
    let listener = (*proxy.cast::<wl_proxy>()).object.implementation;
    if listener.is_null() {
        return None;
    }
    let ptr = *((listener as *mut *mut c_void).add(offset));
    if ptr.is_null() {
        return None;
    }
    Some(ptr)
}

/// Dispatch a synthetic `wl_pointer_listener.motion` event.
///
/// # Safety
/// Must run on the app's Wayland event thread.
unsafe fn dispatch_mouse_move(x: f64, y: f64) {
    let proxy = G_POINTER.load(Ordering::Acquire);
    let Some(func_ptr) = get_listener_func(proxy, 2) else {
        return;
    };
    let motion = std::mem::transmute::<
        *mut c_void,
        extern "C" fn(*mut c_void, *mut c_void, u32, i32, i32),
    >(func_ptr);
    let data = (*proxy.cast::<wl_proxy>()).user_data;
    let time = monotonic_ms();
    motion(data, proxy, time, to_fixed(x), to_fixed(y));
}

/// Dispatch a synthetic `wl_pointer_listener.button` event.
///
/// # Safety
/// Must run on the app's Wayland event thread.
unsafe fn dispatch_mouse_button(button: u32, pressed: bool) {
    let proxy = G_POINTER.load(Ordering::Acquire);
    let Some(func_ptr) = get_listener_func(proxy, 3) else {
        return;
    };
    let func = std::mem::transmute::<
        *mut c_void,
        extern "C" fn(*mut c_void, *mut c_void, u32, u32, u32, u32),
    >(func_ptr);
    let data = (*proxy.cast::<wl_proxy>()).user_data;
    let time = monotonic_ms();
    let state = if pressed { 1 } else { 0 };
    func(data, proxy, next_serial(), time, button, state);
}

/// Dispatch a synthetic `wl_keyboard_listener.key` event.
///
/// # Safety
/// Must run on the app's Wayland event thread.
unsafe fn dispatch_key(key: u32, pressed: bool) {
    let proxy = G_KEYBOARD.load(Ordering::Acquire);
    let Some(func_ptr) = get_listener_func(proxy, 3) else {
        return;
    };
    let func = std::mem::transmute::<
        *mut c_void,
        extern "C" fn(*mut c_void, *mut c_void, u32, u32, u32, u32),
    >(func_ptr);
    let data = (*proxy.cast::<wl_proxy>()).user_data;
    let time = monotonic_ms();
    let state = if pressed { 1 } else { 0 };
    func(data, proxy, next_serial(), time, key, state);
}

/// Dispatch a synthetic `wl_pointer_listener.axis` event.
///
/// # Safety
/// Must run on the app's Wayland event thread.
unsafe fn dispatch_scroll(axis: u32, value: f64) {
    let proxy = G_POINTER.load(Ordering::Acquire);
    let Some(func_ptr) = get_listener_func(proxy, 4) else {
        return;
    };
    let func = std::mem::transmute::<
        *mut c_void,
        extern "C" fn(*mut c_void, *mut c_void, u32, u32, i32),
    >(func_ptr);
    let data = (*proxy.cast::<wl_proxy>()).user_data;
    let time = monotonic_ms();
    func(data, proxy, time, axis, to_fixed(value));
}

// ---------------------------------------------------------------------------
// IPC command handling
// ---------------------------------------------------------------------------

/// Parse one JSON request line and produce a JSON response line.
fn handle_request(line: &str) -> String {
    if line.contains("\"type\":\"hello\"") {
        return make_hello_ack();
    }

    let req: IpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(_) => return make_error("invalid_json", "could not parse request", None),
    };

    match req.ty.as_str() {
        "mouse_move" => {
            let x = req.x.unwrap_or(0.0);
            let y = req.y.unwrap_or(0.0);
            queue_cmd(IpcCommand::MouseMove { x, y })
        }
        "mouse_button" => {
            let button = req.button.unwrap_or(0);
            let pressed = req.state.as_deref() == Some("pressed");
            queue_cmd(IpcCommand::MouseButton { button, pressed })
        }
        "key" => {
            let key = req.key.unwrap_or(0);
            let pressed = req.state.as_deref() == Some("pressed");
            queue_cmd(IpcCommand::Key { key, pressed })
        }
        "scroll" => {
            let axis = req.axis.unwrap_or(0);
            let value = req.value.unwrap_or(0.0);
            queue_cmd(IpcCommand::Scroll { axis, value })
        }
        "surface_size" => {
            if G_XDG_TOPLEVEL.load(Ordering::Acquire).is_null() {
                return make_error(
                    "proxy_not_found",
                    "xdg_toplevel not captured yet",
                    Some("xdg_toplevel"),
                );
            }
            let w = G_SURFACE_W.load(Ordering::Acquire);
            let h = G_SURFACE_H.load(Ordering::Acquire);
            if w == 0 || h == 0 {
                return make_error(
                    "proxy_not_found",
                    "surface size not yet configured",
                    Some("xdg_toplevel"),
                );
            }
            make_ok_size(w, h)
        }
        "rescan" => {
            let display = G_DISPLAY.load(Ordering::Acquire);
            if display.is_null() {
                return make_error("dispatch_hook_not_installed", "display not yet seen", None);
            }
            // SAFETY: `display` was stored by the dispatch hook and is valid.
            unsafe { initial_sweep(display) };
            make_ok()
        }
        "unload" => make_ok(),
        "status" => make_status(),
        _ => make_error("unknown_command", "unrecognized request type", None),
    }
}

/// Push a command into the queue that will be drained by the next
/// `wl_display_dispatch` call.
fn queue_cmd(cmd: IpcCommand) -> String {
    COMMAND_QUEUE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push_back(cmd);
    make_ok()
}

// ---------------------------------------------------------------------------
// IPC thread
// ---------------------------------------------------------------------------

/// Return a suitable runtime directory for temporary files.
///
/// Prefers `$XDG_RUNTIME_DIR` (user-owned, typically `/run/user/<uid>`),
/// falling back to `/tmp`.  Must match the host's `session::runtime_dir()`.
fn runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// Accept a single IPC connection and process newline-delimited JSON requests
/// until the host sends `unload` or the connection closes.
fn ipc_thread() {
    let pid = unsafe { libc::getpid() };
    let sock_path = runtime_dir().join(format!("backseat-{}.sock", pid));
    let sock_path_cstring = std::ffi::CString::new(sock_path.to_string_lossy().as_bytes()).unwrap();
    let _ = std::fs::remove_file(&sock_path);

    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => l,
        Err(_) => return,
    };

    // Restrict socket permissions so only the owner can connect.
    unsafe {
        libc::chmod(sock_path_cstring.as_ptr(), 0o700);
    }

    let (stream, _) = match listener.accept() {
        Ok(v) => v,
        Err(_) => return,
    };

    let mut write_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();

    while let Ok(n) = reader.read_line(&mut line) {
        if n == 0 {
            break;
        }
        let line_trimmed = line.trim();
        if line_trimmed.is_empty() {
            line.clear();
            continue;
        }

        let response = handle_request(line_trimmed);
        let _ = write_stream.write_all(response.as_bytes());

        if line_trimmed.contains("\"type\":\"unload\"") {
            let _ = std::fs::remove_file(&sock_path);
            break;
        }
        line.clear();
    }
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

/// `.init_array` entry point — runs automatically when the `.so` is loaded.
/// Spawns the IPC listener thread (once only).
#[used]
#[link_section = ".init_array"]
static CONSTRUCTOR: extern "C" fn() = init;

/// Set to `true` if the init() self-check confirms that our PLT shadow
/// symbols are visible to the dynamic linker.
static G_INTERPOSITION_OK: AtomicBool = AtomicBool::new(false);

extern "C" fn init() {
    if IPC_THREAD_STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        // Self-check: ask the dynamic linker to resolve "wl_display_dispatch".
        // If it returns OUR function, PLT interposition is working for future
        // dispatches.  (For BIND_NOW targets the PLT was already resolved and
        // this check may still return our address — the only definitive test
        // is whether run_hooks fires, tracked by G_DISPATCH_CALLED.)
        let sym = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                b"wl_display_dispatch\0".as_ptr() as *const i8,
            )
        };
        let ours = wl_display_dispatch as *const () as usize as *mut c_void;
        G_INTERPOSITION_OK.store(sym == ours, Ordering::Release);
        std::thread::spawn(ipc_thread);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_fixed_rounds_half_up() {
        // 1.5 * 256 = 384.0 -> exactly 384
        assert_eq!(to_fixed(1.5), 384);
        // 1.501 * 256 = 384.256 -> rounds to 384
        assert_eq!(to_fixed(1.501), 384);
        // 1.505 * 256 = 385.28 -> rounds to 385
        assert_eq!(to_fixed(1.505), 385);
    }

    #[test]
    fn monotonic_ms_is_monotonic() {
        let a = monotonic_ms();
        let b = monotonic_ms();
        assert!(b >= a, "monotonic_ms went backwards: {a} -> {b}");
    }

    #[test]
    fn next_serial_increments() {
        let s1 = next_serial();
        let s2 = next_serial();
        assert!(s2 > s1, "serial did not increment: {s1} -> {s2}");
    }
}
