//! backseat-payload — injected shared library for Wayland input injection.
//!
//! Shadows libwayland-client PLT entries to capture proxies and dispatch
//! synthetic input events on the target application's own event thread.

use std::collections::VecDeque;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::io::{BufRead, Write};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// libwayland internal structures (ABI-stable across libwayland 1.x)
// ---------------------------------------------------------------------------

#[repr(C)]
struct wl_list {
    prev: *mut wl_list,
    next: *mut wl_list,
}

#[repr(C)]
struct wl_array {
    size: usize,
    alloc: usize,
    data: *mut c_void,
}

#[repr(C)]
pub struct wl_interface {
    name: *const c_char,
    version: c_int,
    method_count: c_int,
    methods: *const c_void,
    event_count: c_int,
    events: *const c_void,
}

#[repr(C)]
struct wl_object {
    interface: *const wl_interface,
    implementation: *const c_void,
    id: u32,
    _pad: u32,
}

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

#[repr(C)]
struct wl_event_queue {
    event_list: wl_list,
    display: *mut c_void,
    link: wl_list,
    name: *mut c_char,
}

#[repr(C)]
struct wl_map {
    client_entries: wl_array,
    server_entries: wl_array,
    free_list: u32,
    side: u32,
}

/// Header of `struct wl_display` up to and including `objects`.
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

static G_POINTER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static G_KEYBOARD: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static G_SEAT: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static G_XDG_TOPLEVEL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static G_SURFACE_W: AtomicU32 = AtomicU32::new(0);
static G_SURFACE_H: AtomicU32 = AtomicU32::new(0);
static G_DISPLAY: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static G_DISPATCH_CALLED: AtomicBool = AtomicBool::new(false);
static G_INITIAL_SWEEP_DONE: AtomicBool = AtomicBool::new(false);

static COMMAND_QUEUE: Mutex<VecDeque<IpcCommand>> = Mutex::new(VecDeque::new());
static IPC_THREAD_STARTED: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

unsafe fn get_real(name: &[u8]) -> Option<*mut c_void> {
    let sym = CStr::from_bytes_with_nul(name).unwrap();
    let ptr = libc::dlsym(libc::RTLD_NEXT, sym.as_ptr());
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

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
// Hooks
// ---------------------------------------------------------------------------

unsafe fn run_hooks(display: *mut c_void) {
    G_DISPLAY.store(display, Ordering::Release);
    G_DISPATCH_CALLED.store(true, Ordering::Release);

    if !G_INITIAL_SWEEP_DONE.swap(true, Ordering::SeqCst) {
        initial_sweep(display);
    }

    // Drain queued async commands.
    let cmds = {
        let mut q = COMMAND_QUEUE.lock().unwrap();
        std::mem::take(&mut *q)
    };
    for cmd in cmds {
        dispatch_event(display, cmd);
    }
}

#[no_mangle]
pub unsafe extern "C" fn wl_display_dispatch(display: *mut c_void) -> c_int {
    run_hooks(display);
    let real = get_real(b"wl_display_dispatch\0");
    match real {
        Some(f) => std::mem::transmute::<*mut c_void, extern "C" fn(*mut c_void) -> c_int>(f)(display),
        None => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn wl_display_dispatch_pending(display: *mut c_void) -> c_int {
    run_hooks(display);
    let real = get_real(b"wl_display_dispatch_pending\0");
    match real {
        Some(f) => std::mem::transmute::<*mut c_void, extern "C" fn(*mut c_void) -> c_int>(f)(display),
        None => -1,
    }
}

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

#[no_mangle]
pub unsafe extern "C" fn wl_seat_get_pointer(seat: *mut c_void) -> *mut c_void {
    let real = get_real(b"wl_seat_get_pointer\0");
    let proxy = match real {
        Some(f) => {
            let func = std::mem::transmute::<*mut c_void, extern "C" fn(*mut c_void) -> *mut c_void>(f);
            func(seat)
        }
        None => std::ptr::null_mut(),
    };
    if !proxy.is_null() {
        G_POINTER.store(proxy, Ordering::Release);
    }
    proxy
}

#[no_mangle]
pub unsafe extern "C" fn wl_seat_get_keyboard(seat: *mut c_void) -> *mut c_void {
    let real = get_real(b"wl_seat_get_keyboard\0");
    let proxy = match real {
        Some(f) => {
            let func = std::mem::transmute::<*mut c_void, extern "C" fn(*mut c_void) -> *mut c_void>(f);
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

static ORIG_TOPLEVEL_CONFIGURE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIG_TOPLEVEL_DATA: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

extern "C" fn toplevel_configure_shim(
    data: *mut c_void,
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
    let orig = ORIG_TOPLEVEL_CONFIGURE.load(Ordering::Acquire);
    if !orig.is_null() {
        let func = unsafe {
            std::mem::transmute::<
                *mut c_void,
                extern "C" fn(*mut c_void, *mut c_void, i32, i32, *mut c_void),
            >(orig)
        };
        func(data, toplevel, width, height, states);
    }
}

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

            let p = proxy as *mut wl_proxy;
            let event_count = (*(*p).object.interface).event_count as usize;
            let shim_size = event_count * std::mem::size_of::<*mut c_void>();
            let shim = libc::malloc(shim_size) as *mut *mut c_void;
            if !shim.is_null() {
                std::ptr::copy_nonoverlapping(implementation, shim, event_count);
                let orig_configure = *shim;
                if !orig_configure.is_null() {
                    ORIG_TOPLEVEL_CONFIGURE.store(orig_configure, Ordering::Release);
                    ORIG_TOPLEVEL_DATA.store(data, Ordering::Release);
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
                // Intentionally leak `shim` — must outlive the proxy.
                return result;
            }
        }
    }

    match real {
        Some(f) => {
            let func = std::mem::transmute::<
                *mut c_void,
                extern "C" fn(*mut c_void, *mut *mut c_void, *mut c_void) -> c_int,
            >(f);
            func(proxy, implementation, data)
        }
        None => -1,
    }
}

// ---------------------------------------------------------------------------
// Initial sweep
// ---------------------------------------------------------------------------

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

#[derive(Debug, Clone)]
enum IpcCommand {
    MouseMove { x: f64, y: f64 },
    MouseButton { button: u32, pressed: bool },
    Key { key: u32, pressed: bool },
    Scroll { axis: u32, value: f64 },
}

fn make_ok() -> String {
    r#"{"status":"ok"}"#.to_string() + "\n"
}

fn make_ok_size(w: u32, h: u32) -> String {
    format!(r#"{{"status":"ok","width":{},"height":{}}}"#, w, h) + "\n"
}

fn make_error(code: &str, message: &str) -> String {
    format!(
        r#"{{"status":"error","code":"{}","message":"{}"}}"#,
        code,
        message.replace('"', "\\\"")
    ) + "\n"
}

fn make_hello_ack() -> String {
    r#"{"type":"hello_ack","protocol_version":1,"payload_version":"0.2.2"}"#.to_string() + "\n"
}

fn make_status(dispatch_called: bool) -> String {
    format!(
        r#"{{"status":"ok","dispatch_hook_installed":{}}}"#,
        dispatch_called
    ) + "\n"
}

// ---------------------------------------------------------------------------
// Wayland fixed-point and serial helpers
// ---------------------------------------------------------------------------

fn to_fixed(v: f64) -> i32 {
    (v * 256.0) as i32
}

static SERIAL_COUNTER: AtomicU32 = AtomicU32::new(1);

fn next_serial() -> u32 {
    SERIAL_COUNTER.fetch_add(1, Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Event dispatch on app thread
// ---------------------------------------------------------------------------

unsafe fn dispatch_event(_display: *mut c_void, cmd: IpcCommand) {
    match cmd {
        IpcCommand::MouseMove { x, y } => dispatch_mouse_move(x, y),
        IpcCommand::MouseButton { button, pressed } => dispatch_mouse_button(button, pressed),
        IpcCommand::Key { key, pressed } => dispatch_key(key, pressed),
        IpcCommand::Scroll { axis, value } => dispatch_scroll(axis, value),
    }
}

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

unsafe fn dispatch_mouse_move(x: f64, y: f64) {
    let proxy = G_POINTER.load(Ordering::Acquire);
    let Some(func_ptr) = get_listener_func(proxy, 2) else { return };
    let motion = std::mem::transmute::<
        *mut c_void,
        extern "C" fn(*mut c_void, *mut c_void, u32, i32, i32),
    >(func_ptr);
    let data = (*proxy.cast::<wl_proxy>()).user_data;
    let time = libc::time(std::ptr::null_mut()) as u32;
    motion(data, proxy, time, to_fixed(x), to_fixed(y));
}

unsafe fn dispatch_mouse_button(button: u32, pressed: bool) {
    let proxy = G_POINTER.load(Ordering::Acquire);
    let Some(func_ptr) = get_listener_func(proxy, 3) else { return };
    let func = std::mem::transmute::<
        *mut c_void,
        extern "C" fn(*mut c_void, *mut c_void, u32, u32, u32, u32),
    >(func_ptr);
    let data = (*proxy.cast::<wl_proxy>()).user_data;
    let time = libc::time(std::ptr::null_mut()) as u32;
    let state = if pressed { 1 } else { 0 };
    func(data, proxy, next_serial(), time, button, state);
}

unsafe fn dispatch_key(key: u32, pressed: bool) {
    let proxy = G_KEYBOARD.load(Ordering::Acquire);
    let Some(func_ptr) = get_listener_func(proxy, 3) else { return };
    let func = std::mem::transmute::<
        *mut c_void,
        extern "C" fn(*mut c_void, *mut c_void, u32, u32, u32, u32),
    >(func_ptr);
    let data = (*proxy.cast::<wl_proxy>()).user_data;
    let time = libc::time(std::ptr::null_mut()) as u32;
    let state = if pressed { 1 } else { 0 };
    func(data, proxy, next_serial(), time, key, state);
}

unsafe fn dispatch_scroll(axis: u32, value: f64) {
    let proxy = G_POINTER.load(Ordering::Acquire);
    let Some(func_ptr) = get_listener_func(proxy, 4) else { return };
    let func = std::mem::transmute::<
        *mut c_void,
        extern "C" fn(*mut c_void, *mut c_void, u32, u32, i32),
    >(func_ptr);
    let data = (*proxy.cast::<wl_proxy>()).user_data;
    let time = libc::time(std::ptr::null_mut()) as u32;
    func(data, proxy, time, axis, to_fixed(value));
}

// ---------------------------------------------------------------------------
// IPC command handling
// ---------------------------------------------------------------------------

fn handle_request(line: &str) -> String {
    if line.contains("\"type\":\"hello\"") {
        return make_hello_ack();
    }

    let req: IpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(_) => return make_error("invalid_json", "could not parse request"),
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
                return make_error("proxy_not_found", "xdg_toplevel not captured yet");
            }
            let w = G_SURFACE_W.load(Ordering::Acquire);
            let h = G_SURFACE_H.load(Ordering::Acquire);
            if w == 0 || h == 0 {
                return make_error("proxy_not_found", "surface size not yet configured");
            }
            make_ok_size(w, h)
        }
        "rescan" => {
            let display = G_DISPLAY.load(Ordering::Acquire);
            if display.is_null() {
                return make_error("dispatch_hook_not_installed", "display not yet seen");
            }
            unsafe { initial_sweep(display) };
            make_ok()
        }
        "unload" => make_ok(),
        "status" => make_status(G_DISPATCH_CALLED.load(Ordering::Acquire)),
        _ => make_error("unknown_command", "unrecognized request type"),
    }
}

fn queue_cmd(cmd: IpcCommand) -> String {
    COMMAND_QUEUE.lock().unwrap().push_back(cmd);
    make_ok()
}

// ---------------------------------------------------------------------------
// IPC thread
// ---------------------------------------------------------------------------

fn ipc_thread() {
    let pid = unsafe { libc::getpid() };
    let sock_path = format!("/tmp/backseat-{}.sock", pid);
    let _ = std::fs::remove_file(&sock_path);

    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => l,
        Err(_) => return,
    };

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

#[used]
#[link_section = ".init_array"]
static CONSTRUCTOR: extern "C" fn() = init;

extern "C" fn init() {
    if IPC_THREAD_STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        std::thread::spawn(ipc_thread);
    }
}
