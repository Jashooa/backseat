//! backseat-payload — injected shared library for Wayland input injection.
//!
//! This crate is compiled as a `cdylib` and injected into a target process via
//! `dlopen`. Once loaded, it:
//!
//! 1. Patches the GOT entries of the target executable (and all loaded
//!    libraries) for `wl_display_dispatch*` functions to point to our hooks.
//! 2. Scans libwayland's internal proxy table to capture existing proxies.
//! 3. Spawns an IPC thread listening on a per-PID Unix socket.
//! 4. Queues synthetic input commands received over the IPC socket and
//!    dispatches them inside the app's natural dispatch calls.

use std::collections::VecDeque;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::io::{BufRead, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};
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
    tag: *const *const c_char,
    queue_link: wl_list,
}

#[repr(C)]
struct wl_event_queue {
    event_list: wl_list,
    proxy_list: wl_list,
    display: *mut c_void,
    name: *mut c_char,
}

#[repr(C)]
struct wl_map {
    client_entries: wl_array,
    server_entries: wl_array,
    side: u32,
    free_list: u32,
}

#[repr(C)]
struct wl_display_header {
    proxy: wl_proxy,
    connection: *mut c_void,
    last_error: c_int,
    _pad1: u32,
    _protocol_error_code: u32,
    _pad2: u32,
    _protocol_error_interface: *const c_void,
    _protocol_error_id: u32,
    _pad3: u32,
    fd: c_int,
    _pad4: u32,
    objects: wl_map,
    display_queue: wl_event_queue,
    // default_queue follows but we don't need it
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

// Stored real function pointers (saved before GOT patching).
static REAL_DISPATCH: AtomicUsize = AtomicUsize::new(0);
static REAL_DISPATCH_PENDING: AtomicUsize = AtomicUsize::new(0);
static REAL_DISPATCH_QUEUE: AtomicUsize = AtomicUsize::new(0);
static REAL_DISPATCH_QUEUE_PENDING: AtomicUsize = AtomicUsize::new(0);
static REAL_ADD_DISPATCHER: AtomicUsize = AtomicUsize::new(0);

/// Per-toplevel saved listener state: `(toplevel_addr, orig_func, orig_data)`.
static TOPLEVEL_LISTENERS: Mutex<Vec<(usize, usize, usize)>> = Mutex::new(Vec::new());

unsafe impl Send for wl_proxy {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn store_real(symbol: &str, ptr: *mut c_void) {
    let target = match symbol {
        "wl_display_dispatch" => &REAL_DISPATCH,
        "wl_display_dispatch_pending" => &REAL_DISPATCH_PENDING,
        "wl_display_dispatch_queue" => &REAL_DISPATCH_QUEUE,
        "wl_display_dispatch_queue_pending" => &REAL_DISPATCH_QUEUE_PENDING,
        "wl_proxy_add_dispatcher" => &REAL_ADD_DISPATCHER,
        _ => return,
    };
    target.store(ptr as usize, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Proxy capture
// ---------------------------------------------------------------------------

unsafe fn capture_proxy(proxy: *mut c_void) {
    if let Some(name) = proxy_interface_name(proxy) {
        match name {
            b"wl_seat" => G_SEAT.store(proxy, Ordering::Release),
            b"wl_pointer" => G_POINTER.store(proxy, Ordering::Release),
            b"wl_keyboard" => G_KEYBOARD.store(proxy, Ordering::Release),
            b"xdg_toplevel" => {
                G_XDG_TOPLEVEL.store(proxy, Ordering::Release);
                install_toplevel_shim(proxy);
            }
            _ => {}
        }
    }
}

unsafe fn install_toplevel_shim(toplevel: *mut c_void) {
    let proxy = toplevel as *mut wl_proxy;

    // Dispatcher proxies store a sentinel (&RUST_MANAGED) in
    // object.implementation, not a listener table.  Writing to that
    // address would corrupt the wayland-backend static.
    if !(*proxy).dispatcher.is_null() {
        return;
    }

    let impl_ptr = (*proxy).object.implementation as *mut usize;
    if impl_ptr.is_null() {
        return;
    }
    let func = *impl_ptr;
    if func == 0 {
        return;
    }
    let data = *impl_ptr.add(1);

    let mut listeners = TOPLEVEL_LISTENERS.lock().unwrap_or_else(|e| e.into_inner());
    let key = toplevel as usize;
    if listeners.iter().any(|(k, _, _)| *k == key) {
        return;
    }
    listeners.push((key, func, data));

    *impl_ptr = toplevel_configure_shim as *const () as usize;
    *impl_ptr.add(1) = data;
}

extern "C" fn toplevel_configure_shim(
    _data: *mut c_void,
    toplevel: *mut c_void,
    width: i32,
    height: i32,
    states: *mut c_void,
) {
    G_SURFACE_W.store(width as u32, Ordering::Release);
    G_SURFACE_H.store(height as u32, Ordering::Release);

    let key = toplevel as usize;
    let listeners = TOPLEVEL_LISTENERS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, orig_func, orig_data)) = listeners.iter().find(|(k, _, _)| *k == key) {
        let func: extern "C" fn(*mut c_void, *mut c_void, i32, i32, *mut c_void) =
            unsafe { std::mem::transmute(*orig_func) };
        func(*orig_data as *mut c_void, toplevel, width, height, states);
    }
}

unsafe fn initial_sweep(display: *mut c_void) {
    let d = display as *mut wl_display_header;
    let map = &(*d).objects;
    let entries = map.client_entries.data as *const usize;
    let count = map.client_entries.size / std::mem::size_of::<usize>();

    if !entries.is_null() && count > 0 {
        let slice = std::slice::from_raw_parts(entries, count);
        for &entry_val in slice.iter() {
            // Skip free-list entries and NULL.
            // On x86_64 valid heap pointers always exceed u32::MAX,
            // whereas free-list entries are small u32 indices.
            if entry_val > u32::MAX as usize {
                capture_proxy(entry_val as *mut c_void);
            }
        }
    }

    // Walk the proxy_list of every captured proxy's event queue to
    // pick up proxies that were removed from the wl_map (seat,
    // pointer, keyboard are frequent casualties of the wrapper
    // pattern in wayland-backend's send_request).
    sweep_event_queues();
}

/// Walk the proxy_list of the event queue that each already-captured
/// proxy belongs to.  Deduplication is handled by `capture_proxy`
/// itself (the globals will only store the first pointer per type).
unsafe fn sweep_event_queues() {
    // Collect the event queue pointer from the first non-display proxy
    // we captured — all application proxies share the same queue.
    let queue = {
        let mut found: *mut c_void = std::ptr::null_mut();
        for atomic in [&G_SEAT, &G_POINTER, &G_KEYBOARD, &G_XDG_TOPLEVEL] {
            let p = atomic.load(Ordering::Acquire);
            if !p.is_null() {
                let proxy = p as *mut wl_proxy;
                let q = (*proxy).queue;
                if !q.is_null() {
                    found = q;
                    break;
                }
            }
        }
        found
    };

    let q = queue as *mut wl_event_queue;
    let head = &(*q).proxy_list as *const wl_list as *mut wl_list;
    let mut cur = (*head).next;

    while cur != head && !cur.is_null() {
        // The proxy is embedded inside wl_proxy.queue_link — offset
        // back to the start of the wl_proxy struct.
        let link_offset = 80usize;
        let proxy = (cur as usize - link_offset) as *mut c_void;
        capture_proxy(proxy);
        cur = (*cur).next;
    }
}

// ---------------------------------------------------------------------------
// Run hooks (called from every patched dispatch function)
// ---------------------------------------------------------------------------

unsafe fn run_hooks(display: *mut c_void) {
    G_DISPLAY.store(display, Ordering::Release);
    G_DISPATCH_CALLED.store(true, Ordering::Release);

    if !G_INITIAL_SWEEP_DONE.swap(true, Ordering::SeqCst) {
        initial_sweep(display);
    }

    let cmds = {
        let mut q = COMMAND_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *q)
    };
    for cmd in cmds {
        dispatch_event(display, cmd);
    }
}

// ---------------------------------------------------------------------------
// Dispatch hooks — these replace the real functions via GOT patching
// ---------------------------------------------------------------------------

unsafe extern "C" fn hook_dispatch(display: *mut c_void) -> c_int {
    run_hooks(display);
    let real: unsafe extern "C" fn(*mut c_void) -> c_int =
        std::mem::transmute(REAL_DISPATCH.load(Ordering::SeqCst));
    real(display)
}

unsafe extern "C" fn hook_dispatch_pending(display: *mut c_void) -> c_int {
    run_hooks(display);
    let real: unsafe extern "C" fn(*mut c_void) -> c_int =
        std::mem::transmute(REAL_DISPATCH_PENDING.load(Ordering::SeqCst));
    real(display)
}

unsafe extern "C" fn hook_dispatch_queue(display: *mut c_void, queue: *mut c_void) -> c_int {
    run_hooks(display);
    let real: unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int =
        std::mem::transmute(REAL_DISPATCH_QUEUE.load(Ordering::SeqCst));
    real(display, queue)
}

unsafe extern "C" fn hook_dispatch_queue_pending(
    display: *mut c_void,
    queue: *mut c_void,
) -> c_int {
    run_hooks(display);
    let real: unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int =
        std::mem::transmute(REAL_DISPATCH_QUEUE_PENDING.load(Ordering::SeqCst));
    real(display, queue)
}

unsafe extern "C" fn hook_add_dispatcher(
    proxy: *mut c_void,
    dispatcher: *mut c_void,
    implementation: *const c_void,
    data: *mut c_void,
) {
    capture_proxy(proxy);
    let real: unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_void, *mut c_void) =
        std::mem::transmute(REAL_ADD_DISPATCHER.load(Ordering::SeqCst));
    real(proxy, dispatcher, implementation, data);
}

// ---------------------------------------------------------------------------
// GOT patching
// ---------------------------------------------------------------------------

/// Patch the GOT entry for `symbol` in every loaded module to point to `hook`.
unsafe fn patch_all_gots(symbol: &str, hook: *mut c_void) {
    let maps = match std::fs::read_to_string("/proc/self/maps") {
        Ok(m) => m,
        Err(_) => return,
    };

    let mut seen = std::collections::HashSet::new();

    for line in maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let path = parts[5];
        if !path.starts_with('/') {
            continue;
        }

        let addr_range: Vec<&str> = parts[0].split('-').collect();
        if addr_range.len() != 2 {
            continue;
        }
        let base = match usize::from_str_radix(addr_range[0], 16) {
            Ok(b) => b,
            Err(_) => continue,
        };

        if !seen.insert(path.to_string()) {
            continue;
        }

        patch_got_in_module(base, path, symbol, hook);
    }
}

/// Read `/proc/self/maps` to determine the original protection of the page
/// containing `addr`.
unsafe fn page_protection(addr: usize) -> Option<i32> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let range: Vec<&str> = parts[0].split('-').collect();
        if range.len() != 2 {
            continue;
        }
        let start = usize::from_str_radix(range[0], 16).ok()?;
        let end = usize::from_str_radix(range[1], 16).ok()?;
        if addr >= start && addr < end {
            let perms = parts[1].as_bytes();
            let mut prot = 0;
            if perms.first() == Some(&b'r') {
                prot |= libc::PROT_READ;
            }
            if perms.get(1) == Some(&b'w') {
                prot |= libc::PROT_WRITE;
            }
            if perms.get(2) == Some(&b'x') {
                prot |= libc::PROT_EXEC;
            }
            return Some(prot);
        }
    }
    None
}

unsafe fn patch_got_in_module(base: usize, path: &str, symbol: &str, hook: *mut c_void) {
    // Never patch libwayland-client itself — it *defines* these symbols.
    if path.contains("libwayland-client") {
        return;
    }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return,
    };

    let elf = match goblin::Object::parse(&data) {
        Ok(goblin::Object::Elf(e)) => e,
        _ => return,
    };

    // Walk .rela.plt and .rela.dyn relocations.
    let relocs: Vec<_> = elf.pltrelocs.iter().chain(elf.dynrelas.iter()).collect();

    for rela in &relocs {
        let sym = match elf.dynsyms.get(rela.r_sym) {
            Some(s) => s,
            None => continue,
        };

        let sym_name = elf.dynstrtab.get_at(sym.st_name);
        if sym_name != Some(symbol) {
            continue;
        }

        // Only patch imports (undefined symbols), not internal references.
        if sym.st_shndx as u32 != goblin::elf::section_header::SHN_UNDEF || sym.st_value != 0 {
            continue;
        }

        let got_entry = (base + rela.r_offset as usize) as *mut *mut c_void;

        // Save the real pointer.
        let real = *got_entry;
        store_real(symbol, real);

        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let page_start = (got_entry as usize) & !(page_size - 1);
        let old_prot = page_protection(page_start);

        if old_prot.is_none() {
            continue;
        }

        // Make the page writable.
        let ret = libc::mprotect(
            page_start as *mut c_void,
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        if ret != 0 {
            continue;
        }

        // Write our hook.
        *got_entry = hook;

        // Restore original protection.
        if let Some(prot) = old_prot {
            let _ = libc::mprotect(page_start as *mut c_void, page_size, prot);
        }

        return;
    }
}

// ---------------------------------------------------------------------------
// Synthetic input dispatch — calls the proxy's dispatcher directly.
// ---------------------------------------------------------------------------

/// Matches libwayland's `union wl_argument`.
#[repr(C)]
union wl_argument {
    i: i32,
    u: u32,
    f: i32, // wl_fixed_t
    s: *const c_char,
    o: *mut c_void,
    n: u32,
    a: *mut c_void,
    h: i32,
}

/// Signature of the dispatcher installed by wayland-backend.
type DispatcherFn = unsafe extern "C" fn(
    *const c_void,
    *mut c_void,
    u32,
    *const c_void,
    *const wl_argument,
) -> c_int;

unsafe fn invoke_dispatcher(proxy: *mut c_void, opcode: u32, args: &mut [wl_argument]) -> bool {
    let p = proxy as *mut wl_proxy;
    let dispatcher_ptr = (*p).dispatcher;
    if dispatcher_ptr.is_null() {
        return false;
    }
    let disp: DispatcherFn = std::mem::transmute(dispatcher_ptr);
    let impl_ptr = (*p).object.implementation;
    let _ = disp(impl_ptr, proxy, opcode, std::ptr::null(), args.as_ptr());
    true
}

static SERIAL: AtomicU32 = AtomicU32::new(1);

fn next_serial() -> u32 {
    SERIAL.fetch_add(1, Ordering::SeqCst)
}

fn monotonic_ms() -> u32 {
    let ts = unsafe {
        let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
        libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr());
        ts.assume_init()
    };
    (ts.tv_sec as u32)
        .wrapping_mul(1000)
        .wrapping_add((ts.tv_nsec / 1_000_000) as u32)
}

fn to_fixed(v: f64) -> i32 {
    (v * 256.0).round() as i32
}

fn dispatch_event(_display: *mut c_void, cmd: IpcCommand) {
    let serial = next_serial();
    let ms = monotonic_ms();
    match cmd {
        IpcCommand::MouseMove { x, y } => {
            if let Some(ptr) = get_pointer_proxy() {
                unsafe {
                    let mut args = [
                        wl_argument { u: ms },
                        wl_argument { f: to_fixed(x) },
                        wl_argument { f: to_fixed(y) },
                    ];
                    invoke_dispatcher(ptr, 2 /* motion */, &mut args);
                }
            }
        }
        IpcCommand::MouseButton { button, state } => {
            if let Some(ptr) = get_pointer_proxy() {
                unsafe {
                    let mut args = [
                        wl_argument { u: serial },
                        wl_argument { u: ms },
                        wl_argument { u: button },
                        wl_argument { u: state },
                    ];
                    invoke_dispatcher(ptr, 3 /* button */, &mut args);
                }
            }
        }
        IpcCommand::Key { key, state } => {
            if let Some(kbd) = get_keyboard_proxy() {
                unsafe {
                    let mut args = [
                        wl_argument { u: serial },
                        wl_argument { u: ms },
                        wl_argument { u: key },
                        wl_argument { u: state },
                    ];
                    invoke_dispatcher(kbd, 3 /* key */, &mut args);
                }
            }
        }
        IpcCommand::Modifiers { depressed } => {
            if let Some(kbd) = get_keyboard_proxy() {
                unsafe {
                    let mut args = [
                        wl_argument { u: serial },
                        wl_argument { u: depressed },
                        wl_argument { u: 0 }, // mods_latched
                        wl_argument { u: 0 }, // mods_locked
                        wl_argument { u: 0 }, // group
                    ];
                    invoke_dispatcher(kbd, 4 /* modifiers */, &mut args);
                }
            }
        }
    }
}

fn get_pointer_proxy() -> Option<*mut c_void> {
    let p = G_POINTER.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        Some(p)
    }
}

fn get_keyboard_proxy() -> Option<*mut c_void> {
    let p = G_KEYBOARD.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        Some(p)
    }
}

// ---------------------------------------------------------------------------
// IPC protocol
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
    depressed: Option<u32>,
}

#[derive(Debug, Clone)]
enum IpcCommand {
    MouseMove { x: f64, y: f64 },
    MouseButton { button: u32, state: u32 },
    Key { key: u32, state: u32 },
    Modifiers { depressed: u32 },
}

#[derive(Debug)]
enum HandleResult {
    Response(String),
    Unload,
}
fn parse_state(s: &str) -> u32 {
    match s {
        "pressed" => 1,
        "released" => 0,
        _ => 0,
    }
}

fn handle_request(line: &str) -> HandleResult {
    let req: IpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            return HandleResult::Response(make_error("invalid_json", &e.to_string()));
        }
    };

    match req.ty.as_str() {
        "hello" => HandleResult::Response(
            r#"{"type":"hello_ack","protocol_version":1,"payload_version":"0.2.2"}"#.to_string(),
        ),
        "mouse_move" => {
            let x = req.x.unwrap_or(0.0);
            let y = req.y.unwrap_or(0.0);
            {
                let mut q = COMMAND_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
                q.push_back(IpcCommand::MouseMove { x, y });
            }
            HandleResult::Response(make_ok())
        }
        "mouse_button" => {
            let button = req.button.unwrap_or(0);
            let state = parse_state(&req.state.unwrap_or_default());
            {
                let mut q = COMMAND_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
                q.push_back(IpcCommand::MouseButton { button, state });
            }
            HandleResult::Response(make_ok())
        }
        "key" => {
            let key = req.key.unwrap_or(0);
            let state = parse_state(&req.state.unwrap_or_default());
            {
                let mut q = COMMAND_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
                q.push_back(IpcCommand::Key { key, state });
            }
            HandleResult::Response(make_ok())
        }
        "modifiers" => {
            let depressed = req.depressed.unwrap_or(0);
            {
                let mut q = COMMAND_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
                q.push_back(IpcCommand::Modifiers { depressed });
            }
            HandleResult::Response(make_ok())
        }
        "surface_size" => {
            if G_XDG_TOPLEVEL.load(Ordering::Acquire).is_null() {
                return HandleResult::Response(make_error(
                    "proxy_not_found",
                    "xdg_toplevel not captured yet",
                ));
            }
            let w = G_SURFACE_W.load(Ordering::Acquire);
            let h = G_SURFACE_H.load(Ordering::Acquire);
            HandleResult::Response(format!(r#"{{"status":"ok","width":{},"height":{}}}"#, w, h))
        }
        "status" => HandleResult::Response(format!(
            r#"{{"status":"ok","dispatch_hook_installed":{}}}"#,
            G_DISPATCH_CALLED.load(Ordering::Acquire)
        )),
        "unload" => HandleResult::Unload,
        _ => HandleResult::Response(make_error("unknown_command", &req.ty)),
    }
}

fn make_ok() -> String {
    r#"{"status":"ok"}"#.to_string()
}

fn make_error(code: &str, message: &str) -> String {
    let mut m = serde_json::Map::new();
    m.insert(
        "status".to_string(),
        serde_json::Value::String("error".to_string()),
    );
    m.insert(
        "code".to_string(),
        serde_json::Value::String(code.to_string()),
    );
    m.insert(
        "message".to_string(),
        serde_json::Value::String(message.to_string()),
    );
    serde_json::to_string(&m).unwrap()
}

// ---------------------------------------------------------------------------
// IPC thread
// ---------------------------------------------------------------------------

fn runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// Buffer that holds the socket path passed in by the host.
static mut BACKSEAT_SOCK_PATH: [u8; 256] = [0; 256];

fn ipc_thread() {
    let pid = unsafe { libc::getpid() };

    let sock_path = unsafe {
        let buf_ptr = std::ptr::addr_of!(BACKSEAT_SOCK_PATH).cast::<u8>();
        if *buf_ptr != 0 {
            let mut len = 0usize;
            while len < 256 && *buf_ptr.add(len) != 0 {
                len += 1;
            }
            PathBuf::from(std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                buf_ptr, len,
            )))
        } else {
            runtime_dir().join(format!("backseat-{}.sock", pid))
        }
    };

    let sock_path_cstring = std::ffi::CString::new(sock_path.to_string_lossy().as_bytes()).unwrap();
    let _ = std::fs::remove_file(&sock_path);

    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => l,
        Err(_) => {
            IPC_THREAD_STARTED.store(false, Ordering::SeqCst);
            return;
        }
    };

    unsafe {
        libc::chmod(sock_path_cstring.as_ptr(), 0o700);
    }

    let (stream, _) = match listener.accept() {
        Ok(v) => v,
        Err(_) => {
            IPC_THREAD_STARTED.store(false, Ordering::SeqCst);
            return;
        }
    };

    let mut write_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => {
            IPC_THREAD_STARTED.store(false, Ordering::SeqCst);
            return;
        }
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

        match handle_request(line_trimmed) {
            HandleResult::Response(response) => {
                let _ = write_stream.write_all(response.as_bytes());
                let _ = write_stream.write_all(b"\n");
            }
            HandleResult::Unload => {
                let _ = write_stream.write_all(make_ok().as_bytes());
                let _ = std::fs::remove_file(&sock_path);
                break;
            }
        }
        line.clear();
    }
    // Allow re-injection after unload.
    IPC_THREAD_STARTED.store(false, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

#[used]
#[link_section = ".init_array"]
static CONSTRUCTOR: extern "C" fn() = init;

extern "C" fn init() {
    unsafe {
        patch_all_gots("wl_display_dispatch", hook_dispatch as *mut c_void);
        patch_all_gots(
            "wl_display_dispatch_pending",
            hook_dispatch_pending as *mut c_void,
        );
        patch_all_gots(
            "wl_display_dispatch_queue",
            hook_dispatch_queue as *mut c_void,
        );
        patch_all_gots(
            "wl_display_dispatch_queue_pending",
            hook_dispatch_queue_pending as *mut c_void,
        );
        patch_all_gots(
            "wl_proxy_add_dispatcher",
            hook_add_dispatcher as *mut c_void,
        );
    }
}

/// Host-visible entry point. Receives the Unix-socket path and starts IPC.
///
/// # Safety
/// `path` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn backseat_init(path: *const c_char) {
    if !path.is_null() {
        let bytes = CStr::from_ptr(path).to_bytes_with_nul();
        let len = bytes.len().min(256);
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            std::ptr::addr_of_mut!(BACKSEAT_SOCK_PATH).cast::<u8>(),
            len,
        );
    }

    extern "C" fn ipc_thread_wrapper(_arg: *mut c_void) -> *mut c_void {
        ipc_thread();
        std::ptr::null_mut()
    }

    if IPC_THREAD_STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        unsafe {
            let mut tid: libc::pthread_t = 0;
            let ret = libc::pthread_create(
                &mut tid,
                std::ptr::null(),
                ipc_thread_wrapper,
                std::ptr::null_mut(),
            );
            if ret != 0 {
                IPC_THREAD_STARTED.store(false, Ordering::SeqCst);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Tests that touch `COMMAND_QUEUE` must run sequentially because
    /// the queue is a process-global `Mutex`.  This lock serialises
    /// entry to every test in the module.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // -----------------------------------------------------------------------
    // to_fixed
    // -----------------------------------------------------------------------

    #[test]
    fn to_fixed_rounds_half_up() {
        assert_eq!(to_fixed(1.5), 384);
        assert_eq!(to_fixed(1.501), 384);
        assert_eq!(to_fixed(1.505), 385);
    }

    #[test]
    fn to_fixed_negative() {
        assert_eq!(to_fixed(-1.0), -256);
        assert_eq!(to_fixed(-0.5), -128);
    }

    #[test]
    fn to_fixed_zero() {
        assert_eq!(to_fixed(0.0), 0);
    }

    // -----------------------------------------------------------------------
    // monotonic_ms / next_serial
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // parse_state
    // -----------------------------------------------------------------------

    #[test]
    fn parse_state_pressed() {
        assert_eq!(parse_state("pressed"), 1);
    }

    #[test]
    fn parse_state_released() {
        assert_eq!(parse_state("released"), 0);
    }

    #[test]
    fn parse_state_unknown_defaults_to_released() {
        assert_eq!(parse_state(""), 0);
        assert_eq!(parse_state("garbage"), 0);
    }

    // -----------------------------------------------------------------------
    // make_ok / make_error
    // -----------------------------------------------------------------------

    #[test]
    fn make_ok_produces_valid_json() {
        let json = make_ok();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["status"], "ok");
    }

    #[test]
    fn make_error_produces_valid_json() {
        let json = make_error("proxy_not_found", "no pointer");
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["status"], "error");
        assert_eq!(v["code"], "proxy_not_found");
        assert_eq!(v["message"], "no pointer");
    }

    /// The host's `Response` struct must be able to deserialize
    /// make_error output.  Verify the exact field names match.
    #[test]
    fn make_error_roundtrips_with_host_response() {
        let json = make_error("bad_cmd", "test message");
        let v: Value = serde_json::from_str(&json).unwrap();
        // The host crate source maps these fields as:
        //   status, code, message
        assert!(v.get("status").is_some());
        assert!(v.get("code").is_some());
        assert!(v.get("message").is_some());
    }

    /// Acquire the serialisation lock for tests that touch global state
    /// (COMMAND_QUEUE, G_* atomics).
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap()
    }

    /// Send a JSON line to handle_request.  The caller must hold
    /// TEST_LOCK.  Returns the parsed response and drains any commands
    /// that were enqueued into a Vec.
    fn send(line: &str) -> (Value, Vec<IpcCommand>) {
        COMMAND_QUEUE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let resp = match handle_request(line) {
            HandleResult::Response(s) => serde_json::from_str(&s).unwrap(),
            HandleResult::Unload => {
                let mut m = serde_json::Map::new();
                m.insert(
                    "status".to_string(),
                    serde_json::Value::String("ok".to_string()),
                );
                serde_json::Value::Object(m)
            }
        };
        let cmds: Vec<IpcCommand> = COMMAND_QUEUE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect();
        (resp, cmds)
    }

    // -----------------------------------------------------------------------
    // handle_request — hello
    // -----------------------------------------------------------------------

    #[test]
    fn handle_hello() {
        let _g = lock();
        let (resp, _) = send(r#"{"type":"hello"}"#);
        assert_eq!(resp["type"], "hello_ack");
        assert_eq!(resp["protocol_version"], 1);
        assert!(resp.get("payload_version").is_some());
    }

    // -----------------------------------------------------------------------
    // handle_request — mouse_move
    // -----------------------------------------------------------------------

    #[test]
    fn handle_mouse_move_enqueues_command() {
        let _g = lock();
        let (resp, cmds) = send(r#"{"type":"mouse_move","x":100.5,"y":200.3}"#);
        assert_eq!(resp["status"], "ok");
        assert_eq!(cmds.len(), 1);
        match &cmds[0] {
            IpcCommand::MouseMove { x, y } => {
                assert!((x - 100.5).abs() < 0.001);
                assert!((y - 200.3).abs() < 0.001);
            }
            other => panic!("expected MouseMove, got {other:?}"),
        }
    }

    #[test]
    fn handle_mouse_move_missing_coords_defaults_to_zero() {
        let _g = lock();
        let (resp, cmds) = send(r#"{"type":"mouse_move"}"#);
        assert_eq!(resp["status"], "ok");
        match &cmds[0] {
            IpcCommand::MouseMove { x, y } => {
                assert_eq!(*x, 0.0);
                assert_eq!(*y, 0.0);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // handle_request — mouse_button
    // -----------------------------------------------------------------------

    #[test]
    fn handle_mouse_button_pressed() {
        let _g = lock();
        let (resp, cmds) = send(r#"{"type":"mouse_button","button":272,"state":"pressed"}"#);
        assert_eq!(resp["status"], "ok");
        match &cmds[0] {
            IpcCommand::MouseButton { button, state } => {
                assert_eq!(*button, 272);
                assert_eq!(*state, 1);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn handle_mouse_button_released() {
        let _g = lock();
        let (resp, cmds) = send(r#"{"type":"mouse_button","button":273,"state":"released"}"#);
        assert_eq!(resp["status"], "ok");
        match &cmds[0] {
            IpcCommand::MouseButton { button, state } => {
                assert_eq!(*button, 273);
                assert_eq!(*state, 0);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // handle_request — key
    // -----------------------------------------------------------------------

    #[test]
    fn handle_key_pressed() {
        let _g = lock();
        let (resp, cmds) = send(r#"{"type":"key","key":30,"state":"pressed"}"#);
        assert_eq!(resp["status"], "ok");
        match &cmds[0] {
            IpcCommand::Key { key, state } => {
                assert_eq!(*key, 30);
                assert_eq!(*state, 1);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn handle_key_missing_fields_defaults() {
        let _g = lock();
        let (resp, cmds) = send(r#"{"type":"key"}"#);
        assert_eq!(resp["status"], "ok");
        match &cmds[0] {
            IpcCommand::Key { key, state } => {
                assert_eq!(*key, 0);
                assert_eq!(*state, 0);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // handle_request — modifiers
    // -----------------------------------------------------------------------

    #[test]
    fn handle_modifiers() {
        let _g = lock();
        let (resp, cmds) = send(r#"{"type":"modifiers","depressed":1}"#);
        assert_eq!(resp["status"], "ok");
        match &cmds[0] {
            IpcCommand::Modifiers { depressed } => assert_eq!(*depressed, 1),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // handle_request — surface_size
    // -----------------------------------------------------------------------

    #[test]
    fn handle_surface_size_without_toplevel() {
        let _g = lock();
        let (resp, _) = send(r#"{"type":"surface_size"}"#);
        assert_eq!(resp["status"], "error");
        assert_eq!(resp["code"], "proxy_not_found");
    }

    #[test]
    fn handle_surface_size_with_toplevel() {
        let _g = lock();
        G_XDG_TOPLEVEL.store(std::ptr::dangling_mut::<c_void>(), Ordering::Release);
        G_SURFACE_W.store(1920, Ordering::Release);
        G_SURFACE_H.store(1080, Ordering::Release);

        let (resp, _) = send(r#"{"type":"surface_size"}"#);
        assert_eq!(resp["status"], "ok");
        assert_eq!(resp["width"], 1920);
        assert_eq!(resp["height"], 1080);

        G_XDG_TOPLEVEL.store(std::ptr::null_mut(), Ordering::Release);
        G_SURFACE_W.store(0, Ordering::Release);
        G_SURFACE_H.store(0, Ordering::Release);
    }

    // -----------------------------------------------------------------------
    // handle_request — status
    // -----------------------------------------------------------------------

    #[test]
    fn handle_status_reports_dispatch_hook() {
        let _g = lock();
        G_DISPATCH_CALLED.store(true, Ordering::Release);
        let (resp, _) = send(r#"{"type":"status"}"#);
        assert_eq!(resp["status"], "ok");
        assert_eq!(resp["dispatch_hook_installed"], true);

        G_DISPATCH_CALLED.store(false, Ordering::Release);
        let (resp, _) = send(r#"{"type":"status"}"#);
        assert_eq!(resp["dispatch_hook_installed"], false);
    }

    // -----------------------------------------------------------------------
    // handle_request — unload
    // -----------------------------------------------------------------------

    #[test]
    fn handle_unload_returns_unload_variant() {
        match handle_request(r#"{"type":"unload"}"#) {
            HandleResult::Unload => {}
            other => panic!("expected Unload, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // handle_request — error cases
    // -----------------------------------------------------------------------

    #[test]
    fn handle_request_malformed_json() {
        let _g = lock();
        let (resp, _) = send("not json at all");
        assert_eq!(resp["status"], "error");
        assert_eq!(resp["code"], "invalid_json");
    }

    #[test]
    fn handle_request_unknown_command() {
        let _g = lock();
        let (resp, _) = send(r#"{"type":"nonexistent_cmd"}"#);
        assert_eq!(resp["status"], "error");
        assert_eq!(resp["code"], "unknown_command");
    }
}
