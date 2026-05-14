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
    let impl_ptr = (*proxy).object.implementation as *mut usize;
    if impl_ptr.is_null() {
        return;
    }
    // Skip if the implementation pointer is not 8-byte aligned — this
    // indicates a dispatcher-managed proxy (not a listener array).
    if (impl_ptr as usize) & 7 != 0 {
        return;
    }
    let func = *impl_ptr;
    // Skip if the "function pointer" at impl_ptr[0] doesn't look like
    // a code pointer (dispatcher proxies store a single function here,
    // not a listener table with user-data at +1).
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
    let entries = map.client_entries.data as *const *mut c_void;
    let count = map.client_entries.size / std::mem::size_of::<*mut c_void>();

    if entries.is_null() || count == 0 {
        return;
    }
    let slice = std::slice::from_raw_parts(entries, count);
    for &proxy_ptr in slice.iter() {
        if !proxy_ptr.is_null() {
            capture_proxy(proxy_ptr);
        }
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
// Synthetic input dispatch
// ---------------------------------------------------------------------------

fn dispatch_event(display: *mut c_void, cmd: IpcCommand) {
    match cmd {
        IpcCommand::MouseMove { x, y } => {
            if let Some(ptr) = get_pointer_proxy() {
                unsafe {
                    let serial = next_serial();
                    wl_pointer_motion(ptr, serial, display, x, y);
                }
            }
        }
        IpcCommand::MouseButton { button, state } => {
            if let Some(ptr) = get_pointer_proxy() {
                unsafe {
                    let serial = next_serial();
                    wl_pointer_button(ptr, serial, display, button, state);
                }
            }
        }
        IpcCommand::Key { key, state } => {
            if let Some(kbd) = get_keyboard_proxy() {
                unsafe {
                    let serial = next_serial();
                    wl_keyboard_key(kbd, serial, display, key, state);
                }
            }
        }
        IpcCommand::Modifiers { depressed } => {
            if let Some(kbd) = get_keyboard_proxy() {
                unsafe {
                    let serial = next_serial();
                    wl_keyboard_modifiers(kbd, serial, display, depressed);
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
// libwayland protocol helpers
// ---------------------------------------------------------------------------

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

/// Emulate `wl_pointer.motion`.
unsafe fn wl_pointer_motion(
    proxy: *mut c_void,
    serial: u32,
    _display: *mut c_void,
    x: f64,
    y: f64,
) {
    let mut args: [u64; 4] = [
        serial as u64,
        monotonic_ms() as u64,
        to_fixed(x) as u64,
        to_fixed(y) as u64,
    ];
    wl_proxy_marshal(proxy, 4, args.as_mut_ptr());
    wl_proxy_marshal(proxy, 5, args.as_mut_ptr());
}

/// Emulate `wl_pointer.button`.
unsafe fn wl_pointer_button(
    proxy: *mut c_void,
    serial: u32,
    _display: *mut c_void,
    button: u32,
    state: u32,
) {
    let mut args: [u64; 4] = [
        serial as u64,
        monotonic_ms() as u64,
        button as u64,
        state as u64,
    ];
    wl_proxy_marshal(proxy, 3, args.as_mut_ptr());
    wl_proxy_marshal(proxy, 5, args.as_mut_ptr());
}

/// Emulate `wl_keyboard.key`.
unsafe fn wl_keyboard_key(
    proxy: *mut c_void,
    serial: u32,
    _display: *mut c_void,
    key: u32,
    state: u32,
) {
    let mut args: [u64; 4] = [
        serial as u64,
        monotonic_ms() as u64,
        key as u64,
        state as u64,
    ];
    wl_proxy_marshal(proxy, 3, args.as_mut_ptr());
}

/// Emulate `wl_keyboard.modifiers`.
unsafe fn wl_keyboard_modifiers(
    proxy: *mut c_void,
    serial: u32,
    _display: *mut c_void,
    depressed: u32,
) {
    let mut args: [u64; 5] = [
        serial as u64,
        depressed as u64,
        0, // mods_latched
        0, // mods_locked
        0, // group
    ];
    wl_proxy_marshal(proxy, 4, args.as_mut_ptr());
}

/// Low-level proxy marshalling — matches libwayland's `wl_proxy_marshal`.
unsafe fn wl_proxy_marshal(proxy: *mut c_void, opcode: u32, args: *mut u64) {
    let func: unsafe extern "C" fn(*mut c_void, u32, ...) =
        std::mem::transmute(libc::dlsym(libc::RTLD_NEXT, c"wl_proxy_marshal".as_ptr()));
    let a = std::slice::from_raw_parts(args, 5);
    func(proxy, opcode, a[0], a[1], a[2], a[3], a[4]);
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

fn log(msg: &str) {
    let _ = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open("/tmp/backseat-debug.log")
        .and_then(|mut f| f.write_all(msg.as_bytes()));
}

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
            log(&format!("bind failed: {}\n", sock_path.display()));
            IPC_THREAD_STARTED.store(false, Ordering::SeqCst);
            return;
        }
    };

    unsafe {
        libc::chmod(sock_path_cstring.as_ptr(), 0o700);
    }

    let (stream, _) = match listener.accept() {
        Ok(v) => v,
        Err(e) => {
            log(&format!("accept failed: {}\n", e));
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
                log(&format!("pthread_create failed: {}\n", ret));
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

    #[test]
    fn to_fixed_rounds_half_up() {
        assert_eq!(to_fixed(1.5), 384);
        assert_eq!(to_fixed(1.501), 384);
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
