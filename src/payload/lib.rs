//! backseat-payload — injected shared library for Wayland input injection.
//!
//! This crate is compiled as a `cdylib` and injected into a target process via
//! `dlopen`. Once loaded, it:
//!
//! 1. Finds the target's Wayland socket fd and inserts itself as a
//!    transparent proxy via socketpair MITM.
//! 2. Spawns a pump thread that forwards traffic bidirectionally between
//!    the app and the real compositor, preserving ancillary `SCM_RIGHTS`
//!    fd data (shm pools, dmabuf).
//! 3. Sniffs the forwarded wire traffic to learn object IDs (wl_pointer,
//!    wl_keyboard, wl_surface) and serials.
//! 4. Spawns an IPC thread listening on a per-PID Unix socket.
//! 5. Encodes synthetic input as correct Wayland wire messages and injects
//!    them into the app's read side — letting *its* libwayland do the
//!    ABI-correct dispatch.
//!
//! # Architecture decision
//!
//! We no longer patch GOT entries, walk wl_map internals, or call listener
//! vtable functions by hand.  Those operations depend on private libwayland
//! struct layouts that change across distro releases.  Instead we sit on the
//! wire — the only stable ABI Wayland has — and feed the app's own
//! libwayland correctly-encoded messages.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::io::{BufRead, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

// ---------------------------------------------------------------------------
// Wire encoding — Little-endian Wayland wire protocol messages
// ---------------------------------------------------------------------------
//
// Message = header + args, all little-endian u32 words:
//   header: [u32 object_id, u32 size_opcode]
//     size_opcode = (total_size_in_bytes << 16) | opcode
//     total_size includes the 8-byte header
//   args:   uint/int/fixed/object/new_id = 1 word each
//           string = u32 len(incl NUL) + data padded to 4
//           array  = u32 len + data padded to 4
//           fd     = ancillary (not in byte stream)
//
// wl_fixed = 24.8 fixed point: fixed = round(double * 256.0)

/// Build a wayland message header (2 u32 words).
/// `object_id`: target object on the wire.
/// `opcode`: event/request opcode.
/// `body_words`: number of u32 argument words (NOT counting the 2 header words).
fn wire_header(object_id: u32, opcode: u16, body_words: u32) -> [u32; 2] {
    let total_bytes = 8 + body_words * 4;
    let size_opcode = (total_bytes << 16) | (opcode as u32);
    [object_id, size_opcode]
}

/// Write a u32 word to a byte buffer (little-endian).
fn push_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

/// Write a wl_fixed value (24.8 fixed point from f64).
fn push_fixed(buf: &mut Vec<u8>, val: f64) {
    push_u32(buf, to_fixed(val) as u32);
}

/// Write a string argument: 4-byte length prefix (incl NUL), NUL-terminated
/// data, 4-byte padded.
#[allow(dead_code)]
fn push_string(buf: &mut Vec<u8>, s: &str) {
    let len_with_nul = (s.len() + 1) as u32;
    push_u32(buf, len_with_nul);
    buf.extend_from_slice(s.as_bytes());
    buf.push(0u8); // NUL terminator
    let padded_len = len_with_nul.div_ceil(4) * 4;
    for _ in len_with_nul..padded_len {
        buf.push(0u8);
    }
}

/// Write an array argument: 4-byte length prefix, data, 4-byte padded.
fn push_array(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u32;
    push_u32(buf, len);
    buf.extend_from_slice(data);
    let padded_len = len.div_ceil(4) * 4;
    for _ in len..padded_len {
        buf.push(0u8);
    }
}

/// Encode `wl_pointer.enter(serial, surface, x, y)` → opcode 0.
/// Returns the complete wire message bytes (header + args).
fn encode_pointer_enter(object_id: u32, serial: u32, surface: u32, x: f64, y: f64) -> Vec<u8> {
    let [h0, h1] = wire_header(object_id, 0, 4);
    let mut buf = Vec::with_capacity(24);
    push_u32(&mut buf, h0);
    push_u32(&mut buf, h1);
    push_u32(&mut buf, serial);
    push_u32(&mut buf, surface);
    push_fixed(&mut buf, x);
    push_fixed(&mut buf, y);
    buf
}

/// Encode `wl_pointer.leave(serial, surface)` → opcode 1.
#[allow(dead_code)]
fn encode_pointer_leave(object_id: u32, serial: u32, surface: u32) -> Vec<u8> {
    let [h0, h1] = wire_header(object_id, 1, 2);
    let mut buf = Vec::with_capacity(16);
    push_u32(&mut buf, h0);
    push_u32(&mut buf, h1);
    push_u32(&mut buf, serial);
    push_u32(&mut buf, surface);
    buf
}

/// Encode `wl_pointer.motion(time, x, y)` → opcode 2.
fn encode_pointer_motion(object_id: u32, time: u32, x: f64, y: f64) -> Vec<u8> {
    let [h0, h1] = wire_header(object_id, 2, 3);
    let mut buf = Vec::with_capacity(20);
    push_u32(&mut buf, h0);
    push_u32(&mut buf, h1);
    push_u32(&mut buf, time);
    push_fixed(&mut buf, x);
    push_fixed(&mut buf, y);
    buf
}

/// Encode `wl_pointer.button(serial, time, button, state)` → opcode 3.
fn encode_pointer_button(
    object_id: u32,
    serial: u32,
    time: u32,
    button: u32,
    state: u32,
) -> Vec<u8> {
    let [h0, h1] = wire_header(object_id, 3, 4);
    let mut buf = Vec::with_capacity(24);
    push_u32(&mut buf, h0);
    push_u32(&mut buf, h1);
    push_u32(&mut buf, serial);
    push_u32(&mut buf, time);
    push_u32(&mut buf, button);
    push_u32(&mut buf, state);
    buf
}

/// Encode `wl_pointer.axis(time, axis, value)` → opcode 4.
fn encode_pointer_axis(object_id: u32, time: u32, axis: u32, value: f64) -> Vec<u8> {
    let [h0, h1] = wire_header(object_id, 4, 3);
    let mut buf = Vec::with_capacity(20);
    push_u32(&mut buf, h0);
    push_u32(&mut buf, h1);
    push_u32(&mut buf, time);
    push_u32(&mut buf, axis);
    push_fixed(&mut buf, value);
    buf
}

/// Encode `wl_pointer.frame()` → opcode 5.
fn encode_pointer_frame(object_id: u32) -> Vec<u8> {
    let [h0, h1] = wire_header(object_id, 5, 0);
    let mut buf = Vec::with_capacity(8);
    push_u32(&mut buf, h0);
    push_u32(&mut buf, h1);
    buf
}

/// Encode `wl_keyboard.enter(serial, surface, keys)` → opcode 1.
/// `keys` is an array of u32 keycodes.
fn encode_keyboard_enter(object_id: u32, serial: u32, surface: u32, keys: &[u32]) -> Vec<u8> {
    let keys_bytes: Vec<u8> = keys
        .iter()
        .flat_map(|k| k.to_le_bytes())
        .collect();
    let array_words = (keys_bytes.len() / 4) as u32;
    // header(2) + serial(1) + surface(1) + array_len(1) + array_body
    let body_words = 1 + 1 + 1 + array_words;
    let [h0, h1] = wire_header(object_id, 1, body_words);
    let mut buf = Vec::with_capacity(8 + (body_words * 4) as usize);
    push_u32(&mut buf, h0);
    push_u32(&mut buf, h1);
    push_u32(&mut buf, serial);
    push_u32(&mut buf, surface);
    push_array(&mut buf, &keys_bytes);
    buf
}

/// Encode `wl_keyboard.leave(serial, surface)` → opcode 2.
#[allow(dead_code)]
fn encode_keyboard_leave(object_id: u32, serial: u32, surface: u32) -> Vec<u8> {
    let [h0, h1] = wire_header(object_id, 2, 2);
    let mut buf = Vec::with_capacity(16);
    push_u32(&mut buf, h0);
    push_u32(&mut buf, h1);
    push_u32(&mut buf, serial);
    push_u32(&mut buf, surface);
    buf
}

/// Encode `wl_keyboard.key(serial, time, key, state)` → opcode 3.
fn encode_keyboard_key(object_id: u32, serial: u32, time: u32, key: u32, state: u32) -> Vec<u8> {
    let [h0, h1] = wire_header(object_id, 3, 4);
    let mut buf = Vec::with_capacity(24);
    push_u32(&mut buf, h0);
    push_u32(&mut buf, h1);
    push_u32(&mut buf, serial);
    push_u32(&mut buf, time);
    push_u32(&mut buf, key);
    push_u32(&mut buf, state);
    buf
}

/// Encode `wl_keyboard.modifiers(serial, depressed, latched, locked, group)` → opcode 4.
fn encode_keyboard_modifiers(
    object_id: u32,
    serial: u32,
    depressed: u32,
    latched: u32,
    locked: u32,
    group: u32,
) -> Vec<u8> {
    let [h0, h1] = wire_header(object_id, 4, 5);
    let mut buf = Vec::with_capacity(28);
    push_u32(&mut buf, h0);
    push_u32(&mut buf, h1);
    push_u32(&mut buf, serial);
    push_u32(&mut buf, depressed);
    push_u32(&mut buf, latched);
    push_u32(&mut buf, locked);
    push_u32(&mut buf, group);
    buf
}

// ---------------------------------------------------------------------------
// Wire message parser — for sniffing traffic to learn object IDs & serials
// ---------------------------------------------------------------------------

/// A parsed Wayland wire message (header + raw args).
#[derive(Debug, Clone)]
struct WireMessage {
    object_id: u32,
    opcode: u16,
    /// Raw u32 argument words (NOT including the 2 header words).
    args: Vec<u32>,
    /// Total message size in bytes (including header), as declared in the header.
    size_bytes: u32,
}

/// Parse a single Wayland message from a byte slice.
/// Returns the message and the number of bytes consumed.
/// Returns `None` if the data doesn't contain a complete message.
fn parse_message(data: &[u8]) -> Option<(WireMessage, usize)> {
    if data.len() < 8 {
        return None;
    }
    let object_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let size_opcode = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let size_bytes = size_opcode >> 16;
    let opcode = (size_opcode & 0xFFFF) as u16;

    if !(8..=0x10000).contains(&size_bytes) {
        // Bogus size — skip this message.
        return None;
    }
    let total = size_bytes as usize;
    if data.len() < total {
        return None;
    }

    let arg_words = (total - 8) / 4;
    let mut args = Vec::with_capacity(arg_words);
    for i in 0..arg_words {
        let off = 8 + i * 4;
        args.push(u32::from_le_bytes([
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
        ]));
    }

    Some((
        WireMessage {
            object_id,
            opcode,
            args,
            size_bytes,
        },
        total,
    ))
}

// ---------------------------------------------------------------------------
// Stream sniffer — learns object IDs and serials from wire traffic
// ---------------------------------------------------------------------------

/// What we know about an object discovered on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
enum ObjectKind {
    WlPointer,
    WlKeyboard,
    WlSurface,
    WlSeat,
}

/// Sniffer state: maps object_id → known type, tracks serials and surface.
struct Sniffer {
    /// Known object types (learned from wire traffic).
    objects: std::collections::HashMap<u32, ObjectKind>,
    /// Pointer object ID (if known).
    pointer_id: Option<u32>,
    /// Keyboard object ID (if known).
    keyboard_id: Option<u32>,
    /// Main surface object ID (if known).
    surface_id: Option<u32>,
    /// Seat object ID (if known).
    seat_id: Option<u32>,
    /// Latest serial seen from compositor events.
    last_server_serial: u32,
    /// Pointer version (inferred from traffic).
    pointer_version: u32,
    /// Pending bind: when we see a client request with opcode 0 and 1 arg (new_id),
    /// we record (from_object_id, new_id).  If we then see opcode 1 with 1 arg on
    /// the same from_object_id, that's seat.get_pointer + seat.get_keyboard.
    pending_bind: Option<(u32, u32)>,
}

impl Sniffer {
    fn new() -> Self {
        Self {
            objects: std::collections::HashMap::new(),
            pointer_id: None,
            keyboard_id: None,
            surface_id: None,
            seat_id: None,
            last_server_serial: 0,
            pointer_version: 5,
            pending_bind: None,
        }
    }

    /// Feed a message travelling *from the compositor to the app* (events).
    /// Learn object types from opcode patterns.
    fn feed_server_event(&mut self, msg: &WireMessage) {
        // Track serial from any event that carries one as the first arg.
        // Most Wayland events that carry a serial have it as arg[0].
        if !msg.args.is_empty() {
            self.last_server_serial = self.last_server_serial.max(msg.args[0]);
        }

        match msg.opcode {
            // opcode 2: wl_pointer.motion — uniquely identifies pointer.
            // wl_keyboard has no opcode 2 event (keyboard opcodes: 0=keymap, 1=enter, 2=leave,
            // 3=key, 4=modifiers).  wl_pointer.leave is opcode 1, so opcode 2 is
            // unambiguously wl_pointer.motion.
            2 => {
                self.set_object(msg.object_id, ObjectKind::WlPointer);
            }
            // opcode 5: wl_pointer.frame — uniquely identifies pointer (keyboard has no opcode 5).
            5 => {
                self.set_object(msg.object_id, ObjectKind::WlPointer);
                self.pointer_version = self.pointer_version.max(5);
            }
            // opcode 0 or 1: ambiguous, but we check the size.
            // wl_pointer.enter(serial, surface, x, y) = 4 args = 24 bytes
            // wl_pointer.leave(serial, surface) = 2 args = 16 bytes
            // wl_keyboard.enter(serial, surface, keys) = 3+ args = 20+ bytes (varies with keys)
            // wl_surface.enter(output) = 1 arg = 12 bytes
            // wl_seat.capabilities(caps) = 1 arg = 12 bytes
            // wl_callback.done(data) = 1 arg = 12 bytes
            0 => {
                if msg.size_bytes == 24 {
                    // 8 header + 4×4 args: serial, surface, x, y → wl_pointer.enter
                    self.set_object(msg.object_id, ObjectKind::WlPointer);
                    if msg.args.len() >= 2 {
                        self.set_object(msg.args[1], ObjectKind::WlSurface);
                    }
                } else if msg.size_bytes == 12 && !msg.args.is_empty() && !self.objects.contains_key(&msg.object_id) {
                    // Could be wl_seat.capabilities or wl_callback.done.
                    // If the caps value looks like a valid seat capability mask (bits 0-3),
                    // treat it as a seat.  This is a heuristic; wl_callback.done's data
                    // is client-defined and could be anything.
                    let caps = msg.args[0];
                    // wl_seat.capability bits: pointer=1, keyboard=2, touch=4
                    if caps > 0 && caps <= 7 {
                        self.set_object(msg.object_id, ObjectKind::WlSeat);
                    }
                }
            }
            1 => {
                if msg.size_bytes >= 20 {
                    // wl_keyboard.enter: 8 header + serial(4) + surface(4) +
                    // keys array len(4) + keys data = 20+ bytes.
                    // Distinguish from wl_pointer.leave (size=16).
                    self.set_object(msg.object_id, ObjectKind::WlKeyboard);
                    if msg.args.len() >= 2 {
                        self.set_object(msg.args[1], ObjectKind::WlSurface);
                    }
                }
            }
            // opcode 4: wl_pointer.axis (size=20, 3 args) vs wl_keyboard.modifiers (size=28, 5 args).
            4 => {
                if msg.size_bytes == 20 {
                    self.set_object(msg.object_id, ObjectKind::WlPointer);
                } else if msg.size_bytes == 28 {
                    self.set_object(msg.object_id, ObjectKind::WlKeyboard);
                }
            }
            // opcode 3: can be wl_pointer.button or wl_keyboard.key — indistinguishable by wire
            // alone.  We rely on the object already being identified via other opcodes.
            3 => {
                if !self.objects.contains_key(&msg.object_id)
                    && self.pointer_id.is_some_and(|p| p != msg.object_id)
                {
                    self.set_object(msg.object_id, ObjectKind::WlKeyboard);
                }
            }
            _ => {}
        }
    }

    /// Feed a message travelling *from the app to the compositor* (requests).
    /// Learn object types from request patterns.
    fn feed_client_request(&mut self, msg: &WireMessage) {
        // Seat detection via request patterns:
        // wl_seat.get_pointer: opcode=0, args=[new_id]
        // wl_seat.get_keyboard: opcode=1, args=[new_id]
        // When we see opcode=0 then opcode=1 on the same object (typical for
        // seat.get_pointer followed by seat.get_keyboard), mark it as seat
        // and record the pointer/keyboard IDs.
        if msg.opcode == 0 && !msg.args.is_empty() {
            let new_id = msg.args[0];
            if new_id != 0 {
                self.pending_bind = Some((msg.object_id, new_id));
            }
        } else if msg.opcode == 1 && !msg.args.is_empty() {
            let new_id = msg.args[0];
            if let Some((pending_obj, pending_new_id)) = self.pending_bind.take() {
                if pending_obj == msg.object_id {
                    // Pair: opcode=0 + opcode=1 on same object → likely seat.
                    self.set_object(msg.object_id, ObjectKind::WlSeat);
                    self.set_object(pending_new_id, ObjectKind::WlPointer);
                    self.set_object(new_id, ObjectKind::WlKeyboard);
                } else {
                    // Opcode=1 on a different object — still could be seat.get_keyboard.
                    // Reset pending; we'll try again next time.
                }
            } else {
                // Opcode=1 without prior opcode=0 — could be seat.get_keyboard if
                // we already know the seat from other sources.
                if let Some(&ObjectKind::WlSeat) = self.objects.get(&msg.object_id) {
                    self.set_object(new_id, ObjectKind::WlKeyboard);
                }
            }
        } else {
            // Clear pending bind on any other opcode.
            self.pending_bind = None;
        }

        // Known-seat detection (backup for already-identified seats).
        if let Some(&ObjectKind::WlSeat) = self.objects.get(&msg.object_id) {
            match msg.opcode {
                0 if !msg.args.is_empty() => {
                    self.set_object(msg.args[0], ObjectKind::WlPointer);
                }
                1 if !msg.args.is_empty() => {
                    self.set_object(msg.args[0], ObjectKind::WlKeyboard);
                }
                _ => {}
            }
        }

        // Surface detection: objects that receive commit(opcode=6) or frame(opcode=3)
        // requests are likely wl_surface.
        match msg.opcode {
            3 | 6 => {
                if !self.objects.contains_key(&msg.object_id) {
                    self.set_object(msg.object_id, ObjectKind::WlSurface);
                }
            }
            _ => {}
        }
    }

    /// Record an object's type.  Also updates the convenience fields.
    fn set_object(&mut self, id: u32, kind: ObjectKind) {
        if id == 0 {
            return;
        }
        self.objects.insert(id, kind);
        match kind {
            ObjectKind::WlPointer => {
                self.pointer_id = Some(id);
            }
            ObjectKind::WlKeyboard => {
                self.keyboard_id = Some(id);
            }
            ObjectKind::WlSurface => {
                if self.surface_id.is_none() {
                    self.surface_id = Some(id);
                }
            }
            ObjectKind::WlSeat => {
                self.seat_id = Some(id);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fd discovery — find the Wayland socket in /proc/self/fd
// ---------------------------------------------------------------------------

/// Try to find the Wayland display fd by scanning `/proc/self/fd`.
/// Matches AF_UNIX SOCK_STREAM sockets whose peer is `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`.
fn find_wayland_fd() -> Option<c_int> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let wayland_display = std::env::var_os("WAYLAND_DISPLAY")
        .unwrap_or_else(|| std::ffi::OsString::from("wayland-0"));
    let expected_path = runtime_dir.join(&wayland_display);

    // Read /proc/self/fd to enumerate fds.
    let fd_dir = match std::fs::read_dir("/proc/self/fd") {
        Ok(d) => d,
        Err(_) => return None,
    };

    for entry in fd_dir.flatten() {
        let path = entry.path();
        // The link target is something like "socket:[12345]".
        // We skip the link check — instead we probe the socket directly.

        let fd_str = path.file_name()?.to_str()?.to_string();
        let fd: c_int = fd_str.parse().ok()?;

        // Use getsockopt to check socket type and domain.
        let mut sock_type: libc::c_int = 0;
        let mut type_len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as u32;
        let type_ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                &mut sock_type as *mut _ as *mut c_void,
                &mut type_len,
            )
        };
        if type_ret != 0 || sock_type != libc::SOCK_STREAM {
            continue;
        }

        let mut domain: libc::c_int = 0;
        let mut domain_len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as u32;
        let domain_ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                &mut domain as *mut _ as *mut c_void,
                &mut domain_len,
            )
        };
        if domain_ret != 0 || domain != libc::AF_UNIX {
            continue;
        }

        // For a definitive match, try SO_PEERNAME and compare with the
        // expected compositor socket path.
        if is_socket_peer(fd, &expected_path) {
            return Some(fd);
        }

        // If SO_PEERNAME fails, fall back: if the target has exactly
        // one AF_UNIX SOCK_STREAM socket, use it.
    }

    // Fallback: if we found any AF_UNIX SOCK_STREAM socket, return it.
    // Walk again and collect candidates.
    let candidates: Vec<c_int> = std::fs::read_dir("/proc/self/fd")
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let fd_str = path.file_name()?.to_str()?.to_string();
            let fd: c_int = fd_str.parse().ok()?;
            let mut sock_type: libc::c_int = 0;
            let mut type_len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as u32;
            let type_ret = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    &mut sock_type as *mut _ as *mut c_void,
                    &mut type_len,
                )
            };
            if type_ret != 0 || sock_type != libc::SOCK_STREAM {
                return None;
            }
            let mut domain: libc::c_int = 0;
            let mut domain_len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as u32;
            let domain_ret = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_DOMAIN,
                    &mut domain as *mut _ as *mut c_void,
                    &mut domain_len,
                )
            };
            if domain_ret != 0 || domain != libc::AF_UNIX {
                return None;
            }
            Some(fd)
        })
        .collect();

    if candidates.len() == 1 {
        return Some(candidates[0]);
    }

    None
}

/// Check whether `fd` is connected to the socket at `expected_path`.
fn is_socket_peer(fd: c_int, expected_path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    let expected_bytes = expected_path.as_os_str().as_bytes();
    // Allocate enough space for the sockaddr_un (sun_path is up to 108 bytes).
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut addr_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_un>() as u32;

    let ret = unsafe {
        libc::getpeername(
            fd,
            &mut addr as *mut _ as *mut libc::sockaddr,
            &mut addr_len,
        )
    };
    if ret != 0 {
        return false;
    }

    // addr.sun_family should be AF_UNIX.
    if addr.sun_family as libc::c_int != libc::AF_UNIX {
        return false;
    }

    // sun_path is a c_char array (108 bytes).  Compare with expected path.
    let path_len = expected_bytes.len().min(addr.sun_path.len());
    let actual_path = &addr.sun_path[..path_len];
    // sun_path may be null-padded.  Find the actual length.
    let actual_len = actual_path
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(path_len);
    let actual = &actual_path[..actual_len];

    // Compare bytes (C strings, not necessarily valid UTF-8).
    if actual.len() != expected_bytes.len() {
        return false;
    }
    // Abstract sockets start with '\0'.  Skip those — Wayland uses
    // pathname sockets.
    if actual.first() == Some(&0) {
        return false;
    }
    actual.iter().zip(expected_bytes.iter()).all(|(a, b)| *a as u8 == *b)
}

// ---------------------------------------------------------------------------
// Fd hijack — insert socketpair between the app and compositor
// ---------------------------------------------------------------------------

/// Result of hijacking the Wayland fd.
struct HijackResult {
    /// The real compositor fd (stashed, still connected).
    stash_fd: c_int,
    /// Our end of the socketpair (the app talks to us here).
    ours_fd: c_int,
}

/// Replace the app's Wayland fd with our socketpair.
///
/// 1. `dup(wl_fd)` → stash_fd (preserves compositor connection).
/// 2. `socketpair(AF_UNIX, SOCK_STREAM)` → (ours_fd, theirs_fd).
/// 3. `dup2(theirs_fd, wl_fd)` → app now talks to us on the same fd number.
/// 4. `close(theirs_fd)` — app keeps the duped fd.
///
/// The app stays blocked in `poll()` on wl_fd and doesn't notice the swap.
/// After this, all app↔compositor traffic flows through `stash_fd` ↔ `ours_fd`.
fn hijack_fd(wl_fd: c_int) -> Option<HijackResult> {
    unsafe {
        let stash_fd = libc::dup(wl_fd);
        if stash_fd < 0 {
            return None;
        }

        let mut fds = [-1i32; 2];
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) != 0 {
            libc::close(stash_fd);
            return None;
        }
        let ours_fd = fds[0];
        let theirs_fd = fds[1];

        if libc::dup2(theirs_fd, wl_fd) < 0 {
            libc::close(stash_fd);
            libc::close(ours_fd);
            libc::close(theirs_fd);
            return None;
        }
        libc::close(theirs_fd);

        Some(HijackResult { stash_fd, ours_fd })
    }
}

// ---------------------------------------------------------------------------
// Pump thread — faithful bidirectional forwarding with SCM_RIGHTS
// ---------------------------------------------------------------------------

/// Maximum number of file descriptors we forward per message.
const MAX_CMSG_FDS: usize = 28;

/// Size of the cmsg buffer for `recvmsg`/`sendmsg`.
const CMSG_BUF_SIZE: usize = unsafe {
    libc::CMSG_SPACE((std::mem::size_of::<c_int>() * MAX_CMSG_FDS) as u32) as usize
};

/// Write a complete byte buffer to an fd, looping on short writes.
/// MUST hold `APP_WRITE_LOCK` when writing to `app_fd`.
fn write_all(fd: c_int, buf: &[u8]) -> bool {
    let mut off = 0usize;
    while off < buf.len() {
        let n = unsafe {
            libc::write(fd, buf.as_ptr().add(off) as *const c_void, buf.len() - off)
        };
        if n <= 0 {
            let e = unsafe { *libc::__errno_location() };
            if e == libc::EAGAIN || e == libc::EINTR {
                continue;
            }
            return false;
        }
        off += n as usize;
    }
    true
}

/// Shared state between the pump thread and the IPC injection path.
struct PumpState {
    /// The sniffer, protected by a mutex for access from both pump and IPC.
    sniffer: Mutex<Sniffer>,
    /// Whether keyboard focus (enter) has been sent to the app.
    keyboard_focus_sent: AtomicBool,
    /// Whether pointer focus (enter) has been sent to the app.
    pointer_focus_sent: AtomicBool,
    /// Next serial to use for synthetic input (seeded from server serial).
    next_serial: AtomicU32,
    /// Monotonic time at pump start (used as base for synthetic timestamps).
    time_base_ms: AtomicU32,
    /// Pump thread running flag.
    pump_running: AtomicBool,
    /// App-side fd (ours_fd) — used by both pump and injection, write-serialized.
    app_fd: AtomicI32,
    /// Surface width from configure events (if learned).
    surface_w: AtomicU32,
    /// Surface height from configure events (if learned).
    surface_h: AtomicU32,
    /// Whether wayland fd was found and hijack succeeded.
    hijack_ok: AtomicBool,
}

impl PumpState {
    fn new() -> Self {
        Self {
            sniffer: Mutex::new(Sniffer::new()),
            keyboard_focus_sent: AtomicBool::new(false),
            pointer_focus_sent: AtomicBool::new(false),
            next_serial: AtomicU32::new(1),
            time_base_ms: AtomicU32::new(0),
            pump_running: AtomicBool::new(false),
            app_fd: AtomicI32::new(-1),
            surface_w: AtomicU32::new(0),
            surface_h: AtomicU32::new(0),
            hijack_ok: AtomicBool::new(false),
        }
    }
}

static PUMP_STATE: OnceLock<PumpState> = OnceLock::new();

fn pump_state() -> &'static PumpState {
    PUMP_STATE.get_or_init(PumpState::new)
}

/// App-write lock — ensures pump and injection don't interleave writes
/// to the app fd, which would corrupt the byte stream.
static APP_WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Main pump loop.  Runs in a dedicated thread.
///
/// Forwards all data between `stash_fd` (real compositor) and `ours_fd` (app),
/// using `recvmsg`/`sendmsg` to preserve ancillary `SCM_RIGHTS` fd data.
/// Also sniffs traffic in both directions to learn object IDs and serials.
fn pump_loop(stash_fd: c_int, ours_fd: c_int) {
    let state = pump_state();
    state.pump_running.store(true, Ordering::Release);

    set_nonblocking(stash_fd);
    set_nonblocking(ours_fd);

    let mut data_buf = vec![0u8; 0x10000];
    let mut cmsg_buf = vec![0u8; CMSG_BUF_SIZE];

    let base_ms = monotonic_ms();
    state.time_base_ms.store(base_ms, Ordering::Release);

    let init_serial = state.sniffer.lock().unwrap().last_server_serial + 1;
    state.next_serial.store(init_serial, Ordering::Release);

    loop {
        let mut pollfds = [
            libc::pollfd {
                fd: stash_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: ours_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), 2, 100) };
        if ret < 0 {
            let e = unsafe { *libc::__errno_location() };
            if e == libc::EINTR {
                continue;
            }
            break;
        }

        // compositor → app
        if pollfds[0].revents & libc::POLLIN != 0 {
            let n = recv_msg(stash_fd, &mut data_buf, &mut cmsg_buf);
            if n > 0 {
                sniff_data(&data_buf[..n as usize], Direction::ServerToClient);
                let _lock = APP_WRITE_LOCK.lock().unwrap();
                send_msg(ours_fd, &data_buf[..n as usize], &cmsg_buf);
            } else if n == 0 {
                break;
            }
        }

        // app → compositor
        if pollfds[1].revents & libc::POLLIN != 0 {
            let n = recv_msg(ours_fd, &mut data_buf, &mut cmsg_buf);
            if n > 0 {
                sniff_data(&data_buf[..n as usize], Direction::ClientToServer);
                send_msg(stash_fd, &data_buf[..n as usize], &cmsg_buf);
            } else if n == 0 {
                break;
            }
        }
    }

    state.pump_running.store(false, Ordering::Release);
}

fn set_nonblocking(fd: c_int) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

/// Receive a message with ancillary fd data from `fd`.
/// Returns number of bytes read, or 0 on EOF, or -1 on error (non-fatal).
fn recv_msg(fd: c_int, data_buf: &mut [u8], cmsg_buf: &mut [u8]) -> isize {
    let mut iov = libc::iovec {
        iov_base: data_buf.as_mut_ptr() as *mut c_void,
        iov_len: data_buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = cmsg_buf.len();

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        let e = unsafe { *libc::__errno_location() };
        if e == libc::EAGAIN || e == libc::EINTR {
            return -1;
        }
        return -1;
    }

    n as isize
}

/// Send a message with ancillary fd data to `fd`.
fn send_msg(fd: c_int, data: &[u8], cmsg_buf: &[u8]) -> bool {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut c_void,
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    // Only attach cmsg if there's actual control data.
    let mut cmsg_buf_local: [u8; CMSG_BUF_SIZE] = [0u8; CMSG_BUF_SIZE];
    if !cmsg_buf.is_empty() {
        let copy_len = cmsg_buf.len().min(CMSG_BUF_SIZE);
        cmsg_buf_local[..copy_len].copy_from_slice(&cmsg_buf[..copy_len]);
        msg.msg_control = cmsg_buf_local.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = copy_len;
    }

    let n = unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL) };
    if n < 0 {
        let e = unsafe { *libc::__errno_location() };
        if e == libc::EAGAIN || e == libc::EINTR {
            return true; // Non-fatal, will retry.
        }
        return false;
    }
    n as usize == data.len()
}

/// Which direction the sniffed data is travelling.
#[derive(Debug, Clone, Copy)]
enum Direction {
    ServerToClient,
    ClientToServer,
}

/// Parse all complete messages in `data` and feed them to the sniffer.
fn sniff_data(data: &[u8], direction: Direction) {
    let state = pump_state();
    let mut sniffer = state.sniffer.lock().unwrap();
    let mut offset = 0usize;
    while offset < data.len() {
        if let Some((msg, consumed)) = parse_message(&data[offset..]) {
            match direction {
                Direction::ServerToClient => sniffer.feed_server_event(&msg),
                Direction::ClientToServer => sniffer.feed_client_request(&msg),
            }
            offset += consumed;
        } else {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Wire injection — encode and write synthetic events to the app fd
// ---------------------------------------------------------------------------

/// Inject a keyboard event into the app's read side.
/// Sends `wl_keyboard.enter` first if focus hasn't been established.
fn inject_key(keycode: u32, pressed: bool) -> Result<(), String> {
    let state = pump_state();

    let kbd_id = state
        .sniffer
        .lock()
        .unwrap()
        .keyboard_id
        .ok_or_else(|| "keyboard object not discovered".to_string())?;

    let surface_id = state
        .sniffer
        .lock()
        .unwrap()
        .surface_id
        .ok_or_else(|| "surface object not discovered".to_string())?;

    let time = monotonic_ms() - state.time_base_ms.load(Ordering::Relaxed);

    let _lock = APP_WRITE_LOCK.lock().unwrap();

    // Send enter before first key if not yet focused.
    if !state.keyboard_focus_sent.swap(true, Ordering::SeqCst) {
        let serial = next_inject_serial();
        let enter = encode_keyboard_enter(kbd_id, serial, surface_id, &[]);
        if !write_all(state.app_fd.load(Ordering::Relaxed), &enter) {
            return Err("write keyboard.enter failed".to_string());
        }
    }

    let serial = next_inject_serial();
    let state_code: u32 = if pressed { 1 } else { 0 };
    let key_msg = encode_keyboard_key(kbd_id, serial, time, keycode, state_code);
    if !write_all(state.app_fd.load(Ordering::Relaxed), &key_msg) {
        return Err("write keyboard.key failed".to_string());
    }

    Ok(())
}

/// Inject a keyboard modifiers change.
fn inject_modifiers(depressed: u32) -> Result<(), String> {
    let state = pump_state();

    let kbd_id = state
        .sniffer
        .lock()
        .unwrap()
        .keyboard_id
        .ok_or_else(|| "keyboard object not discovered".to_string())?;

    let serial = next_inject_serial();
    let msg = encode_keyboard_modifiers(kbd_id, serial, depressed, 0, 0, 0);

    let _lock = APP_WRITE_LOCK.lock().unwrap();
    if !write_all(state.app_fd.load(Ordering::Relaxed), &msg) {
        return Err("write keyboard.modifiers failed".to_string());
    }

    Ok(())
}

/// Inject a pointer motion event.
fn inject_pointer_move(x: f64, y: f64) -> Result<(), String> {
    let state = pump_state();

    let ptr_id = state
        .sniffer
        .lock()
        .unwrap()
        .pointer_id
        .ok_or_else(|| "pointer object not discovered".to_string())?;

    let surface_id = state
        .sniffer
        .lock()
        .unwrap()
        .surface_id
        .ok_or_else(|| "surface object not discovered".to_string())?;

    let time = monotonic_ms() - state.time_base_ms.load(Ordering::Relaxed);

    let _lock = APP_WRITE_LOCK.lock().unwrap();

    // Send enter before first motion if not yet focused.
    if !state.pointer_focus_sent.swap(true, Ordering::SeqCst) {
        let serial = next_inject_serial();
        let enter = encode_pointer_enter(ptr_id, serial, surface_id, x, y);
        if !write_all(state.app_fd.load(Ordering::Relaxed), &enter) {
            return Err("write pointer.enter failed".to_string());
        }
    }

    let motion = encode_pointer_motion(ptr_id, time, x, y);
    if !write_all(state.app_fd.load(Ordering::Relaxed), &motion) {
        return Err("write pointer.motion failed".to_string());
    }

    Ok(())
}

/// Inject a pointer button event.
fn inject_pointer_button(button: u32, pressed: bool) -> Result<(), String> {
    let state = pump_state();

    let ptr_id = state
        .sniffer
        .lock()
        .unwrap()
        .pointer_id
        .ok_or_else(|| "pointer object not discovered".to_string())?;

    let surface_id = state
        .sniffer
        .lock()
        .unwrap()
        .surface_id
        .ok_or_else(|| "surface object not discovered".to_string())?;

    let time = monotonic_ms() - state.time_base_ms.load(Ordering::Relaxed);

    let _lock = APP_WRITE_LOCK.lock().unwrap();

    // Send enter before first button if not yet focused.
    if !state.pointer_focus_sent.swap(true, Ordering::SeqCst) {
        let serial = next_inject_serial();
        let enter = encode_pointer_enter(ptr_id, serial, surface_id, 0.0, 0.0);
        if !write_all(state.app_fd.load(Ordering::Relaxed), &enter) {
            return Err("write pointer.enter failed".to_string());
        }
    }

    let serial = next_inject_serial();
    let state_code: u32 = if pressed { 1 } else { 0 };
    let btn_msg = encode_pointer_button(ptr_id, serial, time, button, state_code);
    if !write_all(state.app_fd.load(Ordering::Relaxed), &btn_msg) {
        return Err("write pointer.button failed".to_string());
    }

    // Always emit frame after button events (v5+).
    let frame = encode_pointer_frame(ptr_id);
    if !write_all(state.app_fd.load(Ordering::Relaxed), &frame) {
        return Err("write pointer.frame failed".to_string());
    }

    Ok(())
}

/// Inject a pointer axis (scroll) event.
fn inject_pointer_axis(axis: u32, value: f64) -> Result<(), String> {
    let state = pump_state();

    let ptr_id = state
        .sniffer
        .lock()
        .unwrap()
        .pointer_id
        .ok_or_else(|| "pointer object not discovered".to_string())?;

    let surface_id = state
        .sniffer
        .lock()
        .unwrap()
        .surface_id
        .ok_or_else(|| "surface object not discovered".to_string())?;

    let time = monotonic_ms() - state.time_base_ms.load(Ordering::Relaxed);

    let _lock = APP_WRITE_LOCK.lock().unwrap();

    // Send enter before first scroll if not yet focused.
    if !state.pointer_focus_sent.swap(true, Ordering::SeqCst) {
        let serial = next_inject_serial();
        let enter = encode_pointer_enter(ptr_id, serial, surface_id, 0.0, 0.0);
        if !write_all(state.app_fd.load(Ordering::Relaxed), &enter) {
            return Err("write pointer.enter failed".to_string());
        }
    }

    let axis_msg = encode_pointer_axis(ptr_id, time, axis, value);
    if !write_all(state.app_fd.load(Ordering::Relaxed), &axis_msg) {
        return Err("write pointer.axis failed".to_string());
    }

    let frame = encode_pointer_frame(ptr_id);
    if !write_all(state.app_fd.load(Ordering::Relaxed), &frame) {
        return Err("write pointer.frame failed".to_string());
    }

    Ok(())
}

/// Get the next synthetic serial, atomically incrementing.
fn next_inject_serial() -> u32 {
    pump_state().next_serial.fetch_add(1, Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Helpers — math, time, JSON
// ---------------------------------------------------------------------------

fn to_fixed(v: f64) -> i32 {
    (v * 256.0).round() as i32
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
    #[serde(default)]
    axis: Option<u32>,
    #[serde(default)]
    value: Option<f64>,
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
            r#"{"type":"hello_ack","protocol_version":1,"payload_version":"0.3.0"}"#.to_string(),
        ),
        "mouse_move" => {
            let x = req.x.unwrap_or(0.0);
            let y = req.y.unwrap_or(0.0);
            match inject_pointer_move(x, y) {
                Ok(()) => HandleResult::Response(make_ok()),
                Err(e) => HandleResult::Response(make_error("inject_failed", &e)),
            }
        }
        "mouse_button" => {
            let button = req.button.unwrap_or(0);
            let pressed = parse_state(&req.state.unwrap_or_default()) == 1;
            match inject_pointer_button(button, pressed) {
                Ok(()) => HandleResult::Response(make_ok()),
                Err(e) => HandleResult::Response(make_error("inject_failed", &e)),
            }
        }
        "key" => {
            let key = req.key.unwrap_or(0);
            let pressed = parse_state(&req.state.unwrap_or_default()) == 1;
            match inject_key(key, pressed) {
                Ok(()) => HandleResult::Response(make_ok()),
                Err(e) => HandleResult::Response(make_error("inject_failed", &e)),
            }
        }
        "modifiers" => {
            let depressed = req.depressed.unwrap_or(0);
            match inject_modifiers(depressed) {
                Ok(()) => HandleResult::Response(make_ok()),
                Err(e) => HandleResult::Response(make_error("inject_failed", &e)),
            }
        }
        "scroll" => {
            let axis = req.axis.unwrap_or(0);
            let amount = req.value.unwrap_or(0.0);
            match inject_pointer_axis(axis, amount) {
                Ok(()) => HandleResult::Response(make_ok()),
                Err(e) => HandleResult::Response(make_error("inject_failed", &e)),
            }
        }
        "surface_size" => {
            let state = pump_state();
            let w = state.surface_w.load(Ordering::Acquire);
            let h = state.surface_h.load(Ordering::Acquire);
            if w == 0 && h == 0 {
                return HandleResult::Response(make_error_with_kind(
                    "proxy_not_found",
                    "surface dimensions not captured yet",
                    "xdg_toplevel",
                ));
            }
            HandleResult::Response(format!(r#"{{"status":"ok","width":{},"height":{}}}"#, w, h))
        }
        "status" => {
            let state = pump_state();
            let sniffer = state.sniffer.lock().unwrap();
            HandleResult::Response(format!(
                r#"{{"status":"ok","pump_running":{},"pointer_id":{},"keyboard_id":{},"surface_id":{},"server_serial":{},"inject_serial":{},"hijack_ok":{}}}"#,
                state.pump_running.load(Ordering::Acquire),
                sniffer.pointer_id.map_or("null".to_string(), |id| id.to_string()),
                sniffer.keyboard_id.map_or("null".to_string(), |id| id.to_string()),
                sniffer.surface_id.map_or("null".to_string(), |id| id.to_string()),
                sniffer.last_server_serial,
                state.next_serial.load(Ordering::Relaxed),
                state.hijack_ok.load(Ordering::Relaxed),
            ))
        }
        "unload" => HandleResult::Unload,
        _ => HandleResult::Response(make_error("unknown_command", &req.ty)),
    }
}

fn make_ok() -> String {
    r#"{"status":"ok"}"#.to_string()
}

fn make_error(code: &str, message: &str) -> String {
    let mut m = serde_json::Map::new();
    m.insert("status".to_string(), serde_json::Value::String("error".to_string()));
    m.insert("code".to_string(), serde_json::Value::String(code.to_string()));
    m.insert(
        "message".to_string(),
        serde_json::Value::String(message.to_string()),
    );
    serde_json::to_string(&m).unwrap()
}

fn make_error_with_kind(code: &str, message: &str, kind: &str) -> String {
    let mut m = serde_json::Map::new();
    m.insert("status".to_string(), serde_json::Value::String("error".to_string()));
    m.insert("code".to_string(), serde_json::Value::String(code.to_string()));
    m.insert(
        "message".to_string(),
        serde_json::Value::String(message.to_string()),
    );
    m.insert(
        "kind".to_string(),
        serde_json::Value::String(kind.to_string()),
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

static BACKSEAT_SOCK_PATH: OnceLock<PathBuf> = OnceLock::new();
static G_HOST_PID: AtomicU32 = AtomicU32::new(0);
static IPC_THREAD_STARTED: AtomicBool = AtomicBool::new(false);
static PROBE_FAILED: AtomicBool = AtomicBool::new(false);

fn ipc_thread() {
    let pid = unsafe { libc::getpid() };

    let sock_path = BACKSEAT_SOCK_PATH
        .get()
        .cloned()
        .unwrap_or_else(|| runtime_dir().join(format!("backseat-{}.sock", pid)));

    let sock_path_cstring =
        std::ffi::CString::new(sock_path.to_string_lossy().as_bytes()).unwrap();
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

    // Enable SO_PASSCRED for peer credential verification.
    unsafe {
        let one: libc::c_int = 1;
        libc::setsockopt(
            listener.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    let (stream, _) = match listener.accept() {
        Ok(v) => v,
        Err(_) => {
            IPC_THREAD_STARTED.store(false, Ordering::SeqCst);
            return;
        }
    };

    // Verify the connecting peer's PID.
    let host_pid = G_HOST_PID.load(Ordering::Acquire);
    if host_pid != 0 {
        let mut cred: libc::ucred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut cred_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut cred_len,
            )
        };
        if ret != 0 || cred.pid != host_pid as libc::pid_t {
            IPC_THREAD_STARTED.store(false, Ordering::SeqCst);
            return;
        }
    }

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
    IPC_THREAD_STARTED.store(false, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

/// Runtime probe — verify the target has libwayland loaded.
unsafe fn probe_libwayland() -> bool {
    let sym = libc::dlsym(
        libc::RTLD_DEFAULT,
        c"wl_proxy_get_version".as_ptr() as *const c_char,
    );
    !sym.is_null()
}

#[used]
#[link_section = ".init_array"]
static CONSTRUCTOR: extern "C" fn() = init;

extern "C" fn init() {
    unsafe {
        if !probe_libwayland() {
            PROBE_FAILED.store(true, Ordering::Release);
        }
    }
}

/// Host-visible entry point. Receives the Unix-socket path and starts
/// the fd hijack, pump thread, and IPC thread.
///
/// # Safety
/// `path` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn backseat_init(path: *const c_char) {
    if !path.is_null() {
        let cstr = CStr::from_ptr(path);
        if let Ok(s) = cstr.to_str() {
            let _ = BACKSEAT_SOCK_PATH.set(PathBuf::from(s));
        }
        let host_pid_ptr = path.add(cstr.to_bytes_with_nul().len()).cast::<u32>();
        G_HOST_PID.store(host_pid_ptr.read_unaligned(), Ordering::SeqCst);
    }

    if PROBE_FAILED.load(Ordering::Acquire) {
        return;
    }

    if IPC_THREAD_STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        // Find and hijack the Wayland fd.
        let state = pump_state();
        if let Some(wl_fd) = find_wayland_fd() {
            if let Some(hijack) = hijack_fd(wl_fd) {
                state.app_fd.store(hijack.ours_fd, Ordering::Release);
                state.hijack_ok.store(true, Ordering::Release);

                // Spawn pump thread.
                let stash_fd = hijack.stash_fd;
                let ours_fd = hijack.ours_fd;
                let mut pump_tid: libc::pthread_t = 0;
                extern "C" fn pump_wrapper(arg: *mut c_void) -> *mut c_void {
                    let fds: &(c_int, c_int) = unsafe { &*(arg as *const (c_int, c_int)) };
                    pump_loop(fds.0, fds.1);
                    std::ptr::null_mut()
                }
                let fds = Box::new((stash_fd, ours_fd));
                let ret = libc::pthread_create(
                    &mut pump_tid,
                    std::ptr::null(),
                    pump_wrapper,
                    Box::into_raw(fds) as *mut c_void,
                );
                if ret != 0 {
                    // Pump failed — still start IPC for graceful error reporting.
                }
                libc::pthread_detach(pump_tid);
            }
        }

        // Spawn IPC thread.
        let mut tid: libc::pthread_t = 0;
        extern "C" fn ipc_thread_wrapper(_arg: *mut c_void) -> *mut c_void {
            ipc_thread();
            std::ptr::null_mut()
        }
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn monotonic_ms_is_monotonic() {
        let a = monotonic_ms();
        let b = monotonic_ms();
        assert!(b >= a, "monotonic_ms went backwards: {a} -> {b}");
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
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["status"], "ok");
    }

    #[test]
    fn make_error_produces_valid_json() {
        let json = make_error("proxy_not_found", "no pointer");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["status"], "error");
        assert_eq!(v["code"], "proxy_not_found");
        assert_eq!(v["message"], "no pointer");
    }

    #[test]
    fn make_error_roundtrips_with_host_response() {
        let json = make_error("bad_cmd", "test message");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("status").is_some());
        assert!(v.get("code").is_some());
        assert!(v.get("message").is_some());
    }

    // -----------------------------------------------------------------------
    // Wire message header encoding
    // -----------------------------------------------------------------------

    #[test]
    fn wire_header_basic() {
        let [id, sop] = wire_header(42, 3, 4);
        assert_eq!(id, 42);
        // total_size = 8 + 4*4 = 24 bytes
        // size_opcode = (24 << 16) | 3 = 0x0018_0003
        assert_eq!(sop, (24 << 16) | 3);
    }

    #[test]
    fn wire_header_zero_args() {
        let [id, sop] = wire_header(1, 5, 0);
        assert_eq!(id, 1);
        // total_size = 8 + 0 = 8
        // size_opcode = (8 << 16) | 5 = 0x0008_0005
        assert_eq!(sop, (8 << 16) | 5);
    }

    // -----------------------------------------------------------------------
    // Encoder round-trip tests (AC6)
    // -----------------------------------------------------------------------

    /// Parse a complete message from a byte buffer and return field values
    /// for verification.
    fn parse_encoded(bytes: &[u8]) -> (u32, u16, u32, Vec<u32>) {
        let (msg, _) = parse_message(bytes).expect("should parse encoded message");
        (msg.object_id, msg.opcode, msg.size_bytes, msg.args)
    }

    #[test]
    fn encode_roundtrip_pointer_motion() {
        let bytes = encode_pointer_motion(7, 1000, 12.5, -3.25);
        let (id, opcode, size, args) = parse_encoded(&bytes);
        assert_eq!(id, 7);
        assert_eq!(opcode, 2);
        assert_eq!(size, 20);
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], 1000); // time
        assert_eq!(args[1] as i32, to_fixed(12.5)); // x in wl_fixed
        assert_eq!(args[2] as i32, to_fixed(-3.25)); // y in wl_fixed
    }

    #[test]
    fn encode_roundtrip_pointer_button() {
        let bytes = encode_pointer_button(7, 123, 500, 0x110, 1);
        let (id, opcode, size, args) = parse_encoded(&bytes);
        assert_eq!(id, 7);
        assert_eq!(opcode, 3);
        assert_eq!(size, 24);
        assert_eq!(args.len(), 4);
        assert_eq!(args[0], 123); // serial
        assert_eq!(args[1], 500); // time
        assert_eq!(args[2], 0x110); // button (BTN_LEFT)
        assert_eq!(args[3], 1); // state (pressed)
    }

    #[test]
    fn encode_roundtrip_pointer_axis() {
        let bytes = encode_pointer_axis(7, 2000, 0, 10.0);
        let (id, opcode, size, args) = parse_encoded(&bytes);
        assert_eq!(id, 7);
        assert_eq!(opcode, 4);
        assert_eq!(size, 20);
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], 2000); // time
        assert_eq!(args[1], 0); // axis = vertical
        assert_eq!(args[2] as i32, to_fixed(10.0)); // value in wl_fixed
    }

    #[test]
    fn encode_roundtrip_pointer_frame() {
        let bytes = encode_pointer_frame(7);
        let (id, opcode, size, args) = parse_encoded(&bytes);
        assert_eq!(id, 7);
        assert_eq!(opcode, 5);
        assert_eq!(size, 8);
        assert_eq!(args.len(), 0);
    }

    #[test]
    fn encode_roundtrip_pointer_enter() {
        let bytes = encode_pointer_enter(7, 1, 5, 100.0, 200.0);
        let (id, opcode, size, args) = parse_encoded(&bytes);
        assert_eq!(id, 7);
        assert_eq!(opcode, 0);
        assert_eq!(size, 24);
        assert_eq!(args.len(), 4);
        assert_eq!(args[0], 1); // serial
        assert_eq!(args[1], 5); // surface
        assert_eq!(args[2] as i32, to_fixed(100.0)); // x
        assert_eq!(args[3] as i32, to_fixed(200.0)); // y
    }

    #[test]
    fn encode_roundtrip_keyboard_key() {
        let bytes = encode_keyboard_key(8, 42, 3000, 30, 1);
        let (id, opcode, size, args) = parse_encoded(&bytes);
        assert_eq!(id, 8);
        assert_eq!(opcode, 3);
        assert_eq!(size, 24);
        assert_eq!(args.len(), 4);
        assert_eq!(args[0], 42); // serial
        assert_eq!(args[1], 3000); // time
        assert_eq!(args[2], 30); // key (KEY_A)
        assert_eq!(args[3], 1); // state (pressed)
    }

    #[test]
    fn encode_roundtrip_keyboard_modifiers() {
        let bytes = encode_keyboard_modifiers(8, 55, 0x01, 0, 0, 0);
        let (id, opcode, size, args) = parse_encoded(&bytes);
        assert_eq!(id, 8);
        assert_eq!(opcode, 4);
        assert_eq!(size, 28);
        assert_eq!(args.len(), 5);
        assert_eq!(args[0], 55); // serial
        assert_eq!(args[1], 0x01); // depressed
        assert_eq!(args[2], 0); // latched
        assert_eq!(args[3], 0); // locked
        assert_eq!(args[4], 0); // group
    }

    #[test]
    fn encode_roundtrip_keyboard_enter_empty_keys() {
        // Enter with empty keys array — the test verifies the array
        // padding is correct (4 bytes for the empty array length).
        let bytes = encode_keyboard_enter(8, 1, 5, &[]);
        let (id, opcode, size, args) = parse_encoded(&bytes);
        assert_eq!(id, 8);
        assert_eq!(opcode, 1);
        // 8 header + serial(4) + surface(4) + array_len(4) + 0 array data = 20 bytes
        assert_eq!(size, 20);
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], 1); // serial
        assert_eq!(args[1], 5); // surface
        assert_eq!(args[2], 0); // keys array length = 0
    }

    #[test]
    fn encode_roundtrip_keyboard_enter_with_keys() {
        // Enter with keys [30, 31] (key A and key S).
        let bytes = encode_keyboard_enter(8, 1, 5, &[30, 31]);
        let (id, opcode, size, args) = parse_encoded(&bytes);
        assert_eq!(id, 8);
        assert_eq!(opcode, 1);
        // 8 header + serial(4) + surface(4) + array_len(4) + 2*4 keys = 28 bytes
        assert_eq!(size, 28);
        assert_eq!(args.len(), 5);
        assert_eq!(args[0], 1); // serial
        assert_eq!(args[1], 5); // surface
        assert_eq!(args[2], 8); // keys array length = 2 u32 = 8 bytes
        assert_eq!(args[3], 30); // first key
        assert_eq!(args[4], 31); // second key
    }

    #[test]
    fn encode_roundtrip_keyboard_leave() {
        let bytes = encode_keyboard_leave(8, 1, 5);
        let (id, opcode, size, args) = parse_encoded(&bytes);
        assert_eq!(id, 8);
        assert_eq!(opcode, 2);
        assert_eq!(size, 16);
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], 1); // serial
        assert_eq!(args[1], 5); // surface
    }

    #[test]
    fn encode_roundtrip_pointer_leave() {
        let bytes = encode_pointer_leave(7, 1, 5);
        let (id, opcode, size, args) = parse_encoded(&bytes);
        assert_eq!(id, 7);
        assert_eq!(opcode, 1);
        assert_eq!(size, 16);
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], 1); // serial
        assert_eq!(args[1], 5); // surface
    }

    // -----------------------------------------------------------------------
    // wl_fixed round-trip in encoder
    // -----------------------------------------------------------------------

    #[test]
    fn wl_fixed_roundtrip_in_encoder() {
        // Verify that wl_fixed values survive encode → parse round-trip.
        let test_values = [0.0, 1.0, -1.0, 0.5, -0.5, 100.25, -99.75, 3.14159];
        for &val in &test_values {
            let bytes = encode_pointer_motion(1, 0, val, val);
            let (_, _, _, args) = parse_encoded(&bytes);
            assert_eq!(
                args[1] as i32,
                to_fixed(val),
                "wl_fixed round-trip failed for {val}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Wire message parser
    // -----------------------------------------------------------------------

    #[test]
    fn parse_message_complete() {
        let bytes = encode_pointer_motion(5, 100, 1.0, 2.0);
        let (msg, consumed) = parse_message(&bytes).unwrap();
        assert_eq!(msg.object_id, 5);
        assert_eq!(msg.opcode, 2);
        assert_eq!(consumed, 20);
    }

    #[test]
    fn parse_message_incomplete() {
        // Only 4 bytes — not enough for a header.
        assert!(parse_message(&[0u8; 4]).is_none());
        // Header only (8 bytes) with declared size 24 — not enough data.
        let mut buf = Vec::new();
        push_u32(&mut buf, 5); // object_id
        push_u32(&mut buf, (24 << 16) | 2); // size_opcode
        assert!(parse_message(&buf).is_none());
    }

    #[test]
    fn parse_message_zero_args() {
        let bytes = encode_pointer_frame(7);
        let (msg, consumed) = parse_message(&bytes).unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(msg.args.len(), 0);
        assert_eq!(msg.opcode, 5);
    }

    #[test]
    fn parse_message_multiple_in_buffer() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&encode_pointer_frame(1));
        buf.extend_from_slice(&encode_pointer_motion(1, 500, 10.0, 20.0));

        // Parse first message.
        let (msg1, consumed1) = parse_message(&buf).unwrap();
        assert_eq!(consumed1, 8);
        assert_eq!(msg1.opcode, 5);

        // Parse second message.
        let (msg2, consumed2) = parse_message(&buf[consumed1..]).unwrap();
        assert_eq!(consumed2, 20);
        assert_eq!(msg2.opcode, 2);
    }

    // -----------------------------------------------------------------------
    // Sniffer — object identification
    // -----------------------------------------------------------------------

    #[test]
    fn sniffer_identifies_pointer_from_motion() {
        let mut s = Sniffer::new();
        let msg = WireMessage {
            object_id: 7,
            opcode: 2,
            args: vec![1000, to_fixed(10.0) as u32, to_fixed(20.0) as u32],
            size_bytes: 20,
        };
        s.feed_server_event(&msg);
        assert_eq!(s.pointer_id, Some(7));
        assert_eq!(s.objects.get(&7), Some(&ObjectKind::WlPointer));
    }

    #[test]
    fn sniffer_identifies_keyboard_from_modifiers() {
        let mut s = Sniffer::new();
        let msg = WireMessage {
            object_id: 8,
            opcode: 4,
            args: vec![1, 0, 0, 0, 0],
            size_bytes: 28,
        };
        s.feed_server_event(&msg);
        assert_eq!(s.keyboard_id, Some(8));
        assert_eq!(s.objects.get(&8), Some(&ObjectKind::WlKeyboard));
    }

    #[test]
    fn sniffer_identifies_surface_from_pointer_enter() {
        let mut s = Sniffer::new();
        let msg = WireMessage {
            object_id: 7,
            opcode: 0,
            args: vec![1, 5, to_fixed(0.0) as u32, to_fixed(0.0) as u32],
            size_bytes: 24,
        };
        s.feed_server_event(&msg);
        assert_eq!(s.surface_id, Some(5));
        assert_eq!(s.objects.get(&5), Some(&ObjectKind::WlSurface));
        assert_eq!(s.pointer_id, Some(7));
    }

    #[test]
    fn sniffer_tracks_server_serial() {
        let mut s = Sniffer::new();
        let msg = WireMessage {
            object_id: 7,
            opcode: 0,
            args: vec![42, 5, 0, 0],
            size_bytes: 24,
        };
        s.feed_server_event(&msg);
        assert_eq!(s.last_server_serial, 42);
    }

    #[test]
    fn sniffer_identifies_surface_from_keyboard_enter() {
        let mut s = Sniffer::new();
        let msg = WireMessage {
            object_id: 8,
            opcode: 1,
            args: vec![1, 5, 0],
            size_bytes: 20,
        };
        s.feed_server_event(&msg);
        assert_eq!(s.surface_id, Some(5));
        assert_eq!(s.keyboard_id, Some(8));
    }

    // -----------------------------------------------------------------------
    // handle_request
    // -----------------------------------------------------------------------

    #[test]
    fn handle_hello() {
        match handle_request(r#"{"type":"hello"}"#) {
            HandleResult::Response(resp) => {
                let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
                assert_eq!(v["type"], "hello_ack");
                assert_eq!(v["protocol_version"], 1);
                assert!(v.get("payload_version").is_some());
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn handle_unload_returns_unload_variant() {
        match handle_request(r#"{"type":"unload"}"#) {
            HandleResult::Unload => {}
            other => panic!("expected Unload, got {other:?}"),
        }
    }

    #[test]
    fn handle_malformed_json() {
        match handle_request("not json at all") {
            HandleResult::Response(resp) => {
                let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
                assert_eq!(v["status"], "error");
                assert_eq!(v["code"], "invalid_json");
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn handle_unknown_command() {
        match handle_request(r#"{"type":"nonexistent_cmd"}"#) {
            HandleResult::Response(resp) => {
                let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
                assert_eq!(v["status"], "error");
                assert_eq!(v["code"], "unknown_command");
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn handle_status_reports_state() {
        // Set up minimal state for the status check.
        let state = pump_state();
        state.pump_running.store(true, Ordering::Release);
        state.hijack_ok.store(true, Ordering::Release);
        {
            let mut s = state.sniffer.lock().unwrap();
            s.set_object(7, ObjectKind::WlPointer);
            s.set_object(8, ObjectKind::WlKeyboard);
            s.set_object(5, ObjectKind::WlSurface);
        }
        state.next_serial.store(100, Ordering::Release);

        match handle_request(r#"{"type":"status"}"#) {
            HandleResult::Response(resp) => {
                let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
                assert_eq!(v["status"], "ok");
                assert_eq!(v["pump_running"], true);
                assert_eq!(v["pointer_id"], "7");
                assert_eq!(v["keyboard_id"], "8");
                assert_eq!(v["surface_id"], "5");
                assert_eq!(v["hijack_ok"], true);
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn handle_surface_size_without_data() {
        match handle_request(r#"{"type":"surface_size"}"#) {
            HandleResult::Response(resp) => {
                let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
                assert_eq!(v["status"], "error");
                assert_eq!(v["code"], "proxy_not_found");
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn handle_surface_size_with_data() {
        let state = pump_state();
        state.surface_w.store(1920, Ordering::Release);
        state.surface_h.store(1080, Ordering::Release);
        match handle_request(r#"{"type":"surface_size"}"#) {
            HandleResult::Response(resp) => {
                let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
                assert_eq!(v["status"], "ok");
                assert_eq!(v["width"], 1920);
                assert_eq!(v["height"], 1080);
            }
            other => panic!("expected Response, got {other:?}"),
        }
        state.surface_w.store(0, Ordering::Release);
        state.surface_h.store(0, Ordering::Release);
    }
}
