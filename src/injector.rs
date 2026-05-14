//! ptrace-based injection engine.
//!
//! This module handles:
//!
//! 1. **Process lookup** — scanning `/proc` to resolve a process name to a PID.
//! 2. **libc resolution** — reusing the `proc-maps` output to locate libc,
//!    then parsing the on-disk ELF to find the virtual address of `dlopen`.
//! 3. **Shellcode injection** — writing a short x86-64 stub into an
//!    executable region of the target and executing it via ptrace.
//! 4. **ptrace flow** — attach, save registers, execute stub, read result,
//!    restore state, detach.

#[cfg(not(target_arch = "x86_64"))]
compile_error!("backseat only supports x86_64 Linux");

use std::path::Path;

use goblin::Object;
use pete::{Ptracer, Restart, Stop};

use crate::error::Error;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Inject the payload shared library into `pid`.
///
/// # Overview
///
/// 1. Attach via `pete::Ptracer` and wait for `SIGSTOP`.
/// 2. Save all registers.
/// 3. Find an executable scratch region via `proc-maps`.
/// 4. Resolve `dlopen` address via ELF parsing.
/// 5. Write the payload path and shellcode into the scratch region
///    (`ptrace` writes bypass page permissions).
/// 6. Set `RIP` to the shellcode and continue.
/// 7. Wait for `SIGTRAP` (the stub ends with `int3`).
/// 8. Read `RAX` — if zero, `dlopen` failed.
/// 9. Restore original bytes and registers, detach.
///
/// # Errors
///
/// Returns structured errors for every failure mode (permission denied,
/// dlopen returning null, ptrace errors, etc.).
pub fn inject_payload(pid: u32, payload_path: &Path, socket_path: &str) -> Result<(), Error> {
    let mut ptracer = Ptracer::new();

    // 1. Attach
    ptracer
        .attach(pete::Pid::from_raw(pid as i32))
        .map_err(|e| {
            if let pete::error::Error::Attach { source, .. } = &e {
                let msg = format!("{source}");
                if msg.contains("EPERM") || msg.contains("EACCES") {
                    return Error::PermissionDenied(pid);
                }
            }
            Error::PayloadExtractFailed(format!("ptrace attach: {e}"))
        })?;

    let tracee = ptracer
        .wait()
        .map_err(|e| Error::PayloadExtractFailed(format!("ptrace wait: {e}")))?
        .ok_or_else(|| Error::PayloadExtractFailed("ptrace attach: no tracee".into()))?;

    // The initial stop after attach is either the explicit SIGSTOP or
    // pete's `Stop::Attach` variant (depending on kernel / pete version).
    let got_attach = matches!(
        tracee.stop,
        Stop::SignalDelivery { signal } if signal == pete::Signal::SIGSTOP
    ) || matches!(tracee.stop, Stop::Attach);
    if !got_attach {
        return Err(Error::UnexpectedWaitStatus {
            pid,
            op: crate::error::PtraceOp::Attach,
            status: format!("{:?}", tracee.stop),
        });
    }

    // 2. Save registers
    let mut tracee = tracee;
    let orig_regs = tracee
        .registers()
        .map_err(|e| Error::PayloadExtractFailed(format!("getregs: {e}")))?;

    // 3. Find an executable scratch region
    let maps = proc_maps::get_process_maps(pid as i32)
        .map_err(|e| Error::PayloadExtractFailed(format!("proc_maps: {e}")))?;

    let scratch = maps
        .iter()
        .find(|m| m.is_exec() && m.size() >= 512)
        .map(|m| {
            let start = m.start() as u64;
            // Skip past any function entry point at the very start.
            start + 0x10
        })
        .ok_or_else(|| Error::PayloadExtractFailed("no executable scratch region".into()))?;

    // 4. Resolve dlopen and dlsym (reuse the same parsed maps)
    let dlopen_addr = resolve_symbol(pid, &maps, "dlopen")
        .or_else(|| resolve_symbol(pid, &maps, "__libc_dlopen_mode"))
        .ok_or(Error::LibcResolutionFailed { pid })?;
    let dlsym_addr = resolve_symbol(pid, &maps, "dlsym")
        .or_else(|| resolve_symbol(pid, &maps, "__libc_dlsym"))
        .ok_or(Error::LibcResolutionFailed { pid })?;

    // 5. Write strings and shellcode to scratch area
    let payload_cstring = std::ffi::CString::new(payload_path.as_os_str().as_encoded_bytes())
        .map_err(|_| Error::PayloadExtractFailed("invalid payload path".into()))?;
    let payload_bytes = payload_cstring.as_bytes_with_nul();

    let socket_cstring = std::ffi::CString::new(socket_path)
        .map_err(|_| Error::PayloadExtractFailed("invalid socket path".into()))?;
    let socket_bytes = socket_cstring.as_bytes_with_nul();

    let symbol_name = b"backseat_init\0";

    let host_pid = std::process::id();
    let host_pid_bytes: [u8; 4] = host_pid.to_ne_bytes();

    let payload_addr = scratch;
    let socket_addr = payload_addr + ((payload_bytes.len() + 7) & !7) as u64;
    let host_pid_addr = socket_addr + socket_bytes.len() as u64;
    let symbol_addr = (host_pid_addr + std::mem::size_of::<u32>() as u64 + 7) & !7;
    let code_addr = symbol_addr + ((symbol_name.len() + 7) & !7) as u64;

    let shellcode = make_shellcode(
        dlopen_addr,
        dlsym_addr,
        payload_addr,
        socket_addr,
        symbol_addr,
    );

    // Remember original bytes so we can restore them later.
    let orig_payload = tracee
        .read_memory(payload_addr, payload_bytes.len())
        .map_err(|e| Error::PayloadExtractFailed(format!("read payload bytes: {e}")))?;
    let orig_socket = tracee
        .read_memory(socket_addr, socket_bytes.len())
        .map_err(|e| Error::PayloadExtractFailed(format!("read socket bytes: {e}")))?;
    let orig_host_pid = tracee
        .read_memory(host_pid_addr, std::mem::size_of::<u32>())
        .map_err(|e| Error::PayloadExtractFailed(format!("read host pid bytes: {e}")))?;
    let orig_symbol = tracee
        .read_memory(symbol_addr, symbol_name.len())
        .map_err(|e| Error::PayloadExtractFailed(format!("read symbol bytes: {e}")))?;
    let orig_code = tracee
        .read_memory(code_addr, shellcode.len())
        .map_err(|e| Error::PayloadExtractFailed(format!("read code bytes: {e}")))?;

    tracee
        .write_memory(payload_addr, payload_bytes)
        .map_err(|e| Error::PayloadExtractFailed(format!("write payload bytes: {e}")))?;
    tracee
        .write_memory(socket_addr, socket_bytes)
        .map_err(|e| Error::PayloadExtractFailed(format!("write socket bytes: {e}")))?;
    tracee
        .write_memory(host_pid_addr, &host_pid_bytes)
        .map_err(|e| Error::PayloadExtractFailed(format!("write host pid: {e}")))?;
    tracee
        .write_memory(symbol_addr, symbol_name)
        .map_err(|e| Error::PayloadExtractFailed(format!("write symbol bytes: {e}")))?;
    tracee
        .write_memory(code_addr, &shellcode)
        .map_err(|e| Error::PayloadExtractFailed(format!("write shellcode: {e}")))?;

    // 6. Set registers for shellcode execution
    let mut regs = orig_regs;
    regs.rip = code_addr;
    regs.rdi = payload_addr;
    regs.rsi = (libc::RTLD_NOW | libc::RTLD_GLOBAL) as u64;
    // If the tracee was blocked in a syscall when we attached, the kernel
    // has saved the return address in the syscall frame.  Clobber orig_rax
    // so the kernel won't restart the syscall and overwrite our RIP.
    regs.orig_rax = u64::MAX;

    // Find the stack (or any large writable anonymous mapping) and
    // place RSP safely inside it.  We must NOT use the executable
    // scratch region for the stack — it is r-xp, not writable.
    let stack = maps
        .iter()
        .find(|m| {
            m.is_write()
                && m.filename()
                    .is_some_and(|p| p.to_string_lossy().contains("[stack]"))
        })
        .or_else(|| {
            maps.iter()
                .find(|m| m.is_write() && m.filename().is_none() && m.size() >= 0x1000)
        })
        .ok_or_else(|| Error::PayloadExtractFailed("no writable stack region".into()))?;

    let stack_top = (stack.start() + stack.size()) as u64;
    // Place RSP well inside the mapping but with ample headroom for the
    // shellcode's call frames, dlopen, constructors, and pthread_create.
    regs.rsp = stack_top.saturating_sub(0x10000);

    tracee
        .set_registers(regs)
        .map_err(|e| Error::PayloadExtractFailed(format!("setregs: {e}")))?;

    // 7. Continue until INT3 (SIGTRAP)
    ptracer
        .restart(tracee, Restart::Continue)
        .map_err(|e| Error::PayloadExtractFailed(format!("cont: {e}")))?;

    let tracee = ptracer
        .wait()
        .map_err(|e| Error::PayloadExtractFailed(format!("wait after cont: {e}")))?
        .ok_or_else(|| Error::PayloadExtractFailed("no tracee after cont".into()))?;

    // Check for SIGSEGV first — gives us the faulting RIP for debugging.
    if let Stop::SignalDelivery { signal } = tracee.stop {
        if signal == pete::Signal::SIGSEGV {
            let fault_regs = tracee
                .registers()
                .map_err(|e| Error::PayloadExtractFailed(format!("getregs after segfault: {e}")))?;
            return Err(Error::PayloadExtractFailed(format!(
                "SIGSEGV at RIP={:#x} (dlopen={:#x} dlsym={:#x} payload={:#x} socket={:#x} symbol={:#x} code={:#x})",
                fault_regs.rip, dlopen_addr, dlsym_addr, payload_addr, socket_addr, symbol_addr, code_addr
            )));
        }
    }

    let got_trap = matches!(
        tracee.stop,
        Stop::SignalDelivery { signal } if signal == pete::Signal::SIGTRAP
    );
    if !got_trap {
        return Err(Error::UnexpectedWaitStatus {
            pid,
            op: crate::error::PtraceOp::Cont,
            status: format!("{:?}", tracee.stop),
        });
    }

    // 8. Read RBX (dlopen handle was saved there by the shellcode)
    let mut tracee = tracee;
    let post_regs = tracee
        .registers()
        .map_err(|e| Error::PayloadExtractFailed(format!("getregs after trap: {e}")))?;
    if post_regs.rbx == 0 {
        return Err(Error::DlopenReturnedNull { pid });
    }

    // 9. Restore original bytes and registers
    tracee
        .write_memory(payload_addr, &orig_payload)
        .map_err(|e| Error::PayloadExtractFailed(format!("restore payload bytes: {e}")))?;
    tracee
        .write_memory(socket_addr, &orig_socket)
        .map_err(|e| Error::PayloadExtractFailed(format!("restore socket bytes: {e}")))?;
    tracee
        .write_memory(host_pid_addr, &orig_host_pid)
        .map_err(|e| Error::PayloadExtractFailed(format!("restore host pid bytes: {e}")))?;
    tracee
        .write_memory(symbol_addr, &orig_symbol)
        .map_err(|e| Error::PayloadExtractFailed(format!("restore symbol bytes: {e}")))?;
    tracee
        .write_memory(code_addr, &orig_code)
        .map_err(|e| Error::PayloadExtractFailed(format!("restore code: {e}")))?;
    tracee
        .set_registers(orig_regs)
        .map_err(|e| Error::PayloadExtractFailed(format!("restore regs: {e}")))?;

    // 10. Detach — pete doesn't expose Restart::Detach, so use nix directly.
    nix::sys::ptrace::detach(nix::unistd::Pid::from_raw(pid as i32), None).map_err(|e| {
        Error::PtraceFailed {
            pid,
            op: crate::error::PtraceOp::Detach,
            errno: e as i32,
        }
    })?;

    Ok(())
}

/// Resolve a human-readable process name to a PID by scanning `/proc`.
pub fn from_name(name: &str) -> Result<u32, Error> {
    let mut matches = Vec::new();
    let proc = std::fs::read_dir("/proc")
        .map_err(|e| Error::PayloadExtractFailed(format!("read /proc: {e}")))?;
    for entry in proc {
        let entry = entry.map_err(|e| Error::PayloadExtractFailed(format!("read /proc: {e}")))?;
        let file_name = entry.file_name();
        let pid_str = file_name.to_string_lossy();
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let comm_path = format!("/proc/{}/comm", pid);
        if let Ok(comm) = std::fs::read_to_string(&comm_path) {
            let comm = comm.trim_end();
            if comm == name {
                matches.push(pid);
                continue; // skip cmdline check — don't double-push
            }
        }
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
            if let Some(arg0) = cmdline.split('\0').next() {
                let base = std::path::Path::new(arg0)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();
                if base == name {
                    matches.push(pid);
                }
            }
        }
    }

    matches.sort_unstable();

    match matches.len() {
        0 => Err(Error::ProcessNotFound(name.to_string())),
        1 => Ok(matches[0]),
        _ => Err(Error::AmbiguousProcessName {
            name: name.to_string(),
            pids: matches,
        }),
    }
}

// ---------------------------------------------------------------------------
// libc / dlopen resolution
// ---------------------------------------------------------------------------

/// Find the virtual address of a symbol inside `pid`'s libc mapping.
///
/// Steps:
/// 1. Reuse the `proc_maps::MapRange` vec to locate the libc mapping.
/// 2. Read the on-disk libc binary.
/// 3. Parse ELF dynamic symbol table (`.dynsym`) for the symbol.
/// 4. Walk program headers to translate the symbol's virtual address to a
///    file offset.
/// 5. Compute `target_base + symbol_vaddr`.
fn resolve_symbol(_pid: u32, maps: &[proc_maps::MapRange], name: &str) -> Option<u64> {
    let map = maps.iter().find(|m| {
        if let Some(path) = m.filename() {
            let basename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let is_libc = basename.starts_with("libc.so")
                || basename.starts_with("libc-")
                || basename.starts_with("libc.musl-");
            let is_musl = basename.starts_with("ld-musl-");
            let path_str = path.to_string_lossy();
            (is_libc || is_musl) && (path_str.ends_with(".so") || path_str.contains(".so."))
        } else {
            false
        }
    })?;

    let base = map.start() as u64;
    let path = map.filename().unwrap().to_path_buf();

    let data = std::fs::read(&path).ok()?;
    let (sym_vaddr, _file_offset) = find_symbol_offset(&data, name)?;

    Some(base + sym_vaddr)
}

/// Translate a virtual address to a file offset using ELF program headers.
fn vaddr_to_file_offset(
    phs: &[goblin::elf::program_header::ProgramHeader],
    vaddr: u64,
) -> Option<u64> {
    phs.iter().find_map(|ph| {
        if ph.p_type == goblin::elf::program_header::PT_LOAD
            && vaddr >= ph.p_vaddr
            && vaddr < ph.p_vaddr + ph.p_filesz
        {
            return Some(vaddr - ph.p_vaddr + ph.p_offset);
        }
        None
    })
}

/// Parse an ELF file in memory and return the symbol's virtual address
/// together with its file offset (translated via program headers).
fn find_symbol_offset(data: &[u8], name: &str) -> Option<(u64, u64)> {
    match Object::parse(data).ok()? {
        Object::Elf(elf) => {
            let sym = elf
                .dynsyms
                .iter()
                .find(|sym| elf.dynstrtab.get_at(sym.st_name) == Some(name))
                .or_else(|| {
                    elf.syms
                        .iter()
                        .find(|sym| elf.strtab.get_at(sym.st_name) == Some(name))
                })?;

            let vaddr = sym.st_value;
            let file_offset = vaddr_to_file_offset(&elf.program_headers, vaddr)?;
            Some((vaddr, file_offset))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Shellcode
// ---------------------------------------------------------------------------

/// Assemble an x86-64 stub that:
///
/// ```asm
/// movabs rdi, <payload_path_addr>
/// movabs rsi, RTLD_NOW | RTLD_GLOBAL
/// movabs rax, <dlopen_addr>
/// call rax              ; rax = handle
/// mov rbx, rax          ; save handle
/// movabs rdi, <symbol_name_addr>
/// movabs rax, <dlsym_addr>
/// call rax              ; rax = backseat_init addr
/// movabs rdi, <socket_path_addr>
/// call rax              ; backseat_init(socket_path)
/// int3
/// ```
fn make_shellcode(
    dlopen_addr: u64,
    dlsym_addr: u64,
    payload_path_addr: u64,
    socket_path_addr: u64,
    symbol_name_addr: u64,
) -> Vec<u8> {
    let mut code = Vec::with_capacity(80);
    // movabs rdi, payload_path_addr
    code.extend_from_slice(&[0x48, 0xBF]);
    code.extend_from_slice(&payload_path_addr.to_le_bytes());
    // movabs rsi, RTLD_NOW
    code.extend_from_slice(&[0x48, 0xBE]);
    code.extend_from_slice(&(libc::RTLD_NOW as u64).to_le_bytes());
    // movabs rax, dlopen_addr
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&dlopen_addr.to_le_bytes());
    // call rax
    code.extend_from_slice(&[0xFF, 0xD0]);
    // mov rbx, rax
    code.extend_from_slice(&[0x48, 0x89, 0xC3]);
    // mov rdi, rbx
    code.extend_from_slice(&[0x48, 0x89, 0xDF]);
    // movabs rsi, symbol_name_addr
    code.extend_from_slice(&[0x48, 0xBE]);
    code.extend_from_slice(&symbol_name_addr.to_le_bytes());
    // movabs rax, dlsym_addr
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&dlsym_addr.to_le_bytes());
    // call rax
    code.extend_from_slice(&[0xFF, 0xD0]);
    // movabs rdi, socket_path_addr
    code.extend_from_slice(&[0x48, 0xBF]);
    code.extend_from_slice(&socket_path_addr.to_le_bytes());
    // call rax
    code.extend_from_slice(&[0xFF, 0xD0]);
    // int3
    code.push(0xCC);
    code
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shellcode_size() {
        let sc = make_shellcode(0x1234, 0x5678, 0x9ABC, 0xDEF0, 0x1111);
        assert_eq!(sc.len(), 73);
    }

    /// Verify the exact byte sequence for a known set of addresses.
    /// A single wrong opcode or endian-swapped immediate silently
    /// corrupts the target process during injection.
    #[test]
    fn shellcode_byte_sequence() {
        // Use addresses with distinct byte patterns so endianness bugs
        // are caught at a glance.
        let sc = make_shellcode(
            0x0000_0001_0203_0405, // dlopen_addr
            0x1011_1213_1415_1617, // dlsym_addr
            0x2021_2223_2425_2627, // payload_path_addr
            0x3031_3233_3435_3637, // socket_path_addr
            0x4041_4243_4445_4647, // symbol_name_addr
        );

        // Build the expected bytes manually so we're not just calling
        // the same function we're testing.
        let mut expected = Vec::with_capacity(80);

        // movabs rdi, payload_path_addr
        expected.extend_from_slice(&[0x48, 0xBF]);
        expected.extend_from_slice(&0x2021_2223_2425_2627u64.to_le_bytes());
        // movabs rsi, RTLD_NOW (2)
        expected.extend_from_slice(&[0x48, 0xBE]);
        expected.extend_from_slice(&2u64.to_le_bytes());
        // movabs rax, dlopen_addr
        expected.extend_from_slice(&[0x48, 0xB8]);
        expected.extend_from_slice(&0x0000_0001_0203_0405u64.to_le_bytes());
        // call rax
        expected.extend_from_slice(&[0xFF, 0xD0]);
        // mov rbx, rax
        expected.extend_from_slice(&[0x48, 0x89, 0xC3]);
        // mov rdi, rbx
        expected.extend_from_slice(&[0x48, 0x89, 0xDF]);
        // movabs rsi, symbol_name_addr
        expected.extend_from_slice(&[0x48, 0xBE]);
        expected.extend_from_slice(&0x4041_4243_4445_4647u64.to_le_bytes());
        // movabs rax, dlsym_addr
        expected.extend_from_slice(&[0x48, 0xB8]);
        expected.extend_from_slice(&0x1011_1213_1415_1617u64.to_le_bytes());
        // call rax
        expected.extend_from_slice(&[0xFF, 0xD0]);
        // movabs rdi, socket_path_addr
        expected.extend_from_slice(&[0x48, 0xBF]);
        expected.extend_from_slice(&0x3031_3233_3435_3637u64.to_le_bytes());
        // call rax
        expected.extend_from_slice(&[0xFF, 0xD0]);
        // int3
        expected.push(0xCC);

        assert_eq!(sc, expected, "shellcode byte sequence mismatch");
    }

    /// The shellcode should handle zero addresses (e.g. if a symbol
    /// happens to be at offset 0 in a library).
    #[test]
    fn shellcode_zero_addresses() {
        let sc = make_shellcode(0, 0, 0, 0, 0);
        assert_eq!(sc.len(), 73);
        // RTLD_NOW immediate is at bytes 12–19 (movabs rsi follows
        // movabs rdi + 8-byte immediate at bytes 0–9).
        let rsi_imm: [u8; 8] = sc[12..20].try_into().unwrap();
        assert_eq!(u64::from_le_bytes(rsi_imm), 2, "RTLD_NOW constant is wrong");
    }

    /// The RTLD_NOW constant must be exactly 2 (RTLD_NOW=2 on Linux).
    #[test]
    fn shellcode_rtld_now_constant() {
        let sc = make_shellcode(1, 2, 3, 4, 5);
        // Bytes 12–19: the movabs rsi immediate.
        let imm: [u8; 8] = sc[12..20].try_into().unwrap();
        let val = u64::from_le_bytes(imm);
        assert_eq!(
            val,
            libc::RTLD_NOW as u64,
            "RTLD_NOW constant embedded in shellcode doesn't match libc::RTLD_NOW"
        );
        assert_eq!(
            libc::RTLD_NOW,
            2,
            "RTLD_NOW changed — update shellcode test"
        );
    }

    #[test]
    fn find_symbol_on_non_elf() {
        assert!(find_symbol_offset(b"not an elf", "dlopen").is_none());
    }

    #[test]
    fn vaddr_to_file_offset_hits_and_misses() {
        use goblin::elf::program_header::ProgramHeader;
        let ph = ProgramHeader {
            p_type: goblin::elf::program_header::PT_LOAD,
            p_flags: goblin::elf::program_header::PF_R | goblin::elf::program_header::PF_X,
            p_offset: 0,
            p_vaddr: 0x1000,
            p_paddr: 0x1000,
            p_filesz: 0x1000,
            p_memsz: 0x1000,
            p_align: 0x1000,
        };
        assert_eq!(
            vaddr_to_file_offset(std::slice::from_ref(&ph), 0x1004),
            Some(0x4)
        );
        assert_eq!(
            vaddr_to_file_offset(std::slice::from_ref(&ph), 0x1FFF),
            Some(0xFFF)
        );
        assert_eq!(vaddr_to_file_offset(std::slice::from_ref(&ph), 0x0), None);
        assert_eq!(
            vaddr_to_file_offset(std::slice::from_ref(&ph), 0x2000),
            None
        );
    }

    #[test]
    fn find_symbol_offset_rejects_uncovered_vaddr() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        data.extend_from_slice(&[0u8; 8]);
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&0x3eu16.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&64u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&64u16.to_le_bytes());
        data.extend_from_slice(&56u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&5u32.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        while data.len() < 64 {
            data.push(0);
        }
        assert!(find_symbol_offset(&data, "dlopen").is_none());
    }
}
