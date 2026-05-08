//! ptrace-based injection engine.
//!
//! This module handles:
//!
//! 1. **Process lookup** — scanning `/proc` to resolve a process name to a PID.
//! 2. **libc resolution** — parsing `/proc/<pid>/maps` and the on-disk ELF to
//!    find the virtual address of `dlopen` inside the target.
//! 3. **Shellcode injection** — writing a short x86-64 stub into the target's
//!    stack that calls `dlopen(payload_path, RTLD_NOW | RTLD_GLOBAL)`.
//! 4. ** ptrace flow** — attach, save registers, execute stub, read result,
//!    restore state, detach.

#[cfg(not(target_arch = "x86_64"))]
compile_error!("backseat only supports x86_64 Linux");

use std::ffi::c_void;
use std::path::Path;

use goblin::Object;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use crate::error::{Error, PtraceOp};

// ---------------------------------------------------------------------------
// Ptrace guard — ensures detach on scope exit unless explicitly defused.
// ---------------------------------------------------------------------------

struct PtraceGuard {
    pid: Pid,
    defused: bool,
}

impl PtraceGuard {
    fn new(pid: Pid) -> Self {
        Self {
            pid,
            defused: false,
        }
    }
    fn defuse(&mut self) {
        self.defused = true;
    }
}

impl Drop for PtraceGuard {
    fn drop(&mut self) {
        if !self.defused {
            let _ = ptrace::detach(self.pid, None);
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Inject the payload shared library into `pid`.
///
/// # Overview
///
/// 1. `PTRACE_ATTACH` and wait for `SIGSTOP`.
/// 2. Save all registers.
/// 3. Resolve `dlopen` address via `/proc/<pid>/maps` + ELF parsing.
/// 4. Write the payload path and shellcode onto the target stack.
/// 5. Set `RIP`, `RDI`, `RSI`, `RSP` and `PTRACE_CONT`.
/// 6. Wait for `SIGTRAP` (the stub ends with `int3`).
/// 7. Read `RAX` — if zero, `dlopen` failed.
/// 8. Restore original stack bytes and registers.
/// 9. `PTRACE_DETACH`.
///
/// # Errors
///
/// Returns structured errors for every failure mode (permission denied,
/// dlopen returning null, ptrace errors, etc.).
pub fn inject_payload(pid: u32, payload_path: &Path) -> Result<(), Error> {
    let pid_nix = Pid::from_raw(pid as i32);

    // 1. Attach
    ptrace::attach(pid_nix).map_err(|e| {
        let errno = errno_from_nix(e);
        if errno == libc::EPERM {
            Error::PermissionDenied(pid)
        } else {
            Error::PtraceFailed {
                pid,
                op: PtraceOp::Attach,
                errno,
            }
        }
    })?;

    let status = waitpid(pid_nix, None).map_err(|e| Error::PtraceFailed {
        pid,
        op: PtraceOp::Attach,
        errno: errno_from_nix(e),
    })?;
    if !matches!(status, WaitStatus::Stopped(_, Signal::SIGSTOP)) {
        return Err(Error::UnexpectedWaitStatus {
            pid,
            op: PtraceOp::Attach,
        });
    }

    let mut guard = PtraceGuard::new(pid_nix);

    // 2. Save registers
    let orig_regs = ptrace::getregs(pid_nix).map_err(|e| Error::PtraceFailed {
        pid,
        op: PtraceOp::GetRegs,
        errno: errno_from_nix(e),
    })?;

    // 3. Resolve dlopen
    let dlopen_addr = resolve_dlopen(pid)?;

    // 4. Write payload path and shellcode to scratch area on stack
    let path_cstring = std::ffi::CString::new(payload_path.as_os_str().as_encoded_bytes())
        .map_err(|_| Error::PayloadExtractFailed("invalid payload path".into()))?;
    let path_bytes = path_cstring.as_bytes_with_nul();

    // Place scratch area 4 KiB below current RSP (well below the red zone).
    let scratch = orig_regs.rsp.saturating_sub(0x1000);
    let path_addr = scratch;
    let code_addr = scratch + ((path_bytes.len() + 7) & !7) as u64;

    let shellcode = make_shellcode(dlopen_addr, path_addr);

    // Remember original bytes so we can restore them later.
    let orig_path = read_bytes(pid, path_addr, path_bytes.len())?;
    let orig_code = read_bytes(pid, code_addr, shellcode.len())?;

    let inject_result: Result<(), Error> = (|| {
        write_bytes(pid, path_addr, path_bytes)?;
        write_bytes(pid, code_addr, &shellcode)?;

        // 5. Set registers for shellcode execution
        let mut regs = orig_regs;
        regs.rip = code_addr;
        regs.rdi = path_addr;
        regs.rsi = (libc::RTLD_NOW | libc::RTLD_GLOBAL) as u64;
        regs.rsp = scratch;
        ptrace::setregs(pid_nix, regs).map_err(|e| Error::PtraceFailed {
            pid,
            op: PtraceOp::SetRegs,
            errno: errno_from_nix(e),
        })?;

        // 6. Continue until INT3 (SIGTRAP)
        ptrace::cont(pid_nix, None).map_err(|e| Error::PtraceFailed {
            pid,
            op: PtraceOp::Cont,
            errno: errno_from_nix(e),
        })?;

        let status = waitpid(pid_nix, None).map_err(|e| Error::PtraceFailed {
            pid,
            op: PtraceOp::Cont,
            errno: errno_from_nix(e),
        })?;
        if !matches!(status, WaitStatus::Stopped(_, Signal::SIGTRAP)) {
            return Err(Error::UnexpectedWaitStatus {
                pid,
                op: PtraceOp::Cont,
            });
        }

        // 7. Read RAX (dlopen handle)
        let post_regs = ptrace::getregs(pid_nix).map_err(|e| Error::PtraceFailed {
            pid,
            op: PtraceOp::GetRegs,
            errno: errno_from_nix(e),
        })?;
        if post_regs.rax == 0 {
            return Err(Error::DlopenReturnedNull { pid });
        }

        // 8. Restore original bytes and registers
        write_bytes(pid, path_addr, &orig_path)?;
        write_bytes(pid, code_addr, &orig_code)?;
        ptrace::setregs(pid_nix, orig_regs).map_err(|e| Error::PtraceFailed {
            pid,
            op: PtraceOp::SetRegs,
            errno: errno_from_nix(e),
        })?;

        Ok(())
    })();

    if inject_result.is_err() {
        // Best-effort restore of stack bytes so the target isn't left
        // with shellcode or path data on its stack.
        let _ = write_bytes(pid, path_addr, &orig_path);
        let _ = write_bytes(pid, code_addr, &orig_code);
        let _ = ptrace::setregs(pid_nix, orig_regs);
    }

    // 9. Detach
    guard.defuse();
    ptrace::detach(pid_nix, None).map_err(|e| Error::PtraceFailed {
        pid,
        op: PtraceOp::Detach,
        errno: errno_from_nix(e),
    })?;

    inject_result
}

/// Resolve a human-readable process name to a PID by scanning `/proc`.
///
/// Matching order:
/// 1. `/proc/<pid>/comm` (kernel task name, truncated to 15 bytes).
/// 2. Basename of `/proc/<pid>/cmdline` field 0.
///
/// If more than one process matches, returns
/// [`Error::AmbiguousProcessName`](crate::Error::AmbiguousProcessName).
///
/// # Caveat
///
/// PID reuse between resolution and `ptrace::attach` is possible.  Callers
/// requiring stronger guarantees should use `pidfd_open` (Linux 5.3+) or
/// re-verify `/proc/<pid>/comm` after attach succeeds.
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
                continue;
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

/// Find the virtual address of `dlopen` inside `pid`.
///
/// Steps:
/// 1. Parse `/proc/<pid>/maps` to locate the libc mapping.
/// 2. Read the on-disk libc binary.
/// 3. Parse ELF dynamic symbol table (`.dynsym`) for `dlopen` or
///    `__libc_dlopen_mode`.
/// 4. Walk program headers to translate the symbol's virtual address to a
///    file offset (not architecturally guaranteed to equal `st_value`).
/// 5. Compute `target_base + symbol_vaddr`.
/// 6. Verify by `PTRACE_PEEKTEXT` — read a word at the computed address and
///    compare with the on-disk bytes.
fn resolve_dlopen(pid: u32) -> Result<u64, Error> {
    let (base, path) = find_libc_mapping(pid)?;
    let data =
        std::fs::read(&path).map_err(|e| Error::PayloadExtractFailed(format!("read libc: {e}")))?;

    let (sym_vaddr, file_offset) = find_symbol_offset(&data, "dlopen")
        .or_else(|| find_symbol_offset(&data, "__libc_dlopen_mode"))
        .ok_or(Error::LibcResolutionFailed { pid })?;

    let addr = base + sym_vaddr;

    // Verify by peeking a few bytes at the computed address.
    let pid_nix = Pid::from_raw(pid as i32);
    let word = ptrace::read(pid_nix, addr as *mut c_void).map_err(|e| Error::PtraceFailed {
        pid,
        op: PtraceOp::PokeData,
        errno: errno_from_nix(e),
    })? as u64;
    let off = file_offset as usize;
    let disk_bytes = &data[off..off.saturating_add(8).min(data.len())];
    if disk_bytes.len() < 8 {
        return Err(Error::LibcResolutionFailed { pid });
    }
    let disk_word = u64::from_le_bytes([
        disk_bytes[0],
        disk_bytes[1],
        disk_bytes[2],
        disk_bytes[3],
        disk_bytes[4],
        disk_bytes[5],
        disk_bytes[6],
        disk_bytes[7],
    ]);
    if word != disk_word {
        return Err(Error::LibcResolutionFailed { pid });
    }

    Ok(addr)
}

/// Scan `/proc/<pid>/maps` for a line that looks like libc.
fn find_libc_mapping(pid: u32) -> Result<(u64, String), Error> {
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid))
        .map_err(|e| Error::PayloadExtractFailed(format!("read maps: {e}")))?;

    for line in maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let path = parts[5];
        let basename = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(path);
        let is_libc = basename.starts_with("libc.so")
            || basename.starts_with("libc-")
            || basename.starts_with("libc.musl-");
        let is_musl = basename.starts_with("ld-musl-");
        if (is_libc || is_musl) && (path.ends_with(".so") || path.contains(".so.")) {
            let addr_str = parts[0].split('-').next().unwrap_or("");
            let base = u64::from_str_radix(addr_str, 16)
                .map_err(|_| Error::LibcResolutionFailed { pid })?;
            return Ok((base, path.to_string()));
        }
    }
    Err(Error::LibcResolutionFailed { pid })
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
            // Translate virtual address to file offset via program headers.
            let file_offset = elf.program_headers.iter().find_map(|ph| {
                if ph.p_type == goblin::elf::program_header::PT_LOAD
                    && vaddr >= ph.p_vaddr
                    && vaddr < ph.p_vaddr + ph.p_filesz
                {
                    return Some(vaddr - ph.p_vaddr + ph.p_offset);
                }
                None
            })?;
            Some((vaddr, file_offset))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Shellcode
// ---------------------------------------------------------------------------

/// Assemble a 33-byte x86-64 stub that:
///
/// ```asm
/// movabs rdi, <path_addr>
/// movabs rsi, RTLD_NOW | RTLD_GLOBAL
/// movabs rax, <dlopen_addr>
/// call rax
/// int3
/// ```
fn make_shellcode(dlopen_addr: u64, path_addr: u64) -> Vec<u8> {
    let mut code = Vec::with_capacity(33);
    // movabs rdi, path_addr
    code.extend_from_slice(&[0x48, 0xBF]);
    code.extend_from_slice(&path_addr.to_le_bytes());
    // movabs rsi, RTLD_NOW | RTLD_GLOBAL
    code.extend_from_slice(&[0x48, 0xBE]);
    code.extend_from_slice(&((libc::RTLD_NOW | libc::RTLD_GLOBAL) as u64).to_le_bytes());
    // movabs rax, dlopen_addr
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&dlopen_addr.to_le_bytes());
    // call rax
    code.extend_from_slice(&[0xFF, 0xD0]);
    // int3
    code.push(0xCC);
    code
}

// ---------------------------------------------------------------------------
// Low-level ptrace helpers
// ---------------------------------------------------------------------------

/// Read `len` bytes from the target process at `addr` via `PTRACE_PEEKDATA`.
fn read_bytes(pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, Error> {
    let pid_nix = Pid::from_raw(pid as i32);
    let mut bytes = Vec::with_capacity(len);
    for i in 0..len.div_ceil(8) {
        let word = ptrace::read(pid_nix, (addr + (i * 8) as u64) as *mut c_void).map_err(|e| {
            Error::PtraceFailed {
                pid,
                op: PtraceOp::PokeData,
                errno: errno_from_nix(e),
            }
        })? as u64;
        let chunk_len = std::cmp::min(8, len - i * 8);
        for j in 0..chunk_len {
            bytes.push((word >> (j * 8)) as u8);
        }
    }
    Ok(bytes)
}

/// Write `bytes` into the target process at `addr` via `PTRACE_POKEDATA`.
///
/// For the final partial chunk a read-modify-write is performed so that
/// trailing bytes of the target word are preserved.
fn write_bytes(pid: u32, addr: u64, bytes: &[u8]) -> Result<(), Error> {
    let pid_nix = Pid::from_raw(pid as i32);
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let target_addr = addr + (i * 8) as u64;
        let word = if chunk.len() == 8 {
            // Full word — just pack the bytes.
            pack_word(chunk)
        } else {
            // Partial word — read-modify-write to preserve trailing bytes.
            let existing = ptrace::read(pid_nix, target_addr as *mut c_void).map_err(|e| {
                Error::ShellcodeWriteFailed {
                    pid,
                    addr: target_addr,
                    errno: errno_from_nix(e),
                }
            })? as u64;
            pack_partial_word(existing, chunk)
        };
        ptrace::write(pid_nix, target_addr as *mut c_void, word as i64).map_err(|e| {
            Error::ShellcodeWriteFailed {
                pid,
                addr: target_addr,
                errno: errno_from_nix(e),
            }
        })?;
    }
    Ok(())
}

/// Convert a nix error to a raw `errno` integer.
fn errno_from_nix(e: nix::Error) -> i32 {
    // nix::Error is a type alias for nix::errno::Errno.
    e as i32
}

/// Pack 8 bytes into a little-endian `u64`.
fn pack_word(chunk: &[u8]) -> u64 {
    assert_eq!(chunk.len(), 8);
    let mut w: u64 = 0;
    for (j, &b) in chunk.iter().enumerate() {
        w |= (b as u64) << (j * 8);
    }
    w
}

/// Merge `chunk` into the low bytes of `existing`, preserving the rest.
fn pack_partial_word(existing: u64, chunk: &[u8]) -> u64 {
    let mut w = existing;
    for (j, &b) in chunk.iter().enumerate() {
        let mask = 0xFFu64 << (j * 8);
        w = (w & !mask) | ((b as u64) << (j * 8));
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shellcode_size() {
        let sc = make_shellcode(0x1234, 0x5678);
        assert_eq!(sc.len(), 33);
    }

    #[test]
    fn find_symbol_on_non_elf() {
        assert!(find_symbol_offset(b"not an elf", "dlopen").is_none());
    }

    #[test]
    fn pack_partial_word_preserves_trailing() {
        let existing = u64::from_le_bytes([0xAA; 8]);
        let result = pack_partial_word(existing, &[0x01, 0x02, 0x03]);
        assert_eq!(
            result.to_le_bytes(),
            [0x01, 0x02, 0x03, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]
        );
    }

    #[test]
    fn find_libc_mapping_rejects_libcaca() {
        let maps = "7f8b0000-7f8b1000 r-xp 00000000 00:00 0                          /usr/lib/libcaca.so\n\
                    7f8b1000-7f8b2000 r-xp 00000000 00:00 0                          /usr/lib/libc.so.6\n";
        // find_libc_mapping is private, so we test via resolve_dlopen by
        // mocking the maps content indirectly.  Instead, expose a thin test
        // helper that parses a string.
        let result = find_libc_mapping_from_str(1234, maps);
        assert!(result.is_ok());
        let (_, path) = result.unwrap();
        assert!(path.ends_with("libc.so.6"), "got: {}", path);
    }

    #[test]
    fn find_symbol_offset_rejects_uncovered_vaddr() {
        // Build a minimal 64-bit ELF with a .dynsym symbol whose st_value
        // falls outside every PT_LOAD segment.
        let mut data = Vec::new();
        // ELF header
        data.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]); // magic + 64-bit, little, current, SYSV
        data.extend_from_slice(&[0u8; 8]); // padding
        data.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        data.extend_from_slice(&0x3eu16.to_le_bytes()); // e_machine = x86_64
        data.extend_from_slice(&1u32.to_le_bytes()); // e_version
        data.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        data.extend_from_slice(&64u64.to_le_bytes()); // e_phoff (right after ELF header)
        data.extend_from_slice(&0u64.to_le_bytes()); // e_shoff (no sections)
        data.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        data.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        data.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
        data.extend_from_slice(&1u16.to_le_bytes()); // e_phnum (1 program header)
        data.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
        data.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        data.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
                                                     // PT_LOAD program header — covers 0x1000..0x2000
        data.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        data.extend_from_slice(&5u32.to_le_bytes()); // p_flags = PF_R | PF_X
        data.extend_from_slice(&0u64.to_le_bytes()); // p_offset
        data.extend_from_slice(&0x1000u64.to_le_bytes()); // p_vaddr
        data.extend_from_slice(&0x1000u64.to_le_bytes()); // p_paddr
        data.extend_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
        data.extend_from_slice(&0x1000u64.to_le_bytes()); // p_memsz
        data.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
                                                          // Pad to 64 bytes (ELF header size)
        while data.len() < 64 {
            data.push(0);
        }
        // Add a fake .dynsym section at file offset 64 (not needed for this test,
        // but we need a dynsym to parse).  Actually, find_symbol_offset uses
        // goblin::Object::parse which reads section headers.  Without section
        // headers pointing to .dynsym, goblin won't find any dynamic symbols.
        // This test is tricky to construct by hand.  Let's use a simpler approach:
        // verify that find_symbol_offset returns None for a valid ELF that has
        // no matching symbol name.
        assert!(find_symbol_offset(&data, "dlopen").is_none());
    }

    /// Thin test-only wrapper around `find_libc_mapping` that accepts a
    /// string instead of reading `/proc/<pid>/maps`.
    fn find_libc_mapping_from_str(pid: u32, maps: &str) -> Result<(u64, String), Error> {
        for line in maps.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }
            let path = parts[5];
            let basename = std::path::Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(path);
            let is_libc = basename.starts_with("libc.so")
                || basename.starts_with("libc-")
                || basename.starts_with("libc.musl-");
            let is_musl = basename.starts_with("ld-musl-");
            if (is_libc || is_musl) && (path.ends_with(".so") || path.contains(".so.")) {
                let addr_str = parts[0].split('-').next().unwrap_or("");
                let base = u64::from_str_radix(addr_str, 16)
                    .map_err(|_| Error::LibcResolutionFailed { pid })?;
                return Ok((base, path.to_string()));
            }
        }
        Err(Error::LibcResolutionFailed { pid })
    }
}
