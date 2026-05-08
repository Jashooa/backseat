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

use std::ffi::c_void;
use std::path::Path;

use goblin::Object;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use crate::error::{Error, PtraceOp};

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
    ptrace::attach(pid_nix).map_err(|e| Error::PtraceFailed {
        pid,
        op: PtraceOp::Attach,
        errno: errno_from_nix(e),
    })?;

    let status = waitpid(pid_nix, None).map_err(|e| Error::PtraceFailed {
        pid,
        op: PtraceOp::Attach,
        errno: errno_from_nix(e),
    })?;
    if !matches!(status, WaitStatus::Stopped(_, Signal::SIGSTOP)) {
        let _ = ptrace::detach(pid_nix, None);
        return Err(Error::PtraceFailed {
            pid,
            op: PtraceOp::Attach,
            errno: -1,
        });
    }

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
        let _ = ptrace::detach(pid_nix, None);
        return Err(Error::PtraceFailed {
            pid,
            op: PtraceOp::Cont,
            errno: -1,
        });
    }

    // 7. Read RAX (dlopen handle)
    let post_regs = ptrace::getregs(pid_nix).map_err(|e| Error::PtraceFailed {
        pid,
        op: PtraceOp::GetRegs,
        errno: errno_from_nix(e),
    })?;
    if post_regs.rax == 0 {
        let _ = ptrace::detach(pid_nix, None);
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

    // 9. Detach
    ptrace::detach(pid_nix, None).map_err(|e| Error::PtraceFailed {
        pid,
        op: PtraceOp::Detach,
        errno: errno_from_nix(e),
    })?;

    Ok(())
}

/// Resolve a human-readable process name to a PID by scanning `/proc`.
///
/// Matching order:
/// 1. `/proc/<pid>/comm` (kernel task name, truncated to 15 bytes).
/// 2. Basename of `/proc/<pid>/cmdline` field 0.
///
/// If more than one process matches, returns
/// [`Error::AmbiguousProcessName`](crate::Error::AmbiguousProcessName).
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
/// 4. Compute `target_base + symbol_offset`.
/// 5. Verify by `PTRACE_PEEKTEXT` — read a word at the computed address and
///    compare with the on-disk bytes.
fn resolve_dlopen(pid: u32) -> Result<u64, Error> {
    let (base, path) = find_libc_mapping(pid)?;
    let data =
        std::fs::read(&path).map_err(|e| Error::PayloadExtractFailed(format!("read libc: {e}")))?;

    let offset = find_symbol_offset(&data, "dlopen")
        .or_else(|| find_symbol_offset(&data, "__libc_dlopen_mode"))
        .ok_or(Error::LibcResolutionFailed { pid })?;

    let addr = base + offset;

    // Verify by peeking a few bytes at the computed address.
    let pid_nix = Pid::from_raw(pid as i32);
    let word = ptrace::read(pid_nix, addr as *mut c_void).map_err(|e| Error::PtraceFailed {
        pid,
        op: PtraceOp::PokeData,
        errno: errno_from_nix(e),
    })? as u64;
    let disk_bytes = &data[offset as usize..offset as usize + 8];
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
        if path.contains("libc") || path.contains("ld-musl") {
            if !path.ends_with(".so") && !path.contains(".so.") {
                continue;
            }
            let addr_str = parts[0].split('-').next().unwrap_or("");
            let base = u64::from_str_radix(addr_str, 16)
                .map_err(|_| Error::LibcResolutionFailed { pid })?;
            return Ok((base, path.to_string()));
        }
    }
    Err(Error::LibcResolutionFailed { pid })
}

/// Parse an ELF file in memory and return the offset of `name` in the
/// dynamic symbol table (`.dynsym`), falling back to the full symbol table.
fn find_symbol_offset(data: &[u8], name: &str) -> Option<u64> {
    match Object::parse(data).ok()? {
        Object::Elf(elf) => {
            for sym in &elf.dynsyms {
                if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
                    if sym_name == name {
                        return Some(sym.st_value);
                    }
                }
            }
            for sym in &elf.syms {
                if let Some(sym_name) = elf.strtab.get_at(sym.st_name) {
                    if sym_name == name {
                        return Some(sym.st_value);
                    }
                }
            }
            None
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
fn write_bytes(pid: u32, addr: u64, bytes: &[u8]) -> Result<(), Error> {
    let pid_nix = Pid::from_raw(pid as i32);
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let mut word: u64 = 0;
        for (j, &b) in chunk.iter().enumerate() {
            word |= (b as u64) << (j * 8);
        }
        let target_addr = (addr + (i * 8) as u64) as *mut c_void;
        ptrace::write(pid_nix, target_addr, word as i64).map_err(|e| {
            Error::ShellcodeWriteFailed {
                pid,
                addr: addr + (i * 8) as u64,
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
}
