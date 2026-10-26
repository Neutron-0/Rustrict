# Rustrict — Windows Native Runtime Compatibility Report

**Audit Date:** 2026-10-24  
**Target Platform:** Microsoft Windows (x86_64)  
**Host Environment:** Windows 11 Enterprise (Build 26100), MSVC C++ Build Tools, Pure Native Rust Toolchain (`stable-x86_64-pc-windows-msvc`)  
**Status:** **NATIVE WINDOWS VERIFIED (NO WSL / DOCKER / BASH REQUIRED)**

---

## 1. Toolchain & Platform Verification

The application builds and executes as a pure native Windows binary. Inspection of `Cargo.toml`, dependencies, and compilation targets establishes:

- **Target Architecture:** `x86_64-pc-windows-msvc`
- **Compiler:** `rustc 1.97.1`
- **Linker:** Microsoft MSVC Linker (`link.exe`)
- **Unix Dependency Check:** Clean. Zero Unix-only crates (e.g. `nix`, `libc`, `tokio-uds`), zero Unix signal handlers, zero shell scripts in build steps.
- **Console Environment:** Supports native Command Prompt (`cmd.exe`), Windows Terminal, and PowerShell. ANSI escape sequences are initialized via Win32 `SetConsoleMode(ENABLE_VIRTUAL_TERMINAL_PROCESSING)`.

---

## 2. Filesystem & Storage Reliability on NTFS / ReFS

### A. Windows Paths Containing Spaces
- **Implementation:** Persistent policy state paths default to `%APPDATA%\Rustrict\router_policies.json` or can be overridden via `RUSTRICT_STORE_PATH`.
- **Space Resilience:** All filesystem operations use `std::path::PathBuf` and `std::fs` functions without shell string expansion.
- **Verification:** Tested writing to directories containing spaces (`C:\Users\...\Test Temp Dir`). Subprocess commands passing paths with spaces wrap arguments or use array args directly.

### B. Atomic Replacement & Antivirus Lock Retries
- **Implementation in `src/gateway/admin/persistence.rs`:**
  - `atomic_write_file`: Writes content to a hidden staging file `.<stem>_<pid>_<nanos>.tmp`.
  - Renames existing valid state to `.<stem>_<pid>_<nanos>.bak`.
  - Atomically renames `.tmp` to destination using `rename_with_retry` with exponential backoff (`10ms`, `20ms`, `30ms`, `40ms`, `50ms`) to overcome transient file locking by Windows Search Indexer, Defender, or antivirus filter drivers.
  - Uses `BackupFileGuard` to restore `.bak` if the final atomic rename fails.
- **Limitation Identified:**
  - `atomic_write_file` lacks OS-level file locking (`LockFileEx`). If two independent processes attempt to write simultaneously, both may attempt to rename the target file at the same time, leading to `NotFound` or `PermissionDenied` errors in the losing process.

---

## 3. Subprocess & Process Lifecycle Management

### A. Windows OpenSSH (`ssh.exe`) Execution
- **Discovery:** Verified on native Windows. Checks `SystemRoot\System32\OpenSSH\ssh.exe` before scanning `PATH`. Successfully locates `C:\Windows\System32\OpenSSH\ssh.exe`.
- **Execution & Timeout:** In `src/gateway/admin/ssh.rs`, subprocess invocation uses `Command::new(&ssh_bin)` with array arguments (`-p`, `-o`, `-i`, `-T`).
- **Zombie Process Prevention:** When an SSH command times out, the monitor loop explicitly calls `child.kill()` followed by `child.wait()`, terminating the Windows process and cleaning up handle tables.
- **Known Risk (Finding SEC-07):** In `ssh.rs`, `child.try_wait()` does not read stdout/stderr until the child exits. Large output (>4KB–64KB) will fill the OS pipe buffer and deadlock the child until the timeout fires.

### B. Windows `curl.exe` Execution
- **Discovery:** Windows 10/11 includes `curl.exe` in `C:\Windows\System32\curl.exe`.
- **MikroTik Provider:** Implements `find_curl()` checking `System32\curl.exe` before PATH. Passes credentials via stdin config (`--config -`) with single-line data directives.
- **AVM & UniFi Providers:** Do not use `find_curl()`; invoke `Command::new("curl.exe")` directly (Finding SEC-09).
- **Catastrophic Flaw (Finding SEC-01):** AVM and UniFi multiplex `--config -` and `--data-binary @-` over the same stdin stream, crashing `curl.exe`.

---

## 4. External Runtime Dependencies & Drivers

| Component | DLL / File | Source / Provider | Required For | Fallback if Missing |
| :--- | :--- | :--- | :--- | :--- |
| **Npcap / WinPcap** | `wpcap.dll` | Npcap Installer | Passive device discovery & L2 raw packet injection | Graceful degradation; diagnostics display warning |
| **WinDivert** | `WinDivert.dll`, `WinDivert64.sys` | WinDivert Project | Local bandwidth limiter & network fault injection | Graceful degradation; diagnostics display warning |
| **Windows OpenSSH** | `ssh.exe` | Windows Optional Feature | OpenWrt SSH provider | Returns `AdminError::CommunicationError` |
| **Windows cURL** | `curl.exe` | Windows System32 (Built-in) | MikroTik REST, AVM TR-064, UniFi REST | Returns `AdminError::CommunicationError` |

---

## 5. Security & DPAPI Integration

- **DPAPI Credential Encryption:** `src/gateway/admin/credentials.rs` implements native DPAPI encryption using Win32 `CryptProtectData` and `CryptUnprotectData` with `CRYPTPROTECT_UI_FORBIDDEN` and `LocalFree`.
- **Memory Zeroing:** `ProtectedString` implements `Drop` using volatile zeroing (`std::ptr::write_volatile(byte, 0)`), preventing compiler dead-store elimination.
- **Current Defect (Finding SEC-08):** `save_protected_credentials` is never invoked by any production or test path.
- **Current Defect (Finding SEC-06):** Password input in `prompt.rs` does not use the Windows Console API to disable `ENABLE_ECHO_INPUT`, displaying typed passwords in cleartext.
