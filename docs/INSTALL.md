# Rustrict Installation Guide

Rustrict is supported on **Windows 10 and Windows 11 (x86_64)**.

---

## Method 1: 1-Line PowerShell Installer (Recommended)

Run an elevated Administrator PowerShell prompt and execute:

```powershell
irm https://raw.githubusercontent.com/Neutron-0/Rustrict/main/scripts/install.ps1 | iex
```

### What the Installer Does:
1. Validates that PowerShell is running with Administrator privileges.
2. Fetches the latest release archive (`rustrict-v2.0.1-x86_64-pc-windows-msvc.zip`) and its cryptographic checksum manifest (`SHA256SUMS.txt`).
3. Computes the SHA-256 hash of the downloaded zip and verifies it matches the official manifest.
4. Extracts `rustrict.exe`, `WinDivert.dll`, and `WinDivert64.sys` to:
   ```text
   %LOCALAPPDATA%\Programs\rustrict\bin\
   ```
5. Adds the bin directory to your User `PATH` environment variable so you can launch `rustrict` from any directory.
6. Checks whether Npcap is present and warns if missing.

---

## Upgrading Rustrict

To upgrade an existing installation to the latest release at any time:

### Quick 1-Line Upgrade
Run in an elevated Administrator PowerShell prompt:

```powershell
irm https://raw.githubusercontent.com/Neutron-0/Rustrict/main/scripts/install.ps1 | iex
```

### In-App Upgrade Check
Inside the `rustrict` interactive shell, type:
```text
rustrict > upgrade
```
or
```text
rustrict > update
```
This prints the installed version, official GitHub Releases link, and upgrade command.

### What Happens During an Upgrade?
- **Rule Preservation**: All persisted blocked hosts, scope definitions, and exclusions in `%ProgramData%\Rustrict\rustrict_state.json` remain untouched and are reloaded automatically on next run.
- **Kernel Driver Safety**: If the `WinDivert` driver service is currently active and locked by the Windows kernel, the installer safely retains the existing driver file and updates `rustrict.exe` without requiring a reboot or system restart.
- **Path Persistence**: The binary path (`%LOCALAPPDATA%\Programs\rustrict\bin`) remains in your User `PATH`, so you can immediately run `rustrict` without reconfiguring environment variables.

---

## Method 2: Pre-compiled GitHub Release (Manual)

1. Navigate to [GitHub Releases](https://github.com/Neutron-0/Rustrict/releases).
2. Download `rustrict-v2.0.1-x86_64-pc-windows-msvc.zip` and `SHA256SUMS.txt`.
3. Verify the checksum in PowerShell:
   ```powershell
   (Get-FileHash .\rustrict-v2.0.1-x86_64-pc-windows-msvc.zip -Algorithm SHA256).Hash
   Get-Content .\SHA256SUMS.txt
   ```
4. Extract the contents into a directory of your choice (e.g. `C:\Tools\Rustrict`).
5. Ensure `WinDivert.dll` and `WinDivert64.sys` remain in the same folder as `rustrict.exe`.
6. Open an **Administrator** terminal and run `.\rustrict.exe`.

---

## Method 3: Building from Source

### Prerequisites:
1. **Rust Toolchain**: Rust 1.75+ (or 1.88.0 MSRV). Install via [rustup.rs](https://rustup.rs/).
2. **Npcap**: Download and install from [npcap.com](https://npcap.com/).
   - ⚠️ **CRITICAL:** Check the box **"Install Npcap in WinPcap API-compatible Mode"** during setup.
3. **C++ Build Tools**: Visual Studio MSVC toolchain (`x64 Native Tools Command Prompt`).

### Build Steps:
```powershell
# 1. Clone repository
git clone https://github.com/Neutron-0/Rustrict.git
cd Rustrict

# 2. Build release binary (bundled WinDivert driver is auto-copied from drivers/ by build.rs)
cargo build --release

# 3. Verify test suite (all tests passing)
cargo test

# 4. Launch in Administrator terminal
.\target\release\rustrict.exe
```

---

## Required Kernel Drivers & Components

| Component | Role | Installation |
| :--- | :--- | :--- |
| **Npcap** (`wpcap.dll`) | Raw Layer 2 Ethernet frame transmission for ARP spoofing and passive DHCP snooping | Download from [npcap.com](https://npcap.com/) with **WinPcap API-compatible mode enabled**. |
| **WinDivert** (`WinDivert.dll` & `WinDivert64.sys`) | Kernel-level `NETWORK_FORWARD` packet inspection, token-bucket throttling, and packet dropping | Automatically bundled in release archives and repository `drivers/` folder. Must be in the same folder as `rustrict.exe`. |
| **IP Helper** (`iphlpapi.dll`) | Native Windows kernel ARP resolution (`SendARP`) | Pre-installed with Windows. |

### Verifying Npcap Installation:
```powershell
Test-Path "$env:ProgramFiles\Npcap\wpcap.dll"
# Should output: True
```

---

## Verifying Driver Health in Rustrict

Launch Rustrict and check the startup banner and diagnostics:
```text
rustrict > nic status
rustrict > scope status
```

If WinDivert is missing or unsigned on test systems, Rustrict will report a graceful driver warning instead of crashing.
