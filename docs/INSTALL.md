# Install

Windows 10/11 x64 only. You need admin rights to run, not to build.

## 1. Npcap

1. Download from [npcap.com](https://npcap.com/).
2. During install, tick **"Install Npcap in WinPcap API-compatible Mode"**.
3. Check it:

```powershell
Test-Path "$env:ProgramFiles\Npcap\wpcap.dll"
# expect: True
```

## 2. WinDivert

You need `WinDivert.dll` and `WinDivert64.sys` next to `rustrict.exe`.

- Easiest: install Python `pydivert` once; `build.rs` finds the files
  and copies them into `target\` during `cargo build`.
- Or copy the two files by hand from a
  [WinDivert release](https://reqrypt.org/windivert.html) into the same
  folder as `rustrict.exe`.

## 3. Build

```powershell
git clone https://github.com/Neutron-0/Rustrict.git
cd Rustrict
cargo build --release
```

Binary lands at `target\release\rustrict.exe`.

## 4. Run

Open PowerShell **as Administrator**, then:

```powershell
.\target\release\rustrict.exe
```

First run: `scan`, then `hosts`. Start with `limit`, not `block`.
See `docs/USAGE.md` for the command list and `docs/SAFETY.md` before
touching any shared network.
