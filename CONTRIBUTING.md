# Contributing

Rustrict is Windows-only Rust. Keep changes small and tested.

## Setup

```powershell
# Administrator PowerShell required for live runs.
# Build works in a normal terminal.
cargo build
cargo test
```

Live runs need: Windows 10/11 x64, Npcap (WinPcap mode), WinDivert
binaries next to the exe. See `docs/INSTALL.md`.

## Rules

1. Windows only. Guard non-Windows code with `#[cfg(windows)]`.
2. Never touch hosts outside the configured scope. Check `ScopeManager`
   before adding new target paths.
3. Restore on exit. Any new spoofing or filtering path must undo itself in
   `free` and in the shutdown path.
4. Add or update tests in `tests/` for behavior changes. Run the full
   suite before pushing: `cargo test`.
5. Keep output plain. No hype words, no emoji in CLI output.

## Pull requests

- One change per PR.
- Describe what you ran: `cargo test` output plus, for live features,
  lab subnet, target count, and before/after behavior.
- Update `CHANGELOG.md` under Unreleased.
