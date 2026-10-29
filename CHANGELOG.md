# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

- Added: Hardware Layer-2 Blackholing (`BLACKHOLE_MAC` `02:bf:00:00:00:01`) for blocked devices, dropping traffic at switch/AP level and eliminating adapter airtime saturation and local host bandwidth drop.
- Added: Asynchronous background worker queue for WinDivert latency and jitter simulation, preventing packet processing loop stalls.
- Added: Scope persistence across CLI restarts saved to `%ProgramData%\Rustrict\rustrict_state.json`.
- Added: Native Windows WinSock `getnameinfo` reverse DNS resolution replacing `nslookup.exe`.
- Added: DHCP `chaddr` client hardware address parsing from BOOTP/DHCP payload and Option 50 requested IP handling.
- Fixed: SMB negotiate dialect rejection on Windows 10/11 targets (`0xC000000D`).
- Fixed: TLS posture probe order to prioritize modern TLS 1.2 before testing legacy handshakes.
- Fixed: Subnet scanning boundary calculation for RFC 3021 `/31` and `/32` networks.
- Fixed: Mermaid architecture diagrams in `README.md` to prevent "Unable to render rich display" failures across GitHub and markdown viewers.
- Fixed: Protected router gateway identity from being overwritten by passive sniffer traffic.
- Added: MIT license, security policy, install/usage/safety docs.

## [2.0.2] - 2026-10-29

- Fixed: Corrected Layer-2 Ethernet frame crafting in `ArpSpoofer` (`src/spoofer/engine.rs`). All outgoing ARP reply and restoration packets now use the transmitting station's physical MAC (`local_mac`) in the Ethernet frame source header (`src_mac`), resolving fatal frame drops by Wi-Fi card drivers and 802.11 Access Points.
- Added: CLI network adapter selection (`--interface <name|index>` / `-i <name|index>`) and adapter listing (`--list-interfaces` / `-l`), allowing operators to inspect and choose specific network adapters.
- Added: Decoupled offline mode (`--offline`, `--no-adapter`), permitting inspection of persistent scopes, rules, and configuration without binding to a physical NIC.
- Added: Interactive `blockmode [blackhole|mitm]` (alias: `spoofer`) command and CLI flag `--blockmode <MODE>` to toggle between L2 unicast blackholing and WinDivert kernel packet drop.
- Fixed: Resolved PowerShell piped stdin UTF-8 Byte Order Mark (`\u{feff}`) stripping in interactive REPL and confirmation inputs.
- Fixed: Display active Scope Mode and Block Mode prominently on startup to eliminate confusion over persistent strict mode settings.

## [2.0.1] - 2026-10-28

- Added: `scope add all` convenience command to quickly admit all RFC 1918 private subnets into operational scope.
- Added: Permissive scope mode admitting cross-subnet RFC 1918 private LAN endpoints (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`).
- Added: Multi-target space-separated and comma-separated syntax (e.g. `block 40 61 84 93`).
- Added: Command aliases (`devices`, `targets`, `unblock`, `unlimit`, `upgrade`, `update`).
- Fixed: Robust installer handling for locked Windows kernel drivers (`WinDivert64.sys`) during version upgrades.

## [2.0.0] - 2026-09-09

- Added: parallel ARP subnet scanner (batches of 48, 10 ms pause).
- Added: 10-step identity resolution (router UPnP, SMB, TLS, NetBIOS,
  mDNS, LLMNR, HTTP, reverse DNS, OUI vendor).
- Added: WinDivert token-bucket limiter with upload/download direction.
- Added: persistent blocks in `rustrict_state.json`, re-armed on launch.
- Added: scope manager (CIDR allow-list, IP/MAC excludes, strict mode).
- Added: port scanner (top 25 + custom), TLS and SMB posture audits.
- Added: fault injection (drop %, delay ms, jitter ms) via `simulate`.
- Added: evidence export (Markdown, JSON, SARIF v2.1.0).
- Added: 39 automated tests across 8 test files.
