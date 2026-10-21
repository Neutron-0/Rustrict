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
