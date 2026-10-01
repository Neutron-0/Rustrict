# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
