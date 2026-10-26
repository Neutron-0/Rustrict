# Rustrict Phase 15.1 — CI Closure, Evidence Integrity & Credential Hardening

**Date:** 2026-10-26  
**Auditor / Verification Lead:** Antigravity Autonomous Systems Review  
**Target Environment:** Windows 10/11 (native x86_64-pc-windows-msvc)  
**Initial Phase 15 Published Commit:** `922c57570a903ef60928d2f252a10a6cfd2d4198`  

---

## 1. Initial Remote CI Failure Diagnosis

The first GitHub Actions run for the Phase 15 push failed on Windows:
- **Run ID:** `40319672537`
- **Run URL:** https://github.com/Neutron-0/Rustrict/actions/runs/40319672537
- **Commit:** `922c57570a903ef60928d2f252a10a6cfd2d4198`
- **Result:** FAILED
- **Step Breakdown:**
  - `cargo fmt --check`: Passed
  - `cargo check --all-targets`: Passed
  - `cargo clippy --all-targets -- -D warnings`: **FAILED** (Exit code 1)
  - `cargo test --all-targets`: **SKIPPED** (due to sequential execution inside a single job)

### Exact Clippy Linter Diagnostics:
The GitHub runner utilized the latest stable Rust compiler (`rustc 1.99.1` / `cargo 1.99.1`), which introduced a new lint `-D clippy::chunks-exact-to-as-chunks`:
1. `src/gateway/admin/avm.rs:57:22`:
   ```text
   error: using `chunks_exact` with a constant chunk size
      --> src\gateway\admin\avm.rs:57:22
   57 |     for chunk in msg.chunks_exact(64) {
      |                      ^^^^^^^^^^^^^^^^ help: consider using `as_chunks` instead: `as_chunks::<64>().0`
   ```
2. `src/resolver/smb.rs:198:14`:
   ```text
   error: using `chunks_exact` with a constant chunk size
      --> src\resolver\smb.rs:198:14
   198 |             .chunks_exact(2)
       |              ^^^^^^^^^^^^^^^ help: consider using `as_chunks` instead: `as_chunks::<2>().0.iter()`
   ```
3. `src/resolver/tls.rs:90:22`:
   ```text
   error: using `chunks_exact` with a constant chunk size
      --> src\resolver\tls.rs:90:22
   90 |                     .chunks_exact(2)
      |                      ^^^^^^^^^^^^^^^ help: consider using `as_chunks` instead: `as_chunks::<2>().0.iter()`
   ```

---

## 2. Toolchain Compatibility & Minimum Supported Rust Version (MSRV)

### Investigation & Discovery:
1. **Rust 1.84.0:** Failed compilation because `Cargo.lock` references `comfy-table 7.2.2`, which uses `edition = "2024"`. Edition 2024 was stabilized in **Rust 1.85.0**.
2. **Rust 1.85.0:** Failed compilation because `comfy-table 7.2.2` utilizes `let_chains` (`if let` within chained conditions), which was stabilized in **Rust 1.88.0**.
3. **Rust 1.88.0:** Compiles and passes all checks. `slice::as_chunks` was also stabilized in **Rust 1.88.0**.
4. **Rust 1.91.0 Dependency Removed:** In `src/gateway/ssdp.rs`, an earlier patch utilized `str::floor_char_boundary(raw_end)` (stabilized in 1.91.0). This was replaced with the portable, standard UTF-8 boundary check `while !xml.is_char_boundary(window_end) { window_end -= 1; }`, restoring compatibility down to Rust 1.88.0.
5. **MSRV Policy Declared:** Explicitly declared `rust-version = "1.88.0"` in `Cargo.toml`.

### Parser Semantics & Chunk Remainder Preservation:
- In `avm.rs`, `msg` length is pre-padded to a strict multiple of 64 bytes. `as_chunks::<64>().0` produces identical blocks with zero remainder.
- In `smb.rs` and `tls.rs`, UTF-16LE / UTF-16BE bytes were previously sliced via `chunks_exact(2)`, which dropped any odd trailing byte. `as_chunks::<2>().0` preserves identical behavior.
- Regression tests added:
  - `test_ntlmssp_challenge_with_odd_trailing_byte` in `tests/test_smb.rs`
  - `test_x509_cn_extraction_bmpstring_with_odd_trailing_byte` in `tests/test_tls.rs`

---

## 3. Workflow Architecture: Independent Test Execution

The CI workflow `.github/workflows/windows.yml` was refactored into three separate parallel jobs:
1. **`lint` (Stable):** Runs `cargo fmt --check`, `cargo check --all-targets`, and `cargo clippy --all-targets -- -D warnings`.
2. **`test` (Stable):** Runs `cargo test --all-targets` independently. Static analysis failures no longer suppress test execution.
3. **`msrv` (1.88.0):** Uses `dtolnay/rust-toolchain@1.88.0` to verify `cargo check --all-targets` and `cargo test --all-targets` at the declared MSRV.

---

## 4. Sensitive Buffer Handling & Secret Hygiene Review

1. **Adoption of `zeroize` Crate:**
   - Integrated `zeroize = { version = "1.8", features = ["zeroize_derive"] }`.
   - Replaced hand-rolled `std::ptr::write_volatile` loop with audited `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop` implementations.
   - `ProtectedBuffer` and `ProtectedString` derive `Zeroize` and `ZeroizeOnDrop`, ensuring compiler fences defeat dead-store elimination.
2. **DPAPI Plaintext & Ciphertext Hygiene:**
   - In `dpapi_decrypt`, Windows LocalAlloc unmanaged memory (`out_blob.pbData`) is zeroized via `zeroize` before calling `LocalFree`.
   - In `load_protected_credentials`, the encrypted disk payload is zeroized immediately after DPAPI decryption.
   - In non-Windows test mock code, documented clearly that XOR masking is strictly a test fixture, not production encryption.
3. **Realistic Overwrite Guarantees in `AutoCleanFile`:**
   - Clarified comments in `curl_util.rs`: in-place file overwriting is a best-effort defense-in-depth measure against raw disk snooping; it does not guarantee cryptographic media erasure on wear-leveling flash/SSDs or copy-on-write filesystems.

---

## 5. Test Totals Reconciliation

### Discrepancy Analysis:
- In the Phase 15 report, `TEST_EVIDENCE.md` claimed "196 passed", while the listed table entries summed to 203.
- Investigation of raw command output revealed:
  - `tests/test_openwrt_admin.rs` was erroneously tabulated as 23 (actual test count is 19).
  - `tests/test_policy_views.rs` was tabulated as 6 (actual test count is 7).
- With 4 new regression tests added in Phase 15.1 (`test_smb`, `test_tls`, and 2 in `test_reliability`), the real verified total is **204 passed**, 0 failed, 0 ignored.

### Reconstructed Fresh Test Count:
| Target / Binary | Passed | Failed | Ignored | Focus |
| :--- | :---: | :---: | :---: | :--- |
| `src/lib.rs` | 2 | 0 | 0 | Unit tests |
| `src/main.rs` | 0 | 0 | 0 | CLI application binary |
| `tests/test_assessment.rs` | 5 | 0 | 0 | CIDR and boundaries |
| `tests/test_avm_admin.rs` | 20 | 0 | 0 | AVM TR-064 & `as_chunks::<64>` |
| `tests/test_dhcp.rs` | 1 | 0 | 0 | DHCP hostname option |
| `tests/test_diagnostics.rs` | 7 | 0 | 0 | Diagnostics isolation |
| `tests/test_fixes.rs` | 8 | 0 | 0 | Edge cases & bounds |
| `tests/test_gateway.rs` | 4 | 0 | 0 | Gateway SSDP/SOAP |
| `tests/test_mikrotik_admin.rs` | 20 | 0 | 0 | MikroTik REST API |
| `tests/test_openwrt_admin.rs` | 19 | 0 | 0 | OpenWrt ubus |
| `tests/test_persistence.rs` | 9 | 0 | 0 | File locking & storage |
| `tests/test_policy_engine.rs` | 8 | 0 | 0 | Policy engine states |
| `tests/test_policy_views.rs` | 7 | 0 | 0 | CLI policy tables |
| `tests/test_reliability.rs` | 9 | 0 | 0 | Credential hygiene & zeroize |
| `tests/test_router_admin.rs` | 12 | 0 | 0 | Provider abstractions |
| `tests/test_smb.rs` | 2 | 0 | 0 | NTLM parsing & odd chunk |
| `tests/test_ssh_admin.rs` | 16 | 0 | 0 | SSH execution & keys |
| `tests/test_target_resolution.rs` | 12 | 0 | 0 | Target ID/IP resolution |
| `tests/test_tls.rs` | 2 | 0 | 0 | X.509 CN & BMPString odd chunk |
| `tests/test_unifi_admin.rs` | 19 | 0 | 0 | UniFi REST API |
| `tests/test_unified_admin.rs` | 10 | 0 | 0 | Registry fail-closed |
| `tests/test_verification.rs` | 5 | 0 | 0 | Verification suite |
| `tests/unit_tests.rs` | 7 | 0 | 0 | Frame crafting |
| **TOTAL** | **204** | **0** | **0** | **Exact match: 204** |
