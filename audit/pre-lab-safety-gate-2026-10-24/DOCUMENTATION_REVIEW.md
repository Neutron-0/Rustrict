# Rustrict — Pre-Lab Safety Protocol Documentation Review (Hardened Evidence Criteria)

**Audit Cycle:** Pre-Lab Safety Gate Review  
**Date:** 2026-10-26  
**Author:** Independent Senior Systems Verification & Security Lead  
**Scope:** Review and correction of Stage 1 evidence criteria, provider-specific operation semantics, encrypted packet capture limits, OpenWrt nftables counter separation, router-side logging boundaries, and AVM FRITZ!Box state inspection capabilities.  

---

## 1. Executive Summary & Defect Remediation

This review finalizes the Stage 1 laboratory safety documentation under `audit/pre-lab-safety-gate-2026-10-24/` in accordance with rigorous, adversarial verification standards:
1. **OpenWrt Snapshot Clarification (Item 1):** Preserves raw outputs (`uci export firewall`, `nft list ruleset`, `uci changes`, `crontab -l`) while establishing an explicit protocol to compare stable policy and chain structure separately from dynamic packet/byte counters. Packet counter increments on existing default rules are distinguished from mutations, but any unexplained structural change (new table, chain, rule, or set) triggers an immediate fail.
2. **Router-Side Logging Limitations (Item 2):** Corrected prior claims regarding router logs. OpenWrt Dropbear, MikroTik account logs, UniFi activity logs, and FRITZ!Box event logs are explicitly recognized as **incapable of proving the execution of every individual command or read-only API operation** under default configurations. The protocol now establishes four distinct evidence layers: source-traced operation semantics, corroborating network transport metadata, corroborating router management logs, and authoritative before/after state snapshots.
3. **AVM FRITZ!Box State Snapshot Verification (Item 3):** Verified the inspected production implementation in [`src/gateway/admin/avm.rs`](file:///d:/Vault/Rustrict/src/gateway/admin/avm.rs). Recognized that AVM does **not** expose a generalized UniFi-style traffic rules table or OpenWrt-style firewall configuration export via TR-064. Furthermore, `query_active_policies()` queries only local in-memory policy state. The checklist was updated to record this architectural limitation and require per-host `GetWANAccessByIP` SOAP queries and Web GUI configuration backup diffs, classifying whole-router native table dumping on AVM as a bounded limitation (**PARTIALLY VERIFIED**).

---

## 2. Detailed Technical Audit of Addressed Items

### Item 1: OpenWrt Snapshot Procedure & NFT Counter Separation

- **Technical Analysis:** On OpenWrt 23.05 (which uses `nftables` via `fw4`), executing `nft list ruleset` outputs rule statements containing dynamic runtime counters (e.g. `counter packets 142 bytes 11520`). If background traffic passes through the router during the test (e.g. ARP, DNS, NTP, or SSH session packets), a raw `diff -u` will show diffs on counter lines even when zero firewall rules were modified or added.
- **Remediation Implemented in `LAB_TEST_CHECKLIST.md` (Section 3.3.1):**
  - **Raw Preservation:** The original raw output files (`/tmp/stage1_pre_nft.txt` and `/tmp/stage1_post_nft.txt`) are preserved in full for archival audit.
  - **Structural Normalization:** A clean comparison pass is executed by stripping dynamic counter tokens (`sed -E 's/packets [0-9]+ bytes [0-9]+//g; s/# handle [0-9]+//g'`).
  - **Strict Failure Boundary:** The normalized diff **must be completely empty**. Any structural change (e.g. added rule, modified jump target, new chain, or altered set) causes an immediate Stage 1 failure and abort. Unexplained structural differences are never suppressed.

---

### Item 2: Router-Side Logging Boundaries & Evidence Layering

- **Technical Analysis:** Default router daemons log coarse connection events rather than granular command/query audit trails:
  - **OpenWrt Dropbear:** Logs only TCP connection, public-key authentication, and exit (`logread -e dropbear`). It does **not** log executed remote command strings (`id -u`, `ubus call system board`) unless verbose debug logging or kernel auditd/acct is specifically enabled.
  - **MikroTik RouterOS:** `/log print where topics~"account"` logs user logins and logouts. It does not log individual REST GET requests unless `/system logging add topics=rest` or `topics=web` is manually provisioned.
  - **UniFi Network Application:** System logs record administrator logins and configuration changes; routine read-only GET queries are not logged in the administrative event journal.
  - **AVM FRITZ!Box:** System event log records TR-064 administrative logins; routine SOAP query actions are not logged.
- **Remediation Implemented in `LAB_TEST_CHECKLIST.md` (Section 3.2):**
  - Established an explicit **Four-Tier Evidence Model**:
    - **Tier 1:** Source-traced operation semantics (defines programmatic invariants).
    - **Tier 2:** Network transport metadata (Wireshark proves destination IP/port, TLS negotiation, absence of plaintext fallback, absence of ARP poisoning).
    - **Tier 3:** Corroborating router management logs (confirms valid login, correct origin IP, and absence of administrative error alerts; recognized as corroboration, not proof of individual sub-operations).
    - **Tier 4:** Authoritative before/after state snapshots (primary, definitive proof of zero configuration change).

---

### Item 3: AVM FRITZ!Box State Snapshot Verification & Limitations

- **Technical Analysis of Inspected Source (`src/gateway/admin/avm.rs`):**
  - The AVM provider communicates strictly with the TR-064 SOAP service `urn:dslforum-org:service:X_AVM-DE_HostFilter:1` using `DisallowWANAccessByIP` and `GetWANAccessByIP`.
  - FRITZ!Box does **not** expose a UniFi-style generalized ruleset export or OpenWrt-style firewall configuration file via TR-064.
  - In [`src/gateway/admin/avm.rs#L1253-L1256`](file:///d:/Vault/Rustrict/src/gateway/admin/avm.rs#L1253-L1256), `AvmAdminProvider::query_active_policies()` returns only policies stored in its local in-memory table `self.active_policies`.
  - In [`src/gateway/admin/avm.rs#L1481-L1515`](file:///d:/Vault/Rustrict/src/gateway/admin/avm.rs#L1481-L1515), `reconcile_policies()` loops over known active policies and queries `GetWANAccessByIP` for each one; it cannot discover externally configured rules or dump a global firewall table.
- **Remediation Implemented in `LAB_TEST_CHECKLIST.md` (Section 3.3.4 & Section 5):**
  - The checklist removes any assumption that AVM exposes a global Traffic Rules or Access Profile list via TR-064.
  - **Verification Procedure:** Requires querying `GetWANAccessByIP` directly for the specific test device IP before and after Stage 1, alongside Web GUI configuration export diffs.
  - **Recorded Limitation:** Officially classified as **PARTIALLY VERIFIED (Bounded Limitation)** in the Stage 1 Acceptance Gates. The lack of an authoritative, whole-router native table dump via TR-064 is documented as an accepted architectural constraint for AVM.

---

## 3. Documentation Files Modified

1. [`audit/pre-lab-safety-gate-2026-10-24/LAB_TEST_CHECKLIST.md`](file:///d:/Vault/Rustrict/audit/pre-lab-safety-gate-2026-10-24/LAB_TEST_CHECKLIST.md):
   - **Section 3.2:** Replaced simplistic logging assertions with the 4-tier evidence model; detailed specific daemon logging limitations (Dropbear, RouterOS, UniFi, FRITZ!Box).
   - **Section 3.3.1:** Clarified OpenWrt snapshot protocol to retain raw outputs while normalizing dynamic nftables packet/byte counters; mandated immediate failure on any structural discrepancy.
   - **Section 3.3.4:** Replaced synthetic GUI/profile assumptions for AVM with exact `GetWANAccessByIP` SOAP actions and configuration backup comparisons, documenting the TR-064 query model.
   - **Section 5:** Updated Acceptance Gate matrix to include NFT counter separation, logging boundaries, and AVM bounded snapshot limitations.
2. [`audit/pre-lab-safety-gate-2026-10-24/DOCUMENTATION_REVIEW.md`](file:///d:/Vault/Rustrict/audit/pre-lab-safety-gate-2026-10-24/DOCUMENTATION_REVIEW.md):
   - Fully revised to document the technical findings, code references, and resolutions for Items 1, 2, and 3.

---

## 4. Unresolved Evidence Limitations

The following architectural limitations are formally recorded:
- **AVM TR-064 Table Dump Absence:** AVM FRITZ!Box TR-064 does not support dumping the full device filter table in a single atomic snapshot. Verification on AVM is bounded to per-host `GetWANAccessByIP` queries and web GUI configuration backup diffs.
- **Dropbear Default Command Visibility:** OpenWrt Dropbear does not log individual SSH exec command strings without kernel audit or process accounting enabled. Verification relies on source-traced semantics and post-test nftables ruleset structural diffs.
- **Encrypted Payload Opacity:** Modern TLS and SSH payloads cannot be inspected via Wireshark without active MITM interception (which is strictly prohibited). Network captures verify transport integrity, while router snapshots provide the definitive proof of zero configuration change.

---

## 5. Formal Safety Gate Decision

```
READY FOR STAGE 1 READ-ONLY LAB DIAGNOSTICS
```

### Scope & Constraints of Decision
1. **Documentation Certified:** All evidence criteria, snapshot procedures, and logging limitations are rigorously defined and aligned with the codebase.
2. **Stage 1 Execution Authorized:** Operators are authorized to execute **Stage 1 (Read-Only Authenticated Diagnostics)** against an isolated, non-production lab router under the controls of [`LAB_TEST_CHECKLIST.md`](file:///d:/Vault/Rustrict/audit/pre-lab-safety-gate-2026-10-24/LAB_TEST_CHECKLIST.md).
3. **Stage 2 Remains Blocked:** No mutating commands (`router pause`, `router resume`, `router adjust`) are authorized until Stage 1 snapshots are recorded and certified with zero structural configuration differences.
