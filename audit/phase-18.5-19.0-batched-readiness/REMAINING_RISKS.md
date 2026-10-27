# Rustrict Phases 18.5–19.0 — Remaining Operational & Lab Risks

**Document Version:** 1.0.0  
**Date:** 2026-10-27  
**Commit:** `10dd09706d2796ebc62b34354719485a4edb92eb`  

---

## 1. Residual Risk Assessment

While Phases 18.5 through 19.0 closed the known target admission vulnerabilities, partial-transaction failure modes, untrusted scope persistence defects, and provided a safe read-only router-lab mode, the following operational and hardware considerations remain:

### 1.1 Physical Router Vendor Divergence (Stage 1 Hardware Testing)
- **Risk:** Vendor firmware updates may alter JSON schemas, TR-064 actions, or REST endpoints unexpectedly.
- **Mitigation:**
  - Stage 1 testing is strictly limited to read-only diagnostics (`--router-lab` mode).
  - Schema-validated evidence export (`router export-evidence`) captures raw responses without applying mutations.
  - Zero mutation retries (`max_attempts == 1`) prevent repeated or duplicate rule injection if a router resets or terminates an HTTPS connection.

### 1.2 Windows Interface Index Reassignment
- **Risk:** If an active network adapter is physically disconnected or disabled by the OS during an active session, PowerShell `Set-NetIPInterface` may fail to query or restore forwarding on that specific alias.
- **Mitigation:**
  - `ForwardingManager` records both alias and initial state.
  - Bounded retries (3 attempts) are performed.
  - If the adapter disappeared, structured failure logs report the exact interface name and warn the operator to inspect `Get-NetIPInterface`.

### 1.3 Administrator Privilege Escalation
- **Risk:** Rustrict requires elevated administrator privileges on Windows for Npcap packet capture and WinDivert traffic shaping.
- **Mitigation:**
  - In `--router-lab` mode, Layer 2 packet injection drivers (`wpcap.dll` / `WinDivert.dll`) are never initialized.
  - Operator can run read-only router diagnostics with standard non-destructive networking.

### 1.4 Operator Error During Confirmation Prompts
- **Risk:** An operator might accidentally confirm a mutation when interacting with a live router.
- **Mitigation:**
  - All router firewall mutation commands (`router pause`, `router adjust`, `router resume`) require explicit preflight plan review and an interactive confirmation prompt (`[yes/N]`), unless explicitly overridden with `--yes`.
  - In `--router-lab` mode, local destructive enforcement (`block`, `limit`, `simulate`) is strictly disabled in code.
