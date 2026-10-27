# Phase 18.1 Remaining Risks & Hardware Lab Readiness Register

## 1. Residual Architecture & Platform Risks

1. **Host-Specific PowerShell Command Execution Delay:**
   - On Windows machines where PowerShell cold-start or WMI query latency is high, executing `Get-NetAdapterStatistics` twice with an interval can take longer than the requested sleep window (e.g. 5.19s actual elapsed vs 2.0s sleep).
   - *Mitigation in Phase 18.1:* The actual rate calculation uses `Instant::now()` elapsed time rather than the requested sleep duration, ensuring that computed throughput rates and link utilization are numerically accurate regardless of execution overhead. Furthermore, commands are bounded by worker-thread timeouts (5s default).

2. **Network Driver Counter Resets During Active Limiting:**
   - Certain wireless network card drivers reset interface byte counters when changing Wi-Fi channels, roaming between access points, or waking from power-save states.
   - *Mitigation in Phase 18.1:* Detected as `counter_reset_detected = true`, invalidating measured deltas and raising a `Degraded` classification warning instead of silently interpreting the reset as zero traffic.

3. **Stage 1 Physical Router Lab Authorization:**
   - While loopback protocol integration and contract testing confirm adapter protocol handling, real hardware variations (firmware revisions, custom port assignments, non-standard TLS renegotiation) require Stage 1 physical lab verification on isolated hardware before production field deployment.
   - *Pre-requisite:* Must follow `STAGE_1_OPERATOR_PACKET.md` with explicit operator authorization, hardware serial number verification, and external serial/console recovery methods in place.
