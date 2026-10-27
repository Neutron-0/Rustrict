# Phase 18.2 Remaining Risks & Operational Notes

## 1. Network Driver Telemetry Variability
- **Risk:** Some Windows virtual network adapters (e.g. certain VPN TUN/TAP adapters or Hyper-V synthetic NICs) do not implement `Get-NetAdapterStatistics` error/discard counters, returning blank values.
- **Mitigation in Phase 18.2:** These adapters are now correctly classified as `Degraded` with explicit notification that error telemetry is absent, rather than giving operators false confidence with a `Normal` rating.
- **Residual Risk:** An operator monitoring a virtual adapter might see persistent `Degraded` status even if no packets are being dropped at the virtual layer. The diagnostic explanation makes the cause explicit.

## 2. Windows Performance Counter Latency
- **Risk:** `Get-NetAdapter` and `Get-NetAdapterStatistics` execute via PowerShell and WMI/CIM, taking between 100ms and 500ms per invocation on loaded systems.
- **Mitigation in Phase 18.2:** The inter-snapshot duration timer now captures `t_start` *after* the first snapshot completes, ensuring that process invocation overhead does not skew throughput rate calculations. Subprocess execution is strictly bounded to 5 seconds with guaranteed child process killing and reaping on timeout.

## 3. Real Router Lab Testing Gate
- **Risk:** Router mutations on physical hardware carry risks of misconfiguration or lockout.
- **Mitigation:** Zero physical routers were contacted during Phase 18.2. All integration tests run against synthetic or loopback emulators. The Stage 1 isolated lab test remains gated behind operator authorization with rollback procedures documented in the Stage 1 Operator Packet.
