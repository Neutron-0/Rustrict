use std::net::Ipv4Addr;

use crate::core::scope::ScopeManager;
use crate::state::PersistentBlockedHost;
use crate::types::{Direction, Host, HostStatus, MacAddress};

/// Network interface and gateway parameters required for safe persistent block restoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestorationNetworkParams<'a> {
    pub iface_ip: Ipv4Addr,
    pub iface_mac: MacAddress,
    pub iface_name: &'a str,
    pub gateway_ip: Ipv4Addr,
    pub gateway_mac: MacAddress,
}

/// Validates whether a persisted blocked record is eligible for active enforcement.
///
/// Returns `Ok(mac)` if valid, or `Err(reason)` detailing the validation failure.
pub fn validate_restored_target(
    ip: &Ipv4Addr,
    mac_str: &str,
    params: &RestorationNetworkParams,
    scope: &ScopeManager,
) -> Result<MacAddress, String> {
    // 1. MAC address syntax parsing
    let mac: MacAddress = mac_str
        .parse()
        .map_err(|e| format!("Malformed MAC address '{}': {}", mac_str, e))?;

    // 2. Delegate to centralized TargetAdmissionValidator (enforcing controller/gateway exclusions,
    // unicast validity, subnet network and directed broadcast addresses, and concrete boundaries)
    let validator = crate::core::admission::TargetAdmissionValidator::new(
        params.iface_ip,
        params.iface_mac,
        params.gateway_ip,
        params.gateway_mac,
        scope,
    );

    validator
        .validate_target(
            ip,
            Some(&mac),
            crate::core::admission::AdmissionOperation::LocalEnforcement,
        )
        .map_err(|e| format!("Admission violation: {}", e))?;

    Ok(mac)
}

/// Abstract seam for enabling scoped IP forwarding.
pub trait ScopedForwardingEnabler {
    fn ensure_forwarding_enabled(&self, iface_name: &str) -> Result<bool, String>;
}

/// Abstract seam for activating spoofer & limiter enforcement.
pub trait PersistentBlockActivator {
    fn is_injection_ready(&self) -> bool;
    fn activate(&mut self, host: &Host, dir: Direction) -> Result<(), String>;
}

/// Default system forwarding enabler.
pub struct SystemForwardingEnabler;

impl ScopedForwardingEnabler for SystemForwardingEnabler {
    fn ensure_forwarding_enabled(&self, iface_name: &str) -> Result<bool, String> {
        crate::platform::ensure_scoped_forwarding_enabled(iface_name)
    }
}

/// Report summarizing the outcome of persistent block restoration at startup.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PersistentRestorationReport {
    /// In-memory host inventory produced from saved records.
    pub restored_hosts: Vec<Host>,
    /// Targets that passed all validations and had enforcement actively started.
    pub activated_targets: Vec<Ipv4Addr>,
    /// Targets that were restored into inventory with `PersistedInactive` status due to unmet preconditions.
    pub inactive_targets: Vec<Ipv4Addr>,
    /// Records that were skipped due to invalid address, MAC, or scope violation.
    pub skipped_targets: Vec<(Ipv4Addr, String)>,
    /// Whether scoped IP forwarding was successfully enabled on the interface.
    pub forwarding_enabled: bool,
    /// Detailed failure reason if preconditions or activation failed.
    pub failure_reason: Option<String>,
}

/// Restores persistent blocked hosts with fail-closed semantics.
///
/// Preconditions checked before any active operation:
/// - Target IP and MAC validity, unicast status, non-gateway/non-self.
/// - Scope boundaries and exclusions.
/// - Scoped IPv4 forwarding enablement.
/// - Packet injection driver readiness (`is_injection_ready`).
///
/// If any precondition fails:
/// - ZERO targets are added to the spoofer or limiter.
/// - The persistent state on disk is NOT modified or rewritten.
/// - Hosts are restored in-memory with `HostStatus::PersistedInactive(dir)`.
pub fn restore_persistent_blocks_with<F, E, A>(
    blocked_records: &[PersistentBlockedHost],
    get_direction: F,
    params: &RestorationNetworkParams,
    scope: &ScopeManager,
    forwarding_enabler: &E,
    activator: &mut A,
) -> PersistentRestorationReport
where
    F: Fn(&Ipv4Addr) -> Direction,
    E: ScopedForwardingEnabler,
    A: PersistentBlockActivator,
{
    let mut report = PersistentRestorationReport::default();
    if blocked_records.is_empty() {
        return report;
    }

    struct ValidCandidate<'a> {
        idx: usize,
        record: &'a PersistentBlockedHost,
        mac: MacAddress,
        dir: Direction,
    }

    let mut valid_candidates = Vec::new();

    // 1. Validate each record individually
    for (idx, b) in blocked_records.iter().enumerate() {
        match validate_restored_target(&b.ip, &b.mac, params, scope) {
            Ok(mac) => {
                let dir = get_direction(&b.ip);
                valid_candidates.push(ValidCandidate {
                    idx,
                    record: b,
                    mac,
                    dir,
                });
            }
            Err(reason) => {
                report.skipped_targets.push((b.ip, reason));
            }
        }
    }

    if valid_candidates.is_empty() {
        return report;
    }

    // 2. Check required preconditions before any active operation

    // Precondition A: Scoped IP forwarding enablement
    match forwarding_enabler.ensure_forwarding_enabled(params.iface_name) {
        Ok(_) => {
            report.forwarding_enabled = true;
        }
        Err(e) => {
            let reason = format!(
                "Failed to enable scoped IP forwarding on '{}': {}",
                params.iface_name, e
            );
            report.failure_reason = Some(reason);

            // Fail-closed: do not add to spoofer or limiter. Restore as PersistedInactive.
            for c in valid_candidates {
                let mut host = Host::with_source(
                    c.idx,
                    c.record.ip,
                    c.mac,
                    c.record.name.clone(),
                    crate::types::NameSource::Manual,
                    "Saved Block".to_string(),
                );
                host.status = HostStatus::PersistedInactive(c.dir);
                host.persistent_block = true;
                host.online = false;
                report.inactive_targets.push(c.record.ip);
                report.restored_hosts.push(host);
            }
            return report;
        }
    }

    // Precondition B: Packet injection driver readiness
    if !activator.is_injection_ready() {
        let reason =
            "Packet injection driver is not initialized or unavailable (Npcap missing)".to_string();
        report.failure_reason = Some(reason);

        // Fail-closed: do not add to spoofer or limiter. Restore as PersistedInactive.
        for c in valid_candidates {
            let mut host = Host::with_source(
                c.idx,
                c.record.ip,
                c.mac,
                c.record.name.clone(),
                crate::types::NameSource::Manual,
                "Saved Block".to_string(),
            );
            host.status = HostStatus::PersistedInactive(c.dir);
            host.persistent_block = true;
            host.online = false;
            report.inactive_targets.push(c.record.ip);
            report.restored_hosts.push(host);
        }
        return report;
    }

    // 3. Preconditions passed: activate enforcement for each valid candidate
    for c in valid_candidates {
        let mut host = Host::with_source(
            c.idx,
            c.record.ip,
            c.mac,
            c.record.name.clone(),
            crate::types::NameSource::Manual,
            "Saved Block".to_string(),
        );
        host.status = HostStatus::Blocked(c.dir);
        host.persistent_block = true;
        host.online = false;

        match activator.activate(&host, c.dir) {
            Ok(()) => {
                report.activated_targets.push(host.ip);
                report.restored_hosts.push(host);
            }
            Err(e) => {
                // If activation fails on a specific target, mark as PersistedInactive
                report.failure_reason = Some(format!("Failed to activate {}: {}", host.ip, e));
                host.status = HostStatus::PersistedInactive(c.dir);
                report.inactive_targets.push(host.ip);
                report.restored_hosts.push(host);
            }
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scope::Ipv4Cidr;
    use crate::state::PersistentState;

    struct TestForwardingEnabler {
        should_fail: bool,
        called_with: parking_lot::Mutex<Vec<String>>,
    }

    impl TestForwardingEnabler {
        fn new(should_fail: bool) -> Self {
            Self {
                should_fail,
                called_with: parking_lot::Mutex::new(Vec::new()),
            }
        }
    }

    impl ScopedForwardingEnabler for TestForwardingEnabler {
        fn ensure_forwarding_enabled(&self, iface_name: &str) -> Result<bool, String> {
            self.called_with.lock().push(iface_name.to_string());
            if self.should_fail {
                Err("PowerShell execution failed: Access Denied".into())
            } else {
                Ok(true)
            }
        }
    }

    struct TestBlockActivator {
        injection_ready: bool,
        activated: Vec<(Ipv4Addr, Direction)>,
    }

    impl TestBlockActivator {
        fn new(injection_ready: bool) -> Self {
            Self {
                injection_ready,
                activated: Vec::new(),
            }
        }
    }

    impl PersistentBlockActivator for TestBlockActivator {
        fn is_injection_ready(&self) -> bool {
            self.injection_ready
        }

        fn activate(&mut self, host: &Host, dir: Direction) -> Result<(), String> {
            self.activated.push((host.ip, dir));
            Ok(())
        }
    }

    fn test_fixture_network() -> (RestorationNetworkParams<'static>, ScopeManager) {
        let params = RestorationNetworkParams {
            iface_ip: Ipv4Addr::new(192, 168, 1, 10),
            iface_mac: "00:11:22:33:44:02".parse().unwrap(),
            iface_name: "EthernetTest",
            gateway_ip: Ipv4Addr::new(192, 168, 1, 1),
            gateway_mac: "00:11:22:33:44:01".parse().unwrap(),
        };

        let mut scope = ScopeManager::new();
        let cidr = Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        scope.add_cidr_direct(cidr);
        scope.set_strict(true);

        (params, scope)
    }

    #[test]
    fn test_restoration_empty_records() {
        let (params, scope) = test_fixture_network();
        let enabler = TestForwardingEnabler::new(false);
        let mut activator = TestBlockActivator::new(true);

        let report = restore_persistent_blocks_with(
            &[],
            |_| Direction::Both,
            &params,
            &scope,
            &enabler,
            &mut activator,
        );

        assert_eq!(report.restored_hosts.len(), 0);
        assert_eq!(report.activated_targets.len(), 0);
        assert_eq!(report.inactive_targets.len(), 0);
        assert_eq!(
            enabler.called_with.lock().len(),
            0,
            "No forwarding check if empty"
        );
        assert_eq!(activator.activated.len(), 0);
    }

    #[test]
    fn test_restoration_forwarding_failure_results_in_zero_activation_and_preserves_records() {
        let (params, scope) = test_fixture_network();
        let enabler = TestForwardingEnabler::new(true); // Forwarding will fail
        let mut activator = TestBlockActivator::new(true);

        let records = vec![
            PersistentBlockedHost {
                ip: Ipv4Addr::new(192, 168, 1, 50),
                mac: "00:aa:bb:cc:dd:50".into(),
                name: "Workstation-50".into(),
                direction: "both".into(),
            },
            PersistentBlockedHost {
                ip: Ipv4Addr::new(192, 168, 1, 51),
                mac: "00:aa:bb:cc:dd:51".into(),
                name: "Workstation-51".into(),
                direction: "download".into(),
            },
        ];

        let report = restore_persistent_blocks_with(
            &records,
            |ip| {
                if *ip == Ipv4Addr::new(192, 168, 1, 51) {
                    Direction::Incoming
                } else {
                    Direction::Both
                }
            },
            &params,
            &scope,
            &enabler,
            &mut activator,
        );

        // Crucial safety invariant: ZERO targets activated in worker/driver
        assert_eq!(
            activator.activated.len(),
            0,
            "Forwarding failure must produce ZERO spoofer/limiter activations"
        );
        assert_eq!(report.activated_targets.len(), 0);

        // Both targets restored in-memory as PersistedInactive
        assert_eq!(report.inactive_targets.len(), 2);
        assert_eq!(report.restored_hosts.len(), 2);

        assert_eq!(
            report.restored_hosts[0].status,
            HostStatus::PersistedInactive(Direction::Both)
        );
        assert!(report.restored_hosts[0].persistent_block);

        assert_eq!(
            report.restored_hosts[1].status,
            HostStatus::PersistedInactive(Direction::Incoming)
        );
        assert!(report.restored_hosts[1].persistent_block);

        assert!(report.failure_reason.is_some());
        assert!(report.failure_reason.unwrap().contains("Access Denied"));
    }

    #[test]
    fn test_restoration_missing_packet_injection_dependency_results_in_zero_activation() {
        let (params, scope) = test_fixture_network();
        let enabler = TestForwardingEnabler::new(false); // Forwarding succeeds
        let mut activator = TestBlockActivator::new(false); // Npcap / L2 sender missing

        let records = vec![PersistentBlockedHost {
            ip: Ipv4Addr::new(192, 168, 1, 60),
            mac: "00:aa:bb:cc:dd:60".into(),
            name: "Target-60".into(),
            direction: "both".into(),
        }];

        let report = restore_persistent_blocks_with(
            &records,
            |_| Direction::Both,
            &params,
            &scope,
            &enabler,
            &mut activator,
        );

        // Zero activations
        assert_eq!(
            activator.activated.len(),
            0,
            "Missing packet injection driver must result in zero activations"
        );
        assert_eq!(report.activated_targets.len(), 0);
        assert_eq!(report.inactive_targets.len(), 1);
        assert_eq!(
            report.restored_hosts[0].status,
            HostStatus::PersistedInactive(Direction::Both)
        );
        assert!(report
            .failure_reason
            .unwrap()
            .contains("Packet injection driver is not initialized"));
    }

    #[test]
    fn test_restoration_mixed_valid_and_invalid_records() {
        let (params, mut scope) = test_fixture_network();
        scope.exclude_ip(Ipv4Addr::new(192, 168, 1, 99));

        let enabler = TestForwardingEnabler::new(false);
        let mut activator = TestBlockActivator::new(true);

        let records = vec![
            // 1. Valid target -> must be activated
            PersistentBlockedHost {
                ip: Ipv4Addr::new(192, 168, 1, 55),
                mac: "00:aa:bb:cc:dd:55".into(),
                name: "ValidTarget".into(),
                direction: "both".into(),
            },
            // 2. Malformed MAC -> must be skipped
            PersistentBlockedHost {
                ip: Ipv4Addr::new(192, 168, 1, 56),
                mac: "invalid-mac-string".into(),
                name: "BadMacTarget".into(),
                direction: "both".into(),
            },
            // 3. Zero MAC -> must be skipped
            PersistentBlockedHost {
                ip: Ipv4Addr::new(192, 168, 1, 57),
                mac: "00:00:00:00:00:00".into(),
                name: "ZeroMacTarget".into(),
                direction: "both".into(),
            },
            // 4. Gateway IP -> must be skipped
            PersistentBlockedHost {
                ip: params.gateway_ip,
                mac: "00:aa:bb:cc:dd:58".into(),
                name: "GatewayIpTarget".into(),
                direction: "both".into(),
            },
            // 5. Gateway MAC -> must be skipped
            PersistentBlockedHost {
                ip: Ipv4Addr::new(192, 168, 1, 59),
                mac: params.gateway_mac.to_string(),
                name: "GatewayMacTarget".into(),
                direction: "both".into(),
            },
            // 6. Local Interface IP -> must be skipped
            PersistentBlockedHost {
                ip: params.iface_ip,
                mac: "00:aa:bb:cc:dd:60".into(),
                name: "SelfIpTarget".into(),
                direction: "both".into(),
            },
            // 7. Local Interface MAC -> must be skipped
            PersistentBlockedHost {
                ip: Ipv4Addr::new(192, 168, 1, 61),
                mac: params.iface_mac.to_string(),
                name: "SelfMacTarget".into(),
                direction: "both".into(),
            },
            // 8. Scope excluded IP -> must be skipped
            PersistentBlockedHost {
                ip: Ipv4Addr::new(192, 168, 1, 99),
                mac: "00:aa:bb:cc:dd:99".into(),
                name: "ExcludedTarget".into(),
                direction: "both".into(),
            },
            // 9. Loopback IP -> must be skipped
            PersistentBlockedHost {
                ip: Ipv4Addr::new(127, 0, 0, 1),
                mac: "00:aa:bb:cc:dd:01".into(),
                name: "LoopbackTarget".into(),
                direction: "both".into(),
            },
            // 10. Broadcast MAC -> must be skipped
            PersistentBlockedHost {
                ip: Ipv4Addr::new(192, 168, 1, 62),
                mac: "ff:ff:ff:ff:ff:ff".into(),
                name: "BroadcastMacTarget".into(),
                direction: "both".into(),
            },
        ];

        let report = restore_persistent_blocks_with(
            &records,
            |_| Direction::Both,
            &params,
            &scope,
            &enabler,
            &mut activator,
        );

        // Exactly one target activated
        assert_eq!(
            report.activated_targets,
            vec![Ipv4Addr::new(192, 168, 1, 55)]
        );
        assert_eq!(activator.activated.len(), 1);
        assert_eq!(activator.activated[0].0, Ipv4Addr::new(192, 168, 1, 55));

        // 9 skipped targets
        assert_eq!(report.skipped_targets.len(), 9);
    }

    #[test]
    fn test_restoration_preserves_persistent_state_unmodified() {
        let mut state = PersistentState::default();
        let host1 = Host::with_source(
            0,
            Ipv4Addr::new(192, 168, 1, 70),
            "00:11:22:33:44:70".parse().unwrap(),
            "HostA".into(),
            crate::types::NameSource::Manual,
            "Saved".into(),
        );
        let host2 = Host::with_source(
            1,
            Ipv4Addr::new(192, 168, 1, 71),
            "00:11:22:33:44:71".parse().unwrap(),
            "HostB".into(),
            crate::types::NameSource::Manual,
            "Saved".into(),
        );

        state.add_blocked(&host1, Direction::Both);
        state.add_blocked(&host2, Direction::Outgoing);
        let original_records = state.blocked_hosts.clone();

        let (params, scope) = test_fixture_network();
        let failing_enabler = TestForwardingEnabler::new(true);
        let mut activator = TestBlockActivator::new(true);

        // Run restoration with failing forwarding
        let report = restore_persistent_blocks_with(
            &state.blocked_hosts,
            |ip| state.get_direction(ip),
            &params,
            &scope,
            &failing_enabler,
            &mut activator,
        );

        assert_eq!(report.activated_targets.len(), 0);
        assert_eq!(report.inactive_targets.len(), 2);

        // Confirm state.blocked_hosts was NOT modified or deleted
        assert_eq!(state.blocked_hosts.len(), original_records.len());
        for (i, b) in state.blocked_hosts.iter().enumerate() {
            assert_eq!(b.ip, original_records[i].ip);
            assert_eq!(b.mac, original_records[i].mac);
        }
    }

    #[test]
    fn test_restoration_repeated_startup_shutdown_idempotency() {
        let (params, scope) = test_fixture_network();
        let records = vec![PersistentBlockedHost {
            ip: Ipv4Addr::new(192, 168, 1, 80),
            mac: "00:aa:bb:cc:dd:80".into(),
            name: "IdempotentTarget".into(),
            direction: "both".into(),
        }];

        let enabler = TestForwardingEnabler::new(false);
        let mut activator1 = TestBlockActivator::new(true);

        // Run 1 (first startup)
        let report1 = restore_persistent_blocks_with(
            &records,
            |_| Direction::Both,
            &params,
            &scope,
            &enabler,
            &mut activator1,
        );
        assert_eq!(report1.activated_targets.len(), 1);

        // Run 2 (second startup after shutdown)
        let mut activator2 = TestBlockActivator::new(true);
        let report2 = restore_persistent_blocks_with(
            &records,
            |_| Direction::Both,
            &params,
            &scope,
            &enabler,
            &mut activator2,
        );
        assert_eq!(report2.activated_targets.len(), 1);
        assert_eq!(report1.activated_targets, report2.activated_targets);
    }
}
