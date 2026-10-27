use std::net::Ipv4Addr;

use rustrict::cli::RustrictCli;
use rustrict::core::admission::{AdmissionOperation, TargetAdmissionValidator};
use rustrict::core::scope::{Ipv4Cidr, ScopeManager};
use rustrict::types::{Host, HostStatus, MacAddress, NetworkInterface};

#[test]
fn test_admission_layer_contract() {
    let mut scope = ScopeManager::new();
    let cidr24 = Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
    scope.add_cidr_direct(cidr24);

    let ctrl_ip = Ipv4Addr::new(192, 168, 1, 10);
    let ctrl_mac: MacAddress = "00:11:22:33:44:02".parse().unwrap();
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let gw_mac: MacAddress = "00:11:22:33:44:01".parse().unwrap();

    let validator = TargetAdmissionValidator::new(ctrl_ip, ctrl_mac, gw_ip, gw_mac, &scope);

    // 1. Mandatory Controller Exclusions
    let res = validator.validate_target(&ctrl_ip, None, AdmissionOperation::LocalEnforcement);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Local controller IP"));

    let res_mac = validator.validate_target(
        &Ipv4Addr::new(192, 168, 1, 50),
        Some(&ctrl_mac),
        AdmissionOperation::LocalEnforcement,
    );
    assert!(res_mac.is_err());
    assert!(res_mac.unwrap_err().contains("Local controller MAC"));

    // 2. Mandatory Gateway Exclusions
    let res_gw = validator.validate_target(&gw_ip, None, AdmissionOperation::LocalEnforcement);
    assert!(res_gw.is_err());
    assert!(res_gw.unwrap_err().contains("Default gateway IP"));

    let res_gw_mac = validator.validate_target(
        &Ipv4Addr::new(192, 168, 1, 50),
        Some(&gw_mac),
        AdmissionOperation::LocalEnforcement,
    );
    assert!(res_gw_mac.is_err());
    assert!(res_gw_mac.unwrap_err().contains("Default gateway MAC"));

    // 3. Subnet Network and Directed Broadcast Rejection
    let res_net = validator.validate_target(
        &Ipv4Addr::new(192, 168, 1, 0),
        None,
        AdmissionOperation::LocalEnforcement,
    );
    assert!(res_net.is_err());
    assert!(res_net.unwrap_err().contains("subnet network identifier"));

    let res_bcast = validator.validate_target(
        &Ipv4Addr::new(192, 168, 1, 255),
        None,
        AdmissionOperation::LocalEnforcement,
    );
    assert!(res_bcast.is_err());
    assert!(res_bcast
        .unwrap_err()
        .contains("directed broadcast address"));

    // 4. Concrete Boundary Requirement for Local Enforcement (Permissive mode cannot target arbitrary Internet IPs)
    let out_ip = Ipv4Addr::new(8, 8, 8, 8);
    let res_out = validator.validate_target(&out_ip, None, AdmissionOperation::LocalEnforcement);
    assert!(res_out.is_err());
    assert!(res_out
        .unwrap_err()
        .contains("outside authorized network boundary CIDRs"));

    // 5. Valid in-boundary target accepted
    let valid_ip = Ipv4Addr::new(192, 168, 1, 50);
    let valid_mac: MacAddress = "00:AA:BB:CC:DD:EE".parse().unwrap();
    assert!(validator
        .validate_target(
            &valid_ip,
            Some(&valid_mac),
            AdmissionOperation::LocalEnforcement
        )
        .is_ok());

    // 6. Router Policy validation
    assert!(validator
        .validate_target(
            &valid_ip,
            Some(&valid_mac),
            AdmissionOperation::RouterPolicy
        )
        .is_ok());
    // Router policy also forbids targeting gateway or controller
    assert!(validator
        .validate_target(&ctrl_ip, None, AdmissionOperation::RouterPolicy)
        .is_err());
    assert!(validator
        .validate_target(&gw_ip, None, AdmissionOperation::RouterPolicy)
        .is_err());
}

#[test]
fn test_saved_scope_sanitization_and_fallback() {
    let mut scope = ScopeManager::new();
    scope.allowed_cidrs.push(Ipv4Cidr {
        network: Ipv4Addr::new(0, 0, 0, 0),
        prefix: 0,
    });
    scope.allowed_cidrs.push(Ipv4Cidr {
        network: Ipv4Addr::new(127, 0, 0, 0),
        prefix: 8,
    });
    scope.allowed_cidrs.push(Ipv4Cidr {
        network: Ipv4Addr::new(224, 0, 0, 0),
        prefix: 4,
    });
    scope.allowed_cidrs.push(Ipv4Cidr {
        network: Ipv4Addr::new(255, 255, 255, 255),
        prefix: 32,
    });

    scope.sanitize();
    assert!(
        scope.allowed_cidrs.is_empty(),
        "All malformed / non-routable CIDRs must be purged"
    );
}

#[test]
fn test_atomic_enforcement_fail_closed_without_injection_driver() {
    let mut cli = RustrictCli::new_for_testing();

    let target_ip = Ipv4Addr::new(127, 0, 0, 42);
    let target_mac: MacAddress = "00:11:22:33:44:55".parse().unwrap();
    let host = Host::new(
        0,
        target_ip,
        target_mac,
        "Test Host".into(),
        "Vendor".into(),
    );
    cli.add_host(host);

    // Testing CLI has inactive spoofer (has_sender() == false).
    // Attempting to block must fail closed immediately.
    cli.handle_block(&["0"]);

    // Host status must NOT be mutated to Blocked
    assert_eq!(cli.hosts()[0].status, HostStatus::Free);
    assert!(!cli.hosts()[0].persistent_block);
}

#[test]
fn test_read_only_router_lab_mode_semantics() {
    let iface = NetworkInterface {
        name: "EthernetLab".into(),
        description: "Test Lab Adapter".into(),
        ip: Ipv4Addr::new(192, 168, 1, 10),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        gateway: Ipv4Addr::new(192, 168, 1, 1),
        gateway_mac: "00:11:22:33:44:01".parse().unwrap(),
        mac: "00:11:22:33:44:02".parse().unwrap(),
        device_path: "\\Device\\NPF_TestLab".into(),
    };

    let mut cli = RustrictCli::new_router_lab(iface);
    assert!(cli.is_router_lab, "Must be flagged as router-lab mode");

    let target_ip = Ipv4Addr::new(192, 168, 1, 50);
    let target_mac: MacAddress = "00:AA:BB:CC:DD:50".parse().unwrap();
    let host_id = cli.hosts().len();
    let host = Host::new(
        host_id,
        target_ip,
        target_mac,
        "Lab Client".into(),
        "Lab Vendor".into(),
    );
    cli.add_host(host);

    let id_str = host_id.to_string();

    // 1. Destructive local commands must be rejected in router-lab mode
    cli.handle_block(&[&id_str]);
    let target_host = cli.hosts().iter().find(|h| h.ip == target_ip).unwrap();
    assert_eq!(target_host.status, HostStatus::Free);

    cli.handle_limit(&[&id_str, "1mbps"]);
    let target_host = cli.hosts().iter().find(|h| h.ip == target_ip).unwrap();
    assert_eq!(target_host.status, HostStatus::Free);

    cli.handle_simulate(&[&id_str, "drop", "20"]);
    let target_host = cli.hosts().iter().find(|h| h.ip == target_ip).unwrap();
    assert_eq!(target_host.status, HostStatus::Free);

    // 2. Read-only router commands must still be functional
    cli.handle_router(&["providers"]);
    cli.handle_router(&["status"]);
    cli.handle_router(&["inventory"]);
}

#[test]
fn test_idempotent_free_operations() {
    let mut cli = RustrictCli::new_for_testing();
    let target_ip = Ipv4Addr::new(127, 0, 0, 42);
    let target_mac: MacAddress = "00:11:22:33:44:55".parse().unwrap();
    let host = Host::new(
        0,
        target_ip,
        target_mac,
        "Test Host".into(),
        "Vendor".into(),
    );
    cli.add_host(host);

    // Calling free on a free host multiple times is completely idempotent
    cli.handle_free(&["0"]);
    assert_eq!(cli.hosts()[0].status, HostStatus::Free);
    cli.handle_free(&["0"]);
    assert_eq!(cli.hosts()[0].status, HostStatus::Free);
}

#[test]
fn test_transactional_multi_target_activation_and_rollback() {
    let mut cli = RustrictCli::new_with_dummy_injection_for_testing();

    // Configure a known operational scope
    let cidr = Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
    let mut scope = ScopeManager::new();
    scope.add_cidr_direct(cidr);

    // Host 1: completely valid target
    let h1_ip = Ipv4Addr::new(192, 168, 1, 51);
    let h1_mac: MacAddress = "00:AA:BB:CC:DD:51".parse().unwrap();
    let h1 = Host::new(0, h1_ip, h1_mac, "Host1".into(), "Vendor1".into());

    // Host 2: valid in admission scope, but triggers spoofer.add failure
    let h2_ip = Ipv4Addr::new(192, 168, 1, 52);
    let conflict_mac: MacAddress = "00:99:88:77:66:55".parse().unwrap();
    let h2 = Host::new(1, h2_ip, conflict_mac, "Host2".into(), "Vendor2".into());

    cli.add_host(h1);
    cli.add_host(h2);

    // Initialize spoofer with conflict_mac as gateway_mac so spoofer.add fails on Host 2
    cli.set_spoofer(
        rustrict::spoofer::ArpSpoofer::new_with_dummy_sender_for_testing(
            cli.iface().mac,
            cli.iface().gateway,
            conflict_mac,
        ),
    );

    // Attempt multi-target block: block 0,1
    cli.handle_block(&["0,1"]);

    // TRANSACTION INTEGRITY CHECK:
    // Host 1 succeeded initially in spoofer.add, but Host 2 failed.
    // Host 1 must be ROLLED BACK from spoofer and limiter!
    // Neither host may be in Blocked status!
    assert_eq!(
        cli.hosts()[0].status,
        HostStatus::Free,
        "Host 1 status must remain Free after transaction rollback"
    );
    assert!(!cli.hosts()[0].persistent_block);

    assert_eq!(
        cli.hosts()[1].status,
        HostStatus::Free,
        "Host 2 status must remain Free after transaction failure"
    );
    assert!(!cli.hosts()[1].persistent_block);
}
