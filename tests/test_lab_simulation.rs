use rustrict::core::lab_simulation::{
    LabSecurityError, LabSimulationConfig, LabSimulationRunner, PrivilegeVector,
};
use rustrict::core::scope::ScopeConfig;
use std::net::Ipv4Addr;

#[test]
fn test_lab_simulation_scope_gate_and_execution() {
    let mut scope = ScopeConfig::new();
    scope.allowed_cidrs.push("192.168.100.0/24".parse().unwrap());
    let excluded_ip = Ipv4Addr::new(192, 168, 100, 1); // e.g. production gateway excluded
    scope.excluded_ips.insert(excluded_ip);

    let runner = LabSimulationRunner::new();

    // 1. Target outside allowed CIDR must fail-closed
    let out_of_scope_target = Ipv4Addr::new(10, 0, 0, 5);
    let cfg_out = LabSimulationConfig {
        target_ip: out_of_scope_target,
        vector: PrivilegeVector::DefaultCredentials,
    };
    let err_out = runner.run_simulation(&cfg_out, &scope).unwrap_err();
    assert_eq!(err_out, LabSecurityError::TargetOutOfScope(out_of_scope_target));

    // 2. Target inside allowed CIDR but in excluded list must fail-closed
    let cfg_excluded = LabSimulationConfig {
        target_ip: excluded_ip,
        vector: PrivilegeVector::WeakServicePermissions,
    };
    let err_excluded = runner.run_simulation(&cfg_excluded, &scope).unwrap_err();
    assert_eq!(err_excluded, LabSecurityError::TargetExplicitlyExcluded(excluded_ip));

    // 3. Authorized target within lab CIDR executes safe simulation
    let valid_lab_target = Ipv4Addr::new(192, 168, 100, 50);
    let cfg_valid = LabSimulationConfig {
        target_ip: valid_lab_target,
        vector: PrivilegeVector::DefaultCredentials,
    };
    let result = runner.run_simulation(&cfg_valid, &scope).expect("Lab simulation should succeed");
    assert_eq!(result.target_ip, valid_lab_target);
    assert!(result.detected_by_blue_team);
    assert!(!result.audit_log.is_empty());
}
