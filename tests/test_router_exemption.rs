use rustrict::gateway::admin::mock::MockRouterAdminProvider;
use rustrict::resilience::router_exemption::RouterExemptionManager;
use rustrict::types::MacAddress;
use std::net::Ipv4Addr;
use std::sync::Arc;

#[test]
fn test_router_admin_exemption_lifecycle() {
    let mock = Arc::new(MockRouterAdminProvider::new(Ipv4Addr::new(192, 168, 1, 1)));
    let manager = RouterExemptionManager::new(mock.clone());

    let operator_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let operator_ip = Ipv4Addr::new(192, 168, 1, 100);

    // Initial state: not exempt
    assert!(!manager.is_exempt(operator_mac));

    // Enforce exemption
    let rule_id = manager.enforce_exemption(operator_mac, operator_ip).unwrap();
    assert!(!rule_id.is_empty());

    // Verified exempt
    assert!(manager.is_exempt(operator_mac));
}
