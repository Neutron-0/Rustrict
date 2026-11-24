use rustrict::gateway::admin::dhcp_dns::{DhcpLease, DnsForwardRule, RouterDhcpDnsManager};
use rustrict::gateway::admin::mock::MockRouterAdminProvider;
use rustrict::types::MacAddress;
use std::net::Ipv4Addr;
use std::sync::Arc;

#[test]
fn test_dhcp_leases_and_dns_forwarding() {
    let mock = Arc::new(MockRouterAdminProvider::new(Ipv4Addr::new(192, 168, 1, 1)));
    let manager = RouterDhcpDnsManager::new(mock.clone());

    // 1. Initial leases list
    let leases = manager.list_dhcp_leases().unwrap();
    assert!(leases.is_empty());

    // 2. Add static DHCP reservation
    let static_lease = DhcpLease {
        ip: Ipv4Addr::new(192, 168, 1, 50),
        mac: MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        hostname: Some("workstation-alpha".into()),
        expires_at: None,
        is_static: true,
    };
    manager.add_static_lease(static_lease.clone()).unwrap();

    let updated_leases = manager.list_dhcp_leases().unwrap();
    assert_eq!(updated_leases.len(), 1);
    assert_eq!(updated_leases[0].ip, static_lease.ip);
    assert!(updated_leases[0].is_static);

    // 3. DNS Forwarding Rule
    let dns_rule = DnsForwardRule {
        domain: "internal.lab".into(),
        target_ip: Ipv4Addr::new(192, 168, 1, 10),
        enabled: true,
    };
    manager.add_dns_forward_rule(dns_rule.clone()).unwrap();

    let dns_rules = manager.list_dns_forward_rules().unwrap();
    assert_eq!(dns_rules.len(), 1);
    assert_eq!(dns_rules[0].domain, "internal.lab");
    assert_eq!(dns_rules[0].target_ip, Ipv4Addr::new(192, 168, 1, 10));
}
