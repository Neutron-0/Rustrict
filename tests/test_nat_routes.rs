use rustrict::gateway::admin::mock::MockRouterAdminProvider;
use rustrict::gateway::admin::nat_routes::{
    ForwardProtocol, PortForwardRule, RouterNatRouteManager, StaticRoute,
};
use std::net::Ipv4Addr;
use std::sync::Arc;

#[test]
fn test_nat_port_forwarding_and_routes() {
    let mock = Arc::new(MockRouterAdminProvider::new(Ipv4Addr::new(192, 168, 1, 1)));
    let manager = RouterNatRouteManager::new(mock.clone());

    // 1. Initial port forwards empty
    assert!(manager.list_port_forwards().unwrap().is_empty());

    // 2. Add port forward rule
    let rule = PortForwardRule {
        name: "SSH-Jumpbox".into(),
        proto: ForwardProtocol::Tcp,
        external_port: 2222,
        internal_ip: Ipv4Addr::new(192, 168, 1, 10),
        internal_port: 22,
        enabled: true,
    };
    manager.add_port_forward(rule.clone()).unwrap();

    let rules = manager.list_port_forwards().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "SSH-Jumpbox");
    assert_eq!(rules[0].external_port, 2222);

    // 3. Static routing table
    assert!(manager.list_static_routes().unwrap().is_empty());

    let route = StaticRoute {
        destination: Ipv4Addr::new(10, 20, 0, 0),
        netmask: Ipv4Addr::new(255, 255, 0, 0),
        gateway: Ipv4Addr::new(192, 168, 1, 254),
        interface: Some("eth0".into()),
        metric: 10,
    };
    manager.add_static_route(route.clone()).unwrap();

    let routes = manager.list_static_routes().unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].destination, Ipv4Addr::new(10, 20, 0, 0));
    assert_eq!(routes[0].metric, 10);
}
