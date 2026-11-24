use rustrict::probes::attack_graph::{AttackEdge, AttackGraph, AttackNode};
use std::net::Ipv4Addr;

#[test]
fn test_attack_graph_pathfinding_to_crown_jewel() {
    let mut graph = AttackGraph::new();

    let workstation_ip = Ipv4Addr::new(192, 168, 1, 50);
    let dev_server_ip = Ipv4Addr::new(192, 168, 1, 20);
    let router_admin_ip = Ipv4Addr::new(192, 168, 1, 1);

    let node_entry = AttackNode::Host(workstation_ip);
    let node_dev = AttackNode::Host(dev_server_ip);
    let node_admin = AttackNode::CrownJewel(router_admin_ip);

    graph.add_node(node_entry.clone());
    graph.add_node(node_dev.clone());
    graph.add_node(node_admin.clone());

    // Lateral move from workstation to dev server via unencrypted telnet
    graph.add_edge(node_entry.clone(), node_dev.clone(), AttackEdge::LateralMovement("telnet:23".into()));

    // Privilege escalation from dev server to router admin via weak default credentials
    graph.add_edge(node_dev.clone(), node_admin.clone(), AttackEdge::PrivilegeEscalation("default_ssh_key".into()));

    // 1. Path finding from entry to crown jewel
    let paths = graph.find_paths_to_crown_jewel(&node_entry);
    assert_eq!(paths.len(), 1);
    let path = &paths[0];
    assert_eq!(path.len(), 3);
    assert_eq!(path[0], node_entry);
    assert_eq!(path[1], node_dev);
    assert_eq!(path[2], node_admin);

    // 2. Disconnected node should have no path
    let isolated_node = AttackNode::Host(Ipv4Addr::new(192, 168, 1, 99));
    graph.add_node(isolated_node.clone());
    let empty_paths = graph.find_paths_to_crown_jewel(&isolated_node);
    assert!(empty_paths.is_empty());
}
