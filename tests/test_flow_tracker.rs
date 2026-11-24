use rustrict::monitor::flow_tracker::{FlowDirection, FlowKey, FlowTracker};
use std::net::Ipv4Addr;

#[test]
fn test_bidirectional_flow_tracking_and_reaping() {
    let mut tracker = FlowTracker::new(60); // 60 seconds idle timeout

    let client_ip = Ipv4Addr::new(192, 168, 1, 100);
    let server_ip = Ipv4Addr::new(93, 184, 216, 34);
    let client_port = 54321;
    let server_port = 443;
    let proto_tcp = 6u8;

    let forward_key = FlowKey {
        src_ip: client_ip,
        dst_ip: server_ip,
        src_port: client_port,
        dst_port: server_port,
        proto: proto_tcp,
    };

    // 1. Ingest forward packet
    let now = 1000u64;
    tracker.record_packet(&forward_key, 120, FlowDirection::Outbound, now);

    let stats = tracker.get_flow(&forward_key).expect("Flow should exist");
    assert_eq!(stats.bytes_sent, 120);
    assert_eq!(stats.packets_sent, 1);
    assert_eq!(stats.bytes_recv, 0);

    // 2. Ingest reverse packet (matching normalized conversation)
    let reverse_key = FlowKey {
        src_ip: server_ip,
        dst_ip: client_ip,
        src_port: server_port,
        dst_port: client_port,
        proto: proto_tcp,
    };
    tracker.record_packet(&reverse_key, 1400, FlowDirection::Inbound, now + 5);

    let updated_stats = tracker.get_flow(&forward_key).expect("Flow should exist");
    assert_eq!(updated_stats.bytes_sent, 120);
    assert_eq!(updated_stats.packets_sent, 1);
    assert_eq!(updated_stats.bytes_recv, 1400);
    assert_eq!(updated_stats.packets_recv, 1);

    // 3. Test active flows list
    assert_eq!(tracker.active_flows().len(), 1);

    // 4. Test reaping expired flows
    tracker.reap_idle_flows(now + 100); // 95s elapsed since last seen
    assert_eq!(tracker.active_flows().len(), 0);
}
