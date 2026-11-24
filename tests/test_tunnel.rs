use rustrict::resilience::tunnel::{ResilientTunnel, ResilientTunnelConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn test_tunnel_handshake_and_heartbeat() {
    let psk = [0x42u8; 32];
    let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 51820);
    let config = ResilientTunnelConfig {
        endpoint,
        psk,
        keepalive_secs: 25,
    };

    let tunnel = ResilientTunnel::new(config);
    let nonce = 123456789u64;

    // 1. Handshake frame crafting and verification
    let handshake_packet = tunnel.craft_handshake(nonce);
    assert!(handshake_packet.len() >= 40); // 8-byte type/magic + 8-byte nonce + 32-byte HMAC/tag
    let verified_nonce = ResilientTunnel::verify_handshake(&handshake_packet, &psk).expect("Handshake should verify");
    assert_eq!(verified_nonce, nonce);

    // Tampered handshake should fail
    let mut bad_packet = handshake_packet.clone();
    bad_packet[10] ^= 0xFF;
    assert!(ResilientTunnel::verify_handshake(&bad_packet, &psk).is_err());

    // 2. Heartbeat frame crafting and verification
    let seq = 42u64;
    let heartbeat_packet = tunnel.craft_heartbeat(seq);
    let verified_seq = ResilientTunnel::verify_heartbeat(&heartbeat_packet, &psk).expect("Heartbeat should verify");
    assert_eq!(verified_seq, seq);

    // 3. Roaming update
    let roaming_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 51820);
    tunnel.update_roaming_endpoint(roaming_endpoint);
    assert_eq!(tunnel.current_endpoint(), roaming_endpoint);
}
