use crate::types::MacAddress;

#[derive(Debug, Clone)]
pub struct WpaHandshakeEvent {
    pub bssid: MacAddress,
    pub station: MacAddress,
    pub message_num: u8, // 1, 2, 3, or 4
    pub has_pmkid: bool,
    pub pmkid: Option<[u8; 16]>,
}

/// Checks if an LLC/SNAP packet is EAPOL (802.1X Authentication)
pub fn is_eapol_frame(payload: &[u8]) -> bool {
    // Look for EtherType 0x888E in LLC/SNAP header or raw Ethernet
    let eapol_ethertype = [0x88, 0x8e];
    payload.windows(2).any(|w| w == eapol_ethertype)
}

/// Inspects an EAPOL-Key packet to determine handshake message number and PMKID
pub fn inspect_eapol_key(
    payload: &[u8],
    bssid: MacAddress,
    station: MacAddress,
) -> Option<WpaHandshakeEvent> {
    let eapol_ethertype = [0x88, 0x8e];
    let pos = payload.windows(2).position(|w| w == eapol_ethertype)?;
    let eapol_body = &payload[pos + 2..];

    if eapol_body.len() < 99 {
        return None;
    }

    // EAPOL Version (1 byte), Type (1 byte: 3 = Key)
    if eapol_body[1] != 3 {
        return None;
    }

    // Key Information field (2 bytes big-endian)
    let key_info = u16::from_be_bytes([eapol_body[5], eapol_body[6]]);
    let is_pairwise = (key_info & (1 << 3)) != 0;
    let is_install = (key_info & (1 << 6)) != 0;
    let is_ack = (key_info & (1 << 7)) != 0;
    let is_mic = (key_info & (1 << 8)) != 0;

    let message_num = if is_pairwise && is_ack && !is_mic && !is_install {
        1 // Message 1 (AP -> Station)
    } else if is_pairwise && !is_ack && is_mic && !is_install {
        2 // Message 2 (Station -> AP)
    } else if is_pairwise && is_ack && is_mic && is_install {
        3 // Message 3 (AP -> Station)
    } else if is_pairwise && !is_ack && is_mic {
        4 // Message 4 (Station -> AP)
    } else {
        0
    };

    // Check for PMKID in Message 1 RSN KDE: OUI 00-0F-AC, DataType 04
    let mut pmkid = None;
    let rsn_pmkid_tag = [0x00, 0x0f, 0xac, 0x04];
    if let Some(tag_pos) = eapol_body.windows(4).position(|w| w == rsn_pmkid_tag) {
        if tag_pos + 4 + 16 <= eapol_body.len() {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&eapol_body[tag_pos + 4..tag_pos + 20]);
            pmkid = Some(bytes);
        }
    }

    let has_pmkid = pmkid.is_some();

    Some(WpaHandshakeEvent {
        bssid,
        station,
        message_num,
        has_pmkid,
        pmkid,
    })
}
