/// Dissector for extracting Server Name Indication (SNI) hostnames from TLS ClientHello records.
pub struct TlsSniDissector;

impl TlsSniDissector {
    /// Inspects raw TCP payload bytes, verifies TLS record framing, and parses ClientHello extensions for SNI.
    pub fn extract_sni(payload: &[u8]) -> Option<String> {
        if payload.len() < 5 || payload[0] != 0x16 {
            // Must be TLS record type 0x16 (Handshake)
            return None;
        }

        let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
        let record_end = 5 + record_len;
        if payload.len() < record_end {
            return None;
        }

        let mut offset = 5;
        // Handshake type: 0x01 == ClientHello
        if offset >= record_end || payload[offset] != 0x01 {
            return None;
        }
        offset += 1;

        // Handshake payload length (3 bytes)
        if offset + 3 > record_end {
            return None;
        }
        let hs_len = ((payload[offset] as usize) << 16)
            | ((payload[offset + 1] as usize) << 8)
            | (payload[offset + 2] as usize);
        offset += 3;
        if offset + hs_len > record_end {
            return None;
        }

        // ClientHello body: Version (2 bytes) + Random (32 bytes) = 34 bytes
        if offset + 34 > record_end {
            return None;
        }
        offset += 34;

        // Session ID length (1 byte) + Session ID
        if offset >= record_end {
            return None;
        }
        let session_id_len = payload[offset] as usize;
        offset += 1 + session_id_len;

        // Cipher suites length (2 bytes) + Cipher suites
        if offset + 2 > record_end {
            return None;
        }
        let cipher_suites_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2 + cipher_suites_len;

        // Compression methods length (1 byte) + Compression methods
        if offset >= record_end {
            return None;
        }
        let comp_len = payload[offset] as usize;
        offset += 1 + comp_len;

        // Extensions block length (2 bytes)
        if offset + 2 > record_end {
            return None;
        }
        let extensions_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        let ext_end = offset + extensions_len;
        if ext_end > record_end {
            return None;
        }

        // Iterate through TLS extensions
        while offset + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let ext_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
            offset += 4;
            if offset + ext_len > ext_end {
                return None;
            }

            if ext_type == 0x0000 {
                // Extension 0x0000: server_name (RFC 6066)
                if ext_len < 2 {
                    return None;
                }
                let mut sn_offset = offset + 2;
                let sn_end = offset + ext_len;
                while sn_offset + 3 <= sn_end {
                    let name_type = payload[sn_offset];
                    let name_len =
                        u16::from_be_bytes([payload[sn_offset + 1], payload[sn_offset + 2]])
                            as usize;
                    sn_offset += 3;
                    if sn_offset + name_len > sn_end {
                        return None;
                    }
                    if name_type == 0x00 {
                        // Type 0x00: host_name
                        return std::str::from_utf8(&payload[sn_offset..sn_offset + name_len])
                            .ok()
                            .map(|s| s.to_string());
                    }
                    sn_offset += name_len;
                }
            }

            offset += ext_len;
        }

        None
    }
}
