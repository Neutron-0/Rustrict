use serde::{Deserialize, Serialize};

/// Represents a parsed DNS question entry extracted from a UDP DNS packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQuery {
    pub tx_id: u16,
    pub qname: String,
    pub qtype: u16,
}

/// Zero-copy DNS protocol dissector for live packet monitoring.
pub struct DnsDissector;

impl DnsDissector {
    /// Extracts transaction ID, queried domain name, and query type from a DNS payload.
    pub fn parse_query(payload: &[u8]) -> Option<DnsQuery> {
        if payload.len() < 12 {
            return None;
        }

        let tx_id = u16::from_be_bytes([payload[0], payload[1]]);
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        if qdcount == 0 {
            return None;
        }

        let mut offset = 12;
        let mut labels = Vec::new();

        while offset < payload.len() {
            let len = payload[offset] as usize;
            if len == 0 {
                offset += 1;
                break;
            }
            // Standard DNS labels are limited to 63 bytes; pointer compression (0xC0) in query is invalid
            if len >= 64 || offset + 1 + len > payload.len() {
                return None;
            }
            offset += 1;
            let label = std::str::from_utf8(&payload[offset..offset + len]).ok()?;
            labels.push(label);
            offset += len;
        }

        if offset + 4 > payload.len() {
            return None;
        }

        let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let qname = labels.join(".");

        Some(DnsQuery { tx_id, qname, qtype })
    }
}
