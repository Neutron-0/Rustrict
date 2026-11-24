use std::collections::HashMap;
use std::net::Ipv4Addr;
use serde::{Deserialize, Serialize};

use crate::types::MacAddress;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArpAlert {
    ConflictingMacMapping {
        ip: Ipv4Addr,
        old_mac: MacAddress,
        new_mac: MacAddress,
    },
}

#[derive(Debug, Clone)]
struct BindingRecord {
    mac: MacAddress,
    last_seen: u64,
}

/// Passive ARP spoofing and cache poisoning detector.
pub struct ArpSpoofDetector {
    bindings: HashMap<Ipv4Addr, BindingRecord>,
}

impl Default for ArpSpoofDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpSpoofDetector {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
        }
    }

    /// Evaluates an observed ARP mapping. If the IP was already bound to a different MAC,
    /// emits a ConflictingMacMapping security alert.
    pub fn process_arp_entry(
        &mut self,
        ip: Ipv4Addr,
        mac: MacAddress,
        now: u64,
    ) -> Option<ArpAlert> {
        if let Some(existing) = self.bindings.get_mut(&ip) {
            if existing.mac != mac {
                let alert = ArpAlert::ConflictingMacMapping {
                    ip,
                    old_mac: existing.mac,
                    new_mac: mac,
                };
                // Update record to current observation
                existing.mac = mac;
                existing.last_seen = now;
                return Some(alert);
            }
            existing.last_seen = now;
            None
        } else {
            self.bindings.insert(ip, BindingRecord { mac, last_seen: now });
            None
        }
    }
}
