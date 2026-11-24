use std::collections::HashMap;
use std::net::Ipv4Addr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CanonicalFlowKey {
    endpoint_a: (Ipv4Addr, u16),
    endpoint_b: (Ipv4Addr, u16),
    proto: u8,
}

impl FlowKey {
    fn to_canonical(&self) -> (CanonicalFlowKey, bool) {
        let ep1 = (self.src_ip, self.src_port);
        let ep2 = (self.dst_ip, self.dst_port);
        if ep1 <= ep2 {
            (
                CanonicalFlowKey {
                    endpoint_a: ep1,
                    endpoint_b: ep2,
                    proto: self.proto,
                },
                true, // Original orientation matches canonical
            )
        } else {
            (
                CanonicalFlowKey {
                    endpoint_a: ep2,
                    endpoint_b: ep1,
                    proto: self.proto,
                },
                false,
            )
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowStats {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub start_time: u64,
    pub last_seen: u64,
}

pub struct FlowTracker {
    idle_timeout_secs: u64,
    table: HashMap<CanonicalFlowKey, (FlowKey, FlowStats)>,
}

impl FlowTracker {
    pub fn new(idle_timeout_secs: u64) -> Self {
        Self {
            idle_timeout_secs,
            table: HashMap::new(),
        }
    }

    /// Records an observed network packet against the bidirectional flow table.
    pub fn record_packet(
        &mut self,
        key: &FlowKey,
        bytes: u64,
        direction: FlowDirection,
        now: u64,
    ) {
        let (canonical, is_orig) = key.to_canonical();
        let entry = self.table.entry(canonical).or_insert_with(|| {
            let primary_key = if is_orig {
                *key
            } else {
                FlowKey {
                    src_ip: key.dst_ip,
                    dst_ip: key.src_ip,
                    src_port: key.dst_port,
                    dst_port: key.src_port,
                    proto: key.proto,
                }
            };
            (
                primary_key,
                FlowStats {
                    bytes_sent: 0,
                    bytes_recv: 0,
                    packets_sent: 0,
                    packets_recv: 0,
                    start_time: now,
                    last_seen: now,
                },
            )
        });

        match direction {
            FlowDirection::Outbound => {
                entry.1.bytes_sent += bytes;
                entry.1.packets_sent += 1;
            }
            FlowDirection::Inbound => {
                entry.1.bytes_recv += bytes;
                entry.1.packets_recv += 1;
            }
        }
        entry.1.last_seen = now;
    }

    /// Queries the flow statistics for a given 5-tuple key.
    pub fn get_flow(&self, key: &FlowKey) -> Option<&FlowStats> {
        let (canonical, _) = key.to_canonical();
        self.table.get(&canonical).map(|(_, stats)| stats)
    }

    /// Lists all currently active tracked network flows.
    pub fn active_flows(&self) -> Vec<(FlowKey, FlowStats)> {
        self.table.values().cloned().collect()
    }

    /// Reaps flows that have been idle longer than the configured timeout.
    pub fn reap_idle_flows(&mut self, now: u64) {
        let timeout = self.idle_timeout_secs;
        self.table
            .retain(|_, (_, stats)| now.saturating_sub(stats.last_seen) <= timeout);
    }
}
