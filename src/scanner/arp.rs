use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use rayon::prelude::*;
use crate::types::{Host, MacAddress};
use crate::platform;
use crate::resolver;

pub struct SubnetScanner {
    pub local_ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub gateway_client: Option<Arc<crate::gateway::GatewayClient>>,
}

impl SubnetScanner {
    pub fn new(local_ip: Ipv4Addr, netmask: Ipv4Addr, gateway_ip: Ipv4Addr) -> Self {
        Self {
            local_ip,
            netmask,
            gateway_ip,
            gateway_client: Some(Arc::new(crate::gateway::GatewayClient::new(gateway_ip))),
        }
    }

    pub fn scan_subnet<F>(&self, fresh: bool, on_progress: F) -> Vec<Host>
    where
        F: Fn(usize, usize, usize) + Sync + Send,
    {
        let ip_u32 = u32::from(self.local_ip);
        let mask_u32 = u32::from(self.netmask);

        let network_u32 = ip_u32 & mask_u32;
        let broadcast_u32 = network_u32 | (!mask_u32);

        let first_ip = network_u32 + 1;
        let last_ip = broadcast_u32 - 1;

        if first_ip >= last_ip {
            return Vec::new();
        }

        let ip_list: Vec<Ipv4Addr> = (first_ip..=last_ip)
            .map(Ipv4Addr::from)
            .collect();

        self.scan_ip_list(&ip_list, fresh, on_progress)
    }

    pub fn scan_range<F>(&self, start: Ipv4Addr, end: Ipv4Addr, fresh: bool, on_progress: F) -> Vec<Host>
    where
        F: Fn(usize, usize, usize) + Sync + Send,
    {
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);

        if start_u32 > end_u32 {
            return Vec::new();
        }

        let ip_list: Vec<Ipv4Addr> = (start_u32..=end_u32)
            .map(Ipv4Addr::from)
            .collect();

        self.scan_ip_list(&ip_list, fresh, on_progress)
    }

    fn scan_ip_list<F>(&self, ip_list: &[Ipv4Addr], fresh: bool, on_progress: F) -> Vec<Host>
    where
        F: Fn(usize, usize, usize) + Sync + Send,
    {
        // 1. Asynchronously query router gateway UPnP / TR-064 client list if available
        if let Some(ref gc) = self.gateway_client {
            if !gc.has_queried() {
                let gc_clone = Arc::clone(gc);
                std::thread::spawn(move || {
                    gc_clone.refresh_hosts();
                });
            }
        }

        let total = ip_list.len();
        let scanned = Arc::new(AtomicUsize::new(0));
        let discovered_count = Arc::new(AtomicUsize::new(0));

        let mut host_map: HashMap<Ipv4Addr, MacAddress> = HashMap::new();

        // If not in fresh mode, seed with existing kernel ARP table cache for speed
        if !fresh {
            for (cached_ip, cached_mac) in platform::get_arp_cache() {
                if ip_list.contains(&cached_ip) {
                    host_map.insert(cached_ip, cached_mac);
                }
            }
        }
        discovered_count.store(host_map.len(), Ordering::SeqCst);

        // 2. Parallel ARP probe for all IPs in range
        let scanned_clone = Arc::clone(&scanned);
        let disc_clone = Arc::clone(&discovered_count);
        let progress_ref = &on_progress;

        let mut probed_results: Vec<(Ipv4Addr, MacAddress)> = Vec::new();
        // Chunk into batches of 48 to avoid router ARP storm/flood drops
        for chunk in ip_list.chunks(48) {
            let chunk_res: Vec<(Ipv4Addr, MacAddress)> = chunk
                .par_iter()
                .filter_map(|&ip| {
                    let mac_opt = platform::send_arp(ip);
                    let current_scanned = scanned_clone.fetch_add(1, Ordering::Relaxed) + 1;

                    if let Some(mac) = mac_opt {
                        disc_clone.fetch_add(1, Ordering::Relaxed);
                        let curr_disc = disc_clone.load(Ordering::Relaxed);
                        progress_ref(current_scanned, total, curr_disc);
                        Some((ip, mac))
                    } else {
                        let curr_disc = disc_clone.load(Ordering::Relaxed);
                        if current_scanned % 5 == 0 || current_scanned == total {
                            progress_ref(current_scanned, total, curr_disc);
                        }
                        None
                    }
                })
                .collect();
            probed_results.extend(chunk_res);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        for (ip, mac) in probed_results {
            host_map.insert(ip, mac);
        }

        // Final progress update
        on_progress(total, total, host_map.len());

        // 3. Multi-protocol parallel identity resolution
        let host_pairs: Vec<(Ipv4Addr, MacAddress)> = host_map.into_iter().collect();
        let local_ip = self.local_ip;
        let gateway_ip = self.gateway_ip;
        let gc_ref = self.gateway_client.as_deref();

        let mut hosts: Vec<Host> = host_pairs
            .into_par_iter()
            .enumerate()
            .map(|(id, (ip, mac))| {
                let identity = resolver::resolve_identity_with_gateway(ip, &mac, local_ip, gateway_ip, gc_ref);
                Host::with_source(
                    id,
                    ip,
                    mac,
                    identity.hostname,
                    identity.source,
                    identity.vendor,
                )
            })
            .collect();

        // Sort by IP address ascending
        hosts.sort_by_key(|h| u32::from(h.ip));
        for (i, host) in hosts.iter_mut().enumerate() {
            host.id = i;
        }

        hosts
    }
}
