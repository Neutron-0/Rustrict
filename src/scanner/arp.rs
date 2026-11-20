use crate::platform;
use crate::resolver;
use crate::types::{Host, MacAddress};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Trait providing network probing and ARP table access for SubnetScanner
pub trait NetworkProbe: Send + Sync {
    fn send_arp(&self, ip: Ipv4Addr) -> Option<MacAddress>;
    fn get_arp_cache(&self) -> Vec<(Ipv4Addr, MacAddress)>;
    fn resolve_identity(
        &self,
        ip: Ipv4Addr,
        mac: &MacAddress,
        local_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        gateway_client: Option<&crate::gateway::GatewayClient>,
    ) -> resolver::HostIdentity;
}

/// Default real platform probe that invokes the OS network stack
#[derive(Debug, Default, Clone, Copy)]
pub struct RealNetworkProbe;

impl NetworkProbe for RealNetworkProbe {
    fn send_arp(&self, ip: Ipv4Addr) -> Option<MacAddress> {
        platform::send_arp(ip)
    }

    fn get_arp_cache(&self) -> Vec<(Ipv4Addr, MacAddress)> {
        platform::get_arp_cache()
    }

    fn resolve_identity(
        &self,
        ip: Ipv4Addr,
        mac: &MacAddress,
        local_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        gateway_client: Option<&crate::gateway::GatewayClient>,
    ) -> resolver::HostIdentity {
        resolver::resolve_identity_with_gateway(ip, mac, local_ip, gateway_ip, gateway_client)
    }
}

pub struct SubnetScanner {
    pub local_ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub gateway_client: Option<Arc<crate::gateway::GatewayClient>>,
    probe: Arc<dyn NetworkProbe>,
}

impl SubnetScanner {
    /// Creates a production scanner with real network probe and real gateway client
    pub fn new(local_ip: Ipv4Addr, netmask: Ipv4Addr, gateway_ip: Ipv4Addr) -> Self {
        Self {
            local_ip,
            netmask,
            gateway_ip,
            gateway_client: Some(Arc::new(crate::gateway::GatewayClient::new(gateway_ip))),
            probe: Arc::new(RealNetworkProbe),
        }
    }

    /// Creates a scanner with a custom network probe and optional gateway client for hermetic testing
    pub fn new_with_probe(
        local_ip: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        gateway_client: Option<Arc<crate::gateway::GatewayClient>>,
        probe: Arc<dyn NetworkProbe>,
    ) -> Self {
        Self {
            local_ip,
            netmask,
            gateway_ip,
            gateway_client,
            probe,
        }
    }

    /// Creates a safe testing scanner that performs zero network I/O, zero ARP packets, and zero gateway discovery
    pub fn new_safe_test(local_ip: Ipv4Addr, netmask: Ipv4Addr, gateway_ip: Ipv4Addr) -> Self {
        Self {
            local_ip,
            netmask,
            gateway_ip,
            gateway_client: None,
            probe: Arc::new(NoopNetworkProbe),
        }
    }

    /// Calculates the bounded IP address list for the configured subnet
    pub fn calculate_subnet_ip_range(&self) -> Vec<Ipv4Addr> {
        let ip_u32 = u32::from(self.local_ip);
        let mask_u32 = u32::from(self.netmask);

        let network_u32 = ip_u32 & mask_u32;
        let broadcast_u32 = network_u32 | (!mask_u32);
        let prefix_len = mask_u32.count_ones();

        let (first_ip, last_ip) = match prefix_len {
            32 => (network_u32, network_u32),
            31 => (network_u32, broadcast_u32), // RFC 3021 point-to-point links
            _ => (
                network_u32.saturating_add(1),
                broadcast_u32.saturating_sub(1),
            ),
        };

        if first_ip > last_ip {
            return Vec::new();
        }

        // Bound automatic subnet scan to at most /16 (65,534 hosts) to prevent memory exhaustion and network DOS
        let max_hosts = 65534u32;
        let bounded_last = if last_ip.saturating_sub(first_ip) >= max_hosts {
            first_ip.saturating_add(max_hosts).saturating_sub(1)
        } else {
            last_ip
        };

        (first_ip..=bounded_last).map(Ipv4Addr::from).collect()
    }

    /// Calculates the bounded IP address list for an arbitrary start and end IP range
    pub fn calculate_bounded_range(&self, start: Ipv4Addr, end: Ipv4Addr) -> Vec<Ipv4Addr> {
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);

        if start_u32 > end_u32 {
            return Vec::new();
        }

        let max_hosts = 65534u32;
        let bounded_end = if end_u32.saturating_sub(start_u32) >= max_hosts {
            start_u32.saturating_add(max_hosts).saturating_sub(1)
        } else {
            end_u32
        };

        (start_u32..=bounded_end).map(Ipv4Addr::from).collect()
    }

    pub fn scan_subnet_with_phases<F, R>(
        &self,
        fresh: bool,
        on_progress: F,
        on_resolve_progress: R,
    ) -> Vec<Host>
    where
        F: Fn(usize, usize, usize) + Sync + Send,
        R: Fn(usize, usize) + Sync + Send,
    {
        let ip_list = self.calculate_subnet_ip_range();
        if ip_list.is_empty() {
            return Vec::new();
        }

        self.scan_ip_list_with_phases(&ip_list, fresh, on_progress, on_resolve_progress)
    }

    pub fn scan_subnet<F>(&self, fresh: bool, on_progress: F) -> Vec<Host>
    where
        F: Fn(usize, usize, usize) + Sync + Send,
    {
        self.scan_subnet_with_phases(fresh, on_progress, |_, _| {})
    }

    pub fn scan_range_with_phases<F, R>(
        &self,
        start: Ipv4Addr,
        end: Ipv4Addr,
        fresh: bool,
        on_progress: F,
        on_resolve_progress: R,
    ) -> Vec<Host>
    where
        F: Fn(usize, usize, usize) + Sync + Send,
        R: Fn(usize, usize) + Sync + Send,
    {
        let ip_list = self.calculate_bounded_range(start, end);
        if ip_list.is_empty() {
            return Vec::new();
        }

        self.scan_ip_list_with_phases(&ip_list, fresh, on_progress, on_resolve_progress)
    }

    pub fn scan_range<F>(
        &self,
        start: Ipv4Addr,
        end: Ipv4Addr,
        fresh: bool,
        on_progress: F,
    ) -> Vec<Host>
    where
        F: Fn(usize, usize, usize) + Sync + Send,
    {
        self.scan_range_with_phases(start, end, fresh, on_progress, |_, _| {})
    }

    fn scan_ip_list_with_phases<F, R>(
        &self,
        ip_list: &[Ipv4Addr],
        fresh: bool,
        on_progress: F,
        on_resolve_progress: R,
    ) -> Vec<Host>
    where
        F: Fn(usize, usize, usize) + Sync + Send,
        R: Fn(usize, usize) + Sync + Send,
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
        let mut cached_ips: HashSet<Ipv4Addr> = HashSet::new();

        // If not in fresh mode, seed with existing kernel ARP table cache for speed
        if !fresh {
            for (cached_ip, cached_mac) in self.probe.get_arp_cache() {
                if ip_list.contains(&cached_ip) {
                    cached_ips.insert(cached_ip);
                    host_map.insert(cached_ip, cached_mac);
                }
            }
        }
        discovered_count.store(host_map.len(), Ordering::SeqCst);

        // 2. High-concurrency parallel ARP probe for all IPs in range
        let num_threads = 256.min(total.max(16));
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .unwrap_or_else(|_| rayon::ThreadPoolBuilder::new().build().unwrap());

        let scanned_clone = Arc::clone(&scanned);
        let disc_clone = Arc::clone(&discovered_count);
        let progress_ref = &on_progress;
        let cached_ips_ref = &cached_ips;
        let probe = Arc::clone(&self.probe);

        let probed_results: Vec<(Ipv4Addr, MacAddress)> = pool.install(|| {
            ip_list
                .par_iter()
                .filter_map(|&ip| {
                    // Fast path: if already discovered in kernel ARP cache, reuse cached MAC
                    if let Some(&cached_mac) = host_map.get(&ip) {
                        let current_scanned = scanned_clone.fetch_add(1, Ordering::Relaxed) + 1;
                        let curr_disc = disc_clone.load(Ordering::Relaxed);
                        if current_scanned.is_multiple_of(5) || current_scanned == total {
                            progress_ref(current_scanned, total, curr_disc);
                        }
                        return Some((ip, cached_mac));
                    }

                    let mac_opt = probe.send_arp(ip);
                    let current_scanned = scanned_clone.fetch_add(1, Ordering::Relaxed) + 1;

                    if let Some(mac) = mac_opt {
                        if !cached_ips_ref.contains(&ip) {
                            disc_clone.fetch_add(1, Ordering::Relaxed);
                        }
                        let curr_disc = disc_clone.load(Ordering::Relaxed);
                        progress_ref(current_scanned, total, curr_disc);
                        Some((ip, mac))
                    } else {
                        let curr_disc = disc_clone.load(Ordering::Relaxed);
                        if current_scanned.is_multiple_of(5) || current_scanned == total {
                            progress_ref(current_scanned, total, curr_disc);
                        }
                        None
                    }
                })
                .collect()
        });

        for (ip, mac) in probed_results {
            host_map.insert(ip, mac);
        }

        // Final progress update for ARP discovery phase
        on_progress(total, total, host_map.len());

        // 3. Multi-protocol high-concurrency parallel identity resolution
        let host_pairs: Vec<(Ipv4Addr, MacAddress)> = host_map.into_iter().collect();
        let total_hosts = host_pairs.len();
        let resolved_count = Arc::new(AtomicUsize::new(0));
        let local_ip = self.local_ip;
        let gateway_ip = self.gateway_ip;
        let gc_ref = self.gateway_client.as_deref();
        let probe = Arc::clone(&self.probe);
        let res_progress_ref = &on_resolve_progress;

        res_progress_ref(0, total_hosts);

        let mut hosts: Vec<Host> = pool.install(|| {
            host_pairs
                .into_par_iter()
                .enumerate()
                .map(|(id, (ip, mac))| {
                    let identity = probe.resolve_identity(ip, &mac, local_ip, gateway_ip, gc_ref);
                    let curr = resolved_count.fetch_add(1, Ordering::Relaxed) + 1;
                    if curr.is_multiple_of(5) || curr == total_hosts {
                        res_progress_ref(curr, total_hosts);
                    }
                    Host::with_source(
                        id,
                        ip,
                        mac,
                        identity.hostname,
                        identity.source,
                        identity.vendor,
                    )
                })
                .collect()
        });

        // Sort by IP address ascending
        hosts.sort_by_key(|h| u32::from(h.ip));
        for (i, host) in hosts.iter_mut().enumerate() {
            host.id = i;
        }

        hosts
    }
}

/// No-op network probe for hermetic unit testing that performs zero network I/O
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopNetworkProbe;

impl NetworkProbe for NoopNetworkProbe {
    fn send_arp(&self, _ip: Ipv4Addr) -> Option<MacAddress> {
        None
    }

    fn get_arp_cache(&self) -> Vec<(Ipv4Addr, MacAddress)> {
        Vec::new()
    }

    fn resolve_identity(
        &self,
        ip: Ipv4Addr,
        _mac: &MacAddress,
        local_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        _gateway_client: Option<&crate::gateway::GatewayClient>,
    ) -> resolver::HostIdentity {
        if ip == gateway_ip {
            resolver::HostIdentity {
                hostname: "Gateway".into(),
                source: crate::types::NameSource::Gateway,
                vendor: "TestVendor".into(),
            }
        } else if ip == local_ip {
            resolver::HostIdentity {
                hostname: "LocalHost".into(),
                source: crate::types::NameSource::Local,
                vendor: "Local Host".into(),
            }
        } else {
            resolver::HostIdentity {
                hostname: String::new(),
                source: crate::types::NameSource::Unresolved,
                vendor: "TestDevice".into(),
            }
        }
    }
}

/// Deterministic mock probe for testing scanning and discovery flows with simulated hosts
pub struct MockNetworkProbe {
    pub simulated_hosts: HashMap<Ipv4Addr, MacAddress>,
    pub arp_calls: Arc<AtomicUsize>,
}

impl MockNetworkProbe {
    pub fn new(hosts: HashMap<Ipv4Addr, MacAddress>) -> Self {
        Self {
            simulated_hosts: hosts,
            arp_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl NetworkProbe for MockNetworkProbe {
    fn send_arp(&self, ip: Ipv4Addr) -> Option<MacAddress> {
        self.arp_calls.fetch_add(1, Ordering::SeqCst);
        self.simulated_hosts.get(&ip).copied()
    }

    fn get_arp_cache(&self) -> Vec<(Ipv4Addr, MacAddress)> {
        Vec::new()
    }

    fn resolve_identity(
        &self,
        ip: Ipv4Addr,
        _mac: &MacAddress,
        local_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        _gateway_client: Option<&crate::gateway::GatewayClient>,
    ) -> resolver::HostIdentity {
        if ip == gateway_ip {
            resolver::HostIdentity {
                hostname: "Test Gateway".into(),
                source: crate::types::NameSource::Gateway,
                vendor: "SimulatedGateway".into(),
            }
        } else if ip == local_ip {
            resolver::HostIdentity {
                hostname: "Test Host".into(),
                source: crate::types::NameSource::Local,
                vendor: "SimulatedHost".into(),
            }
        } else {
            resolver::HostIdentity {
                hostname: format!("host-{}", ip),
                source: crate::types::NameSource::Dns,
                vendor: "SimulatedVendor".into(),
            }
        }
    }
}
