pub mod hosts;
pub mod soap;
pub mod ssdp;

pub use hosts::GatewayHostEntry;
pub use soap::SoapClient;
pub use ssdp::SsdpScanner;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;

/// High-level client for discovering and querying the local network router gateway
pub struct GatewayClient {
    gateway_ip: Ipv4Addr,
    cache: Arc<RwLock<HashMap<Ipv4Addr, GatewayHostEntry>>>,
    queried: AtomicBool,
}

impl GatewayClient {
    pub fn new(gateway_ip: Ipv4Addr) -> Self {
        Self {
            gateway_ip,
            cache: Arc::new(RwLock::new(HashMap::new())),
            queried: AtomicBool::new(false),
        }
    }

    /// Queries the router gateway for its authoritative DHCP / UPnP connected client table
    pub fn refresh_hosts(&self) -> Vec<GatewayHostEntry> {
        self.queried.store(true, Ordering::Relaxed);

        let svc_info = match SsdpScanner::discover(self.gateway_ip) {
            Some(info) => info,
            None => return Vec::new(),
        };

        let mut results = Vec::new();
        // Query sequentially until NoSuchEntryInArray or limit of 64 entries
        for index in 0..64 {
            match SoapClient::get_generic_host_entry(
                svc_info.addr,
                &svc_info.control_url,
                &svc_info.service_urn,
                index,
            ) {
                Ok(Some(entry)) => {
                    self.cache.write().insert(entry.ip, entry.clone());
                    results.push(entry);
                }
                Ok(None) => break, // End of host list
                Err(_) => break,
            }
        }

        results
    }

    /// Retrieves an entry for a given IP if already cached
    pub fn get_host_by_ip(&self, ip: &Ipv4Addr) -> Option<GatewayHostEntry> {
        self.cache.read().get(ip).cloned()
    }

    /// Checks if the gateway client has already queried the router
    pub fn has_queried(&self) -> bool {
        self.queried.load(Ordering::Relaxed)
    }
}
