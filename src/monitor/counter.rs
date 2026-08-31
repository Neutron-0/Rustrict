use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use parking_lot::RwLock;

use crate::types::{BitRate, ByteValue};

#[derive(Default)]
pub struct HostTrafficStats {
    pub bytes_sent: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub total_bytes_sent: AtomicU64,
    pub total_bytes_recv: AtomicU64,
}

pub struct BandwidthMeter {
    stats: Arc<RwLock<HashMap<Ipv4Addr, Arc<HostTrafficStats>>>>,
    last_sample: RwLock<Instant>,
}

impl BandwidthMeter {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(HashMap::new())),
            last_sample: RwLock::new(Instant::now()),
        }
    }

    pub fn register_host(&self, ip: Ipv4Addr) {
        self.stats.write().entry(ip).or_insert_with(|| Arc::new(HostTrafficStats::default()));
    }

    pub fn unregister_host(&self, ip: &Ipv4Addr) {
        self.stats.write().remove(ip);
    }

    pub fn record_packet(&self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, len: u64) {
        let map = self.stats.read();
        if let Some(src_stats) = map.get(&src_ip) {
            src_stats.bytes_sent.fetch_add(len, Ordering::Relaxed);
            src_stats.total_bytes_sent.fetch_add(len, Ordering::Relaxed);
        }
        if let Some(dst_stats) = map.get(&dst_ip) {
            dst_stats.bytes_recv.fetch_add(len, Ordering::Relaxed);
            dst_stats.total_bytes_recv.fetch_add(len, Ordering::Relaxed);
        }
    }

    pub fn sample_rates(&self) -> HashMap<Ipv4Addr, (BitRate, BitRate, ByteValue, ByteValue)> {
        let now = Instant::now();
        let mut last = self.last_sample.write();
        let elapsed = (now - *last).as_secs_f64().max(0.001);
        *last = now;

        let map = self.stats.read();
        let mut results = HashMap::new();

        for (&ip, stats) in map.iter() {
            let sent = stats.bytes_sent.swap(0, Ordering::Relaxed);
            let recv = stats.bytes_recv.swap(0, Ordering::Relaxed);
            let total_sent = stats.total_bytes_sent.load(Ordering::Relaxed);
            let total_recv = stats.total_bytes_recv.load(Ordering::Relaxed);

            let ul_bps = ((sent as f64 * 8.0) / elapsed) as u64;
            let dl_bps = ((recv as f64 * 8.0) / elapsed) as u64;

            results.insert(ip, (BitRate(ul_bps), BitRate(dl_bps), ByteValue(total_sent), ByteValue(total_recv)));
        }

        results
    }
}
