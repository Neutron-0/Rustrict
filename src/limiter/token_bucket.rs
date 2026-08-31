use std::time::Instant;
use parking_lot::Mutex;

#[derive(Debug)]
pub struct TokenBucket {
    rate_bps: u64,
    capacity_bits: u64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(rate_bps: u64, burst_capacity_bits: Option<u64>) -> Self {
        let rate = rate_bps.max(1);
        let capacity = burst_capacity_bits.unwrap_or_else(|| {
            let burst = (rate as f64 * 1.2) as u64;
            burst.max(1500 * 8 * 2)
        });

        Self {
            rate_bps: rate,
            capacity_bits: capacity,
            tokens: capacity as f64,
            last_refill: Instant::now(),
        }
    }

    pub fn try_consume(&mut self, bits: u64) -> bool {
        let now = Instant::now();
        let elapsed_secs = (now - self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed_secs * self.rate_bps as f64).min(self.capacity_bits as f64);
        self.last_refill = now;

        if self.tokens >= bits as f64 {
            self.tokens -= bits as f64;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct SharedTokenBucket(Mutex<TokenBucket>);

impl SharedTokenBucket {
    pub fn new(rate_bps: u64, burst_capacity_bits: Option<u64>) -> Self {
        Self(Mutex::new(TokenBucket::new(rate_bps, burst_capacity_bits)))
    }

    pub fn try_consume(&self, bits: u64) -> bool {
        self.0.lock().try_consume(bits)
    }
}
