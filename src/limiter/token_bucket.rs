use parking_lot::Mutex;
use std::time::Instant;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TokenResult {
    Immediate,
    Delay(std::time::Duration),
    Drop,
}

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
            // Adaptive burst allowance: 250ms of traffic, at least 4 full MTU frames (6000 bytes = 48,000 bits)
            let burst = (rate as f64 * 0.25) as u64;
            burst.max(1500 * 8 * 4)
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
        self.tokens =
            (self.tokens + elapsed_secs * self.rate_bps as f64).min(self.capacity_bits as f64);
        self.last_refill = now;

        if self.tokens >= bits as f64 {
            self.tokens -= bits as f64;
            true
        } else {
            false
        }
    }

    pub fn consume_or_wait(&mut self, bits: u64) -> TokenResult {
        let now = Instant::now();
        let elapsed_secs = (now - self.last_refill).as_secs_f64();
        self.tokens =
            (self.tokens + elapsed_secs * self.rate_bps as f64).min(self.capacity_bits as f64);
        self.last_refill = now;

        if self.tokens >= bits as f64 {
            self.tokens -= bits as f64;
            TokenResult::Immediate
        } else {
            let deficit = (bits as f64) - self.tokens;
            let wait_secs = deficit / (self.rate_bps as f64);
            // Allow micro-delay pacing up to 250ms for smooth TCP self-clocking without drop
            if wait_secs <= 0.250 {
                self.tokens -= bits as f64;
                TokenResult::Delay(std::time::Duration::from_secs_f64(wait_secs))
            } else {
                TokenResult::Drop
            }
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

    pub fn consume_or_wait(&self, bits: u64) -> TokenResult {
        self.0.lock().consume_or_wait(bits)
    }
}
