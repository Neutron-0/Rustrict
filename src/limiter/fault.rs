use std::cell::Cell;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct FaultProfile {
    pub drop_percentage: u8,
    pub latency_ms: u32,
    pub jitter_ms: u32,
}

thread_local! {
    static RNG_STATE: Cell<u64> = Cell::new({
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x853c49e6748fea9b);
        let ptr = &nanos as *const _ as u64;
        let mut s = nanos ^ ptr ^ 0x9e3779b97f4a7c15;
        if s == 0 {
            s = 0x853c49e6748fea9b;
        }
        s
    });
}

fn next_random_u64() -> u64 {
    RNG_STATE.with(|rng| {
        let mut x = rng.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        rng.set(x);
        x.wrapping_mul(0x2545f4914f6cdd1d)
    })
}

impl FaultProfile {
    pub fn new(drop_percentage: u8, latency_ms: u32, jitter_ms: u32) -> Self {
        Self {
            drop_percentage: drop_percentage.min(100),
            latency_ms,
            jitter_ms,
        }
    }

    pub fn is_active(&self) -> bool {
        self.drop_percentage > 0 || self.latency_ms > 0 || self.jitter_ms > 0
    }

    pub fn should_drop(&self) -> bool {
        if self.drop_percentage == 0 {
            return false;
        }
        if self.drop_percentage >= 100 {
            return true;
        }
        let sample = (next_random_u64() % 100) as u8;
        sample < self.drop_percentage
    }

    pub fn compute_delay(&self) -> Duration {
        if self.latency_ms == 0 && self.jitter_ms == 0 {
            return Duration::ZERO;
        }

        let mut delay = self.latency_ms as u64;
        if self.jitter_ms > 0 {
            let span = (self.jitter_ms as u64) * 2 + 1;
            let offset = (next_random_u64() % span) as i64;
            let variance = offset - (self.jitter_ms as i64);
            delay = ((delay as i64) + variance).max(0) as u64;
        }

        Duration::from_millis(delay)
    }
}
