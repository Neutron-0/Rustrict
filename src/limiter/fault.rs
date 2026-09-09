use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct FaultProfile {
    pub drop_percentage: u8,
    pub latency_ms: u32,
    pub jitter_ms: u32,
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
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        ((nanos % 100) as u8) < self.drop_percentage
    }

    pub fn compute_delay(&self) -> Duration {
        if self.latency_ms == 0 && self.jitter_ms == 0 {
            return Duration::ZERO;
        }

        let mut delay = self.latency_ms as u64;
        if self.jitter_ms > 0 {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let span = self.jitter_ms * 2 + 1;
            let variance = (nanos % span) as i64 - (self.jitter_ms as i64);
            delay = ((delay as i64) + variance).max(0) as u64;
        }

        Duration::from_millis(delay)
    }
}

