//! Token-bucket rate limiter per §8.2
use std::time::Instant;

pub struct TokenBucket {
    capacity: u64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u64, refill_per_sec: f64) -> Self {
        Self { capacity, tokens: capacity as f64, refill_per_sec, last: Instant::now() }
    }
    pub fn allow(&mut self, cost: u64) -> bool {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.capacity as f64);
        if self.tokens >= cost as f64 {
            self.tokens -= cost as f64;
            true
        } else { false }
    }
}
