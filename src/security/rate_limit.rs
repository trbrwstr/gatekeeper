use std::{
    collections::HashMap,
    time::Instant,
};

const EVICTION_INTERVAL: u64 = 60;

pub struct RateLimiter {
    buckets: HashMap<String, Bucket>,
    capacity: u32,
    refill_rate: u32,
    last_eviction: Instant,
}

struct Bucket {
    tokens: u32,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(capacity: u32, refill_rate: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            capacity,
            refill_rate,
            last_eviction: Instant::now(),
        }
    }

    pub fn check(&mut self, key: &str) -> bool {
        let now = Instant::now();

        self.maybe_evict(now);

        let bucket = self.buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: self.capacity,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs();
        let refill = (elapsed as u32).saturating_mul(self.refill_rate);

        if refill > 0 {
            bucket.tokens = (bucket.tokens + refill).min(self.capacity);
            bucket.last_refill = now;
        }

        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn maybe_evict(&mut self, now: Instant) {
        if now.duration_since(self.last_eviction).as_secs() < EVICTION_INTERVAL {
            return;
        }
        self.last_eviction = now;

        let stale_threshold = if self.refill_rate > 0 {
            (self.capacity / self.refill_rate).max(1) as u64 * 2
        } else {
            120
        };

        self.buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_refill).as_secs() < stale_threshold
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_within_capacity() {
        let mut limiter = RateLimiter::new(5, 1);
        for _ in 0..5 {
            assert!(limiter.check("ip1"));
        }
    }

    #[test]
    fn blocks_when_exhausted() {
        let mut limiter = RateLimiter::new(2, 1);
        assert!(limiter.check("ip1"));
        assert!(limiter.check("ip1"));
        assert!(!limiter.check("ip1"));
    }

    #[test]
    fn separate_buckets_per_key() {
        let mut limiter = RateLimiter::new(1, 1);
        assert!(limiter.check("ip1"));
        assert!(limiter.check("ip2"));
        assert!(!limiter.check("ip1"));
    }

    #[test]
    fn bucket_count_grows() {
        let mut limiter = RateLimiter::new(10, 1);
        for i in 0..100 {
            limiter.check(&format!("ip_{}", i));
        }
        assert_eq!(limiter.buckets.len(), 100);
    }

    #[test]
    fn saturating_refill_does_not_overflow() {
        let mut limiter = RateLimiter::new(10, u32::MAX);
        limiter.check("ip1");
        let bucket = limiter.buckets.get_mut("ip1").unwrap();
        bucket.tokens = 0;
        bucket.last_refill = Instant::now() - std::time::Duration::from_secs(1000);
        assert!(limiter.check("ip1"));
        let bucket = limiter.buckets.get("ip1").unwrap();
        assert!(bucket.tokens <= 10);
    }
}
