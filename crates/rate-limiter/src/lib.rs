use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[async_trait::async_trait]
pub trait RateLimiter: Send + Sync {
    /// Attempts to record a hit for `key`.
    ///
    /// - `Ok(())` — hit recorded; fewer than `max` hits in `[now - window, now]`.
    /// - `Err(retry_after_secs)` — not recorded; the caller should wait at
    ///   least this many seconds. `max = 0` always rejects. `window =
    ///   Duration::ZERO` allows every call.
    async fn try_acquire(&self, key: &str, max: usize, window: Duration) -> Result<(), u64>;
}

pub struct InMemoryRateLimiter {
    entries: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl InMemoryRateLimiter {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn try_acquire_at(
        &self,
        now: Instant,
        key: &str,
        max: usize,
        window: Duration,
    ) -> Result<(), u64> {
        if max == 0 {
            return Err(window.as_secs().max(1));
        }
        let mut guard = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let bucket = guard.entry(key.to_string()).or_default();

        while let Some(&front) = bucket.front() {
            if now.saturating_duration_since(front) >= window {
                bucket.pop_front();
            } else {
                break;
            }
        }

        if bucket.len() < max {
            bucket.push_back(now);
            Ok(())
        } else {
            let oldest = bucket.front().copied().unwrap_or(now);
            let elapsed = now.saturating_duration_since(oldest);
            let remaining = window.saturating_sub(elapsed).as_secs().max(1);
            Err(remaining)
        }
    }
}

impl Default for InMemoryRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl RateLimiter for InMemoryRateLimiter {
    async fn try_acquire(&self, key: &str, max: usize, window: Duration) -> Result<(), u64> {
        self.try_acquire_at(Instant::now(), key, max, window)
    }
}

#[deprecated(note = "use InMemoryRateLimiter")]
pub type SimpleRateLimiter = InMemoryRateLimiter;

#[cfg(feature = "redis")]
mod redis;
#[cfg(feature = "redis")]
pub use self::redis::RedisRateLimiter;

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn allows_up_to_max_then_rejects() {
        let limiter = InMemoryRateLimiter::new();
        let t0 = Instant::now();
        let window = Duration::from_secs(3600);
        let key = "alice@example.test";

        assert!(limiter.try_acquire_at(t0, key, 3, window).is_ok());
        assert!(limiter.try_acquire_at(at(t0, 10), key, 3, window).is_ok());
        assert!(limiter.try_acquire_at(at(t0, 20), key, 3, window).is_ok());

        let retry = limiter
            .try_acquire_at(at(t0, 30), key, 3, window)
            .expect_err("4th hit must be rejected");
        assert!(retry > 0 && retry <= 3600, "retry={retry}");
    }

    #[test]
    fn different_keys_are_independent() {
        let limiter = InMemoryRateLimiter::new();
        let t0 = Instant::now();
        let window = Duration::from_secs(60);

        assert!(limiter.try_acquire_at(t0, "a", 1, window).is_ok());
        assert!(limiter.try_acquire_at(t0, "b", 1, window).is_ok());
        assert!(limiter.try_acquire_at(t0, "a", 1, window).is_err());
        assert!(limiter.try_acquire_at(t0, "b", 1, window).is_err());
    }

    #[test]
    fn window_expiry_allows_new_hit() {
        let limiter = InMemoryRateLimiter::new();
        let t0 = Instant::now();
        let window = Duration::from_secs(60);
        let key = "k";

        assert!(limiter.try_acquire_at(t0, key, 1, window).is_ok());
        assert!(limiter.try_acquire_at(at(t0, 30), key, 1, window).is_err());
        assert!(
            limiter.try_acquire_at(at(t0, 61), key, 1, window).is_ok(),
            "hit after window must be allowed"
        );
    }

    #[test]
    fn max_zero_always_rejects() {
        let limiter = InMemoryRateLimiter::new();
        assert!(limiter
            .try_acquire_at(Instant::now(), "k", 0, Duration::from_secs(60))
            .is_err());
    }
}
