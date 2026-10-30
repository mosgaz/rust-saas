//! Simple in-memory rate limiter (Stage 3b).
//!
//! Sliding-window counter keyed by an arbitrary string (e.g. an email
//! address). `try_acquire` records a hit and returns `Ok(())` if the number
//! of hits in the current window is under `max`; otherwise it returns
//! `Err(retry_after_secs)` and does **not** record a hit.
//!
//! Stage 3b usage: `#[server] request_email_verification` is limited to
//! `3 / 1 h` per email (see `pages/auth.rs`). Per-email, not per-IP; IP-based
//! limiting belongs to a reverse proxy or a Stage 4 rate limiter.
//!
//! **Process-local.** State is an in-memory `Mutex<HashMap<…>>`; it is not
//! shared across instances. Multi-instance deployments need a shared store
//! (Redis, DB table) — Stage 4+. Same "not distributed" caveat as the
//! refresh-token grace window.
//!
//! **Bounded by key diversity, not by time.** Each distinct key occupies one
//! map entry; per-key buckets are pruned on access, but an unbounded stream
//! of *distinct* keys (e.g. many failed `request_email_verification` calls
//! with attacker-chosen addresses) grows the map. Acceptable for the
//! reference consumer; production should add a sweep or TTL cache (Stage 4+).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Sliding-window, per-key, in-memory rate limiter.
pub struct SimpleRateLimiter {
    entries: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl SimpleRateLimiter {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Attempts to record a hit for `key`.
    ///
    /// - `Ok(())` — hit recorded; fewer than `max` hits in
    ///   `[now - window, now]`.
    /// - `Err(retry_after_secs)` — not recorded; the caller should wait at
    ///   least this many seconds. `max = 0` always rejects. `window =
    ///   Duration::ZERO` allows every call (each hit prunes itself).
    pub fn try_acquire(&self, key: &str, max: usize, window: Duration) -> Result<(), u64> {
        self.try_acquire_at(Instant::now(), key, max, window)
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

        // Prune hits that fell out of the sliding window.
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

impl Default for SimpleRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn allows_up_to_max_then_rejects() {
        let limiter = SimpleRateLimiter::new();
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
        let limiter = SimpleRateLimiter::new();
        let t0 = Instant::now();
        let window = Duration::from_secs(60);

        assert!(limiter.try_acquire_at(t0, "a", 1, window).is_ok());
        assert!(limiter.try_acquire_at(t0, "b", 1, window).is_ok());
        assert!(limiter.try_acquire_at(t0, "a", 1, window).is_err());
        assert!(limiter.try_acquire_at(t0, "b", 1, window).is_err());
    }

    #[test]
    fn window_expiry_allows_new_hit() {
        let limiter = SimpleRateLimiter::new();
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
        let limiter = SimpleRateLimiter::new();
        assert!(limiter
            .try_acquire_at(Instant::now(), "k", 0, Duration::from_secs(60))
            .is_err());
    }
}