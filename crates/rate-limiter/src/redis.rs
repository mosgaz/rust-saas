use std::time::Duration;
use redis::{aio::ConnectionManager, Client, Script};
use crate::RateLimiter;

pub struct RedisRateLimiter {
    conn: ConnectionManager,
    script: Script,
}

impl RedisRateLimiter {
    pub async fn from_url(url: &str) -> Result<Self, redis::RedisError> {
        let client = Client::open(url)?;
        let conn = ConnectionManager::new(client).await?;
        let script = Script::new(r#"
            local now = tonumber(ARGV[1])
            local window = tonumber(ARGV[2])
            redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
            local n = redis.call('ZCARD', KEYS[1])
            if n < tonumber(ARGV[3]) then
                redis.call('ZADD', KEYS[1], now, ARGV[4])
                redis.call('EXPIRE', KEYS[1], math.ceil(window / 1000) + 1)
                return 1
            else
                local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
                local retry_ms = oldest[2] and (tonumber(oldest[2]) + window - now) or 0
                return -math.max(1, math.ceil(retry_ms / 1000))
            end
        "#);
        Ok(Self { conn, script })
    }
}

#[async_trait::async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn try_acquire(&self, key: &str, max: usize, window: Duration) -> Result<(), u64> {
        if max == 0 {
            return Err(window.as_secs().max(1));
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let window_ms = window.as_millis() as u64;
        let member = uuid::Uuid::new_v4().to_string();

        let mut conn = self.conn.clone();
        let res: i64 = self
            .script
            .key(format!("rate_limit:{}", key))
            .arg(now_ms)
            .arg(window_ms)
            .arg(max)
            .arg(member)
            .invoke_async(&mut conn)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "Redis rate limiter failed");
                -1
            });

        if res == 1 {
            Ok(())
        } else if res < 0 {
            Err((-res) as u64)
        } else {
            Err(1)
        }
    }
}
