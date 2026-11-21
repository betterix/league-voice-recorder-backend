use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::db::DbPool;
use crate::db::models::now_iso;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentBanInfo {
    pub reason: String,
    pub violation_count: i64,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct InMemoryRateLimiter {
    general_requests: Arc<DashMap<String, Vec<Instant>>>,
    upload_requests: Arc<DashMap<String, Vec<Instant>>>,
    auth_failures: Arc<DashMap<String, Vec<Instant>>>,
    probe_failures: Arc<DashMap<String, Vec<Instant>>>,
    blocked_ips: Arc<DashMap<String, (Instant, String)>>,
    persistent_banned_ips: Arc<DashMap<String, PersistentBanInfo>>,
}

impl Default for InMemoryRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryRateLimiter {
    pub fn new() -> Self {
        Self {
            general_requests: Arc::new(DashMap::new()),
            upload_requests: Arc::new(DashMap::new()),
            auth_failures: Arc::new(DashMap::new()),
            probe_failures: Arc::new(DashMap::new()),
            blocked_ips: Arc::new(DashMap::new()),
            persistent_banned_ips: Arc::new(DashMap::new()),
        }
    }

    fn cleanup_old_timestamps(timestamps: &mut Vec<Instant>, window_duration: Duration) {
        let now = Instant::now();
        timestamps.retain(|&ts| now.duration_since(ts) < window_duration);
    }

    pub async fn load_banned_ips_from_db(&self, pool: &DbPool) -> Result<usize, sqlx::Error> {
        let rows = sqlx::query_as::<_, crate::db::models::BannedIP>(
            "SELECT id, ip, reason, violation_count, created_at, updated_at FROM banned_ips",
        )
        .fetch_all(pool)
        .await?;

        let count = rows.len();
        for r in rows {
            self.persistent_banned_ips.insert(
                r.ip,
                PersistentBanInfo {
                    reason: r.reason,
                    violation_count: r.violation_count,
                    created_at: r.created_at,
                },
            );
        }
        info!("Loaded {} persistent banned IPs from database", count);
        Ok(count)
    }

    pub fn is_ip_banned_permanent(&self, ip: &str) -> bool {
        self.persistent_banned_ips.contains_key(ip)
    }

    pub async fn ban_ip_permanent(&self, pool: Option<&DbPool>, ip: &str, reason: &str) {
        let now_str = now_iso();
        self.persistent_banned_ips
            .entry(ip.to_string())
            .and_modify(|info| {
                info.violation_count += 1;
                info.reason = reason.to_string();
            })
            .or_insert(PersistentBanInfo {
                reason: reason.to_string(),
                violation_count: 1,
                created_at: now_str.clone(),
            });

        warn!("🚨 IP {} PERMANENTLY BANNED in database: {}", ip, reason);

        if let Some(p) = pool {
            let res = sqlx::query(
                r#"
                INSERT INTO banned_ips (ip, reason, violation_count, created_at, updated_at)
                VALUES (?1, ?2, 1, ?3, ?3)
                ON CONFLICT(ip) DO UPDATE SET
                    violation_count = banned_ips.violation_count + 1,
                    reason = excluded.reason,
                    updated_at = excluded.updated_at
                "#,
            )
            .bind(ip)
            .bind(reason)
            .bind(&now_str)
            .execute(p)
            .await;

            if let Err(e) = res {
                tracing::error!("Failed to persist banned IP {} to database: {}", ip, e);
            }
        }
    }

    pub fn is_ip_blocked(&self, ip: &str) -> (bool, u64) {
        if self.persistent_banned_ips.contains_key(ip) {
            return (true, 0);
        }

        let now = Instant::now();
        if let Some(entry) = self.blocked_ips.get(ip) {
            let (blocked_until, _) = *entry.value();
            if now < blocked_until {
                let remaining = (blocked_until - now).as_secs() + 1;
                return (true, remaining);
            } else {
                drop(entry);
                self.blocked_ips.remove(ip);
            }
        }

        (false, 0)
    }

    pub fn get_block_reason(&self, ip: &str) -> String {
        if let Some(info) = self.persistent_banned_ips.get(ip) {
            return info.reason.clone();
        }
        if let Some(entry) = self.blocked_ips.get(ip) {
            return entry.value().1.clone();
        }
        "Authentication brute-force or scanner activity".to_string()
    }

    pub async fn block_ip(
        &self,
        pool: Option<&DbPool>,
        ip: &str,
        duration_minutes: u32,
        reason: &str,
    ) {
        if duration_minutes == 0 || duration_minutes >= 60 {
            self.ban_ip_permanent(pool, ip, reason).await;
            return;
        }

        let blocked_until = Instant::now() + Duration::from_secs(duration_minutes as u64 * 60);
        self.blocked_ips
            .insert(ip.to_string(), (blocked_until, reason.to_string()));
        warn!(
            "🚨 IP {} BANNED for {} min: {}",
            ip, duration_minutes, reason
        );
    }

    pub async fn record_auth_failure(
        &self,
        pool: Option<&DbPool>,
        ip: &str,
        max_failures: u32,
        window_seconds: f64,
        block_duration_minutes: u32,
    ) -> bool {
        let now = Instant::now();
        let window_duration = Duration::from_secs_f64(window_seconds);

        let mut entry = self.auth_failures.entry(ip.to_string()).or_default();
        Self::cleanup_old_timestamps(&mut entry, window_duration);
        entry.push(now);
        let failure_count = entry.len();

        if failure_count >= max_failures as usize {
            let reason = format!("Authentication brute-force ({failure_count} failed attempts)");
            self.block_ip(pool, ip, block_duration_minutes, &reason)
                .await;
            warn!(
                "Brute-force protection: IP {} blocked for {} min ({} failed attempts)",
                ip, block_duration_minutes, failure_count
            );
            return true;
        }
        false
    }

    pub async fn record_probe_failure(
        &self,
        pool: Option<&DbPool>,
        ip: &str,
        max_failures: u32,
        window_seconds: f64,
        _block_duration_minutes: u32,
        reason: &str,
    ) -> bool {
        let now = Instant::now();
        let window_duration = Duration::from_secs_f64(window_seconds);

        let mut entry = self.probe_failures.entry(ip.to_string()).or_default();
        Self::cleanup_old_timestamps(&mut entry, window_duration);
        entry.push(now);
        let failure_count = entry.len();

        if failure_count >= max_failures as usize {
            self.ban_ip_permanent(pool, ip, reason).await;
            return true;
        }
        false
    }

    pub async fn unblock_ip(&self, pool: Option<&DbPool>, ip: &str) -> bool {
        let removed_temp = self.blocked_ips.remove(ip).is_some();
        let mut removed_perm = self.persistent_banned_ips.remove(ip).is_some();
        self.probe_failures.remove(ip);
        self.auth_failures.remove(ip);
        self.general_requests.remove(ip);
        self.upload_requests.remove(ip);

        if let Some(p) = pool {
            let res = sqlx::query("DELETE FROM banned_ips WHERE ip = ?1")
                .bind(ip)
                .execute(p)
                .await;
            if let Ok(rows) = res
                && rows.rows_affected() > 0
            {
                removed_perm = true;
            }
        }

        let removed = removed_temp || removed_perm;
        if removed {
            info!("IP {} manually unblocked and rate limits reset", ip);
        }
        removed
    }

    pub fn get_blocked_ips(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        let now = Instant::now();

        for entry in self.persistent_banned_ips.iter() {
            let ip = entry.key().clone();
            let info = entry.value();
            map.insert(
                ip,
                serde_json::json!({
                    "type": "permanent",
                    "reason": info.reason,
                    "violation_count": info.violation_count,
                    "created_at": info.created_at,
                }),
            );
        }

        let mut expired = Vec::new();
        for entry in self.blocked_ips.iter() {
            let ip = entry.key();
            let (blocked_until, reason) = entry.value();
            if now < *blocked_until {
                if !map.contains_key(ip) {
                    let rem = (*blocked_until - now).as_secs() + 1;
                    map.insert(
                        ip.clone(),
                        serde_json::json!({
                            "type": "temporary",
                            "remaining_seconds": rem,
                            "reason": reason,
                        }),
                    );
                }
            } else {
                expired.push(ip.clone());
            }
        }

        for exp in expired {
            self.blocked_ips.remove(&exp);
        }

        serde_json::Value::Object(map)
    }

    pub fn check_rate_limit(
        &self,
        ip: &str,
        category: &str,
        limit_per_minute: u32,
        window_seconds: f64,
    ) -> (bool, u32, u64) {
        let now = Instant::now();
        let window_duration = Duration::from_secs_f64(window_seconds);

        let storage = if category == "upload" {
            &self.upload_requests
        } else {
            &self.general_requests
        };

        let mut entry = storage.entry(ip.to_string()).or_default();
        Self::cleanup_old_timestamps(&mut entry, window_duration);

        if entry.len() >= limit_per_minute as usize {
            let oldest = entry[0];
            let elapsed = now.duration_since(oldest);
            let retry_after = if elapsed < window_duration {
                (window_duration - elapsed).as_secs().max(1)
            } else {
                1
            };
            return (false, 0, retry_after);
        }

        entry.push(now);
        let remaining = (limit_per_minute as usize).saturating_sub(entry.len()) as u32;
        (true, remaining, 0)
    }

    pub fn reset(&self) {
        self.general_requests.clear();
        self.upload_requests.clear();
        self.auth_failures.clear();
        self.probe_failures.clear();
        self.blocked_ips.clear();
        self.persistent_banned_ips.clear();
    }
}
