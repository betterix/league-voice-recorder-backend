use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use crate::db::models::now_iso;
use crate::db::DbPool;

pub const DATACENTER_KEYWORDS: &[&str] = &[
    "digitalocean",
    "amazon",
    "aws",
    "microsoft",
    "azure",
    "google cloud",
    "google-cloud",
    "hetzner",
    "ovh",
    "linode",
    "akamai",
    "vultr",
    "choopa",
    "datacamp",
    "censys",
    "shodan",
    "shadowserver",
    "leaseweb",
    "scaleway",
    "alibaba",
    "tencent",
    "oracle",
    "contabo",
    "m247",
    "cogent",
];

pub fn is_local_or_private(ip: &str) -> bool {
    if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" || ip == "testclient" {
        return true;
    }

    if let Ok(addr) = ip.parse::<IpAddr>() {
        match addr {
            IpAddr::V4(v4) => {
                if v4.is_loopback() || v4.is_private() || v4.is_link_local() {
                    return true;
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return true;
                }
            }
        }
    }
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedIntel {
    pub is_datacenter: bool,
    pub isp: String,
    pub org: String,
    pub as_info: String,
    pub country: String,
}

#[derive(Debug, Clone)]
pub struct IPIntelService {
    cache: Arc<DashMap<String, CachedIntel>>,
    client: reqwest::Client,
}

impl Default for IPIntelService {
    fn default() -> Self {
        Self::new()
    }
}

impl IPIntelService {
    pub fn new() -> Self {
        let user_agent = format!(
            "LeagueVoiceRecorder/{} (Security Bot Classifier)",
            env!("CARGO_PKG_VERSION")
        );
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(1800))
            .user_agent(user_agent)
            .build()
            .unwrap_or_default();

        Self {
            cache: Arc::new(DashMap::new()),
            client,
        }
    }

    pub async fn load_cache_from_db(&self, pool: &DbPool) -> Result<usize, sqlx::Error> {
        let rows = sqlx::query_as::<_, crate::db::models::IPIntelRecord>(
            "SELECT ip, is_datacenter, isp, org, as_info, country, created_at FROM ip_intel",
        )
        .fetch_all(pool)
        .await?;

        let count = rows.len();
        for r in rows {
            self.cache.insert(
                r.ip,
                CachedIntel {
                    is_datacenter: r.is_datacenter,
                    isp: r.isp.unwrap_or_default(),
                    org: r.org.unwrap_or_default(),
                    as_info: r.as_info.unwrap_or_default(),
                    country: r.country.unwrap_or_default(),
                },
            );
        }
        info!(
            "Loaded {} IP intelligence records from database cache",
            count
        );
        Ok(count)
    }

    pub async fn is_datacenter_ip(&self, pool: Option<&DbPool>, ip: &str) -> (bool, String) {
        if is_local_or_private(ip) {
            return (false, "Private / Localhost".to_string());
        }

        if let Some(entry) = self.cache.get(ip) {
            let provider = if !entry.org.is_empty() {
                entry.org.clone()
            } else if !entry.isp.is_empty() {
                entry.isp.clone()
            } else {
                "Datacenter / VPS".to_string()
            };
            return (entry.is_datacenter, provider);
        }

        // Query ip-api.com asynchronously
        let url = format!(
            "http://ip-api.com/json/{ip}?fields=status,message,country,isp,org,as,hosting,proxy"
        );
        if let Ok(resp) = self.client.get(&url).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if json.get("status").and_then(|s| s.as_str()) == Some("success") {
                    let isp = json
                        .get("isp")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string();
                    let org = json
                        .get("org")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string();
                    let as_info = json
                        .get("as")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string();
                    let country = json
                        .get("country")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string();

                    let is_hosting = json
                        .get("hosting")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                        || json.get("proxy").and_then(|v| v.as_bool()).unwrap_or(false);

                    let full_text = format!("{isp} {org} {as_info}").to_lowercase();
                    let keyword_match = DATACENTER_KEYWORDS.iter().any(|kw| full_text.contains(kw));

                    let is_dc = is_hosting || keyword_match;
                    let provider = if !org.is_empty() {
                        org.clone()
                    } else if !isp.is_empty() {
                        isp.clone()
                    } else {
                        "Hosting Network".to_string()
                    };

                    let intel = CachedIntel {
                        is_datacenter: is_dc,
                        isp: isp.clone(),
                        org: org.clone(),
                        as_info: as_info.clone(),
                        country: country.clone(),
                    };

                    self.cache.insert(ip.to_string(), intel);

                    if let Some(p) = pool {
                        let now_str = now_iso();
                        let _ = sqlx::query(
                            r#"
                            INSERT INTO ip_intel (ip, is_datacenter, isp, org, as_info, country, created_at)
                            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                            ON CONFLICT(ip) DO NOTHING
                            "#,
                        )
                        .bind(ip)
                        .bind(is_dc)
                        .bind(&isp)
                        .bind(&org)
                        .bind(&as_info)
                        .bind(&country)
                        .bind(&now_str)
                        .execute(p)
                        .await;
                    }

                    if is_dc {
                        info!(
                            "🚫 Datacenter/VPS IP identified: {} ({}, {})",
                            ip, provider, country
                        );
                    }

                    return (is_dc, provider);
                }
            }
        }

        // Fail-safe fallback if external lookup times out or fails
        debug!("IP intelligence lookup failed or timed out for {}", ip);
        (false, "Residential (Unclassified)".to_string())
    }

    pub fn get_ip_info(&self, ip: &str) -> Option<CachedIntel> {
        self.cache.get(ip).map(|r| r.value().clone())
    }
}
