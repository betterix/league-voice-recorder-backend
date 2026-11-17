use regex::Regex;
use std::net::IpAddr;
use std::sync::LazyLock;

use crate::db::models::now_iso;
use crate::db::DbPool;

pub static SCANNER_PROBE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?xi)",
        r"(?:^|/)\.(?:env|git|svn|hg|bzr|vscode|idea|DS_Store|aws|ssh)(?:/|$|\.)",
        r"|(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)",
        r"|\.(?:php|asp|aspx|jsp|jspx|cgi|pl|action|axd|do|cfm|properties)(?:/|$|\?|\#)",
        r"|/(?:wp-|wordpress|wp/|wp_admin|wp_content|xmlrpc\.php)",
        r"|rest_route=/wp/",
        r"|(?:phpmyadmin|pma|myadmin|adminer|cpanel|whm|webmail|roundcube|ecp|owa|autodiscover|proxy_subdomain)",
        r"|/(?:actuator|telescope|debug/default/view|console(?:/|$)|server-status|server-info|elmah\.axd|trace\.axd|metrics|prometheus)(?:/|$|\?)",
        r"|/(?:graphql|gql|api/graphql|graphql/api|api/gql|v1/models|models|mcp|api/mcp|mcp-sse|sse)(?:/|$|\?)",
        r"|/(?:v1/_catalog|v2/_catalog|exporttool|META-INF|WEB-INF|%40vite|@vite|HNAP1|nmap|evox|sdk)(?:/|$|\?)",
        r"|/(?:config\.json|\.well-known/security\.txt|sftp\.json|robots\.txt|sitemap\.xml)(?:/|$|\?)"
    ))
    .unwrap()
});

pub const SUSPICIOUS_METHODS: &[&str] = &[
    "PROPFIND",
    "PROPPATCH",
    "SEARCH",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "CONNECT",
];

pub fn is_scanner_probe(method: &str, target: &str) -> bool {
    if SUSPICIOUS_METHODS
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method))
    {
        return true;
    }
    SCANNER_PROBE_REGEX.is_match(target)
}

pub fn is_trusted_ip(client_ip: &str, allowed_ips_str: &str) -> bool {
    if client_ip == "127.0.0.1"
        || client_ip == "::1"
        || client_ip == "localhost"
        || client_ip == "testclient"
    {
        return true;
    }

    if let Ok(addr) = client_ip.parse::<IpAddr>() {
        if addr.is_loopback() {
            return true;
        }
    }

    if allowed_ips_str.is_empty() {
        return false;
    }

    for entry in allowed_ips_str.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() || trimmed == "0.0.0.0" || trimmed == "*" {
            continue;
        }

        if let (Ok(client_addr), Ok(entry_addr)) =
            (client_ip.parse::<IpAddr>(), trimmed.parse::<IpAddr>())
        {
            if client_addr == entry_addr {
                return true;
            }
        } else if trimmed == client_ip {
            return true;
        }
    }

    false
}

pub async fn log_activity_event(
    pool: &DbPool,
    ip: &str,
    method: &str,
    path: &str,
    status_code: u16,
    category: &str,
    details: Option<&str>,
) {
    if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" || ip == "testclient" {
        return;
    }

    let now_str = now_iso();
    let res = sqlx::query(
        r#"
        INSERT INTO ip_activity (ip, method, path, status_code, category, details, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
    )
    .bind(ip)
    .bind(method)
    .bind(path)
    .bind(status_code as i64)
    .bind(category)
    .bind(details)
    .bind(&now_str)
    .execute(pool)
    .await;

    if let Err(e) = res {
        tracing::debug!("Failed to record IP activity for {}: {}", ip, e);
    }
}
