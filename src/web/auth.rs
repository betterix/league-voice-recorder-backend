use axum::http::HeaderMap;
use std::net::IpAddr;
use subtle::ConstantTimeEq;

use crate::config::Config;

pub fn is_web_ip_allowed(client_ip: &str, allowed_ips_str: &str) -> bool {
    if client_ip == "127.0.0.1"
        || client_ip == "::1"
        || client_ip == "localhost"
        || client_ip == "testclient"
    {
        return true;
    }

    if let Ok(addr) = client_ip.parse::<IpAddr>() {
        match addr {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                if v4.is_loopback() || (octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31)) {
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

    let allowed_list: Vec<&str> = allowed_ips_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if allowed_list.contains(&"0.0.0.0") || allowed_list.contains(&"*") {
        return true;
    }

    for entry in allowed_list {
        if let (Ok(client_addr), Ok(entry_addr)) =
            (client_ip.parse::<IpAddr>(), entry.parse::<IpAddr>())
        {
            if client_addr == entry_addr {
                return true;
            }
        } else if entry == client_ip {
            return true;
        }
    }

    false
}

pub fn extract_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let auth_header = headers.get("authorization")?.to_str().ok()?;
    if !auth_header.starts_with("Basic ") {
        return None;
    }

    let encoded = &auth_header[6..].trim();
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
    let credentials = String::from_utf8(decoded).ok()?;

    let mut parts = credentials.splitn(2, ':');
    let user = parts.next()?.to_string();
    let pass = parts.next()?.to_string();
    Some((user, pass))
}

pub fn verify_basic_auth(user: &str, pass: &str, config: &Config) -> bool {
    let user_match = user
        .as_bytes()
        .ct_eq(config.web_username.as_bytes())
        .unwrap_u8()
        == 1;
    let pass_match = pass
        .as_bytes()
        .ct_eq(config.web_password.as_bytes())
        .unwrap_u8()
        == 1;
    user_match && pass_match
}
