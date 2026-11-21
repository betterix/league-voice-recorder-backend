use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::config::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Upload,
    Pull,
    Admin,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Upload => "upload",
            Role::Pull => "pull",
            Role::Admin => "admin",
        }
    }
}

pub fn verify_secret_constant_time(provided: Option<&str>, expected: Option<&str>) -> bool {
    match (provided, expected) {
        (Some(p), Some(e)) => {
            let p_trim = p.trim().as_bytes();
            let e_trim = e.trim().as_bytes();
            if p_trim.len() != e_trim.len() {
                false
            } else {
                p_trim.ct_eq(e_trim).unwrap_u8() == 1
            }
        }
        _ => false,
    }
}

pub fn authenticate_key(provided_key: Option<&str>, config: &Config) -> Option<Role> {
    let key = provided_key?;

    // Check ADMIN_KEY first if configured
    if let Some(admin_key) = &config.admin_key
        && verify_secret_constant_time(Some(key), Some(admin_key))
    {
        return Some(Role::Admin);
    }

    // Check UPLOAD_KEY
    if verify_secret_constant_time(Some(key), Some(&config.upload_key)) {
        return Some(Role::Upload);
    }

    // Check PULL_KEY
    if verify_secret_constant_time(Some(key), Some(&config.pull_key)) {
        return Some(Role::Pull);
    }

    None
}
