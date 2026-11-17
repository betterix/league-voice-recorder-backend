use std::env;
use std::path::PathBuf;

pub const INSECURE_KEY_SUBSTRINGS: &[&str] = &[
    "generate-secure-random",
    "changeme",
    "change-me",
    "secret",
    "password",
    "admin123",
];

#[derive(Debug, Clone)]
pub struct Config {
    pub domain_name: String,
    pub port: u16,
    pub environment: String,

    pub storage_dir: PathBuf,
    pub db_dir: PathBuf,

    pub upload_key: String,
    pub pull_key: String,
    pub admin_key: Option<String>,

    pub ssl_cert: PathBuf,
    pub ssl_key: PathBuf,
    pub dev_self_signed_cert: bool,

    pub max_upload_mb: usize,
    pub rate_limit_per_minute: u32,
    pub upload_rate_limit_per_minute: u32,
    pub auth_failure_limit_per_minute: u32,
    pub auth_block_duration_minutes: u32,

    pub scanner_block_enabled: bool,
    pub scanner_block_duration_minutes: u32,
    pub scanner_failure_threshold: u32,
    pub scanner_failure_window_seconds: f64,
    pub datacenter_block_enabled: bool,

    pub web_enabled: bool,
    pub web_allowed_ips: String,
    pub web_username: String,
    pub web_password: String,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let _ = dotenvy::dotenv();

        let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "production".to_string());
        let domain_name =
            env::var("DOMAIN_NAME").unwrap_or_else(|_| "voice.example.com".to_string());
        let port = env::var("PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(8443);

        let storage_dir = env::var("STORAGE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/app/data/recordings"));
        let db_dir = env::var("DB_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/app/data/db"));

        let upload_key = env::var("UPLOAD_KEY")
            .unwrap_or_else(|_| "generate-secure-random-upload-secret".to_string());
        let pull_key = env::var("PULL_KEY")
            .unwrap_or_else(|_| "generate-secure-random-pull-secret".to_string());
        let admin_key = env::var("ADMIN_KEY").ok().filter(|s| !s.trim().is_empty());

        let ssl_cert = env::var("SSL_CERT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/app/certs/cert.pem"));
        let ssl_key = env::var("SSL_KEY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/app/certs/key.pem"));
        let dev_self_signed_cert = env::var("DEV_SELF_SIGNED_CERT")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let max_upload_mb = env::var("MAX_UPLOAD_MB")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(250);
        let rate_limit_per_minute = env::var("RATE_LIMIT_PER_MINUTE")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(120);
        let upload_rate_limit_per_minute = env::var("UPLOAD_RATE_LIMIT_PER_MINUTE")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(10);
        let auth_failure_limit_per_minute = env::var("AUTH_FAILURE_LIMIT_PER_MINUTE")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(5);
        let auth_block_duration_minutes = env::var("AUTH_BLOCK_DURATION_MINUTES")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(10);

        let scanner_block_enabled = env::var("SCANNER_BLOCK_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(true);
        let scanner_block_duration_minutes = env::var("SCANNER_BLOCK_DURATION_MINUTES")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(60);
        let scanner_failure_threshold = env::var("SCANNER_FAILURE_THRESHOLD")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(5);
        let scanner_failure_window_seconds = env::var("SCANNER_FAILURE_WINDOW_SECONDS")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(60.0);
        let datacenter_block_enabled = env::var("DATACENTER_BLOCK_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(true);

        let web_enabled = env::var("WEB_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(true);
        let web_allowed_ips =
            env::var("WEB_ALLOWED_IPS").unwrap_or_else(|_| "127.0.0.1,::1".to_string());
        let web_username = env::var("WEB_USERNAME").unwrap_or_else(|_| "admin".to_string());
        let web_password = env::var("WEB_PASSWORD")
            .unwrap_or_else(|_| "change-me-secure-web-password".to_string());

        let cfg = Self {
            domain_name,
            port,
            environment,
            storage_dir,
            db_dir,
            upload_key,
            pull_key,
            admin_key,
            ssl_cert,
            ssl_key,
            dev_self_signed_cert,
            max_upload_mb,
            rate_limit_per_minute,
            upload_rate_limit_per_minute,
            auth_failure_limit_per_minute,
            auth_block_duration_minutes,
            scanner_block_enabled,
            scanner_block_duration_minutes,
            scanner_failure_threshold,
            scanner_failure_window_seconds,
            datacenter_block_enabled,
            web_enabled,
            web_allowed_ips,
            web_username,
            web_password,
        };

        if cfg.is_production() {
            cfg.validate_production()?;
        }

        Ok(cfg)
    }

    pub fn is_production(&self) -> bool {
        self.environment.eq_ignore_ascii_case("production")
    }

    pub fn is_development(&self) -> bool {
        self.environment.eq_ignore_ascii_case("development")
    }

    pub fn is_test(&self) -> bool {
        self.environment.eq_ignore_ascii_case("test")
    }

    pub fn max_upload_bytes(&self) -> usize {
        self.max_upload_mb * 1024 * 1024
    }

    pub fn database_path(&self) -> PathBuf {
        self.db_dir.join("recordings.db")
    }

    pub fn ensure_directories(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.storage_dir)?;
        std::fs::create_dir_all(&self.db_dir)?;
        if let Some(parent) = self.ssl_cert.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    pub fn validate_production(&self) -> Result<(), String> {
        let keys = [
            ("UPLOAD_KEY", &self.upload_key),
            ("PULL_KEY", &self.pull_key),
        ];

        for (name, val) in keys {
            let lowered = val.to_lowercase();
            if INSECURE_KEY_SUBSTRINGS.iter().any(|s| lowered.contains(s)) {
                return Err(format!(
                    "Insecure production credential detected for {name}. Must generate a strong random secret."
                ));
            }
            if val.len() < 32 {
                return Err(format!(
                    "Production {name} is too short (minimum 32 chars required)."
                ));
            }
        }

        if let Some(admin_key) = &self.admin_key {
            let lowered = admin_key.to_lowercase();
            if INSECURE_KEY_SUBSTRINGS.iter().any(|s| lowered.contains(s)) {
                return Err(
                    "Insecure production credential detected for ADMIN_KEY. Must generate a strong random secret."
                        .to_string(),
                );
            }
            if admin_key.len() < 32 {
                return Err(
                    "Production ADMIN_KEY is too short (minimum 32 chars required).".to_string(),
                );
            }
            if admin_key == &self.upload_key || admin_key == &self.pull_key {
                return Err(
                    "ADMIN_KEY must not be identical to UPLOAD_KEY or PULL_KEY.".to_string()
                );
            }
        }

        if self.upload_key == self.pull_key {
            return Err("UPLOAD_KEY and PULL_KEY must not be identical.".to_string());
        }

        if self.web_enabled {
            let lowered_web = self.web_password.to_lowercase();
            if INSECURE_KEY_SUBSTRINGS
                .iter()
                .any(|s| lowered_web.contains(s))
            {
                return Err(
                    "Insecure production credential detected for WEB_PASSWORD. Must generate a strong random password."
                        .to_string(),
                );
            }
            if self.web_password.len() < 16 {
                return Err(
                    "Production WEB_PASSWORD is too short (minimum 16 chars required).".to_string(),
                );
            }
        }

        Ok(())
    }
}
