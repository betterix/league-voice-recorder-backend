pub mod auth;
pub mod cert;
pub mod rate_limiter;
pub mod scanner;

pub use auth::{authenticate_key, verify_secret_constant_time, Role};
pub use cert::{generate_self_signed_cert, validate_tls_certificates};
pub use rate_limiter::InMemoryRateLimiter;
pub use scanner::{is_scanner_probe, is_trusted_ip, log_activity_event};
