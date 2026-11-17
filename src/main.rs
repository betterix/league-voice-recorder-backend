use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use league_voice_recorder_backend::bot_shield::IPIntelService;
use league_voice_recorder_backend::config::Config;
use league_voice_recorder_backend::db::init_db;
use league_voice_recorder_backend::security::{
    generate_self_signed_cert, validate_tls_certificates, InMemoryRateLimiter,
};
use league_voice_recorder_backend::{create_app, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = Config::from_env().map_err(|e| format!("Configuration error: {e}"))?;
    config.ensure_directories()?;

    let db = init_db(&config.database_path()).await?;
    info!(
        "Database initialized at {}",
        config.database_path().display()
    );

    let rate_limiter = InMemoryRateLimiter::new();
    let _ = rate_limiter.load_banned_ips_from_db(&db).await;

    let ip_intel = IPIntelService::new();
    let _ = ip_intel.load_cache_from_db(&db).await;

    info!(
        "League Voice Recorder Backend v{} initialized",
        env!("CARGO_PKG_VERSION")
    );

    let state = AppState {
        config: Arc::new(config.clone()),
        db,
        rate_limiter,
        ip_intel,
    };

    // TLS Certificate Management
    let cert_path = &config.ssl_cert;
    let key_path = &config.ssl_key;

    if (config.dev_self_signed_cert || config.is_development())
        && (!cert_path.exists() || !key_path.exists())
    {
        generate_self_signed_cert(cert_path, key_path, &config.domain_name)
            .map_err(|e| format!("Dev certificate generation failed: {e}"))?;
    }

    if config.is_production() {
        match validate_tls_certificates(cert_path, key_path) {
            Ok(fingerprint) => {
                info!(
                    "Production TLS configuration validated (SHA-256: {})",
                    fingerprint
                );
            }
            Err(e) => {
                tracing::error!("Production TLS validation failed: {}", e);
                return Err(format!("Production TLS validation failed: {e}").into());
            }
        }
    }

    let app = create_app(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));

    if cert_path.exists() && key_path.exists() {
        let rustls_config = RustlsConfig::from_pem_file(cert_path, key_path).await?;
        info!("Listening on https://{} (native TLS 1.3 direct port)", addr);
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        warn!(
            "Starting server in unencrypted HTTP mode on http://{} (development/test only)",
            addr
        );
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }

    Ok(())
}
