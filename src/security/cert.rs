use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use sha2::{Digest, Sha256};
use std::path::Path;
use tracing::{info, warn};

pub fn validate_tls_certificates(cert_path: &Path, key_path: &Path) -> Result<String, String> {
    if !cert_path.exists() {
        return Err(format!(
            "Certificate file not found at {}",
            cert_path.display()
        ));
    }
    if !key_path.exists() {
        return Err(format!(
            "Private key file not found at {}",
            key_path.display()
        ));
    }

    let cert_bytes =
        std::fs::read(cert_path).map_err(|e| format!("Failed to read certificate file: {e}"))?;
    let _key_bytes =
        std::fs::read(key_path).map_err(|e| format!("Failed to read private key file: {e}"))?;

    let hash = Sha256::digest(&cert_bytes);
    let fingerprint = hex::encode(hash).to_uppercase();

    Ok(fingerprint)
}

pub fn generate_self_signed_cert(
    cert_path: &Path,
    key_path: &Path,
    domain: &str,
) -> Result<String, String> {
    if let Some(parent) = cert_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Some(parent) = key_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let key_pair =
        KeyPair::generate().map_err(|e| format!("Failed to generate ECDSA key pair: {e}"))?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domain);
    dn.push(DnType::OrganizationName, "League Voice Recorder");
    params.distinguished_name = dn;

    params.subject_alt_names = vec![
        SanType::DnsName(domain.to_string().try_into().map_err(|e| format!("{e}"))?),
        SanType::DnsName(
            "localhost"
                .to_string()
                .try_into()
                .map_err(|e| format!("{e}"))?,
        ),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("Failed to self-sign certificate: {e}"))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    std::fs::write(cert_path, cert_pem.as_bytes())
        .map_err(|e| format!("Failed to write cert file: {e}"))?;
    std::fs::write(key_path, key_pem.as_bytes())
        .map_err(|e| format!("Failed to write key file: {e}"))?;

    let hash = Sha256::digest(cert.der());
    let fingerprint = hex::encode(hash).to_uppercase();

    warn!(
        "⚠️  DEVELOPMENT MODE: Generated self-signed ECDSA certificate for '{}'.\n    SHA-256 Fingerprint: {}\n    WARNING: NOT publicly trusted. Never use this certificate in production.",
        domain, fingerprint
    );

    info!("Saved generated TLS cert to {}", cert_path.display());
    Ok(fingerprint)
}
