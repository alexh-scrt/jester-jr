//! TLS/SSL support for Jester Jr
//!
//! This module handles loading certificates and private keys,
//! configuring TLS acceptors, and managing secure connections.

use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tracing::{info, warn};

/// Load certificates from a PEM file
///
/// # Arguments
/// * `path` - Path to the certificate file
///
/// # Returns
/// * `Ok(Vec<Certificate>)` - Loaded certificates
/// * `Err(String)` - Error message if loading fails
pub fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    // Open the certificate file
    let file =
        File::open(path).map_err(|e| format!("Failed to open cert file '{}': {}", path, e))?;

    // Create a buffered reader for efficient reading
    let mut reader = BufReader::new(file);

    // Parse certificates from PEM format
    let certs = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse certificates: {}", e))?;

    if certs.is_empty() {
        return Err(format!("No certificates found in '{}'", path));
    }

    info!("✅ Loaded {} certificate(s) from {}", certs.len(), path);
    Ok(certs)
}

/// Load private key from a PEM file
///
/// # Arguments
/// * `path` - Path to the private key file
///
/// # Returns
/// * `Ok(PrivateKey)` - Loaded private key
/// * `Err(String)` - Error message if loading fails
pub fn load_private_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    // Open the key file
    let file =
        File::open(path).map_err(|e| format!("Failed to open key file '{}': {}", path, e))?;

    let mut reader = BufReader::new(file);

    // Try to parse as PKCS8 private key
    let keys = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse private key: {}", e))?;

    if keys.is_empty() {
        return Err(format!("No private keys found in '{}'", path));
    }

    if keys.len() > 1 {
        warn!("⚠️  Multiple keys found in '{}', using the first one", path);
    }

    info!("✅ Loaded private key from {}", path);
    Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(keys[0].clone_key()))
}

/// Create a TLS server configuration
///
/// # Arguments
/// * `cert_path` - Path to certificate file
/// * `key_path` - Path to private key file
///
/// # Returns
/// * `Ok(Arc<ServerConfig>)` - Configured TLS server config
/// * `Err(String)` - Error message if configuration fails
pub fn create_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, String> {
    // Load certificates and private key
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    // Create server configuration
    let config = ServerConfig::builder()
        .with_no_client_auth() // Don't require client certificates
        .with_single_cert(certs, key)
        .map_err(|e| format!("Failed to create TLS config: {}", e))?;

    info!("✅ TLS configuration created successfully");
    Ok(Arc::new(config))
}
