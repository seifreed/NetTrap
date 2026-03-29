use std::path::{Path, PathBuf};
use parking_lot::RwLock;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use nettrap_core::error::{Error, Result};

#[allow(unused_imports)]
use std::sync::Arc;

/// NetTrap Certificate Authority for dynamic cert generation
pub struct CertificateAuthority {
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    ca_cert_pem: String,
    ca_key_pem: String,
    cert_dir: Option<PathBuf>,
    cache: RwLock<std::collections::HashMap<String, CachedCert>>,
}

struct CachedCert {
    cert_pem: String,
    key_pem: String,
}

impl CertificateAuthority {
    /// Generate a new self-signed CA
    pub fn generate() -> Result<Self> {
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| Error::Tls(format!("Failed to create CA params: {}", e)))?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(rcgen::DnType::CommonName, "NetTrap CA");
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "NetTrap");
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2034, 12, 31);

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| Error::Tls(format!("Failed to generate CA key: {}", e)))?;
        let ca_key_pem = key_pair.serialize_pem();

        let ca_cert = params.self_signed(&key_pair)
            .map_err(|e| Error::Tls(format!("Failed to self-sign CA: {}", e)))?;
        let ca_cert_pem = ca_cert.pem();

        Ok(Self {
            ca_cert,
            ca_key: key_pair,
            ca_cert_pem,
            ca_key_pem,
            cert_dir: None,
            cache: RwLock::new(std::collections::HashMap::new()),
        })
    }

    /// Load CA from PEM files.
    /// Since rcgen does not support parsing existing CA certs, this re-generates
    /// the CA with the same key pair. The original cert PEM is preserved for
    /// chain building.
    pub fn from_pem_files(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;

        let key_pair = KeyPair::from_pem(&key_pem)
            .map_err(|e| Error::Tls(format!("Failed to load CA key: {}", e)))?;

        // Re-create CA params (we cannot parse the original cert with rcgen 0.13,
        // so we rebuild with the same key)
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| Error::Tls(format!("Failed to create CA params: {}", e)))?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(rcgen::DnType::CommonName, "NetTrap CA");
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "NetTrap");
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2034, 12, 31);

        let ca_cert = params.self_signed(&key_pair)
            .map_err(|e| Error::Tls(format!("Failed to recreate CA: {}", e)))?;

        Ok(Self {
            ca_cert,
            ca_key: key_pair,
            ca_cert_pem: cert_pem,
            ca_key_pem: key_pem,
            cert_dir: None,
            cache: RwLock::new(std::collections::HashMap::new()),
        })
    }

    pub fn with_cert_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cert_dir = Some(dir.into());
        self
    }

    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    pub fn ca_key_pem(&self) -> &str {
        &self.ca_key_pem
    }

    /// Save CA cert/key to files
    pub fn save_to_dir(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("ca.crt"), &self.ca_cert_pem)?;
        std::fs::write(dir.join("ca.key"), &self.ca_key_pem)?;
        tracing::info!("CA certificate saved to {}", dir.display());
        Ok(())
    }

    /// Generate a certificate for a given hostname (cached)
    pub fn generate_cert_for_host(&self, hostname: &str) -> Result<(String, String)> {
        // Check cache
        if let Some(cached) = self.cache.read().get(hostname) {
            return Ok((cached.cert_pem.clone(), cached.key_pem.clone()));
        }

        let san = vec![hostname.to_string()];
        let mut params = CertificateParams::new(san)
            .map_err(|e| Error::Tls(format!("Failed to create cert params: {}", e)))?;
        params.distinguished_name.push(rcgen::DnType::CommonName, hostname);
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2025, 12, 31);

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| Error::Tls(format!("Failed to generate key: {}", e)))?;
        let key_pem = key_pair.serialize_pem();

        let cert = params.signed_by(&key_pair, &self.ca_cert, &self.ca_key)
            .map_err(|e| Error::Tls(format!("Failed to sign cert: {}", e)))?;
        let cert_pem = cert.pem();

        // Save to disk if cert_dir configured
        if let Some(ref dir) = self.cert_dir {
            let safe_name = hostname.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
            let _ = std::fs::create_dir_all(dir);
            let _ = std::fs::write(dir.join(format!("{}.crt", safe_name)), &cert_pem);
            let _ = std::fs::write(dir.join(format!("{}.key", safe_name)), &key_pem);
        }

        // Cache
        self.cache.write().insert(hostname.to_string(), CachedCert {
            cert_pem: cert_pem.clone(),
            key_pem: key_pem.clone(),
        });

        tracing::debug!("Generated TLS certificate for {}", hostname);
        Ok((cert_pem, key_pem))
    }

    pub fn cache_size(&self) -> usize {
        self.cache.read().len()
    }

    pub fn clear_cache(&self) {
        self.cache.write().clear();
    }
}
