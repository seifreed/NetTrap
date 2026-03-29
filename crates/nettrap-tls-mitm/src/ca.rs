use chrono::Datelike;
use nettrap_core::error::{Error, Result};
use parking_lot::RwLock;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

#[allow(unused_imports)]
use std::sync::Arc;

const MAX_CACHE_SIZE: usize = 1000; // Maximum cached certificates

/// LRU cache for certificates
struct CertCache {
    certs: std::collections::HashMap<String, CachedCert>,
    order: VecDeque<String>,
}

impl CertCache {
    fn new() -> Self {
        Self {
            certs: std::collections::HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&self, hostname: &str) -> Option<&CachedCert> {
        self.certs.get(hostname)
    }

    fn insert(&mut self, hostname: String, cert: CachedCert) {
        // Evict oldest entries if cache is full
        while self.certs.len() >= MAX_CACHE_SIZE {
            if let Some(evict_key) = self.order.pop_front() {
                self.certs.remove(&evict_key);
                tracing::debug!("Evicted TLS cert from cache: {}", evict_key);
            } else {
                break;
            }
        }

        self.certs.insert(hostname.clone(), cert);
        self.order.push_back(hostname);
    }
}

/// NetTrap Certificate Authority for dynamic cert generation
pub struct CertificateAuthority {
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    ca_cert_pem: String,
    ca_key_pem: String,
    cert_dir: Option<PathBuf>,
    cache: RwLock<CertCache>,
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
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "NetTrap CA");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "NetTrap");
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2034, 12, 31);

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| Error::Tls(format!("Failed to generate CA key: {}", e)))?;
        let ca_key_pem = key_pair.serialize_pem();

        let ca_cert = params
            .self_signed(&key_pair)
            .map_err(|e| Error::Tls(format!("Failed to self-sign CA: {}", e)))?;
        let ca_cert_pem = ca_cert.pem();

        Ok(Self {
            ca_cert,
            ca_key: key_pair,
            ca_cert_pem,
            ca_key_pem,
            cert_dir: None,
            cache: RwLock::new(CertCache::new()),
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
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "NetTrap CA");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "NetTrap");
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2034, 12, 31);

        let ca_cert = params
            .self_signed(&key_pair)
            .map_err(|e| Error::Tls(format!("Failed to recreate CA: {}", e)))?;

        Ok(Self {
            ca_cert,
            ca_key: key_pair,
            ca_cert_pem: cert_pem,
            ca_key_pem: key_pem,
            cert_dir: None,
            cache: RwLock::new(CertCache::new()),
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
        {
            let cache = self.cache.read();
            if let Some(cached) = cache.get(hostname) {
                return Ok((cached.cert_pem.clone(), cached.key_pem.clone()));
            }
        }

        let san = vec![hostname.to_string()];
        let mut params = CertificateParams::new(san)
            .map_err(|e| Error::Tls(format!("Failed to create cert params: {}", e)))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, hostname);
        let now = chrono::Utc::now();
        let not_before = now - chrono::Duration::days(1);
        let not_after = now + chrono::Duration::days(730);
        params.not_before = rcgen::date_time_ymd(
            not_before.year(),
            not_before.month() as u8,
            not_before.day() as u8,
        );
        params.not_after = rcgen::date_time_ymd(
            not_after.year(),
            not_after.month() as u8,
            not_after.day() as u8,
        );

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| Error::Tls(format!("Failed to generate key: {}", e)))?;
        let key_pem = key_pair.serialize_pem();

        let cert = params
            .signed_by(&key_pair, &self.ca_cert, &self.ca_key)
            .map_err(|e| Error::Tls(format!("Failed to sign cert: {}", e)))?;
        let cert_pem = cert.pem();

        // Save to disk if cert_dir configured
        if let Some(ref dir) = self.cert_dir {
            let safe_name = hostname.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
            let _ = std::fs::create_dir_all(dir);
            let _ = std::fs::write(dir.join(format!("{}.crt", safe_name)), &cert_pem);
            let _ = std::fs::write(dir.join(format!("{}.key", safe_name)), &key_pem);
        }

        // Cache with LRU eviction (single lock)
        {
            let mut cache = self.cache.write();
            cache.insert(
                hostname.to_string(),
                CachedCert {
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                },
            );
        }

        tracing::debug!("Generated TLS certificate for {}", hostname);
        Ok((cert_pem, key_pem))
    }

    pub fn cache_size(&self) -> usize {
        self.cache.read().certs.len()
    }

    pub fn clear_cache(&self) {
        self.cache.write().certs.clear();
        self.cache.write().order.clear();
    }
}
