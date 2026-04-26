use chrono::Datelike;
use nettrap_core::error::{Error, Result};
use parking_lot::RwLock;
use rcgen::{
    CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::parse_x509_certificate;

#[allow(unused_imports)]
use std::sync::Arc;

const MAX_CACHE_SIZE: usize = 1000; // Maximum cached certificates
const CACHE_TTL_SECS: u64 = 3600; // Certificate cache TTL: 1 hour

/// LRU cache for certificates with TTL
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
        if let Some(entry) = self.certs.get(hostname) {
            if entry.created.elapsed().as_secs() < CACHE_TTL_SECS {
                return Some(entry);
            }
        }
        None
    }

    fn insert(&mut self, hostname: String, cert: CachedCert) {
        // Evict expired entries first
        let expired: Vec<String> = self
            .certs
            .iter()
            .filter(|(_, v)| v.created.elapsed().as_secs() >= CACHE_TTL_SECS)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &expired {
            self.certs.remove(key);
            self.order.retain(|k| k != key);
        }

        // Evict oldest entries if cache is still full
        while self.certs.len() >= MAX_CACHE_SIZE {
            if let Some(evict_key) = self.order.pop_front() {
                self.certs.remove(&evict_key);
                tracing::debug!("Evicted TLS cert from cache: {}", evict_key);
            } else {
                break;
            }
        }

        self.certs.insert(hostname.clone(), cert);
        self.order.retain(|k| k != &hostname);
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
    created: std::time::Instant,
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
    pub fn from_pem_files(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;

        let key_pair = KeyPair::from_pem(&key_pem)
            .map_err(|e| Error::Tls(format!("Failed to load CA key: {}", e)))?;
        validate_ca_key_matches_cert(&cert_pem, &key_pair)?;

        let params = CertificateParams::from_ca_cert_pem(&cert_pem)
            .map_err(|e| Error::Tls(format!("Failed to parse CA certificate: {}", e)))?;

        let ca_cert = params
            .self_signed(&key_pair)
            .map_err(|e| Error::Tls(format!("Failed to load CA certificate: {}", e)))?;

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
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
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
            if let Err(e) = std::fs::create_dir_all(dir) {
                tracing::warn!("Failed to create cert directory {:?}: {}", dir, e);
            } else {
                if let Err(e) = std::fs::write(dir.join(format!("{}.crt", safe_name)), &cert_pem) {
                    tracing::warn!("Failed to write cert file: {}", e);
                }
                if let Err(e) = std::fs::write(dir.join(format!("{}.key", safe_name)), &key_pem) {
                    tracing::warn!("Failed to write key file: {}", e);
                }
            }
        }

        // Cache with LRU eviction — re-check under write lock to avoid TOCTOU duplicates
        {
            let mut cache = self.cache.write();
            if let Some(cached) = cache.get(hostname) {
                return Ok((cached.cert_pem.clone(), cached.key_pem.clone()));
            }
            cache.insert(
                hostname.to_string(),
                CachedCert {
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    created: std::time::Instant::now(),
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
        let mut cache = self.cache.write();
        cache.certs.clear();
        cache.order.clear();
    }
}

fn validate_ca_key_matches_cert(cert_pem: &str, key_pair: &KeyPair) -> Result<()> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| Error::Tls(format!("Failed to parse CA certificate PEM: {}", e)))?;
    let (_, cert) = parse_x509_certificate(&pem.contents)
        .map_err(|e| Error::Tls(format!("Failed to parse CA certificate DER: {}", e)))?;

    let cert_public_key = cert.public_key().raw;
    let key_public_key = key_pair.public_key_der();
    if cert_public_key != key_public_key.as_slice() {
        return Err(Error::Tls(
            "CA certificate public key does not match CA private key".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, DnType, IsCa};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use x509_parser::pem::parse_x509_pem;

    static TEST_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn common_name(pem: &str, issuer: bool) -> String {
        let (_, pem) = parse_x509_pem(pem.as_bytes()).expect("certificate PEM should parse");
        let (_, cert) =
            parse_x509_certificate(&pem.contents).expect("certificate DER should parse");
        let name = if issuer {
            cert.issuer()
        } else {
            cert.subject()
        };
        name.iter_common_name()
            .next()
            .expect("certificate should have a common name")
            .as_str()
            .expect("common name should be UTF-8")
            .to_string()
    }

    fn write_test_ca(common_name: &str) -> (PathBuf, PathBuf, String) {
        let mut params =
            CertificateParams::new(Vec::<String>::new()).expect("CA params should build");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("CA key should build");
        let cert = params.self_signed(&key).expect("CA cert should build");
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();

        let unique = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("nettrap-ca-test-{}-{}", std::process::id(), unique));
        std::fs::create_dir_all(&dir).expect("temp dir should be created");
        let cert_path = dir.join("ca.crt");
        let key_path = dir.join("ca.key");
        std::fs::write(&cert_path, &cert_pem).expect("CA cert should be written");
        std::fs::write(&key_path, key_pem).expect("CA key should be written");

        (cert_path, key_path, cert_pem)
    }

    #[test]
    fn from_pem_files_preserves_loaded_ca_pem() {
        let (cert_path, key_path, original_pem) = write_test_ca("Trusted Test CA");
        let ca = CertificateAuthority::from_pem_files(&cert_path, &key_path)
            .expect("loaded CA should parse");

        assert_eq!(ca.ca_cert_pem(), original_pem);

        let _ = std::fs::remove_dir_all(cert_path.parent().expect("temp path should have parent"));
    }

    #[test]
    fn generated_leaf_uses_loaded_ca_identity_as_issuer() {
        let (cert_path, key_path, _original_pem) = write_test_ca("Trusted Test CA");
        let ca = CertificateAuthority::from_pem_files(&cert_path, &key_path)
            .expect("loaded CA should parse");
        let (leaf_pem, _) = ca
            .generate_cert_for_host("example.test")
            .expect("leaf cert should be generated");

        assert_eq!(common_name(&leaf_pem, true), "Trusted Test CA");
        assert_eq!(common_name(&leaf_pem, false), "example.test");

        let _ = std::fs::remove_dir_all(cert_path.parent().expect("temp path should have parent"));
    }

    #[test]
    fn from_pem_files_rejects_mismatched_ca_key() {
        let (cert_path, _key_path, _original_pem) = write_test_ca("Trusted Test CA");
        let (_other_cert_path, other_key_path, _other_pem) = write_test_ca("Other Test CA");

        let err = match CertificateAuthority::from_pem_files(&cert_path, &other_key_path) {
            Ok(_) => panic!("mismatched CA key should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("does not match CA private key"));

        let _ = std::fs::remove_dir_all(cert_path.parent().expect("temp path should have parent"));
        let _ = std::fs::remove_dir_all(
            other_key_path
                .parent()
                .expect("temp path should have parent"),
        );
    }
}
