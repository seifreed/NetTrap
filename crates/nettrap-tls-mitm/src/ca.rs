use chrono::Datelike;
use nettrap_core::error::{Error, Result};
use nettrap_fsutil::{
    create_regular_file, ensure_no_symlink_ancestors, open_regular_file_beneath_root,
    strip_current_dir_components,
};
use parking_lot::RwLock;
use rcgen::{
    CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use std::collections::VecDeque;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::parse_x509_certificate;

const MAX_CACHE_SIZE: usize = 1000; // Maximum cached certificates
const CACHE_TTL_SECS: u64 = 3600; // Certificate cache TTL: 1 hour
const MAX_CA_PEM_FILE_BYTES: u64 = 1024 * 1024;
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

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

    fn get_cloned(&mut self, hostname: &str) -> Option<(String, String)> {
        let entry = self.certs.get(hostname)?;
        if entry.created.elapsed().as_secs() >= CACHE_TTL_SECS {
            self.certs.remove(hostname);
            self.order.retain(|queued| queued != hostname);
            return None;
        }
        self.order.retain(|queued| queued != hostname);
        self.order.push_back(hostname.to_string());
        Some((entry.cert_pem.clone(), entry.key_pem.clone()))
    }

    fn insert(&mut self, hostname: String, cert: CachedCert) {
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
        self.order.retain(|key| self.certs.contains_key(key));

        // Evict oldest entries if cache is still full
        while self.certs.len() >= MAX_CACHE_SIZE {
            if let Some(evict_key) = self.order.pop_front() {
                self.certs.remove(&evict_key);
                tracing::debug!("Evicted TLS cert from cache: {}", evict_key);
            } else if let Some(evict_key) = self.certs.keys().next().cloned() {
                self.certs.remove(&evict_key);
                tracing::debug!("Evicted unordered TLS cert from cache: {}", evict_key);
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
    now: fn() -> chrono::DateTime<chrono::Utc>,
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
            now: chrono::Utc::now,
            cache: RwLock::new(CertCache::new()),
        })
    }

    /// Load CA from PEM files.
    pub fn from_pem_files(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_pem = read_ca_pem_file(cert_path, "CA certificate")?;
        let key_pem = read_ca_pem_file(key_path, "CA key")?;

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
            now: chrono::Utc::now,
            cache: RwLock::new(CertCache::new()),
        })
    }

    pub fn with_cert_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cert_dir = Some(dir.into());
        self
    }

    pub fn with_now(mut self, now: fn() -> chrono::DateTime<chrono::Utc>) -> Self {
        self.now = now;
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
        ensure_no_symlink_ancestors(dir).map_err(|err| Error::Tls(err.to_string()))?;
        if dir
            .symlink_metadata()
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(Error::Tls("symlink path component".into()));
        }
        std::fs::create_dir_all(dir)?;
        write_pem_pair_atomically(dir, "ca.crt", &self.ca_cert_pem, "ca.key", &self.ca_key_pem)?;
        tracing::info!("CA certificate saved to {}", dir.display());
        Ok(())
    }

    /// Generate a certificate for a given hostname (cached)
    pub fn generate_cert_for_host(&self, hostname: &str) -> Result<(String, String)> {
        let Some(hostname) = normalize_cert_hostname(hostname) else {
            return Err(Error::Tls("invalid certificate hostname".to_string()));
        };
        let hostname = match hostname.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) => ip.to_string(),
            Ok(std::net::IpAddr::V6(ip)) => ip
                .to_ipv4_mapped()
                .map_or_else(|| ip.to_string(), |mapped| mapped.to_string()),
            Err(_) => hostname.to_ascii_lowercase(),
        };

        // Check cache
        {
            let mut cache = self.cache.write();
            if let Some(cached) = cache.get_cloned(hostname.as_str()) {
                return Ok(cached);
            }
        }

        let san = vec![hostname.to_string()];
        let mut params = CertificateParams::new(san)
            .map_err(|e| Error::Tls(format!("Failed to create cert params: {}", e)))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, &hostname);
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let now = (self.now)();
        let not_before = now - chrono::Duration::days(1);
        let not_after = now + chrono::Duration::days(730);
        let not_before_month = u8::try_from(not_before.month())
            .map_err(|_| Error::Tls("certificate not_before month out of range".to_string()))?;
        let not_before_day = u8::try_from(not_before.day())
            .map_err(|_| Error::Tls("certificate not_before day out of range".to_string()))?;
        let not_after_month = u8::try_from(not_after.month())
            .map_err(|_| Error::Tls("certificate not_after month out of range".to_string()))?;
        let not_after_day = u8::try_from(not_after.day())
            .map_err(|_| Error::Tls("certificate not_after day out of range".to_string()))?;
        params.not_before =
            rcgen::date_time_ymd(not_before.year(), not_before_month, not_before_day);
        params.not_after = rcgen::date_time_ymd(not_after.year(), not_after_month, not_after_day);

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| Error::Tls(format!("Failed to generate key: {}", e)))?;
        let key_pem = key_pair.serialize_pem();

        let cert = params
            .signed_by(&key_pair, &self.ca_cert, &self.ca_key)
            .map_err(|e| Error::Tls(format!("Failed to sign cert: {}", e)))?;
        let cert_pem = cert.pem();

        if let Some(ref dir) = self.cert_dir {
            let safe_name = hostname.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
            if let Err(e) = ensure_no_symlink_ancestors(dir) {
                return Err(Error::Tls(format!(
                    "Failed to prepare cert directory {:?}: {}",
                    dir, e
                )));
            } else if dir
                .symlink_metadata()
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(Error::Tls("symlink path component".into()));
            } else if let Err(e) = std::fs::create_dir_all(dir) {
                return Err(Error::Tls(format!(
                    "Failed to create cert directory {:?}: {}",
                    dir, e
                )));
            } else {
                write_pem_pair_atomically(
                    dir,
                    &format!("{}.crt", safe_name),
                    &cert_pem,
                    &format!("{}.key", safe_name),
                    &key_pem,
                )?;
            }
        }

        // Cache with LRU eviction — re-check under write lock to avoid TOCTOU duplicates
        {
            let mut cache = self.cache.write();
            if let Some(cached) = cache.get_cloned(hostname.as_str()) {
                return Ok(cached);
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
        let mut cache = self.cache.write();
        let expired: Vec<String> = cache
            .certs
            .iter()
            .filter(|(_, v)| v.created.elapsed().as_secs() >= CACHE_TTL_SECS)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            cache.certs.remove(&key);
            cache.order.retain(|queued| queued != &key);
        }
        cache.certs.len()
    }

    pub fn clear_cache(&self) {
        let mut cache = self.cache.write();
        cache.certs.clear();
        cache.order.clear();
    }
}

fn normalize_cert_hostname(hostname: &str) -> Option<&str> {
    if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(ip)
                if !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast() =>
            {
                Some(hostname)
            }
            std::net::IpAddr::V6(ip)
                if !ip.is_unspecified()
                    && !ip.is_multicast()
                    && ip.to_ipv4_mapped().is_none_or(|mapped| {
                        !mapped.is_unspecified() && !mapped.is_multicast() && !mapped.is_broadcast()
                    }) =>
            {
                Some(hostname)
            }
            _ => None,
        };
    }

    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    if hostname.is_empty()
        || hostname.len() > 253
        || !hostname
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
        || !hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
        || hostname
            .split('.')
            .all(|label| label.chars().all(|ch| ch.is_ascii_digit()))
    {
        return None;
    }

    Some(hostname)
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

/// Write a PEM private key to `path`, restricting it to owner read/write
/// (`0600`) on Unix so the key material is never world-readable. The file is
/// created with the restrictive mode up front (no world-readable window), and
/// existing files are truncated and re-permissioned. On non-Unix platforms the
/// parent directory's ACLs govern access; the bytes are written normally.
fn write_private_key_pem(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_no_symlink_ancestors(parent)?;
        std::fs::create_dir_all(parent)?;
    }

    let mut file = create_regular_file(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Re-assert the mode in case the file pre-existed with looser bits
        // (create+mode only applies to newly created files).
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }

    file.write_all(contents.as_bytes())
}

fn write_pem_pair_atomically(
    dir: &Path,
    cert_name: &str,
    cert_pem: &str,
    key_name: &str,
    key_pem: &str,
) -> Result<()> {
    let cert_path = dir.join(cert_name);
    let key_path = dir.join(key_name);
    reject_existing_directory(&cert_path)?;
    reject_existing_directory(&key_path)?;
    let cert_tmp = temp_file_path(dir, cert_name, "crt");
    let key_tmp = temp_file_path(dir, key_name, "key");

    let cert_write_result = (|| -> Result<()> {
        let mut cert_file = create_regular_file(&cert_tmp)?;
        use std::io::Write;

        cert_file.write_all(cert_pem.as_bytes())?;
        write_private_key_pem(&key_tmp, key_pem)?;

        std::fs::rename(&key_tmp, &key_path)?;
        if let Err(err) = std::fs::rename(&cert_tmp, &cert_path) {
            let _ = std::fs::remove_file(&key_path);
            return Err(Error::from(err));
        }

        Ok(())
    })();

    if cert_write_result.is_err() {
        let _ = std::fs::remove_file(&cert_tmp);
        let _ = std::fs::remove_file(&key_tmp);
    }

    cert_write_result
}

fn reject_existing_directory(path: &Path) -> Result<()> {
    if path
        .symlink_metadata()
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
    {
        return Err(Error::Tls(format!(
            "refusing to replace directory {}",
            path.display()
        )));
    }
    Ok(())
}

fn temp_file_path(dir: &Path, stem: &str, suffix: &str) -> PathBuf {
    let seq = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nonce = uuid::Uuid::new_v4();
    dir.join(format!(".{}.{}.{}.{}.tmp", stem, pid, nonce, seq))
        .with_extension(suffix)
}

fn read_ca_pem_file(path: &Path, label: &str) -> Result<String> {
    let normalized = strip_current_dir_components(path);
    let root = normalized
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let relative = normalized
        .file_name()
        .ok_or_else(|| Error::Tls(format!("{label} path must point to a file")))?;
    let file = open_regular_file_beneath_root(root, Path::new(relative))
        .map_err(|err: std::io::Error| Error::Tls(err.to_string()))?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_CA_PEM_FILE_BYTES {
        return Err(Error::Tls(format!(
            "{} file exceeds load limit ({} > {} bytes)",
            label,
            metadata.len(),
            MAX_CA_PEM_FILE_BYTES
        )));
    }

    let mut limited = file.take(MAX_CA_PEM_FILE_BYTES + 1);
    let mut pem = String::new();
    limited.read_to_string(&mut pem)?;
    if pem.len() as u64 > MAX_CA_PEM_FILE_BYTES {
        return Err(Error::Tls(format!(
            "{} file exceeds load limit ({} > {} bytes)",
            label,
            pem.len(),
            MAX_CA_PEM_FILE_BYTES
        )));
    }
    Ok(pem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, DnType, IsCa};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::pem::parse_x509_pem;
    use x509_parser::prelude::parse_x509_certificate;

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

    fn cert_has_ip_subject_alt_name(pem: &str, expected: &[u8]) -> bool {
        let (_, pem) = parse_x509_pem(pem.as_bytes()).expect("certificate PEM should parse");
        let (_, cert) =
            parse_x509_certificate(&pem.contents).expect("certificate DER should parse");

        cert.extensions().iter().any(|extension| {
            let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() else {
                return false;
            };

            san.general_names.iter().any(|name| match name {
                GeneralName::IPAddress(bytes) => *bytes == expected,
                _ => false,
            })
        })
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
    #[cfg(unix)]
    fn saved_ca_key_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let ca = CertificateAuthority::generate().expect("CA should generate");
        let unique = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("nettrap-ca-perm-{}-{}", std::process::id(), unique));
        ca.save_to_dir(&dir).expect("CA should save");

        let key_mode = std::fs::metadata(dir.join("ca.key"))
            .expect("ca.key should exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            key_mode, 0o600,
            "CA private key must be owner-only (0600), got {key_mode:o}"
        );

        // The public certificate has no such restriction.
        assert!(dir.join("ca.crt").exists());

        let _ = std::fs::remove_dir_all(&dir);
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
    fn generated_leaf_uses_the_injected_clock_for_validity_range() {
        fn fixed_now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(1_704_157_200, 0).expect("valid instant")
        }

        let ca = CertificateAuthority::generate()
            .expect("CA should generate")
            .with_now(fixed_now);
        let (leaf_pem, _) = ca
            .generate_cert_for_host("example.test")
            .expect("leaf cert should be generated");
        let (_, pem) = parse_x509_pem(leaf_pem.as_bytes()).expect("leaf PEM should parse");
        let (_, cert) = parse_x509_certificate(&pem.contents).expect("leaf DER should parse");
        let expected_not_before = fixed_now() - chrono::Duration::days(1);
        let not_before = cert.validity().not_before;
        let day_seconds = chrono::Duration::days(1).num_seconds();

        assert_eq!(
            not_before.timestamp() / day_seconds,
            expected_not_before.timestamp() / day_seconds
        );
    }

    #[test]
    fn generate_cert_for_host_rejects_invalid_hostnames() {
        let ca = CertificateAuthority::generate().expect("CA should generate");

        for hostname in [
            "",
            "bad\r\nexample.test",
            "-bad.example.test",
            "bad..example.test",
            "bad_example.test",
            "0.0.0.0",
            "::",
            "::ffff:0.0.0.0",
        ] {
            let err = ca
                .generate_cert_for_host(hostname)
                .expect_err("invalid hostname should be rejected");

            assert!(err.to_string().contains("invalid certificate hostname"));
        }
        assert_eq!(ca.cache_size(), 0);
    }

    #[test]
    fn generate_cert_for_host_accepts_absolute_hostnames_with_trailing_dots() {
        let ca = CertificateAuthority::generate().expect("CA should generate");

        let (leaf_pem, _) = ca
            .generate_cert_for_host("example.test.")
            .expect("absolute hostname should be accepted");

        assert_eq!(common_name(&leaf_pem, false), "example.test");
        assert_eq!(ca.cache_size(), 1);
    }

    #[test]
    fn generate_cert_for_host_canonicalizes_hostname_case() {
        let ca = CertificateAuthority::generate().expect("CA should generate");

        let upper = ca
            .generate_cert_for_host("EXAMPLE.TEST")
            .expect("uppercase hostname should be accepted");
        let lower = ca
            .generate_cert_for_host("example.test")
            .expect("lowercase hostname should be accepted");

        assert_eq!(upper, lower);
        assert_eq!(ca.cache_size(), 1);
    }

    #[test]
    fn generate_cert_for_host_accepts_ipv4_literal_san() {
        let ca = CertificateAuthority::generate().expect("CA should generate");
        let (leaf_pem, _) = ca
            .generate_cert_for_host("127.0.0.1")
            .expect("IPv4 literal should be accepted");

        assert!(cert_has_ip_subject_alt_name(
            &leaf_pem,
            &std::net::Ipv4Addr::LOCALHOST.octets()
        ));
    }

    #[test]
    fn generate_cert_for_host_canonicalizes_ipv4_mapped_san() {
        let ca = CertificateAuthority::generate().expect("CA should generate");
        let (mapped_pem, _) = ca
            .generate_cert_for_host("::ffff:127.0.0.1")
            .expect("mapped IPv4 literal should be accepted");
        let (plain_pem, _) = ca
            .generate_cert_for_host("127.0.0.1")
            .expect("plain IPv4 literal should be accepted");

        assert_eq!(mapped_pem, plain_pem);
        assert!(cert_has_ip_subject_alt_name(
            &mapped_pem,
            &std::net::Ipv4Addr::LOCALHOST.octets()
        ));
    }

    #[test]
    fn generate_cert_for_host_accepts_ipv6_literal_san() {
        let ca = CertificateAuthority::generate().expect("CA should generate");
        let (leaf_pem, _) = ca
            .generate_cert_for_host("::1")
            .expect("IPv6 literal should be accepted");

        assert!(cert_has_ip_subject_alt_name(
            &leaf_pem,
            &std::net::Ipv6Addr::LOCALHOST.octets()
        ));
    }

    #[test]
    fn generate_cert_for_host_rejects_multicast_and_broadcast_ips() {
        let ca = CertificateAuthority::generate().expect("CA should generate");

        for hostname in [
            "224.0.0.1",
            "255.255.255.255",
            "ff02::1",
            "::ffff:255.255.255.255",
        ] {
            let err = ca
                .generate_cert_for_host(hostname)
                .expect_err("special IP should be rejected");

            assert!(
                err.to_string().contains("invalid certificate hostname"),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn generate_cert_for_host_canonicalizes_ipv6_cache_keys() {
        let ca = CertificateAuthority::generate().expect("CA should generate");
        let upper = ca
            .generate_cert_for_host("2001:0DB8:0:0::1")
            .expect("IPv6 literal should be accepted");
        let lower = ca
            .generate_cert_for_host("2001:db8::1")
            .expect("IPv6 literal should be accepted");

        assert_eq!(upper, lower);
        assert_eq!(ca.cache_size(), 1);
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

    #[test]
    fn from_pem_files_rejects_oversized_cert_before_loading() {
        let dir = std::env::temp_dir().join(format!(
            "nettrap-ca-oversized-{}-{}",
            std::process::id(),
            TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should be created");
        let cert_path = dir.join("ca.crt");
        let key_path = dir.join("ca.key");
        let cert_file = std::fs::File::create(&cert_path).expect("create sparse cert");
        cert_file
            .set_len(MAX_CA_PEM_FILE_BYTES + 1)
            .expect("extend sparse cert");
        std::fs::write(&key_path, "not-used").expect("write placeholder key");

        let err = match CertificateAuthority::from_pem_files(&cert_path, &key_path) {
            Ok(_) => panic!("oversized CA cert should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("exceeds load limit"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn save_to_dir_rejects_symlinked_parent_directory() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-ca-save-parent-{}-{}",
            std::process::id(),
            TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let real_parent = root.join("real");
        let linked_parent = root.join("linked");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");

        let ca = CertificateAuthority::generate().expect("CA should generate");
        let err = ca
            .save_to_dir(&linked_parent.join("certs"))
            .expect_err("symlinked parent should be rejected");

        assert!(matches!(err, Error::Tls(_)));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn read_ca_pem_file_rejects_symlinked_parent_directory() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-ca-parent-{}-{}",
            std::process::id(),
            TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let real_parent = root.join("real");
        let linked_parent = root.join("linked");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        std::fs::write(real_parent.join("ca.crt"), "-----BEGIN CERTIFICATE-----\n")
            .expect("write cert");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");

        let err = read_ca_pem_file(&linked_parent.join("ca.crt"), "certificate")
            .expect_err("symlinked parent should be rejected");

        assert!(matches!(err, Error::Tls(_)));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn read_ca_pem_file_accepts_trailing_current_dir_component() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-ca-curdir-{}-{}",
            std::process::id(),
            TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("create temp root");
        let cert_path = root.join("ca.crt");
        let key_path = root.join("ca.key");
        std::fs::write(&cert_path, "-----BEGIN CERTIFICATE-----\n").expect("write cert");
        std::fs::write(&key_path, "-----BEGIN PRIVATE KEY-----\n").expect("write key");

        let cert = read_ca_pem_file(&cert_path.join("."), "certificate")
            .expect("trailing current-dir component should be accepted");
        let key = read_ca_pem_file(&key_path.join("."), "key")
            .expect("trailing current-dir component should be accepted");

        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("BEGIN PRIVATE KEY"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn temp_file_path_is_unique_without_clock_dependency() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-ca-temp-{}-{}",
            std::process::id(),
            TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("create temp root");

        let first = temp_file_path(&root, "ca", "crt");
        let second = temp_file_path(&root, "ca", "crt");

        assert_ne!(first, second);
        assert_eq!(first.extension().and_then(|ext| ext.to_str()), Some("crt"));
        assert_eq!(second.extension().and_then(|ext| ext.to_str()), Some("crt"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn read_ca_pem_file_loads_relative_regular_file() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-ca-relative-{}-{}",
            std::process::id(),
            TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(root.join("ca.crt"), "-----BEGIN CERTIFICATE-----\n").expect("write cert");
        std::fs::write(root.join("ca.key"), "-----BEGIN PRIVATE KEY-----\n").expect("write key");
        let previous_dir = std::env::current_dir().expect("current dir");
        std::env::set_current_dir(&root).expect("switch to temp root");

        let cert = read_ca_pem_file(Path::new("ca.crt"), "certificate")
            .expect("relative certificate should load");
        let key = read_ca_pem_file(Path::new("ca.key"), "key").expect("relative key should load");

        std::env::set_current_dir(previous_dir).expect("restore current dir");
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("BEGIN PRIVATE KEY"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn save_to_dir_replaces_symlinked_final_key_path_without_following_target() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-ca-save-final-{}-{}",
            std::process::id(),
            TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let dir = root.join("dir");
        let real_parent = root.join("real");
        std::fs::create_dir_all(&dir).expect("create dir");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        let target = real_parent.join("ca.key");
        std::fs::write(&target, "existing").expect("write target");
        std::os::unix::fs::symlink(&target, dir.join("ca.key")).expect("create symlink");

        let ca = CertificateAuthority::generate().expect("CA should generate");
        ca.save_to_dir(&dir)
            .expect("symlinked key path should be replaced safely");

        assert_eq!(
            std::fs::read_to_string(&target).expect("read original target"),
            "existing"
        );
        assert!(dir.join("ca.key").is_file());

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn save_to_dir_rejects_symlinked_final_directory() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-ca-save-dir-{}-{}",
            std::process::id(),
            TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let real_parent = root.join("real");
        let target_dir = real_parent.join("certs");
        std::fs::create_dir_all(&target_dir).expect("create target dir");
        let link = root.join("certs");
        std::os::unix::fs::symlink(&target_dir, &link).expect("create symlink");

        let ca = CertificateAuthority::generate().expect("CA should generate");
        let err = ca
            .save_to_dir(&link)
            .expect_err("symlinked final directory should be rejected");

        assert!(matches!(err, Error::Tls(_)));
        assert_eq!(
            std::fs::read_dir(&target_dir)
                .expect("read target dir")
                .count(),
            0
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn save_to_dir_rejects_key_directory_before_writing_cert() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-ca-save-cleanup-{}-{}",
            std::process::id(),
            TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let dir = root.join("certs");
        std::fs::create_dir_all(&dir).expect("create cert dir");
        std::fs::create_dir_all(dir.join("ca.key")).expect("create blocking key dir");

        let ca = CertificateAuthority::generate().expect("CA should generate");
        let err = ca.save_to_dir(&dir).expect_err("key directory should fail");

        assert!(matches!(err, Error::Tls(_)));
        assert!(!dir.join("ca.crt").exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn save_to_dir_preserves_existing_key_when_cert_path_is_directory() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-ca-save-cert-dir-{}-{}",
            std::process::id(),
            TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let dir = root.join("certs");
        std::fs::create_dir_all(dir.join("ca.crt")).expect("create blocking cert dir");
        std::fs::write(dir.join("ca.key"), "existing-key").expect("write existing key");

        let ca = CertificateAuthority::generate().expect("CA should generate");
        let err = ca
            .save_to_dir(&dir)
            .expect_err("directory cert path should fail");

        assert!(matches!(err, Error::Tls(_)));
        assert_eq!(
            std::fs::read_to_string(dir.join("ca.key")).expect("read existing key"),
            "existing-key"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn generate_cert_for_host_propagates_symlinked_cert_dir_failure() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-ca-generate-dir-{}-{}",
            std::process::id(),
            TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let real_parent = root.join("real");
        let target_dir = real_parent.join("certs");
        std::fs::create_dir_all(&target_dir).expect("create target dir");
        let link = root.join("certs");
        std::os::unix::fs::symlink(&target_dir, &link).expect("create symlink");

        let ca = CertificateAuthority::generate().expect("CA should generate");
        let ca = ca.with_cert_dir(&link);
        let err = ca
            .generate_cert_for_host("example.test")
            .expect_err("symlinked cert dir should fail");

        assert!(matches!(err, Error::Tls(_)));
        assert!(
            std::fs::read_dir(&target_dir)
                .expect("read target dir")
                .next()
                .is_none()
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cache_size_cleans_up_expired_certs_before_reporting() {
        let ca = CertificateAuthority::generate().expect("CA should generate");
        {
            let mut cache = ca.cache.write();
            cache.certs.insert(
                "expired.example".to_string(),
                CachedCert {
                    cert_pem: "cert".to_string(),
                    key_pem: "key".to_string(),
                    created: std::time::Instant::now()
                        - std::time::Duration::from_secs(CACHE_TTL_SECS + 1),
                },
            );
            cache.order.push_back("expired.example".to_string());
        }

        assert_eq!(ca.cache_size(), 0);
    }

    #[test]
    fn cache_hit_refreshes_lru_order() {
        let ca = CertificateAuthority::generate().expect("CA should generate");
        {
            let mut cache = ca.cache.write();
            cache.certs.insert(
                "first.example".to_string(),
                CachedCert {
                    cert_pem: "cert-a".to_string(),
                    key_pem: "key-a".to_string(),
                    created: std::time::Instant::now(),
                },
            );
            cache.order.push_back("first.example".to_string());
            cache.certs.insert(
                "second.example".to_string(),
                CachedCert {
                    cert_pem: "cert-b".to_string(),
                    key_pem: "key-b".to_string(),
                    created: std::time::Instant::now(),
                },
            );
            cache.order.push_back("second.example".to_string());
        }

        let _ = ca
            .generate_cert_for_host("first.example")
            .expect("cache hit should succeed");

        let cache = ca.cache.read();
        let order: Vec<_> = cache.order.iter().cloned().collect();
        assert_eq!(order, vec!["second.example", "first.example"]);
    }

    #[test]
    fn cache_insert_enforces_capacity_when_lru_order_is_empty() {
        let mut cache = CertCache::new();
        for index in 0..MAX_CACHE_SIZE {
            cache.certs.insert(
                format!("host-{index}.example"),
                CachedCert {
                    cert_pem: "cert".to_string(),
                    key_pem: "key".to_string(),
                    created: std::time::Instant::now(),
                },
            );
        }

        cache.insert(
            "new.example".to_string(),
            CachedCert {
                cert_pem: "new-cert".to_string(),
                key_pem: "new-key".to_string(),
                created: std::time::Instant::now(),
            },
        );

        assert_eq!(cache.certs.len(), MAX_CACHE_SIZE);
        assert!(cache.certs.contains_key("new.example"));
        assert_eq!(cache.order.back().map(String::as_str), Some("new.example"));
    }
}
