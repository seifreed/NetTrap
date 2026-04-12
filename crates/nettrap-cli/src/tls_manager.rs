use std::sync::Arc;

/// TLS Certificate Authority manager.
///
/// Handles certificate authority initialization with priority:
/// 1. Explicit CA cert/key from config
/// 2. mkcert (trusted CA)
/// 3. Self-signed CA (fallback)
pub struct TlsCaManager;

impl TlsCaManager {
    /// Initialize TLS CA based on configuration.
    ///
    /// Returns None if no listeners require SSL.
    /// Returns Some(CA) if CA was successfully initialized.
    pub fn init(
        tls_ca_cert: Option<&String>,
        tls_ca_key: Option<&String>,
        tls_cert_dir: Option<&String>,
        has_ssl_listeners: bool,
    ) -> crate::Result<Option<Arc<nettrap_tls_mitm::CertificateAuthority>>> {
        if !has_ssl_listeners {
            return Ok(None);
        }

        // Priority 1: Explicit CA cert/key from config
        if let (Some(cert), Some(key)) = (tls_ca_cert, tls_ca_key) {
            tracing::info!("Loading TLS CA from config files");
            let ca = nettrap_tls_mitm::CertificateAuthority::from_pem_files(
                std::path::Path::new(cert),
                std::path::Path::new(key),
            )
            .map_err(|e| crate::Error::Other(format!("Failed to load CA: {}", e)))?;

            if let Some(dir) = tls_cert_dir {
                let _ = ca.save_to_dir(std::path::Path::new(dir));
            }
            return Ok(Some(Arc::new(ca)));
        }

        // Priority 2: mkcert (trusted CA)
        if crate::mkcert::is_mkcert_installed() {
            if let Ok((ca_cert_path, ca_key_path)) = crate::mkcert::get_ca_paths() {
                tracing::info!("Using mkcert trusted CA from {}", ca_cert_path.display());
                match nettrap_tls_mitm::CertificateAuthority::from_pem_files(
                    &ca_cert_path,
                    &ca_key_path,
                ) {
                    Ok(mut ca) => {
                        if let Some(dir) = tls_cert_dir {
                            ca = ca.with_cert_dir(dir);
                        }
                        tracing::info!("TLS MITM using mkcert trusted CA — SSL inspection active");
                        return Ok(Some(Arc::new(ca)));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to load mkcert CA ({}), falling back to self-signed",
                            e
                        );
                    }
                }
            } else {
                tracing::info!(
                    "mkcert found but CA not installed. Run 'nettrap tls install' for trusted certs."
                );
            }
        }

        // Priority 3: Self-signed CA (untrusted fallback)
        tracing::info!(
            "Generating self-signed TLS CA (untrusted — install mkcert for SSL inspection)"
        );
        let ca = nettrap_tls_mitm::CertificateAuthority::generate()
            .map_err(|e| crate::Error::Other(format!("Failed to generate CA: {}", e)))?;

        if let Some(dir) = tls_cert_dir {
            let _ = ca.save_to_dir(std::path::Path::new(dir));
        }

        Ok(Some(Arc::new(ca)))
    }
}
