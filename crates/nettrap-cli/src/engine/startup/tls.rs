use std::path::Path;
use std::sync::Arc;

use crate::config::EngineConfig;

pub(super) fn init_tls_ca(
    config: &EngineConfig,
) -> crate::Result<Option<Arc<nettrap_tls_mitm::CertificateAuthority>>> {
    let needs_tls = config.listeners.iter().any(|listener| listener.use_ssl);
    if !needs_tls {
        return Ok(None);
    }

    if let (Some(cert), Some(key)) = (&config.tls_ca_cert, &config.tls_ca_key) {
        tracing::info!("Loading TLS CA from config files");
        let ca =
            nettrap_tls_mitm::CertificateAuthority::from_pem_files(Path::new(cert), Path::new(key))
                .map_err(|err| crate::Error::Other(format!("Failed to load CA: {}", err)))?;

        if let Some(ref dir) = config.tls_cert_dir
            && let Err(err) = ca.save_to_dir(Path::new(dir))
        {
            tracing::warn!("Failed to save TLS CA to {}: {}", dir, err);
        }
        return Ok(Some(Arc::new(ca)));
    }

    if crate::mkcert::is_mkcert_installed() {
        if let Ok((ca_cert_path, ca_key_path)) = crate::mkcert::get_ca_paths() {
            tracing::info!("Using mkcert trusted CA from {}", ca_cert_path.display());
            match nettrap_tls_mitm::CertificateAuthority::from_pem_files(
                &ca_cert_path,
                &ca_key_path,
            ) {
                Ok(mut ca) => {
                    if let Some(ref dir) = config.tls_cert_dir {
                        ca = ca.with_cert_dir(dir);
                    }
                    ca = ca.with_now(crate::faketime::fake_now);
                    tracing::info!("TLS MITM using mkcert trusted CA — SSL inspection active");
                    return Ok(Some(Arc::new(ca)));
                }
                Err(err) => {
                    tracing::warn!(
                        "Failed to load mkcert CA ({}), falling back to self-signed",
                        err
                    );
                }
            }
        } else {
            tracing::info!(
                "mkcert found but CA not installed. Run 'nettrap tls install' for trusted certs."
            );
        }
    }

    tracing::info!("Generating self-signed TLS CA (untrusted — install mkcert for SSL inspection)");
    let ca = nettrap_tls_mitm::CertificateAuthority::generate()
        .map(|ca| ca.with_now(crate::faketime::fake_now))
        .map_err(|err| crate::Error::Other(format!("Failed to generate CA: {}", err)))?;

    if let Some(ref dir) = config.tls_cert_dir
        && let Err(err) = ca.save_to_dir(Path::new(dir))
    {
        tracing::warn!("Failed to save CA certificate to {:?}: {}", dir, err);
    }

    Ok(Some(Arc::new(ca)))
}
