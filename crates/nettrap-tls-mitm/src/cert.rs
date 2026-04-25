use nettrap_core::error::{Error, Result};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::sync::Arc;
use tokio_rustls::rustls;

/// Build a rustls ServerConfig from PEM cert + key strings
pub fn build_server_config(
    cert_pem: &str,
    key_pem: &str,
    ca_cert_pem: &str,
) -> Result<Arc<rustls::ServerConfig>> {
    let certs: Vec<CertificateDer<'_>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Tls(format!("Failed to parse cert: {}", e)))?;

    let ca_certs: Vec<CertificateDer<'_>> = CertificateDer::pem_slice_iter(ca_cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Tls(format!("Failed to parse CA cert: {}", e)))?;

    // Combine: leaf cert + CA cert chain
    let mut full_chain = certs;
    full_chain.extend(ca_certs);

    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| Error::Tls(format!("Failed to parse key: {}", e)))?;

    // Install ring as the crypto provider if not already set
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(full_chain, key)
        .map_err(|e| Error::Tls(format!("Failed to build TLS config: {}", e)))?;

    Ok(Arc::new(config))
}

/// Extract SNI from a TLS ClientHello (first bytes of connection)
pub fn extract_sni(data: &[u8]) -> Option<String> {
    // TLS record header: content_type(1) + version(2) + length(2)
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }

    let record_end = 5 + record_len;
    let handshake = &data[5..record_end];
    if handshake.is_empty() || handshake[0] != 0x01 {
        return None; // Not ClientHello
    }
    if handshake.len() < 4 {
        return None;
    }

    let handshake_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize;
    if handshake.len() < 4 + handshake_len {
        return None;
    }
    let handshake = &handshake[..4 + handshake_len];

    // ClientHello: type(1) + length(3) + version(2) + random(32) = 38
    if handshake.len() < 38 {
        return None;
    }

    let mut pos = 38;

    // Session ID
    if pos >= handshake.len() {
        return None;
    }
    let session_id_len = handshake[pos] as usize;
    if pos + 1 + session_id_len > handshake.len() {
        return None;
    }
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 2 > handshake.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    if pos + 2 + cipher_len > handshake.len() {
        return None;
    }
    pos += 2 + cipher_len;

    // Compression methods
    if pos >= handshake.len() {
        return None;
    }
    let comp_len = handshake[pos] as usize;
    if pos + 1 + comp_len > handshake.len() {
        return None;
    }
    pos += 1 + comp_len;

    // Extensions
    if pos + 2 > handshake.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos.checked_add(ext_len)?;
    if ext_end > handshake.len() {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;
        let next_ext = pos.checked_add(ext_data_len)?;
        if next_ext > ext_end {
            return None;
        }

        if ext_type == 0x0000 {
            // SNI extension
            let sni_end = next_ext;
            if pos + 2 > sni_end {
                return None;
            }
            let sni_list_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
            pos += 2;
            let sni_list_end = pos.checked_add(sni_list_len)?;
            if sni_list_end > sni_end || pos >= sni_list_end {
                return None;
            }
            let _sni_type = handshake[pos];
            pos += 1;
            if pos + 2 > sni_list_end {
                return None;
            }
            let name_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
            pos += 2;
            if pos + name_len > sni_list_end {
                return None;
            }
            return String::from_utf8(handshake[pos..pos + name_len].to_vec()).ok();
        }

        pos = next_ext;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::extract_sni;

    fn client_hello_with_extensions(
        ext_len: u16,
        extension_bytes: &[u8],
        trailing: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&ext_len.to_be_bytes());
        body.extend_from_slice(extension_bytes);

        let handshake_len = body.len();
        let mut record_body = vec![
            0x01,
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ];
        record_body.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(record_body.len() as u16).to_be_bytes());
        record.extend_from_slice(&record_body);
        record.extend_from_slice(trailing);
        record
    }

    #[test]
    fn ignores_sni_outside_declared_record() {
        let sni_extension = [
            0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', b'.', b'c', b'o', b'm',
        ];
        let data = client_hello_with_extensions(0, &[], &sni_extension);

        assert_eq!(extract_sni(&data), None);
    }

    #[test]
    fn rejects_sni_extension_that_overruns_declared_extension_block() {
        let partial_sni_extension = [0x00, 0x00, 0x00, 0x10, 0x00];
        let data = client_hello_with_extensions(5, &partial_sni_extension, &[]);

        assert_eq!(extract_sni(&data), None);
    }
}
