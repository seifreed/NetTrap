use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::rustls;
use nettrap_core::error::{Error, Result};

/// Build a rustls ServerConfig from PEM cert + key strings
pub fn build_server_config(cert_pem: &str, key_pem: &str, ca_cert_pem: &str) -> Result<Arc<rustls::ServerConfig>> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_bytes()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Tls(format!("Failed to parse cert: {}", e)))?;

    let ca_certs = rustls_pemfile::certs(&mut BufReader::new(ca_cert_pem.as_bytes()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Tls(format!("Failed to parse CA cert: {}", e)))?;

    // Combine: leaf cert + CA cert chain
    let mut full_chain = certs;
    full_chain.extend(ca_certs);

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_bytes()))
        .map_err(|e| Error::Tls(format!("Failed to parse key: {}", e)))?
        .ok_or_else(|| Error::Tls("No private key found in PEM".into()))?;

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

    let handshake = &data[5..];
    if handshake.is_empty() || handshake[0] != 0x01 {
        return None; // Not ClientHello
    }

    // ClientHello: type(1) + length(3) + version(2) + random(32) = 38
    if handshake.len() < 38 {
        return None;
    }

    let mut pos = 38;

    // Session ID
    if pos >= handshake.len() { return None; }
    let session_id_len = handshake[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 2 > handshake.len() { return None; }
    let cipher_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_len;

    // Compression methods
    if pos >= handshake.len() { return None; }
    let comp_len = handshake[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    if pos + 2 > handshake.len() { return None; }
    let ext_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_len;
    while pos + 4 <= ext_end && pos + 4 <= handshake.len() {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 { // SNI extension
            if pos + 2 > handshake.len() { return None; }
            let _sni_list_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
            pos += 2;
            if pos >= handshake.len() { return None; }
            let _sni_type = handshake[pos];
            pos += 1;
            if pos + 2 > handshake.len() { return None; }
            let name_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
            pos += 2;
            if pos + name_len > handshake.len() { return None; }
            return String::from_utf8(handshake[pos..pos + name_len].to_vec()).ok();
        }

        pos += ext_data_len;
    }

    None
}
