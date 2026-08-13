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

    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(full_chain, key)
        .map_err(|e| Error::Tls(format!("Failed to build TLS config: {}", e)))?;

    Ok(Arc::new(config))
}

/// Bounds-checked big-endian u16 read.
///
/// Returns `None` under exactly the condition the inline guard
/// `if pos + 2 > bound { return None; }` would, otherwise reads the two
/// bytes at `pos`/`pos + 1` as a big-endian u16. `bound` must be `<=
/// data.len()` (always true for the slices/offsets threaded here), so the
/// indexing is guaranteed in range whenever the guard passes.
fn read_u16_at(data: &[u8], pos: usize, bound: usize) -> Option<u16> {
    let end = pos.checked_add(2)?;
    if end > bound {
        return None;
    }
    Some(u16::from_be_bytes([data[pos], data[pos + 1]]))
}

/// Advance/bounds combinator.
///
/// Returns `None` under exactly the condition the inline guard
/// `if pos + n > bound { return None; }` would, otherwise returns the
/// advanced position `pos + n`.
fn advance(pos: usize, n: usize, bound: usize) -> Option<usize> {
    let end = pos.checked_add(n)?;
    if end > bound {
        return None;
    }
    Some(end)
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

    if pos >= handshake.len() {
        return None;
    }
    let session_id_len = handshake[pos] as usize;
    pos = advance(pos, 1 + session_id_len, handshake.len())?;

    let cipher_len = read_u16_at(handshake, pos, handshake.len())? as usize;
    if pos + 2 + cipher_len > handshake.len() {
        return None;
    }
    if !cipher_len.is_multiple_of(2) {
        return None;
    }
    pos = advance(pos, 2 + cipher_len, handshake.len())?;

    if pos >= handshake.len() {
        return None;
    }
    let comp_len = handshake[pos] as usize;
    pos = advance(pos, 1 + comp_len, handshake.len())?;

    let ext_len = read_u16_at(handshake, pos, handshake.len())? as usize;
    pos += 2;
    let ext_end = pos.checked_add(ext_len)?;
    if ext_end != handshake.len() {
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
            let sni_list_len = read_u16_at(handshake, pos, sni_end)? as usize;
            pos += 2;
            let sni_list_end = pos.checked_add(sni_list_len)?;
            if sni_list_end > sni_end || pos >= sni_list_end {
                return None;
            }
            let sni_type = handshake[pos];
            if sni_type != 0 {
                return None;
            }
            pos += 1;
            let name_len = read_u16_at(handshake, pos, sni_list_end)? as usize;
            pos += 2;
            pos = advance(pos, name_len, sni_list_end)?;
            let hostname = std::str::from_utf8(&handshake[pos - name_len..pos]).ok()?;
            return valid_tls_sni_hostname(hostname).then(|| hostname.to_string());
        }

        pos = next_ext;
    }

    None
}

fn valid_tls_sni_hostname(value: &str) -> bool {
    let value = value.strip_suffix('.').unwrap_or(value);
    !value.is_empty()
        && value.len() <= 253
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
        && !value
            .split('.')
            .all(|label| label.chars().all(|ch| ch.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::{advance, extract_sni, read_u16_at};

    fn client_hello_with_extensions(
        ext_len: u16,
        extension_bytes: &[u8],
        trailing: &[u8],
    ) -> Vec<u8> {
        client_hello_with_cipher_suites(
            &0x1301u16.to_be_bytes(),
            ext_len,
            extension_bytes,
            trailing,
        )
    }

    fn client_hello_with_cipher_suites(
        cipher_suites: &[u8],
        ext_len: u16,
        extension_bytes: &[u8],
        trailing: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
        body.extend_from_slice(cipher_suites);
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

    fn sni_extension(hostname: &[u8]) -> Vec<u8> {
        sni_extension_with_type(0, hostname)
    }

    fn sni_extension_with_type(name_type: u8, hostname: &[u8]) -> Vec<u8> {
        let mut extension = Vec::new();
        let sni_ext_len = 2 + 1 + 2 + hostname.len();
        extension.extend_from_slice(&0x0000u16.to_be_bytes());
        extension.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        extension.extend_from_slice(&((1 + 2 + hostname.len()) as u16).to_be_bytes());
        extension.push(name_type);
        extension.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        extension.extend_from_slice(hostname);
        extension
    }

    #[test]
    fn advance_rejects_overflowing_offset() {
        assert_eq!(advance(usize::MAX, 1, usize::MAX), None);
    }

    #[test]
    fn read_u16_at_rejects_overflowing_offset() {
        assert_eq!(read_u16_at(&[], usize::MAX, usize::MAX), None);
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

    #[test]
    fn rejects_trailing_bytes_after_declared_extension_block() {
        let extension = sni_extension(b"example.com");
        let mut extension_bytes = extension.clone();
        extension_bytes.push(0);
        let data = client_hello_with_extensions(extension.len() as u16, &extension_bytes, &[]);

        assert_eq!(extract_sni(&data), None);
    }

    #[test]
    fn rejects_sni_when_cipher_suite_vector_length_is_odd() {
        let extension = sni_extension(b"example.com");
        let data = client_hello_with_cipher_suites(&[1], extension.len() as u16, &extension, &[]);

        assert_eq!(extract_sni(&data), None);
    }

    #[test]
    fn rejects_sni_names_that_are_not_host_name_type() {
        let extension = sni_extension_with_type(1, b"example.com");
        let data = client_hello_with_extensions(extension.len() as u16, &extension, &[]);

        assert_eq!(extract_sni(&data), None);
    }

    #[test]
    fn rejects_invalid_sni_hostnames() {
        for hostname in [
            b"".as_slice(),
            b"127.0.0.1".as_slice(),
            b"bad\r\nexample.com".as_slice(),
            b"-bad.example".as_slice(),
            b"bad..example".as_slice(),
        ] {
            let extension = sni_extension(hostname);
            let data = client_hello_with_extensions(extension.len() as u16, &extension, &[]);

            assert_eq!(extract_sni(&data), None, "{hostname:?}");
        }
    }

    #[test]
    fn accepts_absolute_sni_hostnames_with_trailing_dots() {
        let extension = sni_extension(b"example.com.");
        let data = client_hello_with_extensions(extension.len() as u16, &extension, &[]);

        assert_eq!(extract_sni(&data).as_deref(), Some("example.com."));
    }

    #[test]
    fn extracts_sni_from_client_hello_larger_than_512_bytes() {
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x1234u16.to_be_bytes());
        extensions.extend_from_slice(&520u16.to_be_bytes());
        extensions.resize(extensions.len() + 520, 0);

        extensions.extend_from_slice(&sni_extension(b"example.com"));

        let data = client_hello_with_extensions(extensions.len() as u16, &extensions, &[]);

        assert!(data.len() > 512);
        assert_eq!(extract_sni(&data).as_deref(), Some("example.com"));
    }
}
