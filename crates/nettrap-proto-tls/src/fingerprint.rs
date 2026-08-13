use crate::ja3::{
    client_hello_record, ec_point_formats_from_extension, slice_at,
    supported_groups_from_extension, u8_at, u16_at, valid_tls_alpn_protocol,
    valid_tls_sni_hostname,
};

#[derive(Debug, Clone)]
pub struct TlsFingerprint {
    pub ja3: String,
    pub ja3_hash: String,
    pub ja4: String,
    pub versions: Vec<u16>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
}

impl TlsFingerprint {
    pub fn compute_ja3(&mut self) {
        let version = self.versions.first().copied().unwrap_or(0x0303);

        self.ja3 = crate::ja3::calculate_ja3(
            version,
            &self.cipher_suites,
            &self.extensions,
            &self.supported_groups,
            &self.ec_point_formats,
        );
        self.ja3_hash = crate::ja3::ja3_hash(&self.ja3);
    }
}

fn client_hello_version(data: &[u8]) -> Option<u16> {
    let handshake = client_hello_record(data)?;
    u16_at(handshake, 9)
}

/// Compute the byte range containing TLS extensions in a ClientHello.
/// Layout: record_header(5) + handshake_header(4) + client_version(2) + random(32)
///         + session_id_len(1) + session_id(var) + cipher_suites_len(2) + cipher_suites(var)
///         + compression_len(1) + compression(var) + extensions_len(2)
fn find_extensions_range(data: &[u8]) -> Option<std::ops::Range<usize>> {
    let data = client_hello_record(data)?;
    let range = declared_extensions_range(data)?;
    (range.end == data.len()).then_some(range)
}

fn declared_extensions_range(data: &[u8]) -> Option<std::ops::Range<usize>> {
    let mut pos = 43; // session_id_length byte
    let session_id_len = u8_at(data, pos)? as usize;
    if pos + 1 + session_id_len > data.len() {
        return None;
    }
    pos += 1 + session_id_len;

    let cipher_suites_len = u16_at(data, pos)? as usize;
    if pos + 2 + cipher_suites_len > data.len() {
        return None;
    }
    if !cipher_suites_len.is_multiple_of(2) {
        return None;
    }
    pos += 2 + cipher_suites_len;

    let compression_len = u8_at(data, pos)? as usize;
    if pos + 1 + compression_len > data.len() {
        return None;
    }
    pos += 1 + compression_len;

    let extensions_len = u16_at(data, pos)? as usize;
    pos += 2; // now pos points to the first extension

    let end = pos.checked_add(extensions_len)?;
    Some(pos..end)
}

pub fn extract_sni(data: &[u8]) -> Option<String> {
    let extensions = find_extensions_range(data)?;
    let mut pos = extensions.start;

    while pos + 4 <= extensions.end {
        let ext_type = u16_at(data, pos)?;
        let ext_len = u16_at(data, pos + 2)? as usize;
        let ext_data_start = pos + 4;
        let ext_data_end = ext_data_start.checked_add(ext_len)?;
        if ext_data_end > extensions.end {
            return None;
        }

        if ext_type == 0x0000 {
            let ext_data = slice_at(data, ext_data_start, ext_len)?;
            if ext_data.len() < 5 {
                return None;
            }

            let sni_len = u16_at(ext_data, 0)? as usize;
            if 2 + sni_len > ext_data.len() || sni_len < 3 {
                return None;
            }
            let sni_list_end = 2 + sni_len;
            if sni_list_end != ext_data.len() {
                return None;
            }

            let hostname_type = u8_at(ext_data, 2)?;
            if hostname_type != 0 {
                return None;
            }

            let hostname_len = u16_at(ext_data, 3)? as usize;
            let hostname_start = 5;

            if hostname_start + hostname_len == sni_list_end {
                let hostname = slice_at(ext_data, hostname_start, hostname_len)?;
                let hostname = std::str::from_utf8(hostname).ok()?;
                return valid_tls_sni_hostname(hostname).then(|| hostname.to_string());
            }
        }

        pos = ext_data_end;
    }

    None
}

pub fn extract_alpn(data: &[u8]) -> Option<String> {
    let extensions = find_extensions_range(data)?;
    let mut pos = extensions.start;

    while pos + 4 <= extensions.end {
        let ext_type = u16_at(data, pos)?;
        let ext_len = u16_at(data, pos + 2)? as usize;
        let ext_data_start = pos + 4;
        let ext_data_end = ext_data_start.checked_add(ext_len)?;
        if ext_data_end > extensions.end {
            return None;
        }

        if ext_type == 0x0010 {
            let ext_data = slice_at(data, ext_data_start, ext_len)?;
            if ext_data.len() < 3 {
                return None;
            }

            let alpn_ext_len = u16_at(ext_data, 0)? as usize;
            if 2 + alpn_ext_len > ext_data.len() || alpn_ext_len == 0 {
                return None;
            }
            let alpn_list_end = 2 + alpn_ext_len;
            if alpn_list_end != ext_data.len() {
                return None;
            }

            let str_len = u8_at(ext_data, 2)? as usize;
            let str_start = 3;

            if str_len > 0 && str_start + str_len == alpn_list_end {
                let protocol = slice_at(ext_data, str_start, str_len)?;
                let protocol = std::str::from_utf8(protocol).ok()?;
                return valid_tls_alpn_protocol(protocol).then(|| protocol.to_string());
            }
        }

        pos = ext_data_end;
    }

    None
}

pub fn parse_tls_handshake(data: &[u8]) -> Option<TlsFingerprint> {
    let client_hello = client_hello_record(data)?;
    if declared_extensions_range(client_hello).is_some_and(|range| range.end != client_hello.len())
    {
        return None;
    }

    let client_version = client_hello_version(data)?;
    let mut fingerprint = TlsFingerprint {
        ja3: String::new(),
        ja3_hash: String::new(),
        ja4: String::new(),
        versions: vec![client_version],
        cipher_suites: Vec::new(),
        extensions: Vec::new(),
        supported_groups: Vec::new(),
        ec_point_formats: Vec::new(),
        signature_algorithms: Vec::new(),
        sni: extract_sni(data),
        alpn: extract_alpn(data),
    };

    let session_id_len = usize::from(u8_at(client_hello, 43)?);
    if 44 + session_id_len > client_hello.len() {
        return None;
    }
    let ciphers_start = 44usize + session_id_len;

    if ciphers_start + 2 > client_hello.len() {
        return None;
    }

    let ciphers_len = u16_at(client_hello, ciphers_start)? as usize;
    let ciphers_end = ciphers_start + 2 + ciphers_len;
    if !ciphers_len.is_multiple_of(2) {
        return None;
    }
    if ciphers_end > client_hello.len() {
        return None;
    }

    for i in (ciphers_start + 2..ciphers_end).step_by(2) {
        fingerprint.cipher_suites.push(u16_at(client_hello, i)?);
    }

    if let Some(extensions) = find_extensions_range(data) {
        let mut pos = extensions.start;

        while pos + 4 <= extensions.end {
            let ext_type = u16_at(data, pos)?;
            let ext_len = u16_at(data, pos + 2)? as usize;
            let ext_data_start = pos + 4;
            let Some(ext_data_end) = ext_data_start.checked_add(ext_len) else {
                break;
            };
            if ext_data_end > extensions.end {
                break;
            }
            fingerprint.extensions.push(ext_type);
            let ext_data = slice_at(data, ext_data_start, ext_len)?;

            if ext_type == 0x000a {
                fingerprint
                    .supported_groups
                    .extend(supported_groups_from_extension(ext_data)?);
            }

            if ext_type == 0x000b {
                fingerprint.ec_point_formats.extend(
                    ec_point_formats_from_extension(ext_data)?
                        .iter()
                        .map(|&format| format as u16),
                );
            }

            pos = ext_data_end;
        }
        if pos != extensions.end {
            return None;
        }
    }

    fingerprint.compute_ja3();
    fingerprint.ja4 = crate::ja3::ja4_from_handshake(data).unwrap_or_default();
    Some(fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello(client_version: u16, extensions: &[u8]) -> Vec<u8> {
        build_client_hello_with_cipher_suites(client_version, &0x1301u16.to_be_bytes(), extensions)
    }

    fn build_client_hello_with_cipher_suites(
        client_version: u16,
        cipher_suites: &[u8],
        extensions: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&client_version.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
        body.extend_from_slice(cipher_suites);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let handshake_len = body.len() as u32;
        let record_len = (4 + body.len()) as u16;

        let mut data = Vec::new();
        data.push(0x16);
        data.extend_from_slice(&0x0301u16.to_be_bytes());
        data.extend_from_slice(&record_len.to_be_bytes());
        data.push(0x01);
        data.push(((handshake_len >> 16) & 0xff) as u8);
        data.push(((handshake_len >> 8) & 0xff) as u8);
        data.push((handshake_len & 0xff) as u8);
        data.extend_from_slice(&body);
        data
    }

    fn sni_extension(hostname: &str) -> Vec<u8> {
        let hostname = hostname.as_bytes();
        let server_name_list_len = 1 + 2 + hostname.len();
        let ext_len = 2 + server_name_list_len;

        let mut extension = Vec::new();
        extension.extend_from_slice(&0x0000u16.to_be_bytes());
        extension.extend_from_slice(&(ext_len as u16).to_be_bytes());
        extension.extend_from_slice(&(server_name_list_len as u16).to_be_bytes());
        extension.push(0);
        extension.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        extension.extend_from_slice(hostname);
        extension
    }

    fn alpn_extension(protocol: &str) -> Vec<u8> {
        let protocol = protocol.as_bytes();
        let protocol_list_len = 1 + protocol.len();
        let ext_len = 2 + protocol_list_len;

        let mut extension = Vec::new();
        extension.extend_from_slice(&0x0010u16.to_be_bytes());
        extension.extend_from_slice(&(ext_len as u16).to_be_bytes());
        extension.extend_from_slice(&(protocol_list_len as u16).to_be_bytes());
        extension.push(protocol.len() as u8);
        extension.extend_from_slice(protocol);
        extension
    }

    #[test]
    fn parse_tls_handshake_uses_client_hello_version_for_ja3() {
        let data = build_client_hello(0x0301, &[]);
        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");

        assert_eq!(fingerprint.versions, vec![0x0301]);
        assert!(fingerprint.ja3.starts_with("769,"));
        assert_eq!(
            fingerprint.ja3,
            crate::ja3::ja3_from_handshake(&data)
                .expect("ja3 parser should succeed")
                .0
        );
    }

    #[test]
    fn parse_tls_handshake_stays_consistent_with_ja3_parser_for_tls13_clienthello() {
        let supported_versions = [0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
        let data = build_client_hello(0x0303, &supported_versions);
        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");
        let (ja3, hash) = crate::ja3::ja3_from_handshake(&data).expect("ja3 parser should succeed");

        assert_eq!(fingerprint.versions, vec![0x0303]);
        assert_eq!(fingerprint.ja3, ja3);
        assert_eq!(fingerprint.ja3_hash, hash);
    }

    #[test]
    fn tls_metadata_extractors_ignore_bytes_outside_declared_extensions() {
        let mut data = build_client_hello(0x0303, &[]);
        data.extend_from_slice(&sni_extension("outside.example"));
        data.extend_from_slice(&alpn_extension("h2"));

        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");

        assert_eq!(extract_sni(&data), None);
        assert_eq!(extract_alpn(&data), None);
        assert_eq!(fingerprint.sni, None);
        assert_eq!(fingerprint.alpn, None);
    }

    #[test]
    fn tls_metadata_extractors_reject_trailing_bytes_after_extensions_vector() {
        let sni = sni_extension("inside.example");
        let mut extensions = sni.clone();
        extensions.push(0);
        let mut data = build_client_hello(0x0303, &extensions);
        data[50..52].copy_from_slice(&(sni.len() as u16).to_be_bytes());

        assert_eq!(
            parse_tls_handshake(&data).map(|fingerprint| fingerprint.sni),
            None
        );
        assert_eq!(extract_sni(&data), None);
        assert_eq!(extract_alpn(&data), None);
        assert_eq!(crate::ja3::ja3_from_handshake(&data), None);
        assert_eq!(crate::ja3::ja4_from_handshake(&data), None);
    }

    #[test]
    fn tls_metadata_extractors_reject_bytes_outside_declared_record() {
        let mut data = build_client_hello(0x0303, &sni_extension("outside-record.example"));
        data[3..5].copy_from_slice(&8u16.to_be_bytes());

        assert_eq!(parse_tls_handshake(&data).map(|f| f.sni), None);
        assert_eq!(extract_sni(&data), None);
        assert_eq!(extract_alpn(&data), None);
        assert_eq!(crate::ja3::ja3_from_handshake(&data), None);
        assert_eq!(crate::ja3::ja4_from_handshake(&data), None);
    }

    #[test]
    fn tls_metadata_extractors_ignore_bytes_outside_declared_handshake() {
        let mut extensions = sni_extension("outside-handshake.example");
        extensions.extend_from_slice(&alpn_extension("h2"));
        let mut data = build_client_hello(0x0303, &extensions);
        let handshake_len_without_extensions = 41u32;
        data[6] = ((handshake_len_without_extensions >> 16) & 0xff) as u8;
        data[7] = ((handshake_len_without_extensions >> 8) & 0xff) as u8;
        data[8] = (handshake_len_without_extensions & 0xff) as u8;

        let fingerprint = parse_tls_handshake(&data).expect("bounded ClientHello should parse");

        assert_eq!(fingerprint.sni, None);
        assert_eq!(fingerprint.alpn, None);
        assert_eq!(extract_sni(&data), None);
        assert_eq!(extract_alpn(&data), None);
        assert!(
            crate::ja3::ja4_from_handshake(&data)
                .expect("ClientHello without extensions should still fingerprint")
                .starts_with("t12i010000_")
        );
    }

    #[test]
    fn tls_metadata_extractors_accept_values_inside_declared_extensions() {
        let mut extensions = sni_extension("inside.example");
        extensions.extend_from_slice(&alpn_extension("h2"));
        let data = build_client_hello(0x0303, &extensions);
        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");

        assert_eq!(extract_sni(&data).as_deref(), Some("inside.example"));
        assert_eq!(extract_alpn(&data).as_deref(), Some("h2"));
        assert_eq!(fingerprint.sni.as_deref(), Some("inside.example"));
        assert_eq!(fingerprint.alpn.as_deref(), Some("h2"));
    }

    #[test]
    fn tls_metadata_extractors_accept_absolute_sni_hostnames_with_trailing_dots() {
        let data = build_client_hello(0x0303, &sni_extension("inside.example."));
        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");

        assert_eq!(extract_sni(&data).as_deref(), Some("inside.example."));
        assert_eq!(fingerprint.sni.as_deref(), Some("inside.example."));
    }

    #[test]
    fn tls_metadata_extractors_reject_all_numeric_sni_hostnames() {
        let data = build_client_hello(0x0303, &sni_extension("192.0.2.10"));
        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");

        assert_eq!(extract_sni(&data), None);
        assert_eq!(fingerprint.sni, None);
    }

    #[test]
    fn tls_metadata_extractors_reject_oversized_sni_labels() {
        let hostname = format!("{}.example", "a".repeat(64));
        let data = build_client_hello(0x0303, &sni_extension(&hostname));
        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");

        assert_eq!(extract_sni(&data), None);
        assert_eq!(fingerprint.sni, None);
    }

    #[test]
    fn tls_metadata_extractors_reject_controlled_text_fields() {
        for hostname in [
            "evil\n.example",
            "evil example",
            "-evil.example",
            "evil-.example",
            "evil..example",
        ] {
            let data = build_client_hello(0x0303, &sni_extension(hostname));
            let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");

            assert_eq!(extract_sni(&data), None, "{hostname:?}");
            assert_eq!(fingerprint.sni, None, "{hostname:?}");
        }

        for protocol in ["h2\n", "http 1", "\u{7f}bad"] {
            let data = build_client_hello(0x0303, &alpn_extension(protocol));
            let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");

            assert_eq!(extract_alpn(&data), None, "{protocol:?}");
            assert_eq!(fingerprint.alpn, None, "{protocol:?}");
        }
    }

    #[test]
    fn tls_metadata_extractors_reject_trailing_bytes_after_declared_extension_lists() {
        let mut sni = sni_extension("inside.example");
        let sni_ext_len = u16::from_be_bytes([sni[2], sni[3]]) + 1;
        sni[2..4].copy_from_slice(&sni_ext_len.to_be_bytes());
        sni.push(0);

        let data = build_client_hello(0x0303, &sni);
        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");
        assert_eq!(extract_sni(&data), None);
        assert_eq!(fingerprint.sni, None);

        let mut alpn = alpn_extension("h2");
        let alpn_ext_len = u16::from_be_bytes([alpn[2], alpn[3]]) + 1;
        alpn[2..4].copy_from_slice(&alpn_ext_len.to_be_bytes());
        alpn.push(0);

        let data = build_client_hello(0x0303, &alpn);
        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");
        assert_eq!(extract_alpn(&data), None);
        assert_eq!(fingerprint.alpn, None);
    }

    #[test]
    fn tls_metadata_extractors_reject_trailing_bytes_inside_declared_extension_lists() {
        let mut sni = sni_extension("inside.example");
        let sni_ext_len = u16::from_be_bytes([sni[2], sni[3]]) + 1;
        let sni_list_len = u16::from_be_bytes([sni[4], sni[5]]) + 1;
        sni[2..4].copy_from_slice(&sni_ext_len.to_be_bytes());
        sni[4..6].copy_from_slice(&sni_list_len.to_be_bytes());
        sni.push(0);

        let data = build_client_hello(0x0303, &sni);
        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");
        assert_eq!(extract_sni(&data), None);
        assert_eq!(fingerprint.sni, None);

        let mut alpn = alpn_extension("h2");
        let alpn_ext_len = u16::from_be_bytes([alpn[2], alpn[3]]) + 1;
        let alpn_list_len = u16::from_be_bytes([alpn[4], alpn[5]]) + 1;
        alpn[2..4].copy_from_slice(&alpn_ext_len.to_be_bytes());
        alpn[4..6].copy_from_slice(&alpn_list_len.to_be_bytes());
        alpn.push(0);

        let data = build_client_hello(0x0303, &alpn);
        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");
        assert_eq!(extract_alpn(&data), None);
        assert_eq!(fingerprint.alpn, None);
    }

    #[test]
    fn tls_fingerprinters_reject_odd_cipher_suite_length() {
        let data = build_client_hello_with_cipher_suites(0x0303, &[1], &[]);

        assert_eq!(
            parse_tls_handshake(&data).map(|fingerprint| fingerprint.ja3),
            None
        );
        assert_eq!(extract_sni(&data), None);
        assert_eq!(extract_alpn(&data), None);
    }

    #[test]
    fn tls_fingerprinters_reject_truncated_cipher_suite_length() {
        let mut data = build_client_hello(0x0303, &[]);
        let handshake_len = 35u32;
        let record_len = 4 + handshake_len as u16;
        data[3..5].copy_from_slice(&record_len.to_be_bytes());
        data[6] = ((handshake_len >> 16) & 0xff) as u8;
        data[7] = ((handshake_len >> 8) & 0xff) as u8;
        data[8] = (handshake_len & 0xff) as u8;

        assert_eq!(
            parse_tls_handshake(&data).map(|fingerprint| fingerprint.ja3),
            None
        );
        assert_eq!(crate::ja3::ja3_from_handshake(&data), None);
        assert_eq!(crate::ja3::ja4_from_handshake(&data), None);
    }

    #[test]
    fn tls_fingerprinters_reject_trailing_extension_bytes() {
        let data = build_client_hello(0x0303, &[0xff]);

        assert_eq!(
            parse_tls_handshake(&data).map(|fingerprint| fingerprint.ja3),
            None
        );
        assert_eq!(crate::ja3::ja3_from_handshake(&data), None);
        assert_eq!(crate::ja3::ja4_from_handshake(&data), None);
    }

    #[test]
    fn parse_tls_handshake_rejects_overdeclared_extensions_vector() {
        let mut data = build_client_hello(0x0303, &sni_extension("inside.example"));
        let extensions_len = u16::from_be_bytes([data[50], data[51]]);
        data[50..52].copy_from_slice(&extensions_len.saturating_add(1).to_be_bytes());

        assert_eq!(
            parse_tls_handshake(&data).map(|fingerprint| fingerprint.ja3),
            None
        );
        assert_eq!(crate::ja3::ja3_from_handshake(&data), None);
        assert_eq!(crate::ja3::ja4_from_handshake(&data), None);
    }

    #[test]
    fn tls_sni_extractor_rejects_hostname_outside_declared_sni_list() {
        let hostname = b"outside.example";
        let mut extension = Vec::new();
        extension.extend_from_slice(&0x0000u16.to_be_bytes());
        extension.extend_from_slice(&((2 + 3 + hostname.len()) as u16).to_be_bytes());
        extension.extend_from_slice(&3u16.to_be_bytes());
        extension.push(0);
        extension.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        extension.extend_from_slice(hostname);
        let data = build_client_hello(0x0303, &extension);

        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");

        assert_eq!(extract_sni(&data), None);
        assert_eq!(fingerprint.sni, None);
    }

    #[test]
    fn tls_alpn_extractor_rejects_protocol_outside_declared_alpn_list() {
        let mut extension = Vec::new();
        extension.extend_from_slice(&0x0010u16.to_be_bytes());
        extension.extend_from_slice(&5u16.to_be_bytes());
        extension.extend_from_slice(&1u16.to_be_bytes());
        extension.push(2);
        extension.extend_from_slice(b"h2");
        let data = build_client_hello(0x0303, &extension);

        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");

        assert_eq!(extract_alpn(&data), None);
        assert_eq!(fingerprint.alpn, None);
    }

    #[test]
    fn tls_fingerprinters_ignore_short_supported_groups_extension() {
        let short_supported_groups = [0x00, 0x0a, 0x00, 0x01, 0xff];
        let data = build_client_hello(0x0303, &short_supported_groups);

        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");
        let (ja3, _) = crate::ja3::ja3_from_handshake(&data).expect("ja3 parser should succeed");
        let ja4 = crate::ja3::ja4_from_handshake(&data);

        assert!(fingerprint.supported_groups.is_empty());
        assert!(ja3.contains(",10,,"));
        assert!(ja4.is_some());
    }

    #[test]
    fn tls_fingerprinters_ignore_malformed_supported_group_and_point_format_lengths() {
        let malformed_supported_groups = [0x00, 0x0a, 0x00, 0x05, 0x00, 0x03, 0x00, 0x1d, 0xff];
        let malformed_point_formats = [0x00, 0x0b, 0x00, 0x03, 0x01, 0x00, 0xff];
        let mut extensions = malformed_supported_groups.to_vec();
        extensions.extend_from_slice(&malformed_point_formats);
        let data = build_client_hello(0x0303, &extensions);

        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");
        let (ja3, _) = crate::ja3::ja3_from_handshake(&data).expect("JA3 should parse");

        assert!(fingerprint.supported_groups.is_empty());
        assert!(fingerprint.ec_point_formats.is_empty());
        assert_eq!(ja3, "771,4865,10-11,,");
    }

    #[test]
    fn tls_fingerprinters_ignore_empty_ec_point_formats_extension() {
        let empty_ec_point_formats = [0x00, 0x0b, 0x00, 0x00];
        let data = build_client_hello(0x0303, &empty_ec_point_formats);

        let fingerprint = parse_tls_handshake(&data).expect("handshake should parse");
        let (ja3, _) = crate::ja3::ja3_from_handshake(&data).expect("ja3 parser should succeed");
        let ja4 = crate::ja3::ja4_from_handshake(&data);

        assert!(fingerprint.ec_point_formats.is_empty());
        assert!(ja3.ends_with("11,,"));
        assert!(ja4.is_some());
    }
}
