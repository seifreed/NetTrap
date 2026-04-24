use md5::Md5;

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

        let version_str = format!("{}", version);
        let ciphers_str = self
            .cipher_suites
            .iter()
            .map(|c| format!("{}", c))
            .collect::<Vec<_>>()
            .join("-");
        let extensions_str = self
            .extensions
            .iter()
            .map(|e| format!("{}", e))
            .collect::<Vec<_>>()
            .join("-");
        let groups_str = self
            .supported_groups
            .iter()
            .map(|g| format!("{}", g))
            .collect::<Vec<_>>()
            .join("-");
        let formats_str = self
            .ec_point_formats
            .iter()
            .map(|f| format!("{}", f))
            .collect::<Vec<_>>()
            .join("-");

        self.ja3 = format!(
            "{},{},{},{},{}",
            version_str, ciphers_str, extensions_str, groups_str, formats_str
        );

        // JA3 spec mandates MD5 hash
        use md5::Digest;
        let mut hasher = Md5::new();
        hasher.update(self.ja3.as_bytes());
        self.ja3_hash = format!("{:x}", hasher.finalize());
    }
}

fn client_hello_version(data: &[u8]) -> Option<u16> {
    if data.len() < 11 || data[0] != 0x16 || data[5] != 0x01 {
        return None;
    }

    Some(u16::from_be_bytes([data[9], data[10]]))
}

/// Compute the byte range containing TLS extensions in a ClientHello.
/// Layout: record_header(5) + handshake_header(4) + client_version(2) + random(32)
///         + session_id_len(1) + session_id(var) + cipher_suites_len(2) + cipher_suites(var)
///         + compression_len(1) + compression(var) + extensions_len(2)
fn find_extensions_range(data: &[u8]) -> Option<std::ops::Range<usize>> {
    if data.len() < 44 || data[0] != 0x16 || data[1] != 0x03 || data[5] != 0x01 {
        return None;
    }
    let mut pos = 43; // session_id_length byte
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    if pos + 1 + session_id_len > data.len() {
        return None;
    }
    pos += 1 + session_id_len;

    if pos + 2 > data.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    if pos + 2 + cipher_suites_len > data.len() {
        return None;
    }
    pos += 2 + cipher_suites_len;

    if pos >= data.len() {
        return None;
    }
    let compression_len = data[pos] as usize;
    if pos + 1 + compression_len > data.len() {
        return None;
    }
    pos += 1 + compression_len;

    if pos + 2 > data.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2; // now pos points to the first extension

    let end = pos.checked_add(extensions_len)?;
    if end > data.len() {
        return None;
    }

    Some(pos..end)
}

pub fn extract_sni(data: &[u8]) -> Option<String> {
    let extensions = find_extensions_range(data)?;
    let mut pos = extensions.start;

    while pos + 4 <= extensions.end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let ext_data_start = pos + 4;
        let ext_data_end = ext_data_start.checked_add(ext_len)?;
        if ext_data_end > extensions.end {
            return None;
        }

        if ext_type == 0x0000 {
            let ext_data = &data[ext_data_start..ext_data_end];
            if ext_data.len() < 5 {
                return None;
            }

            let sni_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
            if 2 + sni_len > ext_data.len() || sni_len < 3 {
                return None;
            }

            let hostname_type = ext_data[2];
            if hostname_type != 0 {
                return None;
            }

            let hostname_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
            let hostname_start = 5;

            if hostname_start + hostname_len <= ext_data.len() {
                return std::str::from_utf8(
                    &ext_data[hostname_start..hostname_start + hostname_len],
                )
                .ok()
                .map(|s| s.to_string());
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
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let ext_data_start = pos + 4;
        let ext_data_end = ext_data_start.checked_add(ext_len)?;
        if ext_data_end > extensions.end {
            return None;
        }

        if ext_type == 0x0010 {
            let ext_data = &data[ext_data_start..ext_data_end];
            if ext_data.len() < 3 {
                return None;
            }

            let alpn_ext_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
            if 2 + alpn_ext_len > ext_data.len() || alpn_ext_len == 0 {
                return None;
            }

            let str_len = ext_data[2] as usize;
            let str_start = 3;

            if str_len > 0 && str_start + str_len <= ext_data.len() {
                return std::str::from_utf8(&ext_data[str_start..str_start + str_len])
                    .ok()
                    .map(|s| s.to_string());
            }
        }

        pos = ext_data_end;
    }

    None
}

pub fn parse_tls_handshake(data: &[u8]) -> Option<TlsFingerprint> {
    if data.len() < 44 {
        return None;
    }

    if data[0] != 0x16 || data[1] != 0x03 {
        return None;
    }

    let handshake_type = data[5];
    if handshake_type != 0x01 {
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

    let session_id_len = data[43] as usize;
    if 44 + session_id_len > data.len() {
        return Some(fingerprint);
    }
    let ciphers_start = 44 + session_id_len;

    if ciphers_start + 2 > data.len() {
        return Some(fingerprint);
    }

    let ciphers_len = u16::from_be_bytes([data[ciphers_start], data[ciphers_start + 1]]) as usize;
    let ciphers_end = ciphers_start + 2 + ciphers_len;

    if ciphers_end <= data.len() && ciphers_len % 2 == 0 {
        for i in (ciphers_start + 2..ciphers_end).step_by(2) {
            fingerprint
                .cipher_suites
                .push(u16::from_be_bytes([data[i], data[i + 1]]));
        }
    }

    if let Some(extensions) = find_extensions_range(data) {
        let mut pos = extensions.start;

        while pos + 4 <= extensions.end {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            let ext_data_start = pos + 4;
            let Some(ext_data_end) = ext_data_start.checked_add(ext_len) else {
                break;
            };
            if ext_data_end > extensions.end {
                break;
            }
            fingerprint.extensions.push(ext_type);
            let ext_data = &data[ext_data_start..ext_data_end];

            if ext_type == 0x000a && ext_data.len() >= 2 {
                // supported_groups
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                if 2 + list_len <= ext_data.len() {
                    for group in ext_data[2..2 + list_len].chunks_exact(2) {
                        fingerprint
                            .supported_groups
                            .push(u16::from_be_bytes([group[0], group[1]]));
                    }
                }
            }

            if ext_type == 0x000b && !ext_data.is_empty() {
                // ec_point_formats
                let fmt_len = ext_data[0] as usize;
                if fmt_len < ext_data.len() {
                    fingerprint
                        .ec_point_formats
                        .extend(ext_data[1..1 + fmt_len].iter().map(|&format| format as u16));
                }
            }

            pos = ext_data_end;
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
        let mut body = Vec::new();
        body.extend_from_slice(&client_version.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
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
