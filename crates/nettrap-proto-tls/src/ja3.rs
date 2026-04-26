use md5::{Digest as Md5Digest, Md5};
use sha2::Sha256;

pub fn calculate_ja3(
    version: u16,
    cipher_suites: &[u16],
    extensions: &[u16],
    supported_groups: &[u16],
    ec_point_formats: &[u8],
) -> String {
    let ciphers_str = cipher_suites
        .iter()
        .map(|c| format!("{}", c))
        .collect::<Vec<_>>()
        .join("-");

    let extensions_str = extensions
        .iter()
        .map(|e| format!("{}", e))
        .collect::<Vec<_>>()
        .join("-");

    let groups_str = supported_groups
        .iter()
        .map(|g| format!("{}", g))
        .collect::<Vec<_>>()
        .join("-");

    let formats_str = ec_point_formats
        .iter()
        .map(|f| format!("{}", f))
        .collect::<Vec<_>>()
        .join("-");

    format!(
        "{},{},{},{},{}",
        version, ciphers_str, extensions_str, groups_str, formats_str
    )
}

pub fn ja3_hash(ja3: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(ja3.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn client_hello_record(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 44 || data[0] != 0x16 || data[1] != 0x03 || data[5] != 0x01 {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let record_end = 5usize.checked_add(record_len)?;
    if record_len < 4 || record_end > data.len() {
        return None;
    }

    let handshake_len = ((data[6] as usize) << 16) | ((data[7] as usize) << 8) | data[8] as usize;
    let handshake_end = 9usize.checked_add(handshake_len)?;
    if handshake_end > record_end || handshake_end < 44 {
        return None;
    }

    Some(&data[..handshake_end])
}

pub fn ja3_from_handshake(data: &[u8]) -> Option<(String, String)> {
    let data = client_hello_record(data)?;

    // Use ClientHello version (offset 9-10), not record-layer version (offset 1-2)
    let version = u16::from_be_bytes([data[9], data[10]]);

    let mut pos = 43usize;
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

    let ciphers_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    if pos + 2 + ciphers_len > data.len() {
        return None;
    }
    pos += 2;

    let mut cipher_suites = Vec::new();
    if ciphers_len % 2 == 0 {
        for i in (pos..pos + ciphers_len).step_by(2) {
            cipher_suites.push(u16::from_be_bytes([data[i], data[i + 1]]));
        }
        pos += ciphers_len;
    }

    if pos >= data.len() {
        return None;
    }

    let compressions_len = data[pos] as usize;
    if pos + 1 + compressions_len > data.len() {
        return None;
    }
    pos += 1 + compressions_len;

    if pos + 2 > data.len() {
        return None;
    }

    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let extensions_end = pos.checked_add(extensions_len)?;
    if extensions_end > data.len() {
        return None;
    }

    let mut extensions = Vec::new();
    let mut supported_groups = Vec::new();
    let mut ec_point_formats = Vec::new();

    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let ext_data_start = pos + 4;
        let ext_data_end = ext_data_start.checked_add(ext_len)?;
        if ext_data_end > extensions_end {
            return None;
        }

        extensions.push(ext_type);
        let ext_data = &data[ext_data_start..ext_data_end];

        if ext_type == 0x000a && ext_data.len() >= 2 {
            // supported_groups: list_length(2) at ext_data start (pos+4), groups start at pos+6
            let groups_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
            if 2 + groups_len <= ext_data.len() {
                for group in ext_data[2..2 + groups_len].chunks_exact(2) {
                    supported_groups.push(u16::from_be_bytes([group[0], group[1]]));
                }
            }
        }

        if ext_type == 0x000b && !ext_data.is_empty() {
            // ec_point_formats: formats_length(1) at ext_data start (pos+4), formats start at pos+5
            let formats_len = ext_data[0] as usize;
            if formats_len < ext_data.len() {
                ec_point_formats.extend_from_slice(&ext_data[1..1 + formats_len]);
            }
        }

        pos = ext_data_end;
    }
    if pos != extensions_end {
        return None;
    }

    let ja3 = calculate_ja3(
        version,
        &cipher_suites,
        &extensions,
        &supported_groups,
        &ec_point_formats,
    );
    let hash = ja3_hash(&ja3);

    Some((ja3, hash))
}

// ---------------------------------------------------------------------------
// JA4 fingerprinting (FoxIO specification)
// ---------------------------------------------------------------------------

pub fn calculate_ja4(
    tls_version: u16,
    cipher_suites: &[u16],
    extensions: &[u16],
    sni: Option<&str>,
    alpn: Option<&str>,
    is_quic: bool,
) -> String {
    // Type
    let proto = if is_quic { "q" } else { "t" };

    // Version
    let version = match tls_version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    };

    // SNI flag
    let sni_flag = if sni.is_some_and(|s| !s.is_empty()) {
        "d"
    } else {
        "i"
    };

    // Counts (capped at 99)
    let cipher_count = cipher_suites.len().min(99);
    let ext_count = extensions.len().min(99);

    // ALPN (first value, truncated to 2 chars)
    let alpn_str = alpn
        .map(|a| {
            let first = a.split(',').next().unwrap_or(a);
            match first {
                "h2" => "h2".to_string(),
                "http/1.1" => "h1".to_string(),
                "h3" => "h3".to_string(),
                "h3-29" => "h3".to_string(),
                _ => first.chars().take(2).collect(),
            }
        })
        .unwrap_or_else(|| "00".to_string());

    // JA4_a: first section (includes ALPN per FoxIO spec)
    let ja4_a = format!(
        "{}{}{}{:02}{:02}{}",
        proto, version, sni_flag, cipher_count, ext_count, alpn_str
    );

    // JA4_b: sorted cipher suites hash (excluding GREASE values)
    let mut sorted_ciphers: Vec<u16> = cipher_suites
        .iter()
        .filter(|&&c| !is_grease(c))
        .copied()
        .collect();
    sorted_ciphers.sort();
    let cipher_str = sorted_ciphers
        .iter()
        .map(|c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");
    let mut hasher = Sha256::new();
    hasher.update(cipher_str.as_bytes());
    let cipher_hash = format!("{:x}", hasher.finalize());
    let ja4_b = &cipher_hash[..12.min(cipher_hash.len())];

    // JA4_c: sorted extensions hash (excluding SNI=0x0000 and ALPN=0x0010, excluding GREASE)
    let mut sorted_exts: Vec<u16> = extensions
        .iter()
        .filter(|&&e| !is_grease(e) && e != 0x0000 && e != 0x0010)
        .copied()
        .collect();
    sorted_exts.sort();
    let ext_str = sorted_exts
        .iter()
        .map(|e| format!("{:04x}", e))
        .collect::<Vec<_>>()
        .join(",");
    let mut hasher = Sha256::new();
    hasher.update(ext_str.as_bytes());
    let ext_hash = format!("{:x}", hasher.finalize());
    let ja4_c = &ext_hash[..12.min(ext_hash.len())];

    format!("{}_{}_{}", ja4_a, ja4_b, ja4_c)
}

/// Check if a value is a TLS GREASE value
fn is_grease(value: u16) -> bool {
    // GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ... 0xfafa
    (value & 0x0f0f) == 0x0a0a
}

fn extract_sni_from_extension(ext_data: &[u8]) -> Option<String> {
    if ext_data.len() < 5 {
        return None;
    }

    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
    let list_end = 2usize.checked_add(list_len)?;
    if list_end > ext_data.len() {
        return None;
    }

    let name_type = ext_data[2];
    if name_type != 0 {
        return None;
    }

    let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
    let name_start = 5usize;
    let name_end = name_start.checked_add(name_len)?;
    if name_len == 0 || name_end > list_end {
        return None;
    }

    std::str::from_utf8(&ext_data[name_start..name_end])
        .ok()
        .map(str::to_string)
}

fn extract_alpn_from_extension(ext_data: &[u8]) -> Option<String> {
    if ext_data.len() < 3 {
        return None;
    }

    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
    let list_end = 2usize.checked_add(list_len)?;
    if list_end > ext_data.len() {
        return None;
    }

    let proto_len = ext_data[2] as usize;
    let proto_start = 3usize;
    let proto_end = proto_start.checked_add(proto_len)?;
    if proto_len == 0 || proto_end > list_end {
        return None;
    }

    std::str::from_utf8(&ext_data[proto_start..proto_end])
        .ok()
        .map(str::to_string)
}

/// Calculate JA4 from raw ClientHello bytes
pub fn ja4_from_handshake(data: &[u8]) -> Option<String> {
    let data = client_hello_record(data)?;

    // Use ClientHello version (offset 9-10), not record-layer version (offset 1-2)
    let tls_version = u16::from_be_bytes([data[9], data[10]]);

    // Parse the same way as ja3_from_handshake
    let mut pos = 43usize;
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

    let ciphers_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    if pos + 2 + ciphers_len > data.len() {
        return None;
    }
    pos += 2;

    let mut cipher_suites = Vec::new();
    if ciphers_len % 2 == 0 {
        for i in (pos..pos + ciphers_len).step_by(2) {
            cipher_suites.push(u16::from_be_bytes([data[i], data[i + 1]]));
        }
        pos += ciphers_len;
    }

    if pos >= data.len() {
        return None;
    }
    let compressions_len = data[pos] as usize;
    if pos + 1 + compressions_len > data.len() {
        return None;
    }
    pos += 1 + compressions_len;
    if pos + 2 > data.len() {
        return None;
    }

    let extensions_total_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let extensions_end = pos.checked_add(extensions_total_len)?;
    if extensions_end > data.len() {
        return None;
    }

    let mut extensions = Vec::new();
    let mut sni: Option<String> = None;
    let mut alpn: Option<String> = None;
    let mut supported_versions: Option<u16> = None;

    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let ext_data_start = pos + 4;
        let ext_data_end = ext_data_start.checked_add(ext_len)?;
        if ext_data_end > extensions_end {
            return None;
        }
        extensions.push(ext_type);
        let ext_data = &data[ext_data_start..ext_data_end];

        // Extract SNI (type 0x0000)
        if ext_type == 0x0000 {
            sni = extract_sni_from_extension(ext_data);
        }

        // Extract ALPN (type 0x0010)
        if ext_type == 0x0010 {
            alpn = extract_alpn_from_extension(ext_data);
        }

        // Extract supported_versions (type 0x002b) for actual TLS version
        if ext_type == 0x002b && ext_data.len() >= 3 {
            // First version in the list is the preferred one
            supported_versions = Some(u16::from_be_bytes([ext_data[1], ext_data[2]]));
        }

        pos = ext_data_end;
    }
    if pos != extensions_end {
        return None;
    }

    // Use supported_versions if available (more accurate for TLS 1.3)
    let actual_version = supported_versions.unwrap_or(tls_version);

    Some(calculate_ja4(
        actual_version,
        &cipher_suites,
        &extensions,
        sni.as_deref(),
        alpn.as_deref(),
        false, // TCP, not QUIC
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&ext_type.to_be_bytes());
        ext.extend_from_slice(&(data.len() as u16).to_be_bytes());
        ext.extend_from_slice(data);
        ext
    }

    fn sni_extension(hostname: &str) -> Vec<u8> {
        let host = hostname.as_bytes();
        let list_len = 1 + 2 + host.len();
        let mut data = Vec::new();
        data.extend_from_slice(&(list_len as u16).to_be_bytes());
        data.push(0);
        data.extend_from_slice(&(host.len() as u16).to_be_bytes());
        data.extend_from_slice(host);
        extension(0x0000, &data)
    }

    fn alpn_extension(protocol: &str) -> Vec<u8> {
        let protocol = protocol.as_bytes();
        let list_len = 1 + protocol.len();
        let mut data = Vec::new();
        data.extend_from_slice(&(list_len as u16).to_be_bytes());
        data.push(protocol.len() as u8);
        data.extend_from_slice(protocol);
        extension(0x0010, &data)
    }

    fn client_hello(extensions: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // empty session id
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);

        let ext_len: usize = extensions.iter().map(Vec::len).sum();
        body.extend_from_slice(&(ext_len as u16).to_be_bytes());
        for ext in extensions {
            body.extend_from_slice(ext);
        }

        let handshake_len = body.len();
        let record_len = handshake_len + 4;
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&0x0303u16.to_be_bytes());
        record.extend_from_slice(&(record_len as u16).to_be_bytes());
        record.push(0x01);
        record.push(((handshake_len >> 16) & 0xff) as u8);
        record.push(((handshake_len >> 8) & 0xff) as u8);
        record.push((handshake_len & 0xff) as u8);
        record.extend_from_slice(&body);
        record
    }

    #[test]
    fn ja4_extracts_valid_sni_and_alpn() {
        let hello = client_hello(&[sni_extension("example.test"), alpn_extension("h2")]);
        let ja4 = ja4_from_handshake(&hello).expect("valid ClientHello should fingerprint");

        assert!(ja4.starts_with("t12d0102h2_"));
    }

    #[test]
    fn ja4_rejects_sni_outside_declared_server_name_list() {
        let host = b"example.test";
        let mut data = Vec::new();
        data.extend_from_slice(&3u16.to_be_bytes());
        data.push(0);
        data.extend_from_slice(&(host.len() as u16).to_be_bytes());
        data.extend_from_slice(host);

        let hello = client_hello(&[extension(0x0000, &data)]);
        let ja4 = ja4_from_handshake(&hello).expect("malformed SNI should not abort JA4");

        assert!(ja4.starts_with("t12i010100_"));
    }

    #[test]
    fn ja4_rejects_alpn_outside_declared_protocol_list() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_be_bytes());
        data.push(2);
        data.extend_from_slice(b"h2");

        let hello = client_hello(&[sni_extension("example.test"), extension(0x0010, &data)]);
        let ja4 = ja4_from_handshake(&hello).expect("malformed ALPN should not abort JA4");

        assert!(ja4.starts_with("t12d010200_"));
    }

    #[test]
    fn ja4_truncates_non_ascii_alpn_without_panicking() {
        let alpn = String::from_utf8(vec![0xe2, 0x82, 0xac, b'h']).unwrap();
        let ja4 = calculate_ja4(0x0303, &[], &[], None, Some(&alpn), false);

        assert!(!ja4.is_empty());
    }
}
