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

pub fn ja3_from_handshake(data: &[u8]) -> Option<(String, String)> {
    if data.len() < 6 {
        return None;
    }

    if data[0] != 0x16 {
        return None;
    }

    if data[5] != 0x01 {
        return None;
    }

    // Use ClientHello version (offset 9-10), not record-layer version (offset 1-2)
    if data.len() < 11 {
        return None;
    }
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
    let extensions_end = pos + extensions_len;

    let mut extensions = Vec::new();
    let mut supported_groups = Vec::new();
    let mut ec_point_formats = Vec::new();

    while pos + 4 <= extensions_end && pos + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;

        extensions.push(ext_type);

        if ext_type == 0x000a && pos + 4 + ext_len <= data.len() {
            // supported_groups: list_length(2) at ext_data start (pos+4), groups start at pos+6
            let mut group_pos = pos + 4;
            let groups_len = u16::from_be_bytes([data[group_pos], data[group_pos + 1]]) as usize;
            group_pos += 2;
            let groups_end = group_pos + groups_len;
            while group_pos + 2 <= groups_end && group_pos + 2 <= data.len() {
                supported_groups.push(u16::from_be_bytes([data[group_pos], data[group_pos + 1]]));
                group_pos += 2;
            }
        }

        if ext_type == 0x000b && pos + 4 + ext_len <= data.len() {
            // ec_point_formats: formats_length(1) at ext_data start (pos+4), formats start at pos+5
            let mut format_pos = pos + 4;
            let formats_len = data[format_pos] as usize;
            format_pos += 1;
            for i in 0..formats_len {
                if format_pos + i < data.len() {
                    ec_point_formats.push(data[format_pos + i]);
                }
            }
        }

        pos += 4 + ext_len;
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
                _ => first[..first.len().min(2)].to_string(),
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

/// Calculate JA4 from raw ClientHello bytes
pub fn ja4_from_handshake(data: &[u8]) -> Option<String> {
    if data.len() < 11 || data[0] != 0x16 || data[5] != 0x01 {
        return None;
    }

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
    let extensions_end = pos + extensions_total_len;

    let mut extensions = Vec::new();
    let mut sni: Option<String> = None;
    let mut alpn: Option<String> = None;
    let mut supported_versions: Option<u16> = None;

    while pos + 4 <= extensions_end && pos + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        extensions.push(ext_type);

        // Extract SNI (type 0x0000)
        if ext_type == 0x0000 && pos + 4 + ext_len <= data.len() {
            let ext_data = &data[pos + 4..pos + 4 + ext_len];
            if ext_data.len() >= 5 {
                let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                if 5 + name_len <= ext_data.len() {
                    sni = String::from_utf8(ext_data[5..5 + name_len].to_vec()).ok();
                }
            }
        }

        // Extract ALPN (type 0x0010)
        if ext_type == 0x0010 && pos + 4 + ext_len <= data.len() {
            let ext_data = &data[pos + 4..pos + 4 + ext_len];
            if ext_data.len() >= 3 {
                let proto_len = ext_data[2] as usize;
                if 3 + proto_len <= ext_data.len() {
                    alpn = String::from_utf8(ext_data[3..3 + proto_len].to_vec()).ok();
                }
            }
        }

        // Extract supported_versions (type 0x002b) for actual TLS version
        if ext_type == 0x002b && pos + 4 + ext_len <= data.len() {
            let ext_data = &data[pos + 4..pos + 4 + ext_len];
            if ext_data.len() >= 3 {
                // First version in the list is the preferred one
                supported_versions = Some(u16::from_be_bytes([ext_data[1], ext_data[2]]));
            }
        }

        pos += 4 + ext_len;
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
