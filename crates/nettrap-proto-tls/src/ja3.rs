use md5::{Digest as Md5Digest, Md5};
use sha2::Sha256;

#[inline]
pub(crate) fn u8_at(data: &[u8], index: usize) -> Option<u8> {
    data.get(index).copied()
}

#[inline]
pub(crate) fn u16_at(data: &[u8], index: usize) -> Option<u16> {
    let end = index.checked_add(2)?;
    let bytes = data.get(index..end)?;
    let bytes: [u8; 2] = bytes.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

#[inline]
pub(crate) fn slice_at(data: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    let end = start.checked_add(len)?;
    data.get(start..end)
}

pub fn calculate_ja3(
    version: u16,
    cipher_suites: &[u16],
    extensions: &[u16],
    supported_groups: &[u16],
    ec_point_formats: &[impl std::fmt::Display],
) -> String {
    let ciphers_str = cipher_suites
        .iter()
        .filter(|&&c| !is_grease(c))
        .map(|c| format!("{}", c))
        .collect::<Vec<_>>()
        .join("-");

    let extensions_str = extensions
        .iter()
        .filter(|&&e| !is_grease(e))
        .map(|e| format!("{}", e))
        .collect::<Vec<_>>()
        .join("-");

    let groups_str = supported_groups
        .iter()
        .filter(|&&g| !is_grease(g))
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

pub(crate) fn client_hello_record(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 44
        || u8_at(data, 0)? != 0x16
        || u8_at(data, 1)? != 0x03
        || u8_at(data, 5)? != 0x01
    {
        return None;
    }

    let record_len = u16_at(data, 3)? as usize;
    let record_end = 5usize.checked_add(record_len)?;
    if record_len < 4 || record_end > data.len() {
        return None;
    }

    let handshake_len = (usize::from(u8_at(data, 6)?) << 16)
        | (usize::from(u8_at(data, 7)?) << 8)
        | usize::from(u8_at(data, 8)?);
    let handshake_end = 9usize.checked_add(handshake_len)?;
    if handshake_end > record_end || handshake_end < 44 {
        return None;
    }

    data.get(..handshake_end)
}

/// Fields parsed from the fixed ClientHello prefix that precedes the
/// extensions block, shared by both JA3 and JA4.
struct ClientHelloPrefix<'a> {
    /// ClientHello legacy version (offset 9-10), not the record-layer version.
    version: u16,
    cipher_suites: Vec<u16>,
    /// The raw extensions block, sized exactly to its declared length.
    extensions: &'a [u8],
}

/// Parse the ClientHello up to (but not including) the extensions, returning
/// the version, cipher suites, and the exact extensions byte range. Returns
/// `None` on any framing inconsistency.
fn parse_client_hello_prefix(data: &[u8]) -> Option<ClientHelloPrefix<'_>> {
    let data = client_hello_record(data)?;

    let version = u16_at(data, 9)?;

    let mut pos = 43usize;
    if pos >= data.len() {
        return None;
    }

    let session_id_len = usize::from(u8_at(data, pos)?);
    if pos + 1 + session_id_len > data.len() {
        return None;
    }
    pos += 1 + session_id_len;

    if pos + 2 > data.len() {
        return None;
    }

    let ciphers_len = u16_at(data, pos)? as usize;
    if pos + 2 + ciphers_len > data.len() {
        return None;
    }
    if !ciphers_len.is_multiple_of(2) {
        return None;
    }
    pos += 2;

    let mut cipher_suites = Vec::new();
    for i in (pos..pos + ciphers_len).step_by(2) {
        cipher_suites.push(u16_at(data, i)?);
    }
    pos += ciphers_len;

    if pos >= data.len() {
        return None;
    }

    let compressions_len = usize::from(u8_at(data, pos)?);
    if pos + 1 + compressions_len > data.len() {
        return None;
    }
    pos += 1 + compressions_len;

    if pos == data.len() {
        return Some(ClientHelloPrefix {
            version,
            cipher_suites,
            extensions: &[],
        });
    }

    if pos + 2 > data.len() {
        return None;
    }

    let extensions_len = u16_at(data, pos)? as usize;
    pos += 2;
    let extensions_end = pos.checked_add(extensions_len)?;
    if extensions_end != data.len() {
        return None;
    }

    Some(ClientHelloPrefix {
        version,
        cipher_suites,
        extensions: data.get(pos..extensions_end)?,
    })
}

pub fn ja3_from_handshake(data: &[u8]) -> Option<(String, String)> {
    let prefix = parse_client_hello_prefix(data)?;
    let ext_block = prefix.extensions;

    let mut extensions = Vec::new();
    let mut supported_groups = Vec::new();
    let mut ec_point_formats: Vec<u8> = Vec::new();

    let mut pos = 0usize;
    while pos + 4 <= ext_block.len() {
        let ext_type = u16_at(ext_block, pos)?;
        let ext_len = u16_at(ext_block, pos + 2)? as usize;
        let ext_data_start = pos + 4;
        let ext_data_end = ext_data_start.checked_add(ext_len)?;
        if ext_data_end > ext_block.len() {
            return None;
        }

        extensions.push(ext_type);
        let ext_data = slice_at(ext_block, ext_data_start, ext_len)?;

        if ext_type == 0x000a {
            supported_groups.extend(supported_groups_from_extension(ext_data)?);
        }

        if ext_type == 0x000b {
            ec_point_formats.extend(ec_point_formats_from_extension(ext_data)?);
        }

        pos = ext_data_end;
    }
    if pos != ext_block.len() {
        return None;
    }

    let ja3 = calculate_ja3(
        prefix.version,
        &prefix.cipher_suites,
        &extensions,
        &supported_groups,
        &ec_point_formats,
    );
    let hash = ja3_hash(&ja3);

    Some((ja3, hash))
}

pub fn calculate_ja4(
    tls_version: u16,
    cipher_suites: &[u16],
    extensions: &[u16],
    sni: Option<&str>,
    alpn: Option<&str>,
    is_quic: bool,
) -> String {
    let proto = if is_quic { "q" } else { "t" };

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

/// Check if a value is a TLS GREASE value (RFC 8701).
///
/// The 16 GREASE code points are 0x0a0a, 0x1a1a, 0x2a2a, … 0xfafa: the two
/// bytes are equal and each byte's low nibble is `a`. The low-nibble mask alone
/// (`value & 0x0f0f == 0x0a0a`) is not sufficient — it also matches values like
/// 0x1a0a or 0x3a7a, which are NOT GREASE. Wrongly stripping such a (valid,
/// assignable) cipher/extension code point from the cipher/extension list
/// yields a JA3/JA4 hash that won't match canonical implementations or
/// published threat-intel. Require the two bytes to be equal as well.
pub(crate) fn is_grease(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0x00ff)
}

fn extract_sni_from_extension(ext_data: &[u8]) -> Option<String> {
    if ext_data.len() < 5 {
        return None;
    }

    let list_len = u16_at(ext_data, 0)? as usize;
    let list_end = 2usize.checked_add(list_len)?;
    if list_end > ext_data.len() {
        return None;
    }
    if list_end != ext_data.len() {
        return None;
    }

    let name_type = u8_at(ext_data, 2)?;
    if name_type != 0 {
        return None;
    }

    let name_len = u16_at(ext_data, 3)? as usize;
    let name_start = 5usize;
    let name_end = name_start.checked_add(name_len)?;
    if name_len == 0 || name_end != list_end {
        return None;
    }

    let name = ext_data.get(name_start..name_end)?;
    let name = std::str::from_utf8(name).ok()?;
    valid_tls_sni_hostname(name).then(|| name.to_string())
}

fn extract_alpn_from_extension(ext_data: &[u8]) -> Option<String> {
    if ext_data.len() < 3 {
        return None;
    }

    let list_len = u16_at(ext_data, 0)? as usize;
    let list_end = 2usize.checked_add(list_len)?;
    if list_end > ext_data.len() {
        return None;
    }
    if list_end != ext_data.len() {
        return None;
    }

    let proto_len = usize::from(u8_at(ext_data, 2)?);
    let proto_start = 3usize;
    let proto_end = proto_start.checked_add(proto_len)?;
    if proto_len == 0 || proto_end != list_end {
        return None;
    }

    let proto = ext_data.get(proto_start..proto_end)?;
    let proto = std::str::from_utf8(proto).ok()?;
    valid_tls_alpn_protocol(proto).then(|| proto.to_string())
}

pub(crate) fn valid_tls_sni_hostname(value: &str) -> bool {
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

pub(crate) fn valid_tls_alpn_protocol(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
}

/// Calculate JA4 from raw ClientHello bytes
pub fn ja4_from_handshake(data: &[u8]) -> Option<String> {
    let prefix = parse_client_hello_prefix(data)?;
    let parsed_extensions = parse_client_hello_extensions(prefix.extensions)?;
    let extensions = parsed_extensions.extensions;
    let sni = parsed_extensions.sni;
    let alpn = parsed_extensions.alpn;
    let supported_versions = parsed_extensions.supported_versions;
    let actual_version = supported_versions.unwrap_or(prefix.version);

    Some(calculate_ja4(
        actual_version,
        &prefix.cipher_suites,
        &extensions,
        sni.as_deref(),
        alpn.as_deref(),
        false, // TCP, not QUIC
    ))
}

/// Extract the Server Name Indication hostname from a ClientHello, if present.
pub fn sni_from_handshake(data: &[u8]) -> Option<String> {
    let prefix = parse_client_hello_prefix(data)?;
    parse_client_hello_extensions(prefix.extensions)?.sni
}

struct ClientHelloExtensions {
    extensions: Vec<u16>,
    sni: Option<String>,
    alpn: Option<String>,
    supported_versions: Option<u16>,
}

fn parse_client_hello_extensions(ext_block: &[u8]) -> Option<ClientHelloExtensions> {
    let mut extensions = Vec::new();
    let mut sni: Option<String> = None;
    let mut alpn: Option<String> = None;
    let mut supported_versions: Option<u16> = None;

    let mut pos = 0usize;
    while pos + 4 <= ext_block.len() {
        let ext_type = u16_at(ext_block, pos)?;
        let ext_len = u16_at(ext_block, pos + 2)? as usize;
        let ext_data_start = pos + 4;
        let ext_data_end = ext_data_start.checked_add(ext_len)?;
        if ext_data_end > ext_block.len() {
            return None;
        }
        extensions.push(ext_type);
        let ext_data = slice_at(ext_block, ext_data_start, ext_len)?;

        if ext_type == 0x0000 {
            sni = extract_sni_from_extension(ext_data);
        }

        if ext_type == 0x0010 {
            alpn = extract_alpn_from_extension(ext_data);
        }

        if ext_type == 0x002b {
            supported_versions = supported_version_from_extension(ext_data);
        }

        pos = ext_data_end;
    }
    if pos != ext_block.len() {
        return None;
    }

    Some(ClientHelloExtensions {
        extensions,
        sni,
        alpn,
        supported_versions,
    })
}

fn supported_version_from_extension(ext_data: &[u8]) -> Option<u16> {
    let versions_len = usize::from(u8_at(ext_data, 0)?);
    if versions_len == 0 || versions_len % 2 != 0 || 1 + versions_len != ext_data.len() {
        return None;
    }
    u16_at(ext_data, 1)
}

pub(crate) fn supported_groups_from_extension(ext_data: &[u8]) -> Option<Vec<u16>> {
    let Some(groups_len) = u16_at(ext_data, 0).map(usize::from) else {
        return Some(Vec::new());
    };
    if groups_len == 0 || groups_len % 2 != 0 || 2 + groups_len != ext_data.len() {
        return Some(Vec::new());
    }
    ext_data
        .get(2..)?
        .chunks_exact(2)
        .map(|group| u16_at(group, 0))
        .collect()
}

pub(crate) fn ec_point_formats_from_extension(ext_data: &[u8]) -> Option<&[u8]> {
    let Some(formats_len) = u8_at(ext_data, 0).map(usize::from) else {
        return Some(&[]);
    };
    if 1 + formats_len != ext_data.len() {
        return Some(&[]);
    }
    ext_data.get(1..)
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

    fn client_hello_with_cipher_suites(cipher_suites: &[u8], extensions: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // empty session id
        body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
        body.extend_from_slice(cipher_suites);
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

    fn client_hello(extensions: &[Vec<u8>]) -> Vec<u8> {
        client_hello_with_cipher_suites(&0x1301u16.to_be_bytes(), extensions)
    }

    fn client_hello_without_extensions_vector() -> Vec<u8> {
        let mut hello = client_hello(&[]);
        let new_len = hello.len() - 2;
        let handshake_len = new_len - 9;
        let record_len = new_len - 5;
        hello[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
        hello[6] = ((handshake_len >> 16) & 0xff) as u8;
        hello[7] = ((handshake_len >> 8) & 0xff) as u8;
        hello[8] = (handshake_len & 0xff) as u8;
        hello.truncate(new_len);
        hello
    }

    #[test]
    fn sni_from_handshake_extracts_client_hello_hostname() {
        let hello = client_hello(&[sni_extension("example.com")]);

        assert_eq!(sni_from_handshake(&hello).as_deref(), Some("example.com"));
    }

    #[test]
    fn sni_from_handshake_rejects_missing_extension() {
        let hello = client_hello(&[]);

        assert_eq!(sni_from_handshake(&hello), None);
    }

    #[test]
    fn ja3_and_ja4_reject_trailing_bytes_after_extensions_vector() {
        let sni = sni_extension("example.com");
        let mut hello = client_hello(&[sni.clone(), extension(0x1234, &[])]);
        hello[50..52].copy_from_slice(&(sni.len() as u16).to_be_bytes());

        assert_eq!(sni_from_handshake(&hello), None);
        assert_eq!(ja3_from_handshake(&hello), None);
        assert_eq!(ja4_from_handshake(&hello), None);
    }

    #[test]
    fn is_grease_accepts_all_16_canonical_values() {
        for high in 0u16..16 {
            let value = (high << 12) | 0x0a00 | (high << 4) | 0x0a;
            assert!(is_grease(value), "{value:#06x} is a real GREASE value");
        }
    }

    #[test]
    fn is_grease_rejects_non_grease_lookalikes() {
        // Low nibbles are `a` in both bytes, but the two bytes differ — these
        // are valid, assignable code points, NOT GREASE. A low-nibble-only mask
        // would classify them as GREASE and strip them from the fingerprint.
        for value in [0x1a0au16, 0x3a7a, 0x0a1a, 0x2a9a, 0xfa0a] {
            assert!(
                !is_grease(value),
                "{value:#06x} must not be treated as GREASE"
            );
        }
        // Plain non-GREASE values stay non-GREASE.
        assert!(!is_grease(0x1301)); // TLS_AES_128_GCM_SHA256
        assert!(!is_grease(0xc02f));
    }

    #[test]
    fn ja3_and_ja4_reject_odd_cipher_suite_length() {
        let hello = client_hello_with_cipher_suites(&[1], &[]);

        assert_eq!(ja3_from_handshake(&hello), None);
        assert_eq!(ja4_from_handshake(&hello), None);
    }

    #[test]
    fn ja3_excludes_grease_values_from_all_indexed_lists() {
        let supported_groups = extension(0x000a, &[0x00, 0x04, 0x1a, 0x1a, 0x00, 0x1d]);
        let grease_extension = extension(0x0a0a, &[]);
        let hello = client_hello_with_cipher_suites(
            &[0x0a, 0x0a, 0x13, 0x01],
            &[grease_extension, supported_groups],
        );

        let (ja3, _) = ja3_from_handshake(&hello).expect("ClientHello should fingerprint");

        assert_eq!(ja3, "771,4865,10,29,");
    }

    #[test]
    fn ja3_and_ja4_accept_client_hello_without_extensions_vector() {
        let hello = client_hello_without_extensions_vector();

        let (ja3, _) = ja3_from_handshake(&hello).expect("ClientHello should fingerprint");
        let ja4 = ja4_from_handshake(&hello).expect("ClientHello should fingerprint");

        assert_eq!(ja3, "771,4865,,,");
        assert!(ja4.starts_with("t12i010000_"));
        assert_eq!(sni_from_handshake(&hello), None);
    }

    #[test]
    fn ja3_ignores_malformed_supported_groups_and_point_format_lengths() {
        let malformed_supported_groups = extension(0x000a, &[0x00, 0x03, 0x00, 0x1d, 0xff]);
        let malformed_point_formats = extension(0x000b, &[0x01, 0x00, 0xff]);
        let hello = client_hello(&[malformed_supported_groups, malformed_point_formats]);

        let (ja3, _) =
            ja3_from_handshake(&hello).expect("malformed extension lists should not abort");

        assert_eq!(ja3, "771,4865,10-11,,");
    }

    #[test]
    fn u16_at_rejects_overflowing_offset() {
        assert_eq!(u16_at(&[0, 1], usize::MAX), None);
    }

    #[test]
    fn ja4_extracts_valid_sni_and_alpn() {
        let hello = client_hello(&[sni_extension("example.test"), alpn_extension("h2")]);
        let ja4 = ja4_from_handshake(&hello).expect("valid ClientHello should fingerprint");

        assert!(ja4.starts_with("t12d0102h2_"));
    }

    #[test]
    fn ja4_ignores_malformed_supported_versions_length() {
        let malformed_supported_versions = extension(0x002b, &[0, 0x03, 0x04]);
        let hello = client_hello(&[malformed_supported_versions]);
        let ja4 = ja4_from_handshake(&hello).expect("malformed extension should not abort JA4");

        assert!(ja4.starts_with("t12i010100_"));
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
    fn ja4_accepts_absolute_sni_hostnames_with_trailing_dots() {
        let hello = client_hello(&[sni_extension("example.test.")]);
        let ja4 = ja4_from_handshake(&hello).expect("absolute SNI should fingerprint");

        assert!(ja4.starts_with("t12d010100_"));
    }

    #[test]
    fn ja4_rejects_all_numeric_sni_hostnames() {
        let hello = client_hello(&[sni_extension("192.0.2.10")]);
        let ja4 = ja4_from_handshake(&hello).expect("numeric SNI should not abort JA4");

        assert!(ja4.starts_with("t12i010100_"));
    }

    #[test]
    fn ja4_rejects_oversized_sni_labels() {
        let hello = client_hello(&[sni_extension(&format!("{}.test", "a".repeat(64)))]);
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
    fn ja4_ignores_sni_and_alpn_with_trailing_bytes_after_declared_lists() {
        let mut sni = sni_extension("inside.example");
        let sni_ext_len = u16::from_be_bytes([sni[2], sni[3]]) + 1;
        sni[2..4].copy_from_slice(&sni_ext_len.to_be_bytes());
        sni.push(0);

        assert_eq!(extract_sni_from_extension(&sni[4..]), None);

        let mut alpn = alpn_extension("h2");
        let alpn_ext_len = u16::from_be_bytes([alpn[2], alpn[3]]) + 1;
        alpn[2..4].copy_from_slice(&alpn_ext_len.to_be_bytes());
        alpn.push(0);

        assert_eq!(extract_alpn_from_extension(&alpn[4..]), None);

        let hello = client_hello(&[sni, alpn]);
        let ja4 = ja4_from_handshake(&hello).expect("malformed metadata should not abort JA4");

        assert!(ja4.starts_with("t12i010200_"));
    }

    #[test]
    fn ja4_ignores_sni_and_alpn_with_trailing_bytes_inside_declared_lists() {
        let mut sni = sni_extension("inside.example");
        let sni_ext_len = u16::from_be_bytes([sni[2], sni[3]]) + 1;
        let sni_list_len = u16::from_be_bytes([sni[4], sni[5]]) + 1;
        sni[2..4].copy_from_slice(&sni_ext_len.to_be_bytes());
        sni[4..6].copy_from_slice(&sni_list_len.to_be_bytes());
        sni.push(0);

        assert_eq!(extract_sni_from_extension(&sni[4..]), None);

        let mut alpn = alpn_extension("h2");
        let alpn_ext_len = u16::from_be_bytes([alpn[2], alpn[3]]) + 1;
        let alpn_list_len = u16::from_be_bytes([alpn[4], alpn[5]]) + 1;
        alpn[2..4].copy_from_slice(&alpn_ext_len.to_be_bytes());
        alpn[4..6].copy_from_slice(&alpn_list_len.to_be_bytes());
        alpn.push(0);

        assert_eq!(extract_alpn_from_extension(&alpn[4..]), None);

        let hello = client_hello(&[sni, alpn]);
        let ja4 = ja4_from_handshake(&hello).expect("malformed metadata should not abort JA4");

        assert!(ja4.starts_with("t12i010200_"));
    }

    #[test]
    fn ja4_truncates_non_ascii_alpn_without_panicking() {
        let alpn = String::from_utf8(vec![0xe2, 0x82, 0xac, b'h']).unwrap();
        let ja4 = calculate_ja4(0x0303, &[], &[], None, Some(&alpn), false);

        assert!(!ja4.is_empty());
    }
}
