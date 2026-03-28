use md5::{Digest as Md5Digest, Md5};

use crate::prelude::*;

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

    let version = u16::from_be_bytes([data[1], data[2]]);

    let mut pos = 43usize;
    if pos >= data.len() {
        return None;
    }

    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 2 > data.len() {
        return None;
    }

    let ciphers_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let mut cipher_suites = Vec::new();
    if pos + ciphers_len <= data.len() && ciphers_len % 2 == 0 {
        for i in (pos..pos + ciphers_len).step_by(2) {
            cipher_suites.push(u16::from_be_bytes([data[i], data[i + 1]]));
        }
        pos += ciphers_len;
    }

    if pos >= data.len() {
        return None;
    }

    let compressions_len = data[pos] as usize;
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
            let mut group_pos = pos + 6;
            let groups_len = u16::from_be_bytes([data[group_pos], data[group_pos + 1]]) as usize;
            group_pos += 2;
            let groups_end = group_pos + groups_len;
            while group_pos + 2 <= groups_end && group_pos + 2 <= data.len() {
                supported_groups.push(u16::from_be_bytes([data[group_pos], data[group_pos + 1]]));
                group_pos += 2;
            }
        }

        if ext_type == 0x000b && pos + 4 + ext_len <= data.len() {
            let mut format_pos = pos + 5;
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
