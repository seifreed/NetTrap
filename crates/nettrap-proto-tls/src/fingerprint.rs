use sha2::{Digest, Sha256};


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

        let version_str = format!("{:04x}", version);
        let ciphers_str = self
            .cipher_suites
            .iter()
            .map(|c| format!("{:04x}", c))
            .collect::<Vec<_>>()
            .join("-");
        let extensions_str = self
            .extensions
            .iter()
            .map(|e| format!("{:04x}", e))
            .collect::<Vec<_>>()
            .join("-");
        let groups_str = self
            .supported_groups
            .iter()
            .map(|g| format!("{:04x}", g))
            .collect::<Vec<_>>()
            .join("-");
        let formats_str = self
            .ec_point_formats
            .iter()
            .map(|f| format!("{:04x}", f))
            .collect::<Vec<_>>()
            .join("-");

        self.ja3 = format!(
            "{},{},{},{},{}",
            version_str, ciphers_str, extensions_str, groups_str, formats_str
        );

        let mut hasher = Sha256::new();
        hasher.update(self.ja3.as_bytes());
        self.ja3_hash = format!("{:x}", hasher.finalize());
    }
}

pub fn extract_sni(data: &[u8]) -> Option<String> {
    if data.len() < 45 {
        return None;
    }

    if data[0] != 0x16 || data[1] != 0x03 {
        return None;
    }

    let extensions_start = 43_usize;
    if data.len() < extensions_start + 4 {
        return None;
    }

    let mut pos = extensions_start;
    while pos + 4 < data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;

        if ext_type == 0x0000 {
            pos += 4;
            let _sni_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            let _hostname_type = data[pos];
            pos += 1;
            let hostname_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            if pos + hostname_len <= data.len() {
                return std::str::from_utf8(&data[pos..pos + hostname_len])
                    .ok()
                    .map(|s| s.to_string());
            }
        }

        pos += 4 + ext_len;
    }

    None
}

pub fn extract_alpn(data: &[u8]) -> Option<String> {
    if data.len() < 45 {
        return None;
    }

    if data[0] != 0x16 || data[1] != 0x03 {
        return None;
    }

    let extensions_start = 43_usize;
    if data.len() < extensions_start + 4 {
        return None;
    }

    let mut pos = extensions_start;
    while pos + 4 < data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;

        if ext_type == 0x0010 {
            pos += 4;
            let _alpn_ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            let str_len = data[pos] as usize;
            pos += 1;

            if pos + str_len <= data.len() {
                return std::str::from_utf8(&data[pos..pos + str_len])
                    .ok()
                    .map(|s| s.to_string());
            }
        }

        pos += 4 + ext_len;
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

    let mut fingerprint = TlsFingerprint {
        ja3: String::new(),
        ja3_hash: String::new(),
        ja4: String::new(),
        versions: vec![0x0303],
        cipher_suites: Vec::new(),
        extensions: Vec::new(),
        supported_groups: Vec::new(),
        ec_point_formats: Vec::new(),
        signature_algorithms: Vec::new(),
        sni: extract_sni(data),
        alpn: extract_alpn(data),
    };

    let session_id_len = data[43] as usize;
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

    fingerprint.compute_ja3();
    fingerprint.ja4 = crate::ja3::ja4_from_handshake(data).unwrap_or_default();
    Some(fingerprint)
}
