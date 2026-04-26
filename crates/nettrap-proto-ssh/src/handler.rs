pub struct SshHandler {
    server_version: String,
}

impl SshHandler {
    pub fn new() -> Self {
        Self {
            server_version: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6".to_string(),
        }
    }

    pub fn with_version(mut self, v: impl Into<String>) -> Self {
        self.server_version = v.into();
        self
    }

    /// Get SSH banner (sent immediately on connect)
    pub fn get_banner(&self) -> Vec<u8> {
        format!("{}\r\n", self.server_version).into_bytes()
    }

    /// Parse client version string from first line
    pub fn parse_client_version(data: &[u8]) -> Option<String> {
        let line_end = data
            .iter()
            .position(|&byte| byte == b'\n')
            .unwrap_or(data.len());
        let mut line = &data[..line_end];
        if line.ends_with(b"\r") {
            line = &line[..line.len().saturating_sub(1)];
        }
        if line.is_empty() || line.len() > 255 {
            return None;
        }

        let line = std::str::from_utf8(line).ok()?;
        let prefix_len = if line.starts_with("SSH-2.0-") {
            "SSH-2.0-".len()
        } else if line.starts_with("SSH-1.99-") {
            "SSH-1.99-".len()
        } else {
            return None;
        };
        let software_version = &line[prefix_len..];
        if software_version.is_empty() || software_version.starts_with(' ') {
            return None;
        }
        if !line.bytes().all(|byte| matches!(byte, 0x20..=0x7e)) {
            return None;
        }

        Some(line.to_string())
    }

    /// Build a fake SSH key exchange init packet
    pub fn build_kexinit(&self) -> Vec<u8> {
        use rand::Rng;

        let mut packet = Vec::new();
        // SSH packet: length(4) + padding_length(1) + type(1=SSH_MSG_KEXINIT) + cookie(16) + ...
        // Generate random cookie to avoid fingerprinting
        let cookie: [u8; 16] = rand::rng().random();

        // Minimal KEX_INIT
        let mut payload = Vec::new();
        payload.push(20); // SSH_MSG_KEXINIT
        payload.extend_from_slice(&cookie);

        // kex_algorithms
        let kex = b"curve25519-sha256,diffie-hellman-group14-sha256";
        payload.extend_from_slice(&(kex.len() as u32).to_be_bytes());
        payload.extend_from_slice(kex);

        // server_host_key_algorithms
        let host_key = b"ssh-ed25519,ssh-rsa";
        payload.extend_from_slice(&(host_key.len() as u32).to_be_bytes());
        payload.extend_from_slice(host_key);

        // encryption_algorithms_client_to_server
        let enc = b"aes256-ctr,aes128-ctr";
        payload.extend_from_slice(&(enc.len() as u32).to_be_bytes());
        payload.extend_from_slice(enc);

        // encryption_algorithms_server_to_client
        payload.extend_from_slice(&(enc.len() as u32).to_be_bytes());
        payload.extend_from_slice(enc);

        // mac_algorithms (both directions)
        let mac = b"hmac-sha2-256";
        for _ in 0..2 {
            payload.extend_from_slice(&(mac.len() as u32).to_be_bytes());
            payload.extend_from_slice(mac);
        }

        // compression (both directions)
        let comp = b"none";
        for _ in 0..2 {
            payload.extend_from_slice(&(comp.len() as u32).to_be_bytes());
            payload.extend_from_slice(comp);
        }

        // languages (both directions, empty)
        for _ in 0..2 {
            payload.extend_from_slice(&0u32.to_be_bytes());
        }

        // first_kex_packet_follows, reserved
        payload.push(0); // false
        payload.extend_from_slice(&0u32.to_be_bytes());

        // Build SSH packet: [packet_length(4)][padding_length(1)][payload][padding]
        // packet_length = 1 + payload.len() + padding_len
        // (1 + payload.len() + padding_len) must be multiple of 8
        let unpadded = 1 + payload.len();
        let padding_len = 8 - (unpadded % 8);
        let padding_len = if padding_len < 4 {
            padding_len + 8
        } else {
            padding_len
        };
        let total_len = (1 + payload.len() + padding_len) as u32;

        packet.extend_from_slice(&total_len.to_be_bytes());
        packet.push(padding_len as u8);
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(&vec![0u8; padding_len]);

        packet
    }

    /// After KEX, send a disconnect with "auth failed" to capture credentials
    /// The malware will have already sent its version string which we logged
    pub fn build_auth_failure(&self) -> Vec<u8> {
        // SSH_MSG_DISCONNECT
        let reason = 2u32; // SSH_DISCONNECT_PROTOCOL_ERROR
        let desc = b"Authentication failed";
        let lang = b"";

        let mut payload = Vec::new();
        payload.push(1); // SSH_MSG_DISCONNECT
        payload.extend_from_slice(&reason.to_be_bytes());
        payload.extend_from_slice(&(desc.len() as u32).to_be_bytes());
        payload.extend_from_slice(desc);
        payload.extend_from_slice(&(lang.len() as u32).to_be_bytes());
        payload.extend_from_slice(lang);

        // SSH packet: [packet_length(4)][padding_length(1)][payload][padding]
        // (1 + payload.len() + padding_len) must be multiple of 8
        let unpadded = 1 + payload.len();
        let padding_len = 8 - (unpadded % 8);
        let padding_len = if padding_len < 4 {
            padding_len + 8
        } else {
            padding_len
        };
        let total_len = (1 + payload.len() + padding_len) as u32;

        let mut packet = Vec::new();
        packet.extend_from_slice(&total_len.to_be_bytes());
        packet.push(padding_len as u8);
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(&vec![0u8; padding_len]);

        packet
    }

    /// Detect brute-force indicators
    pub fn is_brute_force_client(version: &str) -> bool {
        let v = version.to_lowercase();
        v.contains("libssh")
            || v.contains("paramiko")
            || v.contains("go")
            || v.contains("putty")
            || v.contains("ncrack")
            || v.contains("medusa")
            || v.contains("hydra")
    }
}

impl Default for SshHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_client_versions() {
        assert_eq!(
            SshHandler::parse_client_version(b"SSH-2.0-OpenSSH_9.6\r\n"),
            Some("SSH-2.0-OpenSSH_9.6".to_string())
        );
        assert_eq!(
            SshHandler::parse_client_version(b"SSH-1.99-CompatClient\nignored"),
            Some("SSH-1.99-CompatClient".to_string())
        );
    }

    #[test]
    fn rejects_malformed_client_versions() {
        assert!(SshHandler::parse_client_version(b"SSH-\r\n").is_none());
        assert!(SshHandler::parse_client_version(b"SSH-2.0-\r\n").is_none());
        assert!(SshHandler::parse_client_version(b"SSH-2.0- bad\r\n").is_none());
        assert!(SshHandler::parse_client_version(b"SSH-1.5-OldClient\r\n").is_none());
        assert!(SshHandler::parse_client_version(b"SSH-2.0-\tbad\r\n").is_none());
    }

    #[test]
    fn rejects_oversized_client_version_line() {
        let mut line = b"SSH-2.0-".to_vec();
        line.extend(std::iter::repeat_n(b'a', 248));

        assert!(SshHandler::parse_client_version(&line).is_none());
    }
}
