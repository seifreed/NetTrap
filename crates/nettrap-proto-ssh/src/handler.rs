use nettrap_core::error::{Error, Result};

pub struct SshHandler {
    server_version: String,
}

const DEFAULT_SERVER_VERSION: &str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6";

impl SshHandler {
    pub fn new() -> Self {
        Self {
            server_version: DEFAULT_SERVER_VERSION.to_string(),
        }
    }

    pub fn with_version(mut self, v: impl Into<String>) -> Result<Self> {
        self.server_version = validate_server_version(&v.into())?;
        Ok(self)
    }

    /// Get SSH banner (sent immediately on connect)
    pub fn get_banner(&self) -> Vec<u8> {
        format!("{}\r\n", self.server_version).into_bytes()
    }

    /// Parse client version string from first line
    pub fn parse_client_version(data: &[u8]) -> Option<String> {
        let line_end = data.iter().position(|&byte| byte == b'\n')?;
        if line_end + 1 != data.len() {
            return None;
        }
        let mut line = data.get(..line_end)?;
        let max_len = if line.ends_with(b"\r") { 253 } else { 254 };
        if line.ends_with(b"\r") {
            line = line.get(..line.len().saturating_sub(1))?;
        }
        if line.is_empty() || line.len() > max_len {
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

        // SSH packet: length(4) + padding_length(1) + type(1=SSH_MSG_KEXINIT) + cookie(16) + ...
        // Generate random cookie to avoid fingerprinting
        let cookie: [u8; 16] = rand::rng().random();

        let mut payload = Vec::new();
        payload.push(20); // SSH_MSG_KEXINIT
        payload.extend_from_slice(&cookie);

        let kex = b"curve25519-sha256,diffie-hellman-group14-sha256";
        if !push_ssh_string(&mut payload, kex) {
            return Vec::new();
        }

        let host_key = b"ssh-ed25519,ssh-rsa";
        if !push_ssh_string(&mut payload, host_key) {
            return Vec::new();
        }

        let enc = b"aes256-ctr,aes128-ctr";
        if !push_ssh_string(&mut payload, enc) {
            return Vec::new();
        }

        if !push_ssh_string(&mut payload, enc) {
            return Vec::new();
        }

        let mac = b"hmac-sha2-256";
        for _ in 0..2 {
            if !push_ssh_string(&mut payload, mac) {
                return Vec::new();
            }
        }

        let comp = b"none";
        for _ in 0..2 {
            if !push_ssh_string(&mut payload, comp) {
                return Vec::new();
            }
        }

        for _ in 0..2 {
            payload.extend_from_slice(&0u32.to_be_bytes());
        }

        payload.push(0); // false
        payload.extend_from_slice(&0u32.to_be_bytes());

        build_ssh_packet(payload)
    }

    /// After KEX, send a userauth failure so the client can continue auth.
    /// The malware will have already sent its version string which we logged
    pub fn build_auth_failure(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(crate::ssh::SSH_MSG_USERAUTH_FAILURE);
        let methods = b"publickey,password,keyboard-interactive";
        if !push_ssh_string(&mut payload, methods) {
            return Vec::new();
        }
        payload.push(0); // partial success = false

        build_ssh_packet(payload)
    }

    /// Detect brute-force indicators
    pub fn is_brute_force_client(version: &str) -> bool {
        let v = version.to_lowercase();
        v.contains("libssh")
            || v.contains("paramiko")
            || v.contains("putty")
            || v.contains("ncrack")
            || v.contains("medusa")
            || v.contains("hydra")
            || v.contains("golang")
            || v.contains("go-")
            || v.contains("go_")
    }
}

fn build_ssh_packet(payload: Vec<u8>) -> Vec<u8> {
    let mut rng = rand::rng();
    build_ssh_packet_with_rng(payload, &mut rng)
}

fn push_ssh_string(out: &mut Vec<u8>, value: &[u8]) -> bool {
    let Ok(len) = u32::try_from(value.len()) else {
        return false;
    };
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    true
}

fn build_ssh_packet_with_rng(payload: Vec<u8>, rng: &mut impl rand::RngCore) -> Vec<u8> {
    const SSH_PACKET_ALIGNMENT: usize = 8;

    let packet_length_without_padding = payload.len() + 1;
    let padding_len = (SSH_PACKET_ALIGNMENT
        - (packet_length_without_padding % SSH_PACKET_ALIGNMENT))
        % SSH_PACKET_ALIGNMENT;
    let padding_len = if padding_len < 4 {
        padding_len + SSH_PACKET_ALIGNMENT
    } else {
        padding_len
    };
    let Some(total_len) = 1usize
        .checked_add(payload.len())
        .and_then(|len| len.checked_add(padding_len))
        .and_then(|len| u32::try_from(len).ok())
    else {
        return Vec::new();
    };
    let Ok(padding_len_byte) = u8::try_from(padding_len) else {
        return Vec::new();
    };

    let mut packet = Vec::new();
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.push(padding_len_byte);
    packet.extend_from_slice(&payload);
    let mut padding = vec![0u8; padding_len];
    rng.fill_bytes(&mut padding);
    packet.extend_from_slice(&padding);

    packet
}

fn validate_server_version(value: &str) -> Result<String> {
    let line = value;
    if nettrap_core::sanitize::contains_line_separator(line) {
        return Err(Error::Config("invalid SSH server version".to_string()));
    }
    // The "SSH-1.99-" prefix is 9 bytes; using a hardcoded [8..] suffix check
    // would miss an empty software-version suffix for that prefix.
    let prefix_len = if line.starts_with("SSH-2.0-") {
        "SSH-2.0-".len()
    } else if line.starts_with("SSH-1.99-") {
        "SSH-1.99-".len()
    } else {
        return Err(Error::Config("invalid SSH server version".to_string()));
    };
    if line.is_empty()
        || line.chars().next().is_some_and(char::is_whitespace)
        || line.chars().last().is_some_and(char::is_whitespace)
        || line.len() > 253
        || line.chars().any(|ch| !matches!(ch, ' '..='~'))
        || line[prefix_len..].is_empty()
    {
        Err(Error::Config("invalid SSH server version".to_string()))
    } else {
        Ok(line.to_string())
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
    use crate::ssh::SSH_MSG_DISCONNECT;
    use rand::RngCore;

    #[derive(Clone)]
    struct FixedPatternRng {
        byte: u8,
    }

    impl FixedPatternRng {
        fn new(byte: u8) -> Self {
            Self { byte }
        }
    }

    impl RngCore for FixedPatternRng {
        fn next_u32(&mut self) -> u32 {
            u32::from_le_bytes([self.byte; 4])
        }

        fn next_u64(&mut self) -> u64 {
            u64::from_le_bytes([self.byte; 8])
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(self.byte);
        }
    }

    #[test]
    fn parses_valid_client_versions() {
        assert_eq!(
            SshHandler::parse_client_version(b"SSH-2.0-OpenSSH_9.6\r\n"),
            Some("SSH-2.0-OpenSSH_9.6".to_string())
        );
        assert_eq!(
            SshHandler::parse_client_version(b"SSH-1.99-CompatClient\n"),
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
        assert!(SshHandler::parse_client_version(b"SSH-2.0-OpenSSH_9.6").is_none());
        assert!(SshHandler::parse_client_version(b"SSH-2.0-OpenSSH_9.6\nignored").is_none());
    }

    #[test]
    fn rejects_oversized_client_version_line() {
        let mut line = b"SSH-2.0-".to_vec();
        line.extend(std::iter::repeat_n(b'a', 246));

        assert!(SshHandler::parse_client_version(&line).is_none());
    }

    #[test]
    fn accepts_client_version_at_length_limit() {
        let mut line = b"SSH-2.0-".to_vec();
        line.extend(std::iter::repeat_n(b'a', 245));
        line.extend_from_slice(b"\r\n");

        let expected = format!("SSH-2.0-{}", "a".repeat(245));
        assert_eq!(SshHandler::parse_client_version(&line), Some(expected));
    }

    #[test]
    fn accepts_client_version_at_length_limit_without_carriage_return() {
        let mut line = b"SSH-2.0-".to_vec();
        line.extend(std::iter::repeat_n(b'a', 246));
        line.push(b'\n');

        let expected = format!("SSH-2.0-{}", "a".repeat(246));
        assert_eq!(SshHandler::parse_client_version(&line), Some(expected));
    }

    #[test]
    fn configured_server_version_cannot_inject_banner_lines() {
        assert!(
            SshHandler::new()
                .with_version("SSH-2.0-Custom\r\nSSH-2.0-injected")
                .is_err()
        );
    }

    #[test]
    fn configured_server_version_rejects_unicode_line_separators() {
        assert!(
            SshHandler::new()
                .with_version("SSH-2.0-Custom\u{2028}SSH-2.0-injected")
                .is_err()
        );
    }

    #[test]
    fn invalid_configured_server_version_uses_default() {
        assert!(
            SshHandler::new()
                .with_version("not-ssh\r\nSSH-2.0-injected")
                .is_err()
        );
    }

    #[test]
    fn empty_configured_server_version_uses_default() {
        assert!(SshHandler::new().with_version("SSH-2.0-").is_err());
    }

    #[test]
    fn empty_ssh_1_99_server_version_suffix_uses_default() {
        // "SSH-1.99-" has a 9-byte prefix; the empty-suffix check must use
        // the correct prefix length, not a hardcoded [8..] slice that would
        // miss the empty software version for this prefix.
        assert!(SshHandler::new().with_version("SSH-1.99-").is_err());
    }

    #[test]
    fn valid_server_version_with_comment_is_preserved() {
        let handler = SshHandler::new()
            .with_version("SSH-2.0-CustomServer comment")
            .expect("valid SSH version");

        assert_eq!(handler.get_banner(), b"SSH-2.0-CustomServer comment\r\n");
    }

    #[test]
    fn configured_server_version_rejects_overlong_banner() {
        let version = format!("SSH-2.0-{}", "a".repeat(246));
        assert!(SshHandler::new().with_version(&version).is_err());
    }

    #[test]
    fn auth_failure_sends_userauth_failure_with_method_list() {
        let handler = SshHandler::new();
        let packet = handler.build_auth_failure();

        assert!(packet.len() > 12);
        assert_eq!(packet[5], crate::ssh::SSH_MSG_USERAUTH_FAILURE);
        let methods_len = u32::from_be_bytes([packet[6], packet[7], packet[8], packet[9]]) as usize;
        assert_eq!(
            &packet[10..10 + methods_len],
            b"publickey,password,keyboard-interactive"
        );
        assert_eq!(packet[10 + methods_len], 0);
    }

    #[test]
    fn ssh_packet_padding_uses_entropy_bytes() {
        let payload = vec![SSH_MSG_DISCONNECT, 0, 0, 0, 1];
        let mut rng = FixedPatternRng::new(0x5a);
        let packet = super::build_ssh_packet_with_rng(payload, &mut rng);

        let packet_len = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
        let padding_len = packet[4] as usize;
        let padding = &packet[packet.len() - padding_len..];

        assert_eq!(packet_len + 4, packet.len());
        assert_eq!(packet_len % 8, 0);
        assert!(padding.iter().all(|byte| *byte == 0x5a));
        assert!(padding.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn ssh_packet_length_is_aligned_for_short_payloads() {
        for payload_len in 0..=32 {
            let mut rng = FixedPatternRng::new(0x5a);
            let packet = super::build_ssh_packet_with_rng(vec![0; payload_len], &mut rng);
            let packet_len =
                u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;

            assert_eq!(packet_len + 4, packet.len());
            assert_eq!(packet_len % 8, 0, "payload length: {payload_len}");
            assert!(packet[4] >= 4);
        }
    }

    #[test]
    fn leading_whitespace_server_version_falls_back_to_default() {
        assert!(
            SshHandler::new()
                .with_version(" SSH-2.0-CustomServer")
                .is_err()
        );
    }

    #[test]
    fn brute_force_detector_does_not_match_unrelated_go_substrings() {
        assert!(!SshHandler::is_brute_force_client("SSH-2.0-DragonSSH_1.0"));
        assert!(SshHandler::is_brute_force_client("SSH-2.0-go-ssh_1.0"));
    }
}
