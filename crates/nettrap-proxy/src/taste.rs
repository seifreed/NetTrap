//! Protocol taste detection implementations.
//!
//! This file is intentionally large (~750 lines) because it contains the
//! `ProtocolTaste` trait implementation for **all supported protocols**.
//!
//! # Why This File Is Large
//!
//! This is **not a God Object** - it's a **data-driven registry** of protocol
//! fingerprinting logic. Each protocol implementation is self-contained:
//!
//! ```text
//! impl ProtocolTaste for DnsTaste { ... }    // ~30 lines
//! impl ProtocolTaste for HttpTaste { ... }   // ~40 lines
//! impl ProtocolTaste for SshTaste { ... }    // ~20 lines
//! ...                                        // (35+ protocols)
//! ```
//!
//! # Alternatives Considered
//!
//! 1. **One file per protocol**: Would require 50+ files, making navigation harder
//! 2. **Generated code**: Possible, but hand-tuned detection logic is more accurate
//! 3. **External DSL**: Overkill for simple byte-pattern matching
//!
//! # Adding a New Protocol
//!
//! ```ignore
//! pub struct MyProtocolTaste;
//! impl ProtocolTaste for MyProtocolTaste {
//!     fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
//!         if dst_port == MY_PORT { return 90; }
//!         // Check protocol-specific signatures
//!         if data.starts_with(b"MyProtocol") { return 100; }
//!         0
//!     }
//!     fn protocol_name(&self) -> &'static str { "myprotocol" }
//! }
//! ```

/// Confidence score for protocol detection (0-100)
pub type TasteScore = u8;

/// Trait for protocol auto-detection. Each handler implements this to report
/// how confident it is that the given data belongs to its protocol.
pub trait ProtocolTaste: Send + Sync {
    /// Analyze data sample and destination port, return confidence 0-100.
    /// 0 = definitely not this protocol
    /// 1 = raw/fallback (always matches)
    /// 50+ = likely match
    /// 100 = certain match
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore;

    /// Protocol name for logging
    fn protocol_name(&self) -> &'static str;
}

// Built-in taste implementations for known protocols

pub struct DnsTaste;
impl ProtocolTaste for DnsTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 53 {
            return 90;
        }
        // DNS has a specific header structure: ID(2) + flags(2) + counts(8) = min 12 bytes
        if data.len() >= 12 {
            let qdcount = u16::from_be_bytes([data[4], data[5]]);
            let ancount = u16::from_be_bytes([data[6], data[7]]);
            if (1..=10).contains(&qdcount) && ancount <= 100 {
                return 70;
            }
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "dns"
    }
}

pub struct HttpTaste;
impl ProtocolTaste for HttpTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if data.len() >= 4 {
            let methods = [
                b"GET " as &[u8],
                b"POST ",
                b"PUT ",
                b"HEAD ",
                b"DELETE ",
                b"OPTIONS ",
                b"PATCH ",
                b"CONNECT ",
            ];
            for method in &methods {
                if data.starts_with(method) {
                    return 95;
                }
            }
            if data.windows(4).any(|w| w == b"HTTP") {
                return 80;
            }
        }
        if dst_port == 80 || dst_port == 8080 || dst_port == 8443 {
            return 30;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "http"
    }
}

pub struct TlsTaste;
impl ProtocolTaste for TlsTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if data.len() >= 3 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x04 {
            return 95;
        }
        // SSLv2
        if data.len() >= 3 && (data[0] & 0x80) != 0 && data[2] == 0x01 {
            return 80;
        }
        if dst_port == 443 {
            return 40;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "tls"
    }
}

pub struct SmtpTaste;
impl ProtocolTaste for SmtpTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 25 || dst_port == 587 || dst_port == 465 {
            return 85;
        }
        if data.len() >= 4 {
            let upper: Vec<u8> = data[..4.min(data.len())]
                .iter()
                .map(|b| b.to_ascii_uppercase())
                .collect();
            if upper.starts_with(b"EHLO")
                || upper.starts_with(b"HELO")
                || upper.starts_with(b"MAIL")
            {
                return 90;
            }
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "smtp"
    }
}

pub struct FtpTaste;
impl ProtocolTaste for FtpTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 21 {
            return 85;
        }
        if data.len() >= 4 {
            let upper: Vec<u8> = data[..4.min(data.len())]
                .iter()
                .map(|b| b.to_ascii_uppercase())
                .collect();
            if upper.starts_with(b"USER")
                || upper.starts_with(b"PASS")
                || upper.starts_with(b"LIST")
            {
                return 80;
            }
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "ftp"
    }
}

pub struct Pop3Taste;
impl ProtocolTaste for Pop3Taste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 110 || dst_port == 995 {
            return 85;
        }
        if data.len() >= 4 {
            let upper: Vec<u8> = data[..4.min(data.len())]
                .iter()
                .map(|b| b.to_ascii_uppercase())
                .collect();
            // POP3-unique commands at higher score
            if upper.starts_with(b"STAT")
                || upper.starts_with(b"RETR")
                || upper.starts_with(b"DELE")
                || upper.starts_with(b"TOP ")
                || upper.starts_with(b"UIDL")
            {
                return 80;
            }
            // Ambiguous commands shared with FTP — lower score so FTP wins on tie
            if upper.starts_with(b"USER")
                || upper.starts_with(b"PASS")
                || upper.starts_with(b"LIST")
                || upper.starts_with(b"QUIT")
            {
                return 65;
            }
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "pop3"
    }
}

pub struct IrcTaste;
impl ProtocolTaste for IrcTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 6667 || dst_port == 6697 {
            return 85;
        }
        if data.len() >= 5 {
            let upper: Vec<u8> = data[..5].iter().map(|b| b.to_ascii_uppercase()).collect();
            if upper.starts_with(b"NICK ")
                || upper.starts_with(b"USER ")
                || upper.starts_with(b"JOIN ")
                || upper.starts_with(b"PING ")
                || upper.starts_with(b"CAP ")
            {
                return 80;
            }
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "irc"
    }
}

pub struct TftpTaste;
impl ProtocolTaste for TftpTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 69 {
            return 90;
        }
        if data.len() >= 4 {
            let opcode = u16::from_be_bytes([data[0], data[1]]);
            if (1..=5).contains(&opcode) {
                return 75;
            }
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "tftp"
    }
}

pub struct QuicTaste;
impl ProtocolTaste for QuicTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 443 && data.len() >= 5 {
            // QUIC long header: first bit set, version follows
            if data[0] & 0x80 != 0 {
                return 85;
            }
        }
        if data.len() >= 5 && data[0] & 0x80 != 0 {
            // Check for known QUIC versions
            let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            if version == 1 || version == 0xff000010 || version == 0xff000011 {
                return 80;
            }
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "quic"
    }
}

pub struct TelnetTaste;
impl ProtocolTaste for TelnetTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 23 {
            return 90;
        }
        // Telnet IAC sequences start with 0xFF
        if data.len() >= 3 && data[0] == 0xFF {
            return 80;
        }
        // SSH- prefix means it's SSH, not telnet
        if data.starts_with(b"SSH-") {
            return 0;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "telnet"
    }
}

pub struct SshTaste;
impl ProtocolTaste for SshTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if data.starts_with(b"SSH-") {
            return 95;
        }
        if dst_port == 22 {
            return 85;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "ssh"
    }
}

pub struct SmbTaste;
impl ProtocolTaste for SmbTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 445 || dst_port == 139 {
            return 85;
        }
        // NetBIOS + SMB magic
        if data.len() >= 8
            && data[0] == 0x00
            && (data[4..8] == *b"\xffSMB" || data[4..8] == *b"\xfeSMB")
        {
            return 95;
        }
        if data.len() >= 4 && (data[0..4] == *b"\xffSMB" || data[0..4] == *b"\xfeSMB") {
            return 95;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "smb"
    }
}

pub struct RdpTaste;
impl ProtocolTaste for RdpTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 3389 {
            return 90;
        }
        // TPKT header: version 3
        if data.len() >= 4 && data[0] == 0x03 && data[1] == 0x00 {
            return 70;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "rdp"
    }
}

pub struct RedisTaste;
impl ProtocolTaste for RedisTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 6379 {
            return 90;
        }
        let text = String::from_utf8_lossy(data).to_uppercase();
        if text.starts_with("*")
            || text.starts_with("PING")
            || text.starts_with("INFO")
            || text.starts_with("AUTH")
        {
            return 80;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "redis"
    }
}

pub struct MysqlTaste;
impl ProtocolTaste for MysqlTaste {
    fn taste(&self, _data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 3306 {
            return 90;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "mysql"
    }
}

pub struct LdapTaste;
impl ProtocolTaste for LdapTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 389 || dst_port == 636 {
            return 90;
        }
        // LDAP: SEQUENCE(0x30) + length + INTEGER(0x02) for message ID
        // This distinguishes from SNMP which has SEQUENCE + length + INTEGER(version)
        // followed by OCTET STRING (0x04), while LDAP has INTEGER followed by APPLICATION tag (0x60-0x7F)
        if data.len() >= 7 && data[0] == 0x30 {
            // Skip SEQUENCE length (1 or 2 bytes)
            let (_, len_bytes) = if data[1] & 0x80 == 0 {
                (data[1] as usize, 1)
            } else {
                (0, 1 + (data[1] & 0x7F) as usize)
            };
            let msg_id_pos = 1 + len_bytes;
            if msg_id_pos < data.len() && data[msg_id_pos] == 0x02 {
                // After message ID INTEGER, check for LDAP APPLICATION tags (0x60-0x7F)
                let id_len_pos = msg_id_pos + 1;
                if id_len_pos < data.len() {
                    let id_len = data[id_len_pos] as usize;
                    let app_tag_pos = id_len_pos + 1 + id_len;
                    if app_tag_pos < data.len() && (data[app_tag_pos] & 0xE0) == 0x60 {
                        return 55; // LDAP APPLICATION tag found
                    }
                }
            }
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "ldap"
    }
}

pub struct MqttTaste;
impl ProtocolTaste for MqttTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 1883 {
            return 90;
        }
        // MQTT CONNECT packet: fixed header type 1, then variable-length remaining length (1-4 bytes)
        if data.len() >= 7 && (data[0] >> 4) == 1 {
            // Decode variable-length remaining length to find where payload starts
            let mut remaining_start = 1;
            while remaining_start < 5 && remaining_start < data.len() {
                let has_continuation = data[remaining_start] & 0x80 != 0;
                remaining_start += 1;
                if !has_continuation {
                    break;
                }
            }
            // After remaining length: protocol name length (2 bytes) + "MQTT"
            if remaining_start + 6 <= data.len()
                && &data[remaining_start + 2..remaining_start + 6] == b"MQTT"
            {
                return 95;
            }
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "mqtt"
    }
}

pub struct SnmpTaste;
impl ProtocolTaste for SnmpTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 161 || dst_port == 162 {
            return 90;
        }
        if data.len() >= 5 && data[0] == 0x30 && data[2] == 0x02 {
            return 60;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "snmp"
    }
}

pub struct SocksTaste;
impl ProtocolTaste for SocksTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 1080 {
            return 85;
        }
        if data.len() >= 3 && (data[0] == 0x04 || data[0] == 0x05) {
            return 70;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "socks"
    }
}

pub struct MemcachedTaste;
impl ProtocolTaste for MemcachedTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 11211 {
            return 90;
        }
        let text = String::from_utf8_lossy(data);
        if text.starts_with("get ")
            || text.starts_with("set ")
            || text.starts_with("stats")
            || text.starts_with("version")
        {
            return 85;
        }
        if data.len() >= 24 && data[0] == 0x80 {
            return 75;
        } // binary protocol
        0
    }
    fn protocol_name(&self) -> &'static str {
        "memcached"
    }
}

pub struct PostgresTaste;
impl ProtocolTaste for PostgresTaste {
    fn taste(&self, _data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 5432 {
            return 90;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "postgres"
    }
}

pub struct SipTaste;
impl ProtocolTaste for SipTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 5060 || dst_port == 5061 {
            return 85;
        }
        if data.starts_with(b"SIP/")
            || data.starts_with(b"REGISTER")
            || data.starts_with(b"INVITE")
            || data.starts_with(b"OPTIONS")
        {
            return 90;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "sip"
    }
}

pub struct UpnpTaste;
impl ProtocolTaste for UpnpTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 1900 {
            return 85;
        }
        if data.starts_with(b"M-SEARCH") || data.starts_with(b"NOTIFY") {
            return 90;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "upnp"
    }
}

pub struct NtpTaste;
impl ProtocolTaste for NtpTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 123 {
            return 90;
        }
        if data.len() == 48 || data.len() == 68 {
            return 60;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "ntp"
    }
}

pub struct CoapTaste;
impl ProtocolTaste for CoapTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 5683 || dst_port == 5684 {
            return 90;
        }
        if data.len() >= 4 && (data[0] >> 6) == 1 {
            return 50;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "coap"
    }
}

pub struct NknTaste;
impl ProtocolTaste for NknTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if (30001..=30003).contains(&dst_port) {
            return 85;
        }
        let text = String::from_utf8_lossy(data);
        if text.contains("\"jsonrpc\"")
            && (text.contains("getnodestate") || text.contains("getlatestblockheight"))
        {
            return 90;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "nkn"
    }
}

pub struct FingerTaste;
impl ProtocolTaste for FingerTaste {
    fn taste(&self, _data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 79 {
            return 90;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "finger"
    }
}

pub struct IdentTaste;
impl ProtocolTaste for IdentTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 113 {
            return 90;
        }
        // Ident queries format: "port, port\r\n"
        if let Ok(text) = std::str::from_utf8(data) {
            if text.contains(',')
                && text.trim().split(',').count() == 2
                && text
                    .trim()
                    .split(',')
                    .all(|p| p.trim().parse::<u16>().is_ok())
            {
                return 75;
            }
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "ident"
    }
}

pub struct DaytimeTaste;
impl ProtocolTaste for DaytimeTaste {
    fn taste(&self, _data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 13 {
            return 90;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "daytime"
    }
}

pub struct TimeTaste;
impl ProtocolTaste for TimeTaste {
    fn taste(&self, _data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 37 {
            return 90;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "time"
    }
}

pub struct ChargenTaste;
impl ProtocolTaste for ChargenTaste {
    fn taste(&self, _data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 19 {
            return 90;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "chargen"
    }
}

pub struct QuotdTaste;
impl ProtocolTaste for QuotdTaste {
    fn taste(&self, _data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 17 {
            return 90;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "quotd"
    }
}

pub struct SyslogRecvTaste;
impl ProtocolTaste for SyslogRecvTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 514 {
            return 90;
        }
        // Syslog messages start with <PRI>
        if data.len() >= 3 && data[0] == b'<' && data.iter().take(6).any(|&b| b == b'>') {
            return 75;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "syslogrecv"
    }
}

pub struct DummyTaste;
impl ProtocolTaste for DummyTaste {
    fn taste(&self, _data: &[u8], _dst_port: u16) -> TasteScore {
        2 // Just above raw fallback, configurable catch-all
    }
    fn protocol_name(&self) -> &'static str {
        "dummy"
    }
}

pub struct RawTaste;
impl ProtocolTaste for RawTaste {
    fn taste(&self, _data: &[u8], _dst_port: u16) -> TasteScore {
        1 // Always matches as fallback (lowest priority)
    }
    fn protocol_name(&self) -> &'static str {
        "raw"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_taste_port() {
        let taste = DnsTaste;
        assert_eq!(taste.taste(&[], 53), 90);
        assert_eq!(taste.taste(&[], 80), 0);
    }

    #[test]
    fn test_dns_taste_data() {
        let taste = DnsTaste;
        let mut dns_query = vec![0u8; 12];
        dns_query[4] = 0;
        dns_query[5] = 1;
        assert_eq!(taste.taste(&dns_query, 0), 70);
    }

    #[test]
    fn test_http_taste_methods() {
        let taste = HttpTaste;
        assert_eq!(taste.taste(b"GET / HTTP/1.1", 80), 95);
        assert_eq!(taste.taste(b"POST /api", 8080), 95);
        assert_eq!(taste.taste(b"INVALID", 80), 30);
    }

    #[test]
    fn test_tls_taste() {
        let taste = TlsTaste;
        assert_eq!(taste.taste(&[0x16, 0x03, 0x01], 443), 95);
        assert_eq!(taste.taste(&[0x16, 0x03, 0x03], 0), 95);
        assert_eq!(taste.taste(&[], 443), 40);
    }

    #[test]
    fn test_smtp_taste() {
        let taste = SmtpTaste;
        assert_eq!(taste.taste(&[], 25), 85);
        assert_eq!(taste.taste(&[], 587), 85);
        // SMTP commands on non-standard port still detected
        assert_eq!(taste.taste(b"HELO example.com", 8080), 90);
        assert_eq!(taste.taste(b"EHLO test", 0), 90);
    }

    #[test]
    fn test_raw_taste_fallback() {
        let taste = RawTaste;
        assert_eq!(taste.taste(&[], 0), 1);
        assert_eq!(taste.taste(b"any data", 12345), 1);
    }
}
