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

fn first_ascii_token(data: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(data).ok()?;
    let line = text.lines().next()?.trim_end_matches('\r');
    line.split_ascii_whitespace().next()
}

fn command_token_matches(data: &[u8], commands: &[&str]) -> bool {
    let Some(token) = first_ascii_token(data) else {
        return false;
    };
    commands
        .iter()
        .any(|command| token.eq_ignore_ascii_case(command))
}

fn first_text_line(data: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(data).ok()?;
    text.lines().next().map(|line| line.trim_end_matches('\r'))
}

fn looks_like_http_start_line(data: &[u8]) -> bool {
    let Some(line) = first_text_line(data) else {
        return false;
    };
    let mut parts = line.split(' ');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return false;
    };
    let Some(third) = parts.next() else {
        return false;
    };
    if parts.next().is_some() || second.is_empty() || third.is_empty() {
        return false;
    }

    matches!(
        first,
        "GET" | "POST" | "PUT" | "HEAD" | "DELETE" | "OPTIONS" | "PATCH" | "CONNECT"
    ) && matches!(third, "HTTP/1.0" | "HTTP/1.1")
        && second
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace())
}

fn looks_like_dns_query(data: &[u8]) -> bool {
    if data.len() < 12 || data[0].is_ascii_alphabetic() {
        return false;
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_query = (flags & 0x8000) == 0;
    let opcode = (flags >> 11) & 0x0f;
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);

    is_query
        && opcode <= 2
        && (1..=10).contains(&qdcount)
        && ancount == 0
        && dns_questions_fit(data, qdcount)
}

fn dns_questions_fit(data: &[u8], qdcount: u16) -> bool {
    let mut pos = 12usize;

    for _ in 0..qdcount {
        loop {
            let Some(&label_len) = data.get(pos) else {
                return false;
            };

            match label_len & 0xc0 {
                0x00 => {
                    pos += 1;
                    if label_len == 0 {
                        break;
                    }
                    if label_len > 63 {
                        return false;
                    }
                    pos = match pos.checked_add(label_len as usize) {
                        Some(next) if next <= data.len() => next,
                        _ => return false,
                    };
                }
                0xc0 => {
                    let Some(&pointer_low) = data.get(pos + 1) else {
                        return false;
                    };
                    let pointer = (((label_len & 0x3f) as usize) << 8) | pointer_low as usize;
                    if pointer >= data.len() {
                        return false;
                    }
                    pos += 2;
                    break;
                }
                _ => return false,
            }
        }

        pos = match pos.checked_add(4) {
            Some(next) if next <= data.len() => next,
            _ => return false,
        };
    }

    true
}

fn looks_like_complete_tls_record(data: &[u8]) -> bool {
    if data.len() < 5 || data[0] != 0x16 || data[1] != 0x03 || !(0x01..=0x04).contains(&data[2]) {
        return false;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    record_len > 0
        && 5usize
            .checked_add(record_len)
            .is_some_and(|record_end| record_end <= data.len())
}

fn looks_like_sip_request_line(data: &[u8]) -> bool {
    let Some(line) = first_text_line(data) else {
        return false;
    };
    let mut parts = line.split(' ');
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(target) = parts.next() else {
        return false;
    };
    let Some(version) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && !target.is_empty()
        && version == "SIP/2.0"
        && matches!(
            method,
            "REGISTER"
                | "INVITE"
                | "OPTIONS"
                | "ACK"
                | "BYE"
                | "CANCEL"
                | "MESSAGE"
                | "SUBSCRIBE"
                | "NOTIFY"
                | "INFO"
                | "PRACK"
                | "UPDATE"
                | "REFER"
        )
}

fn mqtt_remaining_length_end(data: &[u8]) -> Option<usize> {
    let mut pos = 1usize;
    while pos < data.len() && pos <= 4 {
        let byte = data[pos];
        pos += 1;
        if byte & 0x80 == 0 {
            return Some(pos);
        }
    }
    None
}

fn looks_like_nkn_json_rpc(data: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.get("jsonrpc").and_then(|value| value.as_str()) != Some("2.0") {
        return false;
    }
    matches!(
        object.get("method").and_then(|value| value.as_str()),
        Some("getnodestate" | "getlatestblockheight" | "getwsaddr")
    )
}

// Built-in taste implementations for known protocols

pub struct DnsTaste;
impl ProtocolTaste for DnsTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if looks_like_dns_query(data) {
            if dst_port == 53 {
                return 90;
            }
            return 70;
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
        if looks_like_http_start_line(data) {
            return 95;
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
        if looks_like_complete_tls_record(data) {
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
        if command_token_matches(
            data,
            &[
                "EHLO", "HELO", "MAIL", "RCPT", "DATA", "QUIT", "AUTH", "VRFY", "EXPN",
            ],
        ) {
            return 90;
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
        if command_token_matches(
            data,
            &[
                "USER", "PASS", "LIST", "NLST", "RETR", "STOR", "QUIT", "PASV", "EPSV", "PWD",
                "CWD",
            ],
        ) {
            return 80;
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
        if command_token_matches(
            data,
            &[
                "STAT", "RETR", "DELE", "TOP", "UIDL", "CAPA", "AUTH", "STLS",
            ],
        ) {
            return 80;
        }
        // Ambiguous commands shared with FTP: lower score so FTP wins on tie.
        if command_token_matches(data, &["USER", "PASS", "LIST", "QUIT"]) {
            return 65;
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
        if looks_like_tftp_request(data) {
            return if dst_port == 69 { 90 } else { 75 };
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "tftp"
    }
}

fn looks_like_tftp_request(data: &[u8]) -> bool {
    if data.len() < 6 || !data.ends_with(&[0]) {
        return false;
    }
    let opcode = u16::from_be_bytes([data[0], data[1]]);
    if !matches!(opcode, 1 | 2) {
        return false;
    }

    let mut parts: Vec<&[u8]> = data[2..].split(|&byte| byte == 0).collect();
    if matches!(parts.last(), Some(part) if part.is_empty()) {
        parts.pop();
    }
    if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() || parts.len() % 2 != 0 {
        return false;
    }

    let mode = String::from_utf8_lossy(parts[1]).to_ascii_lowercase();
    matches!(mode.as_str(), "netascii" | "octet" | "mail")
}

pub struct QuicTaste;
impl ProtocolTaste for QuicTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if data.len() < 5 || data[0] & 0x80 == 0 {
            return 0;
        }

        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        if !matches!(version, 1 | 0xff000010 | 0xff000011) {
            return 0;
        }

        if dst_port == 443 { 85 } else { 80 }
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
        if looks_like_rdp_tpkt(data) {
            return if dst_port == 3389 { 95 } else { 70 };
        }
        if dst_port == 3389 {
            return 40;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "rdp"
    }
}

fn looks_like_rdp_tpkt(data: &[u8]) -> bool {
    if data.len() < 7 || data[0] != 0x03 || data[1] != 0x00 {
        return false;
    }
    let tpkt_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if tpkt_len < 7 || tpkt_len > data.len() {
        return false;
    }
    let frame = &data[..tpkt_len];
    let x224_len = frame[4] as usize;
    if x224_len < 2 || 5 + x224_len > frame.len() {
        return false;
    }
    matches!(frame[5] >> 4, 0x0E | 0x0F)
}

pub struct RedisTaste;
impl ProtocolTaste for RedisTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 6379 {
            return 90;
        }
        if looks_like_resp_array(data) || command_token_matches(data, &["PING", "INFO", "AUTH"]) {
            return 80;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "redis"
    }
}

fn looks_like_resp_array(data: &[u8]) -> bool {
    if !data.starts_with(b"*") {
        return false;
    }
    let Some(line_end) = data.windows(2).position(|window| window == b"\r\n") else {
        return false;
    };
    let Ok(count) = std::str::from_utf8(&data[1..line_end]) else {
        return false;
    };
    count.parse::<u64>().is_ok_and(|value| value > 0)
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
        if ldap_app_tag_offset(data).is_some() {
            return 55;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "ldap"
    }
}

fn ldap_app_tag_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 7 || data[0] != 0x30 {
        return None;
    }

    let (seq_len, seq_len_bytes) = ber_length(&data[1..])?;
    let msg_id_pos = 1usize.checked_add(seq_len_bytes)?;
    let seq_end = msg_id_pos.checked_add(seq_len)?;
    if seq_end > data.len() || msg_id_pos >= seq_end || data[msg_id_pos] != 0x02 {
        return None;
    }

    let id_len_pos = msg_id_pos + 1;
    let (id_len, id_len_bytes) = ber_length(&data[id_len_pos..seq_end])?;
    if id_len == 0 || id_len > 4 {
        return None;
    }
    let id_start = id_len_pos.checked_add(id_len_bytes)?;
    let app_tag_pos = id_start.checked_add(id_len)?;
    if app_tag_pos >= seq_end || (data[app_tag_pos] & 0xe0) != 0x60 {
        return None;
    }

    Some(app_tag_pos)
}

fn ber_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }

    let len_bytes = (first & 0x7f) as usize;
    if len_bytes == 0 || len_bytes > 4 || data.len() < 1 + len_bytes {
        return None;
    }
    let mut len = 0usize;
    for byte in &data[1..1 + len_bytes] {
        len = (len << 8) | *byte as usize;
    }
    Some((len, 1 + len_bytes))
}

pub struct MqttTaste;
impl ProtocolTaste for MqttTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 1883 {
            return 90;
        }
        // MQTT CONNECT packet: fixed header type 1, then variable-length remaining length (1-4 bytes)
        if data.len() >= 7 && data[0] == 0x10 {
            let Some(remaining_start) = mqtt_remaining_length_end(data) else {
                return 0;
            };
            // After remaining length: protocol name length (2 bytes) + "MQTT"
            if remaining_start + 6 <= data.len()
                && data[remaining_start] == 0
                && data[remaining_start + 1] == 4
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
        if command_token_matches(
            data,
            &[
                "get",
                "gets",
                "set",
                "add",
                "replace",
                "append",
                "prepend",
                "cas",
                "stats",
                "version",
                "flush_all",
                "quit",
            ],
        ) {
            return 85;
        }
        if data.len() >= 24
            && data[0] == 0x80
            && matches!(
                data[1],
                0x00 | 0x01
                    | 0x02
                    | 0x03
                    | 0x04
                    | 0x05
                    | 0x06
                    | 0x07
                    | 0x08
                    | 0x09
                    | 0x0a
                    | 0x0b
                    | 0x0c
                    | 0x0d
                    | 0x0e
                    | 0x0f
                    | 0x10
                    | 0x11
                    | 0x12
                    | 0x13
                    | 0x14
                    | 0x15
                    | 0x16
                    | 0x17
                    | 0x18
                    | 0x19
                    | 0x1a
                    | 0x1c
                    | 0x1d
            )
        {
            return 75;
        }
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
        if looks_like_sip_request_line(data) {
            return if dst_port == 5060 || dst_port == 5061 {
                90
            } else {
                85
            };
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
        if looks_like_ssdp_request(data) {
            return if dst_port == 1900 { 90 } else { 75 };
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "upnp"
    }
}

fn looks_like_ssdp_request(data: &[u8]) -> bool {
    let Some(line) = first_text_line(data) else {
        return false;
    };
    let mut parts = line.split(' ');
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(target) = parts.next() else {
        return false;
    };
    let Some(version) = parts.next() else {
        return false;
    };
    if parts.next().is_some() || target != "*" || version != "HTTP/1.1" {
        return false;
    }
    if !headers_are_well_formed(data) || header_value(data, "HOST").is_none() {
        return false;
    }
    if method.eq_ignore_ascii_case("M-SEARCH") {
        return header_value(data, "MAN")
            .is_some_and(|value| value.eq_ignore_ascii_case("\"ssdp:discover\""))
            && header_value(data, "ST").is_some();
    }
    if method.eq_ignore_ascii_case("NOTIFY") {
        return header_value(data, "NT").is_some() && header_value(data, "NTS").is_some();
    }
    false
}

fn headers_are_well_formed(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    for line in text.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            return true;
        }
        let Some((key, _)) = line.split_once(':') else {
            return false;
        };
        if key.trim().is_empty() {
            return false;
        }
    }
    false
}

fn header_value<'a>(data: &'a [u8], name: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(data).ok()?;
    for line in text.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim());
        }
    }
    None
}

pub struct NtpTaste;
impl ProtocolTaste for NtpTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if looks_like_ntp_client_request(data) {
            return if dst_port == 123 { 90 } else { 60 };
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "ntp"
    }
}

fn looks_like_ntp_client_request(data: &[u8]) -> bool {
    if data.len() < 48 || data.len() % 4 != 0 {
        return false;
    }
    let version = (data[0] >> 3) & 0x07;
    let mode = data[0] & 0x07;
    (3..=4).contains(&version) && mode == 3
}

pub struct CoapTaste;
impl ProtocolTaste for CoapTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if looks_like_plain_coap_request(data) {
            return if dst_port == 5683 { 90 } else { 50 };
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "coap"
    }
}

fn looks_like_plain_coap_request(data: &[u8]) -> bool {
    if data.len() < 4 || (data[0] >> 6) != 1 {
        return false;
    }
    let msg_type = (data[0] >> 4) & 0x03;
    let tkl = (data[0] & 0x0F) as usize;
    let code_class = data[1] >> 5;
    let code_detail = data[1] & 0x1F;
    msg_type <= 1 && tkl <= 8 && data.len() >= 4 + tkl && code_class == 0 && code_detail != 0
}

pub struct NknTaste;
impl ProtocolTaste for NknTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if looks_like_nkn_json_rpc(data) {
            return if (30001..=30003).contains(&dst_port) {
                95
            } else {
                90
            };
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
        if looks_like_syslog_pri(data) {
            return if dst_port == 514 { 90 } else { 75 };
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "syslogrecv"
    }
}

fn looks_like_syslog_pri(data: &[u8]) -> bool {
    if data.first() != Some(&b'<') {
        return false;
    }
    let Some(end) = data.iter().take(6).position(|&byte| byte == b'>') else {
        return false;
    };
    if end <= 1 {
        return false;
    }
    let pri = &data[1..end];
    if pri.len() > 3
        || !pri.iter().all(|byte| byte.is_ascii_digit())
        || (pri.len() > 1 && pri.first() == Some(&b'0'))
    {
        return false;
    }
    let Ok(pri_text) = std::str::from_utf8(pri) else {
        return false;
    };
    let Ok(pri) = pri_text.parse::<u16>() else {
        return false;
    };
    pri <= 191
}

pub struct DummyTaste;
impl ProtocolTaste for DummyTaste {
    fn taste(&self, _data: &[u8], _dst_port: u16) -> TasteScore {
        0
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
        assert_eq!(taste.taste(&[], 53), 0);
        assert_eq!(taste.taste(b"not dns", 53), 0);
        assert_eq!(taste.taste(&[], 80), 0);
    }

    #[test]
    fn test_dns_taste_data() {
        let taste = DnsTaste;
        let dns_query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1,
        ];
        assert_eq!(taste.taste(&dns_query, 0), 70);
        assert_eq!(taste.taste(&dns_query, 53), 90);

        let truncated = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7, b'e',
        ];
        assert_eq!(taste.taste(&truncated, 53), 0);
    }

    #[test]
    fn test_http_taste_methods() {
        let taste = HttpTaste;
        assert_eq!(taste.taste(b"GET / HTTP/1.1", 80), 95);
        assert_eq!(taste.taste(b"POST /api HTTP/1.1", 8080), 95);
        assert_eq!(taste.taste(b"HTTP/1.1 200 OK", 0), 0);
        assert_eq!(taste.taste(b"garbage HTTP inside", 0), 0);
        assert_eq!(taste.taste(b"INVALID", 80), 30);
    }

    #[test]
    fn test_tls_taste() {
        let taste = TlsTaste;
        let mut tls = vec![0x16, 0x03, 0x01, 0x00, 0x03];
        tls.extend_from_slice(&[0x01, 0x02, 0x03]);
        assert_eq!(taste.taste(&tls, 443), 95);
        let mut tls = vec![0x16, 0x03, 0x03, 0x00, 0x03];
        tls.extend_from_slice(&[0x01, 0x02, 0x03]);
        assert_eq!(taste.taste(&tls, 0), 95);
        assert_eq!(taste.taste(&[0x16, 0x03, 0x03, 0x00, 0x20], 0), 0);
        assert_eq!(taste.taste(&[0x16, 0x03, 0x03, 0x00, 0x20], 443), 40);
        assert_eq!(taste.taste(&[0x16, 0x03, 0x00, 0x00, 0x20], 0), 0);
        assert_eq!(taste.taste(&[], 443), 40);
    }

    #[test]
    fn test_tftp_taste_requires_new_request_shape() {
        let taste = TftpTaste;
        let rrq = b"\x00\x01firmware.bin\x00octet\x00";
        let ack = b"\x00\x04\x00\x01";
        let data = b"\x00\x03\x00\x01payload";

        assert_eq!(taste.taste(rrq, 69), 90);
        assert_eq!(taste.taste(rrq, 1069), 75);
        assert_eq!(taste.taste(ack, 69), 0);
        assert_eq!(taste.taste(data, 69), 0);
        assert_eq!(taste.taste(b"\x00\x01file\x00badmode\x00", 69), 0);
    }

    #[test]
    fn test_ldap_taste_rejects_incomplete_long_form_lengths() {
        let taste = LdapTaste;
        let bind = [0x30, 0x05, 0x02, 0x01, 0x01, 0x60, 0x00];
        let incomplete_long_form = [0x30, 0x82, 0x00];

        assert_eq!(taste.taste(&bind, 1389), 55);
        assert_eq!(taste.taste(&incomplete_long_form, 1389), 0);
    }

    #[test]
    fn test_quic_taste_requires_known_version() {
        let taste = QuicTaste;

        assert_eq!(
            taste.taste(&[0xc3, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0], 443),
            85
        );
        assert_eq!(
            taste.taste(&[0xc3, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0], 443),
            0
        );
    }

    #[test]
    fn test_ntp_taste_requires_client_mode_even_on_standard_port() {
        let taste = NtpTaste;
        let mut client = vec![0u8; 48];
        client[0] = 0x23;
        let mut server = vec![0u8; 48];
        server[0] = 0x24;

        assert_eq!(taste.taste(&client, 123), 90);
        assert_eq!(taste.taste(&client, 12345), 60);
        assert_eq!(taste.taste(&server, 123), 0);
        assert_eq!(taste.taste(&server, 12345), 0);
        assert_eq!(taste.taste(b"garbage", 123), 0);
        assert_eq!(taste.taste(&[0u8; 48], 12345), 0);
    }

    #[test]
    fn test_coap_taste_requires_plain_request_even_on_standard_ports() {
        let taste = CoapTaste;

        assert_eq!(taste.taste(&[0x40, 0x01, 0x12, 0x34], 5683), 90);
        assert_eq!(taste.taste(&[0x40, 0x01, 0x12, 0x34], 5684), 50);
        assert_eq!(taste.taste(&[0x40, 0x01, 0x12, 0x34], 12345), 50);
        assert_eq!(taste.taste(b"garbage", 5683), 0);
        assert_eq!(taste.taste(b"garbage", 5684), 0);
        assert_eq!(taste.taste(&[0x60, 0x41, 0x12, 0x34], 12345), 0);
        assert_eq!(taste.taste(&[0x49, 0x01, 0x12, 0x34], 12345), 0);
    }

    #[test]
    fn test_upnp_taste_requires_well_formed_ssdp() {
        let taste = UpnpTaste;
        let m_search = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: upnp:rootdevice\r\n\r\n";
        let notify = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\n\r\n";

        assert_eq!(taste.taste(m_search, 1900), 90);
        assert_eq!(taste.taste(m_search, 9999), 75);
        assert_eq!(taste.taste(notify, 1900), 90);
        assert_eq!(taste.taste(b"garbage", 1900), 0);
        assert_eq!(
            taste.taste(
                b"M-SEARCH * HTTP/1.1\r\nHOST: x\r\nST: upnp:rootdevice\r\n\r\n",
                1900
            ),
            0
        );
    }

    #[test]
    fn test_smtp_taste() {
        let taste = SmtpTaste;
        assert_eq!(taste.taste(&[], 25), 85);
        assert_eq!(taste.taste(&[], 587), 85);
        // SMTP commands on non-standard port still detected
        assert_eq!(taste.taste(b"HELO example.com", 8080), 90);
        assert_eq!(taste.taste(b"EHLO test", 0), 90);
        assert_eq!(taste.taste(b"EHLOXYZ example.com", 0), 0);
    }

    #[test]
    fn test_command_tastes_reject_prefixed_verbs() {
        assert_eq!(FtpTaste.taste(b"LISTEN\r\n", 0), 0);
        assert_eq!(FtpTaste.taste(b"RETRIEVE file\r\n", 0), 0);
        assert_eq!(FtpTaste.taste(b"LIST\r\n", 0), 80);

        assert_eq!(Pop3Taste.taste(b"RETRIEVE 1\r\n", 0), 0);
        assert_eq!(Pop3Taste.taste(b"RETR 1\r\n", 0), 80);

        assert_eq!(MemcachedTaste.taste(b"statsfoo\r\n", 0), 0);
        assert_eq!(MemcachedTaste.taste(b"stats\r\n", 0), 85);
    }

    #[test]
    fn test_memcached_taste_recognizes_binary_quiet_opcodes() {
        let taste = MemcachedTaste;
        let mut request = [0u8; 24];
        request[0] = 0x80;

        for opcode in [0x18, 0x19, 0x1a] {
            request[1] = opcode;
            assert_eq!(taste.taste(&request, 0), 75);
        }
    }

    #[test]
    fn test_rdp_taste_requires_valid_tpkt_and_x224() {
        let taste = RdpTaste;
        let valid = [
            0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let truncated_x224 = [
            0x03, 0x00, 0x00, 0x0b, 0x07, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let garbage = b"not rdp";

        assert_eq!(taste.taste(&valid, 3389), 95);
        assert_eq!(taste.taste(&valid, 12345), 70);
        assert_eq!(taste.taste(&truncated_x224, 3389), 40);
        assert_eq!(taste.taste(garbage, 3389), 40);
        assert_eq!(taste.taste(garbage, 12345), 0);
    }

    #[test]
    fn test_redis_taste_requires_structured_command() {
        let taste = RedisTaste;

        assert_eq!(taste.taste(b"PING\r\n", 0), 80);
        assert_eq!(taste.taste(b"AUTH password\r\n", 0), 80);
        assert_eq!(
            taste.taste(b"*2\r\n$4\r\nAUTH\r\n$8\r\npassword\r\n", 0),
            80
        );

        assert_eq!(taste.taste(b"PINGX\r\n", 0), 0);
        assert_eq!(taste.taste(b"INFOO\r\n", 0), 0);
        assert_eq!(taste.taste(b"AUTHZ password\r\n", 0), 0);
        assert_eq!(taste.taste(b"*garbage\r\n", 0), 0);
        assert_eq!(taste.taste(b"*0\r\n", 0), 0);
        assert_eq!(taste.taste(b"*2", 0), 0);
    }

    #[test]
    fn test_sip_taste_requires_request_line() {
        let taste = SipTaste;

        assert_eq!(taste.taste(b"SIP/2.0 200 OK\r\n", 5060), 0);
        assert_eq!(
            taste.taste(b"INVITE sip:user@example.test SIP/2.0\r\n", 5060),
            90
        );
        assert_eq!(
            taste.taste(b"INVITEX sip:user@example.test SIP/2.0\r\n", 5060),
            0
        );
    }

    #[test]
    fn test_mqtt_taste_requires_complete_valid_connect_header() {
        let taste = MqttTaste;
        let valid_connect = [
            0x10, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x00, 0x00, 0x00,
        ];

        assert_eq!(taste.taste(&valid_connect, 0), 95);
        assert_eq!(
            taste.taste(&[0x10, 0xff, 0xff, 0xff, 0xff, 0x00, 0x04], 0),
            0
        );
        assert_eq!(
            taste.taste(&[0x11, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T'], 0),
            0
        );
    }

    #[test]
    fn test_nkn_taste_requires_json_rpc() {
        let taste = NknTaste;
        let valid = br#"{"jsonrpc":"2.0","method":"getlatestblockheight","params":[],"id":1}"#;

        assert_eq!(taste.taste(valid, 0), 90);
        assert_eq!(taste.taste(valid, 30001), 95);
        assert_eq!(taste.taste(b"garbage", 30001), 0);
        assert_eq!(taste.taste(b"noise \"jsonrpc\" getlatestblockheight", 0), 0);
    }

    #[test]
    fn test_syslog_taste_validates_pri() {
        let taste = SyslogRecvTaste;

        assert_eq!(taste.taste(b"<13>message", 514), 90);
        assert_eq!(taste.taste(b"<13>message", 1514), 75);
        assert_eq!(taste.taste(b"<013>message", 514), 0);
        assert_eq!(taste.taste(b"<192>message", 514), 0);
        assert_eq!(taste.taste(b"<abc>message", 514), 0);
        assert_eq!(taste.taste(b"garbage", 514), 0);
    }

    #[test]
    fn test_raw_taste_fallback() {
        let taste = RawTaste;
        assert_eq!(taste.taste(&[], 0), 1);
        assert_eq!(taste.taste(b"any data", 12345), 1);
    }
}
