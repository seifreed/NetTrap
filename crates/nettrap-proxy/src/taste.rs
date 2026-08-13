//! Protocol taste detection implementations.

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

mod heuristics;
use heuristics::*;

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
        if looks_like_http_request_line_shape(data) {
            return 0;
        }
        if dst_port == 80 || dst_port == 8080 {
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
        if looks_like_complete_tls_client_hello(data) {
            return 95;
        }
        if looks_like_sslv2_client_hello(data) {
            return 80;
        }
        if matches!(dst_port, 443 | 8443 | 9443) {
            return 40;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "tls"
    }
}

pub struct SmtpTaste;
const SMTP_MAX_COMMAND_LINE_BYTES: usize = 1000;

impl ProtocolTaste for SmtpTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 25 || dst_port == 587 || dst_port == 465 {
            return 85;
        }
        if smtp_command_matches(data, SMTP_MAX_COMMAND_LINE_BYTES) {
            return 90;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "smtp"
    }
}

fn smtp_command_matches(data: &[u8], max_line_bytes: usize) -> bool {
    let Some(parts) = strict_command_parts(data, max_line_bytes) else {
        return false;
    };

    match parts.as_slice() {
        [verb] => matches!(
            verb.to_ascii_uppercase().as_str(),
            "DATA"
                | "QUIT"
                | "STARTTLS"
                | "RSET"
                | "NOOP"
                | "HELP"
                | "X-EXPS"
                | "X-EXCH50"
                | "X-LINK2STATE"
        ),
        [verb, arg] => match verb.to_ascii_uppercase().as_str() {
            "EHLO" | "HELO" | "VRFY" => !arg.is_empty(),
            "AUTH" => !arg.is_empty(),
            "MAIL" => smtp_path_args_are_valid(arg, &[], "FROM"),
            "RCPT" => smtp_path_args_are_valid(arg, &[], "TO"),
            _ => false,
        },
        [verb, first, rest @ ..] => match verb.to_ascii_uppercase().as_str() {
            "MAIL" => smtp_path_args_are_valid(first, rest, "FROM"),
            "RCPT" => smtp_path_args_are_valid(first, rest, "TO"),
            "AUTH" => smtp_auth_args_are_valid(first, rest),
            _ => false,
        },
        _ => false,
    }
}

fn smtp_path_args_are_valid(path_arg: &str, params: &[&str], keyword: &str) -> bool {
    let Some((head, path)) = path_arg.split_once(':') else {
        return false;
    };
    if !head.eq_ignore_ascii_case(keyword) {
        return false;
    }
    if !path.starts_with('<') || !path.ends_with('>') || params.iter().any(|param| param.is_empty())
    {
        return false;
    }
    let address = &path[1..path.len() - 1];
    if keyword.eq_ignore_ascii_case("TO") && address.is_empty() {
        return false;
    }
    (address.is_empty()
        || !address
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control()))
        && params.iter().all(|param| smtp_esmtp_param_is_valid(param))
}

fn smtp_esmtp_param_is_valid(param: &str) -> bool {
    let Some((key, value)) = param.split_once('=') else {
        return false;
    };
    !key.is_empty()
        && !value.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && value.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
}

fn smtp_auth_args_are_valid(mechanism: &str, rest: &[&str]) -> bool {
    match mechanism.to_ascii_uppercase().as_str() {
        "PLAIN" | "LOGIN" => rest.len() <= 1 && rest.iter().all(|arg| !arg.is_empty()),
        "CRAM-MD5" | "CRAM-SHA1" => rest.is_empty(),
        _ => rest.len() <= 1 && rest.iter().all(|arg| !arg.is_empty()),
    }
}

pub struct FtpTaste;
const FTP_MAX_COMMAND_LINE_BYTES: usize = 512;

impl ProtocolTaste for FtpTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 21 {
            return 85;
        }
        if ftp_command_token_matches(
            data,
            &[
                "USER", "PASS", "PWD", "XPWD", "TYPE", "PASV", "EPSV", "LIST", "NLST", "RETR",
                "STOR", "APPE", "PORT", "EPRT", "SYST", "HOST", "ACCT", "REIN", "SMNT", "FEAT",
                "OPTS", "ALLO", "MODE", "STRU", "REST", "SIZE", "MDTM", "CWD", "MKD", "XMKD",
                "RMD", "XRMD", "DELE", "RNFR", "RNTO", "STAT", "ABOR", "CDUP", "NOOP", "HELP",
                "QUIT",
            ],
        ) || looks_like_unknown_ftp_command(data)
        {
            return 80;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "ftp"
    }
}

fn ftp_command_token_matches(data: &[u8], commands: &[&str]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    if text
        .chars()
        .any(|ch| matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
    {
        return false;
    }
    let line = if let Some(line) = text.strip_suffix("\r\n") {
        if line.chars().any(|ch| matches!(ch, '\r' | '\n')) {
            return false;
        }
        line
    } else {
        if text.ends_with(['\r', '\n']) || text.chars().any(|ch| matches!(ch, '\r' | '\n')) {
            return false;
        }
        text
    };
    if line.len() > FTP_MAX_COMMAND_LINE_BYTES
        || line.chars().next().is_some_and(char::is_whitespace)
        || line.chars().last().is_some_and(char::is_whitespace)
        || line.chars().any(|ch| ch == '\0')
    {
        return false;
    }
    let verb_end = line.find(' ').unwrap_or(line.len());
    let verb = &line[..verb_end];
    if verb.is_empty() {
        return false;
    }
    if let Some(arg) = line[verb_end..].strip_prefix(' ')
        && arg.starts_with([' ', '\t'])
    {
        return false;
    }
    commands
        .iter()
        .any(|command| verb.eq_ignore_ascii_case(command))
}

fn looks_like_unknown_ftp_command(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let Some(line) = text.strip_suffix("\r\n") else {
        return false;
    };
    if line.len() > FTP_MAX_COMMAND_LINE_BYTES
        || line.chars().any(|ch| {
            matches!(
                ch,
                '\r' | '\n' | '\0' | '\u{0085}' | '\u{2028}' | '\u{2029}'
            )
        })
        || line.chars().next().is_some_and(char::is_whitespace)
        || line.chars().last().is_some_and(char::is_whitespace)
    {
        return false;
    }
    let verb_end = line.find(' ').unwrap_or(line.len());
    let verb = &line[..verb_end];
    if verb.is_empty() || !verb.as_bytes().iter().all(u8::is_ascii_alphabetic) {
        return false;
    }
    if let Some(arg) = line[verb_end..].strip_prefix(' ')
        && arg.starts_with([' ', '\t'])
    {
        return false;
    }
    true
}

pub struct Pop3Taste;
const POP3_MAX_COMMAND_LINE_BYTES: usize = 512;

impl ProtocolTaste for Pop3Taste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 110 || dst_port == 995 {
            return 85;
        }
        if let Some(score) = pop3_command_score(data, POP3_MAX_COMMAND_LINE_BYTES) {
            return score;
        }
        0
    }
    fn protocol_name(&self) -> &'static str {
        "pop3"
    }
}

fn pop3_command_score(data: &[u8], max_line_bytes: usize) -> Option<TasteScore> {
    let parts = strict_command_parts(data, max_line_bytes)?;
    let is_decimal =
        |value: &str| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit());
    let is_token = |value: &str| !value.is_empty();

    let valid = match parts.as_slice() {
        [verb] => matches!(
            verb.to_ascii_uppercase().as_str(),
            "STAT" | "LIST" | "UIDL" | "CAPA" | "AUTH" | "STLS" | "NOOP" | "RSET" | "QUIT"
        ),
        [verb, arg] => match verb.to_ascii_uppercase().as_str() {
            "USER" | "PASS" => is_token(arg),
            "LIST" | "UIDL" | "RETR" | "DELE" => is_decimal(arg),
            "AUTH" => is_token(arg),
            _ => false,
        },
        [verb, first, second] => match verb.to_ascii_uppercase().as_str() {
            "TOP" => is_decimal(first) && is_decimal(second),
            "APOP" => is_token(first) && is_token(second),
            "AUTH" => is_token(first) && is_token(second),
            _ => false,
        },
        _ => false,
    };
    if !valid {
        return None;
    }
    if matches!(
        parts[0].to_ascii_uppercase().as_str(),
        "USER" | "PASS" | "LIST" | "QUIT"
    ) {
        Some(65)
    } else {
        Some(80)
    }
}

fn strict_command_parts(data: &[u8], max_line_bytes: usize) -> Option<Vec<&str>> {
    let Ok(text) = std::str::from_utf8(data) else {
        return None;
    };
    if text.contains('\0')
        || text
            .chars()
            .any(|ch| matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
    {
        return None;
    }
    let line = if let Some(line) = text.strip_suffix("\r\n") {
        if line.chars().any(|ch| matches!(ch, '\r' | '\n')) {
            return None;
        }
        line
    } else {
        if text.ends_with(['\r', '\n']) || text.chars().any(|ch| matches!(ch, '\r' | '\n')) {
            return None;
        }
        text
    };
    if line.len() > max_line_bytes
        || line.is_empty()
        || line.chars().next().is_some_and(char::is_whitespace)
        || line.chars().last().is_some_and(char::is_whitespace)
        || line
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return None;
    }
    let parts: Vec<&str> = line.split(' ').collect();
    if parts.iter().skip(1).any(|part| part.is_empty()) {
        return None;
    }
    Some(parts)
}

pub struct IrcTaste;
impl ProtocolTaste for IrcTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 6667 || dst_port == 6697 || dst_port == 994 {
            return 85;
        }
        if command_token_matches(
            data,
            &[
                "NICK", "USER", "JOIN", "PING", "CAP", "PONG", "PART", "PRIVMSG", "NOTICE", "MODE",
                "LIST", "QUIT", "WHO", "WHOIS",
            ],
        ) || looks_like_irc_command_line(data)
        {
            return 80;
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

pub struct QuicTaste;
const MAX_QUIC_TASTE_PACKET_BYTES: usize = 65_535;
const MAX_QUIC_CONNECTION_ID_BYTES: usize = 20;

impl ProtocolTaste for QuicTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if data.len() < 9
            || data.len() > MAX_QUIC_TASTE_PACKET_BYTES
            || data[0] & 0x80 == 0
            || data[0] & 0x40 == 0
        {
            return 0;
        }

        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        if version != 1 {
            return 0;
        }

        if !looks_like_quic_v1_long_header(data) {
            return 0;
        }

        if dst_port == 443 { 85 } else { 80 }
    }
    fn protocol_name(&self) -> &'static str {
        "quic"
    }
}

fn looks_like_quic_v1_long_header(data: &[u8]) -> bool {
    let packet_type = (data[0] & 0x30) >> 4;
    let packet_number_len = usize::from(data[0] & 0x03) + 1;
    let mut offset = 5;

    let Some(dcid_len) = read_quic_len_byte(data, &mut offset) else {
        return false;
    };
    if dcid_len > MAX_QUIC_CONNECTION_ID_BYTES || !skip_quic_bytes(data, &mut offset, dcid_len) {
        return false;
    }

    let Some(scid_len) = read_quic_len_byte(data, &mut offset) else {
        return false;
    };
    if scid_len > MAX_QUIC_CONNECTION_ID_BYTES || !skip_quic_bytes(data, &mut offset, scid_len) {
        return false;
    }

    if packet_type == 3 {
        return data.len().saturating_sub(offset) >= 17;
    }

    if packet_type == 0 {
        let Some(token_len) = read_quic_varint(data, &mut offset) else {
            return false;
        };
        let Ok(token_len) = usize::try_from(token_len) else {
            return false;
        };
        if !skip_quic_bytes(data, &mut offset, token_len) {
            return false;
        }
    }

    let Some(payload_len) = read_quic_varint(data, &mut offset) else {
        return false;
    };
    let Ok(payload_len) = usize::try_from(payload_len) else {
        return false;
    };
    payload_len >= packet_number_len && payload_len <= data.len().saturating_sub(offset)
}

fn read_quic_len_byte(data: &[u8], offset: &mut usize) -> Option<usize> {
    let len = usize::from(*data.get(*offset)?);
    *offset += 1;
    Some(len)
}

fn skip_quic_bytes(data: &[u8], offset: &mut usize, count: usize) -> bool {
    let Some(next) = offset.checked_add(count) else {
        return false;
    };
    if next > data.len() {
        return false;
    }
    *offset = next;
    true
}

fn read_quic_varint(data: &[u8], offset: &mut usize) -> Option<u64> {
    let first = *data.get(*offset)?;
    let len = 1usize << usize::from(first >> 6);
    let bytes = data.get(*offset..(*offset).checked_add(len)?)?;
    *offset += len;

    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Some(value)
}

pub struct TelnetTaste;
impl ProtocolTaste for TelnetTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if data.starts_with(b"SSH-") {
            return 0;
        }
        if dst_port == 23 {
            return 90;
        }
        if data.len() >= 3 && data[0] == 0xFF {
            return 80;
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
        if looks_like_ssh_client_version(data) {
            return 95;
        }
        if data.starts_with(b"SSH-") {
            return 0;
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
        if looks_like_smb_message(data) {
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

pub struct RedisTaste;
impl ProtocolTaste for RedisTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 6379 {
            return 90;
        }
        if looks_like_resp_array(data) || looks_like_redis_inline_request(data) {
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
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 3306 {
            return 90;
        }
        if looks_like_mysql_client_packet(data) {
            return if data[3] == 1 { 75 } else { 80 };
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

pub struct MqttTaste;
impl ProtocolTaste for MqttTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 1883 {
            return 90;
        }
        if looks_like_mqtt_client_packet(data) {
            return 95;
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
        if looks_like_snmp_request(data) {
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
        if looks_like_socks_message(data) {
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
        if looks_like_memcached_text_request(data) {
            return 85;
        }
        if looks_like_memcached_binary_request(data) {
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
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 5432 {
            return 90;
        }
        if looks_like_postgres_startup_message(data) {
            return 85;
        }
        if looks_like_postgres_cancel_request(data) {
            return 85;
        }
        if looks_like_postgres_typed_message(data) {
            return 80;
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

pub struct NknTaste;
impl ProtocolTaste for NknTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if (30001..=30003).contains(&dst_port) && looks_like_nkn_json_rpc_request(data) {
            return 95;
        }
        if looks_like_nkn_json_rpc(data) {
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
const IDENT_MAX_QUERY_LINE_BYTES: usize = 512;

impl ProtocolTaste for IdentTaste {
    fn taste(&self, data: &[u8], dst_port: u16) -> TasteScore {
        if dst_port == 113 {
            return 90;
        }
        if let Ok(text) = std::str::from_utf8(data) {
            let query = if let Some(query) = text.strip_suffix("\r\n") {
                if query.chars().any(|ch| matches!(ch, '\r' | '\n')) {
                    return 0;
                }
                query
            } else if text.ends_with(['\r', '\n']) {
                return 0;
            } else {
                if text.chars().any(|ch| matches!(ch, '\r' | '\n')) {
                    return 0;
                }
                text
            };
            if query.len() > IDENT_MAX_QUERY_LINE_BYTES {
                return 0;
            }
            if query.contains(',')
                && query.split(',').count() == 2
                && query
                    .split(',')
                    .all(|part| ident_port_text_is_valid(part.trim_matches(' ')))
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
#[path = "taste_tests.rs"]
mod tests;
