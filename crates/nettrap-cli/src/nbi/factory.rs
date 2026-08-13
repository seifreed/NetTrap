use crate::session::SessionDestination;
use crate::session::normalize_session_ip;

use super::NetworkBehaviorIndicator;

fn apply_fake_timestamp(mut nbi: NetworkBehaviorIndicator) -> NetworkBehaviorIndicator {
    nbi.timestamp = crate::faketime::fake_now().to_rfc3339();
    nbi
}

/// Build NBI for DNS query
pub fn dns_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    domain: &str,
    query_type: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(
        listener,
        "DNS",
        &canonicalize_nbi_ip(src_ip),
        src_port,
        &canonicalize_nbi_destination_ip(src_ip, destination.ip()),
        destination.port(),
    );
    nbi.add("query_type", query_type);
    nbi.add("domain", domain);
    apply_fake_timestamp(nbi)
}

/// Build NBI for HTTP request
pub struct HttpNbiInput<'a> {
    pub listener: &'a str,
    pub src_ip: &'a str,
    pub src_port: u16,
    pub destination: &'a SessionDestination,
    pub method: &'a str,
    pub uri: &'a str,
    pub host: &'a str,
    pub user_agent: &'a str,
    pub body_len: usize,
}

pub fn http_nbi(input: HttpNbiInput<'_>) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(
        input.listener,
        "HTTP",
        &canonicalize_nbi_ip(input.src_ip),
        input.src_port,
        &canonicalize_nbi_destination_ip(input.src_ip, input.destination.ip()),
        input.destination.port(),
    );
    nbi.add("method", input.method);
    nbi.add("uri", input.uri);
    if !input.host.is_empty() {
        nbi.add("host", input.host);
    }
    if !input.user_agent.is_empty() {
        nbi.add("user_agent", input.user_agent);
    }
    if input.body_len > 0 {
        nbi.add("body_length", input.body_len.to_string());
    }
    apply_fake_timestamp(nbi)
}

/// Build NBI for SMTP command
pub fn smtp_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    command: &str,
    args: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(
        listener,
        "SMTP",
        &canonicalize_nbi_ip(src_ip),
        src_port,
        &canonicalize_nbi_destination_ip(src_ip, destination.ip()),
        destination.port(),
    );
    nbi.add("command", command);
    if !args.is_empty() {
        nbi.add("args", args);
    }
    apply_fake_timestamp(nbi)
}

/// Build NBI for FTP command
pub fn ftp_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    command: &str,
    args: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(
        listener,
        "FTP",
        &canonicalize_nbi_ip(src_ip),
        src_port,
        &canonicalize_nbi_destination_ip(src_ip, destination.ip()),
        destination.port(),
    );
    nbi.add("command", command);
    if !args.is_empty() {
        nbi.add("args", args);
    }
    apply_fake_timestamp(nbi)
}

/// Build NBI for POP3 command
pub fn pop3_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    command: &str,
    args: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(
        listener,
        "POP3",
        &canonicalize_nbi_ip(src_ip),
        src_port,
        &canonicalize_nbi_destination_ip(src_ip, destination.ip()),
        destination.port(),
    );
    nbi.add("command", command);
    if !args.is_empty() {
        nbi.add("args", args);
    }
    apply_fake_timestamp(nbi)
}

/// Build NBI for IRC command
pub fn irc_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    nick: &str,
    command: &str,
    args: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(
        listener,
        "IRC",
        &canonicalize_nbi_ip(src_ip),
        src_port,
        &canonicalize_nbi_destination_ip(src_ip, destination.ip()),
        destination.port(),
    );
    nbi.add("nick", nick);
    nbi.add("command", command);
    if !args.is_empty() {
        nbi.add("args", args);
    }
    apply_fake_timestamp(nbi)
}

/// Build NBI for TFTP request
pub fn tftp_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    operation: &str,
    filename: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(
        listener,
        "TFTP",
        &canonicalize_nbi_ip(src_ip),
        src_port,
        &canonicalize_nbi_destination_ip(src_ip, destination.ip()),
        destination.port(),
    );
    nbi.add("operation", operation);
    if !filename.is_empty() {
        nbi.add("filename", filename);
    }
    apply_fake_timestamp(nbi)
}

/// Build NBI for raw/unknown data
pub fn raw_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    data_len: usize,
    hexdump_preview: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(
        listener,
        "RAW",
        &canonicalize_nbi_ip(src_ip),
        src_port,
        &canonicalize_nbi_destination_ip(src_ip, destination.ip()),
        destination.port(),
    );
    nbi.add("data_length", data_len.to_string());
    if !hexdump_preview.is_empty() {
        nbi.add("hexdump", hexdump_preview);
    }
    apply_fake_timestamp(nbi)
}

/// Build NBI for TLS connection
pub fn tls_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    sni: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(
        listener,
        "TLS",
        &canonicalize_nbi_ip(src_ip),
        src_port,
        &canonicalize_nbi_destination_ip(src_ip, destination.ip()),
        destination.port(),
    );
    if !sni.is_empty() {
        nbi.add("sni", sni);
    }
    apply_fake_timestamp(nbi)
}

/// Build NBI for QUIC traffic
pub fn quic_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    sni: Option<&str>,
    data_len: usize,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(
        listener,
        "QUIC",
        &canonicalize_nbi_ip(src_ip),
        src_port,
        &canonicalize_nbi_destination_ip(src_ip, destination.ip()),
        destination.port(),
    );
    nbi.add("data_length", data_len.to_string());
    if let Some(sni) = sni.filter(|sni| !sni.is_empty()) {
        nbi.add("sni", sni);
    }
    apply_fake_timestamp(nbi)
}

fn canonicalize_nbi_ip(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(ip) => normalize_session_ip(ip).to_string(),
        Err(_) => ip.to_string(),
    }
}

fn canonicalize_nbi_destination_ip(src_ip: &str, destination_ip: &str) -> String {
    let destination_ip = canonicalize_nbi_ip(destination_ip);
    if destination_ip != "0.0.0.0" {
        return destination_ip;
    }

    match canonicalize_nbi_ip(src_ip).parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) | Err(_) => destination_ip,
        Ok(std::net::IpAddr::V6(_)) => std::net::Ipv6Addr::UNSPECIFIED.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_nbi_canonicalizes_ipv4_mapped_addresses() {
        let destination = SessionDestination::new_unchecked("::ffff:10.0.0.5", 53);
        let nbi = dns_nbi(
            "dns",
            "::ffff:192.0.2.10",
            12345,
            &destination,
            "example.com",
            "A",
        );

        assert_eq!(nbi.src_ip, "192.0.2.10");
        assert_eq!(nbi.dst_ip, "10.0.0.5");
    }

    #[test]
    fn dns_nbi_uses_faketime_offset_for_timestamp() {
        let baseline = crate::faketime::get_delta();
        crate::faketime::set_delta(86_400);

        let destination = SessionDestination::new_unchecked("198.51.100.9", 53);
        let nbi = dns_nbi(
            "dns",
            "203.0.113.5",
            12345,
            &destination,
            "example.com",
            "A",
        );

        let expected_date = (chrono::Utc::now() + chrono::Duration::days(1)).date_naive();
        let actual_date = chrono::DateTime::parse_from_rfc3339(&nbi.timestamp)
            .expect("timestamp should parse as RFC3339")
            .date_naive();

        assert_eq!(actual_date, expected_date);

        crate::faketime::set_delta(baseline);
    }

    #[test]
    fn raw_nbi_replaces_invalid_source_text_with_unknown_destination() {
        let destination = SessionDestination::new_unchecked("::ffff:203.0.113.10", 80);
        let nbi = raw_nbi("raw", "::ffff:192.0.2.10", 12345, &destination, 4, "");

        assert_eq!(nbi.src_ip, "192.0.2.10");
        assert_eq!(nbi.dst_ip, "203.0.113.10");
    }

    #[test]
    fn raw_nbi_preserves_invalid_source_text_and_unknown_destination() {
        let destination = SessionDestination::unknown(80);
        let nbi = raw_nbi("raw", "not-an-ip", 12345, &destination, 4, "");

        assert_eq!(nbi.src_ip, "not-an-ip");
        assert_eq!(nbi.dst_ip, "0.0.0.0");
    }

    #[test]
    fn raw_nbi_uses_source_family_for_unknown_destination() {
        let destination = SessionDestination::unknown(80);
        let nbi = raw_nbi("raw", "::1", 12345, &destination, 4, "");

        assert_eq!(nbi.src_ip, "::1");
        assert_eq!(nbi.dst_ip, "::");
    }

    #[test]
    fn raw_nbi_treats_ipv4_mapped_source_as_ipv4_for_unknown_destination() {
        let destination = SessionDestination::unknown(80);
        let nbi = raw_nbi("raw", "::ffff:192.0.2.10", 12345, &destination, 4, "");

        assert_eq!(nbi.src_ip, "192.0.2.10");
        assert_eq!(nbi.dst_ip, "0.0.0.0");
    }

    #[test]
    fn http_nbi_omits_empty_optional_fields() {
        let destination = SessionDestination::new_unchecked("198.51.100.9", 80);
        let nbi = http_nbi(HttpNbiInput {
            listener: "http",
            src_ip: "203.0.113.5",
            src_port: 12345,
            destination: &destination,
            method: "GET",
            uri: "/",
            host: "",
            user_agent: "",
            body_len: 0,
        });

        assert_eq!(nbi.src_ip, "203.0.113.5");
        assert_eq!(nbi.dst_ip, "198.51.100.9");
        assert!(!nbi.indicators.contains_key("host"));
        assert!(!nbi.indicators.contains_key("user_agent"));
        assert!(!nbi.indicators.contains_key("body_length"));
    }

    #[test]
    fn http_nbi_includes_non_empty_user_agent() {
        let destination = SessionDestination::new_unchecked("198.51.100.9", 80);
        let nbi = http_nbi(HttpNbiInput {
            listener: "http",
            src_ip: "203.0.113.5",
            src_port: 12345,
            destination: &destination,
            method: "GET",
            uri: "/",
            host: "example.com",
            user_agent: "NetTrapTest/1.0",
            body_len: 0,
        });

        assert_eq!(
            nbi.indicators.get("user_agent").map(String::as_str),
            Some("NetTrapTest/1.0")
        );
    }

    #[test]
    fn http_nbi_uses_faketime_offset_for_timestamp() {
        let baseline = crate::faketime::get_delta();
        crate::faketime::set_delta(86_400);

        let destination = SessionDestination::new_unchecked("198.51.100.9", 80);
        let nbi = http_nbi(HttpNbiInput {
            listener: "http",
            src_ip: "203.0.113.5",
            src_port: 12345,
            destination: &destination,
            method: "GET",
            uri: "/",
            host: "example.com",
            user_agent: "NetTrapTest/1.0",
            body_len: 0,
        });

        let expected_date = (chrono::Utc::now() + chrono::Duration::days(1)).date_naive();
        let actual_date = chrono::DateTime::parse_from_rfc3339(&nbi.timestamp)
            .expect("timestamp should parse as RFC3339")
            .date_naive();

        assert_eq!(actual_date, expected_date);

        crate::faketime::set_delta(baseline);
    }

    #[test]
    fn quic_nbi_canonicalizes_ipv4_mapped_addresses() {
        let destination = SessionDestination::new_unchecked("::ffff:198.51.100.9", 443);
        let nbi = quic_nbi(
            "quic",
            "::ffff:192.0.2.10",
            12345,
            &destination,
            Some("example.com"),
            128,
        );

        assert_eq!(nbi.src_ip, "192.0.2.10");
        assert_eq!(nbi.dst_ip, "198.51.100.9");
        assert_eq!(
            nbi.indicators.get("sni").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(
            nbi.indicators.get("data_length").map(String::as_str),
            Some("128")
        );
    }
}
