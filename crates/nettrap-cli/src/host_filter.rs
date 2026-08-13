use std::net::{IpAddr, ToSocketAddrs};

use ipnet::IpNet;
use nettrap_core::sanitize::{
    has_numeric_domain_labels, has_valid_domain_label_lengths, has_valid_domain_labels,
};

#[cfg(test)]
pub(crate) fn is_loopback_host(host: &str) -> bool {
    host_ip_candidates(host).into_iter().any(|ip| match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostRule {
    ExactIp(IpAddr),
    Cidr(IpNet),
    Hostname {
        hostname: String,
        addresses: Vec<IpAddr>,
    },
}

impl HostRule {
    pub(crate) fn matches(&self, host: &str) -> bool {
        let host = host.trim_matches([' ', '\t']);
        if host.is_empty()
            || host
                .chars()
                .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
        {
            return false;
        }

        match self {
            Self::ExactIp(expected) => host_ip_candidates(host)
                .into_iter()
                .any(|ip| ip == *expected),
            Self::Cidr(cidr) => host_ip_candidates(host)
                .into_iter()
                .any(|ip| cidr.contains(&ip)),
            Self::Hostname {
                hostname,
                addresses,
            } => {
                if hostname_authority_candidate(host)
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(hostname))
                {
                    return true;
                }

                host_ip_candidates(host)
                    .into_iter()
                    .any(|ip| addresses.contains(&ip))
            }
        }
    }
}

pub(crate) fn compile_host_rules(rules: &[String]) -> Result<Vec<HostRule>, String> {
    rules.iter().map(|rule| compile_host_rule(rule)).collect()
}

pub(crate) fn is_host_allowed_with_rules(
    host: &str,
    whitelist: &[HostRule],
    blacklist: &[HostRule],
) -> bool {
    if !whitelist.is_empty() && !whitelist.iter().any(|rule| rule.matches(host)) {
        return false;
    }

    if !blacklist.is_empty() && blacklist.iter().any(|rule| rule.matches(host)) {
        return false;
    }

    true
}

pub(crate) fn resolve_hostname(hostname: &str) -> Result<Vec<IpAddr>, String> {
    let addresses: Vec<IpAddr> = (hostname, 0)
        .to_socket_addrs()
        .map_err(|err| format!("failed to resolve host filter '{}': {}", hostname, err))?
        .map(|addr| addr.ip())
        .collect();

    let addresses = retain_usable_addresses(addresses);
    if addresses.is_empty() {
        return Err(format!(
            "failed to resolve host filter '{}': no IP addresses found",
            hostname
        ));
    }
    Ok(addresses)
}

pub(crate) fn compile_host_rule(rule: &str) -> Result<HostRule, String> {
    if rule.trim_matches([' ', '\t']) != rule || rule.is_empty() {
        return Err(format!("invalid host rule '{}': invalid whitespace", rule));
    }

    if rule
        .chars()
        .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return Err(format!("invalid host rule '{}': invalid whitespace", rule));
    }

    if rule.contains('/') {
        let cidr = rule
            .parse::<IpNet>()
            .map_err(|err| format!("invalid host CIDR '{}': {}", rule, err))?;
        if is_special_cidr(&cidr) {
            return Err(format!("invalid host CIDR '{}': invalid hostname", rule));
        }
        return Ok(HostRule::Cidr(cidr));
    }

    if let Ok(ip) = rule.parse::<IpAddr>() {
        if is_special_ip_literal(&ip) {
            return Err(format!("invalid host rule '{}': invalid hostname", rule));
        }
        return Ok(HostRule::ExactIp(ip));
    }

    let hostname = normalize_hostname(rule);
    if hostname.is_empty() {
        return Err(format!("invalid host rule '{}': invalid hostname", rule));
    }
    if hostname.len() > 253 {
        return Err(format!("invalid host rule '{}': invalid hostname", rule));
    }
    if !has_valid_domain_labels(&hostname)
        || has_numeric_domain_labels(&hostname)
        || !has_valid_domain_label_lengths(&hostname)
    {
        return Err(format!("invalid host rule '{}': invalid hostname", rule));
    }

    resolve_hostname(&hostname).map(|addresses| HostRule::Hostname {
        hostname,
        addresses,
    })
}

#[cfg(test)]
pub(crate) fn host_matches_rule(host: &str, rule: &str) -> bool {
    compile_host_rule(rule).is_ok_and(|compiled| compiled.matches(host))
}

fn normalize_hostname(hostname: &str) -> String {
    if let Some(hostname) = hostname.strip_suffix('.') {
        if hostname.is_empty() || hostname.ends_with('.') {
            return String::new();
        }
        hostname.to_ascii_lowercase()
    } else {
        hostname.to_ascii_lowercase()
    }
}

fn hostname_authority_candidate(host: &str) -> Option<String> {
    if host.starts_with('[') {
        return None;
    }

    let hostname = if let Some((hostname, port)) = host.rsplit_once(':') {
        if hostname.contains(':') {
            return None;
        }
        parse_nonzero_port(port)?;
        hostname
    } else {
        host
    };

    let hostname = normalize_hostname(hostname);
    if hostname.is_empty() {
        None
    } else {
        Some(hostname)
    }
}

fn is_unspecified_ip_literal(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_unspecified(),
        IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_unspecified())
        }
    }
}

fn is_special_ip_literal(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast(),
        IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_multicast()
                || ip.to_ipv4_mapped().is_some_and(|mapped| {
                    mapped.is_unspecified() || mapped.is_multicast() || mapped.is_broadcast()
                })
        }
    }
}

fn is_special_cidr(cidr: &IpNet) -> bool {
    is_special_ip_literal(&cidr.network()) || is_special_ip_literal(&cidr.broadcast())
}

fn host_ip_candidates(host: &str) -> Vec<IpAddr> {
    let Some(ip) = parse_host_ip_literal(host) else {
        return Vec::new();
    };

    let mut candidates = vec![ip];
    match ip {
        IpAddr::V4(ipv4) => {
            candidates.push(IpAddr::V6(ipv4.to_ipv6_mapped()));
        }
        IpAddr::V6(ipv6) => {
            if let Some(mapped) = ipv6.to_ipv4_mapped() {
                candidates.push(IpAddr::V4(mapped));
            }
        }
    }
    candidates
}

fn parse_host_ip_literal(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }

    if let Some(rest) = host.strip_prefix('[') {
        let (inner, suffix) = rest.split_once(']')?;
        if !suffix.is_empty() {
            let port = suffix.strip_prefix(':')?;
            parse_nonzero_port(port)?;
        }
        return inner.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6);
    }

    let (host, port) = host.rsplit_once(':')?;
    if host.contains(':') {
        return None;
    }
    parse_nonzero_port(port)?;
    host.parse::<IpAddr>().ok()
}

fn parse_nonzero_port(value: &str) -> Option<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u16>().ok().filter(|port| *port != 0)
}

fn retain_usable_addresses(mut addresses: Vec<IpAddr>) -> Vec<IpAddr> {
    addresses.retain(|ip| {
        !is_unspecified_ip_literal(ip)
            && match ip {
                IpAddr::V4(ip) => !ip.is_multicast() && !ip.is_broadcast(),
                IpAddr::V6(ip) => {
                    !ip.is_multicast()
                        && ip
                            .to_ipv4_mapped()
                            .is_none_or(|mapped| !mapped.is_multicast() && !mapped.is_broadcast())
                }
            }
    });
    addresses.sort();
    addresses.dedup();
    addresses
}

#[cfg(test)]
mod tests {
    use super::{
        compile_host_rule, compile_host_rules, host_matches_rule, is_host_allowed_with_rules,
        is_loopback_host, resolve_hostname,
    };

    #[test]
    fn recognizes_ipv4_mapped_loopback() {
        assert!(is_loopback_host("::ffff:127.0.0.1"));
        assert!(is_loopback_host("::ffff:127.0.0.42"));
        assert!(!is_loopback_host("::ffff:10.0.0.1"));
    }

    #[test]
    fn rejects_loopback_prefixes_that_are_not_valid_ips() {
        assert!(!is_loopback_host("127.0.0.1.evil"));
        assert!(!is_loopback_host("::ffff:127.0.0.1.evil"));
    }

    #[test]
    fn matches_exact_hosts_and_cidrs() {
        assert!(host_matches_rule("10.1.2.3", "10.0.0.0/8"));
        assert!(host_matches_rule("::ffff:10.1.2.3", "10.0.0.0/8"));
        assert!(!host_matches_rule("192.168.1.10", "10.0.0.0/8"));
        assert!(host_matches_rule("10.1.2.3", "10.1.2.3"));
        assert!(host_matches_rule("127.0.0.1", "::ffff:127.0.0.1"));
        assert!(host_matches_rule("::ffff:10.1.2.3", "10.1.2.3"));
        assert!(!host_matches_rule("10.1.2.4", "10.1.2.3"));
        assert!(!host_matches_rule("10.1.2.3", "10.0.0.0/not-a-prefix"));
    }

    #[test]
    fn matches_ip_authorities_with_ports() {
        assert!(host_matches_rule("10.1.2.3:443", "10.1.2.3"));
        assert!(host_matches_rule("[2001:db8::1]", "2001:db8::1"));
        assert!(host_matches_rule("[2001:db8::1]:443", "2001:db8::/32"));
        assert!(!host_matches_rule("[2001:db8::1]:0", "2001:db8::1"));
        assert!(!host_matches_rule("[2001:db8::1]:bad", "2001:db8::1"));
    }

    #[test]
    fn recognizes_loopback_ip_authorities() {
        assert!(is_loopback_host("127.0.0.1:8080"));
        assert!(is_loopback_host("[::1]:8080"));
        assert!(is_loopback_host("[::ffff:127.0.0.1]:8080"));
        assert!(!is_loopback_host("[::ffff:10.0.0.1]:8080"));
    }

    #[test]
    fn resolves_hostname_rules_to_matching_addresses() {
        let localhost = resolve_hostname("localhost").expect("localhost should resolve");

        assert!(
            localhost
                .iter()
                .any(|address| host_matches_rule(&address.to_string(), "localhost"))
        );
    }

    #[test]
    fn blacklist_hostname_rules_can_block_loopback_hosts() {
        let whitelist = compile_host_rules(&[]).expect("empty whitelist should compile");
        let blacklist = compile_host_rules(&["localhost".to_string()])
            .expect("localhost blacklist should compile");

        assert!(!is_host_allowed_with_rules(
            "127.0.0.1",
            &whitelist,
            &blacklist
        ));
        assert!(!is_host_allowed_with_rules(
            "::ffff:127.0.0.1",
            &whitelist,
            &blacklist
        ));
    }

    #[test]
    fn blacklist_overrides_matching_whitelist_rules() {
        let whitelist = compile_host_rules(&["localhost".to_string()])
            .expect("localhost whitelist should compile");
        let blacklist = compile_host_rules(&["localhost".to_string()])
            .expect("localhost blacklist should compile");

        assert!(!is_host_allowed_with_rules(
            "127.0.0.1",
            &whitelist,
            &blacklist
        ));
        assert!(!is_host_allowed_with_rules(
            "::ffff:127.0.0.1",
            &whitelist,
            &blacklist
        ));
    }

    #[test]
    fn mapped_ipv6_hosts_match_resolved_ipv4_hostname_addresses() {
        let rule = compile_host_rule("localhost").expect("localhost should resolve");

        assert!(rule.matches("::ffff:127.0.0.1"));
    }

    #[test]
    fn matches_absolute_hostnames_with_trailing_dots() {
        assert!(host_matches_rule("example.com.", "example.com"));
        assert!(host_matches_rule("example.com", "example.com."));
    }

    #[test]
    fn matches_hostname_authorities_with_ports() {
        assert!(host_matches_rule("localhost:8080", "localhost"));
        assert!(host_matches_rule("localhost.:8080", "localhost"));
        assert!(!host_matches_rule("localhost:0", "localhost"));
        assert!(!host_matches_rule("localhost:bad", "localhost"));
    }

    #[test]
    fn compile_host_rule_canonicalizes_hostname_case() {
        let upper = compile_host_rule("LOCALHOST.").expect("localhost should resolve");
        let lower = compile_host_rule("localhost").expect("localhost should resolve");

        assert_eq!(upper, lower);
    }

    #[test]
    fn rejects_multiple_trailing_dots_in_hostname_rules() {
        assert!(!host_matches_rule("example.com...", "example.com"));
        assert!(!host_matches_rule("example.com", "example.com..."));
    }

    #[test]
    fn compile_host_rule_rejects_unresolvable_hostnames() {
        let err = compile_host_rule("definitely-not-a-real-nettrap-host.invalid")
            .expect_err("invalid hostname should fail");

        assert!(err.contains("failed to resolve host filter"));
    }

    #[test]
    fn compile_host_rule_rejects_unicode_whitespace() {
        let err = compile_host_rule("example\u{00a0}.test").expect_err("unicode whitespace");

        assert!(err.contains("invalid host rule"));
    }

    #[test]
    fn compile_host_rule_rejects_ascii_padding() {
        let err = compile_host_rule(" localhost ").expect_err("ascii whitespace");

        assert!(err.contains("invalid whitespace"));
        assert!(!host_matches_rule("localhost", " localhost "));
    }

    #[test]
    fn compile_host_rule_rejects_c1_controls() {
        let err = compile_host_rule("example\u{009f}.test").expect_err("C1 control");

        assert!(err.contains("invalid host rule"));
    }

    #[test]
    fn compile_host_rule_rejects_overlong_absolute_hostnames() {
        let hostname = format!("{}.", "a".repeat(254));

        let err = compile_host_rule(&hostname).expect_err("overlong hostname should fail");

        assert!(err.contains("invalid host rule"));
    }

    #[test]
    fn compile_host_rule_rejects_overlong_hostname_labels() {
        let hostname = format!("{}.example.test", "a".repeat(64));

        let err = compile_host_rule(&hostname).expect_err("overlong label should fail");

        assert!(err.contains("invalid host rule"));
    }

    #[test]
    fn compile_host_rule_rejects_underscored_hostnames() {
        let err = compile_host_rule("mail_example.local").expect_err("underscored hostname");

        assert!(err.contains("invalid host rule"));
    }

    #[test]
    fn compile_host_rule_rejects_numeric_hostnames() {
        let err = compile_host_rule("12345").expect_err("numeric hostname should fail");

        assert!(err.contains("invalid host rule"));
    }

    #[test]
    fn compile_host_rule_rejects_unspecified_ip_literals() {
        for rule in ["0.0.0.0", "::", "::ffff:0.0.0.0"] {
            let err = compile_host_rule(rule).expect_err("unspecified IP should fail");

            assert!(err.contains("invalid host rule"), "unexpected error: {err}");
        }
    }

    #[test]
    fn compile_host_rule_accepts_loopback_ip_literals() {
        for rule in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            assert!(host_matches_rule(rule, rule));
        }
    }

    #[test]
    fn compile_host_rule_rejects_multicast_and_broadcast_ip_literals() {
        for rule in [
            "224.0.0.1",
            "255.255.255.255",
            "ff02::1",
            "::ffff:224.0.0.1",
        ] {
            let err = compile_host_rule(rule).expect_err("special IP should fail");

            assert!(err.contains("invalid host rule"), "unexpected error: {err}");
        }
    }

    #[test]
    fn compile_host_rule_rejects_special_cidrs() {
        for rule in ["224.0.0.0/4", "255.255.255.255/32", "ff00::/8", "::/0"] {
            let err = compile_host_rule(rule).expect_err("special CIDR should fail");

            assert!(err.contains("invalid host CIDR"), "unexpected error: {err}");
        }
    }

    #[test]
    fn retain_usable_addresses_discards_unspecified_addresses() {
        let addresses = super::retain_usable_addresses(vec![
            "0.0.0.0".parse::<std::net::IpAddr>().expect("valid IPv4"),
            "127.0.0.1".parse::<std::net::IpAddr>().expect("valid IPv4"),
            "::".parse::<std::net::IpAddr>().expect("valid IPv6"),
            "::ffff:0.0.0.0"
                .parse::<std::net::IpAddr>()
                .expect("valid mapped IPv6"),
            "::1".parse::<std::net::IpAddr>().expect("valid IPv6"),
            "224.0.0.1".parse::<std::net::IpAddr>().expect("valid IPv4"),
            "255.255.255.255"
                .parse::<std::net::IpAddr>()
                .expect("valid IPv4"),
            "ff02::1".parse::<std::net::IpAddr>().expect("valid IPv6"),
            "::ffff:224.0.0.1"
                .parse::<std::net::IpAddr>()
                .expect("valid mapped multicast IPv6"),
            "::ffff:255.255.255.255"
                .parse::<std::net::IpAddr>()
                .expect("valid mapped broadcast IPv6"),
        ]);

        assert_eq!(
            addresses,
            vec![
                "127.0.0.1".parse::<std::net::IpAddr>().expect("valid IPv4"),
                "::1".parse::<std::net::IpAddr>().expect("valid IPv6"),
            ]
        );
    }

    #[test]
    fn shared_allow_logic_matches_compiled_rules() {
        let whitelist = compile_host_rules(&["10.0.0.0/8".to_string()]).expect("compile rules");
        let blacklist = compile_host_rules(&["192.168.0.0/16".to_string()]).expect("compile rules");

        assert!(is_host_allowed_with_rules("10.1.2.3", &whitelist, &[]));
        assert!(!is_host_allowed_with_rules("192.168.1.2", &[], &blacklist));
        assert!(is_host_allowed_with_rules("127.0.0.1", &[], &blacklist));
    }

    #[test]
    fn matching_rejects_unicode_whitespace_padding() {
        assert!(!host_matches_rule(" 10.1.2.3\u{00a0}", "10.1.2.3"));
    }

    #[test]
    fn matching_rejects_c1_control_padding() {
        assert!(!host_matches_rule(" 10.1.2.3\u{009f}", "10.1.2.3"));
    }
}
