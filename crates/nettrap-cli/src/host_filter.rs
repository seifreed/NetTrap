use std::net::{IpAddr, ToSocketAddrs};

use ipnet::IpNet;

pub(crate) fn is_loopback_host(host: &str) -> bool {
    host == "127.0.0.1"
        || host == "::1"
        || host.starts_with("127.")
        || host.starts_with("::ffff:127.")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostRule {
    ExactIp(IpAddr),
    Cidr(IpNet),
    Hostname {
        hostname: String,
        addresses: Vec<IpAddr>,
    },
    NeverMatch,
}

impl HostRule {
    pub(crate) fn matches(&self, host: &str) -> bool {
        let host = host.trim();

        match self {
            Self::ExactIp(expected) => host.parse::<IpAddr>() == Ok(*expected),
            Self::Cidr(cidr) => host.parse::<IpAddr>().is_ok_and(|ip| cidr.contains(&ip)),
            Self::Hostname {
                hostname,
                addresses,
            } => {
                if host.eq_ignore_ascii_case(hostname) {
                    return true;
                }

                host.parse::<IpAddr>()
                    .is_ok_and(|ip| addresses.contains(&ip))
            }
            Self::NeverMatch => false,
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
    if is_loopback_host(host) {
        return true;
    }

    if !whitelist.is_empty() {
        return whitelist.iter().any(|rule| rule.matches(host));
    }

    if !blacklist.is_empty() {
        return !blacklist.iter().any(|rule| rule.matches(host));
    }

    true
}

pub(crate) fn resolve_hostname(hostname: &str) -> Result<Vec<IpAddr>, String> {
    let mut addresses: Vec<IpAddr> = (hostname, 0)
        .to_socket_addrs()
        .map_err(|err| format!("failed to resolve host filter '{}': {}", hostname, err))?
        .map(|addr| addr.ip())
        .collect();

    if addresses.is_empty() {
        return Err(format!(
            "failed to resolve host filter '{}': no IP addresses found",
            hostname
        ));
    }

    addresses.sort();
    addresses.dedup();
    Ok(addresses)
}

pub(crate) fn compile_host_rule(rule: &str) -> Result<HostRule, String> {
    let rule = rule.trim();

    if rule.is_empty() {
        return Ok(HostRule::NeverMatch);
    }

    if rule.contains('/') {
        return rule
            .parse::<IpNet>()
            .map(HostRule::Cidr)
            .map_err(|err| format!("invalid host CIDR '{}': {}", rule, err));
    }

    if let Ok(ip) = rule.parse::<IpAddr>() {
        return Ok(HostRule::ExactIp(ip));
    }

    resolve_hostname(rule).map(|addresses| HostRule::Hostname {
        hostname: rule.to_string(),
        addresses,
    })
}

#[cfg(test)]
pub(crate) fn host_matches_rule(host: &str, rule: &str) -> bool {
    compile_host_rule(rule).is_ok_and(|compiled| compiled.matches(host))
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
    fn matches_exact_hosts_and_cidrs() {
        assert!(host_matches_rule("10.1.2.3", "10.0.0.0/8"));
        assert!(!host_matches_rule("192.168.1.10", "10.0.0.0/8"));
        assert!(host_matches_rule("10.1.2.3", "10.1.2.3"));
        assert!(!host_matches_rule("10.1.2.4", "10.1.2.3"));
        assert!(!host_matches_rule("10.1.2.3", "10.0.0.0/not-a-prefix"));
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
    fn compile_host_rule_rejects_unresolvable_hostnames() {
        let err = compile_host_rule("definitely-not-a-real-nettrap-host.invalid")
            .expect_err("invalid hostname should fail");

        assert!(err.contains("failed to resolve host filter"));
    }

    #[test]
    fn shared_allow_logic_matches_compiled_rules() {
        let whitelist = compile_host_rules(&["10.0.0.0/8".to_string()]).expect("compile rules");
        let blacklist = compile_host_rules(&["192.168.0.0/16".to_string()]).expect("compile rules");

        assert!(is_host_allowed_with_rules("10.1.2.3", &whitelist, &[]));
        assert!(!is_host_allowed_with_rules("192.168.1.2", &[], &blacklist));
        assert!(is_host_allowed_with_rules("127.0.0.1", &[], &blacklist));
    }
}
