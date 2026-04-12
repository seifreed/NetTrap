use ipnet::IpNet;
use regex::Regex;

use crate::prelude::*;

#[derive(Debug, Clone)]
pub struct FlowMatcher {
    port_matchers: Vec<PortMatcher>,
    ip_matchers: Vec<IpMatcher>,
    protocol_matchers: Vec<ProtocolMatcher>,
    process_matchers: Vec<ProcessMatcher>,
}

#[derive(Debug, Clone)]
pub enum PortMatcher {
    Exact(u16),
    Range(u16, u16),
    Any,
}

impl PortMatcher {
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortMatcher::Exact(p) => *p == port,
            PortMatcher::Range(start, end) => *start <= port && port <= *end,
            PortMatcher::Any => true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum IpMatcher {
    Exact(std::net::IpAddr),
    Cidr(IpNet),
    Range(std::net::IpAddr, std::net::IpAddr),
    Any,
}

impl IpMatcher {
    pub fn matches(&self, ip: &std::net::IpAddr) -> bool {
        match self {
            IpMatcher::Exact(i) => i == ip,
            IpMatcher::Cidr(net) => net.contains(ip),
            IpMatcher::Range(start, end) => ip >= start && ip <= end,
            IpMatcher::Any => true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProtocolMatcher {
    Exact(Protocol),
    Any,
}

impl ProtocolMatcher {
    pub fn matches(&self, protocol: Protocol) -> bool {
        match self {
            ProtocolMatcher::Exact(p) => *p == protocol,
            ProtocolMatcher::Any => true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProcessMatcher {
    Pid(u32),
    Name(Regex),
    Path(Regex),
    Any,
}

impl ProcessMatcher {
    pub fn matches(&self, process: Option<&ProcessInfo>) -> bool {
        match self {
            ProcessMatcher::Pid(pid) => process.map(|p| p.pid == *pid).unwrap_or(false),
            ProcessMatcher::Name(re) => process.map(|p| re.is_match(&p.name)).unwrap_or(false),
            ProcessMatcher::Path(re) => process
                .and_then(|p| p.path.as_ref())
                .map(|path| re.is_match(path))
                .unwrap_or(false),
            ProcessMatcher::Any => true,
        }
    }
}

impl FlowMatcher {
    pub fn new() -> Self {
        Self {
            port_matchers: Vec::new(),
            ip_matchers: Vec::new(),
            protocol_matchers: Vec::new(),
            process_matchers: Vec::new(),
        }
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port_matchers.push(PortMatcher::Exact(port));
        self
    }

    pub fn port_range(mut self, start: u16, end: u16) -> Self {
        let (lo, hi) = if start <= end {
            (start, end)
        } else {
            (end, start)
        };
        self.port_matchers.push(PortMatcher::Range(lo, hi));
        self
    }

    pub fn dst_ip(mut self, ip: impl Into<String>) -> Self {
        let ip_str = ip.into();
        match ip_str.parse::<std::net::IpAddr>() {
            Ok(addr) => self.ip_matchers.push(IpMatcher::Exact(addr)),
            Err(e) => tracing::warn!("Invalid dst_ip '{}' in matcher, ignoring: {}", ip_str, e),
        }
        self
    }

    pub fn dst_cidr(mut self, cidr: impl Into<String>) -> Self {
        let cidr_str = cidr.into();
        match cidr_str.parse::<IpNet>() {
            Ok(net) => self.ip_matchers.push(IpMatcher::Cidr(net)),
            Err(e) => tracing::warn!(
                "Invalid dst_cidr '{}' in matcher, ignoring: {}",
                cidr_str,
                e
            ),
        }
        self
    }

    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol_matchers
            .push(ProtocolMatcher::Exact(protocol));
        self
    }

    pub fn tcp(self) -> Self {
        self.protocol(Protocol::Tcp)
    }

    pub fn udp(self) -> Self {
        self.protocol(Protocol::Udp)
    }

    pub fn process_name(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        let pattern = format!("^{}$", regex::escape(&name));
        match regex::Regex::new(&pattern) {
            Ok(re) => self.process_matchers.push(ProcessMatcher::Name(re)),
            Err(error) => tracing::warn!(
                "Invalid process_name '{}' in matcher, ignoring: {}",
                name,
                error
            ),
        }
        self
    }

    pub fn matches(&self, flow: &Flow) -> bool {
        let port_matches = if self.port_matchers.is_empty() {
            true
        } else {
            self.port_matchers
                .iter()
                .any(|m| m.matches(flow.five_tuple.dst_port))
        };

        let ip_matches = if self.ip_matchers.is_empty() {
            true
        } else {
            self.ip_matchers
                .iter()
                .any(|m| m.matches(&flow.five_tuple.dst_ip))
        };

        let protocol_matches = if self.protocol_matchers.is_empty() {
            true
        } else {
            self.protocol_matchers
                .iter()
                .any(|m| m.matches(flow.five_tuple.protocol))
        };

        let process_matches = if self.process_matchers.is_empty() {
            true
        } else {
            self.process_matchers
                .iter()
                .any(|m| m.matches(flow.metadata.process.as_ref()))
        };

        port_matches && ip_matches && protocol_matches && process_matches
    }
}

impl Default for FlowMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn flow_with_process(name: &str) -> Flow {
        Flow::new(FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            53000,
            443,
            Protocol::Tcp,
        ))
        .with_process(ProcessInfo::new(4242, name))
    }

    #[test]
    fn process_name_matches_literal_name_with_regex_metacharacters() {
        let flow = flow_with_process("foo[1].exe");
        let matcher = FlowMatcher::new().process_name("foo[1].exe");

        assert!(matcher.matches(&flow));
    }

    #[test]
    fn process_name_does_not_treat_literal_name_as_regex() {
        let flow = flow_with_process("fooaexe");
        let matcher = FlowMatcher::new().process_name("foo.*exe");

        assert!(!matcher.matches(&flow));
    }
}
