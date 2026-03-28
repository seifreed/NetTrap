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
        self.port_matchers.push(PortMatcher::Range(start, end));
        self
    }

    pub fn dst_ip(mut self, ip: impl Into<String>) -> Self {
        let ip: std::net::IpAddr = ip.into().parse().unwrap();
        self.ip_matchers.push(IpMatcher::Exact(ip));
        self
    }

    pub fn dst_cidr(mut self, cidr: impl Into<String>) -> Self {
        let cidr: IpNet = cidr.into().parse().unwrap();
        self.ip_matchers.push(IpMatcher::Cidr(cidr));
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
        let re = regex::Regex::new(&format!("^{}$", name.into())).unwrap();
        self.process_matchers.push(ProcessMatcher::Name(re));
        self
    }

    pub fn matches(&self, flow: &Flow) -> bool {
        let port_matches = if self.port_matchers.is_empty() {
            true
        } else {
            self.port_matchers
                .iter()
                .any(|m| m.matches(flow.five_tuple.src_port) || m.matches(flow.five_tuple.dst_port))
        };

        let ip_matches = if self.ip_matchers.is_empty() {
            true
        } else {
            self.ip_matchers
                .iter()
                .any(|m| m.matches(&flow.five_tuple.src_ip) || m.matches(&flow.five_tuple.dst_ip))
        };

        let protocol_matches = if self.protocol_matchers.is_empty() {
            true
        } else {
            self.protocol_matchers
                .iter()
                .all(|m| m.matches(flow.five_tuple.protocol))
        };

        let process_matches = if self.process_matchers.is_empty() {
            true
        } else {
            self.process_matchers
                .iter()
                .all(|m| m.matches(flow.metadata.process.as_ref()))
        };

        port_matches && ip_matches && protocol_matches && process_matches
    }
}

impl Default for FlowMatcher {
    fn default() -> Self {
        Self::new()
    }
}
