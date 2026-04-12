use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum RulePriority {
    Critical = 0,
    High = 100,
    Medium = 500,
    Low = 900,
    #[default]
    Default = 1000,
}

impl Ord for RulePriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as u32).cmp(&(*other as u32))
    }
}

impl PartialOrd for RulePriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    pub decision: PolicyDecision,
    pub priority: RulePriority,
    pub enabled: bool,
    pub matchers: Vec<RuleMatcher>,
}

impl PolicyRule {
    pub fn new(id: impl Into<String>, name: impl Into<String>, decision: PolicyDecision) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            decision,
            priority: RulePriority::Default,
            enabled: true,
            matchers: Vec::new(),
        }
    }

    pub fn intercept() -> Self {
        Self::new(
            uuid::Uuid::new_v4().to_string(),
            "intercept",
            PolicyDecision::Intercept,
        )
    }

    pub fn block() -> Self {
        Self::new(
            uuid::Uuid::new_v4().to_string(),
            "block",
            PolicyDecision::Block,
        )
    }

    pub fn passthrough() -> Self {
        Self::new(
            uuid::Uuid::new_v4().to_string(),
            "passthrough",
            PolicyDecision::Passthrough,
        )
    }

    pub fn emulate() -> Self {
        Self::new(
            uuid::Uuid::new_v4().to_string(),
            "emulate",
            PolicyDecision::Emulate,
        )
    }

    pub fn with_priority(mut self, priority: RulePriority) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_matcher(mut self, matcher: RuleMatcher) -> Self {
        self.matchers.push(matcher);
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.matchers.push(RuleMatcher::Port(port));
        self
    }

    pub fn with_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        for port in ports {
            self.matchers.push(RuleMatcher::Port(port));
        }
        self
    }

    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.matchers.push(RuleMatcher::Protocol(protocol));
        self
    }

    pub fn with_src_ip(mut self, ip: &str) -> Self {
        match ip.parse::<ipnet::IpNet>() {
            Ok(cidr) => self.matchers.push(RuleMatcher::SrcIp(cidr)),
            Err(e) => tracing::warn!("Invalid src_ip '{}' in policy rule, ignoring: {}", ip, e),
        }
        self
    }

    pub fn with_dst_ip(mut self, ip: &str) -> Self {
        match ip.parse::<ipnet::IpNet>() {
            Ok(cidr) => self.matchers.push(RuleMatcher::DstIp(cidr)),
            Err(e) => tracing::warn!("Invalid dst_ip '{}' in policy rule, ignoring: {}", ip, e),
        }
        self
    }

    pub fn with_process_name(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        match Regex::new(&format!("^{}$", regex::escape(&name))) {
            Ok(re) => self.matchers.push(RuleMatcher::ProcessName(re)),
            Err(e) => tracing::warn!(
                "Invalid process_name pattern '{}' in policy rule: {}",
                name,
                e
            ),
        }
        self
    }

    pub fn with_process_name_regex(mut self, pattern: &str) -> Self {
        match Regex::new(pattern) {
            Ok(re) => self.matchers.push(RuleMatcher::ProcessName(re)),
            Err(e) => tracing::warn!(
                "Invalid process_name_regex '{}' in policy rule: {}",
                pattern,
                e
            ),
        }
        self
    }

    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }

    pub fn enable(mut self) -> Self {
        self.enabled = true;
        self
    }

    pub fn matches(&self, ctx: &PolicyContext) -> bool {
        if !self.enabled {
            return false;
        }

        if self.matchers.is_empty() {
            return true;
        }

        self.matchers.iter().all(|m| m.matches(ctx))
    }
}

#[derive(Debug, Clone)]
pub enum RuleMatcher {
    Port(u16),
    Ports(Vec<u16>),
    Protocol(Protocol),
    SrcIp(ipnet::IpNet),
    DstIp(ipnet::IpNet),
    SrcIpList(Vec<ipnet::IpNet>),
    DstIpList(Vec<ipnet::IpNet>),
    ProcessId(u32),
    ProcessName(Regex),
    ProcessNameList(Vec<String>),
    ProcessPath(Regex),
    User(String),
    Any,
    All,
}

impl RuleMatcher {
    pub fn matches(&self, ctx: &PolicyContext) -> bool {
        match self {
            RuleMatcher::Port(port) => ctx.flow.five_tuple.dst_port == *port,
            RuleMatcher::Ports(ports) => ports.contains(&ctx.flow.five_tuple.dst_port),
            RuleMatcher::Protocol(proto) => ctx.flow.five_tuple.protocol == *proto,
            RuleMatcher::SrcIp(cidr) => cidr.contains(&ctx.flow.five_tuple.src_ip),
            RuleMatcher::DstIp(cidr) => cidr.contains(&ctx.flow.five_tuple.dst_ip),
            RuleMatcher::SrcIpList(cidrs) => cidrs
                .iter()
                .any(|c| c.contains(&ctx.flow.five_tuple.src_ip)),
            RuleMatcher::DstIpList(cidrs) => cidrs
                .iter()
                .any(|c| c.contains(&ctx.flow.five_tuple.dst_ip)),
            RuleMatcher::ProcessId(pid) => ctx
                .flow
                .metadata
                .process
                .as_ref()
                .map(|p| p.pid == *pid)
                .unwrap_or(false),
            RuleMatcher::ProcessName(re) => ctx
                .flow
                .metadata
                .process
                .as_ref()
                .map(|p| re.is_match(&p.name))
                .unwrap_or(false),
            RuleMatcher::ProcessNameList(names) => ctx
                .flow
                .metadata
                .process
                .as_ref()
                .map(|p| names.iter().any(|n| n == &p.name))
                .unwrap_or(false),
            RuleMatcher::ProcessPath(re) => ctx
                .flow
                .metadata
                .process
                .as_ref()
                .and_then(|p| p.path.as_ref())
                .map(|path| re.is_match(path))
                .unwrap_or(false),
            RuleMatcher::User(user) => ctx
                .flow
                .metadata
                .process
                .as_ref()
                .and_then(|p| p.user.as_ref())
                .map(|u| u == user)
                .unwrap_or(false),
            RuleMatcher::Any => true,
            RuleMatcher::All => true,
        }
    }

    pub fn port(port: u16) -> Self {
        RuleMatcher::Port(port)
    }

    pub fn protocol(proto: Protocol) -> Self {
        RuleMatcher::Protocol(proto)
    }

    pub fn src_ip(cidr: &str) -> Self {
        if let Ok(net) = cidr.parse() {
            RuleMatcher::SrcIp(net)
        } else {
            RuleMatcher::Any
        }
    }

    pub fn dst_ip(cidr: &str) -> Self {
        if let Ok(net) = cidr.parse() {
            RuleMatcher::DstIp(net)
        } else {
            RuleMatcher::Any
        }
    }
}

pub fn intercept_dns() -> PolicyRule {
    PolicyRule::intercept()
        .with_port(53)
        .with_protocol(Protocol::Udp)
}

pub fn intercept_http() -> PolicyRule {
    PolicyRule::intercept()
        .with_port(80)
        .with_protocol(Protocol::Tcp)
}

pub fn intercept_https() -> PolicyRule {
    PolicyRule::intercept()
        .with_port(443)
        .with_protocol(Protocol::Tcp)
}

pub fn block_ip(ip: &str) -> PolicyRule {
    PolicyRule::block().with_dst_ip(ip)
}

pub fn passthrough_localhost() -> PolicyRule {
    let mut rule = PolicyRule::passthrough().with_priority(RulePriority::High);
    rule.matchers.push(RuleMatcher::DstIpList(vec![
        "127.0.0.0/8".parse().expect("valid CIDR"),
        "::1/128".parse().expect("valid CIDR"),
    ]));
    rule
}
