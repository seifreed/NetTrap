use async_trait::async_trait;
use parking_lot::RwLock;
use std::process::Command;
use std::sync::Arc;

use crate::intercept::{InterceptStats, Interceptor, InterceptorConfig};
use crate::prelude::*;

/// Linux NFQUEUE-based interceptor using iptables for traffic redirection.
///
/// In SingleHost mode: installs OUTPUT chain rules to redirect local traffic
/// In MultiHost mode: installs PREROUTING chain rules for gateway operation
///
/// Requires root privileges and iptables.
pub struct NfqueueInterceptor {
    config: InterceptorConfig,
    queue_num: u16,
    running: Arc<RwLock<bool>>,
    stats: Arc<RwLock<InterceptStats>>,
    rules_installed: RwLock<Vec<IptablesRule>>,
    mode: NetworkMode,
    interface: Option<String>,
    redirect_rules: Vec<PortRedirect>,
    flush_on_start: bool,
    saved_ipv4_rules: RwLock<Option<String>>,
    saved_ipv6_rules: RwLock<Option<String>>,
    saved_ipv4_forward: RwLock<Option<String>>,
    saved_ipv6_forward: RwLock<Option<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NetworkMode {
    SingleHost,
    MultiHost,
}

#[derive(Debug, Clone)]
struct IptablesRule {
    command: &'static str,
    rule_args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRedirect {
    pub source_port: Option<u16>,
    pub target_port: u16,
    pub is_tcp: bool,
    pub exclude_uid: Option<u32>,
}

impl PortRedirect {
    pub fn new(source_port: u16, is_tcp: bool, target_port: u16) -> Self {
        Self {
            source_port: Some(source_port),
            target_port,
            is_tcp,
            exclude_uid: Some(nix::unistd::Uid::current().as_raw()),
        }
    }

    pub fn catch_all(is_tcp: bool, target_port: u16) -> Self {
        Self {
            source_port: None,
            target_port,
            is_tcp,
            exclude_uid: Some(nix::unistd::Uid::current().as_raw()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    fn command(self) -> &'static str {
        match self {
            Self::V4 => "iptables",
            Self::V6 => "ip6tables",
        }
    }

    fn save_command(self) -> &'static str {
        match self {
            Self::V4 => "iptables-save",
            Self::V6 => "ip6tables-save",
        }
    }

    fn restore_command(self) -> &'static str {
        match self {
            Self::V4 => "iptables-restore",
            Self::V6 => "ip6tables-restore",
        }
    }

    fn loopback_cidr(self) -> &'static str {
        match self {
            Self::V4 => "127.0.0.0/8",
            Self::V6 => "::1/128",
        }
    }
}

const IP_FAMILIES: [IpFamily; 2] = [IpFamily::V4, IpFamily::V6];
const IPV4_FORWARD_PATH: &str = "/proc/sys/net/ipv4/ip_forward";
const IPV6_FORWARD_PATH: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

fn build_redirect_rule_args(
    mode: NetworkMode,
    interface: Option<&str>,
    redirect: &PortRedirect,
    proto: &str,
    family: IpFamily,
) -> (&'static str, Vec<String>) {
    let chain = match mode {
        NetworkMode::SingleHost => "OUTPUT",
        NetworkMode::MultiHost => "PREROUTING",
    };
    let mut args = vec![
        "-t".to_string(),
        "nat".to_string(),
        "-A".to_string(),
        chain.to_string(),
        "-p".to_string(),
        proto.to_string(),
    ];

    if let Some(source_port) = redirect.source_port {
        args.extend_from_slice(&["--dport".to_string(), source_port.to_string()]);
    }

    args.extend_from_slice(&[
        "!".to_string(),
        "-d".to_string(),
        family.loopback_cidr().to_string(),
    ]);

    if mode == NetworkMode::SingleHost {
        if let Some(uid) = redirect.exclude_uid {
            args.extend_from_slice(&[
                "-m".to_string(),
                "owner".to_string(),
                "!".to_string(),
                "--uid-owner".to_string(),
                uid.to_string(),
            ]);
        }
    } else if let Some(iface) = interface {
        args.extend_from_slice(&["-i".to_string(), iface.to_string()]);
    }

    args.extend_from_slice(&[
        "-j".to_string(),
        "REDIRECT".to_string(),
        "--to-port".to_string(),
        redirect.target_port.to_string(),
    ]);

    (chain, args)
}

impl NfqueueInterceptor {
    pub fn new(config: InterceptorConfig) -> Result<Self> {
        Ok(Self {
            config,
            queue_num: 0,
            running: Arc::new(RwLock::new(false)),
            stats: Arc::new(RwLock::new(InterceptStats::default())),
            rules_installed: RwLock::new(Vec::new()),
            mode: NetworkMode::SingleHost,
            interface: None,
            redirect_rules: Vec::new(),
            flush_on_start: false,
            saved_ipv4_rules: RwLock::new(None),
            saved_ipv6_rules: RwLock::new(None),
            saved_ipv4_forward: RwLock::new(None),
            saved_ipv6_forward: RwLock::new(None),
        })
    }

    pub fn with_queue_num(mut self, num: u16) -> Self {
        self.queue_num = num;
        self
    }

    pub fn with_mode(mut self, mode: NetworkMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_interface(mut self, iface: impl Into<String>) -> Self {
        self.interface = Some(iface.into());
        self
    }

    pub fn with_listener_ports(mut self, ports: Vec<(u16, bool)>) -> Self {
        self.redirect_rules = ports
            .into_iter()
            .map(|(port, is_tcp)| PortRedirect::new(port, is_tcp, port))
            .collect();
        self
    }

    pub fn with_port_redirects(mut self, redirects: Vec<PortRedirect>) -> Self {
        self.redirect_rules = redirects;
        self
    }

    pub fn with_flush_on_start(mut self, flush: bool) -> Self {
        self.flush_on_start = flush;
        self
    }

    pub fn queue_num(&self) -> u16 {
        self.queue_num
    }

    pub fn config(&self) -> &InterceptorConfig {
        &self.config
    }

    pub fn stats(&self) -> InterceptStats {
        self.stats.read().clone()
    }

    /// Save current iptables rules for restoration on shutdown
    fn save_iptables_rules(&self) -> Result<()> {
        *self.saved_ipv4_rules.write() = Some(Self::save_rules(IpFamily::V4)?);
        *self.saved_ipv6_rules.write() = Some(Self::save_rules(IpFamily::V6)?);
        Ok(())
    }

    /// Restore saved iptables rules
    fn restore_iptables_rules(&self) -> Result<()> {
        if let Some(ref rules) = *self.saved_ipv4_rules.read() {
            Self::restore_rules(IpFamily::V4, rules)?;
        }
        if let Some(ref rules) = *self.saved_ipv6_rules.read() {
            Self::restore_rules(IpFamily::V6, rules)?;
        }
        Ok(())
    }

    fn save_rules(family: IpFamily) -> Result<String> {
        let output = Command::new(family.save_command())
            .output()
            .map_err(|e| Error::Interception(format!("{} failed: {}", family.save_command(), e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Interception(format!(
                "{} failed: {}",
                family.save_command(),
                stderr.trim()
            )));
        }

        tracing::debug!(
            "Saved {} rules ({} bytes)",
            family.command(),
            output.stdout.len()
        );
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn restore_rules(family: IpFamily, rules: &str) -> Result<()> {
        let mut child = Command::new(family.restore_command())
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                Error::Interception(format!("{} failed: {}", family.restore_command(), e))
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(rules.as_bytes()).map_err(|e| {
                Error::Interception(format!("{} write failed: {}", family.restore_command(), e))
            })?;
        }

        let status = child.wait().map_err(|e| {
            Error::Interception(format!("{} wait failed: {}", family.restore_command(), e))
        })?;
        if !status.success() {
            return Err(Error::Interception(format!(
                "{} exited with status {}",
                family.restore_command(),
                status
            )));
        }

        tracing::info!("Restored {} rules", family.command());
        Ok(())
    }

    /// Install iptables redirect rules for all listener ports
    fn install_redirect_rules(&self) -> Result<()> {
        let mut installed = Vec::new();

        for redirect in &self.redirect_rules {
            let proto = if redirect.is_tcp { "tcp" } else { "udp" };
            for family in IP_FAMILIES {
                let (_chain, args) = build_redirect_rule_args(
                    self.mode,
                    self.interface.as_deref(),
                    redirect,
                    proto,
                    family,
                );

                self.run_iptables(family.command(), &args)?;
                installed.push(IptablesRule {
                    command: family.command(),
                    rule_args: args,
                });

                if let Some(source_port) = redirect.source_port {
                    tracing::debug!(
                        "Installed {} REDIRECT rule for {} port {} -> {}",
                        family.command(),
                        proto,
                        source_port,
                        redirect.target_port
                    );
                } else {
                    tracing::debug!(
                        "Installed catch-all {} REDIRECT rule for {} traffic -> {}",
                        family.command(),
                        proto,
                        redirect.target_port
                    );
                }
            }
        }

        // Enable IP forwarding for MultiHost mode, saving original state
        if self.mode == NetworkMode::MultiHost {
            Self::enable_forwarding(IPV4_FORWARD_PATH, &self.saved_ipv4_forward, "IPv4");
            Self::enable_forwarding(IPV6_FORWARD_PATH, &self.saved_ipv6_forward, "IPv6");
        }

        *self.rules_installed.write() = installed;
        Ok(())
    }

    fn enable_forwarding(path: &str, saved: &RwLock<Option<String>>, label: &str) {
        if let Ok(original) = std::fs::read_to_string(path) {
            *saved.write() = Some(original.trim().to_string());
        }
        if let Err(e) = std::fs::write(path, "1") {
            tracing::warn!(
                "Failed to enable {} forwarding for MultiHost mode: {}. Routing may not work.",
                label,
                e
            );
        } else {
            tracing::info!("Enabled {} forwarding for MultiHost mode", label);
        }
    }

    /// Remove all installed iptables rules
    fn remove_redirect_rules(&self) -> Result<()> {
        let rules = self.rules_installed.read().clone();

        for rule in &rules {
            // Replace -A with -D to delete
            let delete_args: Vec<String> = rule
                .rule_args
                .iter()
                .map(|a| {
                    if a == "-A" {
                        "-D".to_string()
                    } else {
                        a.clone()
                    }
                })
                .collect();

            if let Err(e) = self.run_iptables(rule.command, &delete_args) {
                tracing::warn!("Failed to remove {} rule: {}", rule.command, e);
            }
        }

        self.rules_installed.write().clear();
        tracing::info!("Removed {} iptables rules", rules.len());
        Ok(())
    }

    fn run_iptables(&self, command: &str, args: &[String]) -> Result<()> {
        let output = Command::new(command)
            .args(args)
            .output()
            .map_err(|e| Error::Interception(format!("{} failed: {}", command, e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Interception(format!(
                "{} {} failed: {}",
                command,
                args.join(" "),
                stderr.trim()
            )));
        }
        Ok(())
    }

    /// Flush iptables NAT table (optional, controlled by config)
    pub fn flush_nat_rules(&self) -> Result<()> {
        let args = ["-t".to_string(), "nat".to_string(), "-F".to_string()];
        for family in IP_FAMILIES {
            self.run_iptables(family.command(), &args)?;
        }
        tracing::info!("Flushed iptables/ip6tables NAT rules");
        Ok(())
    }
}

#[async_trait]
impl Interceptor for NfqueueInterceptor {
    async fn init(&mut self) -> Result<()> {
        tracing::info!(
            "Initializing NFQUEUE interceptor (mode={:?}, queue={})",
            self.mode,
            self.queue_num
        );

        // Check for root privileges
        if !nix::unistd::Uid::effective().is_root() {
            return Err(Error::PermissionDenied(
                "NFQUEUE interceptor requires root privileges".into(),
            ));
        }

        // Save current rules
        self.save_iptables_rules()?;

        // Flush NAT rules if configured
        if self.flush_on_start {
            self.flush_nat_rules()?;
        }

        // Install redirect rules
        self.install_redirect_rules()?;

        *self.running.write() = true;
        tracing::info!(
            "NFQUEUE interceptor initialized with {} redirect rules",
            self.redirect_rules.len()
        );

        Ok(())
    }

    async fn recv_packet(&self) -> Result<Packet> {
        // In redirect mode, packets arrive at our listeners directly.
        // This interceptor mainly manages iptables rules.
        // For actual packet capture, use the PCAP interceptor in parallel.
        // Block until shutdown is requested.
        loop {
            if !*self.running.read() {
                return Err(Error::Shutdown);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    async fn send_packet(&self, _packet: Packet) -> Result<()> {
        // Redirect mode: packets go through kernel stack normally
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        tracing::info!("Shutting down NFQUEUE interceptor");
        *self.running.write() = false;

        // Remove our iptables rules
        self.remove_redirect_rules()?;

        // Optionally restore saved rules
        let _ = self.restore_iptables_rules();

        // Restore original IP forwarding state
        if self.mode == NetworkMode::MultiHost {
            Self::restore_forwarding(
                IPV4_FORWARD_PATH,
                self.saved_ipv4_forward.read().clone(),
                "IPv4",
            );
            Self::restore_forwarding(
                IPV6_FORWARD_PATH,
                self.saved_ipv6_forward.read().clone(),
                "IPv6",
            );
        }

        tracing::info!("NFQUEUE interceptor shut down cleanly");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "nfqueue"
    }

    fn is_running(&self) -> bool {
        *self.running.read()
    }
}

impl NfqueueInterceptor {
    fn restore_forwarding(path: &str, original: Option<String>, label: &str) {
        let original = original.unwrap_or_else(|| "0".to_string());
        if let Err(e) = std::fs::write(path, &original) {
            tracing::error!(
                "CRITICAL: Failed to restore {} forwarding to '{}': {}. \
                 Manual intervention required: echo '{}' > {}",
                label,
                original,
                e,
                original,
                path,
            );
        } else {
            tracing::info!("Restored {} forwarding to '{}'", label, original);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains_args(args: &[String], needle: &[&str]) -> bool {
        args.windows(needle.len())
            .any(|window| window.iter().map(String::as_str).eq(needle.iter().copied()))
    }

    #[test]
    fn single_host_catch_all_excludes_current_uid() {
        let redirect = PortRedirect::catch_all(true, 8080);
        let (chain, args) = build_redirect_rule_args(
            NetworkMode::SingleHost,
            None,
            &redirect,
            "tcp",
            IpFamily::V4,
        );

        assert_eq!(chain, "OUTPUT");
        assert!(contains_args(&args, &["-m", "owner", "!", "--uid-owner"]));
        assert!(contains_args(&args, &["!", "-d", "127.0.0.0/8"]));
    }

    #[test]
    fn single_host_explicit_redirect_excludes_current_uid() {
        let redirect = PortRedirect::new(80, true, 8080);
        let (_chain, args) = build_redirect_rule_args(
            NetworkMode::SingleHost,
            None,
            &redirect,
            "tcp",
            IpFamily::V4,
        );

        assert!(contains_args(&args, &["-m", "owner", "!", "--uid-owner"]));
    }

    #[test]
    fn single_host_ipv6_redirect_excludes_loopback_and_current_uid() {
        let redirect = PortRedirect::new(443, true, 8443);
        let (chain, args) = build_redirect_rule_args(
            NetworkMode::SingleHost,
            None,
            &redirect,
            "tcp",
            IpFamily::V6,
        );

        assert_eq!(chain, "OUTPUT");
        assert!(contains_args(&args, &["!", "-d", "::1/128"]));
        assert!(contains_args(&args, &["-m", "owner", "!", "--uid-owner"]));
        assert_eq!(IpFamily::V6.command(), "ip6tables");
    }

    #[test]
    fn multihost_catch_all_does_not_use_owner_match() {
        let redirect = PortRedirect::catch_all(false, 5353);
        let (chain, args) = build_redirect_rule_args(
            NetworkMode::MultiHost,
            Some("eth0"),
            &redirect,
            "udp",
            IpFamily::V6,
        );

        assert_eq!(chain, "PREROUTING");
        assert!(!contains_args(&args, &["-m", "owner", "!", "--uid-owner"]));
        assert!(contains_args(&args, &["-i", "eth0"]));
        assert!(contains_args(&args, &["!", "-d", "::1/128"]));
    }
}
