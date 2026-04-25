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
    saved_rules: RwLock<Option<String>>,
    saved_ip_forward: RwLock<Option<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NetworkMode {
    SingleHost,
    MultiHost,
}

#[derive(Debug, Clone)]
struct IptablesRule {
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

fn build_redirect_rule_args(
    mode: NetworkMode,
    interface: Option<&str>,
    redirect: &PortRedirect,
    proto: &str,
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

    args.extend_from_slice(&["!".to_string(), "-d".to_string(), "127.0.0.0/8".to_string()]);

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
            saved_rules: RwLock::new(None),
            saved_ip_forward: RwLock::new(None),
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
        let output = Command::new("iptables-save")
            .output()
            .map_err(|e| Error::Interception(format!("iptables-save failed: {}", e)))?;

        if output.status.success() {
            let rules = String::from_utf8_lossy(&output.stdout).to_string();
            *self.saved_rules.write() = Some(rules);
            tracing::debug!("Saved iptables rules ({} bytes)", output.stdout.len());
        }
        Ok(())
    }

    /// Restore saved iptables rules
    fn restore_iptables_rules(&self) -> Result<()> {
        if let Some(ref rules) = *self.saved_rules.read() {
            let mut child = Command::new("iptables-restore")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| Error::Interception(format!("iptables-restore failed: {}", e)))?;

            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                stdin.write_all(rules.as_bytes()).map_err(|e| {
                    Error::Interception(format!("iptables-restore write failed: {}", e))
                })?;
            }

            child
                .wait()
                .map_err(|e| Error::Interception(format!("iptables-restore wait failed: {}", e)))?;

            tracing::info!("Restored iptables rules");
        }
        Ok(())
    }

    /// Install iptables redirect rules for all listener ports
    fn install_redirect_rules(&self) -> Result<()> {
        let mut installed = Vec::new();

        for redirect in &self.redirect_rules {
            let proto = if redirect.is_tcp { "tcp" } else { "udp" };
            let (_chain, args) =
                build_redirect_rule_args(self.mode, self.interface.as_deref(), redirect, proto);

            self.run_iptables(&args)?;
            installed.push(IptablesRule { rule_args: args });

            if let Some(source_port) = redirect.source_port {
                tracing::debug!(
                    "Installed iptables REDIRECT rule for {} port {} -> {}",
                    proto,
                    source_port,
                    redirect.target_port
                );
            } else {
                tracing::debug!(
                    "Installed catch-all iptables REDIRECT rule for {} traffic -> {}",
                    proto,
                    redirect.target_port
                );
            }
        }

        // Enable IP forwarding for MultiHost mode, saving original state
        if self.mode == NetworkMode::MultiHost {
            if let Ok(original) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
                *self.saved_ip_forward.write() = Some(original.trim().to_string());
            }
            if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1") {
                tracing::warn!(
                    "Failed to enable IP forwarding for MultiHost mode: {}. Routing may not work.",
                    e
                );
            } else {
                tracing::info!("Enabled IPv4 forwarding for MultiHost mode");
            }
        }

        *self.rules_installed.write() = installed;
        Ok(())
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

            if let Err(e) = self.run_iptables(&delete_args) {
                tracing::warn!("Failed to remove iptables rule: {}", e);
            }
        }

        self.rules_installed.write().clear();
        tracing::info!("Removed {} iptables rules", rules.len());
        Ok(())
    }

    fn run_iptables(&self, args: &[String]) -> Result<()> {
        let output = Command::new("iptables")
            .args(args)
            .output()
            .map_err(|e| Error::Interception(format!("iptables failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Interception(format!(
                "iptables {} failed: {}",
                args.join(" "),
                stderr.trim()
            )));
        }
        Ok(())
    }

    /// Flush iptables NAT table (optional, controlled by config)
    pub fn flush_nat_rules(&self) -> Result<()> {
        self.run_iptables(&["-t".to_string(), "nat".to_string(), "-F".to_string()])?;
        tracing::info!("Flushed iptables NAT rules");
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
            let original = self
                .saved_ip_forward
                .read()
                .clone()
                .unwrap_or_else(|| "0".to_string());
            if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", &original) {
                tracing::error!(
                    "CRITICAL: Failed to restore IPv4 forwarding to '{}': {}. \
                     Manual intervention required: echo '{}' > /proc/sys/net/ipv4/ip_forward",
                    original,
                    e,
                    original,
                );
            } else {
                tracing::info!("Restored IPv4 forwarding to '{}'", original);
            }
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
        let (chain, args) =
            build_redirect_rule_args(NetworkMode::SingleHost, None, &redirect, "tcp");

        assert_eq!(chain, "OUTPUT");
        assert!(contains_args(&args, &["-m", "owner", "!", "--uid-owner"]));
    }

    #[test]
    fn single_host_explicit_redirect_excludes_current_uid() {
        let redirect = PortRedirect::new(80, true, 8080);
        let (_chain, args) =
            build_redirect_rule_args(NetworkMode::SingleHost, None, &redirect, "tcp");

        assert!(contains_args(&args, &["-m", "owner", "!", "--uid-owner"]));
    }

    #[test]
    fn multihost_catch_all_does_not_use_owner_match() {
        let redirect = PortRedirect::catch_all(false, 5353);
        let (chain, args) =
            build_redirect_rule_args(NetworkMode::MultiHost, Some("eth0"), &redirect, "udp");

        assert_eq!(chain, "PREROUTING");
        assert!(!contains_args(&args, &["-m", "owner", "!", "--uid-owner"]));
        assert!(contains_args(&args, &["-i", "eth0"]));
    }
}
