use std::process::Command;
use std::sync::Arc;
use async_trait::async_trait;
use parking_lot::RwLock;

use crate::intercept::{Interceptor, InterceptorConfig, InterceptStats};
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
    listener_ports: Vec<(u16, bool)>, // (port, is_tcp)
    flush_on_start: bool,
    saved_rules: RwLock<Option<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NetworkMode {
    SingleHost,
    MultiHost,
}

#[derive(Debug, Clone)]
struct IptablesRule {
    table: String,
    chain: String,
    rule_args: Vec<String>,
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
            listener_ports: Vec::new(),
            flush_on_start: false,
            saved_rules: RwLock::new(None),
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
        self.listener_ports = ports;
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
                stdin.write_all(rules.as_bytes())
                    .map_err(|e| Error::Interception(format!("iptables-restore write failed: {}", e)))?;
            }

            child.wait()
                .map_err(|e| Error::Interception(format!("iptables-restore wait failed: {}", e)))?;

            tracing::info!("Restored iptables rules");
        }
        Ok(())
    }

    /// Install iptables redirect rules for all listener ports
    fn install_redirect_rules(&self) -> Result<()> {
        let mut installed = Vec::new();

        for &(port, is_tcp) in &self.listener_ports {
            let proto = if is_tcp { "tcp" } else { "udp" };

            match self.mode {
                NetworkMode::SingleHost => {
                    // OUTPUT chain: redirect local outbound to localhost
                    let mut args = vec![
                        "-t".to_string(), "nat".to_string(),
                        "-A".to_string(), "OUTPUT".to_string(),
                        "-p".to_string(), proto.to_string(),
                        "--dport".to_string(), port.to_string(),
                    ];

                    // Don't redirect loopback
                    args.extend_from_slice(&[
                        "!".to_string(), "-d".to_string(), "127.0.0.0/8".to_string(),
                    ]);

                    args.extend_from_slice(&[
                        "-j".to_string(), "REDIRECT".to_string(),
                        "--to-port".to_string(), port.to_string(),
                    ]);

                    self.run_iptables(&args)?;
                    installed.push(IptablesRule {
                        table: "nat".to_string(),
                        chain: "OUTPUT".to_string(),
                        rule_args: args,
                    });
                }
                NetworkMode::MultiHost => {
                    // PREROUTING chain: redirect incoming traffic from external hosts
                    let mut args = vec![
                        "-t".to_string(), "nat".to_string(),
                        "-A".to_string(), "PREROUTING".to_string(),
                        "-p".to_string(), proto.to_string(),
                        "--dport".to_string(), port.to_string(),
                    ];

                    // Don't redirect loopback traffic
                    args.extend_from_slice(&[
                        "!".to_string(), "-d".to_string(), "127.0.0.0/8".to_string(),
                    ]);

                    if let Some(ref iface) = self.interface {
                        args.extend_from_slice(&[
                            "-i".to_string(), iface.clone(),
                        ]);
                    }

                    args.extend_from_slice(&[
                        "-j".to_string(), "REDIRECT".to_string(),
                        "--to-port".to_string(), port.to_string(),
                    ]);

                    self.run_iptables(&args)?;
                    installed.push(IptablesRule {
                        table: "nat".to_string(),
                        chain: "PREROUTING".to_string(),
                        rule_args: args,
                    });
                }
            }

            tracing::debug!("Installed iptables REDIRECT rule for {} port {}", proto, port);
        }

        // Enable IP forwarding for MultiHost mode
        if self.mode == NetworkMode::MultiHost {
            let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");
            tracing::info!("Enabled IPv4 forwarding for MultiHost mode");
        }

        *self.rules_installed.write() = installed;
        Ok(())
    }

    /// Remove all installed iptables rules
    fn remove_redirect_rules(&self) -> Result<()> {
        let rules = self.rules_installed.read().clone();

        for rule in &rules {
            // Replace -A with -D to delete
            let delete_args: Vec<String> = rule.rule_args.iter()
                .map(|a| if a == "-A" { "-D".to_string() } else { a.clone() })
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
            self.rules_installed.read().len()
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

        // Disable IP forwarding if we enabled it
        if self.mode == NetworkMode::MultiHost {
            let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "0");
            tracing::info!("Disabled IPv4 forwarding");
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
