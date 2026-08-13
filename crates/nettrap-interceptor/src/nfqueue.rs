use async_trait::async_trait;
use parking_lot::RwLock;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::intercept::{Interceptor, InterceptorConfig};
use crate::prelude::*;

/// Linux NFQUEUE-based interceptor using iptables for traffic redirection.
///
/// In SingleHost mode: installs OUTPUT chain rules to redirect local traffic
/// In MultiHost mode: installs PREROUTING chain rules for gateway operation
///
/// Requires root privileges and iptables.
pub struct NfqueueInterceptor {
    queue_num: u16,
    running: Arc<RwLock<bool>>,
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
const MAX_FORWARDING_STATE_BYTES: u64 = 64;
const MAX_SAVED_RULES_BYTES: usize = 4 * 1024 * 1024;
const MAX_COMMAND_ERROR_BYTES: usize = 64 * 1024;
const MAX_COMMAND_LABEL_CHARS: usize = 512;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

struct LimitedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
enum LimitedCommandStream {
    Content(Vec<u8>),
    TooLarge,
}

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
    pub fn new(_config: InterceptorConfig) -> Result<Self> {
        Ok(Self {
            queue_num: 0,
            running: Arc::new(RwLock::new(false)),
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

    pub fn with_mode(mut self, mode: NetworkMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_interface(mut self, iface: impl Into<String>) -> Self {
        self.interface = Some(iface.into());
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

    /// Save current iptables rules for restoration on shutdown
    fn save_iptables_rules(&self) -> Result<()> {
        *self.saved_ipv4_rules.write() = Some(Self::save_rules(IpFamily::V4)?);
        *self.saved_ipv6_rules.write() = Some(Self::save_rules(IpFamily::V6)?);
        Ok(())
    }

    /// Restore saved iptables rules
    fn restore_iptables_rules(&self) -> Result<()> {
        self.restore_iptables_rules_with(Self::restore_rules)
    }

    fn restore_iptables_rules_with<F>(&self, mut restore: F) -> Result<()>
    where
        F: FnMut(IpFamily, &str) -> Result<()>,
    {
        let mut errors = Vec::new();

        if let Some(ref rules) = *self.saved_ipv4_rules.read()
            && let Err(err) = restore(IpFamily::V4, rules)
        {
            errors.push(format!("{}: {}", IpFamily::V4.restore_command(), err));
        }
        if let Some(ref rules) = *self.saved_ipv6_rules.read()
            && let Err(err) = restore(IpFamily::V6, rules)
        {
            errors.push(format!("{}: {}", IpFamily::V6.restore_command(), err));
        }

        if !errors.is_empty() {
            return Err(Error::Interception(format!(
                "failed to restore saved iptables rules: {}",
                errors.join("; ")
            )));
        }

        Ok(())
    }

    fn save_rules(family: IpFamily) -> Result<String> {
        let output = run_command_with_limited_output(
            Command::new(family.save_command()),
            family.save_command(),
            MAX_SAVED_RULES_BYTES,
            MAX_COMMAND_ERROR_BYTES,
        )?;

        if !output.status.success() {
            return Err(Error::Interception(format!(
                "{} failed: {}",
                family.save_command(),
                render_command_output(&output.stderr)
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

        let status = wait_for_command(&mut child, family.restore_command(), COMMAND_TIMEOUT)?;
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
        {
            let mut installed = self.rules_installed.write();
            installed.clear();

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
        }

        if self.mode == NetworkMode::MultiHost {
            self.enable_multihost_forwarding()?;
        }

        Ok(())
    }

    fn enable_multihost_forwarding(&self) -> Result<()> {
        Self::enable_forwarding(IPV4_FORWARD_PATH, &self.saved_ipv4_forward, "IPv4")?;

        if let Err(err) =
            Self::enable_forwarding(IPV6_FORWARD_PATH, &self.saved_ipv6_forward, "IPv6")
        {
            if let Err(restore_err) = Self::restore_forwarding(
                Path::new(IPV4_FORWARD_PATH),
                self.saved_ipv4_forward.read().clone(),
                "IPv4",
            ) {
                return Err(Error::Interception(format!(
                    "{}; rollback failed: {}",
                    err, restore_err
                )));
            }
            return Err(err);
        }

        Ok(())
    }

    fn enable_forwarding(path: &str, saved: &RwLock<Option<String>>, label: &str) -> Result<()> {
        let file = std::fs::File::open(path).map_err(|e| {
            Error::Interception(format!("failed to read {} forwarding state: {}", label, e))
        })?;
        let mut original = String::new();
        file.take(MAX_FORWARDING_STATE_BYTES + 1)
            .read_to_string(&mut original)
            .map_err(|e| {
                Error::Interception(format!("failed to read {} forwarding state: {}", label, e))
            })?;
        if original.len() as u64 > MAX_FORWARDING_STATE_BYTES {
            return Err(Error::Interception(format!(
                "{} forwarding state exceeds {} bytes",
                label, MAX_FORWARDING_STATE_BYTES
            )));
        }
        *saved.write() = Some(original);

        std::fs::write(path, "1").map_err(|e| {
            Error::Interception(format!(
                "failed to enable {} forwarding for MultiHost mode: {}",
                label, e
            ))
        })?;

        tracing::info!("Enabled {} forwarding for MultiHost mode", label);
        Ok(())
    }

    /// Remove all installed iptables rules
    fn remove_redirect_rules(&self) -> Result<()> {
        self.remove_redirect_rules_with(|command, args| self.run_iptables(command, args))
    }

    fn remove_redirect_rules_with<F>(&self, mut delete_rule: F) -> Result<()>
    where
        F: FnMut(&str, &[String]) -> Result<()>,
    {
        let rules = self.rules_installed.read().clone();
        let mut errors = Vec::new();

        for rule in &rules {
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

            if let Err(err) = delete_rule(rule.command, &delete_args) {
                tracing::warn!("Failed to remove {} rule: {}", rule.command, err);
                errors.push(format!("{}: {}", rule.command, err));
            }
        }

        self.rules_installed.write().clear();
        tracing::info!("Removed {} iptables rules", rules.len());
        if errors.is_empty() {
            return Ok(());
        }

        Err(Error::Interception(format!(
            "failed to remove iptables rules: {}",
            errors.join("; ")
        )))
    }

    fn run_iptables(&self, command: &str, args: &[String]) -> Result<()> {
        let mut process = Command::new(command);
        process.args(args);
        let label = command_invocation_label(command, args);
        let output = run_command_with_limited_output(
            process,
            &label,
            MAX_COMMAND_ERROR_BYTES,
            MAX_COMMAND_ERROR_BYTES,
        )?;

        if !output.status.success() {
            return Err(Error::Interception(format!(
                "{} failed: {}",
                label,
                render_command_output(&output.stderr)
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

fn run_command_with_limited_output(
    mut command: Command,
    label: &str,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<LimitedCommandOutput> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Interception(format!("{label} failed: {e}")))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::InvalidState(format!("{label} stdout pipe was not available")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Error::InvalidState(format!("{label} stderr pipe was not available")))?;

    let stdout_reader =
        std::thread::spawn(move || read_limited_command_stream(stdout, stdout_limit));
    let stderr_reader =
        std::thread::spawn(move || read_limited_command_stream(stderr, stderr_limit));
    let status = wait_for_command(&mut child, label, COMMAND_TIMEOUT)?;

    let stdout = join_limited_reader(stdout_reader, label, "stdout")?;
    let stderr = join_limited_reader(stderr_reader, label, "stderr")?;

    let stdout = match stdout {
        LimitedCommandStream::Content(stdout) => stdout,
        LimitedCommandStream::TooLarge => {
            return Err(Error::Interception(format!(
                "{label} stdout exceeded {stdout_limit} byte limit"
            )));
        }
    };
    let stderr = match stderr {
        LimitedCommandStream::Content(stderr) => stderr,
        LimitedCommandStream::TooLarge => {
            return Err(Error::Interception(format!(
                "{label} stderr exceeded {stderr_limit} byte limit"
            )));
        }
    };

    Ok(LimitedCommandOutput {
        status,
        stdout,
        stderr,
    })
}

fn wait_for_command(child: &mut Child, label: &str, timeout: Duration) -> Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child
            .try_wait()
            .map_err(|e| Error::Interception(format!("{label} wait failed: {e}")))?
        {
            Some(status) => return Ok(status),
            None if Instant::now() >= deadline => {
                child.kill().map_err(|e| {
                    Error::Interception(format!("{label} timeout kill failed: {e}"))
                })?;
                child.wait().map_err(|e| {
                    Error::Interception(format!("{label} timeout cleanup wait failed: {e}"))
                })?;
                return Err(Error::Timeout(format!(
                    "{label} exceeded {} seconds",
                    timeout.as_secs()
                )));
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn join_limited_reader(
    handle: std::thread::JoinHandle<io::Result<LimitedCommandStream>>,
    label: &str,
    stream_name: &str,
) -> Result<LimitedCommandStream> {
    handle
        .join()
        .map_err(|_| Error::Interception(format!("{label} {stream_name} reader panicked")))?
        .map_err(|e| Error::Interception(format!("{label} {stream_name} read failed: {e}")))
}

fn command_invocation_label(command: &str, args: &[String]) -> String {
    let joined = std::iter::once(command)
        .chain(args.iter().map(String::as_str))
        .flat_map(|part| part.chars().chain(std::iter::once(' ')))
        .filter(|ch| !ch.is_control())
        .take(MAX_COMMAND_LABEL_CHARS)
        .collect::<String>();
    joined.trim_end().to_string()
}

fn render_command_output(output: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(output) {
        return nettrap_core::sanitize::single_line(text);
    }

    nettrap_core::sanitize::single_line_bytes(output)
}

fn read_limited_command_stream<R: Read>(
    reader: R,
    max_bytes: usize,
) -> io::Result<LimitedCommandStream> {
    let max_bytes_u64 = u64::try_from(max_bytes)
        .map_err(|_| io::Error::other("NFQUEUE command output limit exceeds u64 range"))?;
    let _limit = max_bytes_u64
        .checked_add(1)
        .ok_or_else(|| io::Error::other("NFQUEUE command output limit sentinel overflowed"))?;
    let mut content = Vec::new();
    let mut reader = reader;
    let mut buffer = [0u8; 8192];
    let mut too_large = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let previous_len = content.len();
        if content.len() < max_bytes {
            let retained = (max_bytes - content.len()).min(read);
            content.extend_from_slice(&buffer[..retained]);
        }
        if previous_len.saturating_add(read) > max_bytes {
            too_large = true;
        }
    }
    if too_large {
        return Ok(LimitedCommandStream::TooLarge);
    }
    Ok(LimitedCommandStream::Content(content))
}

#[async_trait]
impl Interceptor for NfqueueInterceptor {
    async fn init(&mut self) -> Result<()> {
        tracing::info!(
            "Initializing NFQUEUE interceptor (mode={:?}, queue={})",
            self.mode,
            self.queue_num
        );

        if !nix::unistd::Uid::effective().is_root() {
            return Err(Error::PermissionDenied(
                "NFQUEUE interceptor requires root privileges".into(),
            ));
        }

        self.save_iptables_rules()?;

        if self.flush_on_start {
            self.flush_nat_rules()?;
        }

        if let Err(err) = self.install_redirect_rules() {
            let mut cleanup_errors = Vec::new();
            Self::run_shutdown_cleanup(
                || self.remove_redirect_rules(),
                || self.restore_iptables_rules(),
                || Ok(()),
                &mut cleanup_errors,
            );

            if cleanup_errors.is_empty() {
                return Err(err);
            }

            let mut message = err.to_string();
            message.push_str("; cleanup: ");
            message.push_str(&cleanup_errors.join("; "));
            return Err(Error::Interception(message));
        }

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
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        tracing::info!("Shutting down NFQUEUE interceptor");
        *self.running.write() = false;

        let mut cleanup_errors = Vec::new();
        Self::run_shutdown_cleanup(
            || self.remove_redirect_rules(),
            || self.restore_iptables_rules(),
            || {
                if self.mode == NetworkMode::MultiHost {
                    Self::restore_forwarding(
                        Path::new(IPV4_FORWARD_PATH),
                        self.saved_ipv4_forward.read().clone(),
                        "IPv4",
                    )?;
                    Self::restore_forwarding(
                        Path::new(IPV6_FORWARD_PATH),
                        self.saved_ipv6_forward.read().clone(),
                        "IPv6",
                    )?;
                }
                Ok(())
            },
            &mut cleanup_errors,
        );

        if cleanup_errors.is_empty() {
            tracing::info!("NFQUEUE interceptor shut down cleanly");
            return Ok(());
        }

        let message = cleanup_errors.join("; ");
        tracing::error!(
            "NFQUEUE interceptor shutdown completed with cleanup errors: {}",
            message
        );
        Err(Error::Interception(message))
    }

    fn name(&self) -> &'static str {
        "nfqueue"
    }

    fn is_running(&self) -> bool {
        *self.running.read()
    }
}

impl NfqueueInterceptor {
    fn run_shutdown_cleanup<Remove, Restore, Forward>(
        mut remove_redirect_rules: Remove,
        mut restore_iptables_rules: Restore,
        mut restore_forwarding: Forward,
        cleanup_errors: &mut Vec<String>,
    ) where
        Remove: FnMut() -> Result<()>,
        Restore: FnMut() -> Result<()>,
        Forward: FnMut() -> Result<()>,
    {
        if let Err(err) = remove_redirect_rules() {
            cleanup_errors.push(format!("redirect rule removal failed: {}", err));
        }

        if let Err(err) = restore_iptables_rules() {
            cleanup_errors.push(format!("iptables restore failed: {}", err));
        }

        if let Err(err) = restore_forwarding() {
            cleanup_errors.push(format!("forwarding restore failed: {}", err));
        }
    }

    fn restore_forwarding(path: &Path, original: Option<String>, label: &str) -> Result<()> {
        let Some(original) = original else {
            return Err(Error::InvalidState(format!(
                "missing saved {} forwarding state",
                label
            )));
        };

        std::fs::write(path, &original).map_err(|e| {
            Error::Interception(format!(
                "failed to restore {} forwarding to '{}': {}",
                label, original, e
            ))
        })?;

        tracing::info!("Restored {} forwarding to '{}'", label, original);
        Ok(())
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
    fn command_invocation_label_is_single_line_and_bounded() {
        let long_arg = "a".repeat(MAX_COMMAND_LABEL_CHARS + 128);
        let args = vec!["-A".to_string(), "bad\narg".to_string(), long_arg];

        let label = command_invocation_label("iptables\r", &args);

        assert!(!label.contains(['\r', '\n']));
        assert!(label.len() <= MAX_COMMAND_LABEL_CHARS);
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_command_kills_process_after_timeout() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 1"])
            .spawn()
            .expect("spawn sleeping command");

        let err = wait_for_command(&mut child, "test command", Duration::from_millis(10))
            .expect_err("sleeping command should time out");

        assert!(matches!(err, Error::Timeout(_)));
    }

    #[test]
    fn limited_command_stream_rejects_content_past_limit() {
        let input = std::io::Cursor::new(vec![b'x'; 5]);

        let result = read_limited_command_stream(input, 4).expect("limited read should finish");

        assert!(matches!(result, LimitedCommandStream::TooLarge));
    }

    #[test]
    fn limited_command_stream_accepts_content_at_limit() {
        let input = std::io::Cursor::new(vec![b'x'; 4]);

        let result = read_limited_command_stream(input, 4).expect("limited read should finish");

        assert!(matches!(result, LimitedCommandStream::Content(content) if content.len() == 4));
    }

    #[test]
    fn limited_command_stream_drains_content_past_limit() {
        let input = std::io::Cursor::new(vec![b'x'; 16 * 1024]);

        let result = read_limited_command_stream(input, 4).expect("limited read should finish");

        assert!(matches!(result, LimitedCommandStream::TooLarge));
    }

    #[test]
    fn limited_command_stream_rejects_unrepresentable_sentinel_limit() {
        let input = std::io::Cursor::new(Vec::<u8>::new());

        let err = read_limited_command_stream(input, usize::MAX)
            .expect_err("overflowing sentinel limit should fail");

        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(err.to_string().contains("sentinel overflowed"), "{err}");
    }

    #[test]
    fn render_command_output_preserves_non_utf8_bytes_as_hex() {
        assert_eq!(
            render_command_output(b"iptables error\n"),
            "iptables error "
        );
        assert_eq!(
            render_command_output(b" iptables error \n"),
            " iptables error  "
        );
        assert_eq!(
            render_command_output(&[0xff, b'e', b'r', b'r']),
            "hex:ff657272"
        );
    }

    #[test]
    fn render_command_output_bounds_non_utf8_hex_preview() {
        let mut output = vec![0xff; nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS];
        output.push(b'e');

        let rendered = render_command_output(&output);

        assert!(rendered.starts_with("hex:"));
        assert!(rendered.len() <= nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS);
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

    #[test]
    fn restore_iptables_rules_attempts_all_saved_families_before_failing() {
        let interceptor =
            NfqueueInterceptor::new(InterceptorConfig::default()).expect("interceptor builds");
        *interceptor.saved_ipv4_rules.write() = Some("ipv4 rules".to_string());
        *interceptor.saved_ipv6_rules.write() = Some("ipv6 rules".to_string());
        let mut attempted = Vec::new();

        let err = interceptor
            .restore_iptables_rules_with(|family, rules| {
                attempted.push((family, rules.to_string()));
                Err(Error::Interception(format!(
                    "{} restore failed",
                    family.restore_command()
                )))
            })
            .expect_err("restore failures should be reported");

        assert_eq!(
            attempted,
            vec![
                (IpFamily::V4, "ipv4 rules".to_string()),
                (IpFamily::V6, "ipv6 rules".to_string())
            ]
        );
        let message = err.to_string();
        assert!(message.contains("iptables-restore"));
        assert!(message.contains("ip6tables-restore"));
    }

    #[test]
    fn remove_redirect_rules_attempts_all_saved_rules_before_failing() {
        let interceptor =
            NfqueueInterceptor::new(InterceptorConfig::default()).expect("interceptor builds");
        *interceptor.rules_installed.write() = vec![
            IptablesRule {
                command: "iptables",
                rule_args: vec!["-A".to_string(), "INPUT".to_string()],
            },
            IptablesRule {
                command: "ip6tables",
                rule_args: vec!["-A".to_string(), "OUTPUT".to_string()],
            },
        ];
        let mut attempted = Vec::new();

        let err = interceptor
            .remove_redirect_rules_with(|command, args| {
                attempted.push((command.to_string(), args.to_vec()));
                Err(Error::Interception(format!("{} delete failed", command)))
            })
            .expect_err("rule deletion failures should be reported");

        assert_eq!(
            attempted,
            vec![
                (
                    "iptables".to_string(),
                    vec!["-D".to_string(), "INPUT".to_string()]
                ),
                (
                    "ip6tables".to_string(),
                    vec!["-D".to_string(), "OUTPUT".to_string()]
                )
            ]
        );
        let message = err.to_string();
        assert!(message.contains("iptables"));
        assert!(message.contains("ip6tables"));
    }

    #[test]
    fn restore_forwarding_without_original_state_returns_error() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-nfqueue-restore-forwarding-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock before UNIX_EPOCH")
                .as_nanos()
        ));
        let err = NfqueueInterceptor::restore_forwarding(&path, None, "IPv4")
            .expect_err("missing forwarding state should be reported");

        assert!(!path.exists());
        assert!(
            err.to_string()
                .contains("missing saved IPv4 forwarding state")
        );
    }

    #[test]
    fn enable_forwarding_reports_missing_source_state() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-nfqueue-enable-forwarding-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock before UNIX_EPOCH")
                .as_nanos()
        ));
        let saved = RwLock::new(None);

        let err = NfqueueInterceptor::enable_forwarding(
            path.to_str().expect("temp path should be utf-8"),
            &saved,
            "IPv4",
        )
        .expect_err("missing forwarding state should be reported");

        assert!(
            err.to_string()
                .contains("failed to read IPv4 forwarding state")
        );
        assert!(saved.read().is_none());
    }

    #[test]
    fn enable_forwarding_rejects_oversized_source_state() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-nfqueue-enable-forwarding-large-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock before UNIX_EPOCH")
                .as_nanos()
        ));
        let oversized = "1".repeat(MAX_FORWARDING_STATE_BYTES as usize + 1);
        std::fs::write(&path, &oversized).expect("write oversized forwarding state");
        let saved = RwLock::new(None);

        let err = NfqueueInterceptor::enable_forwarding(
            path.to_str().expect("temp path should be utf-8"),
            &saved,
            "IPv4",
        )
        .expect_err("oversized forwarding state should be rejected");

        assert!(err.to_string().contains("exceeds 64 bytes"));
        assert!(saved.read().is_none());
        assert_eq!(
            std::fs::read_to_string(&path).expect("read temp forwarding state"),
            oversized
        );
        std::fs::remove_file(path).expect("remove temp forwarding state");
    }

    #[test]
    fn shutdown_cleanup_continues_after_redirect_rule_failure() {
        let mut called_restore = false;
        let mut called_forwarding = false;
        let mut errors = Vec::new();

        NfqueueInterceptor::run_shutdown_cleanup(
            || Err(Error::Interception("remove failed".to_string())),
            || {
                called_restore = true;
                Ok(())
            },
            || {
                called_forwarding = true;
                Ok(())
            },
            &mut errors,
        );

        assert!(called_restore);
        assert!(called_forwarding);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("redirect rule removal failed"));
    }

    #[test]
    fn shutdown_cleanup_reports_forwarding_restore_failure() {
        let mut errors = Vec::new();

        NfqueueInterceptor::run_shutdown_cleanup(
            || Ok(()),
            || Ok(()),
            || Err(Error::Interception("forwarding restore failed".to_string())),
            &mut errors,
        );

        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("forwarding restore failed"));
    }
}
