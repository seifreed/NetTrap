//! Windows-specific network configuration utilities.
//! Only compiled on Windows.

#[cfg(any(test, target_os = "windows"))]
use nettrap_core::sanitize::command_output_preview as render_command_output;
#[cfg(any(test, target_os = "windows"))]
use sha1::{Digest, Sha1};
#[cfg(any(test, target_os = "windows"))]
use std::io::{self, Read};
use std::path::Path;
#[cfg(any(test, target_os = "windows"))]
use std::process::{Child, Command, ExitStatus, Stdio};
#[cfg(any(test, target_os = "windows"))]
use std::time::{Duration, Instant};
#[cfg(any(test, target_os = "windows"))]
use x509_parser::{pem::parse_x509_pem, prelude::parse_x509_certificate};

pub const CA_TRUST_SUBJECT: &str = "NetTrap CA";

#[cfg(any(test, target_os = "windows"))]
const WINDOWS_COMMAND_OUTPUT_LIMIT_BYTES: usize = 64 * 1024;
#[cfg(any(test, target_os = "windows"))]
const WINDOWS_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(any(test, target_os = "windows"))]
const MAX_CA_CERTIFICATE_BYTES: u64 = 1024 * 1024;

#[cfg(any(test, target_os = "windows"))]
struct LimitedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[cfg(any(test, target_os = "windows"))]
enum LimitedCommandStream {
    Content(Vec<u8>),
    TooLarge,
}

/// Fix missing gateway on Windows (e.g., VMware Host-Only adapter)
#[cfg(target_os = "windows")]
pub fn fix_gateway() {
    tracing::info!("Attempting to fix Windows gateway configuration...");
    let mut command = Command::new("netsh");
    command.args(["interface", "ip", "show", "config"]);
    let output = run_command_with_limited_output(command, "netsh interface ip show config");
    match output {
        Ok(o) => {
            if !netsh_output_has_default_gateway(&o.stdout) {
                tracing::warn!("No default gateway detected. Configure one manually if needed.");
            } else {
                tracing::info!("Gateway configuration looks OK");
            }
        }
        Err(e) => tracing::warn!("Failed to check gateway: {}", e),
    }
}

/// Set DNS server to localhost for traffic capture
#[cfg(target_os = "windows")]
pub fn fix_dns(interface: Option<&str>) {
    let interface = match dns_interface_name(interface) {
        Ok(Some(interface)) => interface,
        Ok(None) => "Ethernet",
        Err(err) => {
            tracing::warn!("Invalid DNS interface: {}", err);
            return;
        }
    };
    let dns_arg = format!("name={}", interface);
    tracing::info!("Setting DNS to localhost for traffic capture...");
    let mut command = Command::new("netsh");
    command.args([
        "interface",
        "ip",
        "set",
        "dns",
        dns_arg.as_str(),
        "static",
        "127.0.0.1",
    ]);
    log_windows_command_result(
        "netsh interface ip set dns static",
        run_command_with_limited_output(command, "netsh interface ip set dns static"),
    );
}

/// Flush OS DNS resolver cache after DNS settings change.
#[cfg(target_os = "windows")]
pub fn flush_dns(command: Option<&str>) {
    let configured = match command {
        Some(command) => match parse_dns_flush_command(command) {
            Ok(command) => Some(command),
            Err(err) => {
                tracing::warn!("Invalid dns_flush_command: {}", err);
                None
            }
        },
        None => None,
    };
    let command = configured.unwrap_or_else(default_dns_flush_command);
    tracing::info!("Flushing DNS resolver cache...");
    let mut process = Command::new(&command.program);
    process.args(&command.args);
    log_windows_command_result(
        command.label.as_deref().unwrap_or("dns_flush_command"),
        run_command_with_limited_output(process, command.label.as_deref().unwrap_or("dns flush")),
    );
}

/// Stop Windows DNS Client service to see actual resolving processes
#[cfg(target_os = "windows")]
pub fn stop_dns_service() {
    tracing::info!("Stopping Windows DNS Client service...");
    let mut command = Command::new("net");
    command.args(["stop", "Dnscache"]);
    log_windows_command_result(
        "net stop Dnscache",
        run_command_with_limited_output(command, "net stop Dnscache"),
    );
}

/// Restore Windows DNS Client service
#[cfg(target_os = "windows")]
pub fn start_dns_service() {
    tracing::info!("Starting Windows DNS Client service...");
    let mut command = Command::new("net");
    command.args(["start", "Dnscache"]);
    log_windows_command_result(
        "net start Dnscache",
        run_command_with_limited_output(command, "net start Dnscache"),
    );
}

/// Install CA certificate in Windows trust store
#[cfg(target_os = "windows")]
pub fn install_ca_trust(cert_path: impl AsRef<Path>) -> Option<String> {
    tracing::info!("Installing CA certificate in Windows trust store...");
    let cert_path = cert_path.as_ref();
    let thumbprint = match certificate_sha1_thumbprint(cert_path) {
        Ok(thumbprint) => Some(thumbprint),
        Err(err) => {
            tracing::warn!(
                "Failed to compute CA certificate thumbprint; continuing with installation: {}",
                err
            );
            None
        }
    };
    if let Some(thumbprint) = thumbprint.as_deref() {
        match certutil_root_store_contains_thumbprint(thumbprint) {
            Ok(true) => {
                tracing::info!("CA certificate is already trusted");
                return Some(thumbprint.to_owned());
            }
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(
                    "Failed to inspect Windows trust store; continuing with installation: {}",
                    err
                );
            }
        }
    }
    let mut command = Command::new("certutil");
    command.args(["-addstore", "Root"]).arg(cert_path);
    let output = run_command_with_limited_output(command, "certutil -addstore Root");
    match output {
        Ok(o) if o.status.success() => {
            tracing::info!("CA certificate installed successfully");
            thumbprint
        }
        Ok(o) => {
            tracing::warn!("certutil failed: {}", render_command_output(&o.stderr));
            None
        }
        Err(e) => {
            tracing::warn!("Failed to run certutil: {}", e);
            None
        }
    }
}

#[cfg(test)]
fn should_skip_ca_trust_install(thumbprint: Option<&str>, precheck: Result<bool, String>) -> bool {
    thumbprint.is_some() && matches!(precheck, Ok(true))
}

/// Remove CA certificate from Windows trust store
#[cfg(target_os = "windows")]
pub fn remove_ca_trust(cert_thumbprint: &str) {
    let mut command = Command::new("certutil");
    command.args(["-delstore", "Root", cert_thumbprint]);
    log_windows_command_result(
        "certutil -delstore Root",
        run_command_with_limited_output(command, "certutil -delstore Root"),
    );
}

/// Restore DNS settings that were modified (set back to DHCP)
#[cfg(target_os = "windows")]
pub fn restore_dns(interface: Option<&str>) {
    let interface = match dns_interface_name(interface) {
        Ok(Some(interface)) => interface,
        Ok(None) => "Ethernet",
        Err(err) => {
            tracing::warn!("Invalid DNS interface: {}", err);
            return;
        }
    };
    let dns_arg = format!("name={}", interface);
    tracing::info!("Restoring DNS settings...");
    let mut command = Command::new("netsh");
    command.args(["interface", "ip", "set", "dns", dns_arg.as_str(), "dhcp"]);
    log_windows_command_result(
        "netsh interface ip set dns dhcp",
        run_command_with_limited_output(command, "netsh interface ip set dns dhcp"),
    );
}

#[cfg(any(test, target_os = "windows"))]
fn netsh_output_has_default_gateway(output: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(output) else {
        return false;
    };

    text.lines().any(|line| {
        let Some((label, value)) = line.split_once(':') else {
            return false;
        };
        label.trim() == "Default Gateway" && !value.trim().is_empty()
    })
}

#[cfg(target_os = "windows")]
fn certutil_root_store_contains_thumbprint(thumbprint: &str) -> Result<bool, String> {
    let mut command = Command::new("certutil");
    command.args(["-store", "Root", thumbprint]);
    let output = run_command_with_limited_output(command, "certutil -store Root")?;
    if !output.status.success() {
        return Err(format!(
            "certutil -store Root failed: {}",
            render_command_output(&output.stderr)
        ));
    }

    Ok(certutil_store_output_contains_thumbprint(
        &output.stdout,
        thumbprint,
    ))
}

#[cfg(test)]
fn parse_certutil_sha1_thumbprint_output(output: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(output)
        .map_err(|err| format!("certutil output was not UTF-8: {}", err))?;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() || ch.is_ascii_whitespace())
        {
            let thumbprint: String = trimmed.split_whitespace().collect();
            if thumbprint.len() == 40 {
                return Ok(thumbprint.to_ascii_uppercase());
            }
        }
    }

    Err(format!(
        "certutil output did not include a SHA1 thumbprint: {}",
        render_command_output(output)
    ))
}

#[cfg(any(test, target_os = "windows"))]
fn certificate_sha1_thumbprint(cert_path: &Path) -> Result<String, String> {
    let file = std::fs::File::open(cert_path).map_err(|err| {
        format!(
            "Failed to read CA certificate {}: {}",
            cert_path.display(),
            err
        )
    })?;
    let metadata = file.metadata().map_err(|err| {
        format!(
            "Failed to read CA certificate metadata {}: {}",
            cert_path.display(),
            err
        )
    })?;
    if metadata.len() > MAX_CA_CERTIFICATE_BYTES {
        return Err(format!(
            "CA certificate {} exceeds size limit ({} > {} bytes)",
            cert_path.display(),
            metadata.len(),
            MAX_CA_CERTIFICATE_BYTES
        ));
    }

    let mut limited = file.take(MAX_CA_CERTIFICATE_BYTES + 1);
    let mut contents = Vec::new();
    limited.read_to_end(&mut contents).map_err(|err| {
        format!(
            "Failed to read CA certificate {}: {}",
            cert_path.display(),
            err
        )
    })?;
    if contents.len() as u64 > MAX_CA_CERTIFICATE_BYTES {
        return Err(format!(
            "CA certificate {} exceeds size limit (>{} bytes)",
            cert_path.display(),
            MAX_CA_CERTIFICATE_BYTES
        ));
    }

    let certificate_der = match parse_x509_pem(&contents) {
        Ok((_, pem)) => pem.contents,
        Err(_) => {
            parse_x509_certificate(&contents)
                .map_err(|err| format!("Failed to parse CA certificate PEM or DER: {}", err))?;
            contents
        }
    };
    let mut hasher = Sha1::new();
    hasher.update(&certificate_der);
    Ok(hex::encode_upper(hasher.finalize()))
}

#[cfg(any(test, target_os = "windows"))]
fn certutil_store_output_contains_thumbprint(output: &[u8], thumbprint: &str) -> bool {
    let expected: String = thumbprint
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_uppercase();

    std::str::from_utf8(output)
        .ok()
        .map(|text| {
            text.lines().map(str::trim).any(|line| {
                line.strip_prefix("Cert Hash(sha1):")
                    .map(|value| {
                        value
                            .chars()
                            .filter(|ch| ch.is_ascii_hexdigit())
                            .collect::<String>()
                    })
                    .is_some_and(|candidate| {
                        candidate.len() == expected.len()
                            && candidate.eq_ignore_ascii_case(&expected)
                    })
            })
        })
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn log_windows_command_result(label: &str, result: Result<LimitedCommandOutput, String>) {
    match result {
        Ok(output) if output.status.success() => {}
        Ok(output) => tracing::warn!(
            "{} failed with status {}: {}",
            label,
            output.status,
            render_command_output(&output.stderr)
        ),
        Err(err) => tracing::warn!("{} failed: {}", label, err),
    }
}

#[cfg(any(test, target_os = "windows"))]
fn run_command_with_limited_output(
    mut command: Command,
    label: &str,
) -> Result<LimitedCommandOutput, String> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("{label} failed: {err}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("{label} stdout pipe was not available"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("{label} stderr pipe was not available"))?;

    let stdout_reader = std::thread::spawn(move || {
        read_limited_command_stream(stdout, WINDOWS_COMMAND_OUTPUT_LIMIT_BYTES)
    });
    let stderr_reader = std::thread::spawn(move || {
        read_limited_command_stream(stderr, WINDOWS_COMMAND_OUTPUT_LIMIT_BYTES)
    });
    let status = wait_for_command(&mut child, label, WINDOWS_COMMAND_TIMEOUT)?;

    let stdout = join_limited_reader(stdout_reader, label, "stdout")?;
    let stderr = join_limited_reader(stderr_reader, label, "stderr")?;

    let stdout = match stdout {
        LimitedCommandStream::Content(stdout) => stdout,
        LimitedCommandStream::TooLarge => {
            return Err(format!(
                "{label} stdout exceeded {WINDOWS_COMMAND_OUTPUT_LIMIT_BYTES} byte limit"
            ));
        }
    };
    let stderr = match stderr {
        LimitedCommandStream::Content(stderr) => stderr,
        LimitedCommandStream::TooLarge => {
            return Err(format!(
                "{label} stderr exceeded {WINDOWS_COMMAND_OUTPUT_LIMIT_BYTES} byte limit"
            ));
        }
    };

    Ok(LimitedCommandOutput {
        status,
        stdout,
        stderr,
    })
}

#[cfg(any(test, target_os = "windows"))]
fn wait_for_command(
    child: &mut Child,
    label: &str,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match child
            .try_wait()
            .map_err(|err| format!("{label} wait failed: {err}"))?
        {
            Some(status) => return Ok(status),
            None if Instant::now() >= deadline => {
                child
                    .kill()
                    .map_err(|err| format!("{label} timeout kill failed: {err}"))?;
                child
                    .wait()
                    .map_err(|err| format!("{label} timeout cleanup wait failed: {err}"))?;
                return Err(format!("{label} exceeded {} seconds", timeout.as_secs()));
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

#[cfg(any(test, target_os = "windows"))]
fn join_limited_reader(
    handle: std::thread::JoinHandle<io::Result<LimitedCommandStream>>,
    label: &str,
    stream_name: &str,
) -> Result<LimitedCommandStream, String> {
    handle
        .join()
        .map_err(|_| format!("{label} {stream_name} reader panicked"))?
        .map_err(|err| format!("{label} {stream_name} read failed: {err}"))
}

#[cfg(any(test, target_os = "windows"))]
fn read_limited_command_stream<R: Read>(
    reader: R,
    max_bytes: usize,
) -> io::Result<LimitedCommandStream> {
    let max_bytes_u64 = u64::try_from(max_bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "command output limit is not representable as u64",
        )
    })?;
    let _limit = max_bytes_u64.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "command output limit sentinel overflowed",
        )
    })?;
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

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, PartialEq, Eq)]
struct ParsedCommand {
    program: String,
    args: Vec<String>,
    label: Option<String>,
}

#[cfg(any(test, target_os = "windows"))]
fn default_dns_flush_command() -> ParsedCommand {
    ParsedCommand {
        program: "ipconfig".to_string(),
        args: vec!["/flushdns".to_string()],
        label: Some("ipconfig /flushdns".to_string()),
    }
}

#[cfg(any(test, target_os = "windows"))]
fn parse_dns_flush_command(command: &str) -> Result<ParsedCommand, String> {
    let parts = split_command_words(command)?;
    let Some((program, args)) = parts.split_first() else {
        return Err("command must not be blank".to_string());
    };
    if program.is_empty() {
        return Err("command must not have an empty program".to_string());
    }
    Ok(ParsedCommand {
        program: program.clone(),
        args: args.to_vec(),
        label: Some(command.to_string()),
    })
}

#[cfg(any(test, target_os = "windows"))]
fn split_command_words(command: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut quote: Option<char> = None;
    let mut token_started = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\\' if quote == Some('"') => {
                let Some(next) = chars.peek().copied() else {
                    current.push(ch);
                    token_started = true;
                    continue;
                };
                if matches!(next, '"' | '\\') {
                    chars.next();
                    current.push(next);
                    token_started = true;
                } else {
                    current.push(ch);
                    token_started = true;
                }
            }
            '"' | '\'' if quote == Some(ch) => {
                quote = None;
            }
            '"' | '\'' if quote.is_none() => {
                quote = Some(ch);
                token_started = true;
            }
            ch if ch.is_ascii_whitespace() && quote.is_none() => {
                if token_started || !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                    token_started = false;
                }
            }
            ch if ch.is_control() => {
                return Err("command contains control characters".to_string());
            }
            ch => {
                current.push(ch);
                token_started = true;
            }
        }
    }

    if let Some(quote) = quote {
        return Err(format!("unterminated {quote} quote"));
    }
    if token_started || !current.is_empty() {
        words.push(current);
    }

    Ok(words)
}

#[cfg(any(test, target_os = "windows"))]
fn dns_interface_name(interface: Option<&str>) -> Result<Option<&str>, String> {
    let Some(interface) = interface else {
        return Ok(None);
    };
    if interface.trim_matches([' ', '\t']) != interface {
        return Err(format!("interface '{}' contains ASCII padding", interface));
    }
    if interface.is_empty()
        || interface
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return Err(format!("interface '{}' is invalid", interface));
    }
    Ok(Some(interface))
}

#[cfg(not(target_os = "windows"))]
pub fn fix_gateway() {}
#[cfg(not(target_os = "windows"))]
pub fn fix_dns(_interface: Option<&str>) {}
#[cfg(not(target_os = "windows"))]
pub fn flush_dns(_command: Option<&str>) {}
#[cfg(not(target_os = "windows"))]
pub fn stop_dns_service() {}
#[cfg(not(target_os = "windows"))]
pub fn start_dns_service() {}
#[cfg(not(target_os = "windows"))]
pub fn install_ca_trust(_cert_path: impl AsRef<Path>) -> Option<String> {
    None
}
#[cfg(not(target_os = "windows"))]
pub fn remove_ca_trust(_cert_subject: &str) {}
#[cfg(not(target_os = "windows"))]
pub fn restore_dns(_interface: Option<&str>) {}

#[cfg(test)]
mod tests {
    use super::{
        CA_TRUST_SUBJECT, LimitedCommandStream, MAX_CA_CERTIFICATE_BYTES,
        certificate_sha1_thumbprint, certutil_store_output_contains_thumbprint,
        default_dns_flush_command, dns_interface_name, netsh_output_has_default_gateway,
        parse_certutil_sha1_thumbprint_output, parse_dns_flush_command,
        read_limited_command_stream, should_skip_ca_trust_install,
    };
    #[cfg(unix)]
    use super::{run_command_with_limited_output, wait_for_command};
    use sha1::{Digest, Sha1};
    #[cfg(unix)]
    use std::process::Command;
    use x509_parser::pem::parse_x509_pem;

    #[cfg(unix)]
    #[test]
    fn wait_for_command_kills_process_after_timeout() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 1"])
            .spawn()
            .expect("spawn sleeping command");

        let err = wait_for_command(
            &mut child,
            "test command",
            std::time::Duration::from_millis(10),
        )
        .expect_err("sleeping command should time out");

        assert!(err.contains("exceeded 0 seconds"));
    }

    #[test]
    fn dns_interface_name_trims_and_defaults_to_ethernet() {
        assert_eq!(dns_interface_name(Some("Wi-Fi")).unwrap(), Some("Wi-Fi"));
        assert!(dns_interface_name(Some("  Wi-Fi  ")).is_err());
        assert_eq!(dns_interface_name(None).unwrap(), None);
    }

    #[test]
    fn dns_interface_name_rejects_unicode_whitespace_padding() {
        assert!(dns_interface_name(Some("Wi-Fi\u{00a0}")).is_err());
    }

    #[test]
    fn dns_interface_name_rejects_c1_controls() {
        assert!(dns_interface_name(Some("Wi-Fi\u{009f}")).is_err());
    }

    #[test]
    fn dns_interface_name_rejects_blank_value() {
        assert!(dns_interface_name(Some("   ")).is_err());
    }

    #[test]
    fn ca_trust_subject_is_stable() {
        assert_eq!(CA_TRUST_SUBJECT, "NetTrap CA");
    }

    #[test]
    fn parse_certutil_sha1_thumbprint_output_extracts_hex_lines() {
        let output = b"CertUtil: -hashfile command completed successfully.\r\n\r\n12 34 ab CD ef 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee\r\nCertUtil: done\r\n";

        let thumbprint =
            parse_certutil_sha1_thumbprint_output(output).expect("thumbprint should be extracted");

        assert_eq!(thumbprint, "1234ABCDEF00112233445566778899AABBCCDDEE");
    }

    #[test]
    fn parse_certutil_sha1_thumbprint_output_rejects_missing_hash_line() {
        let output = b"CertUtil: -hashfile command completed successfully.\r\n";

        let err = parse_certutil_sha1_thumbprint_output(output)
            .expect_err("missing hash line should be rejected");

        assert!(err.contains("did not include a SHA1 thumbprint"));
    }

    #[test]
    fn certificate_sha1_thumbprint_hashes_certificate_der_bytes() {
        let ca = nettrap_tls_mitm::CertificateAuthority::generate()
            .expect("CA should generate for thumbprint test");
        let unique = std::process::id();
        let dir = std::env::temp_dir().join(format!(
            "nettrap-thumbprint-{}-{}",
            unique,
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should be created");
        let cert_path = dir.join("ca.crt");
        std::fs::write(&cert_path, ca.ca_cert_pem()).expect("CA cert should be written");

        let thumbprint =
            certificate_sha1_thumbprint(&cert_path).expect("thumbprint should be derived");
        let (_, pem) =
            parse_x509_pem(ca.ca_cert_pem().as_bytes()).expect("CA PEM should parse in test");
        let expected = hex::encode_upper(Sha1::digest(pem.contents));

        assert_eq!(thumbprint, expected);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn certificate_sha1_thumbprint_rejects_oversized_certificate_file() {
        let dir = std::env::temp_dir().join(format!(
            "nettrap-thumbprint-large-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should be created");
        let cert_path = dir.join("ca.crt");
        let file = std::fs::File::create(&cert_path).expect("certificate file should be created");
        file.set_len(MAX_CA_CERTIFICATE_BYTES + 1)
            .expect("certificate file should be extended");

        let err = certificate_sha1_thumbprint(&cert_path)
            .expect_err("oversized certificate should be rejected");

        assert!(err.contains("exceeds size limit"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn should_skip_ca_trust_install_only_skips_when_already_trusted() {
        assert!(should_skip_ca_trust_install(Some("ABC"), Ok(true)));
        assert!(!should_skip_ca_trust_install(Some("ABC"), Ok(false)));
        assert!(!should_skip_ca_trust_install(
            Some("ABC"),
            Err("probe failed".to_string())
        ));
        assert!(!should_skip_ca_trust_install(None, Ok(true)));
        assert!(!should_skip_ca_trust_install(
            None,
            Err("probe failed".to_string())
        ));
    }

    #[test]
    fn certutil_store_output_contains_thumbprint_requires_matching_thumbprint_line() {
        let output =
            b"Cert Hash(sha1): 12 34 ab cd ef 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee\r\n";

        assert!(certutil_store_output_contains_thumbprint(
            output,
            "1234ABCDEF00112233445566778899AABBCCDDEE"
        ));
        assert!(!certutil_store_output_contains_thumbprint(
            b"CertUtil: -store command completed successfully.\r\n",
            "1234ABCDEF00112233445566778899AABBCCDDEE"
        ));
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
    fn limited_command_stream_rejects_unrepresentable_sentinel_limit() {
        let input = std::io::Cursor::new(Vec::<u8>::new());

        let result = read_limited_command_stream(input, usize::MAX);

        match result {
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput),
            Ok(_) => panic!("sentinel overflow should be rejected"),
        }
    }

    #[test]
    fn default_dns_flush_command_uses_ipconfig_without_shell() {
        let command = default_dns_flush_command();

        assert_eq!(command.program, "ipconfig");
        assert_eq!(command.args, ["/flushdns"]);
    }

    #[test]
    fn parse_dns_flush_command_splits_program_and_arguments() {
        let command = parse_dns_flush_command(r#""C:\Tools\flush dns.exe" --scope "local cache""#)
            .expect("quoted command should parse");

        assert_eq!(command.program, r#"C:\Tools\flush dns.exe"#);
        assert_eq!(command.args, ["--scope", "local cache"]);
    }

    #[test]
    fn parse_dns_flush_command_preserves_empty_quoted_arguments() {
        let command = parse_dns_flush_command(r#"flush-dns.exe "" --scope local"#)
            .expect("empty quoted argument should parse");

        assert_eq!(command.program, "flush-dns.exe");
        assert_eq!(command.args, ["", "--scope", "local"]);
    }

    #[test]
    fn parse_dns_flush_command_rejects_empty_program() {
        let err = parse_dns_flush_command(r#""" flush-dns.exe --scope local"#)
            .expect_err("empty program should fail");

        assert_eq!(err, "command must not have an empty program");
    }

    #[test]
    fn parse_dns_flush_command_rejects_blank_command() {
        let err = parse_dns_flush_command(" \t ").expect_err("blank command should fail");

        assert_eq!(err, "command must not be blank");
    }

    #[test]
    fn parse_dns_flush_command_rejects_unterminated_quote() {
        let err = parse_dns_flush_command(r#""C:\Tools\flush.exe"#)
            .expect_err("unterminated quote should fail");

        assert_eq!(err, "unterminated \" quote");
    }

    #[cfg(unix)]
    #[test]
    fn run_command_with_limited_output_captures_stdout_and_stderr() {
        let mut command = Command::new("sh");
        command.current_dir(env!("CARGO_MANIFEST_DIR"));
        command.args(["-c", "printf out; printf err >&2"]);

        let output =
            run_command_with_limited_output(command, "test command").expect("command should run");

        assert!(output.status.success());
        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"err");
    }

    #[test]
    fn netsh_output_has_default_gateway_ignores_padding_only_values() {
        assert!(!netsh_output_has_default_gateway(
            b"Default Gateway:                          \r\n"
        ));
        assert!(netsh_output_has_default_gateway(
            b"Default Gateway: 192.168.1.1\r\n"
        ));
    }
}
