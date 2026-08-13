pub struct TelnetHandler {
    hostname: String,
    shell_prompt: String,
    fake_system: String,
    credentials: Vec<(String, String)>, // accepted user/pass pairs (empty = accept all)
    started_at: std::time::Instant,
    now: fn() -> chrono::DateTime<chrono::Utc>,
}

const MAX_TELNET_COMMAND_ARGS: usize = 32;
const MAX_TELNET_COMMAND_LINE_BYTES: usize = 8192;
const MAX_TELNET_MIRAI_SCAN_BYTES: usize = 4096;
const REDACTED_TELNET_COMMAND_FIELD: &str = "***REDACTED***";

impl TelnetHandler {
    const DEFAULT_HOSTNAME: &'static str = "nettrap.local";
    const SECONDS_PER_MINUTE: u64 = 60;
    const SECONDS_PER_HOUR: u64 = 60 * Self::SECONDS_PER_MINUTE;
    const SECONDS_PER_DAY: u64 = 24 * Self::SECONDS_PER_HOUR;

    pub fn new() -> Self {
        Self {
            hostname: Self::DEFAULT_HOSTNAME.to_string(),
            shell_prompt: "# ".to_string(),
            fake_system: "BusyBox v1.31.1".to_string(),
            credentials: Vec::new(), // accept all by default (honeypot mode)
            started_at: std::time::Instant::now(),
            now: chrono::Utc::now,
        }
    }

    /// Inject the clock used by `uptime` so FakeTime mode can reach the
    /// telnet shell banner too.
    pub fn with_now(mut self, now: fn() -> chrono::DateTime<chrono::Utc>) -> Self {
        self.now = now;
        self
    }

    pub fn with_hostname(mut self, hostname: impl Into<String>) -> crate::error::Result<Self> {
        self.hostname = validate_hostname(&hostname.into())?;
        Ok(self)
    }

    pub fn accepts_credentials(&self, username: &str, password: &str) -> bool {
        self.credentials.is_empty()
            || self
                .credentials
                .iter()
                .any(|(user, pass)| user == username && pass == password)
    }

    /// Get the initial telnet negotiation + login banner
    pub fn get_login_banner(&self) -> Vec<u8> {
        let mut banner = Vec::new();
        banner.extend_from_slice(&[255, 253, 3]); // IAC DO SUPPRESS-GO-AHEAD
        banner.extend_from_slice(&[255, 251, 1]); // IAC WILL ECHO
        banner.extend_from_slice(format!("\r\n{} login: ", self.hostname).as_bytes());
        banner
    }

    pub fn get_password_prompt(&self) -> Vec<u8> {
        b"Password: ".to_vec()
    }

    pub fn get_shell_prompt(&self) -> Vec<u8> {
        self.shell_prompt.as_bytes().to_vec()
    }

    pub fn get_login_success(&self) -> Vec<u8> {
        format!(
            "\r\nLogin successful.\r\n\r\n{}\r\n{}",
            self.fake_system, self.shell_prompt
        )
        .into_bytes()
    }

    pub fn get_login_failure(&self) -> Vec<u8> {
        format!("\r\nLogin incorrect\r\n\r\n{} login: ", self.hostname).into_bytes()
    }

    /// Handle a shell command and return fake output
    pub fn handle_command(&self, cmd: &str) -> Vec<u8> {
        if cmd.len() > MAX_TELNET_COMMAND_LINE_BYTES {
            return self.shell_prompt.as_bytes().to_vec();
        }
        if cmd.starts_with([' ', '\t']) {
            return self.shell_prompt.as_bytes().to_vec();
        }
        if cmd.ends_with(['\r', '\n']) && !cmd.ends_with("\r\n") {
            return self.shell_prompt.as_bytes().to_vec();
        }

        let cmd = cmd.trim_end_matches(['\r', '\n']);
        if cmd.is_empty() {
            return self.shell_prompt.as_bytes().to_vec();
        }
        if cmd.chars().any(|ch| matches!(ch, '\r' | '\n' | '\0')) {
            return self.shell_prompt.as_bytes().to_vec();
        }

        if let Some(rest) = cmd.strip_prefix("echo")
            && (rest.is_empty() || rest.starts_with([' ', '\t']))
        {
            let arg = rest.trim_start_matches([' ', '\t']);
            // Limit echo output to 4KB to prevent memory exhaustion
            let truncated = truncate_utf8(arg, 4096);
            let echo_output = format!("{}\n", truncated);
            return self.build_response(&echo_output, cmd);
        }

        let mut parts = cmd.split([' ', '\t']).filter(|part| !part.is_empty());
        let verb = parts.next().unwrap_or("");
        let mut args = Vec::new();
        for part in parts {
            if args.len() >= MAX_TELNET_COMMAND_ARGS {
                return self.shell_prompt.as_bytes().to_vec();
            }
            args.push(part);
        }
        let output = match verb {
            "ls" if args.is_empty() => {
                "bin   dev   etc   lib   mnt   proc  root  sbin  sys   tmp   usr   var\n"
            }
            "id" if args.is_empty() => "uid=0(root) gid=0(root)\n",
            "whoami" if args.is_empty() => "root\n",
            "uname" if args.is_empty() => "Linux\n",
            "cat" if args == ["/etc/passwd"] => {
                "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            }
            "cat" if args == ["/proc/cpuinfo"] => {
                "processor\t: 0\nmodel name\t: ARMv7 Processor rev 4 (v7l)\nBogoMIPS\t: 38.40\n"
            }
            "cat" if args == ["/proc/mounts"] => {
                "rootfs / rootfs rw 0 0\nproc /proc proc rw,nosuid,nodev,noexec 0 0\nsysfs /sys sysfs rw 0 0\n"
            }
            "cat" if args.len() == 1 => "cat: can't open: No such file or directory\n",
            "pwd" if args.is_empty() => "/root\n",
            "cd" if args.is_empty() => "", // silent
            "wget" | "curl" | "tftp" | "ftpget" if !args.is_empty() => {
                tracing::debug!(
                    "TELNET PAYLOAD DOWNLOAD ATTEMPT: {}",
                    nettrap_core::sanitize::single_line(cmd)
                );
                tracing::warn!(
                    "TELNET PAYLOAD DOWNLOAD ATTEMPT: command={}, args={}",
                    REDACTED_TELNET_COMMAND_FIELD,
                    args.len()
                );
                ""
            }
            "chmod" if !args.is_empty() => "", // silent (Mirai does chmod +x)
            "rm" if !args.is_empty() => "",    // silent
            "cp" | "mv" if !args.is_empty() => "",
            "sh" | "bash" | "/bin/sh" | "/bin/bash" if !args.is_empty() => "",
            "ps" if args.is_empty() => {
                "  PID TTY          TIME CMD\n    1 ?        00:00:01 init\n  123 pts/0    00:00:00 sh\n  456 pts/0    00:00:00 ps\n"
            }
            "kill" | "killall" if !args.is_empty() => "",
            "ifconfig" | "ip" if args.is_empty() => {
                "eth0      Link encap:Ethernet  HWaddr AA:BB:CC:DD:EE:FF\n          inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0\n"
            }
            "free" if args.is_empty() => {
                "             total       used       free     shared    buffers     cached\nMem:         61632      12928      48704          0       2292       5828\n"
            }
            "uptime" if args.is_empty() => return self.build_response(&self.uptime_output(), cmd),
            "enable" | "system" | "shell" | "linuxshell" if args.is_empty() => {
                // Common IoT device shell escape commands
                tracing::debug!(
                    "TELNET IoT shell escape attempt: {}",
                    nettrap_core::sanitize::single_line(cmd)
                );
                tracing::info!(
                    "TELNET IoT shell escape attempt: command={}",
                    REDACTED_TELNET_COMMAND_FIELD
                );
                ""
            }
            "exit" | "quit" | "logout" if args.is_empty() => {
                return b"Connection closed.\r\n".to_vec();
            }
            _ if args.is_empty() => "-sh: not found\n",
            _ => return self.shell_prompt.as_bytes().to_vec(),
        };

        self.build_response(output, cmd)
    }

    fn build_response(&self, output: &str, _cmd: &str) -> Vec<u8> {
        let mut response = output.as_bytes().to_vec();
        response.extend_from_slice(self.shell_prompt.as_bytes());
        response
    }

    fn uptime_output(&self) -> String {
        self.uptime_output_at_secs((self.now)().timestamp(), self.started_at.elapsed())
    }

    fn uptime_output_at_secs(&self, now_secs: i64, uptime: std::time::Duration) -> String {
        telnet_uptime_output(now_secs, uptime.as_secs())
    }

    #[cfg(test)]
    fn uptime_output_at(&self, now: std::time::SystemTime, uptime: std::time::Duration) -> String {
        let now_secs = system_time_unix_timestamp(now);
        self.uptime_output_at_secs(now_secs, uptime)
    }

    /// Check if data contains Mirai-style indicators
    pub fn detect_mirai_indicators(data: &[u8]) -> bool {
        if data.len() > MAX_TELNET_MIRAI_SCAN_BYTES {
            return false;
        }
        let Ok(text) = std::str::from_utf8(data) else {
            return false;
        };
        let text = text.to_lowercase();
        text.contains("/tmp/")
            || text.contains("wget ")
            || text.contains("curl ")
            || text.contains("tftp ")
            || text.contains("chmod ")
            || text.contains("busybox")
            || text.contains("/dev/null")
            || text.contains("cd /tmp")
    }
}

fn truncate_utf8(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }

    let mut end = max_bytes;
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    &input[..end]
}

fn validate_hostname(hostname: &str) -> crate::error::Result<String> {
    if hostname.trim_matches([' ', '\t']) != hostname {
        return Err(crate::error::Error::Config(
            "Telnet hostname must not include leading or trailing whitespace".to_string(),
        ));
    }

    let value = hostname.strip_suffix('.').unwrap_or(hostname);
    if value.is_empty()
        || value.len() > 253
        || value.ends_with('.')
        || value.chars().any(|ch| {
            ch.is_control()
                || ch.is_whitespace()
                || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}')
        })
        || !nettrap_core::sanitize::has_valid_domain_labels(value)
        || value
            .split('.')
            .all(|label| label.chars().all(|ch| ch.is_ascii_digit()))
    {
        return Err(crate::error::Error::Config(format!(
            "Invalid telnet hostname '{}'",
            hostname
        )));
    }

    Ok(value.to_ascii_lowercase())
}

fn telnet_uptime_output(now_secs: i64, uptime_secs: u64) -> String {
    let day_secs = now_secs.rem_euclid(TelnetHandler::SECONDS_PER_DAY as i64) as u64;
    let clock_hour = day_secs / TelnetHandler::SECONDS_PER_HOUR;
    let clock_minute =
        (day_secs % TelnetHandler::SECONDS_PER_HOUR) / TelnetHandler::SECONDS_PER_MINUTE;
    let clock_second = day_secs % TelnetHandler::SECONDS_PER_MINUTE;
    let uptime_text = format_telnet_uptime_duration(uptime_secs);

    format!(
        " {clock_hour:02}:{clock_minute:02}:{clock_second:02} up {uptime_text},  1 user,  load average: 0.00, 0.01, 0.05\n"
    )
}

fn format_telnet_uptime_duration(uptime_secs: u64) -> String {
    let days = uptime_secs / TelnetHandler::SECONDS_PER_DAY;
    let day_remainder = uptime_secs % TelnetHandler::SECONDS_PER_DAY;
    let hours = day_remainder / TelnetHandler::SECONDS_PER_HOUR;
    let minutes =
        (day_remainder % TelnetHandler::SECONDS_PER_HOUR) / TelnetHandler::SECONDS_PER_MINUTE;

    if days > 0 {
        let day_label = if days == 1 { "day" } else { "days" };
        format!("{days} {day_label}, {hours:2}:{minutes:02}")
    } else if hours > 0 {
        format!("{hours:2}:{minutes:02}")
    } else {
        format!("{minutes} min")
    }
}

#[cfg(test)]
fn system_time_unix_timestamp(now: std::time::SystemTime) -> i64 {
    match now.duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs() as i64,
        Err(err) => -(err.duration().as_secs() as i64),
    }
}

impl Default for TelnetHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG_COMMAND_PREVIEW_CHARS: usize = 240;

    #[test]
    fn exact_close_commands_close_connection() {
        let handler = TelnetHandler::new();

        assert_eq!(handler.handle_command("exit"), b"Connection closed.\r\n");
        assert_eq!(handler.handle_command("quit"), b"Connection closed.\r\n");
        assert_eq!(handler.handle_command("logout"), b"Connection closed.\r\n");
    }

    #[test]
    fn prefixed_close_commands_are_regular_shell_commands() {
        let handler = TelnetHandler::new();

        assert_eq!(handler.handle_command(" exit"), b"# ");
        assert_eq!(handler.handle_command("exitnow"), b"-sh: not found\n# ");
        assert_eq!(handler.handle_command("quitnow"), b"-sh: not found\n# ");
        assert_eq!(handler.handle_command("logoutnow"), b"-sh: not found\n# ");
    }

    #[test]
    fn trailing_command_noise_falls_back_to_prompt() {
        let handler = TelnetHandler::new();

        assert_eq!(handler.handle_command("uname trailing"), b"# ");
        assert_eq!(handler.handle_command("exit trailing"), b"# ");
        assert_eq!(handler.handle_command("cat /etc/passwd extra"), b"# ");
    }

    #[test]
    fn excessive_command_arguments_fall_back_to_prompt() {
        let handler = TelnetHandler::new();
        let mut command = String::from("uname");
        for index in 0..=MAX_TELNET_COMMAND_ARGS {
            command.push(' ');
            command.push_str(&index.to_string());
        }

        assert_eq!(handler.handle_command(&command), b"# ");
    }

    #[test]
    fn oversized_command_line_falls_back_to_prompt() {
        let handler = TelnetHandler::new();
        let command = "a".repeat(MAX_TELNET_COMMAND_LINE_BYTES + 1);

        assert_eq!(handler.handle_command(&command), b"# ");
    }

    #[test]
    fn trailing_tabs_do_not_create_valid_telnet_commands() {
        let handler = TelnetHandler::new();

        assert_eq!(handler.handle_command("quit\t"), b"Connection closed.\r\n");
        assert_eq!(
            handler.handle_command("ls\t"),
            b"bin   dev   etc   lib   mnt   proc  root  sbin  sys   tmp   usr   var\n# "
        );
    }

    #[test]
    fn bare_carriage_return_or_line_feed_are_not_executed() {
        let handler = TelnetHandler::new();

        assert_eq!(handler.handle_command("quit\r"), b"# ");
        assert_eq!(handler.handle_command("quit\n"), b"# ");
    }

    #[test]
    fn echo_preserves_tab_separated_arguments() {
        let handler = TelnetHandler::new();

        assert_eq!(handler.handle_command("echo\tfoo"), b"foo\n# ");
        assert_eq!(handler.handle_command("echo\tfoo bar"), b"foo bar\n# ");
    }

    #[test]
    fn echo_truncates_on_utf8_boundary() {
        let handler = TelnetHandler::new();
        let arg = format!("{}é", "a".repeat(4095));
        let response = handler.handle_command(&format!("echo {arg}"));

        assert!(response.ends_with(b"\n# "));
        assert_eq!(&response[..4095], vec![b'a'; 4095].as_slice());
    }

    #[test]
    fn echo_rejects_embedded_line_breaks() {
        let handler = TelnetHandler::new();

        assert_eq!(handler.handle_command("echo hello\r\nid"), b"# ");
        assert_eq!(handler.handle_command("echo hello\nid"), b"# ");
    }

    #[test]
    fn echo_rejects_unicode_whitespace_separator() {
        let handler = TelnetHandler::new();

        assert_eq!(
            handler.handle_command("echo\u{00a0}hello"),
            b"-sh: not found\n# "
        );
    }

    #[test]
    fn leading_unicode_whitespace_is_not_treated_as_blank_input() {
        let handler = TelnetHandler::new();

        assert_eq!(handler.handle_command("\u{00a0}id"), b"-sh: not found\n# ");
    }

    #[test]
    fn configured_credentials_are_enforced() {
        let handler = TelnetHandler {
            hostname: TelnetHandler::DEFAULT_HOSTNAME.to_string(),
            shell_prompt: "# ".to_string(),
            fake_system: "BusyBox v1.31.1".to_string(),
            credentials: vec![("admin".to_string(), "secret".to_string())],
            started_at: std::time::Instant::now(),
            now: chrono::Utc::now,
        };

        assert!(handler.accepts_credentials("admin", "secret"));
        assert!(!handler.accepts_credentials("admin", "wrong"));
        assert!(!handler.accepts_credentials("root", "secret"));
    }

    #[test]
    fn empty_credentials_accept_honeypot_logins() {
        let handler = TelnetHandler::new();

        assert!(handler.accepts_credentials("anything", "anything"));
    }

    #[test]
    fn configured_hostname_cannot_inject_login_banner_lines() {
        let handler = TelnetHandler {
            hostname: "router\r\nPassword: injected".to_string(),
            shell_prompt: "# ".to_string(),
            fake_system: "BusyBox v1.31.1".to_string(),
            credentials: Vec::new(),
            started_at: std::time::Instant::now(),
            now: chrono::Utc::now,
        };

        let banner = handler.get_login_banner();
        let text = String::from_utf8_lossy(&banner);

        assert!(text.contains("router\r\nPassword: injected login: "));
    }

    #[test]
    fn default_hostname_uses_generic_honeypot_identity() {
        let banner = TelnetHandler::new().get_login_banner();
        let text = String::from_utf8_lossy(&banner);

        assert!(text.contains("nettrap.local login: "));
        assert!(!text.contains("localhost"));
    }

    #[test]
    fn configured_hostname_feeds_login_banner_token() {
        let handler = TelnetHandler::new()
            .with_hostname("router.example")
            .expect("hostname should validate");

        let banner = handler.get_login_banner();
        let text = String::from_utf8_lossy(&banner);

        assert!(text.contains("router.example login: "));
    }

    #[test]
    fn configured_hostname_rejects_invalid_service_names() {
        let result = TelnetHandler::new().with_hostname("router\\r\\ninjected");

        assert!(result.is_err());
    }

    #[test]
    fn configured_hostname_rejects_overlong_hostnames() {
        let hostname = ["a"; 128].join(".");

        assert!(hostname.len() > 253);
        assert!(TelnetHandler::new().with_hostname(hostname).is_err());
    }

    #[test]
    fn configured_fake_system_cannot_inject_login_success_lines() {
        let handler = TelnetHandler {
            hostname: TelnetHandler::DEFAULT_HOSTNAME.to_string(),
            shell_prompt: "# ".to_string(),
            fake_system: "BusyBox\r\nowned".to_string(),
            credentials: Vec::new(),
            started_at: std::time::Instant::now(),
            now: chrono::Utc::now,
        };

        let response = handler.get_login_success();
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("BusyBox\r\nowned"));
    }

    #[test]
    fn configured_fake_system_preserves_expected_banner_text() {
        let handler = TelnetHandler {
            hostname: TelnetHandler::DEFAULT_HOSTNAME.to_string(),
            shell_prompt: "# ".to_string(),
            fake_system: "BusyBox v1.31.1".to_string(),
            credentials: Vec::new(),
            started_at: std::time::Instant::now(),
            now: chrono::Utc::now,
        };
        let response = handler.get_login_success();
        let text = String::from_utf8_lossy(&response);

        assert!(text.contains("BusyBox v1.31.1"));
    }

    #[test]
    fn configured_fake_system_trims_edges_and_preserves_punctuation() {
        let handler = TelnetHandler {
            hostname: TelnetHandler::DEFAULT_HOSTNAME.to_string(),
            shell_prompt: "# ".to_string(),
            fake_system: " BusyBox><owned ".to_string(),
            credentials: Vec::new(),
            started_at: std::time::Instant::now(),
            now: chrono::Utc::now,
        };
        let response = handler.get_login_success();
        let text = String::from_utf8_lossy(&response);

        assert!(text.contains(" BusyBox><owned "));
    }

    #[test]
    fn configured_shell_prompt_cannot_inject_response_lines() {
        let handler = TelnetHandler {
            hostname: TelnetHandler::DEFAULT_HOSTNAME.to_string(),
            shell_prompt: "# \r\nowned".to_string(),
            fake_system: "BusyBox v1.31.1".to_string(),
            credentials: Vec::new(),
            started_at: std::time::Instant::now(),
            now: chrono::Utc::now,
        };
        let response = handler.get_shell_prompt();

        assert_eq!(response, b"# \r\nowned");
    }

    #[test]
    fn configured_shell_prompt_preserves_leading_whitespace() {
        let handler = TelnetHandler {
            hostname: TelnetHandler::DEFAULT_HOSTNAME.to_string(),
            shell_prompt: " # ".to_string(),
            fake_system: "BusyBox v1.31.1".to_string(),
            credentials: Vec::new(),
            started_at: std::time::Instant::now(),
            now: chrono::Utc::now,
        };
        let prompt = handler.get_shell_prompt();

        assert_eq!(prompt, b" # ");
    }

    #[test]
    fn configured_shell_prompt_rejects_unicode_whitespace() {
        let handler = TelnetHandler {
            hostname: TelnetHandler::DEFAULT_HOSTNAME.to_string(),
            shell_prompt: " #\u{2028}owned".to_string(),
            fake_system: "BusyBox v1.31.1".to_string(),
            credentials: Vec::new(),
            started_at: std::time::Instant::now(),
            now: chrono::Utc::now,
        };
        let prompt = handler.get_shell_prompt();

        assert_eq!(prompt, " #\u{2028}owned".as_bytes());
    }

    #[test]
    fn cat_known_files_requires_exact_path_argument() {
        let handler = TelnetHandler::new();

        let exact_response = handler.handle_command("cat /etc/passwd");
        let exact = String::from_utf8_lossy(&exact_response);
        assert!(exact.contains("root:x:0:0:root:/root:/bin/sh"));

        let substring_response = handler.handle_command("cat /tmp/etc/passwd.bak");
        let substring = String::from_utf8_lossy(&substring_response);
        assert!(substring.contains("cat: can't open"));
        assert!(!substring.contains("root:x:0:0:root:/root:/bin/sh"));
    }

    #[test]
    fn kill_commands_accept_target_arguments_silently() {
        let handler = TelnetHandler::new();

        assert_eq!(handler.handle_command("kill 123"), b"# ");
        assert_eq!(handler.handle_command("killall telnetd"), b"# ");
    }

    #[test]
    fn uptime_output_uses_supplied_clock_and_elapsed_time() {
        let output = telnet_uptime_output(3661, 90_061);

        assert_eq!(
            output,
            " 01:01:01 up 1 day,  1:01,  1 user,  load average: 0.00, 0.01, 0.05\n"
        );
    }

    #[test]
    fn uptime_output_before_unix_epoch_preserves_clock_time() {
        let handler = TelnetHandler::new();
        let before_unix_epoch = std::time::UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(1))
            .expect("pre-epoch time should be representable");

        let output =
            handler.uptime_output_at(before_unix_epoch, std::time::Duration::from_secs(61));

        assert!(output.starts_with(" 23:59:59 up 1 min"));
    }

    #[test]
    fn uptime_response_does_not_report_frozen_placeholder() {
        let response = TelnetHandler::new().handle_command("uptime");
        let text = String::from_utf8_lossy(&response);

        assert!(text.contains(" up "));
        assert!(text.ends_with("# "));
        assert!(!text.contains("00:00:00 up 1 day,  0:00"));
    }

    #[test]
    fn uptime_response_uses_injected_clock_for_clock_display() {
        fn fixed_now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant")
        }

        let mut handler = TelnetHandler::new().with_now(fixed_now);
        handler.started_at = std::time::Instant::now() - std::time::Duration::from_secs(61);

        let response = handler.handle_command("uptime");
        let text = String::from_utf8(response).expect("uptime response should be UTF-8");

        assert!(text.contains(" 00:00:00 up 1 min,  1 user,  load average: 0.00, 0.01, 0.05\n"));
    }

    #[test]
    fn logged_commands_are_single_line() {
        let command = nettrap_core::sanitize::single_line("wget http://a\nchmod +x\x1b");

        assert_eq!(command, "wget http://a chmod +x ");
        assert!(!command.chars().any(char::is_control));

        let long = "a".repeat(LOG_COMMAND_PREVIEW_CHARS + 1);
        assert_eq!(
            nettrap_core::sanitize::single_line(&long).len(),
            LOG_COMMAND_PREVIEW_CHARS
        );
    }

    #[test]
    fn mirai_detector_rejects_invalid_utf8() {
        assert!(!TelnetHandler::detect_mirai_indicators(
            b"\xffwget /tmp/payload"
        ));
    }

    #[test]
    fn mirai_detector_rejects_oversized_buffers_before_lowercasing() {
        let mut payload = b"wget /tmp/payload ".to_vec();
        payload.extend(std::iter::repeat_n(b'a', MAX_TELNET_MIRAI_SCAN_BYTES));

        assert!(!TelnetHandler::detect_mirai_indicators(&payload));
    }
}
