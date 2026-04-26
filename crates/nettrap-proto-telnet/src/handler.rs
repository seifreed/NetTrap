use crate::telnet::TelnetState;

pub struct TelnetHandler {
    hostname: String,
    shell_prompt: String,
    fake_system: String,
    credentials: Vec<(String, String)>, // accepted user/pass pairs (empty = accept all)
    state: TelnetState,
}

impl TelnetHandler {
    pub fn new() -> Self {
        Self {
            hostname: "localhost".to_string(),
            shell_prompt: "# ".to_string(),
            fake_system: "BusyBox v1.31.1".to_string(),
            credentials: Vec::new(), // accept all by default (honeypot mode)
            state: TelnetState::default(),
        }
    }

    pub fn with_hostname(mut self, h: impl Into<String>) -> Self {
        self.hostname = h.into();
        self
    }

    pub fn with_shell_prompt(mut self, p: impl Into<String>) -> Self {
        self.shell_prompt = p.into();
        self
    }

    pub fn with_fake_system(mut self, s: impl Into<String>) -> Self {
        self.fake_system = s.into();
        self
    }

    pub fn with_credentials(mut self, creds: Vec<(String, String)>) -> Self {
        self.credentials = creds;
        self
    }

    pub fn accepts_credentials(&self, username: &str, password: &str) -> bool {
        self.credentials.is_empty()
            || self
                .credentials
                .iter()
                .any(|(user, pass)| user == username && pass == password)
    }

    pub fn state(&self) -> &TelnetState {
        &self.state
    }

    pub fn set_state(&mut self, state: TelnetState) {
        self.state = state;
    }

    /// Get the initial telnet negotiation + login banner
    pub fn get_login_banner(&self) -> Vec<u8> {
        let mut banner = Vec::new();
        // Telnet negotiation: DO suppress go-ahead, WILL echo
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
        let cmd = cmd.trim();
        if cmd.is_empty() {
            return self.shell_prompt.as_bytes().to_vec();
        }

        let output = match cmd.split_whitespace().next().unwrap_or("") {
            "ls" => "bin   dev   etc   lib   mnt   proc  root  sbin  sys   tmp   usr   var\n",
            "id" => "uid=0(root) gid=0(root)\n",
            "whoami" => "root\n",
            "uname" => "Linux\n",
            "cat" if cmd.contains("/etc/passwd") => {
                "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            }
            "cat" if cmd.contains("/proc/cpuinfo") => {
                "processor\t: 0\nmodel name\t: ARMv7 Processor rev 4 (v7l)\nBogoMIPS\t: 38.40\n"
            }
            "cat" if cmd.contains("/proc/mounts") => {
                "rootfs / rootfs rw 0 0\nproc /proc proc rw,nosuid,nodev,noexec 0 0\nsysfs /sys sysfs rw 0 0\n"
            }
            "cat" => "cat: can't open: No such file or directory\n",
            "pwd" => "/root\n",
            "cd" => "", // silent
            "echo" => {
                let arg = cmd.strip_prefix("echo ").unwrap_or("");
                // Limit echo output to 4KB to prevent memory exhaustion
                let truncated = truncate_utf8(arg, 4096);
                let echo_output = format!("{}\n", truncated);
                return self.build_response(&echo_output, cmd);
            }
            "wget" | "curl" | "tftp" | "ftpget" => {
                // Log payload download attempt - this is what Mirai does
                tracing::warn!("TELNET PAYLOAD DOWNLOAD ATTEMPT: {}", cmd);
                ""
            }
            "chmod" => "", // silent (Mirai does chmod +x)
            "rm" => "",    // silent
            "cp" | "mv" => "",
            "sh" | "bash" | "/bin/sh" | "/bin/bash" => "",
            "ps" => {
                "  PID TTY          TIME CMD\n    1 ?        00:00:01 init\n  123 pts/0    00:00:00 sh\n  456 pts/0    00:00:00 ps\n"
            }
            "kill" | "killall" => "",
            "ifconfig" | "ip" => {
                "eth0      Link encap:Ethernet  HWaddr AA:BB:CC:DD:EE:FF\n          inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0\n"
            }
            "free" => {
                "             total       used       free     shared    buffers     cached\nMem:         61632      12928      48704          0       2292       5828\n"
            }
            "uptime" => " 00:00:00 up 1 day,  0:00,  1 user,  load average: 0.00, 0.01, 0.05\n",
            "enable" | "system" | "shell" | "linuxshell" => {
                // Common IoT device shell escape commands
                tracing::info!("TELNET IoT shell escape attempt: {}", cmd);
                ""
            }
            "exit" | "quit" | "logout" => return b"Connection closed.\r\n".to_vec(),
            _ => "-sh: not found\n",
        };

        self.build_response(output, cmd)
    }

    fn build_response(&self, output: &str, _cmd: &str) -> Vec<u8> {
        let mut response = output.as_bytes().to_vec();
        response.extend_from_slice(self.shell_prompt.as_bytes());
        response
    }

    /// Check if data contains Mirai-style indicators
    pub fn detect_mirai_indicators(data: &[u8]) -> bool {
        let text = String::from_utf8_lossy(data).to_lowercase();
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

impl Default for TelnetHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        assert_eq!(handler.handle_command("exitnow"), b"-sh: not found\n# ");
        assert_eq!(handler.handle_command("quitnow"), b"-sh: not found\n# ");
        assert_eq!(handler.handle_command("logoutnow"), b"-sh: not found\n# ");
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
    fn configured_credentials_are_enforced() {
        let handler = TelnetHandler::new()
            .with_credentials(vec![("admin".to_string(), "secret".to_string())]);

        assert!(handler.accepts_credentials("admin", "secret"));
        assert!(!handler.accepts_credentials("admin", "wrong"));
        assert!(!handler.accepts_credentials("root", "secret"));
    }

    #[test]
    fn empty_credentials_accept_honeypot_logins() {
        let handler = TelnetHandler::new();

        assert!(handler.accepts_credentials("anything", "anything"));
    }
}
