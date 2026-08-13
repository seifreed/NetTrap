/// Telnet protocol command bytes (RFC 854)
pub const IAC: u8 = 255; // Interpret As Command
pub const DONT: u8 = 254;
pub const DO: u8 = 253;
pub const WONT: u8 = 252;
pub const WILL: u8 = 251;
pub const SB: u8 = 250; // Sub-negotiation Begin
pub const SE: u8 = 240; // Sub-negotiation End

/// Telnet option codes
pub const OPT_ECHO: u8 = 1;
pub const OPT_SUPPRESS_GO_AHEAD: u8 = 3;
pub const OPT_TERMINAL_TYPE: u8 = 24;
pub const OPT_WINDOW_SIZE: u8 = 31;
pub const OPT_LINEMODE: u8 = 34;

/// Telnet session state
#[derive(Debug, Clone, PartialEq, Default)]
pub enum TelnetState {
    /// Waiting for username input
    #[default]
    WaitingUsername,
    /// Waiting for password input
    WaitingPassword,
    /// Authenticated, in shell mode
    Shell,
    /// Session disconnected
    Disconnected,
}

/// Parsed telnet data, stripping out IAC sequences
pub fn strip_telnet_commands(data: &[u8]) -> Vec<u8> {
    try_strip_telnet_commands(data).unwrap_or_default()
}

/// Parsed telnet data, stripping out complete IAC sequences.
pub fn try_strip_telnet_commands(data: &[u8]) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i] == IAC {
            if i + 1 >= data.len() {
                return None;
            }
            match data[i + 1] {
                WILL | WONT | DO | DONT => {
                    if i + 2 >= data.len() {
                        return None;
                    }
                    // Skip 3-byte command
                    i += 3;
                }
                SB => {
                    i += 2;
                    let mut found_end = false;
                    while i < data.len() {
                        if data[i] == IAC && i + 1 < data.len() && data[i + 1] == SE {
                            i += 2;
                            found_end = true;
                            break;
                        }
                        i += 1;
                    }
                    if !found_end {
                        return None;
                    }
                }
                IAC => {
                    // Escaped 0xFF
                    result.push(IAC);
                    i += 2;
                }
                _ => {
                    i += 2;
                }
            }
        } else {
            if data[i] < 32 && data[i] != b'\r' && data[i] != b'\n' {
                return None;
            }
            result.push(data[i]);
            i += 1;
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_complete_telnet_negotiation() {
        assert_eq!(
            try_strip_telnet_commands(&[b'i', b'd', IAC, DO, OPT_ECHO, b'\r', b'\n']),
            Some(b"id\r\n".to_vec())
        );
    }

    #[test]
    fn rejects_truncated_telnet_negotiation() {
        assert_eq!(try_strip_telnet_commands(&[b'i', b'd', IAC]), None);
        assert_eq!(try_strip_telnet_commands(&[b'i', b'd', IAC, DO]), None);
        assert_eq!(
            try_strip_telnet_commands(&[b'i', b'd', IAC, SB, OPT_TERMINAL_TYPE]),
            None
        );
    }

    #[test]
    fn rejects_embedded_control_bytes_in_text() {
        assert_eq!(try_strip_telnet_commands(b"e\0xit\r\n"), None);
    }

    #[test]
    fn strip_telnet_commands_rejects_input_when_negotiation_is_truncated() {
        let data = [b'i', b'd', IAC, DO];

        assert!(strip_telnet_commands(&data).is_empty());
    }
}
