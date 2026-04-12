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
#[derive(Debug, Clone, PartialEq)]
pub enum TelnetState {
    /// Waiting for username input
    WaitingUsername,
    /// Waiting for password input
    WaitingPassword,
    /// Authenticated, in shell mode
    Shell,
    /// Session disconnected
    Disconnected,
}

impl Default for TelnetState {
    fn default() -> Self {
        Self::WaitingUsername
    }
}

/// Parsed telnet data, stripping out IAC sequences
pub fn strip_telnet_commands(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i] == IAC && i + 1 < data.len() {
            match data[i + 1] {
                WILL | WONT | DO | DONT => {
                    // Skip 3-byte command
                    i += 3;
                }
                SB => {
                    // Skip until SE
                    i += 2;
                    while i < data.len() {
                        if data[i] == IAC && i + 1 < data.len() && data[i + 1] == SE {
                            i += 2;
                            break;
                        }
                        i += 1;
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
            // Filter out control characters except newline/carriage return
            if data[i] >= 32 || data[i] == b'\r' || data[i] == b'\n' {
                result.push(data[i]);
            }
            i += 1;
        }
    }
    result
}
