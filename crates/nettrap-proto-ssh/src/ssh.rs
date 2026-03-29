/// SSH protocol message types (RFC 4253)
pub const SSH_MSG_DISCONNECT: u8 = 1;
pub const SSH_MSG_IGNORE: u8 = 2;
pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
pub const SSH_MSG_DEBUG: u8 = 4;
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
pub const SSH_MSG_KEXINIT: u8 = 20;
pub const SSH_MSG_NEWKEYS: u8 = 21;

/// SSH disconnect reason codes
pub const SSH_DISCONNECT_HOST_NOT_ALLOWED: u32 = 1;
pub const SSH_DISCONNECT_PROTOCOL_ERROR: u32 = 2;
pub const SSH_DISCONNECT_KEY_EXCHANGE_FAILED: u32 = 3;
pub const SSH_DISCONNECT_AUTH_CANCELLED_BY_USER: u32 = 13;

/// SSH session state
#[derive(Debug, Clone, PartialEq)]
pub enum SshState {
    /// Waiting for client version string
    WaitingVersion,
    /// Version exchanged, performing key exchange
    KeyExchange,
    /// Authentication phase
    Authentication,
    /// Session established
    Session,
    /// Disconnected
    Disconnected,
}

impl Default for SshState {
    fn default() -> Self {
        Self::WaitingVersion
    }
}
