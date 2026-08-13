/// SSH protocol message types (RFC 4253)
pub const SSH_MSG_DISCONNECT: u8 = 1;
pub const SSH_MSG_IGNORE: u8 = 2;
pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
pub const SSH_MSG_DEBUG: u8 = 4;
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;
pub const SSH_MSG_KEXINIT: u8 = 20;
pub const SSH_MSG_NEWKEYS: u8 = 21;

/// SSH disconnect reason codes
pub const SSH_DISCONNECT_HOST_NOT_ALLOWED: u32 = 1;
pub const SSH_DISCONNECT_PROTOCOL_ERROR: u32 = 2;
pub const SSH_DISCONNECT_KEY_EXCHANGE_FAILED: u32 = 3;
pub const SSH_DISCONNECT_AUTH_CANCELLED_BY_USER: u32 = 13;

/// SSH session state
#[derive(Debug, Clone, PartialEq, Default)]
pub enum SshState {
    /// Waiting for client version string
    #[default]
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
