use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Packet error: {0}")]
    Packet(String),

    #[error("Flow error: {0}")]
    Flow(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Interception error: {0}")]
    Interception(String),

    #[error("Attribution error: {0}")]
    Attribution(String),

    #[error("Policy error: {0}")]
    Policy(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Not supported: {0}")]
    NotSupported(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Shutdown requested")]
    Shutdown,

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Buffer overflow")]
    BufferOverflow,

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("NAT error: {0}")]
    Nat(String),
}

pub type Result<T> = std::result::Result<T, Error>;
