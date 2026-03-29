/// RESP (Redis Serialization Protocol) data types
pub const RESP_SIMPLE_STRING: u8 = b'+';
pub const RESP_ERROR: u8 = b'-';
pub const RESP_INTEGER: u8 = b':';
pub const RESP_BULK_STRING: u8 = b'$';
pub const RESP_ARRAY: u8 = b'*';

/// Known Redis attack patterns
#[derive(Debug, Clone, PartialEq)]
pub enum RedisAttackType {
    /// CONFIG SET dir/dbfilename to write SSH keys
    SshKeyWrite,
    /// CONFIG SET dir/dbfilename to write crontab
    CrontabWrite,
    /// SLAVEOF/REPLICAOF for rogue server attack
    RogueReplication,
    /// MODULE LOAD for arbitrary code execution
    ModuleLoad,
    /// EVAL for Lua script execution
    LuaExecution,
    /// Generic unauthorized access
    Unauthorized,
}

/// Redis session state
#[derive(Debug, Clone, PartialEq)]
pub enum RedisState {
    /// Waiting for commands
    Connected,
    /// Client has authenticated
    Authenticated,
    /// Client disconnected
    Disconnected,
}

impl Default for RedisState {
    fn default() -> Self {
        Self::Connected
    }
}
