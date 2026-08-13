mod client;
mod collections;
mod commands;
mod parser;
mod sorted_sets;
mod state;

use client::{client_tracking_info_payload, client_tracking_response};
use collections::*;
pub(crate) use commands::*;
use sorted_sets::*;

use crate::redis::RedisState;

pub struct RedisHandler {
    version: String,
    require_auth: bool,
    started_at: std::time::Instant,
    now: fn() -> chrono::DateTime<chrono::Utc>,
    client_name: std::sync::Mutex<Option<String>>,
    client_lib_name: std::sync::Mutex<Option<String>>,
    client_lib_ver: std::sync::Mutex<Option<String>>,
    client_reply_mode: std::sync::Mutex<ClientReplyMode>,
    client_no_evict: std::sync::Mutex<bool>,
    client_no_touch: std::sync::Mutex<bool>,
    client_tracking_enabled: std::sync::Mutex<bool>,
    client_tracking_bcast: std::sync::Mutex<bool>,
    client_tracking_optin: std::sync::Mutex<bool>,
    client_tracking_optout: std::sync::Mutex<bool>,
    client_tracking_noloop: std::sync::Mutex<bool>,
    client_tracking_redirect: std::sync::Mutex<i64>,
    client_tracking_prefixes: std::sync::Mutex<Vec<String>>,
    client_tracking_caching: std::sync::Mutex<Option<bool>>,
    client_tracking_broken_redir: std::sync::Mutex<bool>,
    resp_version: std::sync::Mutex<u8>,
    state: std::sync::Mutex<RedisState>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientReplyMode {
    On,
    Off,
    Skip,
}

const DEFAULT_REDIS_VERSION: &str = "7.0.15";
const MAX_RESP_COMMANDS: usize = 1024;
const MAX_RESP_ARRAY_COUNT: usize = 1024;
const MAX_RESP_BULK_SIZE: usize = 64 * 1024;
const MAX_RESP_FRAME_SIZE: usize = 1024 * 1024;
const MAX_INLINE_COMMAND_BYTES: usize = 64 * 1024;
const MAX_INLINE_COMMAND_ARGS: usize = 1024;
const MAX_CLIENT_TRACKING_PREFIXES: usize = 128;
const MAX_CLIENT_TRACKING_PREFIX_BYTES: usize = 1024;
const LOG_ARGS_PREVIEW_CHARS: usize = 240;
const REDACTED_AUTH_FIELD: &str = "***REDACTED***";
const REDACTED_COMMAND_FIELD: &str = "***REDACTED***";

impl RedisHandler {
    pub fn new() -> Self {
        Self {
            version: DEFAULT_REDIS_VERSION.to_string(),
            require_auth: false,
            started_at: std::time::Instant::now(),
            now: chrono::Utc::now,
            client_name: std::sync::Mutex::new(None),
            client_lib_name: std::sync::Mutex::new(None),
            client_lib_ver: std::sync::Mutex::new(None),
            client_reply_mode: std::sync::Mutex::new(ClientReplyMode::On),
            client_no_evict: std::sync::Mutex::new(false),
            client_no_touch: std::sync::Mutex::new(false),
            client_tracking_enabled: std::sync::Mutex::new(false),
            client_tracking_bcast: std::sync::Mutex::new(false),
            client_tracking_optin: std::sync::Mutex::new(false),
            client_tracking_optout: std::sync::Mutex::new(false),
            client_tracking_noloop: std::sync::Mutex::new(false),
            client_tracking_redirect: std::sync::Mutex::new(-1),
            client_tracking_prefixes: std::sync::Mutex::new(Vec::new()),
            client_tracking_caching: std::sync::Mutex::new(None),
            client_tracking_broken_redir: std::sync::Mutex::new(false),
            resp_version: std::sync::Mutex::new(2),
            state: std::sync::Mutex::new(RedisState::Connected),
        }
    }

    pub fn with_auth(mut self, require: bool) -> Self {
        self.require_auth = require;
        self
    }

    pub fn with_now(mut self, now: fn() -> chrono::DateTime<chrono::Utc>) -> Self {
        self.now = now;
        self
    }

    pub fn handle_command(&self, data: &[u8]) -> Vec<u8> {
        let mut authenticated = !self.require_auth;
        self.handle_command_with_auth_state(data, &mut authenticated)
    }

    pub fn handle_command_with_auth_state(&self, data: &[u8], authenticated: &mut bool) -> Vec<u8> {
        if self.current_state() == RedisState::Disconnected {
            return Vec::new();
        }

        let Some(commands) = Self::parse_resp(data) else {
            return if data.is_empty() {
                Vec::new()
            } else {
                b"-ERR Protocol error\r\n".to_vec()
            };
        };

        let mut response = Vec::new();
        let mut saw_command = false;
        let mut saw_reply = false;
        for cmd_parts in commands {
            if self.current_state() == RedisState::Disconnected {
                break;
            }
            if cmd_parts.is_empty() {
                continue;
            }
            saw_command = true;
            let Some(cmd) = text_command(&cmd_parts[0]) else {
                response.extend_from_slice(b"-ERR Protocol error\r\n");
                saw_reply = true;
                continue;
            };
            let cmd = cmd.to_uppercase();
            let args = &cmd_parts[1..];
            let caching_before = self.client_tracking_caching();
            let is_client_reply_cmd = cmd == "CLIENT"
                && matches!(
                    args.first().and_then(|arg| text_command(arg)),
                    Some(value) if value.eq_ignore_ascii_case("REPLY")
                );
            let is_client_caching_cmd = cmd == "CLIENT"
                && matches!(
                    args.first().and_then(|arg| text_command(arg)),
                    Some(value) if value.eq_ignore_ascii_case("CACHING")
                );
            let is_hello_auth_cmd = cmd == "HELLO" && hello_has_auth(args);

            if self.require_auth
                && !*authenticated
                && cmd != "AUTH"
                && cmd != "RESET"
                && !is_hello_auth_cmd
            {
                response.extend_from_slice(b"-NOAUTH Authentication required.\r\n");
                saw_reply = true;
                continue;
            }

            let reply_mode_before = self.current_reply_mode();
            let resp = match cmd.as_str() {
                "PING" => ping_response(args),
                "ECHO" => echo_response(args),
                "HELLO" => hello_response(self, args, authenticated, &self.version),
                "INFO" => match text_args(args) {
                    Some(args) if args.len() > 1 => wrong_number_of_arguments("info").into_bytes(),
                    Some(_) => {
                        let info =
                            redis_info_payload(&self.version, self.started_at.elapsed().as_secs());
                        format!("${}\r\n{}\r\n", info.len(), info).into_bytes()
                    }
                    None => protocol_error(),
                },
                "TIME" => time_response(args, (self.now)()),
                "AUTH" => Self::handle_auth_command(args, authenticated),
                "ROLE" => role_response(args),
                "SET" => set_response(args),
                "SETEX" => setex_response(args, "setex"),
                "PSETEX" => setex_response(args, "psetex"),
                "SETNX" => setnx_response(args),
                "MSET" => mset_response(args, "mset"),
                "MSETNX" => mset_response(args, "msetnx"),
                "APPEND" => append_response(args),
                "INCR" => incr_decr_response(args, "incr", 1),
                "DECR" => incr_decr_response(args, "decr", -1),
                "INCRBY" => incrby_decrby_response(args, "incrby", 1),
                "DECRBY" => incrby_decrby_response(args, "decrby", -1),
                "HSET" => hash_set_response(args, "hset"),
                "HSETNX" => hash_set_nx_response(args),
                "HGET" => hash_get_response(args),
                "HDEL" => hash_del_response(args),
                "HEXISTS" => hash_exists_response(args),
                "HLEN" => hash_len_response(args),
                "HMGET" => hash_mget_response(args),
                "SADD" => set_add_response(args),
                "SREM" => set_remove_response(args),
                "SISMEMBER" => set_member_response(args),
                "SCARD" => set_card_response(args),
                "SMEMBERS" => set_members_response(args),
                "SMISMEMBER" => set_multi_member_response(args),
                "LPUSH" => list_push_response(args, "lpush"),
                "RPUSH" => list_push_response(args, "rpush"),
                "LPOP" => list_pop_response(args, "lpop"),
                "RPOP" => list_pop_response(args, "rpop"),
                "LLEN" => list_len_response(args),
                "LRANGE" => list_range_response(args),
                "LINDEX" => list_index_response(args),
                "GETBIT" => getbit_response(args),
                "SETBIT" => setbit_response(args),
                "BITCOUNT" => bitcount_response(args),
                "PFADD" => pfadd_response(args),
                "PFCOUNT" => pfcount_response(args),
                "PFMERGE" => pfmerge_response(args),
                "PUBLISH" => publish_response(args),
                "PUBSUB" => pubsub_response(args),
                "KEYS" => keys_response(args),
                "RANDOMKEY" => randomkey_response(args),
                "SCAN" => scan_response(args),
                "ZCARD" => sorted_set_card_response(args),
                "ZADD" => sorted_set_add_response(args),
                "ZCOUNT" => sorted_set_count_response(args),
                "ZINCRBY" => sorted_set_incr_response(args),
                "ZDIFFSTORE" => sorted_set_diff_store_response(args),
                "ZINTERSTORE" => sorted_set_inter_store_response(args),
                "ZUNIONSTORE" => sorted_set_union_store_response(args),
                "ZRANGE" => sorted_set_range_response(args, "zrange"),
                "ZREVRANGE" => sorted_set_range_response(args, "zrevrange"),
                "ZREM" => sorted_set_remove_response(args),
                "ZSCORE" => sorted_set_score_response(args),
                "ZRANK" => sorted_set_rank_response(args, "zrank"),
                "ZREVRANK" => sorted_set_rank_response(args, "zrevrank"),
                "ZMSCORE" => sorted_set_mscore_response(args),
                "ZRANDMEMBER" => sorted_set_random_member_response(args),
                "SORT" => sort_response(args, true),
                "SORT_RO" => sort_response(args, false),
                "ZRANGESTORE" => sorted_set_range_store_response(args),
                "TOUCH" => touch_response(args),
                "UNLINK" => unlink_response(args),
                "MOVE" => move_response(args),
                "COPY" => copy_response(args),
                "GET" => {
                    if args.len() == 1 {
                        b"$-1\r\n".to_vec()
                    } else {
                        wrong_number_of_arguments("get").into_bytes()
                    }
                }
                "GETSET" => getset_response(args),
                "GETDEL" => getdel_response(args),
                "DEL" => del_response(args),
                "EXISTS" => exists_response(args),
                "MGET" => mget_response(args),
                "TTL" => ttl_response(args, "ttl"),
                "PTTL" => ttl_response(args, "pttl"),
                "EXPIRETIME" => expiretime_response(args, "expiretime"),
                "PEXPIRETIME" => expiretime_response(args, "pexpiretime"),
                "EXPIRE" => expire_response(args, "expire"),
                "PEXPIRE" => expire_response(args, "pexpire"),
                "EXPIREAT" => expire_response(args, "expireat"),
                "PEXPIREAT" => expire_response(args, "pexpireat"),
                "TYPE" => type_response(args),
                "STRLEN" => strlen_response(args),
                "CONFIG" => Self::handle_config_command(args),
                "SLAVEOF" => replication_response("slaveof", args),
                "REPLICAOF" => replication_response("replicaof", args),
                "MODULE" => {
                    if args.is_empty() {
                        wrong_number_of_arguments("module").into_bytes()
                    } else {
                        tracing::warn!("REDIS MODULE LOAD attempt");
                        b"-ERR Module loading is disabled\r\n".to_vec()
                    }
                }
                "EVAL" => Self::handle_eval_command(args),
                "EVALSHA" => eval_response("evalsha", args),
                "FLUSHALL" => flush_response("flushall", args),
                "FLUSHDB" => flush_response("flushdb", args),
                "DBSIZE" => {
                    if args.is_empty() {
                        b":0\r\n".to_vec()
                    } else {
                        wrong_number_of_arguments("dbsize").into_bytes()
                    }
                }
                "SELECT" => select_response(args),
                "RESET" => Self::handle_reset_command(self, authenticated, args),
                "QUIT" => {
                    if args.is_empty() {
                        self.set_state(RedisState::Disconnected);
                        b"+OK\r\n".to_vec()
                    } else {
                        wrong_number_of_arguments("quit").into_bytes()
                    }
                }
                "COMMAND" => {
                    if args.is_empty() {
                        b"*0\r\n".to_vec()
                    } else {
                        wrong_number_of_arguments("command").into_bytes()
                    }
                }
                "CLUSTER" => {
                    if args.is_empty() {
                        wrong_number_of_arguments("cluster").into_bytes()
                    } else {
                        b"-ERR This instance has cluster support disabled\r\n".to_vec()
                    }
                }
                "CLIENT" => client_response(self, args),
                "SAVE" => save_response("save", args),
                "BGSAVE" => bgsave_response(args),
                _ => b"-ERR unknown command\r\n".to_vec(),
            };
            if caching_before.is_some() && !is_client_caching_cmd {
                self.set_client_tracking_caching(None);
            }
            if reply_mode_before == ClientReplyMode::Skip {
                if !is_client_reply_cmd {
                    self.set_reply_mode(ClientReplyMode::On);
                }
                continue;
            }
            if reply_mode_before == ClientReplyMode::Off {
                continue;
            }
            if !resp.is_empty() {
                response.extend_from_slice(&resp);
                saw_reply = true;
            }
        }

        if !saw_command && !data.is_empty() {
            b"-ERR Protocol error\r\n".to_vec()
        } else if !saw_reply {
            Vec::new()
        } else {
            response
        }
    }

    fn handle_auth_command(args: &[Vec<u8>], authenticated: &mut bool) -> Vec<u8> {
        // Capture credentials: AUTH [username] password
        // Always accept (honeypot) and mark this connection authenticated.
        if !auth_args_are_valid_bytes(args) {
            tracing::warn!("REDIS AUTH attempt with missing credentials");
            b"-ERR wrong number of arguments for 'auth' command\r\n".to_vec()
        } else if args.len() == 2 {
            tracing::debug!(
                "REDIS AUTH attempt: username='{}', password='{}'",
                nettrap_core::sanitize::single_line_bytes(&args[0]),
                nettrap_core::sanitize::single_line_bytes(&args[1])
            );
            tracing::warn!(
                "REDIS AUTH attempt: username='{}', password='{}'",
                REDACTED_AUTH_FIELD,
                REDACTED_AUTH_FIELD
            );
            *authenticated = true;
            b"+OK\r\n".to_vec()
        } else {
            tracing::debug!(
                "REDIS AUTH attempt: password='{}'",
                nettrap_core::sanitize::single_line_bytes(&args[0])
            );
            tracing::warn!("REDIS AUTH attempt: password='{}'", REDACTED_AUTH_FIELD);
            *authenticated = true;
            b"+OK\r\n".to_vec()
        }
    }

    fn handle_reset_command(&self, authenticated: &mut bool, args: &[Vec<u8>]) -> Vec<u8> {
        if !args.is_empty() {
            return wrong_number_of_arguments("reset").into_bytes();
        }

        tracing::warn!("REDIS RESET connection state");
        self.set_client_name(None);
        self.set_client_lib_name(None);
        self.set_client_lib_ver(None);
        self.set_reply_mode(ClientReplyMode::On);
        self.set_client_no_evict(false);
        self.set_client_no_touch(false);
        self.set_client_tracking_enabled(false);
        self.set_client_tracking_bcast(false);
        self.set_client_tracking_optin(false);
        self.set_client_tracking_optout(false);
        self.set_client_tracking_noloop(false);
        self.set_client_tracking_redirect(-1);
        self.set_client_tracking_prefixes(Vec::new());
        self.set_client_tracking_caching(None);
        self.set_client_tracking_broken_redir(false);
        self.set_resp_version(2);
        *authenticated = !self.require_auth;
        b"+RESET\r\n".to_vec()
    }

    fn handle_config_command(args: &[Vec<u8>]) -> Vec<u8> {
        let Some(args) = text_args(args) else {
            return protocol_error();
        };
        if args.is_empty() {
            wrong_number_of_arguments("config").into_bytes()
        } else {
            let subcommand = args[0].to_uppercase();
            if subcommand == "SET" {
                if args.len() < 3 || args.len() % 2 == 0 {
                    wrong_number_of_arguments("config|set").into_bytes()
                } else {
                    tracing::debug!("REDIS CONFIG SET attempt: {}", safe_log_args(&args));
                    tracing::warn!(
                        "REDIS CONFIG SET attempt: {} argument(s)",
                        args.len().saturating_sub(1)
                    );
                    b"+OK\r\n".to_vec()
                }
            } else if subcommand == "GET" {
                if args.len() != 2 {
                    wrong_number_of_arguments("config|get").into_bytes()
                } else {
                    config_get_response(args[1])
                }
            } else {
                b"-ERR unknown CONFIG subcommand\r\n".to_vec()
            }
        }
    }

    fn handle_eval_command(args: &[Vec<u8>]) -> Vec<u8> {
        eval_response("eval", args)
    }
}

impl Default for RedisHandler {
    fn default() -> Self {
        Self::new()
    }
}

fn redis_info_payload(version: &str, uptime_secs: u64) -> String {
    let uptime_days = uptime_secs / 86_400;
    format!(
        "# Server\r\nredis_version:{version}\r\nos:Linux\r\narch_bits:64\r\ntcp_port:6379\r\nuptime_in_seconds:{uptime_secs}\r\nuptime_in_days:{uptime_days}\r\n\r\n# Clients\r\nconnected_clients:1\r\n\r\n# Memory\r\nused_memory:1000000\r\nused_memory_human:976.56K\r\n"
    )
}

fn protocol_error() -> Vec<u8> {
    b"-ERR Protocol error\r\n".to_vec()
}

fn text_command(value: &[u8]) -> Option<&str> {
    std::str::from_utf8(value).ok()
}

fn text_args(args: &[Vec<u8>]) -> Option<Vec<&str>> {
    args.iter().map(|arg| text_command(arg)).collect()
}

fn hello_has_auth(args: &[Vec<u8>]) -> bool {
    args.iter()
        .skip(1)
        .any(|arg| text_command(arg).is_some_and(|value| value.eq_ignore_ascii_case("AUTH")))
}

fn set_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() < 2 {
        return wrong_number_of_arguments("set").into_bytes();
    }

    let mut index = 2usize;
    let mut saw_expiry = false;
    let mut saw_condition = false;
    let mut saw_get = false;
    while index < args.len() {
        let Some(option) = text_command(&args[index]).map(|value| value.to_ascii_uppercase())
        else {
            return protocol_error();
        };
        match option.as_str() {
            "EX" | "PX" | "EXAT" | "PXAT" => {
                if saw_expiry {
                    return syntax_error().into_bytes();
                }
                saw_expiry = true;
                index += 1;
                let Some(expiry) = args.get(index) else {
                    return syntax_error().into_bytes();
                };
                if parse_unsigned_decimal_bytes::<u64>(expiry).is_none_or(|value| value == 0) {
                    return b"-ERR invalid expire time in 'set' command\r\n".to_vec();
                }
            }
            "KEEPTTL" => {
                if saw_expiry {
                    return syntax_error().into_bytes();
                }
                saw_expiry = true;
            }
            "NX" | "XX" => {
                if saw_condition {
                    return syntax_error().into_bytes();
                }
                saw_condition = true;
            }
            "IFEQ" | "IFNE" | "IFDEQ" | "IFDNE" => {
                if saw_condition {
                    return syntax_error().into_bytes();
                }
                saw_condition = true;
                index += 1;
                if args.get(index).is_none() {
                    return syntax_error().into_bytes();
                }
            }
            "GET" => {
                if saw_get {
                    return syntax_error().into_bytes();
                }
                saw_get = true;
            }
            _ => return syntax_error().into_bytes(),
        }
        index += 1;
    }

    tracing::debug!("REDIS SET attempt: {}", safe_log_bytes_args(args));
    tracing::warn!("REDIS SET attempt: {} argument(s)", args.len());
    if saw_get {
        b"$-1\r\n".to_vec()
    } else {
        b"+OK\r\n".to_vec()
    }
}

fn replication_response(command: &str, args: &[Vec<u8>]) -> Vec<u8> {
    let Some(args) = text_args(args) else {
        return protocol_error();
    };
    if args.len() != 2 {
        return wrong_number_of_arguments(command).into_bytes();
    }

    if args[0].eq_ignore_ascii_case("NO") && args[1].eq_ignore_ascii_case("ONE") {
        tracing::debug!(
            "REDIS REPLICATION disable attempt: {}",
            safe_log_args(&args)
        );
        tracing::warn!(
            "REDIS REPLICATION disable attempt: {}",
            REDACTED_COMMAND_FIELD
        );
        return b"+OK\r\n".to_vec();
    }

    if args[0].is_empty() || !is_valid_replication_host(args[0]) {
        return b"-ERR invalid host\r\n".to_vec();
    }

    if parse_unsigned_decimal_bytes::<u16>(args[1].as_bytes()).is_none_or(|port| port == 0) {
        return b"-ERR invalid port\r\n".to_vec();
    }

    tracing::debug!("REDIS REPLICATION attempt: {}", safe_log_args(&args));
    tracing::warn!("REDIS REPLICATION attempt: {}", REDACTED_COMMAND_FIELD);
    b"+OK\r\n".to_vec()
}

fn eval_response(command: &str, args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() < 2 {
        return wrong_number_of_arguments(command).into_bytes();
    }

    let Some(key_count) = parse_unsigned_decimal_bytes::<usize>(&args[1]) else {
        return b"-ERR value is not an integer or out of range\r\n".to_vec();
    };

    if key_count > args.len().saturating_sub(2) {
        return b"-ERR Number of keys can't be greater than number of args\r\n".to_vec();
    }

    let Some(log_args) = text_args(args) else {
        return protocol_error();
    };
    tracing::debug!("REDIS EVAL/LUA attempt: {}", safe_log_args(&log_args));
    tracing::warn!("REDIS EVAL/LUA attempt: {} argument(s)", log_args.len());
    b"+OK\r\n".to_vec()
}

fn flush_response(command: &str, args: &[Vec<u8>]) -> Vec<u8> {
    match args {
        [] => {
            tracing::warn!("REDIS FLUSH attempt: {}", command);
            b"+OK\r\n".to_vec()
        }
        [mode] => {
            let Some(mode) = text_command(mode) else {
                return protocol_error();
            };
            if mode.eq_ignore_ascii_case("ASYNC") || mode.eq_ignore_ascii_case("SYNC") {
                tracing::warn!(
                    "REDIS FLUSH attempt: {} {}",
                    command,
                    nettrap_core::sanitize::single_line(mode)
                );
                b"+OK\r\n".to_vec()
            } else {
                syntax_error().into_bytes()
            }
        }
        _ => wrong_number_of_arguments(command).into_bytes(),
    }
}

fn select_response(args: &[Vec<u8>]) -> Vec<u8> {
    let Some(args) = text_args(args) else {
        return protocol_error();
    };
    match args.as_slice() {
        [index] if parse_unsigned_decimal_bytes::<u64>(index.as_bytes()).is_some() => {
            b"+OK\r\n".to_vec()
        }
        [_] => b"-ERR invalid DB index\r\n".to_vec(),
        _ => wrong_number_of_arguments("select").into_bytes(),
    }
}

fn client_response(handler: &RedisHandler, args: &[Vec<u8>]) -> Vec<u8> {
    let Some((subcommand, rest)) = args.split_first() else {
        return wrong_number_of_arguments("client").into_bytes();
    };
    let Some(subcommand) = text_command(subcommand) else {
        return protocol_error();
    };

    match subcommand.to_ascii_uppercase().as_str() {
        "SETNAME" => match rest {
            [name] => match parse_redis_client_name(name) {
                Ok(client_name) => {
                    tracing::debug!(
                        "REDIS CLIENT SETNAME attempt: {}",
                        nettrap_core::sanitize::single_line_bytes(name)
                    );
                    tracing::warn!("REDIS CLIENT SETNAME attempt: {}", REDACTED_COMMAND_FIELD);
                    handler.set_client_name(client_name);
                    b"+OK\r\n".to_vec()
                }
                Err(_) => b"-ERR invalid client name\r\n".to_vec(),
            },
            _ => wrong_number_of_arguments("client|setname").into_bytes(),
        },
        "SETINFO" => match rest {
            [attr, value] => {
                let Some(attr) = text_command(attr) else {
                    return protocol_error();
                };
                let Ok(value) = parse_redis_client_info_value(value) else {
                    return b"-ERR invalid client info value\r\n".to_vec();
                };

                match attr.to_ascii_uppercase().as_str() {
                    "LIB-NAME" => {
                        handler.set_client_lib_name(value);
                        b"+OK\r\n".to_vec()
                    }
                    "LIB-VER" => {
                        handler.set_client_lib_ver(value);
                        b"+OK\r\n".to_vec()
                    }
                    _ => b"-ERR invalid client info attribute\r\n".to_vec(),
                }
            }
            _ => wrong_number_of_arguments("client|setinfo").into_bytes(),
        },
        "REPLY" => match rest {
            [mode] => {
                let Some(mode) = text_command(mode) else {
                    return protocol_error();
                };
                match mode.to_ascii_uppercase().as_str() {
                    "ON" => {
                        handler.set_reply_mode(ClientReplyMode::On);
                        b"+OK\r\n".to_vec()
                    }
                    "OFF" => {
                        handler.set_reply_mode(ClientReplyMode::Off);
                        Vec::new()
                    }
                    "SKIP" => {
                        handler.set_reply_mode(ClientReplyMode::Skip);
                        Vec::new()
                    }
                    _ => b"-ERR invalid CLIENT REPLY mode\r\n".to_vec(),
                }
            }
            _ => wrong_number_of_arguments("client|reply").into_bytes(),
        },
        "CACHING" => match rest {
            [mode] => {
                let Some(mode) = text_command(mode) else {
                    return protocol_error();
                };
                if mode.eq_ignore_ascii_case("YES") || mode.eq_ignore_ascii_case("NO") {
                    if !handler.client_tracking_enabled()
                        || !(handler.client_tracking_optin() || handler.client_tracking_optout())
                    {
                        return b"-ERR CLIENT CACHING can only be called when tracking is enabled in OPTIN or OPTOUT mode\r\n"
                            .to_vec();
                    }
                    if mode.eq_ignore_ascii_case("YES") && !handler.client_tracking_optin() {
                        return b"-ERR CLIENT CACHING YES can only be called when tracking is enabled in OPTIN mode\r\n"
                            .to_vec();
                    }
                    if mode.eq_ignore_ascii_case("NO") && !handler.client_tracking_optout() {
                        return b"-ERR CLIENT CACHING NO can only be called when tracking is enabled in OPTOUT mode\r\n"
                            .to_vec();
                    }
                    handler.set_client_tracking_caching(Some(mode.eq_ignore_ascii_case("YES")));
                    b"+OK\r\n".to_vec()
                } else {
                    b"-ERR argument must be yes or no\r\n".to_vec()
                }
            }
            _ => wrong_number_of_arguments("client|caching").into_bytes(),
        },
        "TRACKING" => client_tracking_response(handler, rest),
        "TRACKINGINFO" => {
            if rest.is_empty() {
                let info = client_tracking_info_payload(handler);
                info.into_bytes()
            } else {
                wrong_number_of_arguments("client|trackinginfo").into_bytes()
            }
        }
        "NO-EVICT" => match rest {
            [mode] => {
                let Some(mode) = text_command(mode) else {
                    return protocol_error();
                };
                match mode.to_ascii_uppercase().as_str() {
                    "ON" => {
                        handler.set_client_no_evict(true);
                        b"+OK\r\n".to_vec()
                    }
                    "OFF" => {
                        handler.set_client_no_evict(false);
                        b"+OK\r\n".to_vec()
                    }
                    _ => b"-ERR invalid CLIENT NO-EVICT mode\r\n".to_vec(),
                }
            }
            _ => wrong_number_of_arguments("client|no-evict").into_bytes(),
        },
        "NO-TOUCH" => match rest {
            [mode] => {
                let Some(mode) = text_command(mode) else {
                    return protocol_error();
                };
                match mode.to_ascii_uppercase().as_str() {
                    "ON" => {
                        handler.set_client_no_touch(true);
                        b"+OK\r\n".to_vec()
                    }
                    "OFF" => {
                        handler.set_client_no_touch(false);
                        b"+OK\r\n".to_vec()
                    }
                    _ => b"-ERR invalid CLIENT NO-TOUCH mode\r\n".to_vec(),
                }
            }
            _ => wrong_number_of_arguments("client|no-touch").into_bytes(),
        },
        "ID" => {
            if rest.is_empty() {
                b":1\r\n".to_vec()
            } else {
                wrong_number_of_arguments("client|id").into_bytes()
            }
        }
        "INFO" => {
            if rest.is_empty() {
                let info = redis_client_payload(
                    "client|info",
                    handler.client_name().as_deref(),
                    handler.client_lib_name().as_deref(),
                    handler.client_lib_ver().as_deref(),
                    &handler.client_flags(),
                    handler.client_tracking_redirect(),
                    handler.resp_version(),
                );
                format!("${}\r\n{}\r\n", info.len(), info).into_bytes()
            } else {
                wrong_number_of_arguments("client|info").into_bytes()
            }
        }
        "GETNAME" => {
            if rest.is_empty() {
                match handler.client_name() {
                    Some(name) => format!("${}\r\n{}\r\n", name.len(), name).into_bytes(),
                    None => b"$-1\r\n".to_vec(),
                }
            } else {
                wrong_number_of_arguments("client|getname").into_bytes()
            }
        }
        "GETREDIR" => {
            if rest.is_empty() {
                format!(":{}\r\n", handler.client_tracking_redirect()).into_bytes()
            } else {
                wrong_number_of_arguments("client|getredir").into_bytes()
            }
        }
        "LIST" => {
            if rest.is_empty() {
                let listing = redis_client_payload(
                    "client|list",
                    handler.client_name().as_deref(),
                    handler.client_lib_name().as_deref(),
                    handler.client_lib_ver().as_deref(),
                    &handler.client_flags(),
                    handler.client_tracking_redirect(),
                    handler.resp_version(),
                );
                format!("${}\r\n{}\r\n", listing.len(), listing).into_bytes()
            } else {
                wrong_number_of_arguments("client|list").into_bytes()
            }
        }
        "HELP" => {
            if rest.is_empty() {
                b"*14\r\n$7\r\nGETNAME\r\n$2\r\nID\r\n$4\r\nINFO\r\n$4\r\nLIST\r\n$7\r\nSETINFO\r\n$7\r\nSETNAME\r\n$8\r\nGETREDIR\r\n$7\r\nCACHING\r\n$6\r\nREPLY\r\n$8\r\nNO-TOUCH\r\n$8\r\nNO-EVICT\r\n$8\r\nTRACKING\r\n$12\r\nTRACKINGINFO\r\n$4\r\nHELP\r\n"
                    .to_vec()
            } else {
                wrong_number_of_arguments("client|help").into_bytes()
            }
        }
        _ => b"-ERR unknown CLIENT subcommand\r\n".to_vec(),
    }
}

fn save_response(command: &str, args: &[Vec<u8>]) -> Vec<u8> {
    if args.is_empty() {
        tracing::warn!("REDIS SAVE attempt (RDB dump attack)");
        b"+OK\r\n".to_vec()
    } else {
        wrong_number_of_arguments(command).into_bytes()
    }
}

fn bgsave_response(args: &[Vec<u8>]) -> Vec<u8> {
    match args {
        [] => {
            tracing::warn!("REDIS BGSAVE attempt (RDB dump attack)");
            b"+OK\r\n".to_vec()
        }
        [mode] => {
            let Some(mode) = text_command(mode) else {
                return protocol_error();
            };
            if mode.eq_ignore_ascii_case("SCHEDULE") {
                tracing::warn!("REDIS BGSAVE SCHEDULE attempt (RDB dump attack)");
                b"+OK\r\n".to_vec()
            } else {
                syntax_error().into_bytes()
            }
        }
        _ => wrong_number_of_arguments("bgsave").into_bytes(),
    }
}

fn config_get_response(pattern: &str) -> Vec<u8> {
    const CONFIG_VALUES: [(&str, &str); 5] = [
        ("dir", "/tmp/"),
        ("dbfilename", "dump.rdb"),
        ("save", "3600 1 300 100 60 10000"),
        ("maxmemory", "0"),
        ("bind", "0.0.0.0"),
    ];

    let pattern = pattern.to_ascii_lowercase();
    let mut entries = Vec::new();
    for (key, value) in CONFIG_VALUES {
        if glob_match_config_pattern(&pattern, key) {
            entries.push((key, value));
        }
    }

    let mut response = Vec::new();
    response.extend_from_slice(b"*");
    response.extend_from_slice((entries.len() * 2).to_string().as_bytes());
    response.extend_from_slice(b"\r\n");
    for (key, value) in entries {
        response.extend_from_slice(b"$");
        response.extend_from_slice(key.len().to_string().as_bytes());
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(key.as_bytes());
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(b"$");
        response.extend_from_slice(value.len().to_string().as_bytes());
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(value.as_bytes());
        response.extend_from_slice(b"\r\n");
    }
    response
}

fn glob_match_config_pattern(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let mut p = 0usize;
    let mut t = 0usize;
    let mut star = None;
    let mut match_t = 0usize;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p].eq_ignore_ascii_case(&text[t])) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            match_t = t;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            match_t += 1;
            t = match_t;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }

    p == pattern.len()
}

fn ping_response(args: &[Vec<u8>]) -> Vec<u8> {
    match args {
        [] => b"+PONG\r\n".to_vec(),
        [message] => {
            let mut response = Vec::with_capacity(message.len() + 4);
            response.extend_from_slice(b"$");
            response.extend_from_slice(message.len().to_string().as_bytes());
            response.extend_from_slice(b"\r\n");
            response.extend_from_slice(message);
            response.extend_from_slice(b"\r\n");
            response
        }
        _ => wrong_number_of_arguments("ping").into_bytes(),
    }
}

fn echo_response(args: &[Vec<u8>]) -> Vec<u8> {
    match args {
        [message] => {
            let mut response = Vec::with_capacity(message.len() + 4);
            response.extend_from_slice(b"$");
            response.extend_from_slice(message.len().to_string().as_bytes());
            response.extend_from_slice(b"\r\n");
            response.extend_from_slice(message);
            response.extend_from_slice(b"\r\n");
            response
        }
        _ => wrong_number_of_arguments("echo").into_bytes(),
    }
}

fn redis_client_payload(
    command: &str,
    client_name: Option<&str>,
    client_lib_name: Option<&str>,
    client_lib_ver: Option<&str>,
    client_flags: &str,
    redir: i64,
    resp: u8,
) -> String {
    let client_name = client_name.unwrap_or("");
    let client_lib_name = client_lib_name.unwrap_or("");
    let client_lib_ver = client_lib_ver.unwrap_or("");
    format!(
        "id=1 addr=127.0.0.1:0 laddr=127.0.0.1:0 fd=1 name={} age=0 idle=0 flags={} db=0 sub=0 psub=0 ssub=0 multi=-1 watch=0 qbuf=0 qbuf-free=0 argv-mem=0 multi-mem=0 rbs=0 rbp=0 obl=0 oll=0 omem=0 tot-mem=0 events=r cmd={} user=default redir={} resp={} lib-name={} lib-ver={} io-thread=0 tot-net-in=0 tot-net-out=0 tot-cmds=0",
        client_name, client_flags, command, redir, resp, client_lib_name, client_lib_ver
    )
}

fn parse_redis_client_name(value: &[u8]) -> Result<Option<String>, ()> {
    if value.is_empty() {
        return Ok(None);
    }

    let value = std::str::from_utf8(value).map_err(|_| ())?;
    if value
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(());
    }

    Ok(Some(value.to_owned()))
}

fn parse_redis_client_info_value(value: &[u8]) -> Result<Option<String>, ()> {
    if value.is_empty() {
        return Ok(Some(String::new()));
    }

    let value = std::str::from_utf8(value).map_err(|_| ())?;
    if value
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(());
    }

    Ok(Some(value.to_owned()))
}

fn hello_response(
    handler: &RedisHandler,
    args: &[Vec<u8>],
    authenticated: &mut bool,
    version: &str,
) -> Vec<u8> {
    let current_resp = handler.resp_version();
    let Some(protover) = args.first() else {
        let resp_version = if current_resp >= 3 { 3 } else { 2 };
        return hello_payload(version, resp_version);
    };
    let Some(protover) = text_command(protover) else {
        return protocol_error();
    };
    let resp_version = match protover {
        "2" => 2,
        "3" => 3,
        _ if args.len() > 1 && !protover.chars().all(|c| c.is_ascii_digit()) => {
            return wrong_number_of_arguments("hello").into_bytes();
        }
        _ => return b"-NOPROTO unsupported protocol version\r\n".to_vec(),
    };

    let mut index = 1usize;
    let mut saw_auth = false;
    let mut saw_setname = false;
    let mut pending_client_name: Option<Option<String>> = None;
    let mut pending_authenticated = *authenticated;
    while index < args.len() {
        let Some(option) = text_command(&args[index]) else {
            return protocol_error();
        };
        match option.to_ascii_uppercase().as_str() {
            "AUTH" => {
                if saw_auth {
                    return syntax_error().into_bytes();
                }
                let Some(username) = args.get(index + 1) else {
                    return wrong_number_of_arguments("hello").into_bytes();
                };
                let Some(password) = args.get(index + 2) else {
                    return wrong_number_of_arguments("hello").into_bytes();
                };
                let auth_args = [username.clone(), password.clone()];
                let auth_reply =
                    RedisHandler::handle_auth_command(&auth_args, &mut pending_authenticated);
                if auth_reply != b"+OK\r\n".to_vec() {
                    return auth_reply;
                }
                saw_auth = true;
                index += 3;
            }
            "SETNAME" => {
                if saw_setname {
                    return syntax_error().into_bytes();
                }
                let Some(name) = args.get(index + 1) else {
                    return wrong_number_of_arguments("hello").into_bytes();
                };
                match parse_redis_client_name(name) {
                    Ok(client_name) => {
                        pending_client_name = Some(client_name);
                        saw_setname = true;
                        index += 2;
                    }
                    Err(_) => return b"-ERR invalid client name\r\n".to_vec(),
                }
            }
            _ => return syntax_error().into_bytes(),
        }
    }

    if saw_auth {
        *authenticated = pending_authenticated;
    }
    if let Some(client_name) = pending_client_name {
        handler.set_client_name(client_name);
    }
    handler.set_resp_version(resp_version);
    hello_payload(version, resp_version)
}

fn hello_payload(version: &str, resp_version: u8) -> Vec<u8> {
    let mut response = Vec::new();
    if resp_version == 3 {
        response.extend_from_slice(b"%7\r\n");
        response.extend_from_slice(b"$6\r\nserver\r\n$5\r\nredis\r\n");
        response.extend_from_slice(b"$7\r\nversion\r\n$");
        response.extend_from_slice(version.len().to_string().as_bytes());
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(version.as_bytes());
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(b"$5\r\nproto\r\n:3\r\n");
        response.extend_from_slice(b"$2\r\nid\r\n:1\r\n");
        response.extend_from_slice(b"$4\r\nmode\r\n$10\r\nstandalone\r\n");
        response.extend_from_slice(b"$4\r\nrole\r\n$6\r\nmaster\r\n");
        response.extend_from_slice(b"$7\r\nmodules\r\n*0\r\n");
    } else {
        response.extend_from_slice(b"*14\r\n");
        response.extend_from_slice(b"$6\r\nserver\r\n$5\r\nredis\r\n");
        response.extend_from_slice(b"$7\r\nversion\r\n$");
        response.extend_from_slice(version.len().to_string().as_bytes());
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(version.as_bytes());
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(b"$5\r\nproto\r\n:2\r\n");
        response.extend_from_slice(b"$2\r\nid\r\n:1\r\n");
        response.extend_from_slice(b"$4\r\nmode\r\n$10\r\nstandalone\r\n");
        response.extend_from_slice(b"$4\r\nrole\r\n$6\r\nmaster\r\n");
        response.extend_from_slice(b"$7\r\nmodules\r\n*0\r\n");
    }

    response
}

fn time_response(args: &[Vec<u8>], now: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
    if !args.is_empty() {
        return wrong_number_of_arguments("time").into_bytes();
    }
    let seconds = now.timestamp();
    let micros = now.timestamp_subsec_micros();
    format!(
        "*2\r\n${}\r\n{}\r\n${}\r\n{:06}\r\n",
        seconds.to_string().len(),
        seconds,
        6,
        micros
    )
    .into_bytes()
}

fn role_response(args: &[Vec<u8>]) -> Vec<u8> {
    if !args.is_empty() {
        return wrong_number_of_arguments("role").into_bytes();
    }
    b"*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n".to_vec()
}

fn mget_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.is_empty() {
        return wrong_number_of_arguments("mget").into_bytes();
    }

    let mut response = Vec::with_capacity(args.len() * 5 + 8);
    response.extend_from_slice(b"*");
    response.extend_from_slice(args.len().to_string().as_bytes());
    response.extend_from_slice(b"\r\n");
    for _ in args {
        response.extend_from_slice(b"$-1\r\n");
    }
    response
}

fn getset_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 2 {
        return wrong_number_of_arguments("getset").into_bytes();
    }
    b"$-1\r\n".to_vec()
}

fn getdel_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 1 {
        return wrong_number_of_arguments("getdel").into_bytes();
    }
    b"$-1\r\n".to_vec()
}

fn del_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.is_empty() {
        return wrong_number_of_arguments("del").into_bytes();
    }
    b":0\r\n".to_vec()
}

fn exists_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.is_empty() {
        return wrong_number_of_arguments("exists").into_bytes();
    }
    b":0\r\n".to_vec()
}

fn ttl_response(args: &[Vec<u8>], command: &str) -> Vec<u8> {
    if args.len() != 1 {
        return wrong_number_of_arguments(command).into_bytes();
    }
    b":-2\r\n".to_vec()
}

fn expiretime_response(args: &[Vec<u8>], command: &str) -> Vec<u8> {
    if args.len() != 1 {
        return wrong_number_of_arguments(command).into_bytes();
    }
    b":-2\r\n".to_vec()
}

fn expire_response(args: &[Vec<u8>], command: &str) -> Vec<u8> {
    if !(args.len() == 2 || args.len() == 3) {
        return wrong_number_of_arguments(command).into_bytes();
    }
    if parse_unsigned_decimal_bytes::<u64>(&args[1]).is_none() {
        return b"-ERR value is not an integer or out of range\r\n".to_vec();
    }
    if let Some(option) = args.get(2)
        && !matches!(
            option.as_slice(),
            b"NX" | b"nx" | b"XX" | b"xx" | b"GT" | b"gt" | b"LT" | b"lt"
        )
    {
        return b"-ERR syntax error\r\n".to_vec();
    }
    b":0\r\n".to_vec()
}

fn type_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 1 {
        return wrong_number_of_arguments("type").into_bytes();
    }
    b"+none\r\n".to_vec()
}

fn strlen_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 1 {
        return wrong_number_of_arguments("strlen").into_bytes();
    }
    b":0\r\n".to_vec()
}

fn setex_response(args: &[Vec<u8>], command: &str) -> Vec<u8> {
    if args.len() != 3 {
        return wrong_number_of_arguments(command).into_bytes();
    }
    if parse_unsigned_decimal_bytes::<u64>(&args[1]).is_none_or(|value| value == 0) {
        return b"-ERR value is not an integer or out of range\r\n".to_vec();
    }
    b"+OK\r\n".to_vec()
}

fn setnx_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 2 {
        return wrong_number_of_arguments("setnx").into_bytes();
    }
    b":1\r\n".to_vec()
}

fn mset_response(args: &[Vec<u8>], command: &str) -> Vec<u8> {
    if args.is_empty() || !args.len().is_multiple_of(2) {
        return wrong_number_of_arguments(command).into_bytes();
    }
    if command == "mset" {
        b"+OK\r\n".to_vec()
    } else {
        b":1\r\n".to_vec()
    }
}

fn append_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 2 {
        return wrong_number_of_arguments("append").into_bytes();
    }
    format!(":{}\r\n", args[1].len()).into_bytes()
}

fn getbit_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 2 {
        return wrong_number_of_arguments("getbit").into_bytes();
    }
    if parse_unsigned_decimal_bytes::<u64>(&args[1]).is_none() {
        return b"-ERR value is not an integer or out of range\r\n".to_vec();
    }
    b":0\r\n".to_vec()
}

fn setbit_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 3 {
        return wrong_number_of_arguments("setbit").into_bytes();
    }
    if parse_unsigned_decimal_bytes::<u64>(&args[1]).is_none() {
        return b"-ERR value is not an integer or out of range\r\n".to_vec();
    }
    match args[2].as_slice() {
        b"0" | b"1" => b":0\r\n".to_vec(),
        _ => b"-ERR The bit argument must be 1 or 0.\r\n".to_vec(),
    }
}

fn bitcount_response(args: &[Vec<u8>]) -> Vec<u8> {
    match args.len() {
        1 => b":0\r\n".to_vec(),
        3 => {
            if parse_signed_decimal_bytes::<i64>(&args[1]).is_none()
                || parse_signed_decimal_bytes::<i64>(&args[2]).is_none()
            {
                return b"-ERR value is not an integer or out of range\r\n".to_vec();
            }
            b":0\r\n".to_vec()
        }
        4 => {
            if parse_signed_decimal_bytes::<i64>(&args[1]).is_none()
                || parse_signed_decimal_bytes::<i64>(&args[2]).is_none()
            {
                return b"-ERR value is not an integer or out of range\r\n".to_vec();
            }
            if !matches!(args[3].as_slice(), b"BYTE" | b"byte" | b"BIT" | b"bit") {
                return b"-ERR syntax error\r\n".to_vec();
            }
            b":0\r\n".to_vec()
        }
        _ => wrong_number_of_arguments("bitcount").into_bytes(),
    }
}

fn pfadd_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() < 2 {
        return wrong_number_of_arguments("pfadd").into_bytes();
    }
    b":1\r\n".to_vec()
}

fn pfcount_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.is_empty() {
        return wrong_number_of_arguments("pfcount").into_bytes();
    }
    b":0\r\n".to_vec()
}

fn pfmerge_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() < 2 {
        return wrong_number_of_arguments("pfmerge").into_bytes();
    }
    b"+OK\r\n".to_vec()
}

fn publish_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 2 {
        return wrong_number_of_arguments("publish").into_bytes();
    }
    b":0\r\n".to_vec()
}

fn pubsub_response(args: &[Vec<u8>]) -> Vec<u8> {
    let Some(subcommand) = args.first() else {
        return wrong_number_of_arguments("pubsub").into_bytes();
    };
    let Some(subcommand) = text_command(subcommand) else {
        return protocol_error();
    };

    match subcommand.to_ascii_uppercase().as_str() {
        "CHANNELS" => {
            if args.len() > 2 {
                return wrong_number_of_arguments("pubsub|channels").into_bytes();
            }
            b"*0\r\n".to_vec()
        }
        "NUMSUB" => {
            if args.len() < 2 {
                return wrong_number_of_arguments("pubsub|numsub").into_bytes();
            }
            let mut response = Vec::with_capacity(args.len() * 4 + 8);
            response.extend_from_slice(b"*");
            response.extend_from_slice((args.len() - 1).saturating_mul(2).to_string().as_bytes());
            response.extend_from_slice(b"\r\n");
            for channel in &args[1..] {
                response.extend_from_slice(b"$");
                response.extend_from_slice(channel.len().to_string().as_bytes());
                response.extend_from_slice(b"\r\n");
                response.extend_from_slice(channel);
                response.extend_from_slice(b"\r\n:0\r\n");
            }
            response
        }
        "NUMPAT" => {
            if args.len() != 1 {
                return wrong_number_of_arguments("pubsub|numpat").into_bytes();
            }
            b":0\r\n".to_vec()
        }
        _ => b"-ERR unknown PUBSUB subcommand\r\n".to_vec(),
    }
}

fn keys_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 1 {
        return wrong_number_of_arguments("keys").into_bytes();
    }
    b"*0\r\n".to_vec()
}

fn randomkey_response(args: &[Vec<u8>]) -> Vec<u8> {
    if !args.is_empty() {
        return wrong_number_of_arguments("randomkey").into_bytes();
    }
    b"$-1\r\n".to_vec()
}

fn scan_response(args: &[Vec<u8>]) -> Vec<u8> {
    let Some(cursor) = args.first() else {
        return wrong_number_of_arguments("scan").into_bytes();
    };
    if parse_unsigned_decimal_bytes::<u64>(cursor).is_none() {
        return b"-ERR value is not an integer or out of range\r\n".to_vec();
    }
    let mut index = 1usize;
    while index < args.len() {
        let Some(option) = text_command(&args[index]).map(|value| value.to_ascii_uppercase())
        else {
            return protocol_error();
        };
        let Some(value) = args.get(index + 1) else {
            return syntax_error().into_bytes();
        };
        match option.as_str() {
            "MATCH" | "TYPE" => {}
            "COUNT" => {
                if parse_unsigned_decimal_bytes::<u64>(value).is_none() {
                    return b"-ERR value is not an integer or out of range\r\n".to_vec();
                }
            }
            _ => return syntax_error().into_bytes(),
        }
        index += 2;
    }
    b"*2\r\n$1\r\n0\r\n*0\r\n".to_vec()
}

fn touch_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.is_empty() {
        return wrong_number_of_arguments("touch").into_bytes();
    }
    b":0\r\n".to_vec()
}

fn unlink_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.is_empty() {
        return wrong_number_of_arguments("unlink").into_bytes();
    }
    b":0\r\n".to_vec()
}

fn move_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 2 {
        return wrong_number_of_arguments("move").into_bytes();
    }
    if parse_unsigned_decimal_bytes::<u64>(&args[1]).is_none() {
        return b"-ERR value is not an integer or out of range\r\n".to_vec();
    }
    b":0\r\n".to_vec()
}

fn copy_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() < 2 {
        return wrong_number_of_arguments("copy").into_bytes();
    }

    let mut index = 2;
    let mut saw_db = false;
    while index < args.len() {
        if args[index].eq_ignore_ascii_case(b"replace") {
            index += 1;
            if index != args.len() {
                return b"-ERR syntax error\r\n".to_vec();
            }
            return b":0\r\n".to_vec();
        }

        if !args[index].eq_ignore_ascii_case(b"db") {
            return b"-ERR syntax error\r\n".to_vec();
        }
        if saw_db {
            return b"-ERR syntax error\r\n".to_vec();
        }
        saw_db = true;

        index += 1;
        let Some(db) = args.get(index) else {
            return wrong_number_of_arguments("copy").into_bytes();
        };
        if parse_unsigned_decimal_bytes::<u64>(db).is_none() {
            return b"-ERR value is not an integer or out of range\r\n".to_vec();
        }
        index += 1;
    }

    b":0\r\n".to_vec()
}

fn sort_response(args: &[Vec<u8>], allow_store: bool) -> Vec<u8> {
    if args.is_empty() {
        return wrong_number_of_arguments(if allow_store { "sort" } else { "sort_ro" })
            .into_bytes();
    }

    let mut index = 1usize;
    let mut saw_by = false;
    let mut saw_limit = false;
    let mut saw_order = false;
    let mut saw_alpha = false;
    let mut saw_store = false;
    while index < args.len() {
        let Some(option) = text_command(&args[index]).map(|value| value.to_ascii_uppercase())
        else {
            return protocol_error();
        };
        match option.as_str() {
            "BY" => {
                if saw_by {
                    return syntax_error().into_bytes();
                }
                saw_by = true;
                index += 2;
                if args.get(index - 1).is_none() {
                    return syntax_error().into_bytes();
                }
            }
            "LIMIT" => {
                if saw_limit {
                    return syntax_error().into_bytes();
                }
                saw_limit = true;
                if index + 2 >= args.len() {
                    return syntax_error().into_bytes();
                }
                if parse_unsigned_decimal_bytes::<u64>(&args[index + 1]).is_none()
                    || parse_unsigned_decimal_bytes::<u64>(&args[index + 2]).is_none()
                {
                    return b"-ERR value is not an integer or out of range\r\n".to_vec();
                }
                index += 3;
            }
            "GET" => {
                index += 2;
                if args.get(index - 1).is_none() {
                    return syntax_error().into_bytes();
                }
            }
            "ASC" | "DESC" | "ALPHA" => {
                if option.as_str() == "ALPHA" {
                    if saw_alpha {
                        return syntax_error().into_bytes();
                    }
                    saw_alpha = true;
                } else {
                    if saw_order {
                        return syntax_error().into_bytes();
                    }
                    saw_order = true;
                }
                index += 1;
            }
            "STORE" => {
                if !allow_store {
                    return syntax_error().into_bytes();
                }
                if saw_store {
                    return syntax_error().into_bytes();
                }
                saw_store = true;
                index += 2;
                if args.get(index - 1).is_none() {
                    return syntax_error().into_bytes();
                }
            }
            _ => return syntax_error().into_bytes(),
        }
    }

    if saw_store {
        b":0\r\n".to_vec()
    } else {
        b"*0\r\n".to_vec()
    }
}

fn incr_decr_response(args: &[Vec<u8>], command: &str, delta: i64) -> Vec<u8> {
    if args.len() != 1 {
        return wrong_number_of_arguments(command).into_bytes();
    }
    format!(":{}\r\n", delta).into_bytes()
}

fn incrby_decrby_response(args: &[Vec<u8>], command: &str, direction: i64) -> Vec<u8> {
    if args.len() != 2 {
        return wrong_number_of_arguments(command).into_bytes();
    }

    let Some(amount) = parse_signed_decimal_bytes::<i64>(&args[1]) else {
        return b"-ERR value is not an integer or out of range\r\n".to_vec();
    };
    let result = if direction > 0 {
        amount
    } else {
        let Some(negated) = amount.checked_neg() else {
            return b"-ERR value is not an integer or out of range\r\n".to_vec();
        };
        negated
    };

    format!(":{}\r\n", result).into_bytes()
}

fn auth_args_are_valid_bytes(args: &[Vec<u8>]) -> bool {
    matches!(args.len(), 1 | 2)
        && args
            .iter()
            .all(|arg| !is_effectively_blank_redis_value_bytes(arg))
}

fn is_effectively_blank_redis_value_bytes(value: &[u8]) -> bool {
    if let Ok(text) = std::str::from_utf8(value) {
        return text.trim().is_empty()
            || text.chars().all(|ch| ch.is_control() || ch.is_whitespace());
    }

    value
        .iter()
        .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
}

fn is_valid_replication_host(host: &str) -> bool {
    if let Some(rest) = host.strip_prefix('[') {
        let Some((inner, suffix)) = rest.split_once(']') else {
            return false;
        };
        return suffix.is_empty()
            && inner
                .parse::<std::net::Ipv6Addr>()
                .is_ok_and(|ip| is_usable_replication_ip(&std::net::IpAddr::V6(ip)));
    }

    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return is_usable_replication_ipv4(ip);
    }

    let host = if let Some(host) = host.strip_suffix('.') {
        if host.is_empty() || host.ends_with('.') {
            return false;
        }
        host
    } else {
        host
    };

    host.len() <= 253
        && nettrap_core::sanitize::has_valid_domain_labels(host)
        && nettrap_core::sanitize::has_valid_domain_label_lengths(host)
        && !nettrap_core::sanitize::has_numeric_domain_labels(host)
}

fn is_usable_replication_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => is_usable_replication_ipv4(*ip),
        std::net::IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_usable_replication_ipv4(mapped);
            }
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
        }
    }
}

fn is_usable_replication_ipv4(ip: std::net::Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
}

fn parse_unsigned_decimal_bytes<T: std::str::FromStr>(value: &[u8]) -> Option<T> {
    let text = std::str::from_utf8(value).ok()?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn parse_float_decimal_bytes(value: &[u8]) -> Option<f64> {
    let text = std::str::from_utf8(value).ok()?;
    text.parse::<f64>().ok().filter(|value| !value.is_nan())
}

fn parse_signed_decimal_bytes<T: std::str::FromStr>(value: &[u8]) -> Option<T> {
    let text = std::str::from_utf8(value).ok()?;
    if text.is_empty() {
        return None;
    }
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn safe_log_bytes_args(args: &[Vec<u8>]) -> String {
    let mut rendered: Vec<String> = Vec::with_capacity(args.len());
    for arg in args {
        rendered.push(nettrap_core::sanitize::single_line_bytes(arg));
    }
    rendered.join(", ")
}

#[cfg(test)]
#[path = "handler_tests.rs"]
mod tests;
