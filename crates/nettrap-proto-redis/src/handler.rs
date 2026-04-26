pub struct RedisHandler {
    version: String,
    require_auth: bool,
}

const MAX_RESP_ARRAY_COUNT: usize = 1024;
const MAX_RESP_BULK_SIZE: usize = 64 * 1024;

impl RedisHandler {
    pub fn new() -> Self {
        Self {
            version: "7.0.15".to_string(),
            require_auth: false,
        }
    }

    pub fn with_version(mut self, v: impl Into<String>) -> Self {
        self.version = v.into();
        self
    }

    pub fn with_auth(mut self, require: bool) -> Self {
        self.require_auth = require;
        self
    }

    pub fn handle_command(&self, data: &[u8]) -> Vec<u8> {
        let mut authenticated = !self.require_auth;
        self.handle_command_with_auth_state(data, &mut authenticated)
    }

    pub fn handle_command_with_auth_state(&self, data: &[u8], authenticated: &mut bool) -> Vec<u8> {
        let commands = Self::parse_resp(data);

        let mut response = Vec::new();
        for cmd_parts in commands {
            if cmd_parts.is_empty() {
                continue;
            }
            let cmd = cmd_parts[0].to_uppercase();
            let args: Vec<&str> = cmd_parts[1..].iter().map(|s| s.as_str()).collect();

            if self.require_auth && !*authenticated && cmd != "AUTH" {
                response.extend_from_slice(b"-NOAUTH Authentication required.\r\n");
                continue;
            }

            let resp = match cmd.as_str() {
                "PING" => ping_response(&args),
                "INFO" => {
                    let info = format!(
                        "# Server\r\nredis_version:{}\r\nos:Linux\r\narch_bits:64\r\ntcp_port:6379\r\nuptime_in_seconds:86400\r\nuptime_in_days:1\r\n\r\n# Clients\r\nconnected_clients:1\r\n\r\n# Memory\r\nused_memory:1000000\r\nused_memory_human:976.56K\r\n",
                        self.version
                    );
                    format!("${}\r\n{}\r\n", info.len(), info)
                }
                "AUTH" => {
                    // Capture credentials: AUTH [username] password
                    // Always accept (honeypot) and mark this connection authenticated.
                    if !auth_args_are_valid(&args) {
                        tracing::warn!("REDIS AUTH attempt with missing credentials");
                        "-ERR wrong number of arguments for 'auth' command\r\n".to_string()
                    } else if args.len() == 2 {
                        tracing::warn!(
                            "REDIS AUTH attempt: username='{}', password='{}'",
                            args[0],
                            args[1]
                        );
                        *authenticated = true;
                        "+OK\r\n".to_string()
                    } else {
                        tracing::warn!("REDIS AUTH attempt: password='{}'", args[0]);
                        *authenticated = true;
                        "+OK\r\n".to_string()
                    }
                }
                "SET" => set_response(&args),
                "GET" => {
                    if args.len() == 1 {
                        "$-1\r\n".to_string()
                    } else {
                        wrong_number_of_arguments("get")
                    }
                }
                "CONFIG" => {
                    if args.is_empty() {
                        wrong_number_of_arguments("config")
                    } else {
                        let subcommand = args[0].to_uppercase();
                        if subcommand == "SET" {
                            if args.len() != 3 {
                                wrong_number_of_arguments("config|set")
                            } else {
                                tracing::warn!("REDIS CONFIG SET attempt: {:?}", args);
                                // This is how attackers write SSH keys or crontabs
                                "+OK\r\n".to_string()
                            }
                        } else if subcommand == "GET" {
                            if args.len() != 2 {
                                wrong_number_of_arguments("config|get")
                            } else {
                                let key = args[1];
                                let value = match key.to_lowercase().as_str() {
                                    "dir" => "/tmp/",
                                    "dbfilename" => "dump.rdb",
                                    "save" => "3600 1 300 100 60 10000",
                                    "maxmemory" => "0",
                                    "bind" => "0.0.0.0",
                                    _ => "",
                                };
                                format!(
                                    "*2\r\n${}\r\n{}\r\n${}\r\n{}\r\n",
                                    key.len(),
                                    key,
                                    value.len(),
                                    value
                                )
                            }
                        } else {
                            "-ERR unknown CONFIG subcommand\r\n".to_string()
                        }
                    }
                }
                "SLAVEOF" => replication_response("slaveof", &args),
                "REPLICAOF" => replication_response("replicaof", &args),
                "MODULE" => {
                    tracing::warn!("REDIS MODULE LOAD attempt");
                    "-ERR Module loading is disabled\r\n".to_string()
                }
                "EVAL" => eval_response("eval", &args),
                "EVALSHA" => eval_response("evalsha", &args),
                "FLUSHALL" => flush_response("flushall", &args),
                "FLUSHDB" => flush_response("flushdb", &args),
                "DBSIZE" => ":0\r\n".to_string(),
                "SELECT" => select_response(&args),
                "QUIT" => {
                    if args.is_empty() {
                        "+OK\r\n".to_string()
                    } else {
                        wrong_number_of_arguments("quit")
                    }
                }
                "COMMAND" => "*0\r\n".to_string(),
                "CLUSTER" => "-ERR This instance has cluster support disabled\r\n".to_string(),
                "CLIENT" => client_response(&args),
                "SAVE" => save_response("save", &args),
                "BGSAVE" => bgsave_response(&args),
                _ => "-ERR unknown command\r\n".to_string(),
            };
            response.extend_from_slice(resp.as_bytes());
        }

        if response.is_empty() && !data.is_empty() {
            b"-ERR Protocol error\r\n".to_vec()
        } else if response.is_empty() {
            Vec::new()
        } else {
            response
        }
    }

    /// Parse RESP protocol (Redis Serialization Protocol)
    fn parse_resp(data: &[u8]) -> Vec<Vec<String>> {
        let mut commands = Vec::new();
        let mut pos = 0usize;

        while pos < data.len() {
            while matches!(data.get(pos), Some(b'\r' | b'\n')) {
                pos += 1;
            }
            if pos >= data.len() {
                break;
            }

            if data[pos] == b'*' {
                let Some((parts, next_pos)) = Self::parse_resp_array_at(data, pos) else {
                    break;
                };
                if !parts.is_empty() {
                    commands.push(parts);
                }
                pos = next_pos;
                continue;
            }

            let Some(line_end) = find_lf_from(data, pos) else {
                break;
            };
            let line = &data[pos..line_end];
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let text = String::from_utf8_lossy(line);
            let parts: Vec<String> = text.split_whitespace().map(|s| s.to_string()).collect();
            if !parts.is_empty() {
                commands.push(parts);
            }
            pos = line_end + 1;
        }
        commands
    }

    fn parse_resp_array_at(data: &[u8], start: usize) -> Option<(Vec<String>, usize)> {
        let header_end = find_crlf_from(data, start)?;
        let count_text = std::str::from_utf8(&data[start + 1..header_end]).ok()?;
        let count = count_text.parse::<usize>().ok()?;
        if count > MAX_RESP_ARRAY_COUNT {
            tracing::warn!("RESP array too large ({count}), rejecting");
            return None;
        }

        let mut pos = header_end + 2;
        let mut parts = Vec::new();
        for _ in 0..count {
            if data.get(pos) != Some(&b'$') {
                return None;
            }

            let bulk_header_end = find_crlf_from(data, pos)?;
            let bulk_len_text = std::str::from_utf8(&data[pos + 1..bulk_header_end]).ok()?;
            let bulk_len = bulk_len_text.parse::<isize>().ok()?;
            pos = bulk_header_end + 2;

            if bulk_len == -1 {
                parts.push(String::new());
                continue;
            }
            if bulk_len < -1 {
                return None;
            }

            let bulk_len = bulk_len as usize;
            if bulk_len > MAX_RESP_BULK_SIZE {
                tracing::warn!("RESP bulk string too large ({bulk_len}), rejecting");
                return None;
            }
            let data_end = pos.checked_add(bulk_len)?;
            let frame_end = data_end.checked_add(2)?;
            if frame_end > data.len() || &data[data_end..frame_end] != b"\r\n" {
                return None;
            }

            parts.push(String::from_utf8_lossy(&data[pos..data_end]).to_string());
            pos = frame_end;
        }

        Some((parts, pos))
    }
}

fn auth_args_are_valid(args: &[&str]) -> bool {
    matches!(args.len(), 1 | 2) && args.iter().all(|arg| !arg.is_empty())
}

fn ping_response(args: &[&str]) -> String {
    match args {
        [] => "+PONG\r\n".to_string(),
        [message] => format!("${}\r\n{}\r\n", message.len(), message),
        _ => wrong_number_of_arguments("ping"),
    }
}

fn select_response(args: &[&str]) -> String {
    match args {
        [index] if index.parse::<u64>().is_ok() => "+OK\r\n".to_string(),
        [_] => "-ERR invalid DB index\r\n".to_string(),
        _ => wrong_number_of_arguments("select"),
    }
}

fn set_response(args: &[&str]) -> String {
    if args.len() < 2 {
        return wrong_number_of_arguments("set");
    }

    let mut index = 2;
    while index < args.len() {
        match args[index].to_ascii_uppercase().as_str() {
            "EX" | "PX" => {
                index += 1;
                let Some(expiry) = args.get(index) else {
                    return syntax_error();
                };
                if expiry.parse::<u64>().map_or(true, |value| value == 0) {
                    return "-ERR invalid expire time in 'set' command\r\n".to_string();
                }
            }
            "NX" | "XX" => {}
            _ => return syntax_error(),
        }
        index += 1;
    }

    tracing::warn!("REDIS SET attempt: {:?}", args);
    "+OK\r\n".to_string()
}

fn replication_response(command: &str, args: &[&str]) -> String {
    if args.len() != 2 {
        return wrong_number_of_arguments(command);
    }

    if args[0].eq_ignore_ascii_case("NO") && args[1].eq_ignore_ascii_case("ONE") {
        tracing::warn!("REDIS REPLICATION disable attempt: {:?}", args);
        return "+OK\r\n".to_string();
    }

    if args[1].parse::<u16>().is_err() {
        return "-ERR invalid port\r\n".to_string();
    }

    tracing::warn!("REDIS REPLICATION attempt: {:?}", args);
    "+OK\r\n".to_string()
}

fn eval_response(command: &str, args: &[&str]) -> String {
    if args.len() < 2 {
        return wrong_number_of_arguments(command);
    }

    let Ok(key_count) = args[1].parse::<usize>() else {
        return "-ERR value is not an integer or out of range\r\n".to_string();
    };

    if key_count > args.len().saturating_sub(2) {
        return "-ERR Number of keys can't be greater than number of args\r\n".to_string();
    }

    tracing::warn!("REDIS EVAL/LUA attempt: {:?}", args);
    "+OK\r\n".to_string()
}

fn flush_response(command: &str, args: &[&str]) -> String {
    match args {
        [] => {
            tracing::warn!("REDIS FLUSH attempt: {}", command);
            "+OK\r\n".to_string()
        }
        [mode] if mode.eq_ignore_ascii_case("ASYNC") || mode.eq_ignore_ascii_case("SYNC") => {
            tracing::warn!("REDIS FLUSH attempt: {} {:?}", command, args);
            "+OK\r\n".to_string()
        }
        [_] => syntax_error(),
        _ => wrong_number_of_arguments(command),
    }
}

fn client_response(args: &[&str]) -> String {
    let Some((subcommand, rest)) = args.split_first() else {
        return wrong_number_of_arguments("client");
    };

    match subcommand.to_ascii_uppercase().as_str() {
        "SETNAME" => match rest {
            [name] if !name.is_empty() => {
                tracing::warn!("REDIS CLIENT SETNAME attempt: {}", name);
                "+OK\r\n".to_string()
            }
            _ => wrong_number_of_arguments("client|setname"),
        },
        "GETNAME" => {
            if rest.is_empty() {
                "$-1\r\n".to_string()
            } else {
                wrong_number_of_arguments("client|getname")
            }
        }
        "LIST" => {
            if rest.is_empty() {
                let listing = "id=1 addr=127.0.0.1:0 fd=1 name= age=0 idle=0 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=0 qbuf-free=0 obl=0 oll=0 omem=0 events=r cmd=client\r\n";
                format!("${}\r\n{}\r\n", listing.len(), listing)
            } else {
                wrong_number_of_arguments("client|list")
            }
        }
        _ => "-ERR unknown CLIENT subcommand\r\n".to_string(),
    }
}

fn save_response(command: &str, args: &[&str]) -> String {
    if args.is_empty() {
        tracing::warn!("REDIS SAVE attempt (RDB dump attack)");
        "+OK\r\n".to_string()
    } else {
        wrong_number_of_arguments(command)
    }
}

fn bgsave_response(args: &[&str]) -> String {
    match args {
        [] => {
            tracing::warn!("REDIS BGSAVE attempt (RDB dump attack)");
            "+OK\r\n".to_string()
        }
        [mode] if mode.eq_ignore_ascii_case("SCHEDULE") => {
            tracing::warn!("REDIS BGSAVE SCHEDULE attempt (RDB dump attack)");
            "+OK\r\n".to_string()
        }
        [_] => syntax_error(),
        _ => wrong_number_of_arguments("bgsave"),
    }
}

fn syntax_error() -> String {
    "-ERR syntax error\r\n".to_string()
}

fn wrong_number_of_arguments(command: &str) -> String {
    format!(
        "-ERR wrong number of arguments for '{}' command\r\n",
        command
    )
}

fn find_lf_from(haystack: &[u8], start: usize) -> Option<usize> {
    haystack
        .get(start..)?
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|offset| start + offset)
}

fn find_crlf_from(haystack: &[u8], start: usize) -> Option<usize> {
    haystack
        .get(start..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
}

impl Default for RedisHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resp_parser_respects_bulk_lengths() {
        let handler = RedisHandler::new();

        assert_eq!(
            handler.handle_command(b"*1\r\n$4\r\nPING\r\n"),
            b"+PONG\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"*1\r\n$4\r\nPI\r\n"),
            b"-ERR Protocol error\r\n".to_vec()
        );
    }

    #[test]
    fn with_auth_blocks_commands_until_auth_succeeds() {
        let handler = RedisHandler::new().with_auth(true);
        let mut authenticated = false;

        assert_eq!(
            handler.handle_command_with_auth_state(b"PING\r\n", &mut authenticated),
            b"-NOAUTH Authentication required.\r\n".to_vec()
        );
        assert!(!authenticated);

        assert_eq!(
            handler.handle_command_with_auth_state(b"AUTH secret\r\n", &mut authenticated),
            b"+OK\r\n".to_vec()
        );
        assert!(authenticated);

        assert_eq!(
            handler.handle_command_with_auth_state(b"PING\r\n", &mut authenticated),
            b"+PONG\r\n".to_vec()
        );
    }

    #[test]
    fn auth_requires_non_empty_credentials() {
        let handler = RedisHandler::new().with_auth(true);
        let mut authenticated = false;

        assert_eq!(
            handler.handle_command_with_auth_state(b"AUTH\r\n", &mut authenticated),
            b"-ERR wrong number of arguments for 'auth' command\r\n".to_vec()
        );
        assert!(!authenticated);

        assert_eq!(
            handler
                .handle_command_with_auth_state(b"*2\r\n$4\r\nAUTH\r\n$-1\r\n", &mut authenticated),
            b"-ERR wrong number of arguments for 'auth' command\r\n".to_vec()
        );
        assert!(!authenticated);

        assert_eq!(
            handler.handle_command_with_auth_state(
                b"*3\r\n$4\r\nAUTH\r\n$4\r\nuser\r\n$6\r\nsecret\r\n",
                &mut authenticated,
            ),
            b"+OK\r\n".to_vec()
        );
        assert!(authenticated);
    }

    #[test]
    fn handle_command_enforces_auth_for_stateless_calls() {
        let handler = RedisHandler::new().with_auth(true);

        assert_eq!(
            handler.handle_command(b"PING\r\n"),
            b"-NOAUTH Authentication required.\r\n".to_vec()
        );
    }

    #[test]
    fn ping_validates_arguments_and_echoes_single_message() {
        let handler = RedisHandler::new();

        assert_eq!(handler.handle_command(b"PING\r\n"), b"+PONG\r\n".to_vec());
        assert_eq!(
            handler.handle_command(b"PING hello\r\n"),
            b"$5\r\nhello\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"PING one two\r\n"),
            b"-ERR wrong number of arguments for 'ping' command\r\n".to_vec()
        );
    }

    #[test]
    fn select_requires_single_numeric_database_index() {
        let handler = RedisHandler::new();

        assert_eq!(handler.handle_command(b"SELECT 0\r\n"), b"+OK\r\n".to_vec());
        assert_eq!(
            handler.handle_command(b"SELECT\r\n"),
            b"-ERR wrong number of arguments for 'select' command\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"SELECT abc\r\n"),
            b"-ERR invalid DB index\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"SELECT 1 extra\r\n"),
            b"-ERR wrong number of arguments for 'select' command\r\n".to_vec()
        );
    }

    #[test]
    fn get_and_set_validate_argument_counts() {
        let handler = RedisHandler::new();

        assert_eq!(handler.handle_command(b"GET key\r\n"), b"$-1\r\n".to_vec());
        assert_eq!(
            handler.handle_command(b"GET\r\n"),
            b"-ERR wrong number of arguments for 'get' command\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"GET one two\r\n"),
            b"-ERR wrong number of arguments for 'get' command\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"SET key value\r\n"),
            b"+OK\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"SET key value EX 60\r\n"),
            b"+OK\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"SET key value PX 100 NX\r\n"),
            b"+OK\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"SET key\r\n"),
            b"-ERR wrong number of arguments for 'set' command\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"SET key value EX\r\n"),
            b"-ERR syntax error\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"SET key value EX nope\r\n"),
            b"-ERR invalid expire time in 'set' command\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"SET key value UNKNOWN\r\n"),
            b"-ERR syntax error\r\n".to_vec()
        );
    }

    #[test]
    fn config_validates_subcommand_and_argument_counts() {
        let handler = RedisHandler::new();

        assert_eq!(
            handler.handle_command(b"CONFIG\r\n"),
            b"-ERR wrong number of arguments for 'config' command\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"CONFIG GET\r\n"),
            b"-ERR wrong number of arguments for 'config|get' command\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"CONFIG GET dir\r\n"),
            b"*2\r\n$3\r\ndir\r\n$5\r\n/tmp/\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"CONFIG SET dir /tmp extra\r\n"),
            b"-ERR wrong number of arguments for 'config|set' command\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"CONFIG SET dir /tmp\r\n"),
            b"+OK\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"CONFIG REWRITE\r\n"),
            b"-ERR unknown CONFIG subcommand\r\n".to_vec()
        );
    }

    #[test]
    fn replication_commands_validate_arguments() {
        let handler = RedisHandler::new();

        assert_eq!(
            handler.handle_command(b"SLAVEOF NO ONE\r\n"),
            b"+OK\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"REPLICAOF host 6379\r\n"),
            b"+OK\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"SLAVEOF\r\n"),
            b"-ERR wrong number of arguments for 'slaveof' command\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"REPLICAOF host nope\r\n"),
            b"-ERR invalid port\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"SLAVEOF NO ONE extra\r\n"),
            b"-ERR wrong number of arguments for 'slaveof' command\r\n".to_vec()
        );
    }

    #[test]
    fn eval_commands_validate_script_and_key_count() {
        let handler = RedisHandler::new();

        assert_eq!(
            handler.handle_command(b"EVAL return 0\r\n"),
            b"+OK\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"EVALSHA abc 1 key\r\n"),
            b"+OK\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"EVAL return\r\n"),
            b"-ERR wrong number of arguments for 'eval' command\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"EVAL return nope\r\n"),
            b"-ERR value is not an integer or out of range\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"EVAL return 2 onlykey\r\n"),
            b"-ERR Number of keys can't be greater than number of args\r\n".to_vec()
        );
    }

    #[test]
    fn flush_quit_client_and_save_validate_arguments() {
        let handler = RedisHandler::new();

        assert_eq!(handler.handle_command(b"FLUSHALL\r\n"), b"+OK\r\n".to_vec());
        assert_eq!(
            handler.handle_command(b"FLUSHDB ASYNC\r\n"),
            b"+OK\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"FLUSHALL LATER\r\n"),
            b"-ERR syntax error\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"QUIT now\r\n"),
            b"-ERR wrong number of arguments for 'quit' command\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"SAVE x\r\n"),
            b"-ERR wrong number of arguments for 'save' command\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"BGSAVE SCHEDULE\r\n"),
            b"+OK\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"BGSAVE NOW\r\n"),
            b"-ERR syntax error\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"CLIENT SETNAME worker\r\n"),
            b"+OK\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"CLIENT GETNAME\r\n"),
            b"$-1\r\n".to_vec()
        );

        let client_list = handler.handle_command(b"CLIENT LIST\r\n");
        assert!(client_list.starts_with(b"$"));
        assert!(
            client_list
                .windows(b"cmd=client".len())
                .any(|w| w == b"cmd=client")
        );

        assert_eq!(
            handler.handle_command(b"CLIENT\r\n"),
            b"-ERR wrong number of arguments for 'client' command\r\n".to_vec()
        );
        assert_eq!(
            handler.handle_command(b"CLIENT KILL all\r\n"),
            b"-ERR unknown CLIENT subcommand\r\n".to_vec()
        );
    }
}
