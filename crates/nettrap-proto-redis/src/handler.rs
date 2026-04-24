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
                "PING" => "+PONG\r\n".to_string(),
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
                    if args.len() >= 2 {
                        tracing::warn!(
                            "REDIS AUTH attempt: username='{}', password='{}'",
                            args[0],
                            args[1]
                        );
                    } else if args.len() == 1 {
                        tracing::warn!("REDIS AUTH attempt: password='{}'", args[0]);
                    } else {
                        tracing::warn!("REDIS AUTH attempt (no credentials)");
                    }
                    *authenticated = true;
                    "+OK\r\n".to_string()
                }
                "SET" => {
                    tracing::warn!("REDIS SET attempt: {:?}", args);
                    "+OK\r\n".to_string()
                }
                "GET" => "$-1\r\n".to_string(), // nil
                "CONFIG" => {
                    if args.first().map(|a| a.to_uppercase()) == Some("SET".to_string()) {
                        tracing::warn!("REDIS CONFIG SET attempt: {:?}", args);
                        // This is how attackers write SSH keys or crontabs
                        "+OK\r\n".to_string()
                    } else if args.first().map(|a| a.to_uppercase()) == Some("GET".to_string()) {
                        let key = args.get(1).copied().unwrap_or("dir");
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
                    } else {
                        "+OK\r\n".to_string()
                    }
                }
                "SLAVEOF" | "REPLICAOF" => {
                    tracing::warn!("REDIS REPLICATION attempt: {:?}", args);
                    "+OK\r\n".to_string()
                }
                "MODULE" => {
                    tracing::warn!("REDIS MODULE LOAD attempt: {:?}", args);
                    "-ERR Module loading is disabled\r\n".to_string()
                }
                "EVAL" | "EVALSHA" => {
                    tracing::warn!("REDIS EVAL/LUA attempt: {:?}", args);
                    "+OK\r\n".to_string()
                }
                "FLUSHALL" | "FLUSHDB" => {
                    tracing::warn!("REDIS FLUSH attempt: {}", cmd);
                    "+OK\r\n".to_string()
                }
                "DBSIZE" => ":0\r\n".to_string(),
                "SELECT" => "+OK\r\n".to_string(),
                "QUIT" => "+OK\r\n".to_string(),
                "COMMAND" => "*0\r\n".to_string(),
                "CLUSTER" => "-ERR This instance has cluster support disabled\r\n".to_string(),
                "CLIENT" => "+OK\r\n".to_string(),
                "SAVE" | "BGSAVE" => {
                    tracing::warn!("REDIS SAVE attempt (RDB dump attack)");
                    "+OK\r\n".to_string()
                }
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
    fn handle_command_enforces_auth_for_stateless_calls() {
        let handler = RedisHandler::new().with_auth(true);

        assert_eq!(
            handler.handle_command(b"PING\r\n"),
            b"-NOAUTH Authentication required.\r\n".to_vec()
        );
    }
}
