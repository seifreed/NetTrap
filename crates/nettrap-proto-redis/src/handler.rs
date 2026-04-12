pub struct RedisHandler {
    version: String,
    require_auth: bool,
}

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
        let text = String::from_utf8_lossy(data);
        let commands = Self::parse_resp(&text);

        let mut response = Vec::new();
        for cmd_parts in commands {
            if cmd_parts.is_empty() {
                continue;
            }
            let cmd = cmd_parts[0].to_uppercase();
            let args: Vec<&str> = cmd_parts[1..].iter().map(|s| s.as_str()).collect();

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
                    // Always accept (honeypot) — no per-connection state needed
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
                        format!("*2\r\n${}\r\n{}\r\n${}\r\n{}\r\n", key.len(), key, value.len(), value)
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

        if response.is_empty() {
            b"+OK\r\n".to_vec()
        } else {
            response
        }
    }

    /// Parse RESP protocol (Redis Serialization Protocol)
    fn parse_resp(data: &str) -> Vec<Vec<String>> {
        const MAX_ARRAY_COUNT: usize = 1024; // Limit number of array elements
        const MAX_BULK_SIZE: usize = 64 * 1024; // 64KB max per bulk string

        let mut commands = Vec::new();
        let lines: Vec<&str> = data.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            if lines[i].starts_with('*') {
                // Array: *N followed by $len\r\ndata pairs (cap at 1024 to prevent abuse)
                let count: usize = lines[i][1..]
                    .trim()
                    .parse()
                    .unwrap_or(0)
                    .min(MAX_ARRAY_COUNT);
                let mut parts = Vec::new();
                i += 1;
                for _ in 0..count {
                    if i < lines.len() && lines[i].starts_with('$') {
                        // Parse bulk string length (signed to handle $-1 null bulk strings)
                        let bulk_len: isize = lines[i][1..].trim().parse().unwrap_or(0);

                        if bulk_len < 0 {
                            // Null bulk string ($-1): no data line follows
                            i += 1;
                            continue;
                        }

                        // Limit bulk string size
                        if bulk_len as usize > MAX_BULK_SIZE {
                            tracing::warn!("RESP bulk string too large ({}), rejecting", bulk_len);
                            return commands; // Return what we have so far
                        }

                        i += 1; // skip $len
                        if i < lines.len() {
                            // Additional validation: ensure data doesn't exceed claimed length
                            let data = lines[i].trim();
                            if data.len() <= MAX_BULK_SIZE {
                                parts.push(data.to_string());
                            }
                            i += 1;
                        }
                    }
                }
                if !parts.is_empty() {
                    commands.push(parts);
                }
            } else {
                // Inline command
                let parts: Vec<String> =
                    lines[i].split_whitespace().map(|s| s.to_string()).collect();
                if !parts.is_empty() {
                    commands.push(parts);
                }
                i += 1;
            }
        }
        commands
    }
}

impl Default for RedisHandler {
    fn default() -> Self {
        Self::new()
    }
}
