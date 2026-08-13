# Configuration Reference

NetTrap uses TOML configuration. Generate defaults with:
```bash
nettrap config --defaults > config.toml
```

## Top-Level Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `attribution_enabled` | bool | `true` | Enable process-to-connection tracking |
| `attribution_timeout_ms` | u64 | `5000` | Attribution operation timeout and cache TTL |
| `default_decision` | string | `"intercept"` | Default packet action |
| `pcap_enabled` | bool | `false` | Enable PCAP recording |
| `pcap_path` | string | - | PCAP output file path |
| `pcap_prefix` | string | - | PCAP filename prefix |
| `output_format` | string | `"jsonl"` | Output format: json, jsonl, sarif, toon, csv |
| `output_path` | string | - | Event output file path |
| `network_mode` | string | `"auto"` | Network mode: singlehost, multihost, auto |
| `global_process_blacklist` | [string] | `[]` | Global process filters; entries support literal, `re:`, and `regex:` forms |
| `global_process_whitelist` | [string] | `[]` | Global process allowlist |
| `blacklist_ports_tcp` | [u16] | `[]` | TCP ports excluded from interception/listening |
| `blacklist_ports_udp` | [u16] | `[]` | UDP ports excluded from interception/listening |
| `blacklist_ids_icmp` | [u16] | `[]` | ICMP type/ID values excluded on Windows |
| `redirect_all_traffic` | bool | `false` | Redirect unbound ports to the configured default listener |
| `default_tcp_listener` | string | - | Listener used for redirected TCP traffic |
| `default_udp_listener` | string | - | Listener used for redirected UDP traffic |
| `restrict_interface` | string | - | Restrict interception or capture to one interface |
| `debug_flags` | [string] | `[]` | Platform/runtime debug flags |
| `modify_local_dns` | bool | `false` | Modify local DNS configuration on supported platforms |
| `dns_flush_command` | string | - | Platform command used to flush DNS after changes |
| `http_post_dump_dir` | string | - | Directory for captured HTTP POST bodies |
| `smtp_dir` | string | - | Directory for captured SMTP data |
| `log_hexdump` | bool | `false` | Enable hexdump in logs |
| `report_language` | string | `"en"` | NBI report language (`en`, `es`, or `de`) |
| `api_bind` | string | - | REST API bind address |
| `tls_ca_cert` | string | - | TLS CA certificate path |
| `tls_ca_key` | string | - | TLS CA private key path |
| `tls_cert_dir` | string | - | Directory for generated TLS certificates |

## Listener Options (`[[listeners]]`)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `name` | string | required | Listener identifier (determines protocol handler). A listener named `forward`/`forwarder` relays to the connection's original destination instead of emulating (requires interception so `SO_ORIGINAL_DST` is set) |
| `port` | u16 | required | Listen port |
| `port_range` | string | - | Comma-separated ports or inclusive range to expand |
| `protocol` | string | `"tcp"` | Protocol: tcp, udp |
| `bind_address` | string | `"0.0.0.0"` | Bind IP address |
| `enabled` | bool | `true` | Enable/disable |
| `use_ssl` | bool | `false` | Enable TLS wrapping |
| `hidden` | bool | `false` | Hidden (proxy-only) |
| `custom_response` | string | - | Protocol-specific custom response definition |
| `banner` | string | - | Custom service banner. FTP banners expand `{servername}`, `{tz}`, and `strftime` (`%H:%M:%S`, `%Y-%m-%d`, …) tokens at emit time |
| `server_name` | string | - | Server name for `{servername}` banner tokens (FTP/IRC). Supports `!gethostname` and `!random` |
| `webroot` | string | - | HTTP file serving directory |
| `ftproot` | string | - | FTP file serving directory |
| `tftproot` | string | - | TFTP file serving directory |
| `response_delay_ms` | u64 | `0` | Response delay |
| `emulate_response` | bool | `true` | Enable protocol response emulation |
| `timeout_ms` | u64 | `30000` | Per-connection timeout |
| `max_connections` | u32 | `100` | Maximum concurrent connections for the listener |
| `banner_delay_ms` | u64 | `0` | Delay before dummy/raw banners |
| `execute_cmd` | string | - | Command on connect |
| `dump_http_posts` | bool | `false` | Save captured HTTP POST bodies |
| `dump_http_posts_prefix` | string | - | Prefix for dumped HTTP POST files |
| `dns_response_ip` | string | - | Static DNS response address |
| `dns_response_mx` | string | - | Static DNS MX response |
| `dns_response_txt` | string | - | Static DNS TXT response |
| `dns_nxdomains` | u32 | - | Number of initial DNS queries answered as NXDOMAIN |
| `dns_ncsi_response_ip` | string | - | Response address for NCSI probes |
| `dns_response_mode` | string | - | DNS response mode: `static`, `auto`, or `hostname` |
| `server_version` | string | - | HTTP server version string |
| `pasv_ports` | string | - | FTP passive port range, for example `60000-60100` |
| `process_whitelist` | [string] | `[]` | Process name whitelist; literal substring by default, `re:`/`regex:` prefix for regex |
| `process_blacklist` | [string] | `[]` | Process name blacklist; literal substring by default, `re:`/`regex:` prefix for regex |
| `host_whitelist` | [string] | `[]` | IP whitelist (exact IPs, CIDR ranges, hostnames resolved at startup). Loopback is always allowed regardless. |
| `host_blacklist` | [string] | `[]` | IP blacklist (exact IPs, CIDR ranges, hostnames). Loopback (`127.0.0.0/8`, `::1`) is never blocked. |

## Distributed Options (`[distributed]`)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable distributed mode |
| `node_region` | string | - | Node region tag |
| `node_tags` | [string] | `[]` | Node labels |
| `health_bind` | string | - | Health/readiness endpoint bind address (`/health`, `/ready`) |
| `metrics_bind` | string | - | Metrics endpoint bind address (`/metrics`) |
| `heartbeat_interval_secs` | u64 | `0` | Heartbeat interval (0=disabled) |
| `control_plane_url` | string | - | Control plane API URL |
| `control_plane_token` | string | - | API authentication token |

All distributed features are gated by `distributed.enabled = true`. If it is `false`, health,
metrics, heartbeat, and event sinks remain disabled even if their sub-options are present.

### Event Sink Options (`[[distributed.event_sinks]]`)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `type` | string | required | Sink type: http, tcp, syslog |
| `target` | string | required | Target URL or address |
| `auth` | string | - | Auth header value |
| `batch_size` | usize | `100` | HTTP batch size |
| `flush_interval_ms` | u64 | `1000` | Maximum time a batch remains buffered |
| `request_timeout_ms` | u64 | `5000` | Timeout for one outbound sink request |

## Database Options (`[database]`)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `backend` | string | `"none"` | `none`, `sqlite`, or `postgres` |
| `sqlite_path` | string | - | SQLite database path |
| `postgres_url` | string | - | PostgreSQL connection URL |
| `pool_size` | u32 | `5` | PostgreSQL connection pool size |
| `node_id` | string | - | Database node identifier |

## Fake Time Options (`[faketime]`)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable shifted service timestamps |
| `init_delta` | i64 | `0` | Initial time shift in seconds |
| `auto_delay_secs` | u64 | `0` | Seconds between automatic time shifts; `0` disables it |
| `auto_increment_secs` | i64 | `0` | Seconds added on each automatic shift |
