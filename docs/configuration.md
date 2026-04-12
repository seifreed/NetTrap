# Configuration Reference

NetTrap uses TOML configuration. Generate defaults with:
```bash
nettrap config --defaults > config.toml
```

## Top-Level Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `attribution_enabled` | bool | `true` | Enable process-to-connection tracking |
| `attribution_timeout_ms` | u64 | `5000` | Attribution cache timeout |
| `default_decision` | string | `"intercept"` | Default packet action |
| `pcap_enabled` | bool | `false` | Enable PCAP recording |
| `pcap_path` | string | - | PCAP output file path |
| `pcap_prefix` | string | - | PCAP filename prefix |
| `output_format` | string | `"jsonl"` | Output format: json, jsonl, sarif, toon, csv |
| `output_path` | string | - | Event output file path |
| `network_mode` | string | `"auto"` | Network mode: singlehost, multihost, auto |
| `log_hexdump` | bool | `false` | Enable hexdump in logs |
| `redirect_all_traffic` | bool | `false` | Redirect unbound ports to the configured default listener |

## Listener Options (`[[listeners]]`)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `name` | string | required | Listener identifier (determines protocol handler) |
| `port` | u16 | required | Listen port |
| `protocol` | string | `"tcp"` | Protocol: tcp, udp |
| `bind_address` | string | `"0.0.0.0"` | Bind IP address |
| `enabled` | bool | `true` | Enable/disable |
| `use_ssl` | bool | `false` | Enable TLS wrapping |
| `hidden` | bool | `false` | Hidden (proxy-only) |
| `banner` | string | - | Custom service banner |
| `webroot` | string | - | HTTP file serving directory |
| `ftproot` | string | - | FTP file serving directory |
| `response_delay_ms` | u64 | `0` | Response delay |
| `execute_cmd` | string | - | Command on connect |
| `process_whitelist` | [string] | `[]` | Process name whitelist |
| `process_blacklist` | [string] | `[]` | Process name blacklist |
| `host_whitelist` | [string] | `[]` | IP whitelist |
| `host_blacklist` | [string] | `[]` | IP blacklist |

## Distributed Options (`[distributed]`)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable distributed mode |
| `node_region` | string | `"default"` | Node region tag |
| `node_tags` | [string] | `[]` | Node labels |
| `health_bind` | string | - | Health/readiness endpoint bind address (`/health`, `/ready`) |
| `metrics_bind` | string | - | Metrics endpoint bind address (`/metrics`) |
| `heartbeat_interval_secs` | u64 | `0` | Heartbeat interval (0=disabled) |
| `control_plane_url` | string | - | Control plane API URL |
| `control_plane_token` | string | - | API authentication token |

All distributed features are gated by `distributed.enabled = true`. If it is `false`, health,
metrics, heartbeat, and event sinks remain disabled even if their sub-options are present.

### Event Sink Options (`[[distributed.event_sinks]]`)

| Option | Type | Description |
|--------|------|-------------|
| `type` | string | Sink type: http, tcp, syslog |
| `target` | string | Target URL or address |
| `auth` | string | Auth header value |
| `batch_size` | usize | HTTP batch size (default 100) |
