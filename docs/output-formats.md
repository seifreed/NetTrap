# Output Formats

NetTrap supports 5 output formats for NBI (Network Behavior Indicators):

## JSONL (default)
One JSON object per line, streamed in real-time during capture.
```
{"timestamp":"2026-03-29T10:15:30Z","listener":"ssh","protocol":"SSH","src_ip":"10.0.0.5","src_port":54321,"dst_port":22,"indicators":{"client_version":"SSH-2.0-libssh_0.9.6"}}
```

## JSON
Pretty-printed array of all events. Select it as the primary shutdown export or use `nettrap report`.

## SARIF v2.1.0
Standards-compliant Static Analysis Results Interchange Format.
Compatible with GitHub Code Scanning, Azure DevOps, and SIEM tools.

## TOON
Token-Oriented Object Notation. Protocol-grouped tabular format optimized for LLM consumption (~40% fewer tokens than JSON).

## CSV
Comma-separated values with dynamic columns based on protocol indicators.

## CLI Usage
```bash
nettrap run -c config.toml --report-format sarif
nettrap run -c config.toml --report-format toon
nettrap run -c config.toml --report-format csv
nettrap report -i events.jsonl -o events.sarif.json --format sarif
```

At runtime, JSONL is streamed when an NBI output path is configured. At shutdown,
NetTrap generates the HTML report and also SARIF and CSV; a selected non-JSONL
primary format such as JSON or TOON is generated as well. It does not generate
all five formats on every run.
