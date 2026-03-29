use serde::Serialize;
use std::path::Path;
use crate::nbi::NetworkBehaviorIndicator;

/// Supported output formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Jsonl,
    Sarif,
    Toon,
    Csv,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => Self::Json,
            "jsonl" | "ndjson" => Self::Jsonl,
            "sarif" => Self::Sarif,
            "toon" => Self::Toon,
            "csv" => Self::Csv,
            _ => Self::Jsonl, // default
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Sarif => "sarif.json",
            Self::Toon => "toon",
            Self::Csv => "csv",
        }
    }
}

/// Export NBI events in the specified format
pub fn export_nbis(
    events: &[NetworkBehaviorIndicator],
    format: OutputFormat,
    output_path: &Path,
) -> std::io::Result<()> {
    match format {
        OutputFormat::Json => export_json(events, output_path),
        OutputFormat::Jsonl => export_jsonl(events, output_path),
        OutputFormat::Sarif => export_sarif(events, output_path),
        OutputFormat::Toon => export_toon(events, output_path),
        OutputFormat::Csv => export_csv(events, output_path),
    }
}

// ─── JSON (pretty-printed array) ─────────────────────────────────────────────

fn export_json(events: &[NetworkBehaviorIndicator], path: &Path) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(events)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(path, json)
}

// ─── JSONL (one JSON object per line) ────────────────────────────────────────

fn export_jsonl(events: &[NetworkBehaviorIndicator], path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;
    for event in events {
        let line = serde_json::to_string(event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        writeln!(file, "{}", line)?;
    }
    Ok(())
}

// ─── SARIF v2.1.0 ───────────────────────────────────────────────────────────

fn export_sarif(events: &[NetworkBehaviorIndicator], path: &Path) -> std::io::Result<()> {
    let results: Vec<SarifResult> = events.iter().map(|e| {
        let level = match e.protocol.as_str() {
            "RAW" | "SMTP" | "FTP" | "POP3" | "IRC" => "note",
            "DNS" | "HTTP" | "TLS" => "warning",
            _ => "warning",
        };

        // Build rule ID from protocol
        let rule_id = format!("NT-{}-001", e.protocol.to_uppercase());

        // Build message
        let indicators_str: String = e.indicators.iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(", ");

        let message = if indicators_str.is_empty() {
            format!("{} event from {}:{}", e.protocol, e.src_ip, e.src_port)
        } else {
            format!("{} event from {}:{} — {}", e.protocol, e.src_ip, e.src_port, indicators_str)
        };

        SarifResult {
            rule_id,
            level: level.to_string(),
            message: SarifMessage { text: message },
            locations: vec![SarifLocation {
                logical_location: SarifLogicalLocation {
                    fully_qualified_name: format!(
                        "{}:{} -> :{}",
                        e.src_ip, e.src_port, e.dst_port
                    ),
                },
            }],
            properties: SarifProperties {
                timestamp: e.timestamp.clone(),
                listener: e.listener.clone(),
                protocol: e.protocol.clone(),
                src_ip: e.src_ip.clone(),
                src_port: e.src_port,
                dst_port: e.dst_port,
                process_name: e.process_name.clone(),
                process_pid: e.process_pid,
                indicators: e.indicators.clone(),
            },
        }
    }).collect();

    // Collect unique rule IDs
    let mut rules: Vec<SarifRule> = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();
    for r in &results {
        if seen_rules.insert(r.rule_id.clone()) {
            let proto = r.properties.protocol.clone();
            rules.push(SarifRule {
                id: r.rule_id.clone(),
                name: format!("{} Network Event", proto),
                short_description: SarifMessage {
                    text: format!("{} protocol activity detected by NetTrap", proto),
                },
            });
        }
    }

    let sarif = SarifDocument {
        schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "NetTrap".to_string(),
                    version: "0.1.0".to_string(),
                    information_uri: "https://github.com/seifreed/NetTrap".to_string(),
                    rules,
                },
            },
            invocations: vec![SarifInvocation {
                execution_successful: true,
                start_time_utc: events.first().map(|e| e.timestamp.clone()).unwrap_or_default(),
                end_time_utc: events.last().map(|e| e.timestamp.clone()).unwrap_or_default(),
            }],
            results,
        }],
    };

    let json = serde_json::to_string_pretty(&sarif)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(path, json)
}

#[derive(Serialize)]
struct SarifDocument {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    invocations: Vec<SarifInvocation>,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: String,
    version: String,
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifInvocation {
    execution_successful: bool,
    start_time_utc: String,
    end_time_utc: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    properties: SarifProperties,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    logical_location: SarifLogicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLogicalLocation {
    fully_qualified_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifProperties {
    timestamp: String,
    listener: String,
    protocol: String,
    src_ip: String,
    src_port: u16,
    dst_port: u16,
    process_name: Option<String>,
    process_pid: Option<u32>,
    indicators: std::collections::HashMap<String, String>,
}

// ─── TOON (Token-Oriented Object Notation) ───────────────────────────────────

fn export_toon(events: &[NetworkBehaviorIndicator], path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;

    // Header
    writeln!(file, "capture:")?;
    writeln!(file, "  tool: NetTrap")?;
    writeln!(file, "  version: 0.1.0")?;
    if let Some(first) = events.first() {
        writeln!(file, "  start: {}", first.timestamp)?;
    }
    if let Some(last) = events.last() {
        writeln!(file, "  end: {}", last.timestamp)?;
    }
    writeln!(file, "  total_events: {}", events.len())?;

    // Group events by protocol
    let mut by_protocol: std::collections::BTreeMap<String, Vec<&NetworkBehaviorIndicator>> =
        std::collections::BTreeMap::new();
    for event in events {
        by_protocol.entry(event.protocol.clone()).or_default().push(event);
    }

    // Write each protocol group as a TOON tabular array
    for (protocol, proto_events) in &by_protocol {
        // Collect all indicator keys used in this protocol
        let mut all_keys: Vec<String> = Vec::new();
        for e in proto_events {
            for key in e.indicators.keys() {
                if !all_keys.contains(key) {
                    all_keys.push(key.clone());
                }
            }
        }
        all_keys.sort();

        // Build column headers: timestamp, listener, src_ip, src_port, dst_port, [indicator keys...]
        let mut columns = vec!["timestamp".to_string(), "listener".to_string(), "src_ip".to_string(), "src_port".to_string(), "dst_port".to_string()];
        if proto_events.iter().any(|e| e.process_name.is_some()) {
            columns.push("process".to_string());
        }
        columns.extend(all_keys.iter().cloned());

        let header = columns.join(",");
        writeln!(file, "{}_events[{}]{{{}}}:", protocol.to_lowercase(), proto_events.len(), header)?;

        for e in proto_events {
            let mut row = Vec::new();
            row.push(e.timestamp.clone());
            row.push(e.listener.clone());
            row.push(e.src_ip.clone());
            row.push(e.src_port.to_string());
            row.push(e.dst_port.to_string());
            if columns.contains(&"process".to_string()) {
                row.push(e.process_name.clone().unwrap_or_default());
            }
            for key in &all_keys {
                row.push(e.indicators.get(key).cloned().unwrap_or_default());
            }
            // Escape commas in values
            let escaped: Vec<String> = row.iter().map(|v| {
                if v.contains(',') || v.contains('\n') {
                    format!("\"{}\"", v.replace('"', "\"\""))
                } else {
                    v.clone()
                }
            }).collect();
            writeln!(file, "  {}", escaped.join(","))?;
        }
    }

    Ok(())
}

// ─── CSV ─────────────────────────────────────────────────────────────────────

fn export_csv(events: &[NetworkBehaviorIndicator], path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;

    // Collect all possible indicator keys
    let mut all_keys: Vec<String> = Vec::new();
    for e in events {
        for key in e.indicators.keys() {
            if !all_keys.contains(key) {
                all_keys.push(key.clone());
            }
        }
    }
    all_keys.sort();

    // Write CSV header
    let mut header_parts = vec![
        "timestamp", "listener", "protocol", "src_ip", "src_port", "dst_port",
        "process_name", "process_pid",
    ];
    let key_refs: Vec<&str> = all_keys.iter().map(|s| s.as_str()).collect();
    header_parts.extend(key_refs.iter());
    writeln!(file, "{}", header_parts.join(","))?;

    // Write rows
    for e in events {
        let mut row = Vec::new();
        row.push(csv_escape(&e.timestamp));
        row.push(csv_escape(&e.listener));
        row.push(csv_escape(&e.protocol));
        row.push(csv_escape(&e.src_ip));
        row.push(e.src_port.to_string());
        row.push(e.dst_port.to_string());
        row.push(csv_escape(&e.process_name.clone().unwrap_or_default()));
        row.push(e.process_pid.map(|p| p.to_string()).unwrap_or_default());
        for key in &all_keys {
            row.push(csv_escape(&e.indicators.get(key).cloned().unwrap_or_default()));
        }
        writeln!(file, "{}", row.join(","))?;
    }

    Ok(())
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Parse NBI events from a JSONL file
pub fn load_nbis_from_jsonl(path: &Path) -> Vec<NetworkBehaviorIndicator> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    content
        .lines()
        .filter_map(|line| serde_json::from_str::<NetworkBehaviorIndicator>(line).ok())
        .collect()
}
