use crate::nbi::NetworkBehaviorIndicator;
use serde::Serialize;
use std::fmt;
use std::path::Path;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputFormatParseError {
    value: String,
}

impl OutputFormatParseError {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

impl fmt::Display for OutputFormatParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unsupported output format '{}'; expected one of: {}",
            self.value,
            supported_output_formats()
        )
    }
}

impl std::error::Error for OutputFormatParseError {}

pub fn supported_output_formats() -> &'static str {
    "json, jsonl, ndjson, sarif, toon, csv"
}

impl std::str::FromStr for OutputFormat {
    type Err = OutputFormatParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let format = match s.trim().to_lowercase().as_str() {
            "json" => Self::Json,
            "jsonl" | "ndjson" => Self::Jsonl,
            "sarif" => Self::Sarif,
            "toon" => Self::Toon,
            "csv" => Self::Csv,
            _ => return Err(OutputFormatParseError::new(s)),
        };
        Ok(format)
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
    let json = serde_json::to_string_pretty(events).map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

// ─── JSONL (one JSON object per line) ────────────────────────────────────────

fn export_jsonl(events: &[NetworkBehaviorIndicator], path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;
    for event in events {
        let line = serde_json::to_string(event).map_err(std::io::Error::other)?;
        writeln!(file, "{}", line)?;
    }
    Ok(())
}

// ─── SARIF v2.1.0 ───────────────────────────────────────────────────────────

fn export_sarif(events: &[NetworkBehaviorIndicator], path: &Path) -> std::io::Result<()> {
    let (start_time_utc, end_time_utc) = event_time_bounds(events);
    let results: Vec<SarifResult> = events
        .iter()
        .map(|e| {
            let level = match e.protocol.as_str() {
                "RAW" | "SMTP" | "FTP" | "POP3" | "IRC" => "note",
                "DNS" | "HTTP" | "TLS" => "warning",
                _ => "warning",
            };

            // Build rule ID from protocol
            let rule_id = format!("NT-{}-001", e.protocol.to_uppercase());

            // Build message
            let indicators_str: String = e
                .indicators
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(", ");

            let message = if indicators_str.is_empty() {
                format!(
                    "{} event from {}:{} to {}:{}",
                    e.protocol, e.src_ip, e.src_port, e.dst_ip, e.dst_port
                )
            } else {
                format!(
                    "{} event from {}:{} to {}:{} — {}",
                    e.protocol, e.src_ip, e.src_port, e.dst_ip, e.dst_port, indicators_str
                )
            };

            SarifResult {
                rule_id,
                level: level.to_string(),
                message: SarifMessage { text: message },
                locations: vec![SarifLocation {
                    logical_location: SarifLogicalLocation {
                        fully_qualified_name: format!(
                            "{}:{} -> {}:{}",
                            e.src_ip, e.src_port, e.dst_ip, e.dst_port
                        ),
                    },
                }],
                properties: SarifProperties {
                    event_id: e.event_id.clone(),
                    timestamp: e.timestamp.clone(),
                    listener: e.listener.clone(),
                    protocol: e.protocol.clone(),
                    src_ip: e.src_ip.clone(),
                    src_port: e.src_port,
                    dst_ip: e.dst_ip.clone(),
                    dst_port: e.dst_port,
                    process_name: e.process_name.clone(),
                    process_pid: e.process_pid,
                    indicators: e.indicators.clone(),
                },
            }
        })
        .collect();

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
                start_time_utc,
                end_time_utc,
            }],
            results,
        }],
    };

    let json = serde_json::to_string_pretty(&sarif).map_err(std::io::Error::other)?;
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
    event_id: String,
    timestamp: String,
    listener: String,
    protocol: String,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    process_name: Option<String>,
    process_pid: Option<u32>,
    indicators: std::collections::HashMap<String, String>,
}

// ─── TOON (Token-Oriented Object Notation) ───────────────────────────────────

fn export_toon(events: &[NetworkBehaviorIndicator], path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;
    let (start, end) = event_time_bounds(events);

    // Header
    writeln!(file, "capture:")?;
    writeln!(file, "  tool: NetTrap")?;
    writeln!(file, "  version: 0.1.0")?;
    if !start.is_empty() {
        writeln!(file, "  start: {}", start)?;
    }
    if !end.is_empty() {
        writeln!(file, "  end: {}", end)?;
    }
    writeln!(file, "  total_events: {}", events.len())?;

    // Group events by protocol
    let mut by_protocol: std::collections::BTreeMap<String, Vec<&NetworkBehaviorIndicator>> =
        std::collections::BTreeMap::new();
    for event in events {
        by_protocol
            .entry(event.protocol.clone())
            .or_default()
            .push(event);
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

        // Build column headers: timestamp, listener, src_ip, src_port, dst_ip, dst_port, [indicator keys...]
        let mut columns = vec![
            "timestamp".to_string(),
            "listener".to_string(),
            "src_ip".to_string(),
            "src_port".to_string(),
            "dst_ip".to_string(),
            "dst_port".to_string(),
        ];
        if proto_events.iter().any(|e| e.process_name.is_some()) {
            columns.push("process".to_string());
        }
        columns.extend(all_keys.iter().cloned());

        let header = columns.join(",");
        writeln!(
            file,
            "{}_events[{}]{{{}}}:",
            protocol.to_lowercase(),
            proto_events.len(),
            header
        )?;

        for e in proto_events {
            let mut row = vec![
                e.timestamp.clone(),
                e.listener.clone(),
                e.src_ip.clone(),
                e.src_port.to_string(),
                e.dst_ip.clone(),
                e.dst_port.to_string(),
            ];
            if columns.contains(&"process".to_string()) {
                row.push(e.process_name.clone().unwrap_or_default());
            }
            for key in &all_keys {
                row.push(e.indicators.get(key).cloned().unwrap_or_default());
            }
            // Escape commas in values
            let escaped: Vec<String> = row
                .iter()
                .map(|v| {
                    if v.contains(',') || v.contains('\n') {
                        format!("\"{}\"", v.replace('"', "\"\""))
                    } else {
                        v.clone()
                    }
                })
                .collect();
            writeln!(file, "  {}", escaped.join(","))?;
        }
    }

    Ok(())
}

fn event_time_bounds(events: &[NetworkBehaviorIndicator]) -> (String, String) {
    let mut earliest_parsed: Option<(chrono::DateTime<chrono::FixedOffset>, &str)> = None;
    let mut latest_parsed: Option<(chrono::DateTime<chrono::FixedOffset>, &str)> = None;
    let mut all_parsed = true;

    for event in events {
        let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&event.timestamp) else {
            all_parsed = false;
            break;
        };

        match &earliest_parsed {
            Some((current, _)) if parsed >= *current => {}
            _ => earliest_parsed = Some((parsed, event.timestamp.as_str())),
        }

        match &latest_parsed {
            Some((current, _)) if parsed <= *current => {}
            _ => latest_parsed = Some((parsed, event.timestamp.as_str())),
        }
    }

    if all_parsed {
        return (
            earliest_parsed
                .map(|(_, timestamp)| timestamp.to_string())
                .unwrap_or_default(),
            latest_parsed
                .map(|(_, timestamp)| timestamp.to_string())
                .unwrap_or_default(),
        );
    }

    let start = events
        .iter()
        .map(|event| event.timestamp.as_str())
        .min()
        .unwrap_or_default()
        .to_string();
    let end = events
        .iter()
        .map(|event| event.timestamp.as_str())
        .max()
        .unwrap_or_default()
        .to_string();

    (start, end)
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
    let header_parts = vec![
        "event_id",
        "timestamp",
        "listener",
        "protocol",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "process_name",
        "process_pid",
    ];
    let escaped_keys: Vec<String> = all_keys.iter().map(|s| csv_escape(s)).collect();
    let header_line: Vec<&str> = header_parts
        .iter()
        .copied()
        .chain(escaped_keys.iter().map(|s| s.as_str()))
        .collect();
    writeln!(file, "{}", header_line.join(","))?;

    // Write rows
    for e in events {
        let mut row = vec![
            csv_escape(&e.event_id),
            csv_escape(&e.timestamp),
            csv_escape(&e.listener),
            csv_escape(&e.protocol),
            csv_escape(&e.src_ip),
            e.src_port.to_string(),
            csv_escape(&e.dst_ip),
            e.dst_port.to_string(),
            csv_escape(&e.process_name.clone().unwrap_or_default()),
            e.process_pid.map(|p| p.to_string()).unwrap_or_default(),
        ];
        for key in &all_keys {
            row.push(csv_escape(
                &e.indicators.get(key).cloned().unwrap_or_default(),
            ));
        }
        writeln!(file, "{}", row.join(","))?;
    }

    Ok(())
}

fn csv_escape(value: &str) -> String {
    // Sanitize CSV formula injection (values starting with =, +, -, @)
    let needs_formula_guard = value.starts_with('=')
        || value.starts_with('+')
        || value.starts_with('-')
        || value.starts_with('@');
    if needs_formula_guard
        || value.contains(',')
        || value.contains('"')
        || value.contains('\n')
        || value.contains('\r')
    {
        if needs_formula_guard {
            format!("\"'{}\"", value.replace('"', "\"\""))
        } else {
            format!("\"{}\"", value.replace('"', "\"\""))
        }
    } else {
        value.to_string()
    }
}

#[derive(Debug, Clone, Default)]
pub struct JsonlLoadResult {
    pub events: Vec<NetworkBehaviorIndicator>,
    pub invalid_lines: usize,
    pub read_error: Option<String>,
}

impl JsonlLoadResult {
    pub fn has_integrity_issues(&self) -> bool {
        self.invalid_lines > 0 || self.read_error.is_some()
    }
}

pub fn load_nbis_from_jsonl_detailed(path: &Path) -> JsonlLoadResult {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return JsonlLoadResult::default();
        }
        Err(err) => {
            return JsonlLoadResult {
                events: Vec::new(),
                invalid_lines: 0,
                read_error: Some(err.to_string()),
            };
        }
    };

    let mut result = JsonlLoadResult::default();
    for line in content.lines() {
        match serde_json::from_str::<NetworkBehaviorIndicator>(line) {
            Ok(mut event) => {
                event.event_id = event.normalized_event_id();
                result.events.push(event);
            }
            Err(_) => result.invalid_lines += 1,
        }
    }

    result
}

/// Parse NBI events from a JSONL file
pub fn load_nbis_from_jsonl(path: &Path) -> Vec<NetworkBehaviorIndicator> {
    load_nbis_from_jsonl_detailed(path).events
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nbi::raw_nbi;
    use crate::session::SessionDestination;

    #[test]
    fn output_format_rejects_unknown_values() {
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!(
            "ndjson".parse::<OutputFormat>().unwrap(),
            OutputFormat::Jsonl
        );

        let err = "xml".parse::<OutputFormat>().unwrap_err();
        assert!(err.to_string().contains("unsupported output format 'xml'"));
    }

    #[test]
    fn detailed_jsonl_loader_reports_invalid_lines() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-output-test-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let valid = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        std::fs::write(&path, format!("{}\n{{invalid-json}}\n", valid.to_json())).unwrap();

        let loaded = load_nbis_from_jsonl_detailed(&path);
        assert_eq!(loaded.events.len(), 1);
        assert_eq!(loaded.invalid_lines, 1);
        assert!(loaded.read_error.is_none());
        assert!(loaded.has_integrity_issues());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sarif_uses_real_timestamp_bounds_for_unsorted_events() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-output-sarif-{}.json",
            uuid::Uuid::new_v4()
        ));
        let destination = SessionDestination::unknown(8080);
        let mut oldest = raw_nbi("raw", "127.0.0.1", 1111, &destination, 4, "");
        let mut newest = raw_nbi("raw", "127.0.0.1", 2222, &destination, 4, "");
        let mut middle = raw_nbi("raw", "127.0.0.1", 3333, &destination, 4, "");

        oldest.timestamp = "2026-04-13T09:00:00Z".to_string();
        newest.timestamp = "2026-04-13T11:00:00Z".to_string();
        middle.timestamp = "2026-04-13T10:00:00Z".to_string();

        export_nbis(
            &[middle.clone(), newest.clone(), oldest.clone()],
            OutputFormat::Sarif,
            &path,
        )
        .unwrap();

        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let invocation = &json["runs"][0]["invocations"][0];
        assert_eq!(invocation["startTimeUtc"], oldest.timestamp);
        assert_eq!(invocation["endTimeUtc"], newest.timestamp);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn toon_uses_real_timestamp_bounds_for_unsorted_events() {
        let path =
            std::env::temp_dir().join(format!("nettrap-output-toon-{}.toon", uuid::Uuid::new_v4()));
        let destination = SessionDestination::unknown(8080);
        let mut oldest = raw_nbi("raw", "127.0.0.1", 1111, &destination, 4, "");
        let mut newest = raw_nbi("raw", "127.0.0.1", 2222, &destination, 4, "");
        let mut middle = raw_nbi("raw", "127.0.0.1", 3333, &destination, 4, "");

        oldest.timestamp = "2026-04-13T09:00:00Z".to_string();
        newest.timestamp = "2026-04-13T11:00:00Z".to_string();
        middle.timestamp = "2026-04-13T10:00:00Z".to_string();

        export_nbis(
            &[middle.clone(), newest.clone(), oldest.clone()],
            OutputFormat::Toon,
            &path,
        )
        .unwrap();

        let output = std::fs::read_to_string(&path).unwrap();
        assert!(output.contains(&format!("  start: {}", oldest.timestamp)));
        assert!(output.contains(&format!("  end: {}", newest.timestamp)));

        let _ = std::fs::remove_file(path);
    }
}
