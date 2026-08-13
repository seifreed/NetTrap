mod csv;
mod sarif;
mod toon;

use crate::nbi::NetworkBehaviorIndicator;
use csv::export_csv;
use nettrap_fsutil::open_regular_file_beneath_root;
use nettrap_fsutil::{ensure_no_symlink_ancestors, strip_current_dir_components};
use sarif::export_sarif;
use serde::Deserialize;
use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use toon::export_toon;

#[cfg(test)]
pub(crate) use csv::csv_escape;

pub use nettrap_core::ExportFormat;
pub use nettrap_core::export_format::ExportFormatParseError;

pub(crate) const MAX_REPORT_INPUT_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_REPORT_EVENTS: usize = 100_000;
const MAX_TEMP_OUTPUT_STEM_BYTES: usize = 96;
const HEX_TEMP_OUTPUT_STEM_PREFIX: &str = "hex-";
static TEMP_OUTPUT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Export NBI events in the specified format
pub fn export_nbis(
    events: &[NetworkBehaviorIndicator],
    format: ExportFormat,
    output_path: &Path,
) -> std::io::Result<()> {
    validate_export_events(events)?;

    match format {
        ExportFormat::Json => export_json(events, output_path),
        ExportFormat::Jsonl => export_jsonl(events, output_path),
        ExportFormat::Sarif => export_sarif(events, output_path),
        ExportFormat::Toon => export_toon(events, output_path),
        ExportFormat::Csv => export_csv(events, output_path),
    }
}

fn validate_export_events(events: &[NetworkBehaviorIndicator]) -> std::io::Result<()> {
    if events.len() > MAX_REPORT_EVENTS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "NBI export exceeds event limit ({} > {} events)",
                events.len(),
                MAX_REPORT_EVENTS
            ),
        ));
    }

    for event in events {
        event
            .validate_resource_bounds()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    }

    Ok(())
}

fn trim_ascii_edges(value: &str) -> &str {
    value.trim_matches(|ch| matches!(ch, ' ' | '\t' | '\r' | '\n' | '\u{000C}'))
}

pub fn read_report_input_to_string(path: &Path) -> std::io::Result<String> {
    let root = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let relative = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;
    let file = open_regular_file_beneath_root(root, Path::new(relative))?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_REPORT_INPUT_BYTES {
        return Err(report_input_size_error(metadata.len()));
    }

    let mut limited = file.take(MAX_REPORT_INPUT_BYTES + 1);
    let mut content = String::new();
    limited.read_to_string(&mut content)?;
    if content.len() as u64 > MAX_REPORT_INPUT_BYTES {
        return Err(report_input_size_error(content.len() as u64));
    }
    Ok(content)
}

fn report_input_size_error(size: u64) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "report input exceeds load limit ({} > {} bytes)",
            size, MAX_REPORT_INPUT_BYTES
        ),
    )
}

fn export_json(events: &[NetworkBehaviorIndicator], path: &Path) -> std::io::Result<()> {
    use std::io::Write;

    write_atomically(path, |file| {
        let json = serde_json::to_string_pretty(events).map_err(std::io::Error::other)?;
        file.write_all(json.as_bytes())
    })
}

fn export_jsonl(events: &[NetworkBehaviorIndicator], path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    write_atomically(path, |file| {
        for event in events {
            let line = serde_json::to_string(event).map_err(std::io::Error::other)?;
            writeln!(file, "{}", line)?;
        }
        Ok(())
    })
}

pub(crate) fn write_atomically<F>(path: &Path, write: F) -> std::io::Result<()>
where
    F: FnOnce(&mut std::fs::File) -> std::io::Result<()>,
{
    use std::fs::OpenOptions;
    use std::io::Write;

    let normalized_path = strip_current_dir_components(path);
    let path = normalized_path.as_path();

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_no_symlink_ancestors(parent)?;
        std::fs::create_dir_all(parent)?;
    }
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "symlink path component",
        ));
    }

    let temp_path = temp_output_path(path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        write(&mut file)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        replace_file(&temp_path, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }

    result
}

#[cfg(not(windows))]
fn replace_file(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::rename(from, to)
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    use windows::core::PCWSTR;

    let from_wide: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to_wide: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        MoveFileExW(
            PCWSTR(from_wide.as_ptr()),
            PCWSTR(to_wide.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(std::io::Error::other)
}

fn temp_output_path(path: &Path) -> std::path::PathBuf {
    let seq = TEMP_OUTPUT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nonce = uuid::Uuid::new_v4();
    let stem = temp_output_stem(path);
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let dir = parent.unwrap_or_else(|| Path::new("."));
    dir.join(format!(".{}.{}.{}.{}.tmp", stem, pid, nonce, seq))
}

fn temp_output_stem(path: &Path) -> String {
    let Some(name) = path.file_name() else {
        return "output".to_string();
    };

    let rendered = render_temp_output_stem(name);

    truncate_to_byte_boundary(rendered, MAX_TEMP_OUTPUT_STEM_BYTES)
}

fn render_temp_output_stem(name: &OsStr) -> String {
    {
        #[cfg(unix)]
        {
            use std::fmt::Write as _;
            use std::os::unix::ffi::OsStrExt;

            if let Some(name) = name.to_str() {
                nettrap_core::sanitize::single_line(name)
            } else {
                let mut rendered = String::from(HEX_TEMP_OUTPUT_STEM_PREFIX);
                for byte in name.as_bytes() {
                    let _ = write!(&mut rendered, "{:02x}", byte);
                }
                rendered
            }
        }

        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            {
                use std::fmt::Write as _;
                use std::os::windows::ffi::OsStrExt;

                let mut rendered = String::from(HEX_TEMP_OUTPUT_STEM_PREFIX);
                for unit in name.encode_wide() {
                    let _ = write!(&mut rendered, "{:04x}", unit);
                }
                rendered
            }

            #[cfg(all(not(unix), not(windows)))]
            {
                let rendered = name.to_string_lossy();
                nettrap_core::sanitize::single_line(&rendered)
            }
        }
    }
}

fn truncate_to_byte_boundary(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    if value.is_empty() {
        "output".to_string()
    } else {
        value
    }
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
    load_nbis_from_jsonl_detailed_with_limit(path, MAX_REPORT_EVENTS)
}

fn load_nbis_from_jsonl_detailed_with_limit(path: &Path, max_events: usize) -> JsonlLoadResult {
    let content = match read_report_input_to_string(path) {
        Ok(c) => c,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return JsonlLoadResult {
                events: Vec::new(),
                invalid_lines: 0,
                read_error: Some(format!(
                    "failed to read NBI input '{}': {}",
                    path.display(),
                    err
                )),
            };
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
    for line in content.split_terminator('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        match parse_jsonl_nbi_line(line) {
            Ok(mut event) => {
                event.event_id = event.normalized_event_id();
                if event.validate_resource_bounds().is_ok() {
                    if result.events.len() >= max_events {
                        result.read_error = Some(format!(
                            "report input exceeds event limit ({} > {} events)",
                            result.events.len() + 1,
                            max_events
                        ));
                        break;
                    }
                    result.events.push(event);
                } else {
                    result.invalid_lines += 1;
                }
            }
            Err(_) if is_event_log_line(line) => {}
            Err(_) => result.invalid_lines += 1,
        }
    }

    result
}

fn parse_jsonl_nbi_line(line: &str) -> Result<NetworkBehaviorIndicator, serde_json::Error> {
    serde_json::from_str::<NetworkBehaviorIndicator>(line).or_else(|err| {
        if !is_legacy_jsonl_nbi_error(&err) {
            return Err(err);
        }

        serde_json::from_str::<LegacyJsonlNetworkBehaviorIndicator>(line)
            .and_then(try_from_legacy_jsonl_network_behavior_indicator)
    })
}

fn is_legacy_jsonl_nbi_error(err: &serde_json::Error) -> bool {
    let message = err.to_string();
    message.contains("missing field `dst_ip`") || message.contains("missing field `event_id`")
}

#[derive(Debug, Deserialize)]
struct LegacyJsonlNetworkBehaviorIndicator {
    #[serde(default)]
    event_id: Option<String>,
    timestamp: String,
    listener: String,
    protocol: String,
    src_ip: String,
    src_port: u16,
    #[serde(default)]
    dst_ip: Option<String>,
    dst_port: u16,
    process_name: Option<String>,
    process_pid: Option<u32>,
    indicators: std::collections::BTreeMap<String, String>,
}

fn should_normalize_legacy_jsonl_event_id(event_id: &str) -> bool {
    let event_id = event_id.trim_matches([' ', '\t']);
    event_id.is_empty()
        || (event_id.starts_with("legacy-db-")
            && !event_id
                .chars()
                .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' ')))
}

fn try_from_legacy_jsonl_network_behavior_indicator(
    value: LegacyJsonlNetworkBehaviorIndicator,
) -> Result<NetworkBehaviorIndicator, serde_json::Error> {
    let protocol = parse_legacy_jsonl_protocol(&value.protocol)?;
    let src_ip = value.src_ip;
    validate_legacy_jsonl_ip("src_ip", &src_ip)?;
    let dst_ip = match value.dst_ip {
        Some(dst_ip) => {
            validate_legacy_jsonl_ip("dst_ip", &dst_ip)?;
            dst_ip
        }
        None => legacy_unknown_destination_ip_for_source(&src_ip),
    };

    let mut event = NetworkBehaviorIndicator::new(
        trim_ascii_edges(&value.listener),
        &protocol,
        &src_ip,
        value.src_port,
        &dst_ip,
        value.dst_port,
    );
    event.timestamp = value.timestamp;
    event.process_name = normalize_optional_process_name(value.process_name);
    event.process_pid = value.process_pid;
    event.indicators = value.indicators;
    let event_id = value.event_id.unwrap_or_default();
    event.event_id = event_id;
    if should_normalize_legacy_jsonl_event_id(&event.event_id) {
        event.event_id = event.normalized_event_id();
    }
    Ok(event)
}

fn normalize_optional_process_name(name: Option<String>) -> Option<String> {
    name.and_then(|name| {
        let name = nettrap_core::sanitize::single_line(&name);
        if name.trim().is_empty() {
            None
        } else {
            Some(name)
        }
    })
}

fn parse_legacy_jsonl_protocol(value: &str) -> Result<String, serde_json::Error> {
    if value.trim_matches([' ', '\t']) != value
        || value.is_empty()
        || value
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return Err(legacy_jsonl_error(format!(
            "NBI protocol '{}' contains unsafe line-break or control characters",
            value
        )));
    }

    Ok(value.to_ascii_uppercase())
}

fn legacy_unknown_destination_ip_for_source(src_ip: &str) -> String {
    match src_ip
        .parse::<std::net::IpAddr>()
        .ok()
        .map(crate::session::normalize_session_ip)
    {
        Some(std::net::IpAddr::V4(_)) => std::net::Ipv4Addr::UNSPECIFIED.to_string(),
        Some(std::net::IpAddr::V6(_)) => std::net::Ipv6Addr::UNSPECIFIED.to_string(),
        None => std::net::Ipv4Addr::UNSPECIFIED.to_string(),
    }
}

fn validate_legacy_jsonl_ip(field: &str, value: &str) -> Result<(), serde_json::Error> {
    value.parse::<std::net::IpAddr>().map_err(|err| {
        legacy_jsonl_error(format!(
            "NBI {} contains invalid IP '{}': {}",
            field, value, err
        ))
    })?;
    Ok(())
}

fn legacy_jsonl_error(message: impl Into<String>) -> serde_json::Error {
    serde_json::Error::io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))
}

/// True for a lightweight `log_event` record: a JSON object carrying an
/// `"event"` field but no NBI `"event_id"`. Genuinely malformed lines (not
/// valid JSON, or JSON lacking both markers) are not treated as event logs and
/// still count as integrity issues.
fn is_event_log_line(line: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|value| {
            value.as_object().map(|obj| {
                if obj.len() != 6 {
                    return false;
                }

                event_log_fields_are_valid(obj)
            })
        })
        .unwrap_or(false)
}

fn event_log_fields_are_valid(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    let (
        Some(serde_json::Value::String(timestamp)),
        Some(serde_json::Value::String(_listener)),
        Some(serde_json::Value::String(src_ip)),
        Some(serde_json::Value::Number(src_port)),
        Some(serde_json::Value::String(_event)),
        Some(serde_json::Value::String(_detail)),
        None,
    ) = (
        obj.get("timestamp"),
        obj.get("listener"),
        obj.get("src_ip"),
        obj.get("src_port"),
        obj.get("event"),
        obj.get("detail"),
        obj.get("event_id"),
    )
    else {
        return false;
    };

    chrono::DateTime::parse_from_rfc3339(timestamp).is_ok()
        && src_ip.parse::<std::net::IpAddr>().is_ok()
        && src_port
            .as_u64()
            .is_some_and(|port| u16::try_from(port).is_ok())
}

/// Parse NBI events from a JSONL file
pub fn load_nbis_from_jsonl(path: &Path) -> std::io::Result<Vec<NetworkBehaviorIndicator>> {
    std::fs::metadata(path).map_err(|err| {
        std::io::Error::other(format!(
            "failed to read NBI input '{}': {}",
            path.display(),
            err
        ))
    })?;

    let loaded = load_nbis_from_jsonl_detailed(path);
    if let Some(read_error) = loaded.read_error {
        return Err(std::io::Error::other(format!(
            "failed to read NBI input '{}': {}",
            path.display(),
            read_error
        )));
    }
    if loaded.invalid_lines > 0 {
        return Err(std::io::Error::other(format!(
            "failed to read NBI input '{}': {} invalid NBI JSONL lines",
            path.display(),
            loaded.invalid_lines
        )));
    }

    Ok(loaded.events)
}

#[cfg(test)]
#[path = "output_tests.rs"]
mod tests;
