//! CLI subcommand handlers (`config`, `pcap`, `report`, `status`).

use std::path::Path;

use crate::config::EngineConfig;
use crate::engine::config_load::validate_adapter_configuration;
use crate::engine::replay;

pub(crate) fn handle_config(
    args: &crate::cli::ConfigArgs,
    config_path: Option<std::path::PathBuf>,
) -> crate::Result<()> {
    if args.migrate {
        let input = config_path.ok_or_else(|| {
            crate::Error::Config("--migrate requires an input config via --config".to_string())
        })?;
        let output = args.output.as_ref().ok_or_else(|| {
            crate::Error::Config("--migrate requires an output path via --output".to_string())
        })?;
        if paths_refer_to_same_file(&input, output) {
            return Err(crate::Error::Config(
                "migration output must differ from the input config".to_string(),
            ));
        }
        EngineConfig::migrate_file(&input, output)?;
        println!("Config migrated to {}", output.display());
        return Ok(());
    }

    if args.defaults {
        let config = EngineConfig::default();
        if let Some(ref output) = args.output {
            config.to_file(output)?;
            println!("Config written to {}", output.display());
        } else {
            let toml_str = toml::to_string_pretty(&config)
                .map_err(|e| crate::Error::Config(format!("Failed to serialize config: {}", e)))?;
            println!("{}", toml_str);
        }
        return Ok(());
    }

    if args.check {
        if let Some(ref path) = config_path {
            return check_config_paths(std::slice::from_ref(path));
        }

        let files = toml_paths_from_dir_entries(
            std::fs::read_dir(".")?.map(|entry| entry.map(|entry| entry.path())),
        )?;

        return check_config_paths(&files);
    }

    let config = if let Some(ref path) = config_path {
        EngineConfig::from_file_declarative(path)?
    } else {
        EngineConfig::default()
    };

    if let Some(ref output) = args.output {
        config.to_file(output)?;
        println!("Config written to {}", output.display());
    } else {
        let toml_str = toml::to_string_pretty(&config)
            .map_err(|e| crate::Error::Config(format!("Failed to serialize config: {}", e)))?;
        println!("{}", toml_str);
    }

    Ok(())
}

pub(crate) fn check_config_paths(paths: &[std::path::PathBuf]) -> crate::Result<()> {
    let mut invalid_configs = Vec::new();

    for path in paths {
        match EngineConfig::from_file(path).and_then(|config| {
            validate_adapter_configuration(&config)?;
            Ok(config)
        }) {
            Ok(_) => println!("✓ {} is valid", path.display()),
            Err(err) => {
                println!("✗ {} is invalid: {}", path.display(), err);
                invalid_configs.push((path.clone(), err));
            }
        }
    }

    if invalid_configs.is_empty() {
        return Ok(());
    }

    let invalid_summary = invalid_configs
        .iter()
        .map(|(path, _)| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");

    Err(crate::Error::Config(format!(
        "Configuration validation failed for {} file(s): {}",
        invalid_configs.len(),
        invalid_summary
    )))
}

pub(crate) fn handle_pcap(args: &crate::cli::PcapArgs, _verbose: bool) -> crate::Result<()> {
    if args.live {
        return Err(crate::Error::Other(
            "`--live` is not valid for offline PCAP replay; use `nettrap run --pcap` for live capture"
                .to_string(),
        ));
    }

    if let Some(output) = args.output.as_deref()
        && paths_refer_to_same_file(output, &args.input)
    {
        return Err(crate::Error::Other(format!(
            "PCAP replay output path must differ from input path: {}",
            output.display()
        )));
    }

    let (output_path, count) = replay::replay_pcap(&args.input, args.output.as_deref())?;
    println!(
        "PCAP replayed: {} ({} indicator(s)) from {}",
        output_path.display(),
        count,
        args.input.display()
    );
    Ok(())
}

pub(crate) fn handle_report(args: &crate::cli::ReportArgs) -> crate::Result<()> {
    let mut events = load_report_events(&args.input)?;
    events.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));

    let format = match args.format.as_deref() {
        Some(raw) => raw
            .parse::<crate::output::ExportFormat>()
            .map_err(|err| crate::Error::Config(err.to_string()))?,
        None => args
            .output
            .as_deref()
            .and_then(infer_report_format_from_path)
            .unwrap_or(crate::output::ExportFormat::Jsonl),
    };

    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| derived_report_output_path(&args.input, format));
    if paths_refer_to_same_file(&output_path, &args.input) {
        return Err(crate::Error::Other(format!(
            "Report output path must differ from input path: {}",
            output_path.display()
        )));
    }
    crate::output::export_nbis(&events, format, &output_path)?;

    println!(
        "Report written to {} ({} event(s), {})",
        output_path.display(),
        events.len(),
        format.extension()
    );
    Ok(())
}

fn paths_refer_to_same_file(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }

    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn derived_report_output_path(
    input: &Path,
    format: crate::output::ExportFormat,
) -> std::path::PathBuf {
    let derived = input.with_extension(format.extension());
    if derived != input {
        return derived;
    }

    let mut file_name = input
        .file_stem()
        .map(std::ffi::OsString::from)
        .unwrap_or_else(|| std::ffi::OsString::from("output"));
    file_name.push(".generated.");
    file_name.push(format.extension());

    input
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(file_name)
}

pub(crate) fn load_report_events(
    path: &Path,
) -> crate::Result<Vec<crate::nbi::NetworkBehaviorIndicator>> {
    let content = crate::output::read_report_input_to_string(path)?;
    let trimmed = content.trim_matches([' ', '\t', '\r', '\n']);
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let parse_as_json_document =
        path_has_json_extension(path) || trimmed.starts_with('[') || trimmed.starts_with('{');

    if parse_as_json_document {
        match parse_report_json_document(trimmed) {
            Ok(mut events) => {
                validate_report_events(path, &events)?;
                normalize_report_event_ids(&mut events);
                return Ok(events);
            }
            Err(err)
                if path_has_json_extension(path)
                    || !trimmed.contains('\n')
                    || !matches!(
                        err.classify(),
                        serde_json::error::Category::Syntax | serde_json::error::Category::Eof
                    ) =>
            {
                return Err(crate::Error::Other(format!(
                    "Failed to parse report input '{}': {}",
                    path.display(),
                    err
                )));
            }
            Err(_) => {}
        }
    }

    let loaded = crate::output::load_nbis_from_jsonl_detailed(path);
    if let Some(err) = loaded.read_error {
        return Err(crate::Error::Other(format!(
            "Failed to read report input '{}': {}",
            path.display(),
            err
        )));
    }
    if loaded.invalid_lines > 0 {
        return Err(crate::Error::Other(format!(
            "Report input '{}' contains {} invalid JSONL line(s)",
            path.display(),
            loaded.invalid_lines
        )));
    }

    Ok(loaded.events)
}

fn validate_report_events(
    path: &Path,
    events: &[crate::nbi::NetworkBehaviorIndicator],
) -> crate::Result<()> {
    for event in events {
        event.validate_resource_bounds().map_err(|err| {
            crate::Error::Other(format!(
                "Report input '{}' contains invalid NBI event: {}",
                path.display(),
                err
            ))
        })?;
    }

    Ok(())
}

pub(crate) fn parse_report_json_document(
    content: &str,
) -> Result<Vec<crate::nbi::NetworkBehaviorIndicator>, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_str(content)?;
    match value {
        serde_json::Value::Array(events) => {
            if events.len() > crate::output::MAX_REPORT_EVENTS {
                return Err(report_json_error(format!(
                    "report input exceeds event limit ({} > {} events)",
                    events.len(),
                    crate::output::MAX_REPORT_EVENTS
                )));
            }
            events
                .into_iter()
                .map(parse_report_json_event)
                .collect::<Result<Vec<_>, _>>()
        }
        other => parse_report_json_event(other).map(|event| vec![event]),
    }
}

fn parse_report_json_event(
    value: serde_json::Value,
) -> Result<crate::nbi::NetworkBehaviorIndicator, serde_json::Error> {
    serde_json::from_value::<crate::nbi::NetworkBehaviorIndicator>(value.clone()).or_else(|_| {
        serde_json::from_value::<LegacyReportNetworkBehaviorIndicator>(value)
            .and_then(try_from_legacy_report_network_behavior_indicator)
    })
}

#[derive(Debug, serde::Deserialize)]
struct LegacyReportNetworkBehaviorIndicator {
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

fn try_from_legacy_report_network_behavior_indicator(
    value: LegacyReportNetworkBehaviorIndicator,
) -> Result<crate::nbi::NetworkBehaviorIndicator, serde_json::Error> {
    let protocol = parse_legacy_report_protocol(&value.protocol)?;
    let src_ip = value.src_ip;
    validate_legacy_report_ip("src_ip", &src_ip)?;
    let dst_ip = match value.dst_ip {
        Some(dst_ip) => {
            validate_legacy_report_ip("dst_ip", &dst_ip)?;
            dst_ip
        }
        None => legacy_unknown_destination_ip_for_source(&src_ip),
    };
    let mut event = crate::nbi::NetworkBehaviorIndicator::new(
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
    event.event_id = value.event_id.unwrap_or_default();
    if should_normalize_legacy_report_event_id(&event.event_id) {
        event.event_id = event.normalized_event_id();
    }
    Ok(event)
}

fn should_normalize_legacy_report_event_id(event_id: &str) -> bool {
    let event_id = event_id.trim_matches([' ', '\t']);
    event_id.is_empty()
        || (event_id.starts_with("legacy-db-")
            && !event_id
                .chars()
                .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' ')))
}

fn trim_ascii_edges(value: &str) -> &str {
    value.trim_matches(|ch| matches!(ch, ' ' | '\t' | '\r' | '\n' | '\u{000C}'))
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

fn parse_legacy_report_protocol(value: &str) -> Result<String, serde_json::Error> {
    if value.trim_matches([' ', '\t']) != value
        || value.is_empty()
        || value
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return Err(legacy_report_error(format!(
            "NBI protocol '{}' contains unsafe line-break or control characters",
            value
        )));
    }

    Ok(value.to_ascii_uppercase())
}

fn validate_legacy_report_ip(field: &str, value: &str) -> Result<(), serde_json::Error> {
    value.parse::<std::net::IpAddr>().map_err(|err| {
        legacy_report_error(format!(
            "NBI {} contains invalid IP '{}': {}",
            field, value, err
        ))
    })?;
    Ok(())
}

fn legacy_report_error(message: impl Into<String>) -> serde_json::Error {
    report_json_error(message)
}

fn report_json_error(message: impl Into<String>) -> serde_json::Error {
    serde_json::Error::io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))
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

pub(crate) fn normalize_report_event_ids(events: &mut [crate::nbi::NetworkBehaviorIndicator]) {
    for event in events {
        event.event_id = event.normalized_event_id();
    }
}

fn has_toml_extension(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        path.extension()
            .map(|ext| ext.as_bytes().eq_ignore_ascii_case(b"toml"))
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    {
        path.extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
    }
}

fn toml_paths_from_dir_entries<I>(entries: I) -> std::io::Result<Vec<std::path::PathBuf>>
where
    I: IntoIterator<Item = std::io::Result<std::path::PathBuf>>,
{
    let mut files = Vec::new();
    for entry in entries {
        let path = entry?;
        if has_toml_extension(&path) {
            files.push(path);
        }
    }
    Ok(files)
}

fn path_has_json_extension(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        path.extension()
            .map(|ext| ext.as_bytes().eq_ignore_ascii_case(b"json"))
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    {
        path.extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
    }
}

pub(crate) fn infer_report_format_from_path(path: &Path) -> Option<crate::output::ExportFormat> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        let file_name = path.file_name()?.as_bytes();
        if ends_with_ascii_case_insensitive(file_name, b".sarif.json") {
            return Some(crate::output::ExportFormat::Sarif);
        }

        let extension = path.extension()?.as_bytes();
        match ascii_lowercase_bytes(extension).as_slice() {
            b"json" => Some(crate::output::ExportFormat::Json),
            b"jsonl" | b"ndjson" => Some(crate::output::ExportFormat::Jsonl),
            b"sarif" => Some(crate::output::ExportFormat::Sarif),
            b"toon" => Some(crate::output::ExportFormat::Toon),
            b"csv" => Some(crate::output::ExportFormat::Csv),
            _ => None,
        }
    }

    #[cfg(not(unix))]
    {
        let file_name = path.file_name()?.to_str()?.to_ascii_lowercase();
        if file_name.ends_with(".sarif.json") {
            return Some(crate::output::ExportFormat::Sarif);
        }

        match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
            "json" => Some(crate::output::ExportFormat::Json),
            "jsonl" | "ndjson" => Some(crate::output::ExportFormat::Jsonl),
            "sarif" => Some(crate::output::ExportFormat::Sarif),
            "toon" => Some(crate::output::ExportFormat::Toon),
            "csv" => Some(crate::output::ExportFormat::Csv),
            _ => None,
        }
    }
}

#[cfg(unix)]
fn ends_with_ascii_case_insensitive(haystack: &[u8], suffix: &[u8]) -> bool {
    haystack.len() >= suffix.len()
        && haystack[haystack.len() - suffix.len()..]
            .iter()
            .zip(suffix.iter())
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

#[cfg(unix)]
fn ascii_lowercase_bytes(input: &[u8]) -> Vec<u8> {
    input.iter().map(u8::to_ascii_lowercase).collect()
}

fn render_status_lines(json: bool) -> Vec<String> {
    if json {
        vec![format!(
            "{{\"status\": \"ok\", \"version\": \"{}\"}}",
            env!("CARGO_PKG_VERSION")
        )]
    } else {
        vec![
            "NetTrap Status: OK".to_string(),
            format!("Version: {}", env!("CARGO_PKG_VERSION")),
        ]
    }
}

pub(crate) fn handle_status(args: &crate::cli::StatusArgs) -> crate::Result<()> {
    for line in render_status_lines(args.json) {
        println!("{}", line);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::infer_report_format_from_path;
    use super::load_report_events;
    use super::render_status_lines;
    #[cfg(unix)]
    use std::ffi::OsString;

    #[test]
    fn load_report_events_rejects_unicode_whitespace_prefixed_json() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-report-unicode-{}.json",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, "\u{00a0}[{\"id\":\"1\"}]").expect("write report fixture");

        let err = match load_report_events(&path) {
            Ok(_) => panic!("unicode whitespace-prefixed JSON should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("Failed to parse report input"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn render_status_lines_uses_the_package_version() {
        assert_eq!(
            render_status_lines(true),
            vec![format!(
                "{{\"status\": \"ok\", \"version\": \"{}\"}}",
                env!("CARGO_PKG_VERSION")
            )]
        );
        assert_eq!(
            render_status_lines(false),
            vec![
                "NetTrap Status: OK".to_string(),
                format!("Version: {}", env!("CARGO_PKG_VERSION"))
            ]
        );
    }

    #[test]
    fn load_report_events_rejects_invalid_json_array_nbi() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-report-invalid-nbi-{}.json",
            uuid::Uuid::new_v4()
        ));
        let value = "v".repeat(nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS + 1);
        std::fs::write(
            &path,
            format!(
                r#"[{{"event_id":"1","listener":"raw","protocol":"RAW","src_ip":"127.0.0.1","src_port":1,"dst_ip":"127.0.0.1","dst_port":2,"process_name":null,"process_pid":null,"indicators":{{"key":"{value}"}},"timestamp":"2024-01-01T00:00:00Z"}}]"#
            ),
        )
        .expect("write report fixture");

        let err = load_report_events(&path).expect_err("invalid JSON NBI should fail");

        assert!(err.to_string().contains("invalid NBI event"));
        assert!(err.to_string().contains("indicator value"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_report_events_rejects_invalid_json_object_nbi() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-report-invalid-nbi-object-{}.json",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            r#"{"event_id":"1","listener":"raw\nproto","protocol":"RAW","src_ip":"127.0.0.1","src_port":1,"dst_ip":"127.0.0.1","dst_port":2,"process_name":null,"process_pid":null,"indicators":{},"timestamp":"2024-01-01T00:00:00Z"}"#,
        )
        .expect("write report fixture");

        let err = load_report_events(&path).expect_err("invalid JSON NBI should fail");

        assert!(err.to_string().contains("invalid NBI event"));
        assert!(err.to_string().contains("listener"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_report_events_accepts_pretty_printed_json_object_without_extension() {
        let path =
            std::env::temp_dir().join(format!("nettrap-report-pretty-{}", uuid::Uuid::new_v4()));
        std::fs::write(
            &path,
            concat!(
                "{\n",
                "  \"event_id\": \"legacy-db-1\",\n",
                "  \"listener\": \"raw\",\n",
                "  \"protocol\": \"RAW\",\n",
                "  \"src_ip\": \"127.0.0.1\",\n",
                "  \"src_port\": 1,\n",
                "  \"dst_ip\": \"127.0.0.1\",\n",
                "  \"dst_port\": 2,\n",
                "  \"process_name\": null,\n",
                "  \"process_pid\": null,\n",
                "  \"indicators\": {},\n",
                "  \"timestamp\": \"2024-01-01T00:00:00Z\"\n",
                "}\n"
            ),
        )
        .expect("write report fixture");

        let events = load_report_events(&path).expect("pretty JSON object should load");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, events[0].normalized_event_id());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_report_events_accepts_legacy_json_object_without_event_id() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-report-legacy-object-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            concat!(
                "{\n",
                "  \"timestamp\": \"2024-01-01T00:00:00Z\",\n",
                "  \"listener\": \"raw\",\n",
                "  \"protocol\": \"RAW\",\n",
                "  \"src_ip\": \"127.0.0.1\",\n",
                "  \"src_port\": 1,\n",
                "  \"dst_port\": 2,\n",
                "  \"process_name\": null,\n",
                "  \"process_pid\": null,\n",
                "  \"indicators\": {}\n",
                "}\n"
            ),
        )
        .expect("write report fixture");

        let events = load_report_events(&path).expect("legacy JSON object should load");

        assert_eq!(events.len(), 1);
        assert!(events[0].event_id.starts_with("legacy-"));
        assert_eq!(events[0].event_id, events[0].normalized_event_id());
        assert_eq!(events[0].dst_ip, "0.0.0.0");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_report_events_preserves_explicit_legacy_json_event_id() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-report-legacy-event-id-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            concat!(
                "{\n",
                "  \"event_id\": \"event-explicit\",\n",
                "  \"timestamp\": \"2024-01-01T00:00:00Z\",\n",
                "  \"listener\": \"raw\",\n",
                "  \"protocol\": \"RAW\",\n",
                "  \"src_ip\": \"127.0.0.1\",\n",
                "  \"src_port\": 1,\n",
                "  \"dst_port\": 2,\n",
                "  \"process_name\": null,\n",
                "  \"process_pid\": null,\n",
                "  \"indicators\": {}\n",
                "}\n"
            ),
        )
        .expect("write report fixture");

        let events = load_report_events(&path).expect("legacy JSON object should load");

        assert_eq!(events[0].event_id, "event-explicit");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_report_events_trims_legacy_json_listener_padding() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-report-legacy-listener-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            concat!(
                "{\n",
                "  \"timestamp\": \"2024-01-01T00:00:00Z\",\n",
                "  \"listener\": \" raw\\t\",\n",
                "  \"protocol\": \"RAW\",\n",
                "  \"src_ip\": \"127.0.0.1\",\n",
                "  \"src_port\": 1,\n",
                "  \"dst_port\": 2,\n",
                "  \"process_name\": null,\n",
                "  \"process_pid\": null,\n",
                "  \"indicators\": {}\n",
                "}\n"
            ),
        )
        .expect("write report fixture");

        let events = load_report_events(&path).expect("legacy JSON object should load");

        assert_eq!(events[0].listener, "raw");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_report_events_sanitizes_legacy_json_process_name() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-report-legacy-process-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            concat!(
                "{\n",
                "  \"timestamp\": \"2024-01-01T00:00:00Z\",\n",
                "  \"listener\": \"raw\",\n",
                "  \"protocol\": \"RAW\",\n",
                "  \"src_ip\": \"127.0.0.1\",\n",
                "  \"src_port\": 1,\n",
                "  \"dst_port\": 2,\n",
                "  \"process_name\": \" alpha\\nbeta \",\n",
                "  \"process_pid\": 4242,\n",
                "  \"indicators\": {}\n",
                "}\n"
            ),
        )
        .expect("write report fixture");

        let events = load_report_events(&path).expect("legacy JSON object should load");

        assert_eq!(events[0].process_name.as_deref(), Some(" alpha beta "));
        assert_eq!(events[0].process_pid, Some(4242));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_report_events_defaults_missing_dst_ip_to_source_family_unknown_destination() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-report-legacy-object-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            concat!(
                "{\n",
                "  \"timestamp\": \"2024-01-01T00:00:00Z\",\n",
                "  \"listener\": \"raw\",\n",
                "  \"protocol\": \"RAW\",\n",
                "  \"src_ip\": \"::1\",\n",
                "  \"src_port\": 1,\n",
                "  \"dst_port\": 2,\n",
                "  \"process_name\": null,\n",
                "  \"process_pid\": null,\n",
                "  \"indicators\": {}\n",
                "}\n"
            ),
        )
        .expect("write report fixture");

        let events = load_report_events(&path).expect("legacy JSON object should load");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].dst_ip, "::");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_report_events_treats_mapped_source_as_ipv4_for_missing_dst_ip() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-report-legacy-object-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            concat!(
                "{\n",
                "  \"timestamp\": \"2024-01-01T00:00:00Z\",\n",
                "  \"listener\": \"raw\",\n",
                "  \"protocol\": \"RAW\",\n",
                "  \"src_ip\": \"::ffff:127.0.0.1\",\n",
                "  \"src_port\": 1,\n",
                "  \"dst_port\": 2,\n",
                "  \"process_name\": null,\n",
                "  \"process_pid\": null,\n",
                "  \"indicators\": {}\n",
                "}\n"
            ),
        )
        .expect("write report fixture");

        let events = load_report_events(&path).expect("legacy JSON object should load");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].src_ip, "127.0.0.1");
        assert_eq!(events[0].dst_ip, "0.0.0.0");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_report_events_accepts_legacy_json_array_without_event_ids() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-report-legacy-array-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            concat!(
                "[\n",
                "  {\n",
                "    \"timestamp\": \"2024-01-01T00:00:00Z\",\n",
                "    \"listener\": \"raw\",\n",
                "    \"protocol\": \"RAW\",\n",
                "    \"src_ip\": \"127.0.0.1\",\n",
                "    \"src_port\": 1,\n",
                "    \"dst_port\": 2,\n",
                "    \"process_name\": null,\n",
                "    \"process_pid\": null,\n",
                "    \"indicators\": {}\n",
                "  }\n",
                "]\n"
            ),
        )
        .expect("write report fixture");

        let events = load_report_events(&path).expect("legacy JSON array should load");

        assert_eq!(events.len(), 1);
        assert!(events[0].event_id.starts_with("legacy-"));
        assert_eq!(events[0].dst_ip, "0.0.0.0");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_report_events_rejects_json_arrays_over_event_limit_before_conversion() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-report-too-many-events-{}.json",
            uuid::Uuid::new_v4()
        ));
        let mut content = String::from("[{}");
        for _ in 0..crate::output::MAX_REPORT_EVENTS {
            content.push_str(",{}");
        }
        content.push(']');
        std::fs::write(&path, content).expect("write report fixture");

        let err = load_report_events(&path).expect_err("oversized JSON arrays should fail");

        assert!(err.to_string().contains("exceeds event limit"), "{err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_report_events_rejects_legacy_json_object_with_invalid_source_ip() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-report-legacy-bad-ip-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            concat!(
                "{\n",
                "  \"timestamp\": \"2024-01-01T00:00:00Z\",\n",
                "  \"listener\": \"raw\",\n",
                "  \"protocol\": \"RAW\",\n",
                "  \"src_ip\": \"not-an-ip\",\n",
                "  \"src_port\": 1,\n",
                "  \"dst_port\": 2,\n",
                "  \"process_name\": null,\n",
                "  \"process_pid\": null,\n",
                "  \"indicators\": {}\n",
                "}\n"
            ),
        )
        .expect("write report fixture");

        let err = load_report_events(&path).expect_err("invalid legacy JSON should fail");

        assert!(err.to_string().contains("Failed to parse report input"));
        assert!(err.to_string().contains("invalid IP"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_report_events_rejects_legacy_json_object_with_padded_protocol() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-report-legacy-bad-proto-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            concat!(
                "{\n",
                "  \"timestamp\": \"2024-01-01T00:00:00Z\",\n",
                "  \"listener\": \"raw\",\n",
                "  \"protocol\": \" RAW \",\n",
                "  \"src_ip\": \"127.0.0.1\",\n",
                "  \"src_port\": 1,\n",
                "  \"dst_port\": 2,\n",
                "  \"process_name\": null,\n",
                "  \"process_pid\": null,\n",
                "  \"indicators\": {}\n",
                "}\n"
            ),
        )
        .expect("write report fixture");

        let err = load_report_events(&path).expect_err("invalid legacy JSON should fail");

        assert!(err.to_string().contains("Failed to parse report input"));
        assert!(
            err.to_string()
                .contains("unsafe line-break or control characters")
        );
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn has_toml_extension_accepts_non_utf8_names() {
        use std::os::unix::ffi::OsStringExt;

        let path = std::path::PathBuf::from(OsString::from_vec(b"config-\xff.toml".to_vec()));

        assert!(super::has_toml_extension(&path));
    }

    #[test]
    fn toml_path_scan_propagates_directory_entry_errors() {
        let entries = vec![
            Ok(std::path::PathBuf::from("valid.toml")),
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "entry denied",
            )),
        ];

        let err = super::toml_paths_from_dir_entries(entries)
            .expect_err("directory entry errors must not be ignored");

        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn load_report_events_accepts_non_utf8_json_filename() {
        use std::os::unix::ffi::OsStringExt;

        let path = std::path::PathBuf::from(OsString::from_vec(b"report-\xff.json".to_vec()));
        std::fs::write(&path, r#"[{"event_id":"1","listener":"x","protocol":"RAW","src_ip":"127.0.0.1","src_port":1,"dst_ip":"127.0.0.1","dst_port":2,"process_name":"p","process_pid":1,"indicators":{},"timestamp":"2024-01-01T00:00:00Z"}]"#)
            .expect("write report fixture");

        let events = load_report_events(&path).expect("non-UTF8 json filename should load");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, events[0].normalized_event_id());

        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn infer_report_format_from_path_accepts_non_utf8_base_names() {
        use std::os::unix::ffi::OsStringExt;

        let path = std::path::PathBuf::from(OsString::from_vec(b"report-\xff.sarif.json".to_vec()));

        assert_eq!(
            infer_report_format_from_path(&path),
            Some(crate::output::ExportFormat::Sarif)
        );
    }
}
