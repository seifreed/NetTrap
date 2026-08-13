use super::*;
use crate::nbi::raw_nbi;
use crate::session::SessionDestination;

#[test]
fn csv_escape_guards_formulas_after_leading_whitespace() {
    assert_eq!(csv_escape("=cmd"), "\"'=cmd\"");
    assert_eq!(csv_escape(" =cmd"), "\"' =cmd\"");
    assert_eq!(csv_escape("\t@cmd"), "\"'\t@cmd\"");
    assert_eq!(csv_escape("\u{00a0}=cmd"), "\"'\u{00a0}=cmd\"");
    assert_eq!(csv_escape("bell\u{0007}value"), "\"bell\\u0007value\"");
    assert_eq!(csv_escape("line\u{2028}value"), "\"line\\u2028value\"");
    assert_eq!(csv_escape("line\nvalue"), "\"line\nvalue\"");
    assert_eq!(csv_escape("normal"), "normal");
}

#[test]
fn toon_escapes_keys_and_string_values_per_format_rules() {
    let path =
        std::env::temp_dir().join(format!("nettrap-output-toon-{}.toon", uuid::Uuid::new_v4()));
    let destination = SessionDestination::unknown(8080);
    let mut event = raw_nbi("raw", "2001:db8::1", 12345, &destination, 4, "");
    event.listener = "leading".to_string();
    event.add("flag", "true");
    event.add("line", "one\ntwo");
    event.add("unicode_line", "alpha\u{2028}beta");
    event.add("number_string", "05");
    event.add("quoted-key", "say \"hi\" \\ path");
    event.add("control\u{0007}key", "bell\u{0000}value");

    export_nbis(&[event], ExportFormat::Toon, &path).unwrap();

    let output = std::fs::read_to_string(&path).unwrap();
    assert!(output.contains(
            "raw_events[1]{timestamp,listener,src_ip,src_port,dst_ip,dst_port,\"control key\",data_length,flag,line,number_string,\"quoted-key\",unicode_line}:"
        ));
    assert!(output.contains("leading"));
    assert!(output.contains("\"2001:db8::1\""));
    assert!(output.contains("\"4\""));
    assert!(output.contains("\"true\""));
    assert!(output.contains("one two"));
    assert!(output.contains("\"05\""));
    assert!(output.contains("\"say \\\"hi\\\" \\\\ path\""));
    assert!(output.contains("bell value"));
    assert!(!output.contains("one\ntwo"));
    assert!(!output.contains("one\\ntwo"));
    assert!(!output.contains("alpha\u{2028}beta"));
    assert!(!output.contains('\u{0000}'));
    assert!(!output.contains('\u{0007}'));

    let _ = std::fs::remove_file(path);
}

#[test]
fn sarif_export_uses_logical_locations_array() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-sarif-{}.sarif",
        uuid::Uuid::new_v4()
    ));
    let event = raw_nbi(
        "raw",
        "127.0.0.1",
        12345,
        &SessionDestination::unknown(8080),
        4,
        "",
    );

    export_nbis(&[event], ExportFormat::Sarif, &path).expect("SARIF export should succeed");

    let output = std::fs::read_to_string(&path).expect("SARIF file should be readable");
    let json: serde_json::Value =
        serde_json::from_str(&output).expect("SARIF output should be JSON");
    let location = &json["runs"][0]["results"][0]["locations"][0];

    assert!(location.get("logicalLocation").is_none());
    assert_eq!(
        location["logicalLocations"][0]["fullyQualifiedName"],
        "127.0.0.1:12345 -> 0.0.0.0:8080"
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn sarif_message_bounds_untrusted_indicator_text() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-sarif-bounds-{}.sarif",
        uuid::Uuid::new_v4()
    ));
    let destination = SessionDestination::unknown(8080);
    let mut event = raw_nbi("raw proto", "127.0.0.1", 12345, &destination, 4, "");
    let long_value = "b".repeat(300);
    event.add("line\nkey", long_value.clone());
    for index in 0..40 {
        event.add(format!("k{index:02}"), format!("v{index}"));
    }

    export_nbis(&[event], ExportFormat::Sarif, &path).expect("SARIF export should succeed");

    let output = std::fs::read_to_string(&path).expect("SARIF file should be readable");
    let json: serde_json::Value =
        serde_json::from_str(&output).expect("SARIF output should be JSON");
    let message = json["runs"][0]["results"][0]["message"]["text"]
        .as_str()
        .expect("SARIF message should be text");

    assert!(!message.contains('\n'));
    assert!(message.contains("more indicators omitted"));
    assert!(!message.contains(&long_value));
    let bounded_value = nettrap_core::sanitize::single_line(&long_value);
    assert_eq!(
        json["runs"][0]["results"][0]["properties"]["indicators"]["line key"],
        bounded_value
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn load_nbis_from_jsonl_detailed_preserves_unicode_line_separators_inside_event_logs() {
    let root = std::env::temp_dir().join(format!("nettrap-output-jsonl-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("events.jsonl");
    let line = serde_json::json!({
        "timestamp": "2026-07-01T00:00:00Z",
        "listener": "http",
        "src_ip": "127.0.0.1",
        "src_port": 12345,
        "event": "info",
        "detail": "alpha\u{2028}beta",
    })
    .to_string();
    std::fs::write(&path, format!("{line}\n")).unwrap();

    let result = load_nbis_from_jsonl_detailed(&path);

    assert_eq!(result.events.len(), 0);
    assert_eq!(result.invalid_lines, 0);
    assert!(result.read_error.is_none());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn load_nbis_from_jsonl_detailed_defaults_missing_dst_ip_to_unknown_destination() {
    let root = std::env::temp_dir().join(format!("nettrap-output-jsonl-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("events.jsonl");
    std::fs::write(
        &path,
        concat!(
            "{\"event_id\":\"legacy-1\",\"timestamp\":\"2026-07-01T00:00:00Z\",",
            "\"listener\":\"raw\",\"protocol\":\"RAW\",\"src_ip\":\"127.0.0.1\",",
            "\"src_port\":1234,\"dst_port\":8080,\"process_name\":null,",
            "\"process_pid\":null,\"indicators\":{}}\n"
        ),
    )
    .unwrap();

    let result = load_nbis_from_jsonl_detailed(&path);

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0].dst_ip, "0.0.0.0");
    assert_eq!(result.invalid_lines, 0);
    assert!(result.read_error.is_none());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn load_nbis_from_jsonl_detailed_defaults_missing_dst_ip_to_source_family_unknown_destination() {
    let root = std::env::temp_dir().join(format!("nettrap-output-jsonl-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("events.jsonl");
    std::fs::write(
        &path,
        concat!(
            "{\"event_id\":\"legacy-1\",\"timestamp\":\"2026-07-01T00:00:00Z\",",
            "\"listener\":\"raw\",\"protocol\":\"RAW\",\"src_ip\":\"::1\",",
            "\"src_port\":1234,\"dst_port\":8080,\"process_name\":null,",
            "\"process_pid\":null,\"indicators\":{}}\n"
        ),
    )
    .unwrap();

    let result = load_nbis_from_jsonl_detailed(&path);

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0].dst_ip, "::");
    assert_eq!(result.invalid_lines, 0);
    assert!(result.read_error.is_none());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn load_nbis_from_jsonl_detailed_treats_mapped_source_as_ipv4_for_missing_dst_ip() {
    let root = std::env::temp_dir().join(format!("nettrap-output-jsonl-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("events.jsonl");
    std::fs::write(
        &path,
        concat!(
            "{\"event_id\":\"legacy-1\",\"timestamp\":\"2026-07-01T00:00:00Z\",",
            "\"listener\":\"raw\",\"protocol\":\"RAW\",\"src_ip\":\"::ffff:127.0.0.1\",",
            "\"src_port\":1234,\"dst_port\":8080,\"process_name\":null,",
            "\"process_pid\":null,\"indicators\":{}}\n"
        ),
    )
    .unwrap();

    let result = load_nbis_from_jsonl_detailed(&path);

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0].src_ip, "127.0.0.1");
    assert_eq!(result.events[0].dst_ip, "0.0.0.0");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn load_nbis_from_jsonl_detailed_defaults_missing_event_id_to_legacy_id() {
    let root = std::env::temp_dir().join(format!("nettrap-output-jsonl-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("events.jsonl");
    std::fs::write(
        &path,
        concat!(
            "{\"timestamp\":\"2026-07-01T00:00:00Z\",\"listener\":\"raw\",",
            "\"protocol\":\"RAW\",\"src_ip\":\"127.0.0.1\",\"src_port\":1234,",
            "\"dst_ip\":\"198.51.100.7\",\"dst_port\":8080,\"process_name\":null,",
            "\"process_pid\":null,\"indicators\":{}}\n"
        ),
    )
    .unwrap();

    let result = load_nbis_from_jsonl_detailed(&path);

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0].dst_ip, "198.51.100.7");
    assert!(result.events[0].event_id.starts_with("legacy-"));
    assert_eq!(result.invalid_lines, 0);
    assert!(result.read_error.is_none());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn load_nbis_from_jsonl_detailed_canonicalizes_blank_event_id_to_legacy_id() {
    let root = std::env::temp_dir().join(format!("nettrap-output-jsonl-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("events.jsonl");
    std::fs::write(
        &path,
        concat!(
            "{\"event_id\":\"\",\"timestamp\":\"2026-07-01T00:00:00Z\",\"listener\":\"raw\",",
            "\"protocol\":\"raw\",\"src_ip\":\"127.0.0.1\",\"src_port\":1234,",
            "\"dst_ip\":\"198.51.100.7\",\"dst_port\":8080,\"process_name\":null,",
            "\"process_pid\":null,\"indicators\":{}}\n"
        ),
    )
    .unwrap();

    let result = load_nbis_from_jsonl_detailed(&path);

    assert_eq!(result.events.len(), 1);
    assert!(result.events[0].event_id.starts_with("legacy-"));
    assert_eq!(result.invalid_lines, 0);
    assert!(result.read_error.is_none());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn load_nbis_from_jsonl_detailed_rejects_invalid_legacy_source_ip() {
    let root = std::env::temp_dir().join(format!("nettrap-output-jsonl-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("events.jsonl");
    std::fs::write(
        &path,
        concat!(
            "{\"event_id\":\"legacy-1\",\"timestamp\":\"2026-07-01T00:00:00Z\",",
            "\"listener\":\"raw\",\"protocol\":\"raw\",\"src_ip\":\"not-an-ip\",",
            "\"src_port\":1234,\"dst_port\":8080,\"process_name\":null,",
            "\"process_pid\":null,\"indicators\":{}}\n"
        ),
    )
    .unwrap();

    let result = load_nbis_from_jsonl_detailed(&path);

    assert!(result.events.is_empty());
    assert_eq!(result.invalid_lines, 1);
    assert!(result.read_error.is_none());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn load_nbis_from_jsonl_detailed_rejects_padded_legacy_protocol() {
    let root = std::env::temp_dir().join(format!("nettrap-output-jsonl-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("events.jsonl");
    std::fs::write(
        &path,
        concat!(
            "{\"event_id\":\"legacy-1\",\"timestamp\":\"2026-07-01T00:00:00Z\",",
            "\"listener\":\"raw\",\"protocol\":\" raw \",\"src_ip\":\"127.0.0.1\",",
            "\"src_port\":1234,\"dst_port\":8080,\"process_name\":null,",
            "\"process_pid\":null,\"indicators\":{}}\n"
        ),
    )
    .unwrap();

    let result = load_nbis_from_jsonl_detailed(&path);

    assert!(result.events.is_empty());
    assert_eq!(result.invalid_lines, 1);
    assert!(result.read_error.is_none());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn load_nbis_from_jsonl_detailed_canonicalizes_legacy_ip_text() {
    let root = std::env::temp_dir().join(format!("nettrap-output-jsonl-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("events.jsonl");
    std::fs::write(
        &path,
        concat!(
            "{\"timestamp\":\"2026-07-01T00:00:00Z\",\"listener\":\"raw\",",
            "\"protocol\":\"raw\",\"src_ip\":\"::ffff:127.0.0.1\",\"src_port\":1234,",
            "\"dst_ip\":\"::ffff:198.51.100.7\",\"dst_port\":8080,\"process_name\":null,",
            "\"process_pid\":null,\"indicators\":{}}\n"
        ),
    )
    .unwrap();

    let result = load_nbis_from_jsonl_detailed(&path);

    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0].src_ip, "127.0.0.1");
    assert_eq!(result.events[0].dst_ip, "198.51.100.7");
    assert_eq!(result.events[0].protocol, "RAW");
    assert!(result.events[0].event_id.starts_with("legacy-"));
    assert_eq!(result.invalid_lines, 0);
    assert!(result.read_error.is_none());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn load_nbis_from_jsonl_detailed_canonicalizes_tab_padded_legacy_event_id() {
    let root = std::env::temp_dir().join(format!("nettrap-output-jsonl-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("events.jsonl");
    std::fs::write(
        &path,
        concat!(
            "{\"event_id\":\"\\tlegacy-db-123\\t\",\"timestamp\":\"2026-07-01T00:00:00Z\",",
            "\"listener\":\"raw\",\"protocol\":\"raw\",\"src_ip\":\"127.0.0.1\",\"src_port\":1234,",
            "\"dst_ip\":\"198.51.100.7\",\"dst_port\":8080,\"process_name\":null,",
            "\"process_pid\":null,\"indicators\":{}}\n"
        ),
    )
    .unwrap();

    let result = load_nbis_from_jsonl_detailed(&path);

    assert_eq!(result.events.len(), 1);
    assert!(result.events[0].event_id.starts_with("legacy-"));
    assert_eq!(result.invalid_lines, 0);
    assert!(result.read_error.is_none());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn load_nbis_from_jsonl_detailed_rejects_line_breaks_in_legacy_event_id() {
    let root = std::env::temp_dir().join(format!("nettrap-output-jsonl-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("events.jsonl");
    std::fs::write(
        &path,
        concat!(
            "{\"event_id\":\"legacy-db-123\\n\",\"timestamp\":\"2026-07-01T00:00:00Z\",",
            "\"listener\":\"raw\",\"protocol\":\"raw\",\"src_ip\":\"127.0.0.1\",\"src_port\":1234,",
            "\"dst_ip\":\"198.51.100.7\",\"dst_port\":8080,\"process_name\":null,",
            "\"process_pid\":null,\"indicators\":{}}\n"
        ),
    )
    .unwrap();

    let result = load_nbis_from_jsonl_detailed(&path);

    assert!(result.events.is_empty());
    assert_eq!(result.invalid_lines, 1);
    assert!(result.read_error.is_none());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn try_from_legacy_jsonl_network_behavior_indicator_defaults_missing_event_id_to_legacy_id() {
    let value = LegacyJsonlNetworkBehaviorIndicator {
        event_id: None,
        timestamp: "2026-07-01T00:00:00Z".to_string(),
        listener: "raw".to_string(),
        protocol: "raw".to_string(),
        src_ip: "127.0.0.1".to_string(),
        src_port: 1234,
        dst_ip: Some("198.51.100.7".to_string()),
        dst_port: 8080,
        process_name: None,
        process_pid: None,
        indicators: std::collections::BTreeMap::new(),
    };

    let event = try_from_legacy_jsonl_network_behavior_indicator(value).unwrap();

    assert!(event.event_id.starts_with("legacy-"));
}

#[test]
fn try_from_legacy_jsonl_network_behavior_indicator_drops_blank_process_name() {
    let value = LegacyJsonlNetworkBehaviorIndicator {
        event_id: None,
        timestamp: "2026-07-01T00:00:00Z".to_string(),
        listener: "raw".to_string(),
        protocol: "raw".to_string(),
        src_ip: "127.0.0.1".to_string(),
        src_port: 1234,
        dst_ip: Some("198.51.100.7".to_string()),
        dst_port: 8080,
        process_name: Some("   ".to_string()),
        process_pid: None,
        indicators: std::collections::BTreeMap::new(),
    };

    let event = try_from_legacy_jsonl_network_behavior_indicator(value).unwrap();

    assert!(event.process_name.is_none());
}

#[test]
fn try_from_legacy_jsonl_network_behavior_indicator_trims_legacy_listener_padding() {
    let value = LegacyJsonlNetworkBehaviorIndicator {
        event_id: None,
        timestamp: "2026-07-01T00:00:00Z".to_string(),
        listener: " raw\t".to_string(),
        protocol: "raw".to_string(),
        src_ip: "127.0.0.1".to_string(),
        src_port: 1234,
        dst_ip: Some("198.51.100.7".to_string()),
        dst_port: 8080,
        process_name: None,
        process_pid: None,
        indicators: std::collections::BTreeMap::new(),
    };

    let event = try_from_legacy_jsonl_network_behavior_indicator(value).unwrap();

    assert_eq!(event.listener, "raw");
}

#[test]
fn try_from_legacy_jsonl_network_behavior_indicator_sanitizes_legacy_process_name() {
    let value = LegacyJsonlNetworkBehaviorIndicator {
        event_id: None,
        timestamp: "2026-07-01T00:00:00Z".to_string(),
        listener: "raw".to_string(),
        protocol: "raw".to_string(),
        src_ip: "127.0.0.1".to_string(),
        src_port: 1234,
        dst_ip: Some("198.51.100.7".to_string()),
        dst_port: 8080,
        process_name: Some(" alpha\nbeta ".to_string()),
        process_pid: Some(4242),
        indicators: std::collections::BTreeMap::new(),
    };

    let event = try_from_legacy_jsonl_network_behavior_indicator(value).unwrap();

    assert_eq!(event.process_name.as_deref(), Some(" alpha beta "));
}

#[test]
fn export_nbis_creates_parent_directories() {
    let root = std::env::temp_dir().join(format!("nettrap-output-parent-{}", uuid::Uuid::new_v4()));
    let path = root.join("nested").join("events.jsonl");
    let event = raw_nbi(
        "raw",
        "127.0.0.1",
        12345,
        &SessionDestination::unknown(8080),
        4,
        "",
    );

    export_nbis(&[event], ExportFormat::Jsonl, &path)
        .expect("export should create parent directories");

    assert!(path.is_file());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_atomically_replaces_existing_file_contents() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-atomic-success-{}.txt",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&path, "original").expect("seed output file");

    write_atomically(&path, |file| {
        use std::io::Write;

        file.write_all(b"replacement")
    })
    .expect("atomic write should replace existing file");

    assert_eq!(std::fs::read_to_string(&path).unwrap(), "replacement");
    let _ = std::fs::remove_file(path);
}

#[test]
fn write_atomically_preserves_existing_file_on_write_failure() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-atomic-failure-{}.txt",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&path, "original").expect("seed output file");

    let err = write_atomically(&path, |file| {
        use std::io::Write;

        file.write_all(b"partial")?;
        Err(std::io::Error::other("boom"))
    })
    .expect_err("write failure should be returned");

    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "original");
    let _ = std::fs::remove_file(path);
}

#[test]
fn write_atomically_accepts_trailing_current_dir_component() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-output-atomic-curdir-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    let path = root.join("events.json");

    write_atomically(&path.join("."), |file| {
        use std::io::Write;

        file.write_all(b"[]")
    })
    .expect("trailing current-dir component should be accepted");

    assert_eq!(std::fs::read_to_string(&path).unwrap(), "[]");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn temp_output_path_bounds_long_destination_stem() {
    let long_name = format!("{}.jsonl", "a".repeat(240));
    let path = std::env::temp_dir().join(long_name);

    let temp_path = temp_output_path(&path);
    let temp_name = temp_path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("temporary output name should be utf-8");

    assert!(temp_name.len() < 200, "{temp_name}");
    assert!(temp_name.starts_with('.'));
    assert!(temp_name.ends_with(".tmp"));
}

#[test]
fn export_nbis_handles_long_but_valid_output_filename() {
    let root =
        std::env::temp_dir().join(format!("nettrap-output-long-name-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("create temp root");
    let path = root.join(format!(
        "{}.jsonl",
        "a".repeat(if cfg!(windows) { 120 } else { 240 })
    ));
    let event = raw_nbi(
        "raw",
        "127.0.0.1",
        12345,
        &SessionDestination::unknown(8080),
        4,
        "",
    );

    export_nbis(&[event], ExportFormat::Jsonl, &path)
        .expect("long valid output filename should export");

    assert!(path.is_file());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn validate_export_events_rejects_unbounded_event_slices() {
    let destination = SessionDestination::unknown(8080);
    let event = raw_nbi("raw", "127.0.0.1", 12345, &destination, 4, "");
    let events = vec![event; MAX_REPORT_EVENTS + 1];

    let err = validate_export_events(&events)
        .expect_err("oversized export event slices should be rejected");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("exceeds event limit"), "{err}");
}

#[test]
fn temp_output_stem_truncates_on_utf8_boundary() {
    let name = "é".repeat(80);
    let path = Path::new(&name);

    let stem = temp_output_stem(path);

    assert!(stem.len() <= MAX_TEMP_OUTPUT_STEM_BYTES);
    assert!(stem.is_char_boundary(stem.len()));
    assert!(!stem.is_empty());
}

#[cfg(unix)]
#[test]
fn temp_output_stem_sanitizes_unicode_line_separators() {
    let path = Path::new("report\u{2028}name.jsonl");

    let stem = temp_output_stem(path);

    assert!(stem.contains("report name.jsonl"));
    assert!(!stem.contains('\u{2028}'));
    assert!(!stem.contains('\u{2029}'));
    assert!(!stem.contains('\u{0085}'));
}

#[cfg(unix)]
#[test]
fn write_atomically_rejects_symlinked_final_path() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-output-atomic-symlink-{}",
        uuid::Uuid::new_v4()
    ));
    let target = root.join("target.json");
    let link = root.join("events.json");
    std::fs::create_dir_all(&root).expect("create temp root");
    std::fs::write(&target, "original").expect("seed target");
    std::os::unix::fs::symlink(&target, &link).expect("create final symlink");

    let err = write_atomically(&link, |file| {
        use std::io::Write;

        file.write_all(b"replacement")
    })
    .expect_err("final symlink should be rejected");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "original");
    assert!(
        link.symlink_metadata()
            .expect("link should remain")
            .file_type()
            .is_symlink()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn read_report_input_to_string_loads_relative_regular_file() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-output-read-relative-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    let _cwd_lock = crate::test_util::lock_current_dir();
    let previous_dir = std::env::current_dir().expect("current dir");
    std::env::set_current_dir(&root).expect("switch to temp root");
    std::fs::write("report.json", b"[]").expect("write report");

    let content =
        read_report_input_to_string(Path::new("report.json")).expect("relative report should load");

    std::env::set_current_dir(previous_dir).expect("restore current dir");
    assert_eq!(content, "[]");
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn export_nbis_rejects_symlinked_parent_directory() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-output-symlink-parent-{}",
        uuid::Uuid::new_v4()
    ));
    let real_parent = root.join("real");
    let linked_parent = root.join("linked");
    std::fs::create_dir_all(&real_parent).expect("create real parent");
    std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");
    let event = raw_nbi(
        "raw",
        "127.0.0.1",
        12345,
        &SessionDestination::unknown(8080),
        4,
        "",
    );

    for format in [
        ExportFormat::Json,
        ExportFormat::Jsonl,
        ExportFormat::Sarif,
        ExportFormat::Toon,
        ExportFormat::Csv,
    ] {
        let ext = match format {
            ExportFormat::Json => "json",
            ExportFormat::Jsonl => "jsonl",
            ExportFormat::Sarif => "sarif",
            ExportFormat::Toon => "toon",
            ExportFormat::Csv => "csv",
        };
        let path = linked_parent.join(format!("events.{ext}"));
        let err = export_nbis(std::slice::from_ref(&event), format, &path)
            .expect_err("symlinked parent should be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    let _ = std::fs::remove_dir_all(root);
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
    std::fs::write(
        &path,
        format!(
            "{}\n{{invalid-json}}\n",
            valid.to_json().expect("serialize NBI")
        ),
    )
    .unwrap();

    let loaded = load_nbis_from_jsonl_detailed(&path);
    assert_eq!(loaded.events.len(), 1);
    assert_eq!(loaded.invalid_lines, 1);
    assert!(loaded.read_error.is_none());
    assert!(loaded.has_integrity_issues());

    let _ = std::fs::remove_file(path);
}

#[test]
fn detailed_jsonl_loader_rejects_indicator_count_over_limit() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-indicator-limit-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let destination = SessionDestination::unknown(8080);
    let mut event = raw_nbi("raw", "127.0.0.1", 12345, &destination, 4, "");
    for index in 0..=NetworkBehaviorIndicator::MAX_INDICATORS {
        event
            .indicators
            .insert(format!("key-{index}"), "value".to_string());
    }
    std::fs::write(&path, event.to_json().expect("serialize oversized NBI")).unwrap();

    let loaded = load_nbis_from_jsonl_detailed(&path);

    assert!(loaded.events.is_empty());
    assert_eq!(loaded.invalid_lines, 1);
    assert!(loaded.read_error.is_none());

    let _ = std::fs::remove_file(path);
}

#[test]
fn detailed_jsonl_loader_rejects_oversized_indicator_values() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-indicator-text-limit-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let destination = SessionDestination::unknown(8080);
    let mut event = raw_nbi("raw", "127.0.0.1", 12345, &destination, 4, "");
    event.indicators.insert(
        "key".to_string(),
        "v".repeat(nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS + 1),
    );
    std::fs::write(&path, event.to_json().expect("serialize oversized NBI")).unwrap();

    let loaded = load_nbis_from_jsonl_detailed(&path);

    assert!(loaded.events.is_empty());
    assert_eq!(loaded.invalid_lines, 1);
    assert!(loaded.read_error.is_none());

    let _ = std::fs::remove_file(path);
}

#[test]
fn export_nbis_rejects_indicator_count_over_limit() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-indicator-limit-{}.json",
        uuid::Uuid::new_v4()
    ));
    let destination = SessionDestination::unknown(8080);
    let mut event = raw_nbi("raw", "127.0.0.1", 12345, &destination, 4, "");
    for index in 0..=NetworkBehaviorIndicator::MAX_INDICATORS {
        event
            .indicators
            .insert(format!("key-{index}"), "value".to_string());
    }

    let err = export_nbis(&[event], ExportFormat::Json, &path)
        .expect_err("oversized indicator map should be rejected");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("too many indicators"));
    assert!(!path.exists());
}

#[test]
fn export_nbis_rejects_unsafe_nbi_text_fields() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-unsafe-text-{}.json",
        uuid::Uuid::new_v4()
    ));
    let destination = SessionDestination::unknown(8080);
    let event = raw_nbi("raw\nproto", "127.0.0.1", 12345, &destination, 4, "");

    let err = export_nbis(&[event], ExportFormat::Json, &path)
        .expect_err("unsafe NBI text should be rejected");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("listener"));
    assert!(err.to_string().contains("unsafe"));
    assert!(!path.exists());
}

#[test]
fn export_nbis_rejects_padded_nbi_fields() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-padded-text-{}.json",
        uuid::Uuid::new_v4()
    ));
    let destination = SessionDestination::unknown(8080);
    let mut event = raw_nbi("raw", "127.0.0.1", 12345, &destination, 4, "");
    event.listener = " raw ".to_string();

    let err = export_nbis(&[event], ExportFormat::Json, &path)
        .expect_err("padded NBI text should be rejected");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("listener"));
    assert!(err.to_string().contains("padded"));
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn temp_output_path_preserves_non_utf8_basename_reversibly() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let raw = OsString::from_vec(b"/tmp/report-\xff.json".to_vec());
    let path = Path::new(&raw);
    let temp = temp_output_path(path);
    let temp_name = temp.file_name().and_then(|name| name.to_str()).unwrap();

    assert!(temp_name.starts_with(".hex-"));
    assert!(temp_name.contains("ff"));
    assert!(temp_name.ends_with(".tmp"));
}

#[test]
fn temp_output_path_is_unique_without_clock_dependency() {
    let path = Path::new("report.json");

    let first = temp_output_path(path);
    let second = temp_output_path(path);

    assert_ne!(first, second);
    assert_eq!(first.parent(), Some(Path::new(".")));
    assert_eq!(second.parent(), Some(Path::new(".")));
}

#[test]
fn temp_output_path_uses_portable_hex_stem_prefix() {
    let stem = format!("{}abcd", HEX_TEMP_OUTPUT_STEM_PREFIX);

    for invalid in ['<', '>', ':', '"', '/', '\\', '|', '?', '*'] {
        assert!(!stem.contains(invalid), "{stem} contains {invalid}");
    }
}

#[cfg(windows)]
#[test]
fn temp_output_path_preserves_non_utf16_basename_reversibly() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let raw = OsString::from_wide(&[
        b'r' as u16,
        b'e' as u16,
        b'p' as u16,
        b'o' as u16,
        b'r' as u16,
        b't' as u16,
        b'-' as u16,
        0xD800,
        b'.' as u16,
        b'j' as u16,
        b's' as u16,
        b'o' as u16,
        b'n' as u16,
    ]);
    let path = Path::new(&raw);
    let temp = temp_output_path(path);
    let temp_name = temp.file_name().and_then(|name| name.to_str()).unwrap();

    assert!(temp_name.starts_with(".hex-"));
    assert!(temp_name.contains("d800"));
    assert!(temp_name.ends_with(".tmp"));
}

#[test]
fn detailed_jsonl_loader_skips_event_log_lines_without_flagging() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-evlog-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let nbi = raw_nbi(
        "raw",
        "127.0.0.1",
        12345,
        &SessionDestination::unknown(8080),
        4,
        "",
    );
    std::fs::write(
            &path,
            format!(
                "{{\"event\":\"connect\",\"detail\":\"\",\"listener\":\"http\",\"src_ip\":\"127.0.0.1\",\"src_port\":1,\"timestamp\":\"2026-01-01T00:00:00+00:00\"}}\n{}\n{{busted}}\n",
                nbi.to_json().expect("serialize NBI")
            ),
        )
        .unwrap();

    let loaded = load_nbis_from_jsonl_detailed(&path);
    assert_eq!(loaded.events.len(), 1, "only the NBI line is an event");
    assert_eq!(loaded.invalid_lines, 1, "only the corrupt line is invalid");

    let _ = std::fs::remove_file(path);
}

#[test]
fn detailed_jsonl_loader_does_not_mask_unrelated_json_objects() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-evlog-mismatch-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(
        &path,
        "{\"event\":\"connect\",\"timestamp\":\"2026-01-01T00:00:00Z\"}\n",
    )
    .unwrap();

    let loaded = load_nbis_from_jsonl_detailed(&path);
    assert!(loaded.events.is_empty());
    assert_eq!(loaded.invalid_lines, 1);
    assert!(loaded.read_error.is_none());

    let _ = std::fs::remove_file(path);
}

#[test]
fn detailed_jsonl_loader_rejects_event_log_lines_with_invalid_types() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-evlog-types-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(
        &path,
        "{\
\"event\":\"connect\",\
\"detail\":\"\",\
\"listener\":\"http\",\
\"src_ip\":\"127.0.0.1\",\
\"src_port\":\"1\",\
\"timestamp\":\"2026-01-01T00:00:00+00:00\"\
}\n",
    )
    .unwrap();

    let loaded = load_nbis_from_jsonl_detailed(&path);
    assert!(loaded.events.is_empty());
    assert_eq!(loaded.invalid_lines, 1);
    assert!(loaded.read_error.is_none());

    let _ = std::fs::remove_file(path);
}

#[test]
fn detailed_jsonl_loader_rejects_event_log_lines_with_invalid_values() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-evlog-values-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(
        &path,
        "{\
\"event\":\"connect\",\
\"detail\":\"\",\
\"listener\":\"http\",\
\"src_ip\":\"not-an-ip\",\
\"src_port\":70000,\
\"timestamp\":\"not-a-time\"\
}\n",
    )
    .unwrap();

    let loaded = load_nbis_from_jsonl_detailed(&path);
    assert!(loaded.events.is_empty());
    assert_eq!(loaded.invalid_lines, 1);
    assert!(loaded.read_error.is_none());

    let _ = std::fs::remove_file(path);
}

#[test]
fn detailed_jsonl_loader_rejects_event_log_lines_with_extra_fields() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-evlog-extra-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(
        &path,
        "{\
\"event\":\"connect\",\
\"detail\":\"\",\
\"listener\":\"http\",\
\"src_ip\":\"127.0.0.1\",\
\"src_port\":1,\
\"timestamp\":\"2026-01-01T00:00:00+00:00\",\
\"extra\":true\
}\n",
    )
    .unwrap();

    let loaded = load_nbis_from_jsonl_detailed(&path);
    assert!(loaded.events.is_empty());
    assert_eq!(loaded.invalid_lines, 1);
    assert!(loaded.read_error.is_none());

    let _ = std::fs::remove_file(path);
}

#[test]
fn detailed_jsonl_loader_reports_missing_input_file() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-jsonl-missing-{}.jsonl",
        uuid::Uuid::new_v4()
    ));

    let loaded = load_nbis_from_jsonl_detailed(&path);

    assert!(loaded.events.is_empty());
    assert_eq!(loaded.invalid_lines, 0);
    assert!(loaded.read_error.is_some());
    assert!(
        loaded
            .read_error
            .as_deref()
            .is_some_and(|err| err.contains("failed to read NBI input"))
    );
}

#[test]
fn detailed_jsonl_loader_rejects_oversized_input_before_loading() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-oversized-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let file = std::fs::File::create(&path).expect("create sparse JSONL input");
    file.set_len(MAX_REPORT_INPUT_BYTES + 1)
        .expect("extend sparse JSONL input");

    let loaded = load_nbis_from_jsonl_detailed(&path);

    assert!(loaded.events.is_empty());
    assert_eq!(loaded.invalid_lines, 0);
    assert!(
        loaded
            .read_error
            .as_deref()
            .is_some_and(|err| err.contains("exceeds load limit"))
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn detailed_jsonl_loader_stops_at_event_limit() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-output-event-limit-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let event = raw_nbi(
        "raw",
        "127.0.0.1",
        12345,
        &SessionDestination::unknown(8080),
        4,
        "",
    )
    .to_json()
    .expect("serialize NBI");
    std::fs::write(&path, format!("{event}\n{event}\n")).expect("write JSONL input");

    let loaded = load_nbis_from_jsonl_detailed_with_limit(&path, 1);

    assert_eq!(loaded.events.len(), 1);
    assert!(
        loaded
            .read_error
            .as_deref()
            .is_some_and(|err| err.contains("exceeds event limit"))
    );

    let _ = std::fs::remove_file(path);
}

#[cfg(unix)]
#[test]
fn report_input_loader_rejects_symlinked_parent_directory() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-report-input-parent-{}",
        uuid::Uuid::new_v4()
    ));
    let real_parent = root.join("real");
    let linked_parent = root.join("linked");
    std::fs::create_dir_all(&real_parent).expect("create real parent");
    std::fs::write(
        real_parent.join("input.jsonl"),
        b"{\"listener\":\"http\"}\n",
    )
    .expect("write report input");
    std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");

    let err = read_report_input_to_string(&linked_parent.join("input.jsonl"))
        .expect_err("symlinked parent should be rejected");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    let _ = std::fs::remove_dir_all(root);
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
        ExportFormat::Sarif,
        &path,
    )
    .unwrap();

    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
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
        ExportFormat::Toon,
        &path,
    )
    .unwrap();

    let output = std::fs::read_to_string(&path).unwrap();
    assert!(output.contains(&format!("  start: \"{}\"", oldest.timestamp)));
    assert!(output.contains(&format!("  end: \"{}\"", newest.timestamp)));

    let _ = std::fs::remove_file(path);
}
