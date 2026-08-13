use std::fs;

use super::{
    EngineConfig, MAX_DISTRIBUTED_EVENT_SINKS, MAX_DISTRIBUTED_HTTP_SINK_BATCH_SIZE,
    MAX_DISTRIBUTED_NODE_TAG_BYTES, MAX_DISTRIBUTED_NODE_TAGS, MAX_FILTER_RULE_BYTES,
    MAX_FILTER_RULES_PER_LIST, parse_listener_pasv_port, validate_listener_optional_string_fields,
};
use crate::config::ListenerConfig;
use crate::engine::validate_adapter_configuration;
use nettrap_core::EventSinkConfig;

#[test]
fn normalize_listener_names_renames_case_insensitive_duplicates() {
    let mut config = EngineConfig {
        listeners: vec![
            ListenerConfig::new("http", 80),
            ListenerConfig::new("HTTP", 8080),
        ],
        ..EngineConfig::default()
    };

    config.normalize_listener_names();

    assert_eq!(config.listeners[0].name, "http");
    assert_eq!(config.listeners[1].name, "HTTP_8080");
}

#[test]
fn validate_global_settings_drops_blank_path_like_values() {
    let mut config = EngineConfig {
        output_path: Some("   ".to_string()),
        http_post_dump_dir: Some("\t".to_string()),
        smtp_dir: Some(" ".to_string()),
        pcap_path: Some("".to_string()),
        pcap_prefix: Some(" ".to_string()),
        tls_ca_cert: Some(" ".to_string()),
        tls_ca_key: Some("\n".to_string()),
        tls_cert_dir: Some("\r".to_string()),
        ..EngineConfig::default()
    };

    config.validate_global_settings().unwrap();

    assert!(config.output_path.is_none());
    assert!(config.http_post_dump_dir.is_none());
    assert!(config.smtp_dir.is_none());
    assert!(config.pcap_path.is_none());
    assert!(config.pcap_prefix.is_none());
    assert!(config.tls_ca_cert.is_none());
    assert!(config.tls_ca_key.is_none());
    assert!(config.tls_cert_dir.is_none());
}

#[test]
fn validate_global_settings_rejects_invalid_optional_identifier() {
    let mut config = EngineConfig::default();
    config.database.node_id = Some("node\u{00a0}1".to_string());

    let err = config
        .validate_global_settings()
        .expect_err("invalid optional identifier should be rejected");

    assert!(
        err.to_string()
            .contains("database.node_id contains invalid whitespace")
    );
}

#[test]
fn validate_global_settings_rejects_invalid_distributed_node_id() {
    let mut config = EngineConfig::default();
    config.distributed.node_id = Some("node\n1".to_string());

    let err = config
        .validate_global_settings()
        .expect_err("invalid distributed node id should be rejected");

    assert!(
        err.to_string()
            .contains("distributed.node_id contains invalid whitespace")
    );
}

#[test]
fn validate_global_settings_trims_distributed_node_region() {
    let mut config = EngineConfig::default();
    config.distributed.node_region = Some(" eu west ".to_string());

    config.validate_global_settings().unwrap();

    assert_eq!(config.distributed.node_region.as_deref(), Some("eu west"));
}

#[test]
fn validate_global_settings_rejects_zero_http_sink_batch_size() {
    let mut config = EngineConfig::default();
    config.distributed.event_sinks.push(EventSinkConfig {
        sink_type: "http".to_string(),
        target: "https://collector.example.test/events".to_string(),
        auth: None,
        batch_size: 0,
        flush_interval_ms: 1000,
        request_timeout_ms: 5000,
    });

    let err = config
        .validate_global_settings()
        .expect_err("zero HTTP sink batch size should be rejected");

    assert!(
        err.to_string()
            .contains("distributed.event_sinks[0].batch_size must be greater than 0")
    );
}

#[test]
fn validate_global_settings_rejects_oversized_http_sink_batch_size() {
    let mut config = EngineConfig::default();
    config.distributed.event_sinks.push(EventSinkConfig {
        sink_type: "webhook".to_string(),
        target: "https://collector.example.test/events".to_string(),
        auth: None,
        batch_size: MAX_DISTRIBUTED_HTTP_SINK_BATCH_SIZE + 1,
        flush_interval_ms: 1000,
        request_timeout_ms: 5000,
    });

    let err = config
        .validate_global_settings()
        .expect_err("oversized HTTP sink batch size should be rejected");

    assert!(
        err.to_string()
            .contains("distributed.event_sinks[0].batch_size exceeds max")
    );
}

#[test]
fn validate_global_settings_rejects_zero_http_sink_timeouts() {
    let mut config = EngineConfig::default();
    config.distributed.event_sinks.push(EventSinkConfig {
        sink_type: "splunk".to_string(),
        target: "https://collector.example.test/events".to_string(),
        auth: None,
        batch_size: 100,
        flush_interval_ms: 0,
        request_timeout_ms: 5000,
    });

    let err = config
        .validate_global_settings()
        .expect_err("zero HTTP sink flush interval should be rejected");

    assert!(
        err.to_string()
            .contains("distributed.event_sinks[0].flush_interval_ms must be greater than 0")
    );

    config.distributed.event_sinks[0].flush_interval_ms = 1000;
    config.distributed.event_sinks[0].request_timeout_ms = 0;
    let err = config
        .validate_global_settings()
        .expect_err("zero HTTP sink request timeout should be rejected");

    assert!(
        err.to_string()
            .contains("distributed.event_sinks[0].request_timeout_ms must be greater than 0")
    );
}

#[test]
fn validate_global_settings_rejects_control_characters_in_path_like_values() {
    let mut config = EngineConfig {
        output_path: Some("out\nput.jsonl".to_string()),
        ..EngineConfig::default()
    };

    let err = config
        .validate_global_settings()
        .expect_err("control characters in path-like values should be rejected");

    assert!(
        err.to_string()
            .contains("output_path contains control characters")
    );
}

#[test]
fn validate_global_settings_rejects_path_like_pcap_prefix() {
    let mut config = EngineConfig {
        pcap_prefix: Some("../escape".to_string()),
        ..EngineConfig::default()
    };

    let err = config
        .validate_global_settings()
        .expect_err("path-like pcap_prefix should be rejected");

    assert!(
        err.to_string()
            .contains("pcap_prefix must be a single file name component")
    );
}

#[test]
fn from_file_declarative_rejects_unknown_top_level_key() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-engine-config-unknown-top-{}.toml",
        uuid::Uuid::new_v4()
    ));
    fs::write(
        &path,
        "network_mode = \"singlehost\"\nattribution_enabledd = true\n",
    )
    .expect("write config");

    let err = EngineConfig::from_file_declarative(&path)
        .expect_err("misspelled top-level key must be rejected");
    assert!(
        err.to_string().contains("attribution_enabledd"),
        "error should name the offending key: {err}"
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn from_file_declarative_rejects_unknown_listener_key() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-engine-config-unknown-listener-{}.toml",
        uuid::Uuid::new_v4()
    ));
    fs::write(
        &path,
        "[[listeners]]\nname = \"http\"\nport = 80\nwebroott = \"/tmp/x\"\n",
    )
    .expect("write config");

    let err = EngineConfig::from_file_declarative(&path)
        .expect_err("misspelled listener key must be rejected");
    assert!(
        err.to_string().contains("webroott"),
        "error should name the offending key: {err}"
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn validate_rejects_non_spawnable_listener_protocol() {
    let mut config = EngineConfig {
        listeners: vec![
            ListenerConfig::new("http", 80).with_protocol(nettrap_core::prelude::Protocol::Icmp),
        ],
        ..EngineConfig::default()
    };

    let err = config
        .validate()
        .expect_err("icmp listener must be rejected at validation");
    let message = err.to_string();
    assert!(
        message.contains("unsupported protocol") && message.contains("Icmp"),
        "error should explain the unsupported protocol: {message}"
    );
}

#[test]
fn validate_rejects_ascii_padded_listener_name() {
    let mut config = EngineConfig {
        listeners: vec![ListenerConfig::new(" http ", 80)],
        ..EngineConfig::default()
    };

    let err = config
        .validate()
        .expect_err("padded listener name should be rejected");

    assert!(err.to_string().contains("Listener name"));
}

#[test]
fn validate_rejects_missing_redirect_default_listener() {
    let mut config = EngineConfig {
        redirect_all_traffic: true,
        default_tcp_listener: Some("missing".to_string()),
        default_udp_listener: None,
        listeners: vec![ListenerConfig::new("http", 80)],
        ..EngineConfig::default()
    };

    let err = config
        .validate()
        .expect_err("missing redirect default should fail validation");
    let message = err.to_string();

    assert!(
        message.contains("redirect_all_traffic")
            && message.contains("missing")
            && message.contains("tcp"),
        "error should explain the missing redirect default: {message}"
    );
}

#[test]
fn validate_rejects_missing_default_listener_without_redirect_all_traffic() {
    let mut config = EngineConfig {
        default_tcp_listener: Some("missing".to_string()),
        default_udp_listener: None,
        listeners: vec![ListenerConfig::new("http", 80)],
        ..EngineConfig::default()
    };

    let err = config
        .validate()
        .expect_err("missing default listener should fail validation");

    assert!(
        err.to_string().contains("default listener")
            && err.to_string().contains("missing")
            && err.to_string().contains("tcp"),
        "unexpected error: {err}"
    );
}

#[test]
fn validate_rejects_disabled_redirect_default_listener() {
    let mut listener = ListenerConfig::new("http", 80);
    listener.enabled = false;
    let mut config = EngineConfig {
        redirect_all_traffic: true,
        default_tcp_listener: Some("http".to_string()),
        default_udp_listener: None,
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .validate()
        .expect_err("disabled redirect default should fail validation");
    let message = err.to_string();

    assert!(
        message.contains("redirect_all_traffic")
            && message.contains("http")
            && message.contains("spawnable"),
        "error should explain the non-spawnable redirect default: {message}"
    );
}

#[test]
fn from_file_declarative_rejects_oversized_config_before_loading() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-engine-config-oversized-{}.toml",
        uuid::Uuid::new_v4()
    ));
    let file = fs::File::create(&path).expect("create sparse config");
    file.set_len(super::MAX_ENGINE_CONFIG_FILE_BYTES + 1)
        .expect("extend sparse config");

    let err = EngineConfig::from_file_declarative(&path)
        .expect_err("oversized engine config should be rejected");

    assert!(err.to_string().contains("exceeds load limit"));
    let _ = fs::remove_file(path);
}

#[test]
fn prepare_runtime_defaults_rejects_too_many_global_filter_rules() {
    let mut config = EngineConfig {
        global_process_whitelist: (0..=MAX_FILTER_RULES_PER_LIST)
            .map(|idx| format!("proc-{idx}"))
            .collect(),
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("oversized global filter list should fail validation");

    assert!(
        err.to_string()
            .contains("global_process_whitelist has too many entries")
    );
}

#[test]
fn prepare_runtime_defaults_rejects_too_many_listener_filter_rules() {
    let mut listener = ListenerConfig::new("http", 80);
    listener.host_blacklist = (0..=MAX_FILTER_RULES_PER_LIST)
        .map(|idx| format!("192.0.2.{idx}"))
        .collect();
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("oversized listener filter list should fail validation");

    assert!(
        err.to_string()
            .contains("Listener 'http': host_blacklist has too many entries")
    );
}

#[test]
fn prepare_runtime_defaults_rejects_oversized_filter_rule_entry() {
    let mut listener = ListenerConfig::new("http", 80);
    listener.process_whitelist = vec!["a".repeat(MAX_FILTER_RULE_BYTES + 1)];
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("oversized listener filter entry should fail validation");

    assert!(
        err.to_string()
            .contains("Listener 'http': process_whitelist entry 0 exceeds size limit")
    );
}

#[test]
fn prepare_runtime_defaults_rejects_blank_host_filter_rule_entries() {
    for (field, value) in [("host_whitelist", " "), ("host_blacklist", "\t")] {
        let mut listener = ListenerConfig::new("http", 80);
        match field {
            "host_whitelist" => listener.host_whitelist = vec![value.to_string()],
            "host_blacklist" => listener.host_blacklist = vec![value.to_string()],
            _ => unreachable!("test only covers known host filter fields"),
        }
        let mut config = EngineConfig {
            listeners: vec![listener],
            ..EngineConfig::default()
        };

        let err = config
            .prepare_runtime_defaults()
            .expect_err("blank listener host filter entry should fail validation");

        assert!(
            err.to_string().contains(&format!(
                "Listener 'http': {field} entry 0 must not be blank"
            )),
            "unexpected error for {field}: {err}"
        );
    }
}

#[test]
fn prepare_runtime_defaults_rejects_unicode_host_filter_rule_entries() {
    let mut listener = ListenerConfig::new("http", 80);
    listener.host_whitelist = vec!["example\u{00a0}.test".to_string()];
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("unicode whitespace listener host filter entry should fail validation");

    assert!(err.to_string().contains(
        "Listener 'http': host_whitelist entry 0 contains control characters or unicode whitespace"
    ));
}

#[test]
fn prepare_runtime_defaults_rejects_invalid_global_process_filter_regex() {
    let mut config = EngineConfig {
        global_process_blacklist: vec!["re:[invalid".to_string()],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("invalid global process regex should fail validation");

    assert!(
        err.to_string()
            .contains("global_process_blacklist entry 0 has invalid regex"),
        "unexpected error: {err}"
    );
}

#[test]
fn prepare_runtime_defaults_rejects_blank_listener_process_filter() {
    let mut listener = ListenerConfig::new("http", 80);
    listener.process_whitelist = vec![" \t ".to_string()];
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("blank listener process filter should fail validation");

    assert!(
        err.to_string()
            .contains("Listener 'http': process_whitelist entry 0 must not be blank"),
        "unexpected error: {err}"
    );
}

#[test]
fn prepare_runtime_defaults_rejects_c1_controls_in_listener_process_filter() {
    let mut listener = ListenerConfig::new("http", 80);
    listener.process_whitelist = vec!["calc\u{009f}".to_string()];
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("listener process filter with C1 controls should fail validation");

    assert!(err.to_string().contains(
            "Listener 'http': process_whitelist entry 0 contains control characters or unicode whitespace"
        ));
}

#[test]
fn prepare_runtime_defaults_rejects_ascii_padded_dns_flush_command() {
    let mut config = EngineConfig {
        dns_flush_command: Some(" \t ipconfig /flushdns \t ".to_string()),
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("padded dns_flush_command should fail validation");

    assert!(err.to_string().contains("must not be padded"));
}

#[test]
fn prepare_runtime_defaults_rejects_blank_dns_flush_command() {
    let mut config = EngineConfig {
        dns_flush_command: Some(String::new()),
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("blank dns_flush_command should fail validation");

    assert!(
        err.to_string()
            .contains("dns_flush_command must not be blank"),
        "unexpected error: {err}"
    );
}

#[test]
fn prepare_runtime_defaults_rejects_control_characters_in_dns_flush_command() {
    let mut config = EngineConfig {
        dns_flush_command: Some("ipconfig\n/flushdns".to_string()),
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("dns_flush_command with controls should fail validation");

    assert!(
        err.to_string()
            .contains("dns_flush_command contains control characters or unicode separators"),
        "unexpected error: {err}"
    );
}

#[test]
fn prepare_runtime_defaults_rejects_unicode_line_separators_in_dns_flush_command() {
    let mut config = EngineConfig {
        dns_flush_command: Some("ipconfig\u{2028}/flushdns".to_string()),
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("dns_flush_command with unicode separators should fail validation");

    assert!(
        err.to_string()
            .contains("dns_flush_command contains control characters or unicode separators"),
        "unexpected error: {err}"
    );
}

#[test]
fn prepare_runtime_defaults_rejects_unterminated_dns_flush_command_quote() {
    let mut config = EngineConfig {
        dns_flush_command: Some(r#""C:\Tools\flush.exe"#.to_string()),
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("dns_flush_command with unterminated quote should fail validation");

    assert!(
        err.to_string()
            .contains("dns_flush_command has unterminated \" quote"),
        "unexpected error: {err}"
    );
}

#[test]
fn prepare_runtime_defaults_rejects_control_characters_in_listener_path_options() {
    let mut listener = ListenerConfig::new("http", 80);
    listener.webroot = Some("web\nroot".to_string());
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("listener path option with controls should fail validation");

    assert!(
        err.to_string()
            .contains("Listener 'http': webroot contains control characters")
    );
}

#[test]
fn prepare_runtime_defaults_rejects_unicode_line_separators_in_listener_path_options() {
    let root =
        std::env::temp_dir().join(format!("nettrap-line-sep-webroot-{}", uuid::Uuid::new_v4()));
    let unsafe_root = root.join("web\u{2028}root");
    fs::create_dir_all(&unsafe_root).expect("create temp root");
    let mut listener = ListenerConfig::new("http", 80);
    listener.webroot = Some(unsafe_root.display().to_string());
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("listener path option with unicode separators should fail validation");

    assert!(
        err.to_string()
            .contains("Listener 'http': webroot contains control characters")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn prepare_runtime_defaults_rejects_missing_listener_root_directory() {
    let missing =
        std::env::temp_dir().join(format!("nettrap-missing-webroot-{}", uuid::Uuid::new_v4()));
    let mut listener = ListenerConfig::new("http", 80);
    listener.webroot = Some(missing.display().to_string());
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("missing webroot should fail validation");

    assert!(
        err.to_string().contains("Listener 'http': webroot"),
        "unexpected error: {err}"
    );
}

#[test]
fn prepare_runtime_defaults_rejects_ascii_padded_listener_root_directory_options() {
    let root = std::env::temp_dir().join(format!("nettrap-trim-webroot-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).expect("create temp root");
    let trimmed = root.display().to_string();
    let mut listener = ListenerConfig::new("http", 80);
    listener.webroot = Some(format!(" {trimmed}\t"));
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("padded webroot should fail validation");

    assert!(err.to_string().contains("must not be padded"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn prepare_runtime_defaults_rejects_ascii_padded_server_version() {
    let mut listener = ListenerConfig::new("http", 80);
    listener.server_version = Some(" Apache/2.4.99 ".to_string());
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("padded server_version should fail validation");

    assert!(
        err.to_string()
            .contains("server_version must not be padded")
    );
}

#[test]
fn prepare_runtime_defaults_rejects_file_listener_root_directory() {
    let root = std::env::temp_dir().join(format!("nettrap-file-webroot-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).expect("create temp root");
    let file_path = root.join("not-a-dir");
    fs::write(&file_path, b"not a directory").expect("write fixture");

    let mut listener = ListenerConfig::new("http", 80);
    listener.webroot = Some(file_path.display().to_string());
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("file webroot should fail validation");

    let _ = fs::remove_dir_all(&root);

    assert!(
        err.to_string().contains("must be a directory"),
        "unexpected error: {err}"
    );
}

#[test]
fn prepare_runtime_defaults_rejects_invalid_listener_server_name() {
    let mut listener = ListenerConfig::new("ftp", 21);
    listener.server_name = Some("bad><name".to_string());
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("invalid server_name should fail validation");

    assert!(err.to_string().contains("Listener 'ftp': server_name"));
}

#[test]
fn prepare_runtime_defaults_rejects_empty_label_listener_server_name() {
    let mut listener = ListenerConfig::new("ftp", 21);
    listener.server_name = Some("mail..example".to_string());
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("invalid server_name should fail validation");

    assert!(err.to_string().contains("empty labels"));
}

#[test]
fn prepare_runtime_defaults_rejects_underscore_listener_server_name() {
    let mut listener = ListenerConfig::new("ftp", 21);
    listener.server_name = Some("mail_example.local".to_string());
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("invalid server_name should fail validation");

    assert!(err.to_string().contains("server_name"));
}

#[test]
fn prepare_runtime_defaults_rejects_numeric_listener_server_name() {
    let mut listener = ListenerConfig::new("ftp", 21);
    listener.server_name = Some("192.0.2.10".to_string());
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("numeric server_name should fail validation");

    assert!(err.to_string().contains("server_name"));
}

#[test]
fn prepare_runtime_defaults_accepts_absolute_listener_server_name() {
    let mut listener = ListenerConfig::new("ftp", 21);
    listener.server_name = Some("mail.example.".to_string());
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    config
        .prepare_runtime_defaults()
        .expect("absolute server_name should validate");
}

#[test]
fn prepare_runtime_defaults_accepts_listener_server_name_escapes() {
    for server_name in ["!hostname", "!gethostname", "!random"] {
        let mut listener = ListenerConfig::new("ftp", 21);
        listener.server_name = Some(server_name.to_string());
        let mut config = EngineConfig {
            listeners: vec![listener],
            ..EngineConfig::default()
        };

        config
            .prepare_runtime_defaults()
            .expect("server_name escape should validate");
    }
}

#[test]
fn prepare_runtime_defaults_rejects_overlong_listener_server_name_labels() {
    let mut listener = ListenerConfig::new("ftp", 21);
    listener.server_name = Some(format!("{}.example.test", "a".repeat(64)));
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("overlong label server_name should fail");

    assert!(err.to_string().contains("server_name"));
}

#[test]
fn prepare_runtime_defaults_rejects_multiple_trailing_dots_listener_server_name() {
    let mut listener = ListenerConfig::new("ftp", 21);
    listener.server_name = Some("mail.example...".to_string());
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("multiple trailing dots should fail validation");

    assert!(err.to_string().contains("server_name"));
}

#[test]
fn prepare_runtime_defaults_rejects_zero_listener_timeout() {
    let mut listener = ListenerConfig::new("http", 80);
    listener.timeout_ms = 0;
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("zero timeout should fail validation");

    assert!(
        err.to_string()
            .contains("Listener 'http': timeout_ms must be greater than 0"),
        "unexpected error: {err}"
    );
}

#[test]
fn prepare_runtime_defaults_rejects_oversized_listener_timeout() {
    let mut listener = ListenerConfig::new("http", 80);
    listener.timeout_ms = super::MAX_LISTENER_TIMEOUT_MS + 1;
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("oversized timeout should fail validation");

    assert!(
        err.to_string().contains("Listener 'http': timeout_ms"),
        "unexpected error: {err}"
    );
}

#[test]
fn prepare_runtime_defaults_rejects_oversized_listener_response_delay() {
    let mut listener = ListenerConfig::new("http", 80);
    listener.response_delay_ms = super::MAX_LISTENER_DELAY_MS + 1;
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("oversized response delay should fail validation");

    assert!(
        err.to_string()
            .contains("Listener 'http': response_delay_ms"),
        "unexpected error: {err}"
    );
}

#[test]
fn prepare_runtime_defaults_rejects_oversized_listener_banner_delay() {
    let mut listener = ListenerConfig::new("http", 80);
    listener.banner_delay_ms = super::MAX_LISTENER_DELAY_MS + 1;
    let mut config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("oversized banner delay should fail validation");

    assert!(
        err.to_string().contains("Listener 'http': banner_delay_ms"),
        "unexpected error: {err}"
    );
}

#[test]
fn prepare_runtime_defaults_rejects_too_many_distributed_event_sinks() {
    let mut config = EngineConfig::default();
    config.distributed.event_sinks = (0..=MAX_DISTRIBUTED_EVENT_SINKS)
        .map(|idx| crate::config::EventSinkConfig {
            sink_type: "http".to_string(),
            target: format!("http://127.0.0.1:{}/events", 9000 + idx),
            auth: None,
            batch_size: 100,
            flush_interval_ms: 1000,
            request_timeout_ms: 5000,
        })
        .collect();

    let err = config
        .prepare_runtime_defaults()
        .expect_err("oversized distributed sink list should fail validation");

    assert!(
        err.to_string()
            .contains("distributed.event_sinks has too many entries")
    );
}

#[test]
fn adapter_validation_rejects_unknown_distributed_event_sink_type() {
    let mut config = EngineConfig::default();
    config.distributed.enabled = true;
    config
        .distributed
        .event_sinks
        .push(crate::config::EventSinkConfig {
            sink_type: "bogus".to_string(),
            target: "127.0.0.1:1".to_string(),
            auth: None,
            batch_size: 1,
            flush_interval_ms: 1000,
            request_timeout_ms: 1000,
        });

    config
        .prepare_runtime_defaults()
        .expect("policy validation should pass");
    let err = validate_adapter_configuration(&config)
        .expect_err("unknown sink type should fail adapter validation");

    assert!(
        err.to_string()
            .contains("Unknown distributed event sink type: bogus")
    );
}

#[test]
fn prepare_runtime_defaults_rejects_too_many_distributed_node_tags() {
    let mut config = EngineConfig {
        distributed: crate::config::DistributedConfig {
            node_tags: (0..=MAX_DISTRIBUTED_NODE_TAGS)
                .map(|idx| format!("tag-{idx}"))
                .collect(),
            ..crate::config::DistributedConfig::default()
        },
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("oversized distributed tag list should fail validation");

    assert!(
        err.to_string()
            .contains("distributed.node_tags has too many entries")
    );
}

#[test]
fn prepare_runtime_defaults_rejects_oversized_distributed_node_tag() {
    let mut config = EngineConfig {
        distributed: crate::config::DistributedConfig {
            node_tags: vec!["a".repeat(MAX_DISTRIBUTED_NODE_TAG_BYTES + 1)],
            ..crate::config::DistributedConfig::default()
        },
        ..EngineConfig::default()
    };

    let err = config
        .prepare_runtime_defaults()
        .expect_err("oversized distributed tag should fail validation");

    assert!(
        err.to_string()
            .contains("distributed.node_tags entry 0 exceeds size limit")
    );
}

#[test]
fn prepare_runtime_defaults_rejects_blank_database_backend() {
    let mut config = EngineConfig::default();
    config.database.backend = String::new();

    let err = config
        .prepare_runtime_defaults()
        .expect_err("blank database backend should fail validation");

    assert!(
        err.to_string()
            .contains("database.backend must not be blank")
    );
}

#[cfg(unix)]
#[test]
fn to_file_rejects_symlinked_parent_directory() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-engine-config-parent-{}",
        uuid::Uuid::new_v4()
    ));
    let real_parent = root.join("real");
    let linked_parent = root.join("linked");
    fs::create_dir_all(&real_parent).expect("create real parent");
    std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");

    let config = EngineConfig::default();
    let err = config
        .to_file(&linked_parent.join("engine.toml"))
        .expect_err("symlinked parent should be rejected");

    assert_eq!(err.to_string(), "IO error: symlink path component");
    let _ = fs::remove_dir_all(root);
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn to_file_preserves_non_utf8_output_path() {
    use std::os::unix::ffi::OsStringExt;

    let root = std::env::temp_dir().join(format!(
        "nettrap-engine-config-nonutf8-{}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&root).expect("create temp root");
    let output = root.join(std::ffi::OsString::from_vec(b"config-\xff.toml".to_vec()));

    let config = EngineConfig::default();
    config
        .to_file(&output)
        .expect("non-UTF8 output path should be preserved");

    assert!(output.is_file());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn expand_listeners_renames_collisions_after_port_range_expansion() {
    let mut ranged = ListenerConfig::new("http", 80);
    ranged.port_range = Some("80,81".to_string());

    let colliding = ListenerConfig::new("http_80", 9000);

    let mut config = EngineConfig {
        listeners: vec![ranged, colliding],
        ..EngineConfig::default()
    };

    config
        .expand_listeners()
        .expect("valid port ranges should expand");

    let names: Vec<&str> = config
        .listeners
        .iter()
        .map(|listener| listener.name.as_str())
        .collect();
    assert_eq!(names, vec!["http_80", "http_81", "http_80_9000"]);
}

#[test]
fn finalize_listener_names_rejects_ambiguous_redirect_defaults() {
    let mut config = EngineConfig {
        listeners: vec![
            ListenerConfig::new("http", 80),
            ListenerConfig::new("http", 8080),
        ],
        redirect_all_traffic: true,
        default_tcp_listener: Some("http".to_string()),
        ..EngineConfig::default()
    };

    let err = config
        .finalize_listener_names()
        .expect_err("ambiguous defaults should be rejected");

    assert!(
        err.to_string().contains("became ambiguous"),
        "unexpected error: {err}"
    );
}

#[test]
fn finalize_listener_names_rewrites_unique_redirect_defaults_to_final_name() {
    let mut config = EngineConfig {
        listeners: vec![
            ListenerConfig::new("http", 80),
            ListenerConfig::new("control", 8080),
        ],
        redirect_all_traffic: true,
        default_tcp_listener: Some("control".to_string()),
        ..EngineConfig::default()
    };

    config
        .finalize_listener_names()
        .expect("unique default listener should remain valid");

    assert_eq!(config.default_tcp_listener.as_deref(), Some("control"));
}

#[test]
fn finalize_listener_names_handles_unicode_case_insensitive_redirect_defaults() {
    let mut config = EngineConfig {
        listeners: vec![ListenerConfig::new("MÜLLER", 80)],
        redirect_all_traffic: true,
        default_tcp_listener: Some("müller".to_string()),
        ..EngineConfig::default()
    };

    config
        .finalize_listener_names()
        .expect("unicode listener names should normalize consistently");

    assert_eq!(config.default_tcp_listener.as_deref(), Some("MÜLLER"));
}

#[test]
fn finalize_listener_names_rejects_ascii_padding_in_redirect_defaults() {
    let mut hidden = ListenerConfig::new("fallback", 8080);
    hidden.hidden = true;
    let mut config = EngineConfig {
        listeners: vec![hidden],
        redirect_all_traffic: true,
        default_tcp_listener: Some(" fallback ".to_string()),
        default_udp_listener: Some(" \t ".to_string()),
        ..EngineConfig::default()
    };

    let err = match config.finalize_listener_names() {
        Ok(_) => panic!("padded default listener should fail"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("default listener"));
}

#[test]
fn listener_is_default_target_handles_unicode_case_folding() {
    let mut hidden = ListenerConfig::new("MÜLLER", 8080);
    hidden.hidden = true;
    let config = EngineConfig {
        listeners: vec![hidden],
        default_tcp_listener: Some("müller".to_string()),
        ..EngineConfig::default()
    };

    assert!(config.listener_is_default_target(&config.listeners[0]));
}

#[test]
fn finalize_listener_names_rejects_unicode_whitespace_redirect_defaults() {
    let mut hidden = ListenerConfig::new("fallback", 8080);
    hidden.hidden = true;
    let mut config = EngineConfig {
        listeners: vec![hidden],
        redirect_all_traffic: true,
        default_tcp_listener: Some("fallback\u{00a0}".to_string()),
        default_udp_listener: Some("fallback\u{00a0}".to_string()),
        ..EngineConfig::default()
    };

    let err = match config.finalize_listener_names() {
        Ok(_) => panic!("unicode whitespace redirect defaults should fail"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("default listener"));
}

#[test]
fn adapter_validation_rejects_unresolvable_hostname_filters() {
    let path =
        std::env::temp_dir().join(format!("nettrap-host-filter-{}.toml", std::process::id()));
    let mut listener = ListenerConfig::new("http", 80);
    listener.host_whitelist = vec!["definitely-not-a-real-nettrap-host.invalid".to_string()];
    let config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let loaded = EngineConfig::from_file(&path).expect("policy validation should pass");
    let err = validate_adapter_configuration(&loaded)
        .expect_err("invalid hostname should fail adapter validation");

    let _ = fs::remove_file(&path);

    assert!(err.to_string().contains("failed to resolve host filter"));
}

#[test]
fn finalize_listener_names_rejects_spawnable_socket_collisions() {
    let mut config = EngineConfig {
        listeners: vec![
            ListenerConfig::new("http", 80),
            ListenerConfig::new("http-alt", 80),
        ],
        ..EngineConfig::default()
    };

    let err = config
        .finalize_listener_names()
        .expect_err("colliding sockets should fail validation");

    assert!(
        err.to_string()
            .contains("both resolve to tcp socket 0.0.0.0:80")
    );
}

#[test]
fn finalize_listener_names_ignores_disabled_socket_collisions() {
    let mut disabled = ListenerConfig::new("http-alt", 80);
    disabled.enabled = false;
    let mut config = EngineConfig {
        listeners: vec![ListenerConfig::new("http", 80), disabled],
        ..EngineConfig::default()
    };

    config
        .finalize_listener_names()
        .expect("disabled listeners should not trigger socket collisions");
}

#[test]
fn from_file_rejects_invalid_bind_address() {
    let path =
        std::env::temp_dir().join(format!("nettrap-bind-address-{}.toml", std::process::id()));
    let config = EngineConfig {
        listeners: vec![ListenerConfig::new("http", 80).with_bind_address("not-an-ip")],
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err = EngineConfig::from_file(&path).expect_err("invalid bind_address should fail");

    let _ = fs::remove_file(&path);

    assert!(err.to_string().contains("invalid bind_address"));
}

#[test]
fn from_file_rejects_invalid_dns_response_mode() {
    let path = std::env::temp_dir().join(format!("nettrap-dns-mode-{}.toml", std::process::id()));
    let mut listener = ListenerConfig::new("dns", 53);
    listener.dns_response_mode = Some("banana".to_string());
    let config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err = EngineConfig::from_file(&path).expect_err("invalid dns_response_mode should fail");

    let _ = fs::remove_file(&path);

    assert!(err.to_string().contains("invalid dns_response_mode"));
}

#[test]
fn from_file_rejects_invalid_udp_dns_custom_response_domain() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-invalid-dns-custom-response-{}.toml",
        std::process::id()
    ));
    let listener =
        ListenerConfig::new("dns", 53).with_custom_response("bad/domain=1.2.3.4".to_string());
    let config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err = EngineConfig::from_file(&path)
        .expect_err("invalid DNS custom_response domain should fail config validation");

    let _ = fs::remove_file(&path);

    assert!(
        err.to_string()
            .contains("Listener 'dns': invalid DNS custom_response"),
        "unexpected error: {err}"
    );
}

#[test]
fn from_file_accepts_raw_udp_custom_response_shorthand() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-raw-udp-custom-response-{}.toml",
        std::process::id()
    ));
    let listener = ListenerConfig::new("raw", 53).with_custom_response("static:pong".to_string());
    let config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let loaded = EngineConfig::from_file(&path)
        .expect("raw UDP custom_response should not be parsed as DNS");

    let _ = fs::remove_file(&path);

    assert_eq!(
        loaded.listeners[0].custom_response.as_deref(),
        Some("static:pong")
    );
}

#[test]
fn adapter_validation_rejects_invalid_raw_custom_response() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-invalid-raw-custom-response-{}.toml",
        std::process::id()
    ));
    let listener =
        ListenerConfig::new("raw", 53).with_custom_response("base64:not-valid-base64".to_string());
    let config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let loaded = EngineConfig::from_file(&path).expect("policy validation should pass");
    let err = validate_adapter_configuration(&loaded)
        .expect_err("invalid raw custom_response should fail adapter validation");

    let _ = fs::remove_file(&path);

    assert!(
        err.to_string()
            .contains("Listener 'raw': invalid raw custom_response"),
        "unexpected error: {err}"
    );
}

#[test]
fn adapter_validation_rejects_invalid_echo_custom_response() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-invalid-echo-custom-response-{}.toml",
        std::process::id()
    ));
    let listener = ListenerConfig::new("echo", 2323)
        .with_custom_response("base64:not-valid-base64".to_string());
    let config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let loaded = EngineConfig::from_file(&path).expect("policy validation should pass");
    let err = validate_adapter_configuration(&loaded)
        .expect_err("invalid echo custom_response should fail adapter validation");

    let _ = fs::remove_file(&path);

    assert!(
        err.to_string()
            .contains("Listener 'echo': invalid raw custom_response"),
        "unexpected error: {err}"
    );
}

#[test]
fn from_file_accepts_dns_custom_response_on_tcp_listener() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-tcp-dns-custom-response-{}.toml",
        std::process::id()
    ));
    let listener =
        ListenerConfig::new("dns", 1053).with_custom_response("example.com=1.2.3.4".to_string());
    let config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let loaded = EngineConfig::from_file(&path)
        .expect("TCP DNS listeners should still validate DNS custom responses");

    let _ = fs::remove_file(&path);

    assert_eq!(loaded.listeners[0].name, "dns");
    assert_eq!(
        loaded.listeners[0].custom_response.as_deref(),
        Some("example.com=1.2.3.4")
    );
}

#[test]
fn from_file_rejects_empty_restrict_interface() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-empty-restrict-interface-{}.toml",
        std::process::id()
    ));
    let config = EngineConfig {
        restrict_interface: Some("   ".to_string()),
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err =
        EngineConfig::from_file(&path).expect_err("empty restrict_interface should be rejected");

    let _ = fs::remove_file(&path);

    assert!(
        err.to_string()
            .contains("restrict_interface cannot be empty")
    );
}

#[test]
fn from_file_normalizes_report_language() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-report-language-{}.toml",
        std::process::id()
    ));
    let config = EngineConfig {
        report_language: " EN ".to_string(),
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let loaded = EngineConfig::from_file(&path).expect("report_language should normalize");

    let _ = fs::remove_file(&path);

    assert_eq!(loaded.report_language, "en");
}

#[test]
fn from_file_rejects_unsupported_report_language() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-report-language-unsupported-{}.toml",
        std::process::id()
    ));
    let config = EngineConfig {
        report_language: "xx".to_string(),
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err =
        EngineConfig::from_file(&path).expect_err("unsupported report_language should be rejected");

    let _ = fs::remove_file(&path);

    assert!(err.to_string().contains("unsupported report_language"));
}

#[test]
fn from_file_normalizes_default_decision() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-default-decision-{}.toml",
        std::process::id()
    ));
    let config = EngineConfig {
        default_decision: " INTERCEPT ".to_string(),
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let loaded = EngineConfig::from_file(&path).expect("default_decision should normalize");

    let _ = fs::remove_file(&path);

    assert_eq!(loaded.default_decision, "intercept");
}

#[test]
fn from_file_rejects_unsupported_default_decision() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-default-decision-unsupported-{}.toml",
        std::process::id()
    ));
    let config = EngineConfig {
        default_decision: "drop".to_string(),
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err = EngineConfig::from_file(&path)
        .expect_err("unsupported default_decision should be rejected");

    let _ = fs::remove_file(&path);

    assert!(err.to_string().contains("unsupported default_decision"));
}

#[test]
fn from_file_rejects_partial_tls_ca_configuration() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-partial-tls-ca-{}.toml",
        std::process::id()
    ));
    let config = EngineConfig {
        tls_ca_cert: Some("/tmp/ca.crt".to_string()),
        tls_ca_key: None,
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err = EngineConfig::from_file(&path)
        .expect_err("partial TLS CA configuration should be rejected");

    let _ = fs::remove_file(&path);

    assert!(
        err.to_string()
            .contains("tls_ca_cert and tls_ca_key must both be set together")
    );
}

#[test]
fn from_file_trims_database_node_id() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-database-node-id-{}.toml",
        std::process::id()
    ));
    let config = EngineConfig {
        database: crate::config::DatabaseConfig {
            node_id: Some(" db-node ".to_string()),
            ..crate::config::DatabaseConfig::default()
        },
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let loaded = EngineConfig::from_file(&path).expect("database node id should normalize");

    let _ = fs::remove_file(&path);

    assert_eq!(loaded.database.node_id.as_deref(), Some("db-node"));
}

#[test]
fn from_file_drops_blank_database_node_id() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-database-node-id-blank-{}.toml",
        std::process::id()
    ));
    let config = EngineConfig {
        database: crate::config::DatabaseConfig {
            node_id: Some("   ".to_string()),
            ..crate::config::DatabaseConfig::default()
        },
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let loaded = EngineConfig::from_file(&path).expect("blank database node id should drop");

    let _ = fs::remove_file(&path);

    assert_eq!(loaded.database.node_id, None);
}

#[test]
fn from_file_rejects_padded_distributed_control_plane_url() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-control-plane-url-{}.toml",
        std::process::id()
    ));
    let config = EngineConfig {
        distributed: crate::config::DistributedConfig {
            control_plane_url: Some(" https://control.example.test ".to_string()),
            ..crate::config::DistributedConfig::default()
        },
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err = EngineConfig::from_file(&path).expect_err("padded control plane url should fail");

    let _ = fs::remove_file(&path);

    assert!(err.to_string().contains("invalid URL"));
}

#[test]
fn from_file_rejects_heartbeat_without_control_plane_url() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-heartbeat-no-control-plane-{}.toml",
        std::process::id()
    ));
    let config = EngineConfig {
        distributed: crate::config::DistributedConfig {
            enabled: true,
            heartbeat_interval_secs: 30,
            ..crate::config::DistributedConfig::default()
        },
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err = EngineConfig::from_file(&path).expect_err("heartbeat requires a control plane url");

    let _ = fs::remove_file(&path);

    assert!(
        err.to_string()
            .contains("distributed.heartbeat_interval_secs requires distributed.control_plane_url")
    );
}

#[test]
fn from_file_rejects_invalid_control_plane_url() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-invalid-control-plane-url-{}.toml",
        std::process::id()
    ));
    let config = EngineConfig {
        distributed: crate::config::DistributedConfig {
            control_plane_url: Some("not-a-url".to_string()),
            ..crate::config::DistributedConfig::default()
        },
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err =
        EngineConfig::from_file(&path).expect_err("invalid control plane url should be rejected");

    let _ = fs::remove_file(&path);

    assert!(err.to_string().contains("invalid URL"));
}

#[test]
fn from_file_rejects_non_http_control_plane_url() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-non-http-control-plane-url-{}.toml",
        std::process::id()
    ));
    let config = EngineConfig {
        distributed: crate::config::DistributedConfig {
            control_plane_url: Some("file:///tmp/control".to_string()),
            ..crate::config::DistributedConfig::default()
        },
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err =
        EngineConfig::from_file(&path).expect_err("non-http control plane url should be rejected");

    let _ = fs::remove_file(&path);

    assert!(err.to_string().contains("unsupported scheme 'file'"));
}

#[test]
fn finalize_listener_names_rejects_canonical_socket_collisions() {
    let mut config = EngineConfig {
        listeners: vec![
            ListenerConfig::new("http-v6-short", 80).with_bind_address("::1"),
            ListenerConfig::new("http-v6-long", 80).with_bind_address("0:0:0:0:0:0:0:1"),
        ],
        ..EngineConfig::default()
    };

    let err = config
        .validate()
        .expect_err("canonicalized IPv6 collisions should fail validation");

    assert!(
        err.to_string()
            .contains("both resolve to tcp socket ::1:80")
    );
}

#[test]
fn from_file_rejects_invalid_listener_port_range() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-empty-expansion-{}.toml",
        std::process::id()
    ));
    let mut listener = ListenerConfig::new("http", 80);
    listener.port_range = Some("not-a-port".to_string());
    let config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err = EngineConfig::from_file(&path)
        .expect_err("fully invalid port_range should leave no listeners");

    let _ = fs::remove_file(&path);

    assert!(err.to_string().contains("invalid port"));
}

#[test]
fn from_file_rejects_invalid_listener_pasv_ports() {
    for pasv_ports in [
        "60000",
        "0-1",
        "60100-60000",
        "1-65535",
        "+5000-+5001",
        " 60000-60100 ",
        "60000-60100\u{00a0}",
    ] {
        let path = std::env::temp_dir().join(format!(
            "nettrap-invalid-pasv-{}-{}.toml",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let mut listener = ListenerConfig::new("ftp", 21);
        listener.pasv_ports = Some(pasv_ports.to_string());
        let config = EngineConfig {
            listeners: vec![listener],
            ..EngineConfig::default()
        };
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let err = EngineConfig::from_file(&path)
            .expect_err("invalid pasv_ports should fail config validation");

        let _ = fs::remove_file(&path);

        assert!(
            err.to_string()
                .contains("Listener 'ftp': invalid pasv_ports"),
            "unexpected error for {pasv_ports:?}: {err}"
        );
    }
}

#[test]
fn parse_listener_pasv_port_rejects_c1_controls() {
    assert_eq!(parse_listener_pasv_port("60000\u{009f}"), None);
}

#[test]
fn parse_listener_pasv_port_rejects_ascii_padding() {
    assert_eq!(parse_listener_pasv_port(" 60000"), None);
    assert_eq!(parse_listener_pasv_port("60000 "), None);
    assert_eq!(parse_listener_pasv_port("\t60000"), None);
}

#[test]
fn from_file_rejects_zero_listener_max_connections() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-zero-max-connections-{}.toml",
        std::process::id()
    ));
    let mut listener = ListenerConfig::new("http", 80);
    listener.max_connections = Some(0);
    let config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err = EngineConfig::from_file(&path).expect_err("zero max_connections should be rejected");

    let _ = fs::remove_file(&path);

    assert!(
        err.to_string()
            .contains("Listener 'http': max_connections must be greater than 0")
    );
}

#[test]
fn adapter_validation_rejects_invalid_distributed_event_sinks() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-invalid-distributed-sink-{}.toml",
        std::process::id()
    ));
    let mut distributed = crate::config::DistributedConfig {
        enabled: true,
        ..crate::config::DistributedConfig::default()
    };
    distributed
        .event_sinks
        .push(crate::config::EventSinkConfig {
            sink_type: "bogus".into(),
            target: "127.0.0.1:1".into(),
            auth: None,
            batch_size: 1,
            flush_interval_ms: 1000,
            request_timeout_ms: 1000,
        });
    let config = EngineConfig {
        distributed,
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let loaded = EngineConfig::from_file(&path).expect("policy validation should pass");
    let err = validate_adapter_configuration(&loaded)
        .expect_err("invalid sink should fail adapter validation");

    let _ = fs::remove_file(&path);

    assert!(
        err.to_string()
            .contains("Unknown distributed event sink type")
    );
}

#[test]
fn adapter_validation_rejects_invalid_distributed_event_sink_target() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-invalid-distributed-target-{}.toml",
        std::process::id()
    ));
    let mut distributed = crate::config::DistributedConfig {
        enabled: true,
        ..crate::config::DistributedConfig::default()
    };
    distributed
        .event_sinks
        .push(crate::config::EventSinkConfig {
            sink_type: "http".into(),
            target: "not-a-url".into(),
            auth: None,
            batch_size: 1,
            flush_interval_ms: 1000,
            request_timeout_ms: 1000,
        });
    let config = EngineConfig {
        distributed,
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let loaded = EngineConfig::from_file(&path).expect("policy validation should pass");
    let err = validate_adapter_configuration(&loaded)
        .expect_err("invalid sink target should fail adapter validation");

    let _ = fs::remove_file(&path);

    assert!(
        err.to_string()
            .contains("Invalid distributed HTTP sink target")
    );
}

#[test]
fn from_file_api_applies_global_normalization_without_expanding_listeners() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-api-global-normalization-{}.toml",
        std::process::id()
    ));
    let listener = ListenerConfig::new("http", 80);
    let config = EngineConfig {
        listeners: vec![listener],
        database: crate::config::DatabaseConfig {
            pool_size: 0,
            ..crate::config::DatabaseConfig::default()
        },
        attribution_timeout_ms: 0,
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err =
        EngineConfig::from_file_api(&path).expect_err("invalid global settings should be rejected");

    let _ = fs::remove_file(&path);

    assert!(err.to_string().contains("database.pool_size"));
}

#[test]
fn from_file_api_rejects_zero_attribution_timeout_when_enabled() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-api-attribution-timeout-{}.toml",
        std::process::id()
    ));
    let mut config = EngineConfig::default();
    config.database.pool_size = 5;
    config.attribution_timeout_ms = 0;
    config.listeners = vec![ListenerConfig::new("http", 80)];
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err = EngineConfig::from_file_api(&path)
        .expect_err("zero attribution_timeout_ms should be rejected");

    let _ = fs::remove_file(&path);

    assert!(
        err.to_string()
            .contains("attribution_timeout_ms must be greater than 0")
    );
}

#[test]
fn from_file_api_rejects_invalid_listener_bind_address() {
    let path = std::env::temp_dir().join(format!("nettrap-api-raw-{}.toml", std::process::id()));
    let mut config = EngineConfig::default();
    config.database.pool_size = 5;
    config.attribution_timeout_ms = 5000;
    config.listeners = vec![ListenerConfig::new("http", 80).with_bind_address("not-an-ip")];
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err = EngineConfig::from_file_api(&path)
        .expect_err("API-only config loading should reject listener bind validation");

    let _ = fs::remove_file(&path);

    assert!(err.to_string().contains("bind_address"));
}

#[test]
fn from_file_api_rejects_invalid_api_bind() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-invalid-api-bind-{}.toml",
        std::process::id()
    ));
    let config = EngineConfig {
        api_bind: Some("not-a-socket".into()),
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err = EngineConfig::from_file_api(&path).expect_err("invalid api_bind should fail");

    let _ = fs::remove_file(&path);

    assert!(err.to_string().contains("Invalid api_bind"));
}

#[test]
fn from_file_api_ignores_invalid_distributed_probe_binds() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-invalid-distributed-bind-{}.toml",
        std::process::id()
    ));
    let config = EngineConfig {
        distributed: crate::config::DistributedConfig {
            health_bind: Some("still-not-a-socket".into()),
            metrics_bind: Some("still-not-a-socket-either".into()),
            ..crate::config::DistributedConfig::default()
        },
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let loaded = EngineConfig::from_file_api(&path)
        .expect("API-only config loading should ignore distributed probe binds");

    let _ = fs::remove_file(&path);

    assert_eq!(
        loaded.distributed.health_bind.as_deref(),
        Some("still-not-a-socket")
    );
    assert_eq!(
        loaded.distributed.metrics_bind.as_deref(),
        Some("still-not-a-socket-either")
    );
}

#[test]
fn from_file_api_ignores_distributed_runtime_configuration() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-api-distributed-runtime-{}.toml",
        std::process::id()
    ));
    let mut config = EngineConfig::default();
    config.database.pool_size = 5;
    config.distributed.enabled = true;
    config.distributed.health_bind = Some("127.0.0.1:0".into());
    config.distributed.metrics_bind = Some("127.0.0.1:0".into());
    config
        .distributed
        .event_sinks
        .push(crate::config::EventSinkConfig {
            sink_type: "http".into(),
            target: "not-a-valid-target".into(),
            auth: None,
            batch_size: 1,
            flush_interval_ms: 1000,
            request_timeout_ms: 1000,
        });
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let loaded = EngineConfig::from_file_api(&path)
        .expect("API-only config loading should ignore distributed runtime config");

    let _ = fs::remove_file(&path);

    assert_eq!(loaded.distributed.event_sinks.len(), 1);
    assert!(loaded.distributed.enabled);
}

#[test]
fn from_file_api_rejects_too_many_distributed_node_tags() {
    let path =
        std::env::temp_dir().join(format!("nettrap-api-node-tags-{}.toml", std::process::id()));
    let mut config = EngineConfig::default();
    config.distributed.node_tags = (0..=MAX_DISTRIBUTED_NODE_TAGS)
        .map(|idx| format!("tag-{idx}"))
        .collect();
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err = EngineConfig::from_file_api(&path)
        .expect_err("API-only config should reject oversized node tags");

    let _ = fs::remove_file(&path);

    assert!(
        err.to_string()
            .contains("distributed.node_tags has too many entries")
    );
}

#[test]
fn from_file_api_rejects_oversized_distributed_node_tag() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-api-node-tag-size-{}.toml",
        std::process::id()
    ));
    let mut config = EngineConfig::default();
    config.distributed.node_tags = vec!["a".repeat(MAX_DISTRIBUTED_NODE_TAG_BYTES + 1)];
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err = EngineConfig::from_file_api(&path)
        .expect_err("API-only config should reject oversized node tags");

    let _ = fs::remove_file(&path);

    assert!(
        err.to_string()
            .contains("distributed.node_tags entry 0 exceeds size limit")
    );
}

#[test]
fn from_file_api_rejects_empty_global_binds() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-empty-api-bind-{}.toml",
        std::process::id()
    ));
    let config = EngineConfig {
        api_bind: Some("   ".into()),
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let err = EngineConfig::from_file_api(&path).expect_err("empty api_bind should fail");

    let _ = fs::remove_file(&path);

    assert!(err.to_string().contains("api_bind cannot be empty"));
}

#[test]
fn finalize_listener_names_rejects_listener_and_api_bind_collisions() {
    let mut config = EngineConfig {
        listeners: vec![ListenerConfig::new("http", 8080).with_bind_address("127.0.0.1")],
        api_bind: Some("127.0.0.1:8080".into()),
        ..EngineConfig::default()
    };

    let err = config
        .validate()
        .expect_err("api_bind colliding with listener should fail validation");

    assert!(
        err.to_string()
            .contains("listener 'http' and api_bind both resolve to tcp socket 127.0.0.1:8080")
    );
}

#[test]
fn finalize_listener_names_rejects_ipv4_mapped_listener_and_api_bind_collisions() {
    let mut config = EngineConfig {
        listeners: vec![ListenerConfig::new("http", 8080).with_bind_address("127.0.0.1")],
        api_bind: Some("[::ffff:127.0.0.1]:8080".into()),
        ..EngineConfig::default()
    };

    let err = config
        .validate()
        .expect_err("mapped api_bind collision should fail validation");

    assert!(
        err.to_string()
            .contains("listener 'http' and api_bind both resolve to tcp socket 127.0.0.1:8080"),
        "{err}"
    );
}

#[test]
fn validate_socket_collision_with_unspecified_listener_and_concrete_api_bind() {
    let mut config = EngineConfig {
        listeners: vec![ListenerConfig::new("http", 8080).with_bind_address("0.0.0.0")],
        api_bind: Some("127.0.0.1:8080".into()),
        ..EngineConfig::default()
    };

    let err = config
        .validate()
        .expect_err("unspecified listener bind should collide with concrete api_bind");

    assert!(
        err.to_string()
            .contains("listener 'http' and api_bind overlap on tcp socket port 8080")
    );
}

#[test]
fn validate_socket_collision_with_ipv4_and_ipv6_wildcards() {
    let mut config = EngineConfig {
        listeners: vec![ListenerConfig::new("http", 8080).with_bind_address("0.0.0.0")],
        api_bind: Some("[::]:8080".into()),
        ..EngineConfig::default()
    };

    let err = config
        .validate()
        .expect_err("dual-stack wildcards should collide");

    assert!(
        err.to_string()
            .contains("listener 'http' and api_bind overlap on tcp socket port 8080")
    );
}

#[test]
fn validate_allows_ipv4_wildcard_with_ipv6_loopback_bind() {
    let mut config = EngineConfig {
        listeners: vec![ListenerConfig::new("http", 8080).with_bind_address("0.0.0.0")],
        api_bind: Some("[::1]:8080".into()),
        ..EngineConfig::default()
    };

    config
        .validate()
        .expect("ipv4 wildcard and ipv6 loopback should not collide");
}

#[test]
fn validate_allows_multiple_dynamic_port_binds() {
    let mut config = EngineConfig {
        listeners: vec![
            ListenerConfig::new("http-a", 0).with_bind_address("127.0.0.1"),
            ListenerConfig::new("http-b", 0).with_bind_address("127.0.0.1"),
        ],
        api_bind: Some("127.0.0.1:0".into()),
        ..EngineConfig::default()
    };

    config
        .validate()
        .expect("port 0 binds should receive distinct runtime ports");
}

#[test]
fn finalize_listener_names_rejects_global_endpoint_collisions() {
    let mut config = EngineConfig {
        listeners: vec![ListenerConfig::new("http", 8080)],
        distributed: crate::config::DistributedConfig {
            health_bind: Some("127.0.0.1:9000".into()),
            metrics_bind: Some("127.0.0.1:9000".into()),
            ..crate::config::DistributedConfig::default()
        },
        ..EngineConfig::default()
    };

    let err = config
        .validate()
        .expect_err("health and metrics bind collision should fail validation");

    assert!(
            err.to_string()
                .contains("distributed.health_bind and distributed.metrics_bind both resolve to tcp socket 127.0.0.1:9000")
        );
}

#[test]
fn validate_listener_optional_string_fields_reject_unicode_separators() {
    let mut listener = ListenerConfig::new("http", 8080);
    listener.execute_cmd = Some("echo\u{2028}next".to_string());

    let err = validate_listener_optional_string_fields(&listener)
        .expect_err("unicode separators in listener text fields should fail validation");

    assert!(
        err.to_string()
            .contains("execute_cmd contains control characters or unicode separators")
    );
}

#[test]
fn validate_listener_optional_string_fields_reject_blank_execute_cmd() {
    let mut listener = ListenerConfig::new("http", 8080);
    listener.execute_cmd = Some("  ".to_string());

    let err = validate_listener_optional_string_fields(&listener)
        .expect_err("blank execute_cmd should fail validation");

    assert!(err.to_string().contains("execute_cmd must not be blank"));
}

#[test]
fn validate_listener_optional_string_fields_reject_blank_custom_response() {
    let mut listener = ListenerConfig::new("http", 8080);
    listener.custom_response = Some("  ".to_string());

    let err = validate_listener_optional_string_fields(&listener)
        .expect_err("blank custom_response should fail validation");

    assert!(
        err.to_string()
            .contains("custom_response must not be blank")
    );
}

#[test]
fn validate_listener_optional_string_fields_reject_blank_dump_http_posts_prefix() {
    let mut listener = ListenerConfig::new("http", 8080);
    listener.dump_http_posts_prefix = Some(" \t ".to_string());

    let err = validate_listener_optional_string_fields(&listener)
        .expect_err("blank dump_http_posts_prefix should fail validation");

    assert!(
        err.to_string()
            .contains("dump_http_posts_prefix must not be blank")
    );
}

#[test]
fn from_file_declarative_preserves_port_range_form() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-declarative-roundtrip-{}.toml",
        std::process::id()
    ));
    let mut listener = ListenerConfig::new("http", 80);
    listener.port_range = Some("80,81".to_string());
    let config = EngineConfig {
        listeners: vec![listener],
        ..EngineConfig::default()
    };
    let serialized = toml::to_string(&config).expect("serialize config");
    fs::write(&path, serialized).expect("write temp config");

    let loaded =
        EngineConfig::from_file_declarative(&path).expect("declarative config should load");

    let _ = fs::remove_file(&path);

    assert_eq!(loaded.listeners.len(), 1);
    assert_eq!(loaded.listeners[0].name, "http");
    assert_eq!(loaded.listeners[0].port_range.as_deref(), Some("80,81"));
}
