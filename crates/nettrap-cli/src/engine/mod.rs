use tokio::sync::mpsc;

mod api;
mod background;
mod command;
mod commands;
mod config_load;
mod interceptor;
mod lifecycle;
mod platform;
mod replay;
mod runtime;
mod shutdown;
mod spawn;
mod startup;

#[cfg(test)]
use api::{canonicalize_socket_addr_bind, report_api_server_exit};
#[cfg(test)]
use command::build_engine;
pub use command::handle_command;
pub(crate) use commands::*;
#[cfg(test)]
pub(crate) use config_load::validate_adapter_configuration;
#[cfg(test)]
use config_load::{apply_cli_overrides, load_api_config};
pub use runtime::Engine;
#[cfg(any(target_os = "linux", test))]
pub(crate) use spawn::listener_should_spawn;
#[cfg(test)]
use spawn::validate_listener_presence;

pub(crate) fn send_fatal_runtime_error(
    tx: &mpsc::UnboundedSender<String>,
    message: String,
) -> bool {
    match tx.send(message) {
        Ok(()) => true,
        Err(err) => {
            tracing::warn!(
                "Dropped fatal runtime error because the receiver was closed: {}",
                err.0
            );
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

    use nettrap_core::prelude::Protocol;

    use super::spawn::listener_is_default_target;
    use super::*;
    use crate::cli::RunArgs;
    use crate::config::EngineConfig;

    #[test]
    fn cli_attribution_flag_does_not_disable_config_when_absent() {
        let mut config = EngineConfig::default();
        config.attribution_enabled = true;

        let args = RunArgs {
            interface: None,
            ports: Vec::new(),
            attribution: false,
            intercept: false,
            output: None,
            pcap: false,
            pcap_path: None,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        apply_cli_overrides(&mut config, &args).expect("CLI overrides should apply");

        assert!(config.attribution_enabled);
    }

    #[test]
    fn canonicalize_socket_addr_bind_canonicalizes_ipv4_mapped_addresses() {
        let addr = canonicalize_socket_addr_bind("[::ffff:127.0.0.1]:18888")
            .expect("mapped socket addr should parse");

        assert_eq!(
            addr,
            "127.0.0.1:18888"
                .parse::<std::net::SocketAddr>()
                .expect("valid IPv4 socket addr")
        );
    }

    fn temp_path(ext: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nettrap-pcap-test-{}.{}",
            uuid::Uuid::new_v4(),
            ext
        ))
    }

    fn write_test_pcap(packets: &[nettrap_core::prelude::Packet]) -> PathBuf {
        let path = temp_path("pcap");
        let writer = nettrap_pcap::PcapWriter::new(&path).expect("valid pcap path");
        writer.open().expect("pcap writer should open");
        for p in packets {
            writer.write_packet(p).expect("packet should encode");
        }
        writer.close().expect("pcap writer should close");
        path
    }

    fn dns_query_example_com() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q.push(7);
        q.extend_from_slice(b"example");
        q.push(3);
        q.extend_from_slice(b"com");
        q.push(0);
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        q
    }

    #[test]
    fn handle_pcap_replays_http_and_dns_flow() {
        use nettrap_core::prelude::{FiveTuple, Packet, PacketDirection};
        use std::net::{IpAddr, Ipv4Addr};

        let http = Packet::new(
            FiveTuple::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                5000,
                80,
                Protocol::Tcp,
            ),
            PacketDirection::Inbound,
            bytes::Bytes::from_static(
                b"GET /malware.exe HTTP/1.1\r\nHost: evil.test\r\nUser-Agent: curl/8\r\n\r\n",
            ),
        );
        let dns = Packet::new(
            FiveTuple::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                5353,
                53,
                Protocol::Udp,
            ),
            PacketDirection::Inbound,
            bytes::Bytes::from(dns_query_example_com()),
        );

        let pcap = write_test_pcap(&[http, dns]);
        let out = temp_path("jsonl");
        let args = crate::cli::PcapArgs {
            input: pcap.clone(),
            output: Some(out.clone()),
            live: false,
        };
        handle_pcap(&args, false).expect("offline replay should succeed");

        let body = fs::read_to_string(&out).expect("replay output should exist");
        assert!(body.contains("HTTP"), "missing HTTP NBI: {body}");
        assert!(body.contains("malware.exe"), "missing uri: {body}");
        assert!(body.contains("evil.test"), "missing host: {body}");
        assert!(body.contains("DNS"), "missing DNS NBI: {body}");
        assert!(body.contains("example.com"), "missing domain: {body}");

        let _ = fs::remove_file(pcap);
        let _ = fs::remove_file(out);
    }

    #[test]
    fn send_fatal_runtime_error_reports_closed_receiver() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        drop(rx);

        assert!(!send_fatal_runtime_error(&tx, "fatal".to_string()));
    }

    #[test]
    fn handle_pcap_records_tls_flow_not_dropped() {
        use nettrap_core::prelude::{FiveTuple, Packet, PacketDirection};
        use std::net::{IpAddr, Ipv4Addr};

        let tls = Packet::new(
            FiveTuple::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                6000,
                443,
                Protocol::Tcp,
            ),
            PacketDirection::Inbound,
            bytes::Bytes::from_static(&[0x16, 0x03, 0x01, 0x00, 0x2c, 0x01, 0x00, 0x00, 0x28]),
        );
        let pcap = write_test_pcap(&[tls]);
        let out = temp_path("jsonl");
        let args = crate::cli::PcapArgs {
            input: pcap.clone(),
            output: Some(out.clone()),
            live: false,
        };
        handle_pcap(&args, false).expect("replay should succeed");

        let body = fs::read_to_string(&out).expect("output should exist");
        assert!(body.contains("TLS"), "TLS flow must be recorded: {body}");
        assert!(
            body.contains("encrypted, not replayed"),
            "TLS flow must be annotated, not dropped: {body}"
        );

        let _ = fs::remove_file(pcap);
        let _ = fs::remove_file(out);
    }

    #[test]
    fn handle_pcap_rejects_live_flag() {
        let args = crate::cli::PcapArgs {
            input: PathBuf::from("capture.pcap"),
            output: None,
            live: true,
        };
        let err = handle_pcap(&args, false).expect_err("--live must be rejected offline");
        assert!(err.to_string().contains("--live"));
    }

    #[test]
    fn handle_pcap_defaults_output_path_from_input() {
        use nettrap_core::prelude::{FiveTuple, Packet, PacketDirection};
        use std::net::{IpAddr, Ipv4Addr};

        let http = Packet::new(
            FiveTuple::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                5001,
                80,
                Protocol::Tcp,
            ),
            PacketDirection::Inbound,
            bytes::Bytes::from_static(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"),
        );
        let pcap = write_test_pcap(&[http]);
        let args = crate::cli::PcapArgs {
            input: pcap.clone(),
            output: None,
            live: false,
        };
        handle_pcap(&args, false).expect("replay should succeed");

        let expected = pcap.with_extension("jsonl");
        assert!(expected.exists(), "default output path must be written");

        let _ = fs::remove_file(pcap);
        let _ = fs::remove_file(expected);
    }

    #[test]
    fn handle_pcap_avoids_colliding_with_jsonl_input_when_format_is_defaulted() {
        use nettrap_core::prelude::{FiveTuple, Packet, PacketDirection};
        use std::net::{IpAddr, Ipv4Addr};

        let http = Packet::new(
            FiveTuple::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)),
                5003,
                80,
                Protocol::Tcp,
            ),
            PacketDirection::Inbound,
            bytes::Bytes::from_static(b"GET / HTTP/1.1\r\nHost: c.test\r\n\r\n"),
        );
        let pcap = write_test_pcap(&[http]);
        let input = pcap.with_extension("jsonl");
        std::fs::rename(&pcap, &input).expect("rename fixture to jsonl");

        let args = crate::cli::PcapArgs {
            input: input.clone(),
            output: None,
            live: false,
        };

        handle_pcap(&args, false).expect("replay should succeed");

        let output = input.with_file_name(format!(
            "{}.generated.jsonl",
            input
                .file_stem()
                .and_then(|stem| stem.to_str())
                .expect("stem")
        ));
        assert!(
            output.exists(),
            "default output should avoid input collision"
        );

        let _ = fs::remove_file(input);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn handle_pcap_rejects_in_place_output_path() {
        use nettrap_core::prelude::{FiveTuple, Packet, PacketDirection};
        use std::net::{IpAddr, Ipv4Addr};

        let http = Packet::new(
            FiveTuple::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                5002,
                80,
                Protocol::Tcp,
            ),
            PacketDirection::Inbound,
            bytes::Bytes::from_static(b"GET / HTTP/1.1\r\nHost: b.test\r\n\r\n"),
        );
        let pcap = write_test_pcap(&[http]);
        let args = crate::cli::PcapArgs {
            input: pcap.clone(),
            output: Some(pcap.clone()),
            live: false,
        };

        let err = handle_pcap(&args, false).expect_err("in-place replay must fail");
        assert!(
            err.to_string()
                .contains("PCAP replay output path must differ from input path")
        );

        let _ = fs::remove_file(pcap);
    }

    #[test]
    fn handle_pcap_rejects_canonical_in_place_output_path() {
        use nettrap_core::prelude::{FiveTuple, Packet, PacketDirection};
        use std::net::{IpAddr, Ipv4Addr};

        let http = Packet::new(
            FiveTuple::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                5002,
                80,
                Protocol::Tcp,
            ),
            PacketDirection::Inbound,
            bytes::Bytes::from_static(b"GET / HTTP/1.1\r\nHost: b.test\r\n\r\n"),
        );
        let pcap = write_test_pcap(&[http]);
        let output = pcap
            .parent()
            .expect("parent")
            .join(".")
            .join(pcap.file_name().expect("file name"));
        let args = crate::cli::PcapArgs {
            input: pcap.clone(),
            output: Some(output),
            live: false,
        };

        let err = handle_pcap(&args, false).expect_err("canonical in-place replay must fail");
        assert!(
            err.to_string()
                .contains("PCAP replay output path must differ from input path")
        );

        let _ = fs::remove_file(pcap);
    }

    #[test]
    fn handle_report_exports_jsonl_input() {
        let dir = std::env::temp_dir();
        let input = dir.join(format!(
            "nettrap-report-input-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let output = dir.join(format!(
            "nettrap-report-output-{}.csv",
            uuid::Uuid::new_v4()
        ));
        let destination = crate::session::SessionDestination::unknown(8080);
        let event = crate::nbi::raw_nbi("raw", "127.0.0.1", 12345, &destination, 4, "74657374");
        fs::write(
            &input,
            format!("{}\n", event.to_json().expect("serialize NBI")),
        )
        .expect("write JSONL input");

        let args = crate::cli::ReportArgs {
            input: input.clone(),
            output: Some(output.clone()),
            format: None,
        };

        handle_report(&args).expect("report export should succeed");

        let csv = fs::read_to_string(&output).expect("report output should be readable");
        assert!(csv.contains("RAW"));
        assert!(csv.contains("127.0.0.1"));

        let _ = fs::remove_file(input);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn handle_report_rejects_in_place_output_path() {
        let dir = std::env::temp_dir();
        let input = dir.join(format!(
            "nettrap-report-input-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let destination = crate::session::SessionDestination::unknown(8080);
        let event = crate::nbi::raw_nbi("raw", "127.0.0.1", 12345, &destination, 4, "74657374");
        fs::write(
            &input,
            format!("{}\n", event.to_json().expect("serialize NBI")),
        )
        .expect("write JSONL input");

        let args = crate::cli::ReportArgs {
            input: input.clone(),
            output: Some(input.clone()),
            format: None,
        };

        let err = handle_report(&args).expect_err("in-place report rewrite must fail");
        assert!(
            err.to_string()
                .contains("Report output path must differ from input path")
        );

        let _ = fs::remove_file(input);
    }

    #[test]
    fn handle_report_rejects_canonical_in_place_output_path() {
        let dir = std::env::temp_dir();
        let input = dir.join(format!(
            "nettrap-report-input-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let output = input
            .parent()
            .expect("parent")
            .join(".")
            .join(input.file_name().expect("file name"));
        let destination = crate::session::SessionDestination::unknown(8080);
        let event = crate::nbi::raw_nbi("raw", "127.0.0.1", 12345, &destination, 4, "74657374");
        fs::write(
            &input,
            format!("{}\n", event.to_json().expect("serialize NBI")),
        )
        .expect("write JSONL input");

        let args = crate::cli::ReportArgs {
            input: input.clone(),
            output: Some(output),
            format: None,
        };

        let err = handle_report(&args).expect_err("canonical in-place report rewrite must fail");
        assert!(
            err.to_string()
                .contains("Report output path must differ from input path")
        );

        let _ = fs::remove_file(input);
    }

    #[test]
    fn handle_report_defaults_to_jsonl_when_no_format_is_specified() {
        let dir = std::env::temp_dir();
        let input = dir.join(format!("nettrap-report-default-{}", uuid::Uuid::new_v4()));
        let destination = crate::session::SessionDestination::unknown(8080);
        let event = crate::nbi::raw_nbi("raw", "127.0.0.1", 12345, &destination, 4, "74657374");
        fs::write(
            &input,
            format!("{}\n", event.to_json().expect("serialize NBI")),
        )
        .expect("write JSONL input");

        let args = crate::cli::ReportArgs {
            input: input.clone(),
            output: None,
            format: None,
        };

        handle_report(&args).expect("report export should succeed");

        let output = input.with_extension("jsonl");
        assert_eq!(
            output.extension().and_then(|ext| ext.to_str()),
            Some("jsonl")
        );
        let jsonl = fs::read_to_string(&output).expect("report output should be readable");
        assert!(jsonl.contains("\"protocol\":\"RAW\""));
        assert!(jsonl.contains("\"src_ip\":\"127.0.0.1\""));

        let _ = fs::remove_file(input);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn handle_report_avoids_colliding_with_jsonl_input_when_format_is_defaulted() {
        let dir = std::env::temp_dir();
        let input = dir.join(format!(
            "nettrap-report-default-collision-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let destination = crate::session::SessionDestination::unknown(8080);
        let event = crate::nbi::raw_nbi("raw", "127.0.0.1", 12345, &destination, 4, "74657374");
        fs::write(
            &input,
            format!("{}\n", event.to_json().expect("serialize NBI")),
        )
        .expect("write JSONL input");

        let args = crate::cli::ReportArgs {
            input: input.clone(),
            output: None,
            format: None,
        };

        handle_report(&args).expect("report export should succeed");

        let stem = input
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("valid stem");
        let output = dir.join(format!("{stem}.generated.jsonl"));
        assert!(
            output.exists(),
            "derived output should avoid input collision"
        );

        let jsonl = fs::read_to_string(&output).expect("report output should be readable");
        assert!(jsonl.contains("\"protocol\":\"RAW\""));
        assert!(jsonl.contains("\"src_ip\":\"127.0.0.1\""));

        let _ = fs::remove_file(input);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn handle_report_rejects_oversized_input_before_loading() {
        let dir = std::env::temp_dir();
        let input = dir.join(format!(
            "nettrap-report-oversized-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let output = dir.join(format!(
            "nettrap-report-oversized-output-{}.csv",
            uuid::Uuid::new_v4()
        ));
        let file = fs::File::create(&input).expect("create sparse report input");
        file.set_len(crate::output::MAX_REPORT_INPUT_BYTES + 1)
            .expect("extend sparse report input");

        let args = crate::cli::ReportArgs {
            input: input.clone(),
            output: Some(output.clone()),
            format: None,
        };

        let err = handle_report(&args).expect_err("oversized report input should be rejected");

        assert!(err.to_string().contains("exceeds load limit"));
        assert!(!output.exists());

        let _ = fs::remove_file(input);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn finalize_after_cli_overrides_rejects_invalid_output_format() {
        let mut config = EngineConfig::default();
        config.output_format = "xml".to_string();

        let err = config
            .finalize_after_cli_overrides()
            .expect_err("invalid output format should be rejected");

        assert!(err.to_string().contains("unsupported output format 'xml'"));
    }

    #[test]
    fn cli_ports_are_renormalized_after_overrides() {
        let mut config = EngineConfig::default();
        config.listeners = vec![
            crate::config::ListenerConfig::new("cli_80", 443),
            crate::config::ListenerConfig::new("https", 8443),
        ];

        let args = RunArgs {
            interface: None,
            ports: vec![80, 443],
            attribution: false,
            intercept: false,
            output: None,
            pcap: false,
            pcap_path: None,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        apply_cli_overrides(&mut config, &args).expect("CLI overrides should apply");
        config
            .finalize_listener_names()
            .expect("post-CLI listener names should normalize");

        let names: Vec<&str> = config
            .listeners
            .iter()
            .map(|listener| listener.name.as_str())
            .collect();
        assert_eq!(names, vec!["cli_80", "cli_80_80"]);
    }

    #[test]
    fn cli_ports_are_deduplicated_before_synthetic_listeners_are_added() {
        let mut config = EngineConfig::default();
        config.listeners.clear();

        let args = RunArgs {
            interface: None,
            ports: vec![80, 80, 81],
            attribution: false,
            intercept: false,
            output: None,
            pcap: false,
            pcap_path: None,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        apply_cli_overrides(&mut config, &args).expect("CLI overrides should apply");

        let mut ports: Vec<u16> = config
            .listeners
            .iter()
            .map(|listener| listener.port)
            .collect();
        ports.sort_unstable();
        assert_eq!(ports, vec![80, 81]);
    }

    #[test]
    fn cli_ports_create_synthetic_listener_when_existing_port_is_not_spawnable() {
        let mut config = EngineConfig::default();
        let mut hidden = crate::config::ListenerConfig::new("hidden_http", 80);
        hidden.hidden = true;
        config.listeners = vec![hidden];
        config
            .finalize_listener_names()
            .expect("listener names should normalize");

        let args = RunArgs {
            interface: None,
            ports: vec![80],
            attribution: false,
            intercept: false,
            output: None,
            pcap: false,
            pcap_path: None,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        apply_cli_overrides(&mut config, &args).expect("CLI overrides should apply");

        assert!(
            config
                .listeners
                .iter()
                .any(|listener| listener.name == "cli_80")
        );
        assert!(
            config
                .listeners
                .iter()
                .any(|listener| listener.name == "hidden_http")
        );
    }

    #[test]
    fn cli_ports_override_global_port_blacklists_for_requested_ports() {
        let mut config = EngineConfig::default();
        config.listeners.clear();
        config.blacklist_ports_tcp = vec![80];

        let args = RunArgs {
            interface: None,
            ports: vec![80],
            attribution: false,
            intercept: false,
            output: None,
            pcap: false,
            pcap_path: None,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        apply_cli_overrides(&mut config, &args).expect("CLI overrides should apply");

        assert!(config.blacklist_ports_tcp.is_empty());
        assert!(config.listeners.iter().any(|listener| listener.port == 80));
    }

    #[test]
    fn cli_ports_inherit_protocol_from_non_spawnable_listener() {
        let mut config = EngineConfig::default();
        let mut hidden_dns = crate::config::ListenerConfig::new("hidden_dns", 53);
        hidden_dns.protocol = Protocol::Udp;
        hidden_dns.hidden = true;
        hidden_dns.bind_address = "127.0.0.1".to_string();
        hidden_dns.use_ssl = true;
        config.listeners = vec![hidden_dns];

        let args = RunArgs {
            interface: None,
            ports: vec![53],
            attribution: false,
            intercept: false,
            output: None,
            pcap: false,
            pcap_path: None,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        apply_cli_overrides(&mut config, &args).expect("CLI overrides should apply");

        let synthetic = config
            .listeners
            .iter()
            .find(|listener| listener.name == "cli_53")
            .expect("synthetic listener should be created");
        assert_eq!(synthetic.protocol, Protocol::Udp);
        assert_eq!(synthetic.bind_address, "127.0.0.1");
        assert!(synthetic.use_ssl);
        assert!(synthetic.enabled);
        assert!(!synthetic.hidden);
    }

    #[test]
    fn cli_ports_reject_ambiguous_protocol_inheritance() {
        let mut config = EngineConfig::default();
        let mut hidden_tcp = crate::config::ListenerConfig::new("hidden_tcp", 5353);
        hidden_tcp.protocol = Protocol::Tcp;
        hidden_tcp.hidden = true;
        let mut hidden_udp = crate::config::ListenerConfig::new("hidden_udp", 5353);
        hidden_udp.protocol = Protocol::Udp;
        hidden_udp.hidden = true;
        config.listeners = vec![hidden_tcp, hidden_udp];

        let args = RunArgs {
            interface: None,
            ports: vec![5353],
            attribution: false,
            intercept: false,
            output: None,
            pcap: false,
            pcap_path: None,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        let err = apply_cli_overrides(&mut config, &args)
            .expect_err("mixed protocol listeners should be rejected");

        assert!(err.to_string().contains("use both TCP and UDP"));
    }

    #[test]
    fn load_api_config_rejects_invalid_listener_bind_address() {
        let path =
            std::env::temp_dir().join(format!("nettrap-api-raw-{}.toml", std::process::id()));
        let mut config = EngineConfig::default();
        config.database.pool_size = 5;
        config.attribution_timeout_ms = 5000;
        config.listeners =
            vec![crate::config::ListenerConfig::new("http", 80).with_bind_address("not-an-ip")];
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let err = load_api_config(Some(path.clone()), None)
            .expect_err("API-only config loading should reject listener bind validation");

        let _ = fs::remove_file(&path);

        assert!(err.to_string().contains("bind_address"));
    }

    #[test]
    fn handle_config_check_takes_priority_over_explicit_config_output() {
        let config_path = std::env::temp_dir().join(format!(
            "nettrap-config-check-priority-{}.toml",
            uuid::Uuid::new_v4()
        ));
        let output_path = std::env::temp_dir().join(format!(
            "nettrap-config-check-priority-out-{}.toml",
            uuid::Uuid::new_v4()
        ));
        let serialized = toml::to_string(&EngineConfig::default()).expect("serialize config");
        fs::write(&config_path, serialized).expect("write config");

        let args = crate::cli::ConfigArgs {
            output: Some(output_path.clone()),
            check: true,
            defaults: false,
        };

        handle_config(&args, Some(config_path.clone())).expect("config check should succeed");

        assert!(!output_path.exists());

        let _ = fs::remove_file(&config_path);
        let _ = fs::remove_file(&output_path);
    }

    #[test]
    fn handle_config_check_returns_error_for_invalid_explicit_config() {
        let config_path = std::env::temp_dir().join(format!(
            "nettrap-config-check-invalid-{}.toml",
            uuid::Uuid::new_v4()
        ));
        let mut config = EngineConfig::default();
        config.api_bind = Some(" ".into());
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&config_path, serialized).expect("write config");

        let args = crate::cli::ConfigArgs {
            output: None,
            check: true,
            defaults: false,
        };

        let err = handle_config(&args, Some(config_path.clone()))
            .expect_err("invalid config check should return error");

        assert!(err.to_string().contains("Configuration validation failed"));

        let _ = fs::remove_file(&config_path);
    }

    #[test]
    fn load_api_config_overrides_invalid_api_bind_from_config() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-api-override-bind-{}.toml",
            std::process::id()
        ));
        let mut config = EngineConfig::default();
        config.api_bind = Some("not-a-socket".to_string());
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let loaded = load_api_config(Some(path.clone()), Some("127.0.0.1:18888"))
            .expect("API bind override should be applied");

        let _ = fs::remove_file(&path);

        assert_eq!(loaded.api_bind.as_deref(), Some("127.0.0.1:18888"));
    }

    #[test]
    fn load_api_config_ignores_redirect_defaults_in_api_mode() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-api-redirect-default-{}.toml",
            std::process::id()
        ));
        let mut config = EngineConfig::default();
        config.redirect_all_traffic = true;
        config.default_tcp_listener = Some("missing".to_string());
        config.listeners = vec![crate::config::ListenerConfig::new("http", 80)];
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let loaded = load_api_config(Some(path.clone()), None)
            .expect("API-only config loading should ignore redirect defaults");

        let _ = fs::remove_file(&path);

        assert_eq!(loaded.default_tcp_listener.as_deref(), Some("missing"));
        assert!(loaded.redirect_all_traffic);
    }

    #[test]
    fn load_api_config_ignores_partial_tls_ca_configuration() {
        let path =
            std::env::temp_dir().join(format!("nettrap-api-tls-ca-{}.toml", std::process::id()));
        let mut config = EngineConfig::default();
        config.tls_ca_cert = Some("/definitely/missing/nettrap-ca.pem".into());
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let loaded = load_api_config(Some(path.clone()), None)
            .expect("API-only config loading should ignore TLS CA config");

        let _ = fs::remove_file(&path);

        assert_eq!(
            loaded.tls_ca_cert.as_deref(),
            Some("/definitely/missing/nettrap-ca.pem")
        );
        assert!(loaded.tls_ca_key.is_none());
    }

    #[test]
    fn load_api_config_trims_distributed_node_region() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-api-node-region-{}.toml",
            std::process::id()
        ));
        let mut config = EngineConfig::default();
        config.distributed.node_region = Some(" eu west ".into());
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let loaded = load_api_config(Some(path.clone()), None)
            .expect("API-only config loading should trim node region");

        let _ = fs::remove_file(&path);

        assert_eq!(loaded.distributed.node_region.as_deref(), Some("eu west"));
    }

    #[test]
    fn check_config_paths_returns_error_if_any_file_is_invalid() {
        let valid_path = std::env::temp_dir().join(format!(
            "nettrap-config-check-valid-{}.toml",
            uuid::Uuid::new_v4()
        ));
        let invalid_path = std::env::temp_dir().join(format!(
            "nettrap-config-check-invalid-list-{}.toml",
            uuid::Uuid::new_v4()
        ));

        fs::write(
            &valid_path,
            toml::to_string(&EngineConfig::default()).expect("serialize config"),
        )
        .expect("write valid config");

        let mut invalid = EngineConfig::default();
        invalid.api_bind = Some("".into());
        fs::write(
            &invalid_path,
            toml::to_string(&invalid).expect("serialize invalid config"),
        )
        .expect("write invalid config");

        let err = check_config_paths(&[valid_path.clone(), invalid_path.clone()])
            .expect_err("mixed validity should return error");

        assert!(err.to_string().contains("1 file(s)"));

        let _ = fs::remove_file(&valid_path);
        let _ = fs::remove_file(&invalid_path);
    }

    #[test]
    fn allow_zero_listeners_does_not_enable_api_only_mode() {
        let engine = Engine::new(
            EngineConfig::default(),
            false,
            None,
            None,
            None,
            false,
            true,
        );

        assert!(engine.options.plan.allow_zero_listeners());
        assert_eq!(
            engine.options.plan.mode(),
            nettrap_engine::StartupMode::Standard
        );
    }

    #[test]
    fn api_only_engine_uses_explicit_mode() {
        let engine = Engine::api_only(EngineConfig::default());

        assert!(engine.options.plan.allow_zero_listeners());
        assert_eq!(
            engine.options.plan.mode(),
            nettrap_engine::StartupMode::ApiOnly
        );
        assert!(!engine.options.intercept_enabled);
    }

    #[tokio::test]
    async fn api_only_engine_does_not_initialize_faketime() {
        crate::faketime::set_delta(0);

        let mut config = EngineConfig::default();
        config.faketime.enabled = true;
        config.faketime.init_delta = 3600;

        let stop_flag =
            std::env::temp_dir().join(format!("nettrap-api-stop-{}", uuid::Uuid::new_v4()));
        fs::write(&stop_flag, b"stop").expect("write stop flag");

        let engine = Engine::api_only(config);
        engine
            .run(Some(stop_flag.clone()))
            .await
            .expect("api-only engine should stop cleanly");

        assert_eq!(crate::faketime::get_delta(), 0);

        let _ = fs::remove_file(&stop_flag);
    }

    #[tokio::test]
    async fn api_only_engine_ignores_distributed_runtime_configuration() {
        let mut config = EngineConfig::default();
        config.distributed.enabled = true;
        config.distributed.health_bind = Some("127.0.0.1:0".into());
        config.distributed.metrics_bind = Some("127.0.0.1:0".into());
        config
            .distributed
            .event_sinks
            .push(crate::config::EventSinkConfig {
                sink_type: "bogus".into(),
                target: "127.0.0.1:1".into(),
                auth: None,
                batch_size: 1,
                flush_interval_ms: 1000,
                request_timeout_ms: 1000,
            });

        let stop_flag = std::env::temp_dir().join(format!(
            "nettrap-api-distributed-stop-{}",
            uuid::Uuid::new_v4()
        ));
        fs::write(&stop_flag, b"stop").expect("write stop flag");

        let engine = Engine::api_only(config);
        engine
            .run(Some(stop_flag.clone()))
            .await
            .expect("api-only engine should ignore distributed runtime config");

        let _ = fs::remove_file(&stop_flag);
    }

    #[tokio::test]
    async fn api_only_engine_rejects_invalid_database_backend() {
        let mut config = EngineConfig::default();
        config.database.backend = "postgres".to_string();
        config.database.postgres_url = Some("postgres://invalid:bad".to_string());

        let stop_flag =
            std::env::temp_dir().join(format!("nettrap-api-db-stop-{}", uuid::Uuid::new_v4()));
        fs::write(&stop_flag, b"stop").expect("write stop flag");

        let engine = Engine::api_only(config);
        let error = engine
            .run(Some(stop_flag.clone()))
            .await
            .expect_err("api-only engine should reject invalid DB backend");

        let error = error.to_string();
        assert!(error.contains("database initialization failed"));
        assert!(error.contains("PostgreSQL connect error"));

        let _ = fs::remove_file(&stop_flag);
    }

    #[test]
    fn cli_ports_reject_ambiguous_listener_clone_settings() {
        let mut config = EngineConfig::default();
        let mut hidden_a = crate::config::ListenerConfig::new("hidden_a", 8080);
        hidden_a.hidden = true;
        hidden_a.bind_address = "127.0.0.1".to_string();
        let mut hidden_b = crate::config::ListenerConfig::new("hidden_b", 8080);
        hidden_b.hidden = true;
        hidden_b.bind_address = "127.0.0.2".to_string();
        config.listeners = vec![hidden_a, hidden_b];

        let args = RunArgs {
            interface: None,
            ports: vec![8080],
            attribution: false,
            intercept: false,
            output: None,
            pcap: false,
            pcap_path: None,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        let err = apply_cli_overrides(&mut config, &args)
            .expect_err("incompatible base listeners should be rejected");

        assert!(err.to_string().contains("incompatible settings"));
    }

    #[test]
    fn hidden_default_listener_is_considered_spawnable() {
        let mut config = EngineConfig::default();
        let mut listener = crate::config::ListenerConfig::new("http-default", 8080);
        listener.hidden = true;
        config.listeners = vec![listener.clone()];
        config.default_tcp_listener = Some(listener.name.to_uppercase());

        assert!(listener_is_default_target(&config, &listener));
        assert!(listener_should_spawn(&config, &listener));
    }

    #[tokio::test]
    async fn report_api_server_exit_marks_ok_exit_as_failed() {
        let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
        let (fatal_runtime_tx, mut fatal_runtime_rx) = mpsc::unbounded_channel();

        report_api_server_exit(
            Ok::<(), nettrap_core::Error>(()),
            Arc::clone(&runtime_health),
            fatal_runtime_tx,
        );

        assert_eq!(
            runtime_health.snapshot().api.state,
            nettrap_api::ComponentState::Failed
        );
        assert_eq!(
            runtime_health.snapshot().api.error.as_deref(),
            Some("API server exited unexpectedly")
        );
        assert_eq!(
            fatal_runtime_rx.recv().await.as_deref(),
            Some("API server exited unexpectedly")
        );
    }

    #[test]
    fn validate_listener_presence_rejects_empty_runtime_in_run_mode() {
        let mut config = EngineConfig::default();
        config.listeners.clear();

        let err = validate_listener_presence(&config, nettrap_engine::StartupMode::Standard, false)
            .unwrap_err();
        assert!(err.to_string().contains("No spawnable listeners"));
    }

    #[test]
    fn validate_listener_presence_allows_api_only_mode_without_listeners() {
        let mut config = EngineConfig::default();
        config.listeners.clear();

        validate_listener_presence(&config, nettrap_engine::StartupMode::ApiOnly, true)
            .expect("api-only mode should be allowed");
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn build_engine_requires_interceptor_when_requested() {
        let args = RunArgs {
            interface: None,
            ports: Vec::new(),
            attribution: false,
            intercept: true,
            output: None,
            pcap: false,
            pcap_path: None,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        let engine = build_engine(&args, false, None)
            .await
            .expect("engine should build");

        assert!(engine.options.intercept_enabled);
        assert!(engine.options.require_interceptor);
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn build_engine_rejects_windows_interception() {
        let args = RunArgs {
            interface: None,
            ports: Vec::new(),
            attribution: false,
            intercept: true,
            output: None,
            pcap: false,
            pcap_path: None,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        let Err(err) = build_engine(&args, false, None).await else {
            panic!("Windows interception must remain disabled");
        };

        assert!(err.to_string().contains("not supported on Windows"));
    }

    #[tokio::test]
    async fn build_engine_keeps_interceptor_optional_when_not_requested() {
        let args = RunArgs {
            interface: None,
            ports: Vec::new(),
            attribution: false,
            intercept: false,
            output: None,
            pcap: false,
            pcap_path: None,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        let engine = build_engine(&args, false, None)
            .await
            .expect("engine should build");

        assert!(!engine.options.intercept_enabled);
        assert!(!engine.options.require_interceptor);
    }
}
