mod event_log;
mod handler_factory;

pub use event_log::*;
pub use handler_factory::*;

use crate::listener_context::ListenerContext;
use crate::session::SessionDestination;
use crate::utils::canonical_socket_ip_string;
use crate::utils::log_event;
use crate::utils::service_name::{is_usable_service_name_input, resolve_service_name};
use nettrap_protocols::handlers::*;

pub fn get_protocol_banner(name: &str, banner: Option<&str>) -> crate::Result<Option<Vec<u8>>> {
    if !is_usable_service_name_input(name) {
        return Err(crate::Error::Config(format!(
            "invalid listener name for banner lookup: {}",
            name
        )));
    }
    let had_banner = banner.is_some();
    let banner = match banner {
        Some(value) if fallback_name_matches_protocol(name, "ftp") => {
            if is_invalid_ftp_banner_override(value) {
                return Err(crate::Error::Config(format!(
                    "invalid banner override for listener {}: {}",
                    name, value
                )));
            }
            Some(value)
        }
        Some(value) if fallback_name_matches_protocol(name, "ssh") => Some(value),
        Some(value) if is_usable_service_name_input(value) => Some(value),
        Some(value) => {
            return Err(crate::Error::Config(format!(
                "invalid banner override for listener {}: {}",
                name, value
            )));
        }
        None => None,
    };

    let resolved = crate::handler_registry::get_protocol_banner(name, banner)?;
    if had_banner {
        Ok(resolved)
    } else {
        Ok(resolved.or_else(|| fallback_get_protocol_banner(name, banner)))
    }
}

fn fallback_get_protocol_banner(name: &str, banner: Option<&str>) -> Option<Vec<u8>> {
    match name {
        _ if fallback_name_matches_protocol(name, "smtp") => {
            let handler = if let Some(b) = banner {
                nettrap_proto_smtp::SmtpHandler::new()
                    .with_domain(resolve_service_name(b))
                    .ok()?
            } else {
                nettrap_proto_smtp::SmtpHandler::new()
            };
            Some(handler.get_welcome_banner().into_bytes())
        }
        _ if fallback_name_matches_protocol(name, "ftp") => {
            let handler = if let Some(b) = banner {
                nettrap_proto_ftp::FtpHandler::new()
                    .with_preformatted_banner(nettrap_proto_ftp::resolve_banner(b))
                    .ok()?
            } else {
                nettrap_proto_ftp::FtpHandler::new()
            };
            Some(handler.get_banner_at(crate::faketime::fake_now()).to_vec())
        }
        _ if fallback_name_matches_protocol(name, "pop3") => {
            let handler = if let Some(b) = banner {
                nettrap_proto_pop3::Pop3Handler::new()
                    .with_now(crate::faketime::fake_now)
                    .with_domain(resolve_service_name(b))
                    .ok()?
            } else {
                nettrap_proto_pop3::Pop3Handler::new().with_now(crate::faketime::fake_now)
            };
            Some(handler.get_welcome_banner().into_bytes())
        }
        _ if fallback_name_matches_protocol(name, "irc") => {
            let handler = if let Some(b) = banner {
                nettrap_proto_irc::IrcHandler::new()
                    .with_clock(crate::faketime::fake_now())
                    .with_server_name(resolve_service_name(b))
                    .unwrap_or_else(|_| {
                        nettrap_proto_irc::IrcHandler::new().with_clock(crate::faketime::fake_now())
                    })
            } else {
                nettrap_proto_irc::IrcHandler::new().with_clock(crate::faketime::fake_now())
            };
            Some(handler.get_welcome_banner().into_bytes())
        }
        _ if fallback_name_matches_protocol(name, "ssh") => {
            Some(nettrap_proto_ssh::SshHandler::new().get_banner())
        }
        _ => None,
    }
}

fn is_invalid_ftp_banner_override(value: &str) -> bool {
    value.trim_matches([' ', '\t']) != value
        || value
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
}

fn fallback_name_matches_protocol(name: &str, protocol: &str) -> bool {
    if name.trim_matches([' ', '\t']) != name
        || name.is_empty()
        || name
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return false;
    }

    let listener = name;
    if listener.is_empty()
        || listener
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return false;
    }

    let listener = listener.to_lowercase();
    listener == protocol
        || listener
            .strip_prefix(protocol)
            .and_then(|suffix| suffix.as_bytes().first().copied())
            .is_some_and(|byte| matches!(byte, b'-' | b'_'))
}

pub struct UdpGenericResponse<'a> {
    pub response: &'a [u8],
    pub src: std::net::SocketAddr,
    pub destination: &'a SessionDestination,
    pub len: usize,
    pub output_path: Option<&'a std::path::Path>,
    pub protocol_name: &'a str,
}

pub async fn handle_udp_generic(
    ctx: &ListenerContext,
    socket: &tokio::net::UdpSocket,
    packet: UdpGenericResponse<'_>,
) {
    let mut sent_bytes = 0u64;
    if !packet.response.is_empty() {
        ctx.apply_response_delay().await;
        if socket.send_to(packet.response, packet.src).await.is_ok() {
            ctx.write_pcap_response_udp_for_destination(
                packet.response,
                &packet.src,
                packet.destination,
            );
            sent_bytes = packet.response.len() as u64;
        }
    }
    ctx.update_session_bytes(
        &packet.src,
        "UDP",
        packet.destination,
        packet.len as u64,
        sent_bytes,
    );
    log_event(
        packet.output_path,
        ctx.name(),
        &packet.src,
        &format!("{}_request", packet.protocol_name),
        &format!("{} bytes", packet.len),
    )
    .await;
    let mut nbi = crate::nbi::raw_nbi(
        ctx.name(),
        &canonical_socket_ip_string(&packet.src),
        packet.src.port(),
        packet.destination,
        packet.len,
        "",
    );
    nbi.add("detected_protocol", packet.protocol_name);
    ctx.record_nbi(&nbi).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
    use crate::process_filter::ProcessFilter;
    use crate::session::{PortForwardTable, SessionTracker};
    use std::sync::Arc;

    fn test_context_with_pasv_ports(pasv_ports: Option<String>) -> ListenerContext {
        ListenerContext::builder()
            .name("ftp")
            .port(21)
            .pasv_ports(pasv_ports)
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    attribution: None,
                    attribution_timeout: std::time::Duration::from_millis(5000),
                    pcap_writer: None,
                    nbi_collector: Arc::new(
                        crate::nbi::NbiCollector::new(None).expect("collector should build"),
                    ),
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build")
    }

    fn test_dns_context_with_response_mode(mode: &str) -> ListenerContext {
        ListenerContext::builder()
            .name("dns")
            .port(53)
            .dns_response_mode(Some(mode.to_string()))
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    attribution: None,
                    attribution_timeout: std::time::Duration::from_millis(5000),
                    pcap_writer: None,
                    nbi_collector: Arc::new(
                        crate::nbi::NbiCollector::new(None).expect("collector should build"),
                    ),
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build")
    }

    #[test]
    fn test_get_protocol_banner_smtp() {
        let result = get_protocol_banner("smtp", Some("mail.example.com")).expect("banner");
        assert!(result.is_some());
        let binding = result.unwrap();
        let banner = String::from_utf8_lossy(&binding);
        assert!(banner.contains("ESMTP") || banner.contains("NetTrap"));
    }

    #[tokio::test]
    async fn udp_generic_nbi_records_protocol_without_fake_hexdump() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind UDP socket");
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind UDP receiver");
        let src = receiver.local_addr().expect("receiver addr");
        let destination = SessionDestination::new_unchecked("127.0.0.1".to_string(), 5353);
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-udp-generic-nbi-{}-{}.jsonl",
            std::process::id(),
            src.port()
        ));
        let collector = Arc::new(
            crate::nbi::NbiCollector::new(Some(nbi_path.clone())).expect("collector should build"),
        );
        let ctx = ListenerContext::builder()
            .name("snmp")
            .port(161)
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    attribution: None,
                    attribution_timeout: std::time::Duration::from_millis(5000),
                    pcap_writer: None,
                    nbi_collector: Arc::clone(&collector),
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build");

        handle_udp_generic(
            &ctx,
            &socket,
            UdpGenericResponse {
                response: b"OK\n",
                src,
                destination: &destination,
                len: 5,
                output_path: None,
                protocol_name: "snmp",
            },
        )
        .await;
        collector.flush_all_pending().await;

        let content = tokio::fs::read_to_string(&nbi_path)
            .await
            .expect("NBI JSONL should be written");
        let event: nettrap_core::nbi::NetworkBehaviorIndicator =
            serde_json::from_str(content.lines().next().expect("NBI line"))
                .expect("NBI line should deserialize");
        assert_eq!(event.protocol, "RAW");
        assert_eq!(event.indicators.get("hexdump"), None);
        assert_eq!(
            event
                .indicators
                .get("detected_protocol")
                .map(String::as_str),
            Some("snmp")
        );
        let _ = tokio::fs::remove_file(nbi_path).await;
    }

    #[test]
    fn test_get_protocol_banner_ftp() {
        let result = get_protocol_banner("ftp", Some("FTP Server")).expect("banner");
        assert!(result.is_some());
    }

    #[test]
    fn test_get_protocol_banner_ftp_preserves_special_banner_presets() {
        let result = get_protocol_banner("ftp", Some("!as400")).expect("banner");
        let binding = result.expect("ftp banner");
        let banner = String::from_utf8_lossy(&binding);

        assert!(banner.contains("QTCP at"));
        assert!(banner.contains("nettrap"));
    }

    #[test]
    fn test_get_protocol_banner_unknown() {
        let result = get_protocol_banner("unknown", Some("banner")).expect("banner");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_protocol_banner_telnet() {
        let result = get_protocol_banner("telnet", None).expect("banner");
        assert!(result.is_some());
    }

    #[test]
    fn test_get_protocol_banner_ssh() {
        let result = get_protocol_banner("ssh", None).expect("banner");
        assert!(result.is_some());
        let binding = result.unwrap();
        let banner = String::from_utf8_lossy(&binding);
        assert!(banner.contains("SSH"));
    }

    #[test]
    fn test_get_protocol_banner_ssh_invalid_banner_is_rejected() {
        let result = get_protocol_banner("ssh", Some("Example"));
        assert!(result.is_err());
    }

    #[test]
    fn test_get_protocol_banner_mysql() {
        let result = get_protocol_banner("mysql", None).expect("banner");
        assert!(result.is_some());
    }

    #[test]
    fn test_get_protocol_banner_prefix_match() {
        assert!(
            get_protocol_banner("smtp-25", None)
                .expect("banner")
                .is_some()
        );
        assert!(
            get_protocol_banner("ftp-21", Some("banner"))
                .expect("banner")
                .is_some()
        );
        assert!(
            get_protocol_banner("pop3-110", None)
                .expect("banner")
                .is_some()
        );

        assert!(
            get_protocol_banner("smtpbackup", None)
                .expect("banner")
                .is_none()
        );
        assert!(
            get_protocol_banner("ftpbackup", Some("banner"))
                .expect("banner")
                .is_none()
        );
        assert!(
            get_protocol_banner("pop3backup", None)
                .expect("banner")
                .is_none()
        );
    }

    #[test]
    fn test_get_protocol_banner_rejects_c1_controls_in_listener_name() {
        let err = get_protocol_banner("smtp\u{009f}-25", None)
            .expect_err("invalid listener name should fail");

        assert!(err.to_string().contains("invalid listener name"));
    }

    #[test]
    fn service_name_banners_reject_injected_lines() {
        for protocol in ["smtp", "pop3", "irc", "ftp"] {
            let banner = get_protocol_banner(protocol, Some("mx\r\n250 injected"))
                .expect_err("{protocol} banner should be rejected");
            assert!(banner.to_string().contains("invalid banner override"));
        }
    }

    #[test]
    fn blank_banner_overrides_are_rejected() {
        for protocol in ["smtp", "pop3", "irc", "ftp"] {
            let blank = get_protocol_banner(protocol, Some(" "));
            assert!(
                blank.is_err(),
                "{protocol} banner should reject blank override"
            );
        }
    }

    #[test]
    fn unicode_whitespace_banner_override_is_rejected() {
        for protocol in ["smtp", "pop3", "irc", "ftp"] {
            let banner = get_protocol_banner(protocol, Some("mx\u{00a0}example"));
            assert!(
                banner.is_err(),
                "{protocol} banner should reject unicode-whitespace-padded override"
            );
        }
    }

    #[test]
    fn ascii_padded_banner_override_is_rejected() {
        for protocol in ["smtp", "pop3", "irc", "ftp"] {
            let banner = get_protocol_banner(protocol, Some(" mx.example "));
            assert!(
                banner.is_err(),
                "{protocol} banner should reject ascii-padded override"
            );
        }
    }

    #[test]
    fn unicode_whitespace_listener_name_does_not_match_fallback_banner_handlers() {
        let err = get_protocol_banner("smtp\u{00a0}", Some("mx.example"))
            .expect_err("invalid listener name should fail");

        assert!(err.to_string().contains("invalid listener name"));
    }

    #[test]
    fn c1_control_listener_name_does_not_match_fallback_banner_handlers() {
        let err = get_protocol_banner("smtp\u{009f}", Some("mx.example"))
            .expect_err("invalid listener name should fail");

        assert!(err.to_string().contains("invalid listener name"));
    }

    #[test]
    fn ascii_padded_listener_name_does_not_match_fallback_banner_handlers() {
        let err = get_protocol_banner(" smtp ", Some("mx.example"))
            .expect_err("invalid listener name should fail");

        assert!(err.to_string().contains("invalid listener name"));
    }

    #[test]
    fn blank_server_name_and_banner_fall_back_to_default_protocol_identity() {
        let ctx = ListenerContext::builder()
            .name("smtp")
            .port(25)
            .server_name(Some(" ".to_string()))
            .banner(Some(" ".to_string()))
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    attribution: None,
                    attribution_timeout: std::time::Duration::from_millis(5000),
                    pcap_writer: None,
                    nbi_collector: Arc::new(
                        crate::nbi::NbiCollector::new(None).expect("collector should build"),
                    ),
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build");

        let smtp_blank = init_smtp_handler(&ctx)
            .expect("SMTP handler should build")
            .get_welcome_banner()
            .into_bytes();
        let smtp_default = nettrap_proto_smtp::SmtpHandler::new()
            .get_welcome_banner()
            .into_bytes();
        assert_eq!(smtp_blank, smtp_default);

        let pop3_blank = init_pop3_handler(&ctx)
            .expect("POP3 handler should build")
            .get_welcome_banner()
            .into_bytes();
        let pop3_default = nettrap_proto_pop3::Pop3Handler::new()
            .with_now(crate::faketime::fake_now)
            .get_welcome_banner()
            .into_bytes();
        assert_eq!(pop3_blank, pop3_default);

        let irc_blank = init_irc_handler(&ctx)
            .expect("IRC handler should build")
            .get_welcome_banner()
            .into_bytes();
        let irc_default = nettrap_proto_irc::IrcHandler::new()
            .with_clock(crate::faketime::fake_now())
            .get_welcome_banner()
            .into_bytes();
        assert_eq!(irc_blank, irc_default);
    }

    #[test]
    fn invalid_server_name_is_rejected_for_hostname_based_handlers() {
        let ctx = ListenerContext::builder()
            .name("smtp")
            .port(25)
            .server_name(Some("bad><name".to_string()))
            .banner(Some("banner.example".to_string()))
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    attribution: None,
                    attribution_timeout: std::time::Duration::from_millis(5000),
                    pcap_writer: None,
                    nbi_collector: Arc::new(
                        crate::nbi::NbiCollector::new(None).expect("collector should build"),
                    ),
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build");

        for (protocol, result) in [
            (
                "smtp",
                init_smtp_handler(&ctx).map(|handler| handler.get_welcome_banner().into_bytes()),
            ),
            (
                "pop3",
                init_pop3_handler(&ctx).map(|handler| handler.get_welcome_banner().into_bytes()),
            ),
            (
                "irc",
                init_irc_handler(&ctx).map(|handler| handler.get_welcome_banner().into_bytes()),
            ),
            (
                "ftp",
                init_ftp_handler(&ctx)
                    .map(|handler| handler.get_banner_at(crate::faketime::fake_now()).to_vec()),
            ),
            (
                "imap",
                init_imap_handler(&ctx).map(|handler| handler.get_welcome_banner().into_bytes()),
            ),
        ] {
            let err = match result {
                Ok(_) => panic!("{protocol} should reject invalid server_name"),
                Err(err) => err,
            };

            assert!(err.to_string().contains("invalid"), "{protocol}: {err}");
        }
    }

    #[test]
    fn blank_ftp_server_name_matches_omitted_server_name() {
        let blank_ctx = ListenerContext::builder()
            .name("ftp")
            .port(21)
            .server_name(Some(" ".to_string()))
            .banner(Some("!as400".to_string()))
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    attribution: None,
                    attribution_timeout: std::time::Duration::from_millis(5000),
                    pcap_writer: None,
                    nbi_collector: Arc::new(
                        crate::nbi::NbiCollector::new(None).expect("collector should build"),
                    ),
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build");
        let plain_ctx = ListenerContext::builder()
            .name("ftp")
            .port(21)
            .banner(Some("!as400".to_string()))
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    attribution: None,
                    attribution_timeout: std::time::Duration::from_millis(5000),
                    pcap_writer: None,
                    nbi_collector: Arc::new(
                        crate::nbi::NbiCollector::new(None).expect("collector should build"),
                    ),
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build");

        let blank_banner = init_ftp_handler(&blank_ctx)
            .expect("FTP handler should build")
            .get_banner_at(crate::faketime::fake_now())
            .to_vec();
        let plain_banner = init_ftp_handler(&plain_ctx)
            .expect("FTP handler should build")
            .get_banner_at(crate::faketime::fake_now())
            .to_vec();

        assert_eq!(blank_banner, plain_banner);
    }

    #[test]
    fn unicode_whitespace_server_name_is_rejected_for_hostname_based_handlers() {
        let ctx = ListenerContext::builder()
            .name("smtp")
            .port(25)
            .server_name(Some("mainframe01\u{00a0}".to_string()))
            .banner(Some("banner.example".to_string()))
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    attribution: None,
                    attribution_timeout: std::time::Duration::from_millis(5000),
                    pcap_writer: None,
                    nbi_collector: Arc::new(
                        crate::nbi::NbiCollector::new(None).expect("collector should build"),
                    ),
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build");

        for (protocol, result) in [
            (
                "smtp",
                init_smtp_handler(&ctx).map(|handler| handler.get_welcome_banner().into_bytes()),
            ),
            (
                "pop3",
                init_pop3_handler(&ctx).map(|handler| handler.get_welcome_banner().into_bytes()),
            ),
            (
                "irc",
                init_irc_handler(&ctx).map(|handler| handler.get_welcome_banner().into_bytes()),
            ),
            (
                "ftp",
                init_ftp_handler(&ctx)
                    .map(|handler| handler.get_banner_at(crate::faketime::fake_now()).to_vec()),
            ),
            (
                "imap",
                init_imap_handler(&ctx).map(|handler| handler.get_welcome_banner().into_bytes()),
            ),
        ] {
            let err = match result {
                Ok(_) => panic!("{protocol} should reject unicode whitespace hostnames"),
                Err(err) => err,
            };

            assert!(err.to_string().contains("invalid"), "{protocol}: {err}");
        }
    }

    #[test]
    fn init_ftp_handler_rejects_signed_pasv_ports() {
        let ctx = test_context_with_pasv_ports(Some("+5000-+5001".to_string()));
        let err = match init_ftp_handler(&ctx) {
            Ok(_) => panic!("signed PASV range should fail"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("Invalid pasv_ports"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn init_ftp_handler_interpolates_configured_server_name() {
        let ctx = ListenerContext::builder()
            .name("ftp")
            .port(21)
            .server_name(Some("mainframe01".to_string()))
            .banner(Some("!as400".to_string()))
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    attribution: None,
                    attribution_timeout: std::time::Duration::from_millis(5000),
                    pcap_writer: None,
                    nbi_collector: Arc::new(
                        crate::nbi::NbiCollector::new(None).expect("collector should build"),
                    ),
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build");

        let handler = init_ftp_handler(&ctx).expect("FTP handler should build");
        let banner = String::from_utf8_lossy(&handler.get_banner()).into_owned();

        assert!(
            banner.contains("QTCP at mainframe01."),
            "server name not interpolated: {banner}"
        );
    }

    #[test]
    fn init_ftp_handler_rejects_invalid_banner_override() {
        let ctx = ListenerContext::builder()
            .name("ftp")
            .port(21)
            .banner(Some("bad\r\n250 injected".to_string()))
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    attribution: None,
                    attribution_timeout: std::time::Duration::from_millis(5000),
                    pcap_writer: None,
                    nbi_collector: Arc::new(
                        crate::nbi::NbiCollector::new(None).expect("collector should build"),
                    ),
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build");

        let err = init_ftp_handler(&ctx).expect_err("FTP handler should reject invalid banner");
        assert!(err.to_string().contains("invalid FTP banner"));
    }

    #[test]
    fn init_ftp_handler_rejects_invalid_pasv_range_format() {
        let ctx = test_context_with_pasv_ports(Some("60000".to_string()));
        let err = match init_ftp_handler(&ctx) {
            Ok(_) => panic!("invalid PASV format should fail"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("Invalid pasv_ports"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn init_dns_handler_rejects_invalid_ncsi_response_ip() {
        let ctx = ListenerContext::builder()
            .name("dns")
            .port(53)
            .dns_ncsi_response_ip(Some("not-an-ip".to_string()))
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    attribution: None,
                    attribution_timeout: std::time::Duration::from_millis(5000),
                    pcap_writer: None,
                    nbi_collector: Arc::new(
                        crate::nbi::NbiCollector::new(None).expect("collector should build"),
                    ),
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build");

        let err = match init_dns_handler(&ctx) {
            Ok(_) => panic!("invalid NCSI IP should fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("Invalid dns_ncsi_response_ip"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn init_dns_handler_rejects_unusable_ncsi_response_ip() {
        for ip in ["0.0.0.0", "127.0.0.1", "255.255.255.255", "224.0.0.1"] {
            let ctx = ListenerContext::builder()
                .name("dns")
                .port(53)
                .dns_ncsi_response_ip(Some(ip.to_string()))
                .build(
                    ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                        .expect("empty host rules should compile"),
                    ListenerRuntime::new(ListenerRuntimeResources {
                        ca: None,
                        router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                        attribution: None,
                        attribution_timeout: std::time::Duration::from_millis(5000),
                        pcap_writer: None,
                        nbi_collector: Arc::new(
                            crate::nbi::NbiCollector::new(None).expect("collector should build"),
                        ),
                        session_tracker: Arc::new(SessionTracker::new()),
                        port_forward_table: Arc::new(PortForwardTable::new()),
                        flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                    }),
                )
                .expect("listener context should build");

            let err = match init_dns_handler(&ctx) {
                Ok(_) => panic!("special NCSI IP should fail"),
                Err(err) => err,
            };
            assert!(
                err.to_string().contains("usable unicast address"),
                "unexpected error for {ip}: {err}"
            );
        }
    }

    #[test]
    fn init_dns_handler_rejects_unknown_response_mode() {
        let ctx = test_dns_context_with_response_mode("banana");

        let err = match init_dns_handler(&ctx) {
            Ok(_) => panic!("unknown DNS mode should fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("Unknown dns_response_mode"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn init_dns_handler_accepts_explicit_static_response_mode() {
        let ctx = test_dns_context_with_response_mode("static");

        init_dns_handler(&ctx).expect("explicit static mode should initialize");
    }

    #[test]
    fn init_dns_handler_accepts_uppercase_response_mode() {
        let ctx = test_dns_context_with_response_mode("HOSTNAME");

        init_dns_handler(&ctx).expect("uppercase DNS mode should initialize");
    }

    #[test]
    fn init_dns_handler_accepts_gethostname_response_mode_alias() {
        let ctx = test_dns_context_with_response_mode("gethostname");

        init_dns_handler(&ctx).expect("gethostname alias should initialize like hostname");
    }
}
