//! Protocol event-logging helpers (TCP, DNS-over-TCP, FTP, POP3, IRC, SMTP).

use crate::listener_context::ListenerContext;
use crate::session::SessionDestination;
use crate::utils::canonical_socket_ip_string;
use crate::utils::log_event;

const REDACTED_COMMAND_FIELD: &str = "***REDACTED***";

pub struct TcpEventDetails<'a> {
    pub event_type: &'a str,
    pub detail: &'a str,
    pub data_len: usize,
    pub protocol: &'a str,
}

pub async fn log_tcp_event(
    ctx: &ListenerContext,
    output_path: Option<&std::path::Path>,
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    details: TcpEventDetails<'_>,
) {
    log_event(
        output_path,
        ctx.name(),
        peer,
        details.event_type,
        details.detail,
    )
    .await;
    let mut nbi = crate::nbi::raw_nbi(
        ctx.name(),
        &canonical_socket_ip_string(peer),
        peer.port(),
        destination,
        details.data_len,
        "",
    );
    nbi.add("detected_protocol", details.protocol);
    ctx.record_nbi(&nbi).await;
}

pub async fn log_dns_tcp_event(
    ctx: &ListenerContext,
    output_path: Option<&std::path::Path>,
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    data_len: usize,
) {
    log_event(
        output_path,
        ctx.name(),
        peer,
        "dns_tcp_query",
        &format!("{} bytes", data_len),
    )
    .await;
    let nbi = crate::nbi::dns_nbi(
        ctx.name(),
        &canonical_socket_ip_string(peer),
        peer.port(),
        destination,
        "",
        "tcp_query",
    );
    ctx.record_nbi(&nbi).await;
}

pub async fn log_ftp_event(
    ctx: &ListenerContext,
    output_path: Option<&std::path::Path>,
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    command: &str,
) {
    let command = redact_ftp_command(command);
    log_event(output_path, ctx.name(), peer, "ftp_command", &command).await;
    let nbi = crate::nbi::ftp_nbi(
        ctx.name(),
        &canonical_socket_ip_string(peer),
        peer.port(),
        destination,
        &command,
        "",
    );
    ctx.record_nbi(&nbi).await;
}

pub async fn log_pop3_event(
    ctx: &ListenerContext,
    output_path: Option<&std::path::Path>,
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    command: &str,
) {
    let command = redact_pop3_command(command);
    log_event(output_path, ctx.name(), peer, "pop3_command", &command).await;
    let nbi = crate::nbi::pop3_nbi(
        ctx.name(),
        &canonical_socket_ip_string(peer),
        peer.port(),
        destination,
        &command,
        "",
    );
    ctx.record_nbi(&nbi).await;
}

pub async fn log_irc_event(
    ctx: &ListenerContext,
    output_path: Option<&std::path::Path>,
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    nick: &str,
    command: &str,
) {
    let command = redact_irc_command(command);
    log_event(output_path, ctx.name(), peer, "irc_command", &command).await;
    let nbi = crate::nbi::irc_nbi(
        ctx.name(),
        &canonical_socket_ip_string(peer),
        peer.port(),
        destination,
        nick,
        &command,
        "",
    );
    ctx.record_nbi(&nbi).await;
}

pub async fn log_smtp_event(
    ctx: &ListenerContext,
    output_path: Option<&std::path::Path>,
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    command: &str,
) {
    let command = redact_smtp_command(command);
    log_event(output_path, ctx.name(), peer, "smtp_command", &command).await;
    let nbi = crate::nbi::smtp_nbi(
        ctx.name(),
        &canonical_socket_ip_string(peer),
        peer.port(),
        destination,
        &command,
        "",
    );
    ctx.record_nbi(&nbi).await;
}

pub(crate) fn redact_ftp_command(command: &str) -> String {
    let verb = command_verb(command);
    if verb.eq_ignore_ascii_case("PASS") || verb.eq_ignore_ascii_case("ACCT") {
        return format!("{} {}", verb.to_ascii_uppercase(), REDACTED_COMMAND_FIELD);
    }
    nettrap_core::sanitize::single_line(command)
}

pub(crate) fn redact_pop3_command(command: &str) -> String {
    let verb = command_verb(command);
    if verb.eq_ignore_ascii_case("PASS")
        || verb.eq_ignore_ascii_case("APOP")
        || verb.eq_ignore_ascii_case("AUTH")
    {
        return format!("{} {}", verb.to_ascii_uppercase(), REDACTED_COMMAND_FIELD);
    }
    if looks_like_base64_auth_continuation(command) {
        return REDACTED_COMMAND_FIELD.to_string();
    }
    nettrap_core::sanitize::single_line(command)
}

pub(crate) fn redact_irc_command(command: &str) -> String {
    let verb = command_verb(command);
    if verb.eq_ignore_ascii_case("PASS")
        || verb.eq_ignore_ascii_case("OPER")
        || verb.eq_ignore_ascii_case("AUTHENTICATE")
    {
        return format!("{} {}", verb.to_ascii_uppercase(), REDACTED_COMMAND_FIELD);
    }
    nettrap_core::sanitize::single_line(command)
}

pub(crate) fn redact_smtp_command(command: &str) -> String {
    let verb = command_verb(command);
    if verb.eq_ignore_ascii_case("AUTH") {
        return format!("AUTH {}", REDACTED_COMMAND_FIELD);
    }
    if !is_known_smtp_command(verb) && looks_like_base64_auth_continuation(command) {
        return REDACTED_COMMAND_FIELD.to_string();
    }
    nettrap_core::sanitize::single_line(command)
}

fn command_verb(command: &str) -> &str {
    command
        .trim_start()
        .split(|ch: char| ch.is_ascii_whitespace())
        .next()
        .unwrap_or("")
}

fn is_known_smtp_command(verb: &str) -> bool {
    matches!(
        verb.to_ascii_uppercase().as_str(),
        "EHLO"
            | "HELO"
            | "MAIL"
            | "RCPT"
            | "DATA"
            | "RSET"
            | "NOOP"
            | "VRFY"
            | "QUIT"
            | "HELP"
            | "STARTTLS"
            | "AUTH"
            | "X-EXPS"
            | "X-EXCH50"
            | "X-LINK2STATE"
    )
}

fn looks_like_base64_auth_continuation(command: &str) -> bool {
    let trimmed = command.trim();
    trimmed.len() >= 4
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener_context::ListenerContext;
    use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
    use crate::process_filter::ProcessFilter;
    use crate::session::{PortForwardTable, SessionTracker};
    use std::sync::Arc;

    #[tokio::test]
    async fn log_tcp_event_records_protocol_without_fake_hexdump() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-log-tcp-event-nbi-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create temp root");
        let nbi_path = root.join("events.jsonl");
        let collector =
            Arc::new(crate::nbi::NbiCollector::new(Some(nbi_path.clone())).expect("collector"));
        let ctx = ListenerContext::builder()
            .name("ssh")
            .port(22)
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
        let peer: std::net::SocketAddr = "127.0.0.1:53022".parse().expect("peer");
        let destination = SessionDestination::new_unchecked("10.0.0.5", 22);

        log_tcp_event(
            &ctx,
            None,
            &peer,
            &destination,
            TcpEventDetails {
                event_type: "ssh_data",
                detail: "4 bytes",
                data_len: 4,
                protocol: "ssh",
            },
        )
        .await;
        collector.flush_all_pending().await;
        collector.stop_background_tasks();

        let events = crate::output::load_nbis_from_jsonl(&nbi_path).expect("load NBI JSONL");
        let event = events.first().expect("event should be recorded");
        assert_eq!(event.protocol, "RAW");
        assert_eq!(
            event.indicators.get("data_length").map(String::as_str),
            Some("4")
        );
        assert_eq!(event.indicators.get("hexdump"), None);
        assert_eq!(
            event
                .indicators
                .get("detected_protocol")
                .map(String::as_str),
            Some("ssh")
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn redact_ftp_command_hides_password_and_account() {
        assert_eq!(
            redact_ftp_command("PASS hunter2\r\n"),
            "PASS ***REDACTED***"
        );
        assert_eq!(redact_ftp_command("acct billing"), "ACCT ***REDACTED***");
        assert_eq!(redact_ftp_command("USER analyst\r\n"), "USER analyst  ");
    }

    #[test]
    fn redact_pop3_command_hides_password_digest_and_auth() {
        assert_eq!(redact_pop3_command("PASS hunter2"), "PASS ***REDACTED***");
        assert_eq!(
            redact_pop3_command("APOP alice deadbeef"),
            "APOP ***REDACTED***"
        );
        assert_eq!(
            redact_pop3_command("AUTH PLAIN AHVzZXIAcGFzcw=="),
            "AUTH ***REDACTED***"
        );
        assert_eq!(redact_pop3_command("dXNlcg=="), "***REDACTED***");
        assert_eq!(redact_pop3_command("cGFzcw==\r\n"), "***REDACTED***");
    }

    #[test]
    fn redact_irc_command_hides_auth_fields() {
        assert_eq!(redact_irc_command("PASS hunter2"), "PASS ***REDACTED***");
        assert_eq!(
            redact_irc_command("oper root hunter2\r\n"),
            "OPER ***REDACTED***"
        );
        assert_eq!(
            redact_irc_command("AUTHENTICATE AHVzZXIAcGFzcw=="),
            "AUTHENTICATE ***REDACTED***"
        );
        assert_eq!(redact_irc_command("NICK analyst\r\n"), "NICK analyst  ");
    }

    #[test]
    fn redact_smtp_command_hides_auth_and_continuations() {
        assert_eq!(
            redact_smtp_command("AUTH PLAIN AHVzZXIAcGFzcw=="),
            "AUTH ***REDACTED***"
        );
        assert_eq!(redact_smtp_command("cGFzc3dvcmQ="), "***REDACTED***");
        assert_eq!(
            redact_smtp_command("MAIL FROM:<a@example.test>"),
            "MAIL FROM:<a@example.test>"
        );
    }
}
