//! HTTP/HTTPS and SMTP response-builder helpers.

use nettrap_protocols::handlers::*;
use std::sync::Arc;

use crate::listener_context::ListenerContext;
use crate::listeners::tcp_framing::MAX_SMTP_DATA_SIZE;
use crate::listeners::tcp_handler::TcpSessionState;
use crate::nbi::enrich_nbi_with_iocs;
use crate::protocol_handlers::redact_smtp_command;
use crate::session::SessionDestination;
use crate::session::normalize_session_ip;
use crate::utils::{build_http_response_with_fakefile, dump_http_post, log_event};
use nettrap_fsutil::create_regular_file;

pub(crate) async fn handle_http_plain(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
    webroot_server: Option<&crate::webroot::WebrootServer>,
) -> Vec<u8> {
    handle_http_response(
        ctx,
        data,
        peer,
        destination,
        output_path,
        webroot_server,
        false,
    )
    .await
}

pub(crate) async fn handle_https(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
    webroot_server: Option<&crate::webroot::WebrootServer>,
) -> Vec<u8> {
    handle_http_response(
        ctx,
        data,
        peer,
        destination,
        output_path,
        webroot_server,
        true,
    )
    .await
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedHttpForResponse {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) path: String,
    pub(crate) host: String,
    pub(crate) user_agent: String,
    pub(crate) body: Vec<u8>,
    pub(crate) has_body: bool,
}

pub(crate) fn parse_http_for_response(data: &[u8]) -> crate::Result<Option<ParsedHttpForResponse>> {
    let Some(request) = nettrap_proto_http::HttpRequestParsed::parse(data)? else {
        return Ok(None);
    };
    let host = request.host().cloned().unwrap_or_default();
    let user_agent = request
        .user_agent
        .as_deref()
        .unwrap_or_default()
        .to_string();
    let target = request.target;
    let path = request.path;
    let body = request.body.unwrap_or_default();

    Ok(Some(ParsedHttpForResponse {
        method: request.method,
        target,
        path,
        host,
        user_agent,
        body,
        has_body: request.has_body,
    }))
}

fn build_bad_http_request_response() -> Vec<u8> {
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
}

async fn handle_http_response(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
    webroot_server: Option<&crate::webroot::WebrootServer>,
    over_tls: bool,
) -> Vec<u8> {
    let event_name = if over_tls {
        "https_request"
    } else {
        "http_request"
    };
    let transport_label = if over_tls { "HTTPS" } else { "HTTP" };

    log_event(output_path, ctx.name(), peer, event_name, "").await;

    let parsed = match parse_http_for_response(data) {
        Ok(Some(parsed)) => parsed,
        Ok(None) => {
            tracing::warn!(
                "{} malformed request from {} ({} bytes)",
                transport_label,
                peer,
                data.len()
            );
            return build_bad_http_request_response();
        }
        Err(err) => {
            tracing::warn!(
                "{} parse error from {} ({} bytes): {}",
                transport_label,
                peer,
                data.len(),
                err
            );
            return build_bad_http_request_response();
        }
    };

    let mut nbi = crate::nbi::http_nbi(crate::nbi::HttpNbiInput {
        listener: ctx.name(),
        src_ip: &canonical_peer_ip_string(peer),
        src_port: peer.port(),
        destination,
        method: &parsed.method,
        uri: &parsed.target,
        host: &parsed.host,
        user_agent: &parsed.user_agent,
        body_len: parsed.body.len(),
    });
    enrich_nbi_with_iocs(&mut nbi, &parsed.host, &parsed.target, &parsed.body);
    ctx.runtime.nbi_collector.record(&nbi).await;

    if ctx.dump_http_posts() && parsed.method.eq_ignore_ascii_case("POST") && parsed.has_body {
        let dump_prefix = ctx.dump_prefix().map(|s| s.to_string());
        dump_http_post(&parsed.body, &dump_prefix, peer).await;
    }

    // DynDNS checkip emulation
    if is_dyn_dns_checkip_request(&parsed.host, &parsed.path) {
        let src_ip = canonical_peer_ip_string(peer);
        let body = format!("Current IP Address: {}", src_ip);
        let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
        tracing::info!(
            "DynDNS checkip response for {} ({})",
            src_ip,
            transport_label
        );
        return maybe_suppress_http_body(
            &parsed.method,
            format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nDate: {}\r\nServer: DynDNS-CheckIP/1.0\r\n\r\n{}",
            body.len(), date, body
            )
            .into_bytes(),
        );
    }

    if parsed.path == "/wpad.dat" || parsed.path == "/proxy.pac" {
        let pac = "function FindProxyForURL(url, host) { return \"DIRECT\"; }";
        let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
        tracing::info!("WPAD/PAC response for {} ({})", peer, transport_label);
        return maybe_suppress_http_body(
            &parsed.method,
            format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nDate: {}\r\n\r\n{}",
            pac.len(), date, pac
            )
            .into_bytes(),
        );
    }

    if let Some(ref crc) = ctx.config.custom_response_config
        && let Some(resp) =
            crc.build_response_for_request(&parsed.host, &parsed.path, &parsed.target)
    {
        return maybe_suppress_http_body(&parsed.method, resp);
    }

    let response = if let Some(ws) = webroot_server {
        ws.build_http_response(&parsed.target)
    } else {
        build_http_response_with_fakefile(&parsed.target, ctx.server_version().unwrap_or("NetTrap"))
    };
    maybe_suppress_http_body(&parsed.method, response)
}

fn canonical_peer_ip_string(peer: &std::net::SocketAddr) -> String {
    normalize_session_ip(peer.ip()).to_string()
}

fn maybe_suppress_http_body(method: &str, mut response: Vec<u8>) -> Vec<u8> {
    if !method.eq_ignore_ascii_case("HEAD") {
        return response;
    }

    if let Some(body_start) = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)
    {
        response.truncate(body_start);
    }

    response
}

/// Handle SMTP data mode.
pub async fn handle_smtp_data(
    data: &[u8],
    smtp_handler: &nettrap_proto_smtp::SmtpHandler,
    session: &mut TcpSessionState,
    output_path: Option<&std::path::Path>,
    listener_name: &str,
    peer: &std::net::SocketAddr,
    smtp_dir: Option<&std::path::Path>,
) -> crate::Result<Vec<u8>> {
    let TcpSessionState {
        smtp_data_mode,
        smtp_data_buf,
        smtp_auth_state,
        ..
    } = session;
    if *smtp_data_mode {
        if smtp_data_buf
            .len()
            .checked_add(data.len())
            .is_none_or(|len| len > MAX_SMTP_DATA_SIZE)
        {
            tracing::warn!(
                "SMTP DATA buffer exceeded limit from {} ({} bytes), discarding",
                peer,
                smtp_data_buf.len().saturating_add(data.len())
            );
            *smtp_data_mode = false;
            smtp_data_buf.clear();
            return Ok(b"552 Message too large\r\n".to_vec());
        }
        smtp_data_buf.extend_from_slice(data);
        if let Some(message_bytes) = smtp_message_bytes_from_data_frame(smtp_data_buf) {
            let body_size = message_bytes.len();
            tracing::debug!("SMTP DATA complete from {}: {} bytes", peer, body_size);
            log_event(
                output_path,
                listener_name,
                peer,
                "smtp_data",
                &format!("{} bytes", body_size),
            )
            .await;

            let mbox_dir = smtp_dir
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("/var/log/nettrap/smtp"));
            let queued_id = uuid::Uuid::new_v4();
            let filename = smtp_email_path(&mbox_dir, queued_id);
            let mut file = match create_regular_file(&filename) {
                Ok(file) => file,
                Err(e) => {
                    tracing::error!("Failed to write SMTP email to {:?}: {}", filename, e);
                    *smtp_data_mode = false;
                    smtp_data_buf.clear();
                    return Err(crate::Error::Other(format!(
                        "Failed to write SMTP email to {:?}: {}",
                        filename, e
                    )));
                }
            };
            use std::io::Write;
            if let Err(e) = file.write_all(&message_bytes) {
                tracing::error!("Failed to write SMTP email to {:?}: {}", filename, e);
                *smtp_data_mode = false;
                smtp_data_buf.clear();
                return Err(crate::Error::Other(format!(
                    "Failed to write SMTP email to {:?}: {}",
                    filename, e
                )));
            }
            tracing::info!("SMTP email saved to {}", filename.display());

            *smtp_data_mode = false;
            smtp_data_buf.clear();
            Ok(format!("250 OK Queued as {}\r\n", queued_id).into_bytes())
        } else {
            Ok(Vec::new())
        }
    } else {
        let command = std::str::from_utf8(data).map_err(|e| {
            crate::Error::Other(format!("SMTP command contains invalid UTF-8: {}", e))
        })?;
        let logged_command = redact_smtp_command(command);
        tracing::debug!("SMTP command from {}: {}", peer, logged_command);
        log_event(
            output_path,
            listener_name,
            peer,
            "smtp_command",
            &logged_command,
        )
        .await;

        // Use stateful SMTP handler for proper AUTH support
        let (resp, new_state) = smtp_handler.handle_with_state(command, smtp_auth_state.clone());
        *smtp_auth_state = new_state;

        if resp.code == 354 {
            *smtp_data_mode = true;
            smtp_data_buf.clear();
        }
        Ok(resp.to_bytes())
    }
}

fn smtp_email_path(dir: &std::path::Path, id: uuid::Uuid) -> std::path::PathBuf {
    dir.join(format!("{id}.eml"))
}

fn smtp_message_bytes_from_data_frame(frame: &[u8]) -> Option<Vec<u8>> {
    let content = if frame == b".\r\n" {
        &frame[..0]
    } else {
        let offset = frame.windows(5).position(|window| window == b"\r\n.\r\n")?;
        let content_end = offset + 2;
        if content_end + 3 != frame.len() {
            return None;
        }
        &frame[..content_end]
    };

    let mut message = Vec::with_capacity(content.len());
    let mut line_start = true;
    let mut previous_was_cr = false;
    let mut index = 0usize;
    while index < content.len() {
        if line_start
            && content
                .get(index..)
                .is_some_and(|tail| tail.starts_with(b".."))
        {
            index += 1;
        }

        let byte = content[index];
        message.push(byte);
        line_start = previous_was_cr && byte == b'\n';
        previous_was_cr = byte == b'\r';
        index += 1;
    }

    Some(message)
}

/// Build minimal TLS ServerHello response (RFC 5246).
pub fn build_tls_response() -> Vec<u8> {
    let mut handshake = Vec::new();
    handshake.push(0x02); // HandshakeType: ServerHello
    // Handshake length placeholder (3 bytes) — filled below
    handshake.extend_from_slice(&[0, 0, 0]);
    handshake.extend_from_slice(&[0x03, 0x03]); // Server version: TLS 1.2
    handshake.extend_from_slice(&[0u8; 32]); // Random (32 bytes)
    handshake.push(0); // Session ID length: 0
    handshake.extend_from_slice(&[0x00, 0x2F]); // Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA
    handshake.push(0x00); // Compression method: null
    // Fill handshake length (bytes after the 4-byte header)
    let Ok(body_len) = u32::try_from(handshake.len() - 4) else {
        return Vec::new();
    };
    let body_len = body_len.to_be_bytes();
    handshake[1..4].copy_from_slice(&body_len[1..4]);
    // TLS record header
    let mut response = Vec::new();
    response.push(22); // ContentType: Handshake
    response.extend_from_slice(&[0x03, 0x03]); // Version: TLS 1.2
    let Ok(record_len) = u16::try_from(handshake.len()) else {
        return Vec::new();
    };
    response.extend_from_slice(&record_len.to_be_bytes());
    response.extend_from_slice(&handshake);
    response
}

pub(crate) fn is_dyn_dns_checkip_request(host: &str, path: &str) -> bool {
    crate::custom_response::host_matches_pattern(host, "checkip.dyndns.org")
        && matches!(path, "/" | "/checkip")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
    use crate::listeners::tcp_handler::TcpSessionState;
    use crate::process_filter::ProcessFilter;
    use crate::session::{PortForwardTable, SessionTracker};
    use nettrap_core::nbi::NetworkBehaviorIndicator;

    fn http_context() -> Arc<ListenerContext> {
        Arc::new(
            ListenerContext::builder()
                .name("http")
                .port(80)
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
                .expect("listener context should build"),
        )
    }

    fn empty_nbi_with_now(now: fn() -> chrono::DateTime<chrono::Utc>) -> NetworkBehaviorIndicator {
        let mut nbi =
            NetworkBehaviorIndicator::new("http", "tcp", "203.0.113.7", 51000, "10.0.0.1", 80);
        nbi.timestamp = now().to_rfc3339();
        nbi
    }

    fn empty_nbi() -> NetworkBehaviorIndicator {
        empty_nbi_with_now(crate::faketime::fake_now)
    }

    #[test]
    fn empty_nbi_uses_the_injected_clock_for_timestamp() {
        fn fixed_now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(1_704_157_200, 0).expect("valid instant")
        }

        let nbi = empty_nbi_with_now(fixed_now);

        assert_eq!(nbi.timestamp, fixed_now().to_rfc3339());
    }

    #[test]
    fn enrich_extracts_iocs_from_request_content() {
        let mut nbi = empty_nbi();
        let body = b"download from http://evil.example.com/payload.bin sha256 \
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
            beacon 45.77.12.34 contact operator@evil.example.com";
        enrich_nbi_with_iocs(&mut nbi, "malware.example.org", "/c2/checkin", body);

        let domains = nbi.indicators.get("ioc_domains").expect("domains");
        assert!(domains.contains("malware.example.org"));
        assert!(domains.contains("evil.example.com"));
        assert_eq!(
            nbi.indicators.get("ioc_urls").map(String::as_str),
            Some("http://evil.example.com/payload.bin")
        );
        assert_eq!(
            nbi.indicators.get("ioc_ips").map(String::as_str),
            Some("45.77.12.34")
        );
        assert_eq!(
            nbi.indicators.get("ioc_emails").map(String::as_str),
            Some("operator@evil.example.com")
        );
        assert_eq!(
            nbi.indicators.get("ioc_hashes").map(String::as_str),
            Some("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn enrich_omits_empty_and_internal_iocs() {
        let mut nbi = empty_nbi();
        enrich_nbi_with_iocs(&mut nbi, "", "/healthz", b"ping 192.168.1.10");

        assert!(!nbi.indicators.contains_key("ioc_domains"));
        assert!(!nbi.indicators.contains_key("ioc_urls"));
        assert!(!nbi.indicators.contains_key("ioc_hashes"));
        assert!(!nbi.indicators.contains_key("ioc_emails"));
        assert!(
            !nbi.indicators.contains_key("ioc_ips"),
            "internal IPs must not be recorded as IOCs"
        );
    }

    #[test]
    fn enrich_extracts_iocs_from_lossy_binary_body() {
        let mut nbi = empty_nbi();
        enrich_nbi_with_iocs(
            &mut nbi,
            "",
            "/download",
            b"\xffhttp://evil.example.com/payload.bin",
        );

        assert!(
            nbi.indicators
                .get("ioc_domains")
                .is_some_and(|value| value.contains("evil.example.com"))
        );
        assert_eq!(
            nbi.indicators.get("ioc_urls").map(String::as_str),
            Some("http://evil.example.com/payload.bin")
        );
        assert!(!nbi.indicators.contains_key("ioc_hashes"));
        assert!(!nbi.indicators.contains_key("ioc_emails"));
        assert!(!nbi.indicators.contains_key("ioc_ips"));
    }

    #[tokio::test]
    async fn http_webroot_rejects_raw_dotdot_target_before_path_normalization() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-http-webroot-dotdot-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(root.join("secret.exe"), b"secret").expect("write fixture");

        let ctx = http_context();
        let peer: std::net::SocketAddr = "127.0.0.1:51000".parse().expect("peer addr");
        let destination =
            SessionDestination::new("127.0.0.1".to_string(), 80).expect("destination");
        let webroot = crate::webroot::WebrootServer::new(&root).expect("valid webroot");
        let response = handle_http_plain(
            &ctx,
            b"GET /../../secret.exe HTTP/1.1\r\nHost: example.test\r\n\r\n",
            &peer,
            &destination,
            None,
            Some(&webroot),
        )
        .await;
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 404 Not Found"), "got: {text:?}");
        assert!(!text.contains("secret"), "got: {text:?}");
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[tokio::test]
    async fn smtp_data_returns_error_when_email_cannot_be_saved() {
        let root =
            std::env::temp_dir().join(format!("nettrap-smtp-data-error-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("create temp root");
        let smtp_dir = root.join("blocked");
        std::fs::write(&smtp_dir, b"not a directory").expect("create blocking file");

        let mut session = TcpSessionState {
            smtp_data_mode: true,
            ..Default::default()
        };

        let peer: std::net::SocketAddr = "127.0.0.1:2525".parse().expect("peer addr");
        let err = handle_smtp_data(
            b"Subject: test\r\n\r\nbody\r\n.\r\n",
            &nettrap_proto_smtp::SmtpHandler::new(),
            &mut session,
            None,
            "smtp",
            &peer,
            Some(&smtp_dir),
        )
        .await
        .expect_err("SMTP save failure should propagate");

        assert!(
            err.to_string().contains("Failed to write SMTP email"),
            "unexpected error: {err}"
        );
        assert!(!session.smtp_data_mode);
        assert!(session.smtp_data_buf.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn smtp_data_rejects_symlinked_mailbox_directory() {
        let root =
            std::env::temp_dir().join(format!("nettrap-smtp-data-symlink-{}", std::process::id()));
        let real_parent = root.join("real");
        let linked_parent = root.join("linked");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");

        let mut session = TcpSessionState {
            smtp_data_mode: true,
            ..Default::default()
        };

        let peer: std::net::SocketAddr = "127.0.0.1:2525".parse().expect("peer addr");
        let err = handle_smtp_data(
            b"Subject: test\r\n\r\nbody\r\n.\r\n",
            &nettrap_proto_smtp::SmtpHandler::new(),
            &mut session,
            None,
            "smtp",
            &peer,
            Some(&linked_parent),
        )
        .await
        .expect_err("SMTP save should reject symlinked mailbox dir");

        assert!(err.to_string().contains("Failed to write SMTP email"));
        assert!(!session.smtp_data_mode);
        assert!(session.smtp_data_buf.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn smtp_data_uses_matching_queue_id_for_saved_email() {
        let root =
            std::env::temp_dir().join(format!("nettrap-smtp-data-match-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("create temp root");

        let mut session = TcpSessionState {
            smtp_data_mode: true,
            ..Default::default()
        };

        let peer: std::net::SocketAddr = "127.0.0.1:2525".parse().expect("peer addr");
        let response = handle_smtp_data(
            b"Subject: test\r\n\r\nbody\r\n.\r\n",
            &nettrap_proto_smtp::SmtpHandler::new(),
            &mut session,
            None,
            "smtp",
            &peer,
            Some(&root),
        )
        .await
        .expect("SMTP save should succeed");

        let response_text = std::str::from_utf8(&response).expect("response is utf-8");
        let queued_id = response_text
            .strip_prefix("250 OK Queued as ")
            .and_then(|text| text.strip_suffix("\r\n"))
            .expect("queued response should include an id");
        let saved_path = std::fs::read_dir(&root)
            .expect("read mailbox dir")
            .next()
            .expect("saved email should exist")
            .expect("mailbox entry");
        let saved_name = saved_path.file_name();

        assert_eq!(saved_name.to_string_lossy(), format!("{queued_id}.eml"));
        let saved_bytes = std::fs::read(saved_path.path()).expect("saved email should be readable");
        assert_eq!(saved_bytes, b"Subject: test\r\n\r\nbody\r\n");
        assert!(!session.smtp_data_mode);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn smtp_message_bytes_remove_terminator_and_dot_stuffing() {
        assert_eq!(
            smtp_message_bytes_from_data_frame(b"..leading\r\nnormal\r\n.\r\n"),
            Some(b".leading\r\nnormal\r\n".to_vec())
        );
        assert_eq!(
            smtp_message_bytes_from_data_frame(b".\r\n"),
            Some(Vec::new())
        );
        assert_eq!(smtp_message_bytes_from_data_frame(b".\n"), None);
        assert_eq!(smtp_message_bytes_from_data_frame(b"\n.\n"), None);
        assert_eq!(smtp_message_bytes_from_data_frame(b".\r\njunk"), None);
        assert_eq!(smtp_message_bytes_from_data_frame(b"unterminated"), None);
    }

    #[test]
    fn smtp_message_bytes_only_unstuff_after_crlf_boundaries() {
        assert_eq!(
            smtp_message_bytes_from_data_frame(b"bare\n..not-stuffed\r\n.\r\n"),
            Some(b"bare\n..not-stuffed\r\n".to_vec())
        );
    }

    #[test]
    fn smtp_email_path_joins_directory_as_filesystem_path() {
        let dir = std::path::Path::new("mail/spool");
        let id = uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000")
            .expect("uuid literal must parse");

        let path = smtp_email_path(dir, id);

        assert_eq!(
            path,
            std::path::Path::new("mail/spool").join("123e4567-e89b-12d3-a456-426614174000.eml")
        );
    }

    #[tokio::test]
    async fn handle_smtp_data_rejects_invalid_utf8_commands() {
        let mut session = TcpSessionState::default();
        let peer: std::net::SocketAddr = "127.0.0.1:2525".parse().expect("peer addr");

        let err = handle_smtp_data(
            &[0xff, 0xfe, 0xfd],
            &nettrap_proto_smtp::SmtpHandler::new(),
            &mut session,
            None,
            "smtp",
            &peer,
            None,
        )
        .await
        .expect_err("invalid UTF-8 should fail");

        assert!(err.to_string().contains("invalid UTF-8"));
    }

    #[tokio::test]
    async fn handle_smtp_data_rejects_unicode_whitespace_padding() {
        let mut session = TcpSessionState::default();
        let peer: std::net::SocketAddr = "127.0.0.1:2525".parse().expect("peer addr");

        let response = handle_smtp_data(
            "HELO example.test\u{00a0}\r\n".as_bytes(),
            &nettrap_proto_smtp::SmtpHandler::new(),
            &mut session,
            None,
            "smtp",
            &peer,
            None,
        )
        .await
        .expect("unicode-padded command should parse");

        assert_eq!(response, b"500 Command not recognized\r\n");
    }

    #[tokio::test]
    async fn handle_smtp_data_rejects_bare_lf_terminated_commands() {
        let mut session = TcpSessionState::default();
        let peer: std::net::SocketAddr = "127.0.0.1:2525".parse().expect("peer addr");

        let response = handle_smtp_data(
            b"QUIT\n",
            &nettrap_proto_smtp::SmtpHandler::new(),
            &mut session,
            None,
            "smtp",
            &peer,
            None,
        )
        .await
        .expect("bare-LF command should parse as invalid SMTP");

        assert_eq!(response, b"500 Command not recognized\r\n");
    }

    #[tokio::test]
    async fn handle_smtp_data_rejects_buffer_growth_past_limit() {
        let mut session = TcpSessionState {
            smtp_data_mode: true,
            smtp_data_buf: vec![b'a'; MAX_SMTP_DATA_SIZE],
            ..TcpSessionState::default()
        };
        let peer: std::net::SocketAddr = "127.0.0.1:2525".parse().expect("peer addr");

        let response = handle_smtp_data(
            b"b",
            &nettrap_proto_smtp::SmtpHandler::new(),
            &mut session,
            None,
            "smtp",
            &peer,
            None,
        )
        .await
        .expect("oversized SMTP data should be handled");

        assert_eq!(response, b"552 Message too large\r\n");
        assert!(!session.smtp_data_mode);
        assert!(session.smtp_data_buf.is_empty());
    }

    #[test]
    fn maybe_suppress_http_body_removes_payload_for_head() {
        let response = maybe_suppress_http_body(
            "HEAD",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
        );

        assert_eq!(response, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
    }

    #[test]
    fn maybe_suppress_http_body_keeps_payload_for_get() {
        let response = maybe_suppress_http_body(
            "GET",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
        );

        assert_eq!(
            response,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        );
    }

    #[test]
    fn parse_http_for_response_captures_user_agent_header() {
        let parsed = parse_http_for_response(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: NetTrapTest/1.0\r\n\r\n",
        )
        .expect("request should parse")
        .expect("parsed request should be present");

        assert_eq!(parsed.user_agent, "NetTrapTest/1.0");
    }

    #[test]
    fn canonical_peer_ip_string_canonicalizes_ipv4_mapped_addresses() {
        let peer: std::net::SocketAddr = "[::ffff:198.51.100.7]:51000".parse().unwrap();

        assert_eq!(canonical_peer_ip_string(&peer), "198.51.100.7");
    }
}
