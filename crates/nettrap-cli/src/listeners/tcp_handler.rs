//! TCP connection handler functions.
//!
//! Contains the main TCP connection handling logic for protocols.

use nettrap_proto_irc::IrcHandlerTrait;
use nettrap_proto_pop3::Pop3HandlerTrait;
use nettrap_protocols::handlers::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::listener_context::ListenerContext;
use crate::session::SessionDestination;
use crate::utils::{
    build_http_response_with_fakefile, dump_http_post, extract_http_host, extract_http_method,
    extract_http_path, log_event,
};

/// Handle a TCP connection after accept.
#[allow(clippy::too_many_arguments)]
pub async fn handle_tcp_connection(
    ctx: Arc<ListenerContext>,
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    destination: SessionDestination,
    output_path: Option<&std::path::Path>,
) -> crate::Result<()> {
    // Rate-limited connection logging - deduplicate connect events
    let dedup_key = format!("{}:{}", ctx.name(), peer.ip());
    if ctx.connection_dedup.should_log(&dedup_key) {
        log_event(output_path, ctx.name(), &peer, "connect", "").await;
    }
    ctx.fire_execute_cmd_for_session(&peer, "TCP", &destination);

    // Use protocol_handlers for handler initialization
    let smtp_handler = crate::protocol_handlers::init_smtp_handler(&ctx);
    let ftp_handler = crate::protocol_handlers::init_ftp_handler(&ctx);
    let pop3_handler = crate::protocol_handlers::init_pop3_handler(&ctx);
    let irc_handler = crate::protocol_handlers::init_irc_handler(&ctx);

    let webroot_server = ctx.webroot().map(|w| crate::webroot::WebrootServer::new(w));

    let mut smtp_data_mode = false;
    let mut smtp_data_buf: Vec<u8> = Vec::new();
    let mut smtp_auth_state = nettrap_proto_smtp::SmtpAuthState::None;
    let mut irc_nick = "unknown".to_string();
    let mut ssh_first_packet = true;

    // Apply banner delay BEFORE sending banner to frustrate scanners
    let name = ctx.name();
    if ctx.banner_delay_ms() > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(ctx.banner_delay_ms())).await;
    }

    // Protocol-specific banners (only for non-TLS connections)
    // For TLS connections, banners are sent inside handle_wrapped_connection after the handshake
    if !ctx.use_ssl() {
        if let Some(banner_bytes) =
            crate::protocol_handlers::get_protocol_banner(name, ctx.banner())
        {
            stream.write_all(&banner_bytes).await?;
            stream.flush().await?;
        } else if name == "ftp" || name.starts_with("ftp") {
            stream.write_all(ftp_handler.get_banner()).await?;
            stream.flush().await?;
        }
    }

    // TLS wrapping
    if ctx.use_ssl() {
        if let Some(ref ca) = ctx.runtime.ca {
            let wrapper = nettrap_tls_mitm::TlsWrapper::new(Arc::clone(ca));
            let mut peek_buf = vec![0u8; 512];
            match stream.peek(&mut peek_buf).await {
                Ok(n)
                    if n >= 3
                        && peek_buf[0] == 0x16
                        && peek_buf[1] == 0x03
                        && peek_buf[2] <= 0x04 =>
                {
                    if let Some((ja3_str, ja3_hash)) =
                        nettrap_proto_tls::ja3::ja3_from_handshake(&peek_buf[..n])
                    {
                        tracing::info!("JA3: {} ({})", ja3_hash, ja3_str);
                        let mut nbi = crate::nbi::tls_nbi(
                            ctx.name(),
                            &peer.ip().to_string(),
                            peer.port(),
                            &destination,
                            "",
                        );
                        nbi.add("ja3", ja3_str);
                        nbi.add("ja3_hash", ja3_hash);
                        if let Some(ja4) =
                            nettrap_proto_tls::ja3::ja4_from_handshake(&peek_buf[..n])
                        {
                            tracing::info!("JA4: {}", ja4);
                            nbi.add("ja4", ja4);
                        }
                        ctx.runtime.nbi_collector.record(&nbi).await;
                    }
                    match wrapper.maybe_wrap(stream, &peek_buf[..n]).await {
                        Ok((wrapped, sni)) => {
                            if let Some(ref sni_name) = sni {
                                tracing::debug!("TLS SNI: {} from {}", sni_name, peer);
                                log_event(output_path, ctx.name(), &peer, "tls_sni", sni_name)
                                    .await;
                                let nbi = crate::nbi::tls_nbi(
                                    ctx.name(),
                                    &peer.ip().to_string(),
                                    peer.port(),
                                    &destination,
                                    sni_name,
                                );
                                ctx.runtime.nbi_collector.record(&nbi).await;
                            }
                            return handle_wrapped_connection(
                                ctx,
                                wrapped,
                                peer,
                                destination.clone(),
                                output_path,
                                &smtp_handler,
                                &ftp_handler,
                                &pop3_handler,
                                &irc_handler,
                                webroot_server.as_ref(),
                            )
                            .await;
                        }
                        Err(e) => {
                            tracing::debug!("TLS wrap failed for {}: {}", peer, e);
                            return Ok(());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let mut buf = vec![0u8; 4096];

    loop {
        match stream.read(&mut buf).await {
            Ok(0) => {
                tracing::debug!("TCP connection closed by {}", peer);
                return Ok(());
            }
            Ok(len) => {
                tracing::debug!("TCP '{}' received {} bytes from {}", ctx.name(), len, peer);
                let data = &buf[..len];

                if ctx.config.log_hexdump {
                    tracing::debug!("Hexdump:\n{}", crate::hexdump::hexdump(data, 256));
                }

                ctx.write_pcap_event_for_destination(data, &peer, &destination);

                let first_bytes = &data[..len.min(20)];

                let response = handle_tcp_protocol(
                    &ctx,
                    name,
                    data,
                    first_bytes,
                    &peer,
                    output_path,
                    &smtp_handler,
                    &ftp_handler,
                    &pop3_handler,
                    &irc_handler,
                    &webroot_server,
                    &destination,
                    &mut smtp_data_mode,
                    &mut smtp_data_buf,
                    &mut smtp_auth_state,
                    &mut irc_nick,
                    &mut ssh_first_packet,
                )
                .await;

                let mut sent_bytes = 0u64;
                if !response.is_empty() {
                    ctx.write_pcap_response_for_destination(&response, &peer, &destination);
                    ctx.apply_response_delay().await;
                    let send_result = async {
                        stream.write_all(&response).await?;
                        stream.flush().await
                    }
                    .await;
                    if send_result.is_ok() {
                        sent_bytes = response.len() as u64;
                    }
                    ctx.update_session_bytes(&peer, "TCP", &destination, len as u64, sent_bytes);
                    send_result?;
                } else {
                    ctx.update_session_bytes(&peer, "TCP", &destination, len as u64, 0);
                }
            }
            Err(e) => {
                tracing::debug!("TCP read error from {}: {}", peer, e);
                return Ok(());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_protocol(
    ctx: &Arc<ListenerContext>,
    name: &str,
    data: &[u8],
    first_bytes: &[u8],
    peer: &std::net::SocketAddr,
    output_path: Option<&std::path::Path>,
    smtp_handler: &nettrap_proto_smtp::SmtpHandler,
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    pop3_handler: &nettrap_proto_pop3::Pop3Handler,
    irc_handler: &nettrap_proto_irc::IrcHandler,
    webroot_server: &Option<crate::webroot::WebrootServer>,
    destination: &SessionDestination,
    smtp_data_mode: &mut bool,
    smtp_data_buf: &mut Vec<u8>,
    smtp_auth_state: &mut nettrap_proto_smtp::SmtpAuthState,
    irc_nick: &mut String,
    ssh_first_packet: &mut bool,
) -> Vec<u8> {
    if let Some(response) = dispatch_named_tcp_protocol(
        ctx,
        name,
        data,
        peer,
        output_path,
        smtp_handler,
        ftp_handler,
        pop3_handler,
        irc_handler,
        destination,
        smtp_data_mode,
        smtp_data_buf,
        smtp_auth_state,
        irc_nick,
        ssh_first_packet,
    )
    .await
    {
        response
    } else {
        // Auto-detect protocol via taste router
        handle_detected_protocol(
            ctx,
            data,
            first_bytes,
            peer,
            output_path,
            smtp_handler,
            ftp_handler,
            pop3_handler,
            irc_handler,
            webroot_server,
            destination,
            smtp_data_mode,
            smtp_data_buf,
            smtp_auth_state,
            irc_nick,
            ssh_first_packet,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_named_tcp_protocol(
    ctx: &Arc<ListenerContext>,
    name: &str,
    data: &[u8],
    peer: &std::net::SocketAddr,
    output_path: Option<&std::path::Path>,
    smtp_handler: &nettrap_proto_smtp::SmtpHandler,
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    pop3_handler: &nettrap_proto_pop3::Pop3Handler,
    irc_handler: &nettrap_proto_irc::IrcHandler,
    destination: &SessionDestination,
    smtp_data_mode: &mut bool,
    smtp_data_buf: &mut Vec<u8>,
    smtp_auth_state: &mut nettrap_proto_smtp::SmtpAuthState,
    irc_nick: &mut String,
    ssh_first_packet: &mut bool,
) -> Option<Vec<u8>> {
    if name == "dns" || name.starts_with("dns") {
        Some(handle_dns_tcp(ctx, data, peer, destination, output_path).await)
    } else if name == "smtp" || name.starts_with("smtp") {
        let cmd_str = std::str::from_utf8(data).unwrap_or("").trim();
        crate::protocol_handlers::log_smtp_event(ctx, output_path, peer, destination, cmd_str)
            .await;
        Some(
            handle_smtp_data(
                data,
                smtp_handler,
                smtp_data_mode,
                smtp_data_buf,
                smtp_auth_state,
                output_path,
                ctx.name(),
                peer,
                ctx.config.smtp_dir.as_deref(),
            )
            .await,
        )
    } else if name == "ftp" || name.starts_with("ftp") {
        let command = std::str::from_utf8(data).unwrap_or("").trim();
        tracing::debug!("FTP command from {}: {}", peer, command);
        crate::protocol_handlers::log_ftp_event(ctx, output_path, peer, destination, command).await;
        Some(ftp_handler.handle(command).to_bytes())
    } else if name == "pop3" || name.starts_with("pop3") {
        let command = std::str::from_utf8(data).unwrap_or("").trim();
        tracing::debug!("POP3 command from {}: {}", peer, command);
        crate::protocol_handlers::log_pop3_event(ctx, output_path, peer, destination, command)
            .await;
        Some(match pop3_handler.handle(command).await {
            Ok(resp) => resp.to_bytes(),
            Err(_) => b"-ERR Server error\r\n".to_vec(),
        })
    } else if name == "irc" || name.starts_with("irc") {
        Some(
            handle_irc(
                ctx,
                data,
                peer,
                destination,
                output_path,
                irc_handler,
                irc_nick,
            )
            .await,
        )
    } else if name == "telnet" || name.starts_with("telnet") {
        let handler = nettrap_proto_telnet::TelnetHandler::new();
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "telnet_command",
            std::str::from_utf8(data).unwrap_or(""),
            "telnet",
        )
        .await;
        Some(
            handler
                .handle_command(std::str::from_utf8(data).unwrap_or(""))
                .to_vec(),
        )
    } else if name == "ssh" || name.starts_with("ssh") {
        Some(handle_ssh(ctx, data, peer, destination, output_path, ssh_first_packet).await)
    } else if name == "smb" || name.starts_with("smb") {
        let handler = nettrap_proto_smb::SmbHandler::new();
        let nbi = crate::nbi::raw_nbi(
            ctx.name(),
            &peer.ip().to_string(),
            peer.port(),
            destination,
            data.len(),
            "smb",
        );
        ctx.runtime.nbi_collector.record(&nbi).await;
        Some(handler.handle(data))
    } else if name == "rdp" || name.starts_with("rdp") {
        let handler = nettrap_proto_rdp::RdpHandler::new();
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "rdp_request",
            &format!("{} bytes", data.len()),
            "rdp",
        )
        .await;
        Some(handler.handle(data))
    } else if name == "redis" || name.starts_with("redis") {
        let handler = nettrap_proto_redis::RedisHandler::new();
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "redis_request",
            &format!("{} bytes", data.len()),
            "redis",
        )
        .await;
        Some(handler.handle_command(data))
    } else if name == "mysql" || name.starts_with("mysql") {
        let handler = nettrap_proto_mysql::MysqlHandler::new();
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "mysql_request",
            &format!("{} bytes", data.len()),
            "mysql",
        )
        .await;
        Some(handler.handle(data))
    } else if name == "ldap" || name.starts_with("ldap") {
        let handler = nettrap_proto_ldap::LdapHandler::new();
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "ldap_request",
            &format!("{} bytes", data.len()),
            "ldap",
        )
        .await;
        Some(handler.handle(data))
    } else if name == "socks" || name.starts_with("socks") {
        let handler = nettrap_proto_socks::SocksHandler::new();
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "socks_request",
            &format!("{} bytes", data.len()),
            "socks",
        )
        .await;
        Some(handler.handle(data))
    } else if name == "memcached" || name.starts_with("memcached") {
        let handler = nettrap_proto_memcached::MemcachedHandler::new();
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "memcached_request",
            &format!("{} bytes", data.len()),
            "memcached",
        )
        .await;
        Some(handler.handle(data))
    } else if name == "nkn" || name.starts_with("nkn") {
        let handler = nettrap_proto_nkn::NknHandler::new();
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "nkn_request",
            &format!("{} bytes", data.len()),
            "nkn",
        )
        .await;
        Some(handler.handle(data))
    } else if name == "postgres" || name.starts_with("postgres") {
        let handler = nettrap_proto_postgres::PostgresHandler::new();
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "postgres_request",
            &format!("{} bytes", data.len()),
            "postgres",
        )
        .await;
        Some(handler.handle(data))
    } else if name == "raw" || name.starts_with("raw") || name == "echo" || name.starts_with("echo")
    {
        let raw_handler = if let Some(ref custom) = ctx.custom_response() {
            nettrap_proto_raw::RawHandler::from_custom_response(custom)
        } else {
            nettrap_proto_raw::RawHandler::new()
        };
        let raw_resp = raw_handler.handle(data);
        log_event(
            output_path,
            ctx.name(),
            peer,
            "raw",
            &format!("{} bytes", data.len()),
        )
        .await;
        let nbi = crate::nbi::raw_nbi(
            ctx.name(),
            &peer.ip().to_string(),
            peer.port(),
            destination,
            data.len(),
            "",
        );
        ctx.runtime.nbi_collector.record(&nbi).await;
        Some(raw_resp.to_bytes())
    } else {
        None
    }
}

async fn handle_dns_tcp(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
) -> Vec<u8> {
    use nettrap_proto_dns::handler::DnsHandlerTrait;

    let mut tcp_dns_handler = nettrap_proto_dns::handler::DnsHandler::new();
    if let Some("auto") = ctx.dns_response_mode() {
        tcp_dns_handler = tcp_dns_handler.with_auto_response_ip();
    }
    if let Some(ip) = ctx.dns_response_ip() {
        tcp_dns_handler = tcp_dns_handler.with_default_response_ip(ip);
    }
    if let Some(ref mx) = ctx.config.dns_response_mx {
        tcp_dns_handler = tcp_dns_handler.with_default_response_mx(mx);
    }
    if let Some(ref txt) = ctx.config.dns_response_txt {
        tcp_dns_handler = tcp_dns_handler.with_default_response_txt(txt);
    }
    if let Some(n) = ctx.config.dns_nxdomains {
        tcp_dns_handler = tcp_dns_handler.with_nxdomains(n);
    }

    if data.len() > 2 {
        let dns_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let available = data.len() - 2;
        let dns_data = if dns_len >= 12 && dns_len <= available {
            &data[2..2 + dns_len]
        } else if available >= 12 {
            // Fallback: use available data only if it looks like a valid DNS packet
            tracing::debug!(
                "DNS TCP: declared len {} but only {} bytes available",
                dns_len,
                available
            );
            &data[2..]
        } else {
            return Vec::new();
        };
        match tcp_dns_handler.handle_query(dns_data, *peer).await {
            Ok(response) => {
                let len_bytes = (response.len() as u16).to_be_bytes();
                let mut tcp_response = Vec::with_capacity(2 + response.len());
                tcp_response.extend_from_slice(&len_bytes);
                tcp_response.extend_from_slice(&response);
                log_event(
                    output_path,
                    ctx.name(),
                    peer,
                    "dns_tcp_query",
                    &format!("{} bytes", data.len()),
                )
                .await;
                let nbi = crate::nbi::dns_nbi(
                    ctx.name(),
                    &peer.ip().to_string(),
                    peer.port(),
                    destination,
                    "",
                    "tcp_query",
                );
                ctx.runtime.nbi_collector.record(&nbi).await;
                tcp_response
            }
            Err(e) => {
                tracing::warn!("DNS TCP error: {}", e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    }
}

async fn handle_irc(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
    irc_handler: &nettrap_proto_irc::IrcHandler,
    irc_nick: &mut String,
) -> Vec<u8> {
    let command = std::str::from_utf8(data).unwrap_or("").trim();
    let upper_cmd = command.to_uppercase();
    if upper_cmd.starts_with("NICK ") {
        let raw_nick = command.get(5..).unwrap_or("").trim();
        *irc_nick = raw_nick
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .take(30)
            .collect();
        if irc_nick.is_empty() {
            *irc_nick = "unknown".to_string();
        }
    }
    tracing::debug!("IRC command from {} ({}): {}", peer, irc_nick, command);
    crate::protocol_handlers::log_irc_event(ctx, output_path, peer, destination, irc_nick, command)
        .await;
    match irc_handler.handle(command, irc_nick).await {
        Ok(resp) => resp.to_bytes(),
        Err(_) => Vec::new(),
    }
}

async fn handle_ssh(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
    first_packet: &mut bool,
) -> Vec<u8> {
    let handler = nettrap_proto_ssh::SshHandler::new();

    if *first_packet {
        *first_packet = false;
        // Parse and log client version string
        if let Some(client_version) = nettrap_proto_ssh::SshHandler::parse_client_version(data) {
            let is_brute = nettrap_proto_ssh::SshHandler::is_brute_force_client(&client_version);
            tracing::warn!(
                "SSH client version from {}: {} (brute_force_indicator={})",
                peer, client_version, is_brute
            );
            crate::protocol_handlers::log_tcp_event(
                ctx, output_path, peer, destination,
                "ssh_version", &client_version, "ssh",
            ).await;
        } else {
            crate::protocol_handlers::log_tcp_event(
                ctx, output_path, peer, destination,
                "ssh_handshake", &format!("{} bytes", data.len()), "ssh",
            ).await;
        }
        // Respond with server banner + KEXINIT (no disconnect yet)
        let mut resp = handler.get_banner();
        resp.extend_from_slice(&handler.build_kexinit());
        resp
    } else {
        // Subsequent packets: log and send auth failure (disconnect)
        crate::protocol_handlers::log_tcp_event(
            ctx, output_path, peer, destination,
            "ssh_data", &format!("{} bytes", data.len()), "ssh",
        ).await;
        handler.build_auth_failure()
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_detected_protocol(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    _first_bytes: &[u8],
    peer: &std::net::SocketAddr,
    output_path: Option<&std::path::Path>,
    smtp_handler: &nettrap_proto_smtp::SmtpHandler,
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    pop3_handler: &nettrap_proto_pop3::Pop3Handler,
    irc_handler: &nettrap_proto_irc::IrcHandler,
    _webroot_server: &Option<crate::webroot::WebrootServer>,
    destination: &SessionDestination,
    smtp_data_mode: &mut bool,
    smtp_data_buf: &mut Vec<u8>,
    smtp_auth_state: &mut nettrap_proto_smtp::SmtpAuthState,
    irc_nick: &mut String,
    ssh_first_packet: &mut bool,
) -> Vec<u8> {
    if let Some((detected_name, score)) = ctx.runtime.router.route_tcp(data, destination.port) {
        let is_default = ctx.runtime.router.default_tcp_handler() == Some(detected_name.as_str());
        let is_raw_fallback = detected_name == "raw";
        if score >= 50 || is_default || is_raw_fallback {
            tracing::debug!(
                "TCP '{}' routed {} bytes from {} to handler '{}' (score={}, default={})",
                ctx.name(),
                data.len(),
                peer,
                detected_name,
                score,
                is_default
            );

            if let Some(response) = dispatch_named_tcp_protocol(
                ctx,
                &detected_name,
                data,
                peer,
                output_path,
                smtp_handler,
                ftp_handler,
                pop3_handler,
                irc_handler,
                destination,
                smtp_data_mode,
                smtp_data_buf,
                smtp_auth_state,
                irc_nick,
                ssh_first_packet,
            )
            .await
            {
                return response;
            }
        }
    }

    tracing::debug!("Unknown TCP protocol from {}", peer);
    log_event(
        output_path,
        ctx.name(),
        peer,
        "raw",
        &format!("{} bytes", data.len()),
    )
    .await;
    let nbi = crate::nbi::raw_nbi(
        ctx.name(),
        &peer.ip().to_string(),
        peer.port(),
        destination,
        data.len(),
        "unknown",
    );
    ctx.runtime.nbi_collector.record(&nbi).await;

    let raw_handler = nettrap_proto_raw::RawHandler::new();
    raw_handler.handle(data).to_bytes()
}

/// Handle connection wrapped with TLS.
#[allow(clippy::too_many_arguments)]
pub async fn handle_wrapped_connection(
    ctx: Arc<ListenerContext>,
    mut stream: nettrap_tls_mitm::WrappedStream,
    peer: std::net::SocketAddr,
    destination: SessionDestination,
    output_path: Option<&std::path::Path>,
    smtp_handler: &nettrap_proto_smtp::SmtpHandler,
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    pop3_handler: &nettrap_proto_pop3::Pop3Handler,
    irc_handler: &nettrap_proto_irc::IrcHandler,
    webroot_server: Option<&crate::webroot::WebrootServer>,
) -> crate::Result<()> {
    let name = ctx.name();
    let mut smtp_data_mode = false;
    let mut smtp_data_buf: Vec<u8> = Vec::new();
    let mut smtp_auth_state = nettrap_proto_smtp::SmtpAuthState::None;
    let mut irc_nick = "unknown".to_string();
    let mut ssh_first_packet = true;

    // Apply banner delay before sending TLS banner
    if ctx.banner_delay_ms() > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(ctx.banner_delay_ms())).await;
    }

    // Send TLS banner
    if name == "smtp" || name.starts_with("smtp") {
        stream
            .write_all(smtp_handler.get_welcome_banner().as_bytes())
            .await?;
        stream.flush().await?;
    } else if name == "ftp" || name.starts_with("ftp") {
        stream
            .write_all(ftp_handler.get_banner())
            .await?;
        stream.flush().await?;
    } else if name == "pop3" || name.starts_with("pop3") {
        stream
            .write_all(pop3_handler.get_welcome_banner().as_bytes())
            .await?;
        stream.flush().await?;
    }

    let mut buf = vec![0u8; 4096];

    loop {
        match stream.read(&mut buf).await {
            Ok(0) => return Ok(()),
            Ok(len) => {
                let data = &buf[..len];

                if ctx.config.log_hexdump {
                    tracing::debug!("TLS Hexdump:\n{}", crate::hexdump::hexdump(data, 256));
                }

                ctx.write_pcap_event_for_destination(data, &peer, &destination);

                let response = if name == "smtp" || name.starts_with("smtp") {
                    let cmd_str = std::str::from_utf8(data).unwrap_or("").trim();
                    let nbi = crate::nbi::smtp_nbi(
                        ctx.name(),
                        &peer.ip().to_string(),
                        peer.port(),
                        &destination,
                        cmd_str,
                        "",
                    );
                    ctx.runtime.nbi_collector.record(&nbi).await;
                    handle_smtp_data(
                        data,
                        smtp_handler,
                        &mut smtp_data_mode,
                        &mut smtp_data_buf,
                        &mut smtp_auth_state,
                        output_path,
                        ctx.name(),
                        &peer,
                        ctx.config.smtp_dir.as_deref(),
                    )
                    .await
                } else if name == "pop3" || name.starts_with("pop3") {
                    let command = std::str::from_utf8(data).unwrap_or("").trim();
                    log_event(output_path, ctx.name(), &peer, "pop3_command", command).await;
                    let nbi = crate::nbi::pop3_nbi(
                        ctx.name(),
                        &peer.ip().to_string(),
                        peer.port(),
                        &destination,
                        command,
                        "",
                    );
                    ctx.runtime.nbi_collector.record(&nbi).await;
                    match pop3_handler.handle(command).await {
                        Ok(resp) => resp.to_bytes(),
                        Err(_) => b"-ERR Server error\r\n".to_vec(),
                    }
                } else if name == "irc" || name.starts_with("irc") {
                    let command = std::str::from_utf8(data).unwrap_or("").trim();
                    if command.to_uppercase().starts_with("NICK ") {
                        let raw_nick = command[5..].trim();
                        irc_nick = raw_nick
                            .chars()
                            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                            .take(30)
                            .collect();
                        if irc_nick.is_empty() {
                            irc_nick = "unknown".to_string();
                        }
                    }
                    log_event(output_path, ctx.name(), &peer, "irc_command", command).await;
                    let nbi = crate::nbi::irc_nbi(
                        ctx.name(),
                        &peer.ip().to_string(),
                        peer.port(),
                        &destination,
                        &irc_nick,
                        command,
                        "",
                    );
                    ctx.runtime.nbi_collector.record(&nbi).await;
                    match irc_handler.handle(command, &irc_nick).await {
                        Ok(resp) => resp.to_bytes(),
                        Err(_) => Vec::new(),
                    }
                } else if let Some((detected, score)) = ctx.runtime.router.route_tcp(data, destination.port) {
                    if score >= 50 && detected != "http" && detected != "https" {
                        // Non-HTTP protocol detected over TLS — use raw handler
                        tracing::debug!("TLS '{}' routed to '{}' (score={})", name, detected, score);
                        log_event(output_path, ctx.name(), &peer, "raw", &format!("{} bytes", data.len())).await;
                        let nbi = crate::nbi::raw_nbi(ctx.name(), &peer.ip().to_string(), peer.port(), &destination, data.len(), &detected);
                        ctx.runtime.nbi_collector.record(&nbi).await;
                        nettrap_proto_raw::RawHandler::new().handle(data).to_bytes()
                    } else {
                        handle_https(&ctx, data, &peer, &destination, output_path, webroot_server).await
                    }
                } else {
                    // Default: HTTP over TLS
                    handle_https(&ctx, data, &peer, &destination, output_path, webroot_server).await
                };

                let mut sent_bytes = 0u64;
                if !response.is_empty() {
                    ctx.write_pcap_response_for_destination(&response, &peer, &destination);
                    ctx.apply_response_delay().await;
                    let send_result = async {
                        stream.write_all(&response).await?;
                        stream.flush().await
                    }
                    .await;
                    if send_result.is_ok() {
                        sent_bytes = response.len() as u64;
                    }
                    ctx.update_session_bytes(&peer, "TCP", &destination, len as u64, sent_bytes);
                    send_result?;
                } else {
                    ctx.update_session_bytes(&peer, "TCP", &destination, len as u64, 0);
                }
            }
            Err(e) => {
                tracing::debug!("TLS read error from {}: {}", peer, e);
                return Ok(());
            }
        }
    }
}

async fn handle_https(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
    webroot_server: Option<&crate::webroot::WebrootServer>,
) -> Vec<u8> {
    log_event(output_path, ctx.name(), peer, "https_request", "").await;

    let path = extract_http_path(data);
    let host = extract_http_host(data);
    let method = extract_http_method(data);
    let nbi = crate::nbi::http_nbi(
        ctx.name(),
        &peer.ip().to_string(),
        peer.port(),
        destination,
        &method,
        &path,
        &host,
        "",
        data.len(),
    );
    ctx.runtime.nbi_collector.record(&nbi).await;

    if ctx.dump_http_posts() && data.starts_with(b"POST") {
        let dump_prefix = ctx.dump_prefix().map(|s| s.to_string());
        dump_http_post(data, &dump_prefix, peer).await;
    }

    // DynDNS checkip emulation
    if host.contains("checkip.dyndns") || host.contains("checkip") {
        let src_ip = peer.ip().to_string();
        let body = format!("Current IP Address: {}", src_ip);
        let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
        tracing::info!("DynDNS checkip response for {} (HTTPS)", src_ip);
        return format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nDate: {}\r\nServer: DynDNS-CheckIP/1.0\r\n\r\n{}",
            body.len(), date, body
        ).into_bytes();
    }

    // WPAD / proxy.pac
    if path == "/wpad.dat" || path == "/proxy.pac" {
        let pac = "function FindProxyForURL(url, host) { return \"DIRECT\"; }";
        let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
        tracing::info!("WPAD/PAC response for {} (HTTPS)", peer);
        return format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nDate: {}\r\n\r\n{}",
            pac.len(), date, pac
        ).into_bytes();
    }

    // Custom response or webroot
    if let Some(ref crc) = ctx.config.custom_response_config {
        if let Some(resp) = crc.build_response(&host, &path) {
            return resp;
        }
    }

    if let Some(ws) = webroot_server {
        ws.build_http_response(&path)
    } else {
        build_http_response_with_fakefile(&path, ctx.server_version().unwrap_or("NetTrap"))
    }
}

/// Handle SMTP data mode.
#[allow(clippy::too_many_arguments)]
pub async fn handle_smtp_data(
    data: &[u8],
    smtp_handler: &nettrap_proto_smtp::SmtpHandler,
    smtp_data_mode: &mut bool,
    smtp_data_buf: &mut Vec<u8>,
    smtp_auth_state: &mut nettrap_proto_smtp::SmtpAuthState,
    output_path: Option<&std::path::Path>,
    listener_name: &str,
    peer: &std::net::SocketAddr,
    smtp_dir: Option<&std::path::Path>,
) -> Vec<u8> {
    const MAX_SMTP_DATA_SIZE: usize = 50 * 1024 * 1024;

    if *smtp_data_mode {
        if smtp_data_buf.len() + data.len() > MAX_SMTP_DATA_SIZE {
            tracing::warn!(
                "SMTP DATA buffer exceeded limit from {} ({} bytes), discarding",
                peer,
                smtp_data_buf.len() + data.len()
            );
            *smtp_data_mode = false;
            smtp_data_buf.clear();
            return b"552 Message too large\r\n".to_vec();
        }
        smtp_data_buf.extend_from_slice(data);
        let has_terminator = smtp_data_buf.windows(5).any(|w| w == b"\r\n.\r\n")
            || smtp_data_buf.windows(3).any(|w| w == b"\n.\n");
        if has_terminator {
            let body_size = smtp_data_buf.len();
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
            if let Err(e) = tokio::fs::create_dir_all(&mbox_dir).await {
                tracing::warn!("Failed to create SMTP directory {:?}: {}", mbox_dir, e);
            }
            let filename = format!("{}/{}.eml", mbox_dir.display(), uuid::Uuid::new_v4());
            if let Err(e) = tokio::fs::write(&filename, &*smtp_data_buf).await {
                tracing::warn!("Failed to write SMTP email to {:?}: {}", filename, e);
            } else {
                tracing::info!("SMTP email saved to {}", filename);
            }

            *smtp_data_mode = false;
            smtp_data_buf.clear();
            format!("250 OK Queued as {}\r\n", uuid::Uuid::new_v4()).into_bytes()
        } else {
            Vec::new()
        }
    } else {
        let command = std::str::from_utf8(data).unwrap_or("").trim();
        tracing::debug!("SMTP command from {}: {}", peer, command);
        log_event(output_path, listener_name, peer, "smtp_command", command).await;

        // Use stateful SMTP handler for proper AUTH support
        let (resp, new_state) = smtp_handler.handle_with_state(command, smtp_auth_state.clone());
        *smtp_auth_state = new_state;

        if resp.code == 354 {
            *smtp_data_mode = true;
            smtp_data_buf.clear();
        }
        format!("{} {}\r\n", resp.code, resp.message).into_bytes()
    }
}

/// Build minimal TLS ServerHello response (RFC 5246).
pub fn build_tls_response() -> Vec<u8> {
    // ServerHello handshake message
    let mut handshake = Vec::new();
    handshake.push(0x02); // HandshakeType: ServerHello
    // Handshake length placeholder (3 bytes) — filled below
    handshake.extend_from_slice(&[0, 0, 0]);
    // ServerHello body
    handshake.extend_from_slice(&[0x03, 0x03]); // Server version: TLS 1.2
    handshake.extend_from_slice(&[0u8; 32]); // Random (32 bytes)
    handshake.push(0); // Session ID length: 0
    handshake.extend_from_slice(&[0x00, 0x2F]); // Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA
    handshake.push(0x00); // Compression method: null
    // Fill handshake length (bytes after the 4-byte header)
    let body_len = handshake.len() - 4;
    handshake[1] = ((body_len >> 16) & 0xFF) as u8;
    handshake[2] = ((body_len >> 8) & 0xFF) as u8;
    handshake[3] = (body_len & 0xFF) as u8;
    // TLS record header
    let mut response = Vec::new();
    response.push(22); // ContentType: Handshake
    response.extend_from_slice(&[0x03, 0x03]); // Version: TLS 1.2
    response.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    response.extend_from_slice(&handshake);
    response
}
