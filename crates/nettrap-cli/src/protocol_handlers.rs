use crate::listener_context::ListenerContext;
use crate::session::SessionDestination;
use crate::utils::log_event;
use crate::utils::service_name::resolve_service_name;
use nettrap_protocols::handlers::*;

pub fn get_protocol_banner(name: &str, banner: Option<&str>) -> Option<Vec<u8>> {
    crate::handler_registry::get_protocol_banner(name, banner)
        .or_else(|| fallback_get_protocol_banner(name, banner))
}

fn fallback_get_protocol_banner(name: &str, banner: Option<&str>) -> Option<Vec<u8>> {
    match name {
        _ if name.starts_with("smtp") => {
            let handler = if let Some(b) = banner {
                nettrap_proto_smtp::SmtpHandler::new().with_domain(resolve_service_name(b))
            } else {
                nettrap_proto_smtp::SmtpHandler::new()
            };
            Some(handler.get_welcome_banner().into_bytes())
        }
        _ if name.starts_with("ftp") => {
            let handler = if let Some(b) = banner {
                nettrap_proto_ftp::FtpHandler::new()
                    .with_banner(nettrap_proto_ftp::resolve_banner(b))
            } else {
                nettrap_proto_ftp::FtpHandler::new()
            };
            Some(handler.get_banner().to_vec())
        }
        _ if name.starts_with("pop3") => {
            let handler = if let Some(b) = banner {
                nettrap_proto_pop3::Pop3Handler::new().with_domain(resolve_service_name(b))
            } else {
                nettrap_proto_pop3::Pop3Handler::new()
            };
            Some(handler.get_welcome_banner().into_bytes())
        }
        _ if name.starts_with("irc") => {
            let handler = if let Some(b) = banner {
                nettrap_proto_irc::IrcHandler::new().with_server_name(resolve_service_name(b))
            } else {
                nettrap_proto_irc::IrcHandler::new()
            };
            Some(handler.get_welcome_banner().into_bytes())
        }
        _ => None,
    }
}

pub fn has_simple_handler(name: &str) -> bool {
    crate::handler_registry::has_simple_tcp_handler(name)
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
    ctx.apply_response_delay().await;
    ctx.write_pcap_response_udp_for_destination(packet.response, &packet.src, packet.destination);
    let _ = socket.send_to(packet.response, packet.src).await;
    ctx.update_session_bytes(
        &packet.src,
        "UDP",
        packet.destination,
        packet.len as u64,
        packet.response.len() as u64,
    );
    log_event(
        packet.output_path,
        ctx.name(),
        &packet.src,
        &format!("{}_request", packet.protocol_name),
        &format!("{} bytes", packet.len),
    )
    .await;
    let nbi = crate::nbi::raw_nbi(
        ctx.name(),
        &packet.src.ip().to_string(),
        packet.src.port(),
        packet.destination,
        packet.len,
        packet.protocol_name,
    );
    ctx.record_nbi(&nbi).await;
}

pub fn init_dns_handler(ctx: &ListenerContext) -> nettrap_proto_dns::handler::DnsHandler {
    let mut dns_handler = nettrap_proto_dns::handler::DnsHandler::new();

    match ctx.dns_response_mode() {
        Some("auto") => {
            dns_handler = dns_handler.with_auto_response_ip();
        }
        Some("hostname") => {
            if let Ok(hostname) = hostname::get() {
                let hostname_str = hostname.to_string_lossy().to_string();
                if let Ok(addrs) =
                    std::net::ToSocketAddrs::to_socket_addrs(&(hostname_str.as_str(), 0))
                {
                    for addr in addrs {
                        if !addr.ip().is_loopback() {
                            dns_handler =
                                dns_handler.with_default_response_ip(addr.ip().to_string());
                            break;
                        }
                    }
                }
            }
        }
        Some(unknown) => {
            tracing::warn!(
                "Unknown dns_response_mode '{}' for listener {}, using default",
                unknown,
                ctx.name(),
            );
        }
        None => {}
    }

    if let Some(ip) = ctx.dns_response_ip() {
        dns_handler = dns_handler.with_default_response_ip(ip);
    }
    if let Some(mx) = ctx.config.dns_response_mx.as_deref() {
        dns_handler = dns_handler.with_default_response_mx(mx);
    }
    if let Some(txt) = ctx.config.dns_response_txt.as_deref() {
        dns_handler = dns_handler.with_default_response_txt(txt);
    }
    if let Some(n) = ctx.config.dns_nxdomains {
        dns_handler = dns_handler.with_nxdomains(n);
    }

    if let Some(custom) = ctx.custom_response() {
        for entry in custom.split(';') {
            if let Some((domain, ips)) = entry.split_once('=') {
                let ip_list: Vec<String> = ips.split(',').map(|s| s.trim().to_string()).collect();
                dns_handler.add_custom_response(domain.trim(), ip_list);
            }
        }
    }

    dns_handler
}

pub fn init_ftp_handler(ctx: &ListenerContext) -> nettrap_proto_ftp::FtpHandler {
    let mut ftp_handler = nettrap_proto_ftp::FtpHandler::new();
    if let Some(ref banner) = ctx.config.banner {
        ftp_handler = ftp_handler.with_banner(nettrap_proto_ftp::resolve_banner(banner.as_str()));
    }
    if let Some(ref root) = ctx.config.ftproot {
        ftp_handler = ftp_handler.with_root_dir(root);
    }
    if let Some(ref pasv) = ctx.config.pasv_ports {
        if let Some((start_s, end_s)) = pasv.split_once('-') {
            if let (Ok(start), Ok(end)) =
                (start_s.trim().parse::<u16>(), end_s.trim().parse::<u16>())
            {
                let (lo, hi) = if start <= end {
                    (start, end)
                } else {
                    (end, start)
                };
                if lo < 1024 {
                    tracing::warn!(
                        "FTP PASV port range starts below 1024 ({}), may require elevated privileges",
                        lo
                    );
                }
                if (hi - lo) > 1000 {
                    tracing::warn!(
                        "FTP PASV port range is very large ({}-{}, {} ports)",
                        lo,
                        hi,
                        hi - lo
                    );
                }
                ftp_handler = ftp_handler.with_pasv_ports(lo, hi);
            } else {
                tracing::warn!(
                    "Invalid pasv_ports '{}' for listener {}, expected format: start-end",
                    pasv,
                    ctx.name(),
                );
            }
        } else {
            tracing::warn!(
                "Invalid pasv_ports '{}' for listener {}, expected format: start-end",
                pasv,
                ctx.name(),
            );
        }
    }
    ftp_handler
}

pub fn init_tftp_handler(ctx: &ListenerContext) -> nettrap_proto_tftp::TftpHandler {
    if let Some(ref root) = ctx.config.tftproot {
        nettrap_proto_tftp::TftpHandler::new().with_root_dir(root)
    } else {
        nettrap_proto_tftp::TftpHandler::new()
    }
}

pub fn init_smtp_handler(ctx: &ListenerContext) -> nettrap_proto_smtp::SmtpHandler {
    if let Some(ref banner) = ctx.config.banner {
        let resolved = resolve_service_name(banner);
        nettrap_proto_smtp::SmtpHandler::new().with_domain(resolved)
    } else {
        nettrap_proto_smtp::SmtpHandler::new()
    }
}

pub fn init_pop3_handler(ctx: &ListenerContext) -> nettrap_proto_pop3::Pop3Handler {
    if let Some(ref banner) = ctx.config.banner {
        let resolved = resolve_service_name(banner);
        nettrap_proto_pop3::Pop3Handler::new().with_domain(resolved)
    } else {
        nettrap_proto_pop3::Pop3Handler::new()
    }
}

pub fn init_irc_handler(ctx: &ListenerContext) -> nettrap_proto_irc::IrcHandler {
    if let Some(ref banner) = ctx.config.banner {
        let resolved = resolve_service_name(banner);
        nettrap_proto_irc::IrcHandler::new().with_server_name(resolved)
    } else {
        nettrap_proto_irc::IrcHandler::new()
    }
}

pub async fn log_tcp_event(
    ctx: &ListenerContext,
    output_path: Option<&std::path::Path>,
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    event_type: &str,
    data: &str,
    protocol: &str,
) {
    log_event(output_path, ctx.name(), peer, event_type, data).await;
    let nbi = crate::nbi::raw_nbi(
        ctx.name(),
        &peer.ip().to_string(),
        peer.port(),
        destination,
        data.len(),
        protocol,
    );
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
        &peer.ip().to_string(),
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
    log_event(output_path, ctx.name(), peer, "ftp_command", command).await;
    let nbi = crate::nbi::ftp_nbi(
        ctx.name(),
        &peer.ip().to_string(),
        peer.port(),
        destination,
        command,
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
    log_event(output_path, ctx.name(), peer, "pop3_command", command).await;
    let nbi = crate::nbi::pop3_nbi(
        ctx.name(),
        &peer.ip().to_string(),
        peer.port(),
        destination,
        command,
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
    log_event(output_path, ctx.name(), peer, "irc_command", command).await;
    let nbi = crate::nbi::irc_nbi(
        ctx.name(),
        &peer.ip().to_string(),
        peer.port(),
        destination,
        nick,
        command,
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
    log_event(output_path, ctx.name(), peer, "smtp_command", command).await;
    let nbi = crate::nbi::smtp_nbi(
        ctx.name(),
        &peer.ip().to_string(),
        peer.port(),
        destination,
        command,
        "",
    );
    ctx.record_nbi(&nbi).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_protocol_banner_smtp() {
        let result = get_protocol_banner("smtp", Some("mail.example.com"));
        assert!(result.is_some());
        let binding = result.unwrap();
        let banner = String::from_utf8_lossy(&binding);
        assert!(banner.contains("ESMTP") || banner.contains("NetTrap"));
    }

    #[test]
    fn test_get_protocol_banner_ftp() {
        let result = get_protocol_banner("ftp", Some("FTP Server"));
        assert!(result.is_some());
    }

    #[test]
    fn test_get_protocol_banner_unknown() {
        let result = get_protocol_banner("unknown", Some("banner"));
        assert!(result.is_none());
    }

    #[test]
    fn test_get_protocol_banner_telnet() {
        let result = get_protocol_banner("telnet", None);
        assert!(result.is_some());
    }

    #[test]
    fn test_get_protocol_banner_ssh() {
        let result = get_protocol_banner("ssh", None);
        assert!(result.is_some());
        let binding = result.unwrap();
        let banner = String::from_utf8_lossy(&binding);
        assert!(banner.contains("SSH"));
    }

    #[test]
    fn test_get_protocol_banner_mysql() {
        let result = get_protocol_banner("mysql", None);
        assert!(result.is_some());
    }

    #[test]
    fn test_get_protocol_banner_prefix_match() {
        assert!(get_protocol_banner("smtp-25", None).is_some());
        assert!(get_protocol_banner("ftp-21", Some("banner")).is_some());
        assert!(get_protocol_banner("pop3-110", None).is_some());
    }
}
