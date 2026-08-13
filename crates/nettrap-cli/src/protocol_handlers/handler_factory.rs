//! Protocol handler construction (factory functions).

use crate::listener_config::DnsResponseMode;
use crate::listener_context::ListenerContext;
use crate::session::normalize_session_ip;
use crate::utils::service_name::{
    is_usable_service_name_input, resolve_hostname_service_name, resolve_service_name,
};
use nettrap_protocols::handlers::*;
use std::net::{IpAddr, Ipv4Addr};

pub fn init_dns_handler(
    ctx: &ListenerContext,
) -> crate::Result<nettrap_proto_dns::handler::DnsHandler> {
    let mut dns_handler =
        nettrap_proto_dns::handler::DnsHandler::new().with_now(crate::faketime::fake_now);

    match ctx
        .dns_response_mode()
        .map(str::parse::<DnsResponseMode>)
        .transpose()
        .map_err(|_| {
            crate::Error::Config(format!(
                "Unknown dns_response_mode '{}' for listener {}",
                ctx.dns_response_mode().unwrap_or_default(),
                ctx.name(),
            ))
        })? {
        Some(DnsResponseMode::Auto) => {
            dns_handler = dns_handler.with_auto_response_ip()?;
        }
        Some(DnsResponseMode::Hostname) => {
            if let Ok(hostname) = hostname::get() {
                let hostname = resolve_hostname_service_name(&hostname);
                if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&(hostname.as_str(), 0))
                {
                    for addr in addrs {
                        if is_usable_dns_response_ip(addr.ip()) {
                            dns_handler = dns_handler.with_default_response_ip(
                                normalize_session_ip(addr.ip()).to_string(),
                            )?;
                            break;
                        }
                    }
                }
            }
        }
        Some(DnsResponseMode::Static) | None => {}
    }

    if let Some(ip) = ctx.dns_response_ip() {
        dns_handler = dns_handler.with_default_response_ip(ip)?;
    }
    if let Some(mx) = ctx.config.dns_response_mx.as_deref() {
        dns_handler = dns_handler.with_default_response_mx(mx)?;
    }
    if let Some(txt) = ctx.config.dns_response_txt.as_deref() {
        dns_handler = dns_handler.with_default_response_txt(txt)?;
    }
    if let Some(n) = ctx.config.dns_nxdomains {
        dns_handler = dns_handler.with_nxdomains(n);
    }
    if let Some(ip) = ctx.dns_ncsi_response_ip() {
        let ip = ip.parse::<std::net::Ipv4Addr>().map_err(|e| {
            crate::Error::Config(format!(
                "Invalid dns_ncsi_response_ip '{}' for listener {}: {}",
                ip,
                ctx.name(),
                e
            ))
        })?;
        if !is_usable_dns_response_ipv4(ip) {
            return Err(crate::Error::Config(format!(
                "Invalid dns_ncsi_response_ip '{}' for listener {}: must be a usable unicast address",
                ip,
                ctx.name()
            )));
        }
        dns_handler = dns_handler.with_ncsi_response_ip(ip)?;
    }

    for (domain, ips) in ctx.config.parse_dns_custom_responses()? {
        dns_handler.add_custom_response(domain, ips)?;
    }

    Ok(dns_handler)
}

pub fn init_ftp_handler(ctx: &ListenerContext) -> crate::Result<nettrap_proto_ftp::FtpHandler> {
    let mut ftp_handler = nettrap_proto_ftp::FtpHandler::new().with_now(crate::faketime::fake_now);
    if let Some(server_name) = ctx.config.server_name.as_deref() {
        if !is_usable_service_name_input(server_name) {
            return Err(crate::Error::Config(format!(
                "invalid FTP server name for listener {}: {}",
                ctx.name(),
                server_name
            )));
        }
        ftp_handler = ftp_handler
            .with_server_name(resolve_service_name(server_name))
            .map_err(|err| crate::Error::Config(format!("invalid FTP server name: {}", err)))?;
    }
    if let Some(ref banner) = ctx.config.banner {
        if ftp_banner_override_is_invalid(banner) {
            return Err(crate::Error::Config(format!(
                "invalid FTP banner for listener {}: {}",
                ctx.name(),
                banner
            )));
        }
        ftp_handler = ftp_handler
            .with_preformatted_banner(nettrap_proto_ftp::resolve_banner(banner.as_str()))
            .map_err(|err| crate::Error::Config(format!("invalid FTP banner: {}", err)))?;
    }
    if let Some(ref root) = ctx.config.ftproot {
        ftp_handler = ftp_handler
            .with_root_dir(root)
            .map_err(|err| crate::Error::Config(format!("invalid FTP root directory: {}", err)))?;
    }
    if let Some(ref pasv) = ctx.config.pasv_ports {
        if let Some((lo, hi)) = parse_pasv_port_range(pasv) {
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
            ftp_handler = ftp_handler.with_pasv_ports(lo, hi).map_err(|error| {
                crate::Error::Config(format!(
                    "Invalid pasv_ports '{}' for listener {}: {}",
                    pasv,
                    ctx.name(),
                    error
                ))
            })?;
        } else {
            return Err(crate::Error::Config(format!(
                "Invalid pasv_ports '{}' for listener {}, expected format: start-end",
                pasv,
                ctx.name(),
            )));
        }
    }
    Ok(ftp_handler)
}

fn ftp_banner_override_is_invalid(value: &str) -> bool {
    value.trim_matches([' ', '\t']) != value
        || value
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
}

pub fn init_imap_handler(
    ctx: &ListenerContext,
) -> crate::Result<crate::handler_registry::ImapHandler> {
    // Prefer the dedicated ServerName setting; fall back to the legacy banner
    // overload for back-compat with configs that set the IMAP service name via `banner`.
    let handler = crate::handler_registry::ImapHandler::new();
    if let Some(name) = preferred_hostname(ctx, "IMAP service name")? {
        handler
            .with_service_name(resolve_service_name(name))
            .map_err(|err| crate::Error::Config(format!("invalid IMAP service name: {}", err)))
    } else {
        Ok(handler)
    }
}

fn parse_pasv_port_range(value: &str) -> Option<(u16, u16)> {
    let (start_s, end_s) = value.split_once('-')?;
    let start = parse_unsigned_port(start_s)?;
    let end = parse_unsigned_port(end_s)?;
    if start == 0 || end == 0 {
        return None;
    }
    if start > end {
        return None;
    }
    Some((start, end))
}

fn parse_unsigned_port(value: &str) -> Option<u16> {
    if value.trim_matches([' ', '\t']) != value
        || value.is_empty()
        || value
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

fn is_usable_dns_response_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_usable_dns_response_ipv4(ipv4),
        IpAddr::V6(ipv6) => {
            if let Some(mapped) = ipv6.to_ipv4_mapped() {
                return is_usable_dns_response_ipv4(mapped);
            }
            !ipv6.is_unspecified() && !ipv6.is_loopback() && !ipv6.is_multicast()
        }
    }
}

fn is_usable_dns_response_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
}

pub fn init_tftp_handler(ctx: &ListenerContext) -> crate::Result<nettrap_proto_tftp::TftpHandler> {
    if let Some(ref root) = ctx.config.tftproot {
        nettrap_proto_tftp::TftpHandler::new()
            .with_root_dir(root)
            .map_err(|err| crate::Error::Config(format!("invalid TFTP root directory: {}", err)))
    } else {
        Ok(nettrap_proto_tftp::TftpHandler::new())
    }
}

pub fn init_smtp_handler(ctx: &ListenerContext) -> crate::Result<nettrap_proto_smtp::SmtpHandler> {
    // Prefer the dedicated ServerName setting; fall back to the legacy banner
    // overload for configurations that set the service name via `banner`.
    let handler = nettrap_proto_smtp::SmtpHandler::new().with_now(crate::faketime::fake_now);
    if let Some(name) = preferred_hostname(ctx, "SMTP domain")? {
        let resolved = resolve_service_name(name);
        handler
            .with_domain(resolved)
            .map_err(|err| crate::Error::Config(format!("invalid SMTP domain: {}", err)))
    } else {
        Ok(handler)
    }
}

pub fn init_pop3_handler(ctx: &ListenerContext) -> crate::Result<nettrap_proto_pop3::Pop3Handler> {
    // Prefer ServerName, fall back to the legacy banner overload (see SMTP).
    let handler = nettrap_proto_pop3::Pop3Handler::new().with_now(crate::faketime::fake_now);
    if let Some(name) = preferred_hostname(ctx, "POP3 domain")? {
        let resolved = resolve_service_name(name);
        handler
            .with_domain(resolved)
            .map_err(|err| crate::Error::Config(format!("invalid POP3 domain: {}", err)))
    } else {
        Ok(handler)
    }
}

pub fn init_irc_handler(ctx: &ListenerContext) -> crate::Result<nettrap_proto_irc::IrcHandler> {
    // Prefer the dedicated ServerName setting; fall back to the legacy banner
    // overload for back-compat with configs that set the IRC name via `banner`.
    let handler = nettrap_proto_irc::IrcHandler::new().with_clock(crate::faketime::fake_now());
    if let Some(name) = preferred_hostname(ctx, "IRC server name")? {
        handler
            .with_server_name(resolve_service_name(name))
            .map_err(|err| crate::Error::Config(format!("invalid IRC server name: {}", err)))
    } else {
        Ok(handler)
    }
}

pub fn init_upnp_handler(
    listen_ip: impl Into<String>,
) -> crate::Result<nettrap_proto_upnp::UpnpHandler> {
    build_upnp_handler(listen_ip, crate::faketime::fake_now)
}

fn build_upnp_handler(
    listen_ip: impl Into<String>,
    now: fn() -> chrono::DateTime<chrono::Utc>,
) -> crate::Result<nettrap_proto_upnp::UpnpHandler> {
    nettrap_proto_upnp::UpnpHandler::new()
        .with_now(now)
        .with_listen_ip(listen_ip)
        .map_err(|err| crate::Error::Config(format!("invalid UPnP listen IP: {}", err)))
}

fn preferred_hostname<'a>(ctx: &'a ListenerContext, label: &str) -> crate::Result<Option<&'a str>> {
    if let Some(name) = ctx.config.server_name.as_deref() {
        if !is_usable_service_name_input(name) {
            return Err(crate::Error::Config(format!(
                "invalid {} for listener {}: {}",
                label,
                ctx.name(),
                name
            )));
        }
        return Ok(Some(name));
    }
    if let Some(name) = ctx.config.banner.as_deref() {
        if !is_usable_service_name_input(name) {
            return Err(crate::Error::Config(format!(
                "invalid {} for listener {}: {}",
                label,
                ctx.name(),
                name
            )));
        }
        return Ok(Some(name));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{
        init_ftp_handler, init_imap_handler, is_usable_dns_response_ip, parse_pasv_port_range,
    };
    use crate::listener_context::ListenerContext;
    use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
    use crate::process_filter::ProcessFilter;
    use crate::session::{PortForwardTable, SessionTracker};
    use std::net::IpAddr;
    use std::sync::Arc;

    fn test_context() -> ListenerContext {
        ListenerContext::builder()
            .name("ftp")
            .port(21)
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
    fn parse_pasv_port_range_rejects_unicode_whitespace_padding() {
        assert_eq!(parse_pasv_port_range("60000-60100\u{00a0}"), None);
    }

    #[test]
    fn parse_pasv_port_range_rejects_ascii_padding() {
        assert_eq!(parse_pasv_port_range(" 60000-60100"), None);
        assert_eq!(parse_pasv_port_range("60000-60100 "), None);
    }

    #[test]
    fn parse_pasv_port_range_rejects_port_zero() {
        assert_eq!(parse_pasv_port_range("0-1"), None);
        assert_eq!(parse_pasv_port_range("1-0"), None);
        assert_eq!(parse_pasv_port_range("0-0"), None);
    }

    #[test]
    fn init_ftp_handler_rejects_unicode_whitespace_pasv_range() {
        let mut ctx = test_context();
        ctx.config.pasv_ports = Some("60000-60100\u{00a0}".to_string());

        let err = match init_ftp_handler(&ctx) {
            Ok(_) => panic!("unicode whitespace should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("Invalid pasv_ports"));
    }

    #[test]
    fn init_ftp_handler_rejects_zero_pasv_ports() {
        let mut ctx = test_context();
        ctx.config.pasv_ports = Some("0-1".to_string());

        let err = match init_ftp_handler(&ctx) {
            Ok(_) => panic!("zero PASV port should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("Invalid pasv_ports"));
    }

    #[test]
    fn init_ftp_handler_rejects_inverted_pasv_range() {
        let mut ctx = test_context();
        ctx.config.pasv_ports = Some("60100-60000".to_string());

        let err = match init_ftp_handler(&ctx) {
            Ok(_) => panic!("inverted PASV range should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("Invalid pasv_ports"));
    }

    #[test]
    fn init_imap_handler_prefers_server_name_over_banner() {
        let mut ctx = test_context();
        ctx.config.server_name = Some("mail.example".to_string());
        ctx.config.banner = Some("ignored.example".to_string());

        let handler = init_imap_handler(&ctx).expect("handler should build");
        let banner = handler.get_welcome_banner();

        assert!(banner.contains("mail.example IMAP4rev1 Service Ready"));
        assert!(!banner.contains("ignored.example"));
    }

    #[test]
    fn init_imap_handler_rejects_invalid_server_name_without_defaulting() {
        let mut ctx = test_context();
        ctx.config.server_name = Some("bad\r\nname".to_string());

        let err = match init_imap_handler(&ctx) {
            Ok(_) => panic!("invalid IMAP server name should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("invalid IMAP service name"));
    }

    #[test]
    fn parse_pasv_port_range_rejects_c1_controls_in_port() {
        assert_eq!(parse_pasv_port_range("60000-60100\u{009f}"), None);
    }

    #[test]
    fn is_usable_dns_response_ip_rejects_special_addresses() {
        assert!(!is_usable_dns_response_ip(IpAddr::from([0, 0, 0, 0])));
        assert!(!is_usable_dns_response_ip(IpAddr::from([127, 0, 0, 1])));
        assert!(!is_usable_dns_response_ip(IpAddr::from([
            255, 255, 255, 255
        ])));
        assert!(!is_usable_dns_response_ip(IpAddr::from(
            std::net::Ipv6Addr::LOCALHOST
        )));
        assert!(!is_usable_dns_response_ip(IpAddr::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1
        ])));
    }

    #[test]
    fn is_usable_dns_response_ip_accepts_routable_addresses() {
        assert!(is_usable_dns_response_ip(IpAddr::from([192, 0, 2, 10])));
        assert!(is_usable_dns_response_ip(IpAddr::from([
            2001, 0xdb8, 0, 0, 0, 0, 0, 1
        ])));
    }

    #[test]
    fn init_upnp_handler_uses_the_injected_clock_for_ssdp_dates() {
        fn fixed_now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant")
        }

        let handler =
            super::build_upnp_handler("192.168.1.1", fixed_now).expect("UPnP handler should build");
        let response = handler.handle_ssdp(
            b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n",
        );

        let response_text = String::from_utf8_lossy(&response);
        assert!(response_text.contains("DATE: Mon, 01 Jan 2024 00:00:00 GMT"));
    }
}
