use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use crate::listener_context::ListenerContext;
use crate::utils::canonical_socket_ip_string;
use crate::utils::log_event;
use crate::utils::service_name::{is_usable_service_name_input, resolve_service_name};
use nettrap_protocols::tcp::*;

type TcpBannerFactory = fn(Option<&str>) -> crate::Result<Option<Vec<u8>>>;
const MAX_IMAP_COMMAND_LINE_BYTES: usize = 4096;
const MAX_IMAP_TAG_BYTES: usize = 64;

#[derive(Debug, Clone)]
pub struct ImapHandler {
    service_name: String,
}

impl ImapHandler {
    pub fn new() -> Self {
        Self {
            service_name: "NetTrap".to_string(),
        }
    }

    pub fn with_service_name(mut self, service_name: impl Into<String>) -> Result<Self, String> {
        self.service_name = validate_imap_service_name(&service_name.into())?;
        Ok(self)
    }

    pub fn get_welcome_banner(&self) -> String {
        format!("* OK {} IMAP4rev1 Service Ready\r\n", self.service_name)
    }

    fn capability_response(&self, tag: &str) -> Vec<u8> {
        format!("* CAPABILITY IMAP4rev1 LITERAL+\r\n{tag} OK CAPABILITY completed\r\n").into_bytes()
    }

    fn logout_response(&self, tag: &str) -> Vec<u8> {
        format!(
            "* BYE {} IMAP4rev1 server logging out\r\n{tag} OK LOGOUT completed\r\n",
            self.service_name
        )
        .into_bytes()
    }

    fn tagged_response(tag: &str, status: &str, detail: &str) -> Vec<u8> {
        format!("{tag} {status} {detail}\r\n").into_bytes()
    }
}

fn validate_imap_service_name(value: &str) -> Result<String, String> {
    if value.trim_matches([' ', '\t']) != value {
        return Err("invalid IMAP service name".to_string());
    }

    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty()
        || value.len() > 253
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        || !nettrap_core::sanitize::has_valid_domain_labels(value)
        || nettrap_core::sanitize::has_numeric_domain_labels(value)
    {
        Err("invalid IMAP service name".to_string())
    } else {
        Ok(value.to_ascii_lowercase())
    }
}

impl Default for ImapHandler {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn parse_imap_command_line(line: &str) -> Option<(&str, &str)> {
    parse_imap_command_parts(line).map(|(tag, command, _)| (tag, command))
}

fn imap_command_line(command: &str) -> Option<&str> {
    if nettrap_core::sanitize::contains_unicode_line_separator(command) {
        return None;
    }
    if let Some(line) = command.strip_suffix("\r\n") {
        if line.chars().any(|ch| matches!(ch, '\r' | '\n')) {
            return None;
        }
        return Some(line);
    }
    if command.ends_with(['\r', '\n']) {
        return None;
    }
    if command.chars().any(|ch| matches!(ch, '\r' | '\n')) {
        return None;
    }
    Some(command)
}

fn parse_imap_command_parts(line: &str) -> Option<(&str, &str, &str)> {
    if line.is_empty() || line.len() > MAX_IMAP_COMMAND_LINE_BYTES || line.starts_with(' ') {
        return None;
    }

    let tag_end = line.find(' ')?;
    let tag = &line[..tag_end];
    if tag.len() > MAX_IMAP_TAG_BYTES || !is_imap_tag(tag) {
        return None;
    }

    let command_start = line[tag_end..]
        .find(|ch| ch != ' ')
        .map(|offset| tag_end + offset)?;
    let command_end = line[command_start..]
        .find(' ')
        .map_or(line.len(), |offset| command_start + offset);
    let command = &line[command_start..command_end];
    if !is_imap_command_token(command) {
        return None;
    }

    let args = line[command_end..].trim_start_matches(' ');
    if args
        .chars()
        .any(|ch| ch.is_control() || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
    {
        return None;
    }

    Some((tag, command, args))
}

fn is_imap_command_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
}

fn is_imap_tag(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(byte, 0x21..=0x7e)
                && !matches!(
                    byte,
                    b'(' | b')' | b'{' | b'%' | b'*' | b'"' | b'\\' | b']' | b'+'
                )
        })
}

pub struct HandlerRegistry {
    tcp_banner_factories: HashMap<&'static str, TcpBannerFactory>,
}

impl HandlerRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            tcp_banner_factories: HashMap::new(),
        };
        registry.register_defaults();
        registry
    }

    fn register_defaults(&mut self) {
        self.register_tcp_banner("ssh", Self::ssh_banner);
        self.register_tcp_banner("mysql", Self::mysql_banner);
        self.register_tcp_banner("telnet", Self::telnet_banner);
        self.register_tcp_banner("smtp", Self::smtp_banner);
        self.register_tcp_banner("ftp", Self::ftp_banner);
        self.register_tcp_banner("pop3", Self::pop3_banner);
        self.register_tcp_banner("irc", Self::irc_banner);
        self.register_tcp_banner("imap", Self::imap_banner);
        self.register_tcp_banner("imaps", Self::imap_banner);
    }

    fn register_tcp_banner(&mut self, name: &'static str, factory: TcpBannerFactory) {
        self.tcp_banner_factories.insert(name, factory);
    }

    pub fn get_banner(
        &self,
        name: &str,
        banner_text: Option<&str>,
    ) -> crate::Result<Option<Vec<u8>>> {
        let key = Self::normalize_name(name);
        match self.tcp_banner_factories.get(key.as_str()) {
            Some(factory) => factory(banner_text),
            None => Ok(None),
        }
    }

    pub fn has_banner(&self, name: &str) -> bool {
        let key = Self::normalize_name(name);
        self.tcp_banner_factories.contains_key(key.as_str())
    }

    fn normalize_name(name: &str) -> String {
        if name.trim_matches([' ', '\t']) != name
            || name.is_empty()
            || name
                .chars()
                .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
        {
            return String::new();
        }
        let base = if let Some(idx) = name.find('-') {
            &name[..idx]
        } else if let Some(idx) = name.find('_') {
            &name[..idx]
        } else {
            name
        };
        base.to_lowercase()
    }

    fn ssh_banner(banner: Option<&str>) -> crate::Result<Option<Vec<u8>>> {
        let handler = if let Some(banner) = banner {
            SshHandler::new()
                .with_version(banner)
                .map_err(|err| crate::Error::Config(format!("invalid SSH banner: {}", err)))?
        } else {
            SshHandler::new()
        };
        Ok(Some(handler.get_banner()))
    }

    fn mysql_banner(_banner: Option<&str>) -> crate::Result<Option<Vec<u8>>> {
        Ok(Some(MysqlHandler::new().get_handshake()))
    }

    fn telnet_banner(_banner: Option<&str>) -> crate::Result<Option<Vec<u8>>> {
        let handler = if let Some(b) = _banner {
            if !is_usable_service_name_input(b) {
                return Err(crate::Error::Config("invalid Telnet banner".to_string()));
            }
            TelnetHandler::new()
                .with_hostname(resolve_service_name(b))
                .map_err(|err| crate::Error::Config(format!("invalid Telnet banner: {}", err)))?
        } else {
            TelnetHandler::new()
        };
        Ok(Some(handler.get_login_banner()))
    }

    fn smtp_banner(banner: Option<&str>) -> crate::Result<Option<Vec<u8>>> {
        let handler = if let Some(b) = banner {
            if !is_usable_service_name_input(b) {
                return Err(crate::Error::Config("invalid SMTP banner".to_string()));
            }
            SmtpHandler::new()
                .with_domain(resolve_service_name(b))
                .map_err(|err| crate::Error::Config(format!("invalid SMTP banner: {}", err)))?
        } else {
            SmtpHandler::new()
        };
        Ok(Some(handler.get_welcome_banner().into_bytes()))
    }

    fn ftp_banner(banner: Option<&str>) -> crate::Result<Option<Vec<u8>>> {
        let handler = if let Some(b) = banner {
            if b.trim_matches([' ', '\t']) != b
                || b.chars()
                    .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
            {
                return Err(crate::Error::Config("invalid FTP banner".to_string()));
            }
            FtpHandler::new()
                .with_preformatted_banner(
                    nettrap_protocols::handlers::nettrap_proto_ftp::resolve_banner(b),
                )
                .map_err(|err| crate::Error::Config(format!("invalid FTP banner: {}", err)))?
        } else {
            FtpHandler::new()
        };
        Ok(Some(
            handler.get_banner_at(crate::faketime::fake_now()).to_vec(),
        ))
    }

    fn pop3_banner(banner: Option<&str>) -> crate::Result<Option<Vec<u8>>> {
        let handler = if let Some(b) = banner {
            if !is_usable_service_name_input(b) {
                return Err(crate::Error::Config("invalid POP3 banner".to_string()));
            }
            Pop3Handler::new()
                .with_now(crate::faketime::fake_now)
                .with_domain(resolve_service_name(b))
                .map_err(|err| crate::Error::Config(format!("invalid POP3 banner: {}", err)))?
        } else {
            Pop3Handler::new().with_now(crate::faketime::fake_now)
        };
        Ok(Some(handler.get_welcome_banner().into_bytes()))
    }

    fn irc_banner(banner: Option<&str>) -> crate::Result<Option<Vec<u8>>> {
        let handler = if let Some(b) = banner {
            if !is_usable_service_name_input(b) {
                return Err(crate::Error::Config("invalid IRC banner".to_string()));
            }
            IrcHandler::new()
                .with_clock(crate::faketime::fake_now())
                .with_server_name(resolve_service_name(b))
                .map_err(|err| crate::Error::Config(format!("invalid IRC banner: {}", err)))?
        } else {
            IrcHandler::new().with_clock(crate::faketime::fake_now())
        };
        Ok(Some(handler.get_welcome_banner().into_bytes()))
    }

    fn imap_banner(banner: Option<&str>) -> crate::Result<Option<Vec<u8>>> {
        let handler = if let Some(b) = banner {
            if !is_usable_service_name_input(b) {
                return Err(crate::Error::Config("invalid IMAP banner".to_string()));
            }
            ImapHandler::new()
                .with_service_name(resolve_service_name(b))
                .map_err(|err| crate::Error::Config(format!("invalid IMAP banner: {}", err)))?
        } else {
            ImapHandler::new()
        };
        Ok(Some(handler.get_welcome_banner().into_bytes()))
    }

    pub fn get_simple_tcp_handler(
        &self,
        name: &str,
    ) -> Option<Box<dyn SimpleTcpHandler + Send + Sync>> {
        let key = Self::normalize_name(name);
        match key.as_str() {
            "ssh" => Some(Box::new(SshHandler::new())),
            "mysql" => Some(Box::new(MysqlHandler::new())),
            "rdp" => Some(Box::new(RdpHandler::new())),
            "redis" => Some(Box::new(RedisHandler::new())),
            "ldap" => Some(Box::new(LdapHandler::new())),
            "socks" => Some(Box::new(SocksHandler::new())),
            "memcached" => Some(Box::new(
                MemcachedHandler::new().with_now(crate::faketime::fake_now),
            )),
            "nkn" => Some(Box::new(NknHandler::new())),
            "postgres" => Some(Box::new(PostgresHandler::new())),
            "smb" => Some(Box::new(SmbHandler::new())),
            "telnet" => Some(Box::new(
                TelnetHandler::new().with_now(crate::faketime::fake_now),
            )),
            "imap" | "imaps" => Some(Box::new(ImapHandler::new())),
            "finger" => Some(Box::new(FingerHandler::new())),
            "ident" => Some(Box::new(IdentHandler::new())),
            "daytime" => Some(Box::new(
                DaytimeHandler::new().with_now(crate::faketime::fake_now),
            )),
            "time" => Some(Box::new(
                TimeHandler::new().with_now(crate::faketime::fake_now),
            )),
            "chargen" => Some(Box::new(ChargenHandler::new())),
            "quotd" | "qotd" => Some(Box::new(QuotdHandler::new())),
            "syslogrecv" => Some(Box::new(SyslogRecvHandler::new())),
            "dummy" => Some(Box::new(DummyHandler::new())),
            _ => None,
        }
    }

    pub fn is_simple_tcp_handler(name: &str) -> bool {
        let key = Self::normalize_name(name);
        matches!(
            key.as_str(),
            "ssh"
                | "mysql"
                | "rdp"
                | "redis"
                | "ldap"
                | "socks"
                | "memcached"
                | "nkn"
                | "postgres"
                | "smb"
                | "telnet"
                | "imap"
                | "imaps"
                | "finger"
                | "ident"
                | "daytime"
                | "time"
                | "chargen"
                | "quotd"
                | "qotd"
                | "syslogrecv"
                | "dummy"
        )
    }

    pub async fn handle_simple_tcp(
        &self,
        protocol: &str,
        data: &[u8],
        ctx: &Arc<ListenerContext>,
        output_path: Option<&Path>,
        peer: &SocketAddr,
    ) -> Option<Vec<u8>> {
        let handler = self.get_simple_tcp_handler(protocol)?;
        let response = handler.handle_tcp(data)?;
        log_event(
            output_path,
            ctx.name(),
            peer,
            &format!("{}_request", protocol),
            &format!("{} bytes", data.len()),
        )
        .await;
        let mut nbi = crate::nbi::raw_nbi(
            ctx.name(),
            &canonical_socket_ip_string(peer),
            peer.port(),
            &ctx.resolve_session_destination_for_port(peer, "TCP", ctx.port()),
            data.len(),
            "",
        );
        nbi.add("detected_protocol", protocol);
        ctx.record_nbi(&nbi).await;
        Some(response)
    }
}

pub trait SimpleTcpHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>>;
}

impl SimpleTcpHandler for ImapHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>> {
        let line = imap_command_line(std::str::from_utf8(data).ok()?)?;
        let (tag, command, args) = parse_imap_command_parts(line)?;
        let command = command.to_ascii_uppercase();

        let response = match command.as_str() {
            "CAPABILITY" if args.is_empty() => self.capability_response(tag),
            "LOGOUT" if args.is_empty() => self.logout_response(tag),
            "NOOP" | "CHECK" | "CLOSE" | "EXPUNGE" if !args.is_empty() => {
                Self::tagged_response(tag, "BAD", &format!("{command} takes no arguments"))
            }
            "NOOP" | "CHECK" | "CLOSE" | "EXPUNGE" => {
                Self::tagged_response(tag, "OK", &format!("{command} completed"))
            }
            "STARTTLS" if args.is_empty() => {
                Self::tagged_response(tag, "BAD", "STARTTLS is not available")
            }
            "STARTTLS" => Self::tagged_response(tag, "BAD", "STARTTLS takes no arguments"),
            "LOGIN" | "AUTHENTICATE" | "SELECT" | "EXAMINE" | "STATUS" | "LIST" | "LSUB"
            | "FETCH" | "STORE" | "APPEND" | "ID" | "UID"
                if args.is_empty() =>
            {
                Self::tagged_response(tag, "BAD", &format!("{command} requires arguments"))
            }
            "LOGIN" | "AUTHENTICATE" if !args.is_empty() => {
                Self::tagged_response(tag, "BAD", &format!("{command} not supported"))
            }
            "SELECT" | "EXAMINE" | "STATUS" | "LIST" | "LSUB" | "FETCH" | "STORE" | "APPEND"
            | "ID" | "UID" => Self::tagged_response(tag, "OK", &format!("{command} completed")),
            _ => Self::tagged_response(tag, "BAD", &format!("{command} not understood")),
        };

        Some(response)
    }
}

impl SimpleTcpHandler for SshHandler {
    fn handle_tcp(&self, _data: &[u8]) -> Option<Vec<u8>> {
        let mut resp = self.build_kexinit();
        resp.extend_from_slice(&self.build_auth_failure());
        Some(resp)
    }
}

impl SimpleTcpHandler for MysqlHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>> {
        Some(self.handle(data))
    }
}

impl SimpleTcpHandler for RdpHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>> {
        Some(self.handle(data))
    }
}

impl SimpleTcpHandler for RedisHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>> {
        Some(self.handle_command(data))
    }
}

impl SimpleTcpHandler for LdapHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>> {
        Some(self.handle(data))
    }
}

impl SimpleTcpHandler for SocksHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>> {
        Some(self.handle(data))
    }
}

impl SimpleTcpHandler for MemcachedHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>> {
        Some(self.handle(data))
    }
}

impl SimpleTcpHandler for NknHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>> {
        Some(self.handle(data))
    }
}

impl SimpleTcpHandler for PostgresHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>> {
        Some(self.handle(data))
    }
}

impl SimpleTcpHandler for SmbHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>> {
        Some(self.handle(data))
    }
}

impl SimpleTcpHandler for TelnetHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>> {
        let cmd = std::str::from_utf8(data).ok()?;
        Some(self.handle_command(cmd).to_vec())
    }
}

impl SimpleTcpHandler for FingerHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>> {
        let query = std::str::from_utf8(data).unwrap_or("\0");
        Some(self.handle(query).into_bytes())
    }
}

impl SimpleTcpHandler for IdentHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>> {
        let query = std::str::from_utf8(data).ok()?;
        Some(self.handle(query).into_bytes())
    }
}

impl SimpleTcpHandler for DaytimeHandler {
    fn handle_tcp(&self, _data: &[u8]) -> Option<Vec<u8>> {
        Some(self.handle_at(crate::faketime::fake_now()).into_bytes())
    }
}

impl SimpleTcpHandler for TimeHandler {
    fn handle_tcp(&self, _data: &[u8]) -> Option<Vec<u8>> {
        Some(self.handle_at(crate::faketime::fake_now()))
    }
}

impl SimpleTcpHandler for ChargenHandler {
    fn handle_tcp(&self, _data: &[u8]) -> Option<Vec<u8>> {
        Some(self.handle(6))
    }
}

impl SimpleTcpHandler for QuotdHandler {
    fn handle_tcp(&self, _data: &[u8]) -> Option<Vec<u8>> {
        Some(self.handle().into_bytes())
    }
}

impl SimpleTcpHandler for SyslogRecvHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>> {
        if self.handle(data).is_none() {
            tracing::warn!("Syslog receiver rejected malformed TCP payload");
        }
        Some(Vec::new())
    }
}

impl SimpleTcpHandler for DummyHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>> {
        Some(self.handle(data))
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

static REGISTRY: std::sync::OnceLock<HandlerRegistry> = std::sync::OnceLock::new();

pub fn global_registry() -> &'static HandlerRegistry {
    REGISTRY.get_or_init(HandlerRegistry::new)
}

pub fn get_protocol_banner(name: &str, banner: Option<&str>) -> crate::Result<Option<Vec<u8>>> {
    global_registry().get_banner(name, banner)
}

pub fn has_simple_tcp_handler(name: &str) -> bool {
    HandlerRegistry::is_simple_tcp_handler(name)
}

pub async fn handle_simple_tcp(
    protocol: &str,
    data: &[u8],
    ctx: &Arc<ListenerContext>,
    output_path: Option<&Path>,
    peer: &SocketAddr,
) -> Option<Vec<u8>> {
    global_registry()
        .handle_simple_tcp(protocol, data, ctx, output_path, peer)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_ssh_banner() {
        let registry = HandlerRegistry::new();
        assert!(registry.has_banner("ssh"));
        let banner = registry.get_banner("ssh", None).expect("ssh banner");
        assert!(banner.is_some());
        let banner_vec = banner.unwrap();
        let banner_str = String::from_utf8_lossy(&banner_vec);
        assert!(banner_str.contains("SSH"));
    }

    #[test]
    fn registry_ssh_banner_honors_configured_version() {
        let registry = HandlerRegistry::new();
        let banner = registry
            .get_banner("ssh", Some("SSH-2.0-CustomSSH_1.0"))
            .expect("ssh banner");

        assert_eq!(banner.expect("banner"), b"SSH-2.0-CustomSSH_1.0\r\n");
    }

    #[test]
    fn registry_ssh_banner_rejects_invalid_configured_version() {
        let registry = HandlerRegistry::new();

        assert!(
            registry
                .get_banner("ssh", Some("SSH-2.0-Custom\r\nSSH-2.0-injected"))
                .is_err()
        );
    }

    #[test]
    fn test_registry_mysql_banner() {
        let registry = HandlerRegistry::new();
        assert!(registry.has_banner("mysql"));
        let banner = registry.get_banner("mysql", None).expect("mysql banner");
        assert!(banner.is_some());
    }

    #[test]
    fn test_registry_telnet_banner() {
        let registry = HandlerRegistry::new();
        assert!(registry.has_banner("telnet"));
        let banner = registry.get_banner("telnet", None).expect("telnet banner");
        assert!(banner.is_some());
    }

    #[test]
    fn registry_telnet_banner_honors_configured_hostname() {
        let registry = HandlerRegistry::new();

        let banner = registry
            .get_banner("telnet", Some("router.example"))
            .expect("banner should build");
        let banner_vec = banner.expect("banner");
        let text = String::from_utf8_lossy(&banner_vec);

        assert!(text.contains("router.example login: "));
    }

    #[test]
    fn test_registry_unknown_banner() {
        let registry = HandlerRegistry::new();
        assert!(!registry.has_banner("unknown"));
        let banner = registry
            .get_banner("unknown", None)
            .expect("unknown banner");
        assert!(banner.is_none());
    }

    #[test]
    fn test_registry_imap_banner_and_handler() {
        let registry = HandlerRegistry::new();
        assert!(registry.has_banner("imap"));
        assert!(registry.has_banner("imaps"));
        let banner = registry.get_banner("imap", None).expect("imap banner");
        let banner_vec = banner.expect("banner");
        let banner_text = std::str::from_utf8(&banner_vec).expect("banner is utf-8");
        assert!(banner_text.contains("IMAP4rev1"));

        let handler = ImapHandler::new();
        let capability = handler
            .handle_tcp(b"A001 CAPABILITY\r\n")
            .expect("capability response");
        let capability_text = std::str::from_utf8(&capability).expect("response is utf-8");
        assert!(capability_text.contains("* CAPABILITY IMAP4rev1"));
        assert!(!capability_text.contains("STARTTLS"));
        assert!(!capability_text.contains("AUTH=PLAIN"));
        assert!(!capability_text.contains("AUTH=LOGIN"));
        assert!(capability_text.contains("A001 OK CAPABILITY completed"));

        let starttls = handler
            .handle_tcp(b"A002 STARTTLS\r\n")
            .expect("starttls response");
        let starttls_text = std::str::from_utf8(&starttls).expect("response is utf-8");
        assert!(starttls_text.contains("A002 BAD STARTTLS is not available"));

        let login = handler
            .handle_tcp(b"A003 LOGIN user pass\r\n")
            .expect("login response");
        let login_text = std::str::from_utf8(&login).expect("response is utf-8");
        assert!(login_text.contains("A003 BAD LOGIN not supported"));
    }

    #[test]
    fn imap_handler_rejects_invalid_service_name() {
        assert!(
            ImapHandler::new()
                .with_service_name(" mail.example")
                .is_err()
        );
        assert!(
            ImapHandler::new()
                .with_service_name("mail..example")
                .is_err()
        );
        assert!(
            ImapHandler::new()
                .with_service_name("mail_example")
                .is_err()
        );
    }

    #[test]
    fn test_imap_handler_rejects_tab_separator() {
        let handler = ImapHandler::new();

        assert!(handler.handle_tcp(b"A001\tCAPABILITY\r\n").is_none());
    }

    #[test]
    fn test_imap_handler_rejects_unicode_whitespace_separator() {
        let handler = ImapHandler::new();
        let request = "A001\u{00a0}CAPABILITY\r\n";

        assert!(handler.handle_tcp(request.as_bytes()).is_none());
    }

    #[test]
    fn test_imap_handler_rejects_unicode_line_separators() {
        let handler = ImapHandler::new();
        let request = "A001\u{2028}CAPABILITY\r\n";

        assert!(handler.handle_tcp(request.as_bytes()).is_none());
        assert_eq!(parse_imap_command_line("A001\u{2028}CAPABILITY"), None);
        assert!(
            handler
                .handle_tcp("A001 LOGIN user\u{2028}pass\r\n".as_bytes())
                .is_none()
        );
    }

    #[test]
    fn test_imap_handler_rejects_partial_line_terminators() {
        let handler = ImapHandler::new();

        assert!(handler.handle_tcp(b"A001 CAPABILITY\r\n").is_some());
        assert!(handler.handle_tcp(b"A001 CAPABILITY").is_some());
        assert!(handler.handle_tcp(b"A001 CAPABILITY\n").is_none());
        assert!(handler.handle_tcp(b"A001 CAPABILITY\r").is_none());
    }

    #[test]
    fn test_imap_handler_rejects_embedded_crlf_in_command_line() {
        let handler = ImapHandler::new();

        assert!(handler.handle_tcp(b"A001 CAPABILITY\r\nNOOP\r\n").is_none());
        assert_eq!(parse_imap_command_line("A001 CAPABILITY\r\nNOOP"), None);
    }

    #[test]
    fn test_imap_command_parser_accepts_multiple_ascii_spaces() {
        assert_eq!(
            parse_imap_command_line("A001   CAPABILITY"),
            Some(("A001", "CAPABILITY"))
        );
    }

    #[test]
    fn test_imap_zero_arg_commands_reject_extra_arguments() {
        let handler = ImapHandler::new();

        for request in [
            b"A001 CAPABILITY now\r\n".as_slice(),
            b"A002 LOGOUT now\r\n".as_slice(),
            b"A003 NOOP now\r\n".as_slice(),
            b"A004 CHECK now\r\n".as_slice(),
            b"A005 CLOSE now\r\n".as_slice(),
            b"A006 EXPUNGE now\r\n".as_slice(),
            b"A007 STARTTLS now\r\n".as_slice(),
        ] {
            let response = handler.handle_tcp(request).expect("imap response");
            let response = std::str::from_utf8(&response).expect("response is utf-8");

            assert!(response.contains(" BAD "), "{response}");
        }
    }

    #[test]
    fn test_imap_argument_commands_still_get_basic_ok() {
        let handler = ImapHandler::new();

        let response = handler
            .handle_tcp(b"A001 SELECT INBOX\r\n")
            .expect("imap response");
        let response = std::str::from_utf8(&response).expect("response is utf-8");

        assert_eq!(response, "A001 OK SELECT completed\r\n");
    }

    #[test]
    fn test_imap_argument_commands_reject_missing_arguments() {
        let handler = ImapHandler::new();

        for request in [
            b"A001 LOGIN\r\n".as_slice(),
            b"A002 AUTHENTICATE\r\n".as_slice(),
            b"A003 SELECT\r\n".as_slice(),
            b"A004 EXAMINE\r\n".as_slice(),
            b"A005 STATUS\r\n".as_slice(),
            b"A006 LIST\r\n".as_slice(),
            b"A007 LSUB\r\n".as_slice(),
            b"A008 FETCH\r\n".as_slice(),
            b"A009 STORE\r\n".as_slice(),
            b"A010 APPEND\r\n".as_slice(),
            b"A011 ID\r\n".as_slice(),
            b"A012 UID\r\n".as_slice(),
        ] {
            let response = handler.handle_tcp(request).expect("imap response");
            let response = std::str::from_utf8(&response).expect("response is utf-8");

            assert!(response.contains(" BAD "), "{response}");
            assert!(response.contains("requires arguments"), "{response}");
        }
    }

    #[test]
    fn test_imap_command_parser_rejects_leading_space() {
        assert_eq!(parse_imap_command_line(" A001 CAPABILITY"), None);
    }

    #[test]
    fn test_imap_command_parser_rejects_oversized_line() {
        let request = format!(
            "A001 {} CAPABILITY",
            "X".repeat(MAX_IMAP_COMMAND_LINE_BYTES)
        );

        assert_eq!(parse_imap_command_line(&request), None);
    }

    #[test]
    fn test_imap_handler_rejects_oversized_tag_without_reflection() {
        let handler = ImapHandler::new();
        let request = format!("{} CAPABILITY\r\n", "A".repeat(MAX_IMAP_TAG_BYTES + 1));

        assert!(handler.handle_tcp(request.as_bytes()).is_none());
    }

    #[test]
    fn test_imap_handler_accepts_maximum_tag_length() {
        let handler = ImapHandler::new();
        let tag = "A".repeat(MAX_IMAP_TAG_BYTES);
        let request = format!("{tag} NOOP\r\n");

        let response = handler
            .handle_tcp(request.as_bytes())
            .expect("maximum-length tag should be accepted");
        let response = std::str::from_utf8(&response).expect("response is utf-8");

        assert_eq!(response, format!("{tag} OK NOOP completed\r\n"));
    }

    #[test]
    fn test_imap_handler_rejects_special_tags_without_reflection() {
        let handler = ImapHandler::new();

        for tag in ["*", "A*1", "A%1", "A+1", "A]1", "A\"1", "A\\1", "A{1"] {
            let request = format!("{tag} CAPABILITY\r\n");

            assert!(
                handler.handle_tcp(request.as_bytes()).is_none(),
                "tag should be rejected: {tag:?}"
            );
        }
    }

    #[test]
    fn test_simple_tcp_handler_check() {
        assert!(has_simple_tcp_handler("ssh"));
        assert!(has_simple_tcp_handler("mysql"));
        assert!(has_simple_tcp_handler("rdp"));
        assert!(has_simple_tcp_handler("finger"));
        assert!(has_simple_tcp_handler("syslogrecv"));
        assert!(has_simple_tcp_handler("dummy"));
        assert!(has_simple_tcp_handler("imap"));
        assert!(has_simple_tcp_handler("imaps"));
        assert!(!has_simple_tcp_handler("unknown"));
    }

    #[test]
    fn test_simple_tcp_handler_chargen_preserves_offset() {
        let handler = ChargenHandler::new();
        let first = handler.handle_tcp(b"").expect("first response");
        let second = handler.handle_tcp(b"").expect("second response");

        assert_ne!(first, second);
    }

    #[test]
    fn test_simple_tcp_handler_syslogrecv_handles_invalid_packets_as_empty_response() {
        let handler = SyslogRecvHandler::new();

        assert_eq!(handler.handle_tcp(b"not syslog"), Some(Vec::new()));
    }

    #[test]
    fn test_simple_tcp_handler_syslogrecv_returns_empty_response_on_valid_packet() {
        let handler = SyslogRecvHandler::new();

        assert_eq!(handler.handle_tcp(b"<13> hello"), Some(Vec::new()));
    }

    #[test]
    fn test_normalize_name() {
        assert_eq!(HandlerRegistry::normalize_name("ssh"), "ssh");
        assert_eq!(HandlerRegistry::normalize_name("ssh-22"), "ssh");
        assert_eq!(HandlerRegistry::normalize_name("mysql_3306"), "mysql");
        assert_eq!(HandlerRegistry::normalize_name("SSH"), "ssh");
        assert_eq!(HandlerRegistry::normalize_name("MySQL_3306"), "mysql");
    }

    #[test]
    fn test_normalize_name_rejects_unicode_whitespace_padding() {
        assert_eq!(HandlerRegistry::normalize_name("ssh\u{00a0}"), "");
        assert!(!has_simple_tcp_handler("ssh\u{00a0}"));
    }

    #[test]
    fn test_normalize_name_rejects_c1_controls() {
        assert_eq!(HandlerRegistry::normalize_name("smtp-\u{009f}mail"), "");
        assert!(!has_simple_tcp_handler("smtp-\u{009f}mail"));
    }

    #[test]
    fn test_registry_matches_protocol_names_case_insensitively() {
        let registry = HandlerRegistry::new();

        assert!(registry.has_banner("SSH"));
        assert!(
            registry
                .get_banner("MYSQL_3306", None)
                .expect("mysql banner")
                .is_some()
        );
        assert!(has_simple_tcp_handler("RDP"));
        assert!(has_simple_tcp_handler("QOTD"));
        assert!(registry.get_simple_tcp_handler("MemCached_11211").is_some());
    }

    #[test]
    fn test_registry_matches_unicode_listener_names_case_insensitively() {
        assert_eq!(HandlerRegistry::normalize_name("MÜLLER"), "müller");
        assert_eq!(HandlerRegistry::normalize_name("MÜLLER-80"), "müller");
        assert_eq!(HandlerRegistry::normalize_name("MÜLLER_80"), "müller");
    }

    #[test]
    fn test_normalize_name_rejects_ascii_padding() {
        assert_eq!(HandlerRegistry::normalize_name(" ssh "), "");
        assert!(!HandlerRegistry::is_simple_tcp_handler(" ssh "));
        assert!(!HandlerRegistry::new().has_banner(" smtp "));
    }

    #[test]
    fn test_telnet_handler_rejects_invalid_utf8() {
        let handler = TelnetHandler::new();

        assert!(handler.handle_tcp(b"\xff\xfe\xfd").is_none());
    }

    #[test]
    fn test_finger_handler_rejects_invalid_utf8_without_listing_users() {
        let handler = FingerHandler::new();

        let response = handler
            .handle_tcp(b"\xff\xfe\xfd")
            .expect("finger should return a protocol response");
        let response = String::from_utf8(response).expect("finger response is utf-8");

        assert_eq!(response, "No such user.\r\n");
        assert!(!response.contains("INVALID-PORT"));
    }

    #[test]
    fn test_ident_handler_rejects_invalid_utf8() {
        let handler = IdentHandler::new();

        assert!(handler.handle_tcp(b"\xff\xfe\xfd").is_none());
    }
}
