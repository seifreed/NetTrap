use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use crate::listener_context::ListenerContext;
use crate::utils::log_event;
use crate::utils::service_name::resolve_service_name;
use nettrap_protocols::tcp::*;

type TcpBannerFactory = fn(Option<&str>) -> Option<Vec<u8>>;

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
    }

    fn register_tcp_banner(&mut self, name: &'static str, factory: TcpBannerFactory) {
        self.tcp_banner_factories.insert(name, factory);
    }

    pub fn get_banner(&self, name: &str, banner_text: Option<&str>) -> Option<Vec<u8>> {
        let key = Self::normalize_name(name);
        self.tcp_banner_factories
            .get(key)
            .and_then(|f| f(banner_text))
    }

    pub fn has_banner(&self, name: &str) -> bool {
        let key = Self::normalize_name(name);
        self.tcp_banner_factories.contains_key(key)
    }

    fn normalize_name(name: &str) -> &str {
        let name = name.trim();
        if let Some(idx) = name.find('-') {
            &name[..idx]
        } else if let Some(idx) = name.find('_') {
            &name[..idx]
        } else {
            name
        }
    }

    fn ssh_banner(_banner: Option<&str>) -> Option<Vec<u8>> {
        Some(SshHandler::new().get_banner())
    }

    fn mysql_banner(_banner: Option<&str>) -> Option<Vec<u8>> {
        Some(MysqlHandler::new().get_handshake())
    }

    fn telnet_banner(_banner: Option<&str>) -> Option<Vec<u8>> {
        Some(TelnetHandler::new().get_login_banner())
    }

    fn smtp_banner(banner: Option<&str>) -> Option<Vec<u8>> {
        let handler = if let Some(b) = banner {
            SmtpHandler::new().with_domain(resolve_service_name(b))
        } else {
            SmtpHandler::new()
        };
        Some(handler.get_welcome_banner().into_bytes())
    }

    fn ftp_banner(banner: Option<&str>) -> Option<Vec<u8>> {
        let handler = if let Some(b) = banner {
            FtpHandler::new()
                .with_banner(nettrap_protocols::handlers::nettrap_proto_ftp::resolve_banner(b))
        } else {
            FtpHandler::new()
        };
        Some(handler.get_banner().to_vec())
    }

    fn pop3_banner(banner: Option<&str>) -> Option<Vec<u8>> {
        let handler = if let Some(b) = banner {
            Pop3Handler::new().with_domain(resolve_service_name(b))
        } else {
            Pop3Handler::new()
        };
        Some(handler.get_welcome_banner().into_bytes())
    }

    fn irc_banner(banner: Option<&str>) -> Option<Vec<u8>> {
        let handler = if let Some(b) = banner {
            IrcHandler::new().with_server_name(resolve_service_name(b))
        } else {
            IrcHandler::new()
        };
        Some(handler.get_welcome_banner().into_bytes())
    }

    pub fn get_simple_tcp_handler(name: &str) -> Option<Box<dyn SimpleTcpHandler + Send + Sync>> {
        let key = Self::normalize_name(name);
        match key {
            "ssh" => Some(Box::new(SshHandler::new())),
            "mysql" => Some(Box::new(MysqlHandler::new())),
            "rdp" => Some(Box::new(RdpHandler::new())),
            "redis" => Some(Box::new(RedisHandler::new())),
            "ldap" => Some(Box::new(LdapHandler::new())),
            "socks" => Some(Box::new(SocksHandler::new())),
            "memcached" => Some(Box::new(MemcachedHandler::new())),
            "nkn" => Some(Box::new(NknHandler::new())),
            "postgres" => Some(Box::new(PostgresHandler::new())),
            "smb" => Some(Box::new(SmbHandler::new())),
            "telnet" => Some(Box::new(TelnetHandler::new())),
            _ => None,
        }
    }

    pub fn is_simple_tcp_handler(name: &str) -> bool {
        let key = Self::normalize_name(name);
        matches!(
            key,
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
        )
    }

    pub async fn handle_simple_tcp(
        protocol: &str,
        data: &[u8],
        ctx: &Arc<ListenerContext>,
        output_path: Option<&Path>,
        peer: &SocketAddr,
    ) -> Option<Vec<u8>> {
        let handler = Self::get_simple_tcp_handler(protocol)?;
        let response = handler.handle_tcp(data)?;
        log_event(
            output_path,
            ctx.name(),
            peer,
            &format!("{}_request", protocol),
            &format!("{} bytes", data.len()),
        )
        .await;
        let nbi = crate::nbi::raw_nbi(
            ctx.name(),
            &peer.ip().to_string(),
            peer.port(),
            &ctx.resolve_session_destination_for_port(peer, "TCP", ctx.port()),
            data.len(),
            protocol,
        );
        ctx.record_nbi(&nbi).await;
        Some(response)
    }
}

pub trait SimpleTcpHandler {
    fn handle_tcp(&self, data: &[u8]) -> Option<Vec<u8>>;
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
        let cmd = std::str::from_utf8(data).unwrap_or("");
        Some(self.handle_command(cmd).to_vec())
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

pub fn get_protocol_banner(name: &str, banner: Option<&str>) -> Option<Vec<u8>> {
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
    HandlerRegistry::handle_simple_tcp(protocol, data, ctx, output_path, peer).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_ssh_banner() {
        let registry = HandlerRegistry::new();
        assert!(registry.has_banner("ssh"));
        let banner = registry.get_banner("ssh", None);
        assert!(banner.is_some());
        let banner_vec = banner.unwrap();
        let banner_str = String::from_utf8_lossy(&banner_vec);
        assert!(banner_str.contains("SSH"));
    }

    #[test]
    fn test_registry_mysql_banner() {
        let registry = HandlerRegistry::new();
        assert!(registry.has_banner("mysql"));
        let banner = registry.get_banner("mysql", None);
        assert!(banner.is_some());
    }

    #[test]
    fn test_registry_telnet_banner() {
        let registry = HandlerRegistry::new();
        assert!(registry.has_banner("telnet"));
        let banner = registry.get_banner("telnet", None);
        assert!(banner.is_some());
    }

    #[test]
    fn test_registry_unknown_banner() {
        let registry = HandlerRegistry::new();
        assert!(!registry.has_banner("unknown"));
        let banner = registry.get_banner("unknown", None);
        assert!(banner.is_none());
    }

    #[test]
    fn test_simple_tcp_handler_check() {
        assert!(has_simple_tcp_handler("ssh"));
        assert!(has_simple_tcp_handler("mysql"));
        assert!(has_simple_tcp_handler("rdp"));
        assert!(!has_simple_tcp_handler("unknown"));
    }

    #[test]
    fn test_normalize_name() {
        assert_eq!(HandlerRegistry::normalize_name("ssh"), "ssh");
        assert_eq!(HandlerRegistry::normalize_name("ssh-22"), "ssh");
        assert_eq!(HandlerRegistry::normalize_name("mysql_3306"), "mysql");
    }
}
