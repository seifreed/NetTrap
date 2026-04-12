//! Builder pattern for ListenerContext construction.
//!
//! This module provides a fluent API for constructing ListenerContext instances,
//! following the Builder pattern.

use std::path::PathBuf;

use crate::custom_response::CustomResponseConfig;
use crate::listener_config::ListenerConfig;
use crate::listener_runtime::{ListenerRuntime, ListenerSecurity};
use crate::process_filter::ProcessFilter;

use super::ListenerContext;

/// Builder for creating ListenerContext instances.
///
/// # Example
///
/// ```ignore
/// let ctx = ListenerContext::builder()
///     .name("dns")
///     .port(53)
///     .build(security, runtime);
/// ```
#[derive(Default)]
pub struct ListenerContextBuilder {
    name: Option<String>,
    port: Option<u16>,
    banner: Option<String>,
    webroot: Option<String>,
    ftproot: Option<String>,
    tftproot: Option<String>,
    execute_cmd: Option<String>,
    use_ssl: bool,
    dump_http_posts: bool,
    dump_prefix: Option<String>,
    timeout_ms: u64,
    response_delay_ms: u64,
    custom_response: Option<String>,
    server_version: Option<String>,
    dns_response_mode: Option<String>,
    dns_response_ip: Option<String>,
    dns_response_mx: Option<String>,
    dns_response_txt: Option<String>,
    dns_nxdomains: Option<u32>,
    pasv_ports: Option<String>,
    max_connections: Option<u32>,
    banner_delay_ms: u64,
    smtp_dir: Option<PathBuf>,
    log_hexdump: bool,
    process_filter: Option<ProcessFilter>,
    host_whitelist: Vec<String>,
    host_blacklist: Vec<String>,
}

impl ListenerContextBuilder {
    pub fn new() -> Self {
        Self {
            timeout_ms: 30000,
            ..Default::default()
        }
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn banner(mut self, banner: Option<String>) -> Self {
        self.banner = banner;
        self
    }

    pub fn webroot(mut self, webroot: Option<String>) -> Self {
        self.webroot = webroot;
        self
    }

    pub fn ftproot(mut self, ftproot: Option<String>) -> Self {
        self.ftproot = ftproot;
        self
    }

    pub fn tftproot(mut self, tftproot: Option<String>) -> Self {
        self.tftproot = tftproot;
        self
    }

    pub fn execute_cmd(mut self, cmd: Option<String>) -> Self {
        self.execute_cmd = cmd;
        self
    }

    pub fn use_ssl(mut self, use_ssl: bool) -> Self {
        self.use_ssl = use_ssl;
        self
    }

    pub fn dump_http_posts(mut self, dump: bool) -> Self {
        self.dump_http_posts = dump;
        self
    }

    pub fn dump_prefix(mut self, prefix: Option<String>) -> Self {
        self.dump_prefix = prefix;
        self
    }

    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    pub fn response_delay_ms(mut self, ms: u64) -> Self {
        self.response_delay_ms = ms;
        self
    }

    pub fn custom_response(mut self, response: Option<String>) -> Self {
        self.custom_response = response;
        self
    }

    pub fn server_version(mut self, version: Option<String>) -> Self {
        self.server_version = version;
        self
    }

    pub fn dns_response_mode(mut self, mode: Option<String>) -> Self {
        self.dns_response_mode = mode;
        self
    }

    pub fn dns_response_ip(mut self, ip: Option<String>) -> Self {
        self.dns_response_ip = ip;
        self
    }

    pub fn dns_response_mx(mut self, mx: Option<String>) -> Self {
        self.dns_response_mx = mx;
        self
    }

    pub fn dns_response_txt(mut self, txt: Option<String>) -> Self {
        self.dns_response_txt = txt;
        self
    }

    pub fn dns_nxdomains(mut self, nxdomains: Option<u32>) -> Self {
        self.dns_nxdomains = nxdomains;
        self
    }

    pub fn pasv_ports(mut self, ports: Option<String>) -> Self {
        self.pasv_ports = ports;
        self
    }

    pub fn banner_delay_ms(mut self, ms: u64) -> Self {
        self.banner_delay_ms = ms;
        self
    }

    pub fn smtp_dir(mut self, dir: Option<PathBuf>) -> Self {
        self.smtp_dir = dir;
        self
    }

    pub fn log_hexdump(mut self, enabled: bool) -> Self {
        self.log_hexdump = enabled;
        self
    }

    pub fn process_filter(mut self, filter: ProcessFilter) -> Self {
        self.process_filter = Some(filter);
        self
    }

    pub fn host_whitelist(mut self, whitelist: Vec<String>) -> Self {
        self.host_whitelist = whitelist;
        self
    }

    pub fn host_blacklist(mut self, blacklist: Vec<String>) -> Self {
        self.host_blacklist = blacklist;
        self
    }

    pub fn max_connections(mut self, max: Option<u32>) -> Self {
        self.max_connections = max;
        self
    }

    pub fn build(self, security: ListenerSecurity, runtime: ListenerRuntime) -> ListenerContext {
        let custom_response_config = self
            .custom_response
            .as_ref()
            .map(|s| CustomResponseConfig::parse(s));

        let config = ListenerConfig {
            name: self.name.unwrap_or_default(),
            port: self.port.unwrap_or(0),
            banner: self.banner,
            webroot: self.webroot,
            ftproot: self.ftproot,
            tftproot: self.tftproot,
            execute_cmd: self.execute_cmd,
            use_ssl: self.use_ssl,
            dump_http_posts: self.dump_http_posts,
            dump_prefix: self.dump_prefix,
            timeout_ms: self.timeout_ms,
            response_delay_ms: self.response_delay_ms,
            custom_response: self.custom_response,
            custom_response_config,
            server_version: self.server_version,
            dns_response_mode: self.dns_response_mode,
            dns_response_ip: self.dns_response_ip,
            dns_response_mx: self.dns_response_mx,
            dns_response_txt: self.dns_response_txt,
            dns_nxdomains: self.dns_nxdomains,
            pasv_ports: self.pasv_ports,
            max_connections: self.max_connections,
            banner_delay_ms: self.banner_delay_ms,
            smtp_dir: self.smtp_dir,
            log_hexdump: self.log_hexdump,
        };

        ListenerContext::new(config, security, runtime)
    }
}
