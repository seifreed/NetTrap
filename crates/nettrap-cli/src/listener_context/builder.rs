//! Builder pattern for ListenerContext construction.
//!
//! This module provides a fluent API for constructing ListenerContext instances,
//! following the Builder pattern.

use std::path::PathBuf;

use crate::custom_response::CustomResponseConfig;
use crate::listener_config::ListenerConfig;
use crate::listener_runtime::{ListenerRuntime, ListenerSecurity};
use crate::listeners::tcp_framing::listener_name_matches_protocol;
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
pub struct ListenerContextBuilder {
    name: Option<String>,
    port: Option<u16>,
    banner: Option<String>,
    server_name: Option<String>,
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
    dns_ncsi_response_ip: Option<String>,
    pasv_ports: Option<String>,
    max_connections: Option<u32>,
    banner_delay_ms: u64,
    smtp_dir: Option<PathBuf>,
    log_hexdump: bool,
    process_filter: Option<ProcessFilter>,
    host_whitelist: Vec<String>,
    host_blacklist: Vec<String>,
}

impl Default for ListenerContextBuilder {
    fn default() -> Self {
        Self {
            name: None,
            port: None,
            banner: None,
            server_name: None,
            webroot: None,
            ftproot: None,
            tftproot: None,
            execute_cmd: None,
            use_ssl: false,
            dump_http_posts: false,
            dump_prefix: None,
            timeout_ms: 30000,
            response_delay_ms: 0,
            custom_response: None,
            server_version: None,
            dns_response_mode: None,
            dns_response_ip: None,
            dns_response_mx: None,
            dns_response_txt: None,
            dns_nxdomains: None,
            dns_ncsi_response_ip: None,
            pasv_ports: None,
            max_connections: Some(100),
            banner_delay_ms: 0,
            smtp_dir: None,
            log_hexdump: false,
            process_filter: None,
            host_whitelist: Vec::new(),
            host_blacklist: Vec::new(),
        }
    }
}

impl ListenerContextBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = normalize_required_string(name.into());
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn banner(mut self, banner: Option<String>) -> Self {
        self.banner = normalize_optional_string(banner);
        self
    }

    pub fn server_name(mut self, server_name: Option<String>) -> Self {
        self.server_name = normalize_optional_string(server_name);
        self
    }

    pub fn webroot(mut self, webroot: Option<String>) -> Self {
        self.webroot = normalize_optional_string(webroot);
        self
    }

    pub fn ftproot(mut self, ftproot: Option<String>) -> Self {
        self.ftproot = normalize_optional_string(ftproot);
        self
    }

    pub fn tftproot(mut self, tftproot: Option<String>) -> Self {
        self.tftproot = normalize_optional_string(tftproot);
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
        self.custom_response = normalize_optional_payload_string(response);
        self
    }

    pub fn server_version(mut self, version: Option<String>) -> Self {
        self.server_version = normalize_optional_string(version);
        self
    }

    pub fn dns_response_mode(mut self, mode: Option<String>) -> Self {
        self.dns_response_mode = normalize_optional_string(mode);
        self
    }

    pub fn dns_response_ip(mut self, ip: Option<String>) -> Self {
        self.dns_response_ip = normalize_optional_string(ip);
        self
    }

    pub fn dns_response_mx(mut self, mx: Option<String>) -> Self {
        self.dns_response_mx = normalize_optional_string(mx);
        self
    }

    pub fn dns_response_txt(mut self, txt: Option<String>) -> Self {
        self.dns_response_txt = normalize_optional_string(txt);
        self
    }

    pub fn dns_nxdomains(mut self, nxdomains: Option<u32>) -> Self {
        self.dns_nxdomains = nxdomains;
        self
    }

    pub fn dns_ncsi_response_ip(mut self, ip: Option<String>) -> Self {
        self.dns_ncsi_response_ip = normalize_optional_string(ip);
        self
    }

    pub fn pasv_ports(mut self, ports: Option<String>) -> Self {
        self.pasv_ports = normalize_optional_string(ports);
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

    pub fn build(
        self,
        security: ListenerSecurity,
        runtime: ListenerRuntime,
    ) -> crate::Result<ListenerContext> {
        if let Some(version) = self.server_version.as_deref() {
            if version.trim_matches([' ', '\t']) != version {
                return Err(crate::Error::Config(
                    "server_version must not be padded".to_string(),
                ));
            }
            if contains_control_or_unicode_separator(version) {
                return Err(crate::Error::Config(
                    "server_version contains unsafe control characters".to_string(),
                ));
            }
        }

        if let Some(response) = self.custom_response.as_deref()
            && response.chars().all(|ch| ch.is_whitespace())
        {
            return Err(crate::Error::Config(
                "custom_response must not be blank".to_string(),
            ));
        }

        if let Some(cmd) = self.execute_cmd.as_deref() {
            if cmd.chars().all(|ch| ch.is_whitespace()) {
                return Err(crate::Error::Config(
                    "execute_cmd must not be blank".to_string(),
                ));
            }
            if contains_control_or_unicode_separator(cmd) {
                return Err(crate::Error::Config(
                    "execute_cmd contains control characters or unicode separators".to_string(),
                ));
            }
        }

        if let Some(prefix) = self.dump_prefix.as_deref() {
            if prefix.chars().all(|ch| ch.is_whitespace()) {
                return Err(crate::Error::Config(
                    "dump_http_posts_prefix must not be blank".to_string(),
                ));
            }
            if contains_control_or_unicode_separator(prefix) {
                return Err(crate::Error::Config(
                    "dump_http_posts_prefix contains control characters or unicode separators"
                        .to_string(),
                ));
            }
        }

        let name = self
            .name
            .ok_or_else(|| crate::Error::Config("listener name is required".to_string()))?;
        let port = self
            .port
            .ok_or_else(|| crate::Error::Config("listener port is required".to_string()))?;
        let custom_response_config =
            self.custom_response
                .as_ref()
                .and_then(|s| {
                    if listener_name_matches_protocol(&name, "http")
                        || listener_name_matches_protocol(&name, "https")
                    {
                        Some(CustomResponseConfig::parse(s).and_then(|cfg| {
                            cfg.with_server_version(self.server_version.as_deref())
                        }))
                    } else {
                        None
                    }
                })
                .transpose()?;
        let config = ListenerConfig {
            name,
            port,
            banner: self.banner,
            server_name: self.server_name,
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
            dns_ncsi_response_ip: self.dns_ncsi_response_ip,
            pasv_ports: self.pasv_ports,
            max_connections: self.max_connections,
            banner_delay_ms: self.banner_delay_ms,
            smtp_dir: self.smtp_dir,
            log_hexdump: self.log_hexdump,
        };

        Ok(ListenerContext::new(config, security, runtime))
    }
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    let value = value?;
    if value.is_empty() || value.chars().all(|ch| ch.is_whitespace()) {
        None
    } else {
        Some(value)
    }
}

fn normalize_optional_payload_string(value: Option<String>) -> Option<String> {
    value
}

fn contains_control_or_unicode_separator(value: &str) -> bool {
    value
        .chars()
        .any(|ch| ch.is_control() || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
}

fn normalize_required_string(value: String) -> Option<String> {
    if value.is_empty() || value.chars().all(|ch| ch.is_whitespace()) {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
    use crate::process_filter::ProcessFilter;
    use crate::session::{PortForwardTable, SessionTracker};

    fn test_security() -> ListenerSecurity {
        ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
            .expect("empty host rules should compile")
    }

    fn test_runtime() -> ListenerRuntime {
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
        })
    }

    #[test]
    fn build_rejects_missing_listener_name() {
        let err = match ListenerContextBuilder::new()
            .port(80)
            .build(test_security(), test_runtime())
        {
            Ok(_) => panic!("missing name should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("listener name is required"));
    }

    #[test]
    fn build_rejects_missing_listener_port() {
        let err = match ListenerContextBuilder::new()
            .name("http")
            .build(test_security(), test_runtime())
        {
            Ok(_) => panic!("missing port should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("listener port is required"));
    }

    #[test]
    fn build_accepts_raw_custom_response_shorthand_without_http_rules() {
        let context = ListenerContextBuilder::new()
            .name("udp")
            .port(53)
            .custom_response(Some("static:pong".to_string()))
            .build(test_security(), test_runtime())
            .expect("raw shorthand should not require HTTP rule parsing");

        assert_eq!(context.custom_response(), Some("static:pong"));
    }

    #[test]
    fn build_accepts_silent_custom_response_without_http_rules() {
        let context = ListenerContextBuilder::new()
            .name("udp")
            .port(53)
            .custom_response(Some("silent".to_string()))
            .build(test_security(), test_runtime())
            .expect("silent shorthand should not require HTTP rule parsing");

        assert_eq!(context.custom_response(), Some("silent"));
    }

    #[test]
    fn build_keeps_raw_custom_response_with_key_like_text_inside_body() {
        let context = ListenerContextBuilder::new()
            .name("udp")
            .port(53)
            .custom_response(Some("silent path=/tmp".to_string()))
            .build(test_security(), test_runtime())
            .expect("raw custom response should not be parsed as HTTP rules");

        assert_eq!(context.custom_response(), Some("silent path=/tmp"));
        assert!(context.config.custom_response_config.is_none());
    }

    #[test]
    fn build_keeps_raw_custom_response_with_embedded_rule_like_fields() {
        let context = ListenerContextBuilder::new()
            .name("udp")
            .port(53)
            .custom_response(Some("silent; host=example.test; type=static".to_string()))
            .build(test_security(), test_runtime())
            .expect("raw custom response should not be parsed as HTTP rules");

        assert_eq!(
            context.custom_response(),
            Some("silent; host=example.test; type=static")
        );
        assert!(context.config.custom_response_config.is_none());
    }

    #[test]
    fn build_keeps_raw_custom_response_with_rule_like_prefix_and_no_separator() {
        let context = ListenerContextBuilder::new()
            .name("udp")
            .port(53)
            .custom_response(Some("host=example.test".to_string()))
            .build(test_security(), test_runtime())
            .expect("raw custom response should not be parsed as HTTP rules");

        assert_eq!(context.custom_response(), Some("host=example.test"));
        assert!(context.config.custom_response_config.is_none());
    }

    #[test]
    fn build_keeps_raw_custom_response_with_late_rule_like_fields() {
        let context = ListenerContextBuilder::new()
            .name("udp")
            .port(53)
            .custom_response(Some("foo=bar;host=example.test;uri=/gate".to_string()))
            .build(test_security(), test_runtime())
            .expect("raw custom response should not be parsed as HTTP rules");

        assert_eq!(
            context.custom_response(),
            Some("foo=bar;host=example.test;uri=/gate")
        );
        assert!(context.config.custom_response_config.is_none());
    }

    #[test]
    fn build_keeps_raw_custom_response_with_type_body_suffix() {
        let context = ListenerContextBuilder::new()
            .name("udp")
            .port(53)
            .custom_response(Some("foo=bar;type=static;body=OK".to_string()))
            .build(test_security(), test_runtime())
            .expect("raw custom response should not be parsed as HTTP rules");

        assert_eq!(
            context.custom_response(),
            Some("foo=bar;type=static;body=OK")
        );
        assert!(context.config.custom_response_config.is_none());
    }

    #[test]
    fn build_keeps_raw_custom_response_with_dns_domain_named_host() {
        let context = ListenerContextBuilder::new()
            .name("udp")
            .port(53)
            .custom_response(Some("host=1.2.3.4;example.net=5.6.7.8".to_string()))
            .build(test_security(), test_runtime())
            .expect("dns custom response should not be parsed as HTTP rules");

        assert_eq!(
            context.custom_response(),
            Some("host=1.2.3.4;example.net=5.6.7.8")
        );
        assert!(context.config.custom_response_config.is_none());
    }

    #[test]
    fn build_parses_http_custom_response_with_numeric_uri_matcher() {
        let context = ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .custom_response(Some("host=1.2.3.4;uri=5.6.7.8".to_string()))
            .build(test_security(), test_runtime())
            .expect("HTTP rules should be parsed even when values look numeric");

        let parsed = context
            .config
            .custom_response_config
            .as_ref()
            .expect("HTTP rules should produce a parsed config");
        assert!(parsed.find_match("1.2.3.4", "5.6.7.8").is_some());
    }

    #[test]
    fn build_parses_http_custom_response_without_explicit_type_when_host_and_uri_match() {
        let context = ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .custom_response(Some("host=example.test;uri=/gate".to_string()))
            .build(test_security(), test_runtime())
            .expect("host+uri HTTP rules should still parse");

        let parsed = context
            .config
            .custom_response_config
            .as_ref()
            .expect("HTTP rules should produce a parsed config");
        assert!(parsed.find_match("example.test", "/gate").is_some());
    }

    #[test]
    fn build_parses_http_custom_response_without_semicolon_when_host_and_uri_match() {
        let context = ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .custom_response(Some("host=example.test,uri=/gate".to_string()))
            .build(test_security(), test_runtime())
            .expect("compact host+uri HTTP rules should still parse");

        let parsed = context
            .config
            .custom_response_config
            .as_ref()
            .expect("HTTP rules should produce a parsed config");
        assert!(parsed.find_match("example.test", "/gate").is_some());
    }

    #[test]
    fn build_parses_http_custom_response_with_body_only_rule() {
        let context = ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .custom_response(Some("body=OK".to_string()))
            .build(test_security(), test_runtime())
            .expect("body-only HTTP rules should parse");

        let parsed = context
            .config
            .custom_response_config
            .as_ref()
            .expect("HTTP rules should produce a parsed config");
        assert!(
            parsed
                .build_response_for_request("example.test", "/", "/")
                .is_some()
        );
    }

    #[test]
    fn build_keeps_raw_custom_response_with_body_prefix_on_non_http_listener() {
        let context = ListenerContextBuilder::new()
            .name("udp")
            .port(53)
            .custom_response(Some("body=OK".to_string()))
            .build(test_security(), test_runtime())
            .expect("raw custom response should stay raw on non-HTTP listeners");

        assert_eq!(context.custom_response(), Some("body=OK"));
        assert!(context.config.custom_response_config.is_none());
    }

    #[test]
    fn build_rejects_malformed_custom_response_rules_instead_of_treating_them_as_raw() {
        let result = ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .custom_response(Some("typo=static;host=example.test;body=OK".to_string()))
            .build(test_security(), test_runtime());

        let err = match result {
            Ok(_) => panic!("malformed rule-like custom response should fail"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("Unknown custom response rule field"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn build_keeps_raw_custom_response_with_equals_but_no_rule_fields() {
        let context = ListenerContextBuilder::new()
            .name("udp")
            .port(53)
            .custom_response(Some("foo=bar;baz".to_string()))
            .build(test_security(), test_runtime())
            .expect("raw custom response should not be parsed as HTTP rules");

        assert_eq!(context.custom_response(), Some("foo=bar;baz"));
        assert!(context.config.custom_response_config.is_none());
    }

    #[test]
    fn build_normalizes_blank_string_options_to_none() {
        let context = ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .banner(Some("   ".to_string()))
            .server_name(Some("\t".to_string()))
            .webroot(Some("".to_string()))
            .ftproot(Some(" ".to_string()))
            .tftproot(Some("\n".to_string()))
            .server_version(Some(" ".to_string()))
            .dns_response_mode(Some("".to_string()))
            .dns_response_ip(Some(" ".to_string()))
            .dns_response_mx(Some("".to_string()))
            .dns_response_txt(Some(" ".to_string()))
            .dns_ncsi_response_ip(Some("".to_string()))
            .pasv_ports(Some(" ".to_string()))
            .build(test_security(), test_runtime())
            .expect("blank string options should be normalized away");

        assert!(context.banner().is_none());
        assert!(context.config.server_name.is_none());
        assert!(context.webroot().is_none());
        assert!(context.ftproot().is_none());
        assert!(context.tftproot().is_none());
        assert!(context.server_version().is_none());
        assert!(context.config.dns_response_mode.is_none());
        assert!(context.config.dns_response_ip.is_none());
        assert!(context.config.dns_response_mx.is_none());
        assert!(context.config.dns_response_txt.is_none());
        assert!(context.config.dns_ncsi_response_ip.is_none());
        assert!(context.config.pasv_ports.is_none());
        assert!(context.config.custom_response.is_none());
    }

    #[test]
    fn build_rejects_blank_dump_prefix() {
        let result = ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .dump_prefix(Some(" \t ".to_string()))
            .build(test_security(), test_runtime());

        match result {
            Ok(_) => panic!("blank dump prefix should fail"),
            Err(err) => assert!(
                err.to_string()
                    .contains("dump_http_posts_prefix must not be blank")
            ),
        }
    }

    #[test]
    fn build_rejects_blank_execute_cmd() {
        let result = ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .execute_cmd(Some("\t".to_string()))
            .build(test_security(), test_runtime());

        match result {
            Ok(_) => panic!("blank execute_cmd should fail"),
            Err(err) => assert!(
                err.to_string().contains("execute_cmd must not be blank"),
                "unexpected error: {err}"
            ),
        }
    }

    #[test]
    fn build_rejects_blank_custom_response_payload() {
        let result = ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .custom_response(Some("\n".to_string()))
            .build(test_security(), test_runtime());

        match result {
            Ok(_) => panic!("blank custom_response should fail"),
            Err(err) => assert!(
                err.to_string()
                    .contains("custom_response must not be blank"),
                "unexpected error: {err}"
            ),
        }
    }

    #[test]
    fn build_preserves_newlines_in_static_custom_response_body() {
        let context = ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .custom_response(Some("type=static;body=line one\nline two".to_string()))
            .build(test_security(), test_runtime())
            .expect("static custom response body may contain newlines");

        assert_eq!(
            context.custom_response(),
            Some("type=static;body=line one\nline two")
        );
        assert!(
            context.config.custom_response_config.is_some(),
            "custom response rules should still be parsed"
        );
    }

    #[test]
    fn build_normalizes_unicode_whitespace_string_options_to_none() {
        let context = ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .banner(Some("banner\u{00a0}".to_string()))
            .server_name(Some("server\u{00a0}".to_string()))
            .build(test_security(), test_runtime())
            .expect("unicode whitespace string options should be preserved");

        assert_eq!(context.banner(), Some("banner\u{00a0}"));
        assert_eq!(
            context.config.server_name.as_deref(),
            Some("server\u{00a0}")
        );
    }

    #[test]
    fn build_rejects_ascii_padded_server_version() {
        let err = match ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .server_version(Some(" Apache/2.4.99 ".to_string()))
            .build(test_security(), test_runtime())
        {
            Ok(_) => panic!("padded server_version should fail"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("server_version must not be padded")
        );
    }

    #[test]
    fn build_rejects_control_characters_in_server_version() {
        let err = match ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .custom_response(Some("host=*;uri=*;type=static;body=OK".to_string()))
            .server_version(Some("Apache\n2.4.99".to_string()))
            .build(test_security(), test_runtime())
        {
            Ok(_) => panic!("control bytes in server_version should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("server_version"));
    }

    #[test]
    fn build_rejects_control_characters_in_server_version_without_custom_response() {
        let err = match ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .server_version(Some("Apache\n2.4.99".to_string()))
            .build(test_security(), test_runtime())
        {
            Ok(_) => panic!("control bytes in server_version should fail"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("server_version contains unsafe control characters")
        );
    }

    #[test]
    fn build_rejects_blank_listener_name() {
        let err = match ListenerContextBuilder::new()
            .name("   ")
            .port(80)
            .build(test_security(), test_runtime())
        {
            Ok(_) => panic!("blank listener name should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("listener name is required"));
    }

    #[test]
    fn build_preserves_unicode_whitespace_listener_name() {
        let context = match ListenerContextBuilder::new()
            .name("ssh\u{00a0}")
            .port(22)
            .build(test_security(), test_runtime())
        {
            Ok(context) => context,
            Err(err) => panic!("unicode whitespace listener name should build: {err}"),
        };

        assert_eq!(context.name(), "ssh\u{00a0}");
    }

    #[test]
    fn build_preserves_c1_controls_in_listener_name() {
        let context = match ListenerContextBuilder::new()
            .name("ssh\u{009f}")
            .port(22)
            .build(test_security(), test_runtime())
        {
            Ok(context) => context,
            Err(err) => panic!("C1 control listener name should build: {err}"),
        };

        assert_eq!(context.name(), "ssh\u{009f}");
    }

    #[test]
    fn build_preserves_spaced_listener_name() {
        let context = match ListenerContextBuilder::new()
            .name("  http  ")
            .port(80)
            .build(test_security(), test_runtime())
        {
            Ok(context) => context,
            Err(err) => panic!("padded listener name should build: {err}"),
        };

        assert_eq!(context.name(), "  http  ");
    }

    #[test]
    fn build_preserves_spaced_optional_string_values() {
        let context = ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .banner(Some("  banner  ".to_string()))
            .server_name(Some("  server  ".to_string()))
            .dump_prefix(Some("  dumps  ".to_string()))
            .execute_cmd(Some("  echo hello  ".to_string()))
            .build(test_security(), test_runtime())
            .expect("spaced optional values should be preserved");

        assert_eq!(context.banner(), Some("  banner  "));
        assert_eq!(context.config.server_name.as_deref(), Some("  server  "));
        assert_eq!(context.dump_prefix(), Some("  dumps  "));
        assert_eq!(
            context.config.execute_cmd.as_deref(),
            Some("  echo hello  ")
        );
    }

    #[test]
    fn build_preserves_unicode_line_separators_in_banner_option() {
        let context = ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .banner(Some("banner\u{2028}next".to_string()))
            .build(test_security(), test_runtime())
            .expect("builder should preserve banner text");

        assert_eq!(context.banner(), Some("banner\u{2028}next"));
    }

    #[test]
    fn build_rejects_control_characters_in_execute_cmd() {
        let result = ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .execute_cmd(Some("echo\nnext".to_string()))
            .build(test_security(), test_runtime());

        match result {
            Ok(_) => panic!("control characters in execute_cmd should fail"),
            Err(err) => assert!(
                err.to_string()
                    .contains("execute_cmd contains control characters or unicode separators")
            ),
        }
    }

    #[test]
    fn build_rejects_control_characters_in_dump_prefix() {
        let result = ListenerContextBuilder::new()
            .name("http")
            .port(80)
            .dump_prefix(Some("spool\n".to_string()))
            .build(test_security(), test_runtime());

        match result {
            Ok(_) => panic!("control characters in dump_prefix should fail"),
            Err(err) => assert!(err.to_string().contains(
                "dump_http_posts_prefix contains control characters or unicode separators"
            )),
        }
    }

    #[test]
    fn build_defaults_max_connections_to_hundred_when_unset() {
        let context = ListenerContextBuilder::default()
            .name("http")
            .port(80)
            .build(test_security(), test_runtime())
            .expect("builder should use bounded default max connections");

        assert_eq!(context.max_connections(), Some(100));
    }
}
