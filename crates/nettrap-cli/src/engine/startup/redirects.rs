use nettrap_core::prelude::Protocol;

use super::super::spawn::listener_should_spawn;
use crate::config::EngineConfig;
use crate::listeners::tcp_framing::listener_name_matches_protocol;
use crate::listeners::udp_listener::explicit_udp_protocol_name;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ValidatedRedirectDefaults {
    pub(super) tcp: Option<ValidatedDefaultListener>,
    pub(super) udp: Option<ValidatedDefaultListener>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ValidatedDefaultListener {
    name: String,
    port: u16,
}

pub(super) fn validate_redirect_defaults(
    config: &EngineConfig,
) -> crate::Result<ValidatedRedirectDefaults> {
    if !config.redirect_all_traffic {
        return Ok(ValidatedRedirectDefaults::default());
    }

    let tcp = validate_redirect_default_listener(
        config,
        config.default_tcp_listener.as_deref(),
        Protocol::Tcp,
    )?;
    let udp = validate_redirect_default_listener(
        config,
        config.default_udp_listener.as_deref(),
        Protocol::Udp,
    )?;

    if tcp.is_none() && udp.is_none() {
        return Err(crate::Error::Config(
            "redirect_all_traffic requires at least one valid default listener".into(),
        ));
    }

    Ok(ValidatedRedirectDefaults { tcp, udp })
}

fn validate_redirect_default_listener(
    config: &EngineConfig,
    listener_name: Option<&str>,
    protocol: Protocol,
) -> crate::Result<Option<ValidatedDefaultListener>> {
    let Some(listener_name) = listener_name else {
        return Ok(None);
    };

    if listener_name.chars().all(char::is_whitespace) {
        return Ok(None);
    }
    if listener_name.trim_matches([' ', '\t']) != listener_name
        || listener_name
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && !matches!(ch, ' ' | '\t')))
    {
        return Err(crate::Error::Config(format!(
            "redirect_all_traffic requires a valid {} default listener, but '{}' is invalid",
            protocol_label(protocol),
            listener_name,
        )));
    }

    let mut listeners = spawnable_default_listeners(config, listener_name, protocol);
    let Some(listener) = listeners.next() else {
        return Err(crate::Error::Config(format!(
            "redirect_all_traffic requires a valid {} default listener, but '{}' does not resolve to a spawnable {} listener",
            protocol_label(protocol),
            listener_name,
            protocol_label(protocol),
        )));
    };

    if listeners.next().is_some() {
        return Err(crate::Error::Config(format!(
            "redirect_all_traffic requires an unambiguous {} default listener, but '{}' matches multiple spawnable {} listeners",
            protocol_label(protocol),
            listener_name,
            protocol_label(protocol),
        )));
    }

    Ok(Some(ValidatedDefaultListener {
        name: listener.name.clone(),
        port: listener.port,
    }))
}

fn spawnable_default_listeners<'a>(
    config: &'a EngineConfig,
    listener_name: &'a str,
    protocol: Protocol,
) -> impl Iterator<Item = &'a crate::config::ListenerConfig> + 'a {
    config.listeners.iter().filter(move |listener| {
        listener.protocol == protocol
            && same_listener_name(&listener.name, listener_name)
            && listener_should_spawn(config, listener)
    })
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn find_spawnable_default_listener<'a>(
    config: &'a EngineConfig,
    listener_name: &'a str,
    protocol: Protocol,
) -> Option<&'a crate::config::ListenerConfig> {
    let mut listeners = spawnable_default_listeners(config, listener_name, protocol);
    let listener = listeners.next()?;
    if listeners.next().is_some() {
        return None;
    }
    Some(listener)
}

fn same_listener_name(left: &str, right: &str) -> bool {
    left.to_lowercase() == right.to_lowercase()
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
pub(crate) fn resolve_default_listener_port(
    config: &EngineConfig,
    listener_name: &str,
    protocol: Protocol,
) -> Option<u16> {
    find_spawnable_default_listener(config, listener_name, protocol).map(|listener| listener.port)
}

fn protocol_label(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        _ => "unsupported",
    }
}

pub(super) fn init_protocol_router(
    defaults: &ValidatedRedirectDefaults,
) -> std::sync::Arc<nettrap_proxy::ProtocolRouter> {
    nettrap_proxy::ProtocolRouter::with_default_tastes(
        defaults
            .tcp
            .as_ref()
            .map(|listener| default_tcp_handler_name(&listener.name)),
        defaults
            .udp
            .as_ref()
            .map(|listener| default_udp_handler_name(&listener.name)),
    )
}

fn default_tcp_handler_name(listener_name: &str) -> String {
    if listener_name_matches_protocol(listener_name, "echo") {
        return "raw".to_string();
    }

    [
        "dns",
        "http",
        "https",
        "smtp",
        "smtps",
        "ftp",
        "ftps",
        "pop3",
        "pop3s",
        "imap",
        "imaps",
        "irc",
        "ircs",
        "telnet",
        "telnets",
        "finger",
        "ident",
        "daytime",
        "time",
        "chargen",
        "quotd",
        "syslogrecv",
        "dummy",
        "ssh",
        "smb",
        "rdp",
        "redis",
        "mysql",
        "ldap",
        "ldaps",
        "socks",
        "memcached",
        "mqtt",
        "tls",
        "ssl",
        "upnp",
        "nkn",
        "postgres",
        "raw",
    ]
    .into_iter()
    .find(|protocol| listener_name_matches_protocol(listener_name, protocol))
    .unwrap_or("raw")
    .to_string()
}

fn default_udp_handler_name(listener_name: &str) -> String {
    explicit_udp_protocol_name(listener_name)
        .unwrap_or("raw")
        .to_string()
}
