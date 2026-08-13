use std::collections::HashSet;
use std::net::IpAddr;

use nettrap_core::prelude::Protocol;

use super::parsing::{
    NormalizedBindAddr, normalize_bind_addr, parse_bind_address, parse_optional_socket_addr,
    protocol_label, socket_bindings_overlap,
};
use super::{EngineConfig, ListenerConfig};

impl EngineConfig {
    pub(crate) fn listener_name_matches_protocol(listener_name: &str, protocol: &str) -> bool {
        if listener_name.trim_matches([' ', '\t']) != listener_name
            || listener_name.is_empty()
            || listener_name
                .chars()
                .any(|ch| ch.is_control() || (ch.is_whitespace() && !matches!(ch, ' ' | '\t')))
        {
            return false;
        }

        let listener = match listener_name.to_ascii_lowercase().as_str() {
            "echo" => "raw".to_string(),
            other if other.starts_with("echo-") || other.starts_with("echo_") => {
                format!("raw{}", &other["echo".len()..])
            }
            other => other.to_string(),
        };
        listener == protocol
            || listener
                .strip_prefix(protocol)
                .and_then(|suffix| suffix.as_bytes().first().copied())
                .is_some_and(|byte| matches!(byte, b'-' | b'_'))
    }

    pub(crate) fn validate_listener_name(listener_name: &str) -> crate::Result<()> {
        if listener_name.trim_matches([' ', '\t']) != listener_name
            || listener_name.is_empty()
            || listener_name
                .chars()
                .any(|ch| ch.is_control() || (ch.is_whitespace() && !matches!(ch, ' ' | '\t')))
        {
            return Err(crate::Error::Config(format!(
                "Listener name '{}' is invalid",
                listener_name
            )));
        }

        Ok(())
    }

    /// Expand all listeners with port ranges into individual listeners.
    pub fn expand_listeners(&mut self) -> crate::Result<()> {
        let mut expanded = Vec::new();
        for listener in &self.listeners {
            expanded.extend(listener.expand_port_range()?);
        }
        self.listeners = expanded;
        self.normalize_listener_names();
        Ok(())
    }

    pub(crate) fn finalize_listener_names(&mut self) -> crate::Result<()> {
        self.prepare_listener_names()?;
        self.validate_socket_collisions()?;
        Ok(())
    }

    pub(crate) fn prepare_listener_names(&mut self) -> crate::Result<()> {
        self.normalize_listener_names();
        self.resolve_redirect_defaults()?;
        Ok(())
    }

    pub(crate) fn normalize_listener_names(&mut self) {
        let mut used_names = HashSet::new();
        self.listener_name_aliases.clear();

        for listener in &mut self.listeners {
            let normalized = Self::normalize_listener_name_key(&listener.name);
            let original = listener.name.clone();

            if !used_names.insert(normalized) {
                let base = format!("{}_{}", original, listener.port);
                let mut candidate = base.clone();
                let mut suffix = 2u32;

                while !used_names.insert(Self::normalize_listener_name_key(&candidate)) {
                    candidate = format!("{}_{}", base, suffix);
                    suffix += 1;
                }

                tracing::warn!(
                    "Duplicate listener name '{}' detected; renaming listener on port {} to '{}'",
                    original,
                    listener.port,
                    candidate
                );
                listener.name = candidate;
            }

            let aliases = self
                .listener_name_aliases
                .entry(Self::normalize_listener_name_key(&original))
                .or_default();
            if !aliases
                .iter()
                .any(|name| Self::same_listener_name(name, listener.name.as_str()))
            {
                aliases.push(listener.name.clone());
            }
        }
    }

    fn resolve_redirect_defaults(&mut self) -> crate::Result<()> {
        self.default_tcp_listener = self
            .default_tcp_listener
            .as_deref()
            .map(|listener| {
                let trimmed = listener.trim_matches([' ', '\t']);
                if trimmed != listener {
                    return Err(crate::Error::Config(format!(
                        "redirect_all_traffic tcp default listener '{}' is invalid",
                        listener
                    )));
                }
                Ok(trimmed)
            })
            .transpose()?
            .filter(|listener| !listener.is_empty())
            .map(|listener| self.resolve_redirect_default(listener, Protocol::Tcp))
            .transpose()?;
        self.default_udp_listener = self
            .default_udp_listener
            .as_deref()
            .map(|listener| {
                let trimmed = listener.trim_matches([' ', '\t']);
                if trimmed != listener {
                    return Err(crate::Error::Config(format!(
                        "redirect_all_traffic udp default listener '{}' is invalid",
                        listener
                    )));
                }
                Ok(trimmed)
            })
            .transpose()?
            .filter(|listener| !listener.is_empty())
            .map(|listener| self.resolve_redirect_default(listener, Protocol::Udp))
            .transpose()?;
        Ok(())
    }

    fn resolve_redirect_default(
        &self,
        requested_name: &str,
        protocol: Protocol,
    ) -> crate::Result<String> {
        let requested_name = requested_name.trim_matches([' ', '\t']);
        if requested_name.is_empty()
            || requested_name
                .chars()
                .any(|ch| ch.is_whitespace() && !matches!(ch, ' ' | '\t'))
        {
            return Err(crate::Error::Config(format!(
                "redirect_all_traffic {} default listener '{}' is invalid",
                protocol_label(protocol),
                requested_name
            )));
        }

        let alias_matches: Vec<&ListenerConfig> = self
            .listener_name_aliases
            .get(&Self::normalize_listener_name_key(requested_name))
            .into_iter()
            .flat_map(|aliases| aliases.iter())
            .filter_map(|alias| {
                self.listeners.iter().find(|listener| {
                    listener.protocol == protocol && Self::same_listener_name(&listener.name, alias)
                })
            })
            .collect();

        if alias_matches.len() > 1 {
            return Err(crate::Error::Config(format!(
                "redirect_all_traffic {} default listener '{}' became ambiguous after listener name normalization",
                protocol_label(protocol),
                requested_name
            )));
        }

        if let Some(listener) = alias_matches.first() {
            self.validate_redirect_default_is_spawnable(requested_name, protocol, listener)?;
            return Ok(listener.name.clone());
        }

        let exact_matches: Vec<&ListenerConfig> = self
            .listeners
            .iter()
            .filter(|listener| {
                listener.protocol == protocol
                    && Self::same_listener_name(&listener.name, requested_name)
            })
            .collect();

        if exact_matches.len() == 1 {
            self.validate_redirect_default_is_spawnable(
                requested_name,
                protocol,
                exact_matches[0],
            )?;
            return Ok(exact_matches[0].name.clone());
        }

        if exact_matches.len() > 1 {
            return Err(crate::Error::Config(format!(
                "redirect_all_traffic {} default listener '{}' is ambiguous",
                protocol_label(protocol),
                requested_name
            )));
        }

        if self.redirect_all_traffic {
            return Err(crate::Error::Config(format!(
                "redirect_all_traffic requires a valid {} default listener, but '{}' does not match a configured {} listener",
                protocol_label(protocol),
                requested_name,
                protocol_label(protocol),
            )));
        }

        Err(crate::Error::Config(format!(
            "{} default listener '{}' does not match a configured {} listener",
            protocol_label(protocol),
            requested_name,
            protocol_label(protocol),
        )))
    }

    fn normalize_listener_name_key(value: &str) -> String {
        value.to_lowercase()
    }

    fn same_listener_name(left: &str, right: &str) -> bool {
        Self::normalize_listener_name_key(left) == Self::normalize_listener_name_key(right)
    }

    fn validate_redirect_default_is_spawnable(
        &self,
        requested_name: &str,
        protocol: Protocol,
        listener: &ListenerConfig,
    ) -> crate::Result<()> {
        let is_tcp = matches!(protocol, Protocol::Tcp);
        if self.redirect_all_traffic
            && (!listener.enabled || self.is_port_blacklisted(listener.port, is_tcp))
        {
            return Err(crate::Error::Config(format!(
                "redirect_all_traffic requires a valid {} default listener, but '{}' does not resolve to a spawnable {} listener",
                protocol_label(protocol),
                requested_name,
                protocol_label(protocol),
            )));
        }
        Ok(())
    }

    fn validate_socket_collisions(&self) -> crate::Result<()> {
        let mut sockets: Vec<RegisteredSocket> = Vec::new();

        #[derive(Clone)]
        struct RegisteredSocket {
            protocol: Protocol,
            bind_addr: IpAddr,
            port: u16,
            owner: String,
        }

        let mut register_socket = |protocol: Protocol,
                                   bind_addr: IpAddr,
                                   port: u16,
                                   owner: String|
         -> crate::Result<()> {
            if let Some(existing) = sockets.iter().find(|existing| {
                socket_bindings_overlap(
                    existing.protocol,
                    existing.bind_addr,
                    existing.port,
                    protocol,
                    bind_addr,
                    port,
                )
            }) {
                if Self::socket_bindings_equal(existing.bind_addr, bind_addr) {
                    return Err(crate::Error::Config(format!(
                        "{} and {} both resolve to {} socket {}:{}",
                        existing.owner,
                        owner,
                        protocol_label(protocol),
                        Self::canonical_bind_addr(bind_addr),
                        port
                    )));
                }

                return Err(crate::Error::Config(format!(
                    "{} and {} overlap on {} socket port {} ({} vs {})",
                    existing.owner,
                    owner,
                    protocol_label(protocol),
                    port,
                    Self::canonical_bind_addr(existing.bind_addr),
                    Self::canonical_bind_addr(bind_addr)
                )));
            }

            sockets.push(RegisteredSocket {
                protocol,
                bind_addr,
                port,
                owner,
            });
            Ok(())
        };

        for listener in self
            .listeners
            .iter()
            .filter(|listener| self.listener_is_spawnable(listener))
        {
            let bind_addr = parse_bind_address(&listener.bind_address)?;
            register_socket(
                listener.protocol,
                bind_addr,
                listener.port,
                format!("listener '{}'", listener.name),
            )?;
        }

        if let Some(addr) = parse_optional_socket_addr("api_bind", self.api_bind.as_deref())? {
            register_socket(
                Protocol::Tcp,
                addr.ip(),
                addr.port(),
                "api_bind".to_string(),
            )?;
        }

        if let Some(addr) = parse_optional_socket_addr(
            "distributed.health_bind",
            self.distributed.health_bind.as_deref(),
        )? {
            register_socket(
                Protocol::Tcp,
                addr.ip(),
                addr.port(),
                "distributed.health_bind".to_string(),
            )?;
        }

        if let Some(addr) = parse_optional_socket_addr(
            "distributed.metrics_bind",
            self.distributed.metrics_bind.as_deref(),
        )? {
            register_socket(
                Protocol::Tcp,
                addr.ip(),
                addr.port(),
                "distributed.metrics_bind".to_string(),
            )?;
        }

        Ok(())
    }

    fn socket_bindings_equal(left: IpAddr, right: IpAddr) -> bool {
        normalize_bind_addr(left) == normalize_bind_addr(right)
    }

    fn canonical_bind_addr(addr: IpAddr) -> String {
        match normalize_bind_addr(addr) {
            NormalizedBindAddr::V4(ip) => ip.to_string(),
            NormalizedBindAddr::V6(ip) => ip.to_string(),
        }
    }

    pub(crate) fn listener_is_default_target(&self, listener: &ListenerConfig) -> bool {
        match listener.protocol {
            Protocol::Tcp => self
                .default_tcp_listener
                .as_deref()
                .is_some_and(|name| name.to_lowercase() == listener.name.to_lowercase()),
            Protocol::Udp => self
                .default_udp_listener
                .as_deref()
                .is_some_and(|name| name.to_lowercase() == listener.name.to_lowercase()),
            _ => false,
        }
    }

    fn listener_is_spawnable(&self, listener: &ListenerConfig) -> bool {
        if !listener.enabled {
            return false;
        }

        if listener.hidden && !self.listener_is_default_target(listener) {
            return false;
        }

        let is_tcp = listener.protocol == Protocol::Tcp;
        !self.is_port_blacklisted(listener.port, is_tcp)
    }

    /// Check if a port is blacklisted.
    pub fn is_port_blacklisted(&self, port: u16, is_tcp: bool) -> bool {
        if is_tcp {
            self.blacklist_ports_tcp
                .iter()
                .any(|candidate| candidate == &port)
        } else {
            self.blacklist_ports_udp
                .iter()
                .any(|candidate| candidate == &port)
        }
    }
}
