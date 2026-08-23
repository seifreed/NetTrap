mod io;
mod listeners;
mod model;
mod parsing;

use super::ListenerConfig;
pub use model::{CONFIG_VERSION, EngineConfig, FakeTimeConfig, NetworkMode};
pub use nettrap_core::{DatabaseConfig, DistributedConfig, EventSinkConfig};

use parsing::{
    canonicalize_bind_address, normalize_default_decision, normalize_optional_identifier,
    normalize_optional_path, normalize_optional_url, normalize_report_language,
    normalize_restrict_interface, validate_file_prefix_setting,
    validate_loopback_socket_addr_setting, validate_output_format_setting,
    validate_socket_addr_setting,
};

const MAX_ENGINE_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
const MAX_FILTER_RULES_PER_LIST: usize = 256;
const MAX_FILTER_RULE_BYTES: usize = 512;
const MAX_DISTRIBUTED_EVENT_SINKS: usize = 32;
const MAX_DISTRIBUTED_HTTP_SINK_BATCH_SIZE: usize = 1024;
const MAX_DISTRIBUTED_NODE_TAGS: usize = 64;
const MAX_DISTRIBUTED_NODE_TAG_BYTES: usize = 128;
const MAX_DNS_FLUSH_COMMAND_BYTES: usize = 512;
const MAX_LISTENER_TIMEOUT_MS: u64 = 60 * 60 * 1000;
const MAX_LISTENER_DELAY_MS: u64 = 60 * 60 * 1000;
const MAX_LISTENER_PASV_PORT_RANGE: u16 = 1000;

mod validation;

#[cfg(test)]
pub(crate) use validation::parse_listener_pasv_port;
use validation::{
    normalize_dns_flush_command, normalize_listener_directory_options,
    validate_distributed_config_bounds, validate_filter_rule_list,
    validate_listener_directory_options, validate_listener_optional_string_fields,
    validate_listener_pasv_ports, validate_listener_server_name, validate_listener_server_version,
    validate_listener_timing, validate_process_filter_rule_list,
};

impl EngineConfig {
    fn validate(&mut self) -> crate::Result<()> {
        self.validate_global_settings()?;
        self.prepare_listeners_for_runtime()?;
        Ok(())
    }

    fn validate_global_settings(&mut self) -> crate::Result<()> {
        if self.config_version != CONFIG_VERSION {
            return Err(crate::Error::Config(format!(
                "unsupported config_version {}; expected {}",
                self.config_version, CONFIG_VERSION
            )));
        }
        if self.database.pool_size == 0 {
            return Err(crate::Error::Config(
                "database.pool_size must be greater than 0".to_string(),
            ));
        }
        if self.attribution_timeout_ms == 0 && self.attribution_enabled {
            return Err(crate::Error::Config(
                "attribution_timeout_ms must be greater than 0 when attribution is enabled"
                    .to_string(),
            ));
        }
        self.validate_database_backend()?;
        if self.distributed.heartbeat_interval_secs > 0
            && self.distributed.control_plane_url.is_none()
        {
            return Err(crate::Error::Config(
                "distributed.heartbeat_interval_secs requires distributed.control_plane_url"
                    .to_string(),
            ));
        }

        validate_loopback_socket_addr_setting("api_bind", self.api_bind.as_deref())?;
        validate_socket_addr_setting(
            "distributed.health_bind",
            self.distributed.health_bind.as_deref(),
        )?;
        validate_socket_addr_setting(
            "distributed.metrics_bind",
            self.distributed.metrics_bind.as_deref(),
        )?;
        validate_output_format_setting(&self.output_format)?;
        normalize_default_decision(&mut self.default_decision)?;
        normalize_restrict_interface(&mut self.restrict_interface)?;
        normalize_report_language(&mut self.report_language)?;
        normalize_optional_identifier("database.node_id", &mut self.database.node_id)?;
        normalize_optional_identifier("distributed.node_id", &mut self.distributed.node_id)?;
        normalize_optional_identifier(
            "distributed.node_region",
            &mut self.distributed.node_region,
        )?;
        normalize_optional_url(&mut self.distributed.control_plane_url)?;
        normalize_optional_identifier(
            "distributed.control_plane_token",
            &mut self.distributed.control_plane_token,
        )?;
        normalize_optional_path("output_path", &mut self.output_path)?;
        normalize_optional_path("http_post_dump_dir", &mut self.http_post_dump_dir)?;
        normalize_optional_path("smtp_dir", &mut self.smtp_dir)?;
        normalize_optional_path("pcap_path", &mut self.pcap_path)?;
        normalize_optional_path("pcap_prefix", &mut self.pcap_prefix)?;
        validate_file_prefix_setting("pcap_prefix", self.pcap_prefix.as_deref())?;
        normalize_dns_flush_command(&mut self.dns_flush_command)?;
        normalize_optional_path("tls_ca_cert", &mut self.tls_ca_cert)?;
        normalize_optional_path("tls_ca_key", &mut self.tls_ca_key)?;
        normalize_optional_path("tls_cert_dir", &mut self.tls_cert_dir)?;
        validate_process_filter_rule_list(
            "global_process_whitelist",
            &self.global_process_whitelist,
        )?;
        validate_process_filter_rule_list(
            "global_process_blacklist",
            &self.global_process_blacklist,
        )?;
        validate_distributed_config_bounds(&self.distributed)?;

        if self.tls_ca_cert.is_some() ^ self.tls_ca_key.is_some() {
            return Err(crate::Error::Config(
                "tls_ca_cert and tls_ca_key must both be set together".to_string(),
            ));
        }

        Ok(())
    }

    pub(crate) fn validate_runtime_file_prefixes(&self) -> crate::Result<()> {
        validate_file_prefix_setting("pcap_prefix", self.pcap_prefix.as_deref())
    }

    fn validate_database_backend(&self) -> crate::Result<()> {
        match self.database.backend.as_str() {
            "none" | "sqlite" | "postgres" | "postgresql" => Ok(()),
            "" => Err(crate::Error::Config(
                "database.backend must not be blank".to_string(),
            )),
            backend => Err(crate::Error::Config(format!(
                "Unknown database backend '{}'",
                backend
            ))),
        }
    }

    fn prepare_listeners_for_runtime(&mut self) -> crate::Result<()> {
        use nettrap_core::prelude::Protocol;

        for listener in &mut self.listeners {
            // Only TCP and UDP listeners can be spawned (they bind a socket).
            // Reject anything else here so `config --check` fails the same way
            // the engine would at startup, instead of passing validation and
            // then aborting `run` with "Unsupported protocol …".
            if !matches!(listener.protocol, Protocol::Tcp | Protocol::Udp) {
                return Err(crate::Error::Config(format!(
                    "Listener '{}' uses unsupported protocol {:?}; only 'tcp' and 'udp' listeners can be spawned",
                    listener.name, listener.protocol
                )));
            }

            Self::validate_listener_name(&listener.name)?;

            listener.bind_address =
                canonicalize_bind_address(&listener.bind_address).map_err(|err| match err {
                    crate::Error::Config(message) => {
                        crate::Error::Config(format!("Listener '{}': {}", listener.name, message))
                    }
                    other => other,
                })?;

            let has_port_range = listener
                .port_range
                .as_deref()
                .is_some_and(|range| !range.trim().is_empty());
            if listener.port == 0 && !has_port_range {
                tracing::warn!(
                    "Listener '{}' has port 0, will bind to random port",
                    listener.name
                );
            }

            if listener.max_connections == Some(0) {
                return Err(crate::Error::Config(format!(
                    "Listener '{}': max_connections must be greater than 0",
                    listener.name
                )));
            }
            normalize_listener_directory_options(listener)?;
            validate_listener_optional_string_fields(listener)?;
            validate_listener_server_version(listener)?;
            validate_listener_directory_options(listener)?;
            validate_listener_server_name(listener)?;
            validate_listener_pasv_ports(listener)?;
            validate_listener_timing(listener)?;
            validate_process_filter_rule_list(
                &format!("Listener '{}': process_whitelist", listener.name),
                &listener.process_whitelist,
            )?;
            validate_process_filter_rule_list(
                &format!("Listener '{}': process_blacklist", listener.name),
                &listener.process_blacklist,
            )?;
            validate_filter_rule_list(
                &format!("Listener '{}': host_whitelist", listener.name),
                &listener.host_whitelist,
            )?;
            validate_filter_rule_list(
                &format!("Listener '{}': host_blacklist", listener.name),
                &listener.host_blacklist,
            )?;

            // Validate dns_response_mode if set
            if let Some(ref mode) = listener.dns_response_mode {
                let valid = ["static", "auto", "hostname", "gethostname"];
                let mode = mode.to_lowercase();
                if !valid.iter().any(|candidate| candidate == &mode) {
                    return Err(crate::Error::Config(format!(
                        "Listener '{}': invalid dns_response_mode '{}'. Valid: {:?}",
                        listener.name, mode, valid
                    )));
                }
            }

            if listener.custom_response.is_some()
                && Self::listener_name_matches_protocol(&listener.name, "dns")
            {
                listener.parse_dns_custom_responses().map_err(|err| {
                    crate::Error::Config(format!(
                        "Listener '{}': invalid DNS custom_response: {}",
                        listener.name, err
                    ))
                })?;
            }
        }

        self.expand_listeners()?;
        if self.listeners.is_empty() {
            return Err(crate::Error::Config(
                "No valid listeners remain after port_range expansion".into(),
            ));
        }
        self.finalize_listener_names()?;
        Ok(())
    }

    pub(crate) fn prepare_runtime_defaults(&mut self) -> crate::Result<()> {
        self.validate()
    }

    pub(crate) fn prepare_api_defaults(&mut self) -> crate::Result<()> {
        let saved_distributed_runtime = (
            self.distributed.enabled,
            std::mem::take(&mut self.distributed.event_sinks),
            self.distributed.control_plane_url.take(),
            self.distributed.control_plane_token.take(),
            std::mem::take(&mut self.distributed.heartbeat_interval_secs),
            self.distributed.metrics_bind.take(),
            self.distributed.health_bind.take(),
        );
        let result = (|| {
            self.validate_api_global_settings()?;
            let saved_default_tcp_listener = self.default_tcp_listener.take();
            let saved_default_udp_listener = self.default_udp_listener.take();
            let listener_validation = self.prepare_listeners_for_runtime();
            self.default_tcp_listener = saved_default_tcp_listener;
            self.default_udp_listener = saved_default_udp_listener;
            listener_validation?;
            self.validate_database_backend()?;
            Ok(())
        })();
        self.distributed.enabled = saved_distributed_runtime.0;
        self.distributed.event_sinks = saved_distributed_runtime.1;
        self.distributed.control_plane_url = saved_distributed_runtime.2;
        self.distributed.control_plane_token = saved_distributed_runtime.3;
        self.distributed.heartbeat_interval_secs = saved_distributed_runtime.4;
        self.distributed.metrics_bind = saved_distributed_runtime.5;
        self.distributed.health_bind = saved_distributed_runtime.6;
        result
    }

    fn validate_api_global_settings(&mut self) -> crate::Result<()> {
        if self.database.pool_size == 0 {
            return Err(crate::Error::Config(
                "database.pool_size must be greater than 0".to_string(),
            ));
        }
        if self.attribution_timeout_ms == 0 && self.attribution_enabled {
            return Err(crate::Error::Config(
                "attribution_timeout_ms must be greater than 0 when attribution is enabled"
                    .to_string(),
            ));
        }

        validate_loopback_socket_addr_setting("api_bind", self.api_bind.as_deref())?;
        validate_output_format_setting(&self.output_format)?;
        normalize_default_decision(&mut self.default_decision)?;
        normalize_restrict_interface(&mut self.restrict_interface)?;
        normalize_report_language(&mut self.report_language)?;
        normalize_optional_identifier("database.node_id", &mut self.database.node_id)?;
        normalize_optional_identifier(
            "distributed.node_region",
            &mut self.distributed.node_region,
        )?;
        validate_distributed_config_bounds(&self.distributed)?;
        validate_process_filter_rule_list(
            "global_process_whitelist",
            &self.global_process_whitelist,
        )?;
        validate_process_filter_rule_list(
            "global_process_blacklist",
            &self.global_process_blacklist,
        )?;

        Ok(())
    }

    pub(crate) fn finalize_after_cli_overrides(&mut self) -> crate::Result<()> {
        self.validate_global_settings()?;
        self.finalize_listener_names()?;
        Ok(())
    }

    /// Check if a debug flag is enabled
    pub fn has_debug_flag(&self, flag: &str) -> bool {
        self.debug_flags
            .iter()
            .any(|f| f.eq_ignore_ascii_case(flag))
    }

    /// Resolve effective network mode based on OS
    pub fn effective_network_mode(&self) -> NetworkMode {
        match self.network_mode {
            NetworkMode::Auto => {
                if cfg!(target_os = "linux") {
                    NetworkMode::MultiHost
                } else {
                    NetworkMode::SingleHost
                }
            }
            other => other,
        }
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
