use super::spawn::listener_should_spawn;
use crate::config::EngineConfig;
use std::io::ErrorKind;
use std::path::Path;

pub(crate) fn validate_adapter_configuration(config: &EngineConfig) -> crate::Result<()> {
    if config.distributed.enabled {
        let _ = crate::distributed::build_event_fanout(&config.distributed)?;
    }

    for listener in &config.listeners {
        for (field, rules) in [
            ("host_whitelist", &listener.host_whitelist),
            ("host_blacklist", &listener.host_blacklist),
        ] {
            crate::host_filter::compile_host_rules(rules).map_err(|err| {
                crate::Error::Config(format!("Listener '{}': {}: {}", listener.name, field, err))
            })?;
        }

        if listener.custom_response.is_some()
            && EngineConfig::listener_name_matches_protocol(&listener.name, "raw")
        {
            let custom_response = listener.custom_response.as_deref().unwrap_or_default();
            nettrap_protocols::handlers::nettrap_proto_raw::RawHandler::from_custom_response(
                custom_response,
            )
            .map_err(|err| {
                crate::Error::Config(format!(
                    "Listener '{}': invalid raw custom_response: {}",
                    listener.name, err
                ))
            })?;
        }
    }

    Ok(())
}

fn load_from_default_paths<T, F>(default_paths: &[&str], mut load: F) -> crate::Result<Option<T>>
where
    F: FnMut(&Path) -> crate::Result<T>,
{
    for path_str in default_paths {
        let path = Path::new(path_str);
        match load(path) {
            Ok(value) => return Ok(Some(value)),
            Err(crate::Error::Io(error)) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
    }

    Ok(None)
}

pub(super) fn load_config(config_path: Option<std::path::PathBuf>) -> crate::Result<EngineConfig> {
    if let Some(path) = config_path {
        let config = EngineConfig::from_file(&path)?;
        validate_adapter_configuration(&config)?;
        return Ok(config);
    }

    #[cfg(not(target_os = "windows"))]
    let default_paths: &[&str] = &["/etc/nettrap/config.toml"];

    #[cfg(target_os = "windows")]
    let default_paths: &[&str] = &["C:\\ProgramData\\NetTrap\\config.toml", ".\\config.toml"];

    if let Some(config) = load_from_default_paths(default_paths, EngineConfig::from_file)? {
        validate_adapter_configuration(&config)?;
        return Ok(config);
    }

    let mut config = EngineConfig::default();
    config.prepare_runtime_defaults()?;
    validate_adapter_configuration(&config)?;
    Ok(config)
}

fn prepare_loaded_api_config(
    mut config: EngineConfig,
    api_bind_override: Option<&str>,
) -> crate::Result<EngineConfig> {
    if let Some(bind) = api_bind_override {
        config.api_bind = Some(bind.to_string());
    }
    config.prepare_api_defaults()?;
    Ok(config)
}

pub(super) fn load_api_config(
    config_path: Option<std::path::PathBuf>,
    api_bind_override: Option<&str>,
) -> crate::Result<EngineConfig> {
    if let Some(path) = config_path {
        return prepare_loaded_api_config(
            EngineConfig::from_file_declarative(&path)?,
            api_bind_override,
        );
    }

    #[cfg(not(target_os = "windows"))]
    let default_paths: &[&str] = &["/etc/nettrap/config.toml"];

    #[cfg(target_os = "windows")]
    let default_paths: &[&str] = &["C:\\ProgramData\\NetTrap\\config.toml", ".\\config.toml"];

    if let Some(config) =
        load_from_default_paths(default_paths, EngineConfig::from_file_declarative)?
    {
        return prepare_loaded_api_config(config, api_bind_override);
    }

    prepare_loaded_api_config(EngineConfig::default(), api_bind_override)
}

pub(super) fn apply_cli_overrides(
    config: &mut EngineConfig,
    args: &crate::cli::RunArgs,
) -> crate::Result<()> {
    if !args.ports.is_empty() {
        let mut requested_ports = Vec::new();
        let mut seen_ports = std::collections::HashSet::new();
        for port in &args.ports {
            if seen_ports.insert(*port) {
                requested_ports.push(*port);
            }
        }

        config
            .blacklist_ports_tcp
            .retain(|port| !seen_ports.iter().any(|seen| seen == port));
        config
            .blacklist_ports_udp
            .retain(|port| !seen_ports.iter().any(|seen| seen == port));

        let requested_port_set: std::collections::HashSet<u16> =
            requested_ports.iter().copied().collect();
        let mut selected_listeners: Vec<_> = std::mem::take(&mut config.listeners)
            .into_iter()
            .filter(|listener| requested_port_set.iter().any(|port| port == &listener.port))
            .collect();

        for port in requested_ports {
            let covered_by_spawnable_listener = selected_listeners
                .iter()
                .any(|listener| listener.port == port && listener_should_spawn(config, listener));

            if !covered_by_spawnable_listener {
                selected_listeners.push(build_cli_listener_for_port(&selected_listeners, port)?);
            }
        }

        config.listeners = selected_listeners;
    }

    if args.pcap {
        config.pcap_enabled = true;
    }

    if args.pcap_path.is_some() {
        config.pcap_enabled = true;
    }

    if args.attribution {
        config.attribution_enabled = true;
    }

    // --report-format is the explicit selector and wins; --json-output is a
    // convenience shorthand for the common "json" case. Without this, the
    // documented-looking --json-output flag was parsed but never applied.
    if let Some(ref fmt) = args.report_format {
        config.output_format = fmt.clone();
    } else if args.json_output {
        config.output_format = "json".to_string();
    }

    Ok(())
}

fn build_cli_listener_for_port(
    existing_listeners: &[crate::config::ListenerConfig],
    port: u16,
) -> crate::Result<crate::config::ListenerConfig> {
    use nettrap_core::prelude::Protocol;

    let matching_listeners: Vec<_> = existing_listeners
        .iter()
        .filter(|listener| listener.port == port)
        .collect();

    let mut matching_protocols: Vec<Protocol> = matching_listeners
        .iter()
        .map(|listener| listener.protocol)
        .collect();
    matching_protocols.sort_unstable_by_key(|protocol| match protocol {
        Protocol::Tcp => 0,
        Protocol::Udp => 1,
        _ => 2,
    });
    matching_protocols.dedup();

    if matching_protocols.len() > 1 {
        return Err(crate::Error::Config(format!(
            "CLI --ports {} is ambiguous: existing listeners on that port use both TCP and UDP",
            port
        )));
    }

    if let Some(base_listener) = matching_listeners.first() {
        for other in matching_listeners.iter().skip(1) {
            if !cli_listener_bases_are_compatible(base_listener, other) {
                return Err(crate::Error::Config(format!(
                    "CLI --ports {} is ambiguous: existing listeners on that port have incompatible settings",
                    port
                )));
            }
        }

        let mut listener = (*base_listener).clone();
        listener.name = format!("cli_{}", port);
        listener.port = port;
        listener.port_range = None;
        listener.enabled = true;
        listener.hidden = false;
        return Ok(listener);
    }

    Ok(crate::config::ListenerConfig::new(
        format!("cli_{}", port),
        port,
    ))
}

fn cli_listener_bases_are_compatible(
    base: &crate::config::ListenerConfig,
    other: &crate::config::ListenerConfig,
) -> bool {
    fn normalized_listener_signature(
        listener: &crate::config::ListenerConfig,
    ) -> crate::Result<serde_json::Value> {
        let mut normalized = listener.clone();
        normalized.name.clear();
        normalized.enabled = true;
        normalized.hidden = false;
        normalized.port_range = None;
        serde_json::to_value(normalized).map_err(|error| {
            crate::Error::Config(format!("listener config should serialize: {error}"))
        })
    }

    let base_signature = match normalized_listener_signature(base) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    let other_signature = match normalized_listener_signature(other) {
        Ok(signature) => signature,
        Err(_) => return false,
    };

    base_signature == other_signature
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn load_from_default_paths_skips_missing_candidates() {
        let missing = std::env::temp_dir().join(format!(
            "nettrap-config-missing-{}.toml",
            uuid::Uuid::new_v4()
        ));
        let existing = std::env::temp_dir().join(format!(
            "nettrap-config-existing-{}.toml",
            uuid::Uuid::new_v4()
        ));

        let mut config = EngineConfig::default();
        config.api_bind = Some("127.0.0.1:18888".to_string());
        fs::write(
            &existing,
            toml::to_string(&config).expect("serialize config"),
        )
        .expect("write config");

        let missing_str = missing.to_string_lossy().to_string();
        let existing_str = existing.to_string_lossy().to_string();
        let loaded =
            load_from_default_paths(&[missing_str.as_str(), existing_str.as_str()], |path| {
                EngineConfig::from_file(path)
            })
            .expect("missing paths should be skipped")
            .expect("existing path should be loaded");

        assert_eq!(loaded.api_bind.as_deref(), Some("127.0.0.1:18888"));

        let _ = fs::remove_file(existing);
    }

    #[test]
    fn load_from_default_paths_does_not_skip_non_not_found_errors() {
        let invalid = std::env::temp_dir().join(format!(
            "nettrap-config-invalid-{}.toml",
            uuid::Uuid::new_v4()
        ));
        let fallback = std::env::temp_dir().join(format!(
            "nettrap-config-fallback-{}.toml",
            uuid::Uuid::new_v4()
        ));

        fs::write(&invalid, "api_bind = \"not-a-socket\"").expect("write invalid config");

        let mut config = EngineConfig::default();
        config.api_bind = Some("127.0.0.1:18889".to_string());
        fs::write(
            &fallback,
            toml::to_string(&config).expect("serialize config"),
        )
        .expect("write fallback config");

        let invalid_str = invalid.to_string_lossy().to_string();
        let fallback_str = fallback.to_string_lossy().to_string();
        let err = load_from_default_paths(&[invalid_str.as_str(), fallback_str.as_str()], |path| {
            EngineConfig::from_file(path)
        })
        .expect_err("invalid config should stop the search");

        assert!(!matches!(err, crate::Error::Io(error) if error.kind() == ErrorKind::NotFound));

        let _ = fs::remove_file(invalid);
        let _ = fs::remove_file(fallback);
    }
}
