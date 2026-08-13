use std::path::Path;

use nettrap_fsutil::ensure_no_symlink_ancestors;

use super::{
    DistributedConfig, ListenerConfig, MAX_DISTRIBUTED_EVENT_SINKS,
    MAX_DISTRIBUTED_HTTP_SINK_BATCH_SIZE, MAX_DISTRIBUTED_NODE_TAG_BYTES,
    MAX_DISTRIBUTED_NODE_TAGS, MAX_DNS_FLUSH_COMMAND_BYTES, MAX_FILTER_RULE_BYTES,
    MAX_FILTER_RULES_PER_LIST, MAX_LISTENER_DELAY_MS, MAX_LISTENER_PASV_PORT_RANGE,
    MAX_LISTENER_TIMEOUT_MS,
};

pub(super) fn validate_filter_rule_list(field: &str, rules: &[String]) -> crate::Result<()> {
    if rules.len() > MAX_FILTER_RULES_PER_LIST {
        return Err(crate::Error::Config(format!(
            "{} has too many entries ({} > {})",
            field,
            rules.len(),
            MAX_FILTER_RULES_PER_LIST
        )));
    }

    if let Some((idx, rule)) = rules
        .iter()
        .enumerate()
        .find(|(_, rule)| rule.len() > MAX_FILTER_RULE_BYTES)
    {
        return Err(crate::Error::Config(format!(
            "{} entry {} exceeds size limit ({} > {} bytes)",
            field,
            idx,
            rule.len(),
            MAX_FILTER_RULE_BYTES
        )));
    }

    if let Some((idx, _)) = rules
        .iter()
        .enumerate()
        .find(|(_, rule)| rule.trim_matches([' ', '\t']).is_empty())
    {
        return Err(crate::Error::Config(format!(
            "{} entry {} must not be blank",
            field, idx
        )));
    }

    if let Some((idx, _)) = rules
        .iter()
        .enumerate()
        .find(|(_, rule)| contains_control_or_unicode_whitespace(rule.trim_matches([' ', '\t'])))
    {
        return Err(crate::Error::Config(format!(
            "{} entry {} contains control characters or unicode whitespace",
            field, idx
        )));
    }

    Ok(())
}

pub(super) fn validate_process_filter_rule_list(
    field: &str,
    rules: &[String],
) -> crate::Result<()> {
    validate_filter_rule_list(field, rules)?;

    for (idx, rule) in rules.iter().enumerate() {
        let trimmed = rule.trim_matches([' ', '\t']);
        if contains_control_or_unicode_whitespace(trimmed) {
            return Err(crate::Error::Config(format!(
                "{} entry {} contains control characters or unicode whitespace",
                field, idx
            )));
        }
        if let Some(pattern) = trimmed
            .strip_prefix("re:")
            .or_else(|| trimmed.strip_prefix("regex:"))
        {
            if pattern.is_empty() {
                return Err(crate::Error::Config(format!(
                    "{} entry {} regex pattern must not be blank",
                    field, idx
                )));
            }
            regex::Regex::new(pattern).map_err(|err| {
                crate::Error::Config(format!(
                    "{} entry {} has invalid regex: {}",
                    field, idx, err
                ))
            })?;
        }
    }

    Ok(())
}

pub(super) fn contains_control_or_unicode_whitespace(value: &str) -> bool {
    value
        .chars()
        .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
}

pub(super) fn normalize_dns_flush_command(command: &mut Option<String>) -> crate::Result<()> {
    let Some(value) = command.as_mut() else {
        return Ok(());
    };

    let trimmed = value.trim_matches([' ', '\t']);
    if trimmed != value {
        return Err(crate::Error::Config(
            "dns_flush_command must not be padded".to_string(),
        ));
    }
    if trimmed.is_empty() {
        return Err(crate::Error::Config(
            "dns_flush_command must not be blank".to_string(),
        ));
    }
    if trimmed.len() > MAX_DNS_FLUSH_COMMAND_BYTES {
        return Err(crate::Error::Config(format!(
            "dns_flush_command exceeds size limit ({} > {} bytes)",
            trimmed.len(),
            MAX_DNS_FLUSH_COMMAND_BYTES
        )));
    }
    if nettrap_core::sanitize::contains_line_separator_or_control(trimmed) {
        return Err(crate::Error::Config(
            "dns_flush_command contains control characters or unicode separators".to_string(),
        ));
    }
    validate_dns_flush_command_words(trimmed)?;
    Ok(())
}

pub(super) fn validate_dns_flush_command_words(command: &str) -> crate::Result<()> {
    let mut has_word = false;
    let mut current_has_content = false;
    let mut chars = command.chars().peekable();
    let mut quote: Option<char> = None;

    while let Some(ch) = chars.next() {
        match ch {
            '\\' if quote == Some('"') => {
                if matches!(chars.peek(), Some('"' | '\\')) {
                    chars.next();
                }
                current_has_content = true;
            }
            '"' | '\'' if quote == Some(ch) => {
                quote = None;
            }
            '"' | '\'' if quote.is_none() => {
                quote = Some(ch);
            }
            ch if ch.is_ascii_whitespace() && quote.is_none() => {
                has_word |= current_has_content;
                current_has_content = false;
            }
            _ => {
                current_has_content = true;
            }
        }
    }

    if let Some(quote) = quote {
        return Err(crate::Error::Config(format!(
            "dns_flush_command has unterminated {quote} quote"
        )));
    }
    if !(has_word || current_has_content) {
        return Err(crate::Error::Config(
            "dns_flush_command must include an executable".to_string(),
        ));
    }

    Ok(())
}

pub(super) fn validate_listener_optional_string_field(
    listener_name: &str,
    field: &str,
    value: Option<&str>,
) -> crate::Result<()> {
    let Some(value) = value else {
        return Ok(());
    };

    if contains_unicode_separator_or_control(value) {
        return Err(crate::Error::Config(format!(
            "Listener '{}': {} contains control characters or unicode separators",
            listener_name, field
        )));
    }

    Ok(())
}

pub(super) fn contains_unicode_separator_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|ch| ch.is_control() || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
}

pub(super) fn validate_listener_optional_string_fields(
    listener: &ListenerConfig,
) -> crate::Result<()> {
    for (field, value) in [
        ("banner", listener.banner.as_deref()),
        ("server_name", listener.server_name.as_deref()),
        ("webroot", listener.webroot.as_deref()),
        ("ftproot", listener.ftproot.as_deref()),
        ("tftproot", listener.tftproot.as_deref()),
        ("custom_response", listener.custom_response.as_deref()),
        ("execute_cmd", listener.execute_cmd.as_deref()),
        (
            "dump_http_posts_prefix",
            listener.dump_http_posts_prefix.as_deref(),
        ),
        ("server_version", listener.server_version.as_deref()),
        ("dns_response_mode", listener.dns_response_mode.as_deref()),
        ("dns_response_ip", listener.dns_response_ip.as_deref()),
        ("dns_response_mx", listener.dns_response_mx.as_deref()),
        ("dns_response_txt", listener.dns_response_txt.as_deref()),
        (
            "dns_ncsi_response_ip",
            listener.dns_ncsi_response_ip.as_deref(),
        ),
        ("pasv_ports", listener.pasv_ports.as_deref()),
    ] {
        if field == "custom_response" {
            validate_listener_custom_response(listener.name.as_str(), value)?;
            continue;
        }
        if field == "dump_http_posts_prefix" {
            validate_listener_dump_http_posts_prefix(listener.name.as_str(), value)?;
            continue;
        }
        if field == "execute_cmd" {
            validate_listener_execute_cmd(listener.name.as_str(), value)?;
            continue;
        }
        validate_listener_optional_string_field(&listener.name, field, value)?;
    }

    Ok(())
}

pub(super) fn validate_listener_execute_cmd(
    listener_name: &str,
    value: Option<&str>,
) -> crate::Result<()> {
    let Some(value) = value else {
        return Ok(());
    };

    if value.is_empty() || value.chars().all(|ch| ch.is_whitespace()) {
        return Err(crate::Error::Config(format!(
            "Listener '{}': execute_cmd must not be blank",
            listener_name
        )));
    }

    validate_listener_optional_string_field(listener_name, "execute_cmd", Some(value))
}

pub(super) fn validate_listener_custom_response(
    listener_name: &str,
    value: Option<&str>,
) -> crate::Result<()> {
    let Some(value) = value else {
        return Ok(());
    };

    if value.is_empty() || value.chars().all(|ch| ch.is_whitespace()) {
        return Err(crate::Error::Config(format!(
            "Listener '{}': custom_response must not be blank",
            listener_name
        )));
    }

    validate_listener_optional_string_field(listener_name, "custom_response", Some(value))
}

pub(super) fn validate_listener_dump_http_posts_prefix(
    listener_name: &str,
    value: Option<&str>,
) -> crate::Result<()> {
    let Some(value) = value else {
        return Ok(());
    };

    if value.chars().all(|ch| ch.is_whitespace()) {
        return Err(crate::Error::Config(format!(
            "Listener '{}': dump_http_posts_prefix must not be blank",
            listener_name
        )));
    }

    validate_listener_optional_string_field(listener_name, "dump_http_posts_prefix", Some(value))
}

pub(super) fn normalize_listener_directory_option(value: &mut Option<String>) -> crate::Result<()> {
    let Some(path) = value.as_mut() else {
        return Ok(());
    };
    if path.trim_matches([' ', '\t']) != path {
        return Err(crate::Error::Config(
            "listener root directory options must not be padded".to_string(),
        ));
    }

    Ok(())
}

pub(super) fn normalize_listener_directory_options(
    listener: &mut ListenerConfig,
) -> crate::Result<()> {
    normalize_listener_directory_option(&mut listener.webroot)?;
    normalize_listener_directory_option(&mut listener.ftproot)?;
    normalize_listener_directory_option(&mut listener.tftproot)?;
    Ok(())
}

pub(super) fn validate_listener_directory_option(
    listener_name: &str,
    field: &str,
    value: Option<&str>,
) -> crate::Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.trim_matches([' ', '\t']) != value {
        return Err(crate::Error::Config(format!(
            "Listener '{}': {} must not be padded",
            listener_name, field
        )));
    }
    if value.is_empty() {
        return Err(crate::Error::Config(format!(
            "Listener '{}': {} must not be blank",
            listener_name, field
        )));
    }
    if contains_unicode_separator_or_control(value) {
        return Err(crate::Error::Config(format!(
            "Listener '{}': {} contains control characters or unicode separators",
            listener_name, field
        )));
    }

    let path = Path::new(value);
    ensure_no_symlink_ancestors(path).map_err(|err| {
        crate::Error::Config(format!(
            "Listener '{}': {} '{}' is invalid: {}",
            listener_name,
            field,
            path.display(),
            err
        ))
    })?;
    let metadata = path.symlink_metadata().map_err(|err| {
        crate::Error::Config(format!(
            "Listener '{}': {} '{}' is not accessible: {}",
            listener_name,
            field,
            path.display(),
            err
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(crate::Error::Config(format!(
            "Listener '{}': {} '{}' must not be a symlink",
            listener_name,
            field,
            path.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(crate::Error::Config(format!(
            "Listener '{}': {} '{}' must be a directory",
            listener_name,
            field,
            path.display()
        )));
    }

    Ok(())
}
pub(super) fn validate_listener_directory_options(listener: &ListenerConfig) -> crate::Result<()> {
    for (field, value) in [
        ("webroot", listener.webroot.as_deref()),
        ("ftproot", listener.ftproot.as_deref()),
        ("tftproot", listener.tftproot.as_deref()),
    ] {
        validate_listener_directory_option(&listener.name, field, value)?;
    }

    Ok(())
}

pub(super) fn validate_listener_server_name(listener: &ListenerConfig) -> crate::Result<()> {
    let Some(server_name) = listener.server_name.as_deref() else {
        return Ok(());
    };
    if matches!(server_name, "!hostname" | "!gethostname" | "!random") {
        return Ok(());
    }
    let canonical_server_name = if let Some(canonical_server_name) = server_name.strip_suffix('.') {
        if canonical_server_name.is_empty() || canonical_server_name.ends_with('.') {
            ""
        } else {
            canonical_server_name
        }
    } else {
        server_name
    };

    if server_name.is_empty()
        || server_name.chars().next().is_some_and(char::is_whitespace)
        || server_name.chars().last().is_some_and(char::is_whitespace)
        || canonical_server_name.is_empty()
        || canonical_server_name.len() > 253
        || !nettrap_core::sanitize::has_valid_domain_labels(canonical_server_name)
        || nettrap_core::sanitize::has_numeric_domain_labels(canonical_server_name)
        || !is_valid_listener_server_name(canonical_server_name)
    {
        return Err(crate::Error::Config(format!(
            "Listener '{}': server_name must be 1-253 characters using dot-separated labels made of ASCII letters, digits or '-' with no surrounding whitespace or empty labels",
            listener.name
        )));
    }

    Ok(())
}

pub(super) fn validate_listener_server_version(listener: &ListenerConfig) -> crate::Result<()> {
    let Some(server_version) = listener.server_version.as_deref() else {
        return Ok(());
    };

    if server_version.trim_matches([' ', '\t']) != server_version {
        return Err(crate::Error::Config(format!(
            "Listener '{}': server_version must not be padded",
            listener.name
        )));
    }
    if server_version
        .chars()
        .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return Err(crate::Error::Config(format!(
            "Listener '{}': server_version contains unsafe control characters",
            listener.name
        )));
    }

    Ok(())
}

pub(super) fn is_valid_listener_server_name(value: &str) -> bool {
    !value.is_empty()
        && nettrap_core::sanitize::has_valid_domain_labels(value)
        && !nettrap_core::sanitize::has_numeric_domain_labels(value)
}

pub(super) fn parse_listener_pasv_port_range(value: &str) -> Option<(u16, u16)> {
    let (start_s, end_s) = value.split_once('-')?;
    let start = parse_listener_pasv_port(start_s)?;
    let end = parse_listener_pasv_port(end_s)?;
    if start == 0 || end == 0 {
        return None;
    }

    if start > end {
        return None;
    }
    if end - start >= MAX_LISTENER_PASV_PORT_RANGE {
        return None;
    }

    Some((start, end))
}

pub(crate) fn parse_listener_pasv_port(value: &str) -> Option<u16> {
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

pub(super) fn validate_listener_pasv_ports(listener: &ListenerConfig) -> crate::Result<()> {
    let Some(pasv_ports) = listener.pasv_ports.as_deref() else {
        return Ok(());
    };

    if parse_listener_pasv_port_range(pasv_ports).is_none() {
        return Err(crate::Error::Config(format!(
            "Listener '{}': invalid pasv_ports '{}', expected format: start-end",
            listener.name, pasv_ports
        )));
    }

    Ok(())
}

pub(super) fn validate_listener_timing(listener: &ListenerConfig) -> crate::Result<()> {
    if listener.timeout_ms == 0 {
        return Err(crate::Error::Config(format!(
            "Listener '{}': timeout_ms must be greater than 0",
            listener.name
        )));
    }
    if listener.timeout_ms > MAX_LISTENER_TIMEOUT_MS {
        return Err(crate::Error::Config(format!(
            "Listener '{}': timeout_ms exceeds max {}",
            listener.name, MAX_LISTENER_TIMEOUT_MS
        )));
    }
    for (field, value) in [
        ("response_delay_ms", listener.response_delay_ms),
        ("banner_delay_ms", listener.banner_delay_ms),
    ] {
        if value > MAX_LISTENER_DELAY_MS {
            return Err(crate::Error::Config(format!(
                "Listener '{}': {} exceeds max {}",
                listener.name, field, MAX_LISTENER_DELAY_MS
            )));
        }
    }

    Ok(())
}

pub(super) fn validate_distributed_config_bounds(config: &DistributedConfig) -> crate::Result<()> {
    if config.event_sinks.len() > MAX_DISTRIBUTED_EVENT_SINKS {
        return Err(crate::Error::Config(format!(
            "distributed.event_sinks has too many entries ({} > {})",
            config.event_sinks.len(),
            MAX_DISTRIBUTED_EVENT_SINKS
        )));
    }

    for (idx, sink) in config.event_sinks.iter().enumerate() {
        match sink.sink_type.as_str() {
            "http" | "webhook" | "elasticsearch" | "splunk" => {
                if sink.batch_size == 0 {
                    return Err(crate::Error::Config(format!(
                        "distributed.event_sinks[{}].batch_size must be greater than 0",
                        idx
                    )));
                }
                if sink.batch_size > MAX_DISTRIBUTED_HTTP_SINK_BATCH_SIZE {
                    return Err(crate::Error::Config(format!(
                        "distributed.event_sinks[{}].batch_size exceeds max {}",
                        idx, MAX_DISTRIBUTED_HTTP_SINK_BATCH_SIZE
                    )));
                }
                if sink.flush_interval_ms == 0 {
                    return Err(crate::Error::Config(format!(
                        "distributed.event_sinks[{}].flush_interval_ms must be greater than 0",
                        idx
                    )));
                }
                if sink.request_timeout_ms == 0 {
                    return Err(crate::Error::Config(format!(
                        "distributed.event_sinks[{}].request_timeout_ms must be greater than 0",
                        idx
                    )));
                }
            }
            "tcp" | "nats" | "logstash" | "fluentd" | "syslog" | "syslog_udp" => {}
            _ => {}
        }
    }

    if config.node_tags.len() > MAX_DISTRIBUTED_NODE_TAGS {
        return Err(crate::Error::Config(format!(
            "distributed.node_tags has too many entries ({} > {})",
            config.node_tags.len(),
            MAX_DISTRIBUTED_NODE_TAGS
        )));
    }

    if let Some((idx, tag)) = config
        .node_tags
        .iter()
        .enumerate()
        .find(|(_, tag)| tag.len() > MAX_DISTRIBUTED_NODE_TAG_BYTES)
    {
        return Err(crate::Error::Config(format!(
            "distributed.node_tags entry {} exceeds size limit ({} > {} bytes)",
            idx,
            tag.len(),
            MAX_DISTRIBUTED_NODE_TAG_BYTES
        )));
    }

    Ok(())
}
