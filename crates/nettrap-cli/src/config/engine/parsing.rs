//! Parsing and validation helpers for engine configuration.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use super::MAX_ENGINE_CONFIG_FILE_BYTES;
use nettrap_core::sanitize::trim_ascii_spaces_tabs as trim_ascii_edges;
use nettrap_fsutil::open_regular_file_beneath_root;

pub(crate) fn protocol_label(protocol: nettrap_core::prelude::Protocol) -> &'static str {
    match protocol {
        nettrap_core::prelude::Protocol::Tcp => "tcp",
        nettrap_core::prelude::Protocol::Udp => "udp",
        _ => "unsupported",
    }
}

pub(crate) fn parse_bind_address(bind_address: &str) -> crate::Result<IpAddr> {
    let trimmed = trim_ascii_edges(bind_address);
    if trimmed.is_empty()
        || trimmed != bind_address
        || contains_unicode_whitespace_or_control(trimmed)
    {
        return Err(crate::Error::Config(format!(
            "invalid bind_address '{}': invalid format",
            bind_address
        )));
    }
    trimmed.parse::<IpAddr>().map_err(|err| {
        crate::Error::Config(format!("invalid bind_address '{}': {}", bind_address, err))
    })
}

pub(crate) fn validate_socket_addr_setting(
    setting_name: &str,
    value: Option<&str>,
) -> crate::Result<()> {
    parse_optional_socket_addr(setting_name, value).map(|_| ())
}

pub(crate) fn validate_output_format_setting(value: &str) -> crate::Result<()> {
    value
        .parse::<nettrap_core::ExportFormat>()
        .map(|_| ())
        .map_err(|err| crate::Error::Config(err.to_string()))
}

pub(crate) fn validate_file_prefix_setting(
    setting_name: &str,
    value: Option<&str>,
) -> crate::Result<()> {
    let Some(value) = value else {
        return Ok(());
    };

    let path = Path::new(value);
    let mut components = path.components();
    let Some(first) = components.next() else {
        return Ok(());
    };
    if components.next().is_some() || !matches!(first, std::path::Component::Normal(_)) {
        return Err(crate::Error::Config(format!(
            "{} must be a single file name component",
            setting_name
        )));
    }

    Ok(())
}

pub(crate) fn normalize_restrict_interface(interface: &mut Option<String>) -> crate::Result<()> {
    let Some(value) = interface.as_mut() else {
        return Ok(());
    };

    let trimmed = trim_ascii_edges(value);
    if trimmed.is_empty() {
        return Err(crate::Error::Config(
            "restrict_interface cannot be empty".to_string(),
        ));
    }
    if trimmed != value {
        return Err(crate::Error::Config(
            "restrict_interface cannot be padded".to_string(),
        ));
    }
    if contains_unicode_whitespace_or_control(trimmed) {
        return Err(crate::Error::Config(
            "restrict_interface contains invalid whitespace".to_string(),
        ));
    }

    Ok(())
}

pub(crate) fn normalize_report_language(language: &mut String) -> crate::Result<()> {
    let trimmed = trim_ascii_edges(language);
    if trimmed.is_empty() {
        return Err(crate::Error::Config(
            "report_language cannot be empty".to_string(),
        ));
    }
    if contains_unicode_whitespace_or_control(trimmed) {
        return Err(crate::Error::Config(format!(
            "unsupported report_language '{}'",
            trimmed
        )));
    }

    let normalized = trimmed.to_ascii_lowercase();
    if !crate::i18n::SUPPORTED_LANGUAGES
        .iter()
        .any(|(code, _)| *code == normalized)
    {
        return Err(crate::Error::Config(format!(
            "unsupported report_language '{}'",
            trimmed
        )));
    }

    if normalized != *language {
        *language = normalized;
    }

    Ok(())
}

pub(crate) fn normalize_default_decision(decision: &mut String) -> crate::Result<()> {
    let trimmed = trim_ascii_edges(decision);
    if trimmed.is_empty() {
        return Err(crate::Error::Config(
            "default_decision cannot be empty".to_string(),
        ));
    }
    if contains_unicode_whitespace_or_control(trimmed) {
        return Err(crate::Error::Config(format!(
            "unsupported default_decision '{}'",
            trimmed
        )));
    }

    let normalized = trimmed.to_ascii_lowercase();
    if normalized != "intercept" {
        return Err(crate::Error::Config(format!(
            "unsupported default_decision '{}'",
            trimmed
        )));
    }

    if normalized != *decision {
        *decision = normalized;
    }

    Ok(())
}

pub(crate) fn normalize_optional_identifier(
    setting_name: &str,
    value: &mut Option<String>,
) -> crate::Result<()> {
    let Some(raw) = value.as_mut() else {
        return Ok(());
    };

    let trimmed = trim_ascii_edges(raw);
    if trimmed.is_empty() {
        *value = None;
        return Ok(());
    }
    if contains_unicode_whitespace_or_control(trimmed) {
        return Err(crate::Error::Config(format!(
            "{} contains invalid whitespace",
            setting_name
        )));
    }

    if trimmed != raw {
        *raw = trimmed.to_string();
    }

    Ok(())
}

pub(crate) fn normalize_optional_path(
    setting_name: &str,
    value: &mut Option<String>,
) -> crate::Result<()> {
    let Some(raw) = value.as_mut() else {
        return Ok(());
    };

    if raw.chars().all(char::is_whitespace) {
        *value = None;
        return Ok(());
    }

    if nettrap_core::sanitize::contains_line_separator_or_control(raw) {
        return Err(crate::Error::Config(format!(
            "{} contains control characters or unicode whitespace",
            setting_name
        )));
    }

    Ok(())
}

pub(crate) fn normalize_optional_url(value: &mut Option<String>) -> crate::Result<()> {
    let Some(raw) = value.as_mut() else {
        return Ok(());
    };

    let trimmed = trim_ascii_edges(raw);
    if trimmed != raw {
        return Err(crate::Error::Config(format!("invalid URL '{}'", raw)));
    }
    if trimmed.is_empty() {
        *value = None;
        return Ok(());
    }
    if contains_unicode_whitespace_or_control(trimmed) {
        return Err(crate::Error::Config(format!("invalid URL '{}'", trimmed)));
    }

    let parsed = reqwest::Url::parse(trimmed)
        .map_err(|err| crate::Error::Config(format!("invalid URL '{}': {}", trimmed, err)))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(crate::Error::Config(format!(
            "invalid URL '{}': unsupported scheme '{}'",
            trimmed,
            parsed.scheme()
        )));
    }
    *raw = parsed.to_string();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_default_decision, normalize_optional_identifier, normalize_optional_path,
        normalize_optional_url, normalize_report_language, normalize_restrict_interface,
        parse_bind_address, parse_optional_socket_addr, read_engine_config_file,
    };
    use std::fs;
    use std::path::PathBuf;

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nettrap-engine-config-{name}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn normalize_restrict_interface_rejects_ascii_padding() {
        let mut interface = Some(" eth0 ".to_string());
        let err = normalize_restrict_interface(&mut interface)
            .expect_err("ascii padded restrict_interface should be rejected");
        assert!(err.to_string().contains("cannot be padded"));
    }

    #[test]
    fn normalize_restrict_interface_rejects_empty_value() {
        let mut interface = Some("   ".to_string());
        let err = normalize_restrict_interface(&mut interface)
            .expect_err("empty restrict_interface should be rejected");
        assert!(
            err.to_string()
                .contains("restrict_interface cannot be empty")
        );
    }

    #[test]
    fn normalize_report_language_trims_and_lowercases() {
        let mut language = " EN ".to_string();
        normalize_report_language(&mut language).unwrap();
        assert_eq!(language, "en");
    }

    #[test]
    fn normalize_report_language_rejects_empty_value() {
        let mut language = "   ".to_string();
        let err =
            normalize_report_language(&mut language).expect_err("empty report_language rejected");
        assert!(err.to_string().contains("report_language cannot be empty"));
    }

    #[test]
    fn normalize_report_language_rejects_unknown_language() {
        let mut language = "xx".to_string();
        let err = normalize_report_language(&mut language)
            .expect_err("unsupported report_language should be rejected");
        assert!(err.to_string().contains("unsupported report_language"));
    }

    #[test]
    fn normalize_default_decision_accepts_intercept() {
        let mut decision = " INTERCEPT ".to_string();
        normalize_default_decision(&mut decision).unwrap();
        assert_eq!(decision, "intercept");
    }

    #[test]
    fn normalize_default_decision_rejects_unknown_value() {
        let mut decision = "drop".to_string();
        let err = normalize_default_decision(&mut decision)
            .expect_err("unsupported default_decision should be rejected");
        assert!(err.to_string().contains("unsupported default_decision"));
    }

    #[test]
    fn normalize_optional_identifier_trims_and_keeps_value() {
        let mut value = Some(" node-1 ".to_string());
        normalize_optional_identifier("node_id", &mut value).unwrap();
        assert_eq!(value.as_deref(), Some("node-1"));
    }

    #[test]
    fn normalize_optional_identifier_drops_blank_value() {
        let mut value = Some("   ".to_string());
        normalize_optional_identifier("node_id", &mut value).unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn normalize_optional_identifier_rejects_invalid_whitespace() {
        let mut value = Some("node\u{00a0}1".to_string());
        let err = normalize_optional_identifier("node_id", &mut value)
            .expect_err("invalid identifier whitespace should be rejected");
        assert!(
            err.to_string()
                .contains("node_id contains invalid whitespace")
        );
    }

    #[test]
    fn normalize_optional_identifier_rejects_c1_controls() {
        let mut value = Some("node\u{009f}1".to_string());
        let err = normalize_optional_identifier("node_id", &mut value)
            .expect_err("C1 control characters should be rejected");
        assert!(
            err.to_string()
                .contains("node_id contains invalid whitespace")
        );
    }

    #[test]
    fn normalize_optional_path_drops_blank_value() {
        let mut value = Some("   ".to_string());
        normalize_optional_path("output_path", &mut value).unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn normalize_optional_path_preserves_ascii_spaced_value() {
        let mut value = Some("  cache dir  ".to_string());
        normalize_optional_path("output_path", &mut value).unwrap();
        assert_eq!(value.as_deref(), Some("  cache dir  "));
    }

    #[test]
    fn normalize_optional_path_preserves_unicode_whitespace_value() {
        let mut value = Some("output\u{00a0}.jsonl".to_string());
        normalize_optional_path("output_path", &mut value).unwrap();
        assert_eq!(value.as_deref(), Some("output\u{00a0}.jsonl"));
    }

    #[test]
    fn normalize_optional_path_rejects_control_characters() {
        let mut value = Some("out\nput.jsonl".to_string());
        let err = normalize_optional_path("output_path", &mut value)
            .expect_err("control characters should be rejected");
        assert!(
            err.to_string()
                .contains("output_path contains control characters or unicode whitespace")
        );
    }

    #[test]
    fn normalize_optional_path_rejects_unicode_line_separators() {
        let mut value = Some("out\u{2028}put.jsonl".to_string());
        let err = normalize_optional_path("output_path", &mut value)
            .expect_err("unicode separators should be rejected");
        assert!(
            err.to_string()
                .contains("output_path contains control characters or unicode whitespace")
        );
    }

    #[test]
    fn normalize_optional_url_rejects_ascii_padding() {
        let mut value = Some(" https://control.example.test/ ".to_string());
        let err = normalize_optional_url(&mut value).expect_err("ascii padding should be rejected");
        assert!(err.to_string().contains("invalid URL"));
    }

    #[test]
    fn normalize_optional_url_rejects_invalid_value() {
        let mut value = Some("not-a-url".to_string());
        let err = normalize_optional_url(&mut value).expect_err("invalid URL should be rejected");
        assert!(err.to_string().contains("invalid URL"));
    }

    #[test]
    fn normalize_optional_url_rejects_non_http_scheme() {
        let mut value = Some("file:///tmp/control".to_string());
        let err = normalize_optional_url(&mut value)
            .expect_err("non-http control URL should be rejected");
        assert!(err.to_string().contains("unsupported scheme 'file'"));
    }

    #[test]
    fn normalize_report_language_rejects_unicode_whitespace() {
        let mut language = "\u{00a0}en\u{00a0}".to_string();
        let err = normalize_report_language(&mut language)
            .expect_err("unicode whitespace should be rejected");
        assert!(err.to_string().contains("unsupported report_language"));
    }

    #[test]
    fn parse_bind_address_rejects_unicode_whitespace() {
        let err = parse_bind_address("127.0.0.1\u{00a0}").expect_err("invalid bind_address");
        assert!(err.to_string().contains("invalid bind_address"));
    }

    #[test]
    fn parse_bind_address_rejects_ascii_padding() {
        let err = parse_bind_address(" 127.0.0.1 ").expect_err("invalid bind_address");
        assert!(err.to_string().contains("invalid bind_address"));
    }

    #[test]
    fn parse_optional_socket_addr_rejects_unicode_whitespace() {
        let err = parse_optional_socket_addr("listen", Some("127.0.0.1:8080\u{00a0}"))
            .expect_err("unicode whitespace should be rejected");
        assert!(err.to_string().contains("Invalid listen"));
    }

    #[test]
    fn parse_optional_socket_addr_rejects_ascii_padding() {
        let err = parse_optional_socket_addr("listen", Some(" 127.0.0.1:8080 "))
            .expect_err("ascii whitespace should be rejected");
        assert!(err.to_string().contains("Invalid listen"));
    }

    #[cfg(unix)]
    #[test]
    fn read_engine_config_file_rejects_symlinked_parent_directory() {
        let root = test_root("parent-symlink");
        let real_parent = root.join("real");
        let linked_parent = root.join("linked");
        fs::create_dir_all(&real_parent).expect("create real parent");
        fs::write(
            real_parent.join("engine.toml"),
            b"api_bind = \"127.0.0.1:0\"",
        )
        .expect("write config");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");

        let err = read_engine_config_file(&linked_parent.join("engine.toml"))
            .expect_err("symlinked parent should be rejected");

        assert!(matches!(err, crate::Error::Io(_)));
        fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn read_engine_config_file_loads_regular_file() {
        let root = test_root("regular");
        fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("engine.toml");
        fs::write(&path, b"api_bind = \"127.0.0.1:0\"").expect("write config");

        let content = read_engine_config_file(&path).expect("config should load");

        assert!(content.contains("api_bind"));
        fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn read_engine_config_file_loads_relative_regular_file() {
        let root = test_root("relative");
        fs::create_dir_all(&root).expect("create temp root");
        let _cwd_lock = crate::test_util::lock_current_dir();
        let previous_dir = std::env::current_dir().expect("current dir");
        std::env::set_current_dir(&root).expect("switch to temp root");
        fs::write("engine.toml", b"api_bind = \"127.0.0.1:0\"").expect("write config");

        let content = read_engine_config_file(std::path::Path::new("engine.toml"))
            .expect("relative config should load");

        std::env::set_current_dir(previous_dir).expect("restore current dir");
        assert!(content.contains("api_bind"));
        fs::remove_dir_all(root).expect("cleanup temp root");
    }
}

pub(crate) fn parse_optional_socket_addr(
    setting_name: &str,
    value: Option<&str>,
) -> crate::Result<Option<std::net::SocketAddr>> {
    match value {
        None => Ok(None),
        Some(raw) => {
            let trimmed = trim_ascii_edges(raw);
            if trimmed.is_empty() {
                return Err(crate::Error::Config(format!(
                    "{} cannot be empty",
                    setting_name
                )));
            }
            if trimmed != raw {
                return Err(crate::Error::Config(format!(
                    "Invalid {} '{}': invalid format",
                    setting_name, raw
                )));
            }
            if contains_unicode_whitespace_or_control(trimmed) {
                return Err(crate::Error::Config(format!(
                    "Invalid {} '{}': invalid format",
                    setting_name, raw
                )));
            }

            trimmed
                .parse::<std::net::SocketAddr>()
                .map(Some)
                .map_err(|err| {
                    crate::Error::Config(format!("Invalid {} '{}': {}", setting_name, raw, err))
                })
        }
    }
}

pub(crate) fn canonicalize_bind_address(bind_address: &str) -> crate::Result<String> {
    Ok(parse_bind_address(bind_address)?.to_string())
}

fn contains_unicode_whitespace_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NormalizedBindAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

pub(crate) fn normalize_bind_addr(addr: IpAddr) -> NormalizedBindAddr {
    match addr {
        IpAddr::V4(addr) => NormalizedBindAddr::V4(addr),
        IpAddr::V6(addr) => match addr.to_ipv4_mapped() {
            Some(mapped) => NormalizedBindAddr::V4(mapped),
            None => NormalizedBindAddr::V6(addr),
        },
    }
}

pub(crate) fn socket_bindings_overlap(
    left_protocol: nettrap_core::prelude::Protocol,
    left_addr: IpAddr,
    left_port: u16,
    right_protocol: nettrap_core::prelude::Protocol,
    right_addr: IpAddr,
    right_port: u16,
) -> bool {
    if left_port == 0 || right_port == 0 {
        return false;
    }

    if left_protocol != right_protocol || left_port != right_port {
        return false;
    }

    let left = normalize_bind_addr(left_addr);
    let right = normalize_bind_addr(right_addr);

    match (left, right) {
        (NormalizedBindAddr::V4(left), NormalizedBindAddr::V4(right)) => {
            left == right || left.is_unspecified() || right.is_unspecified()
        }
        (NormalizedBindAddr::V6(left), NormalizedBindAddr::V6(right)) => {
            left == right || left.is_unspecified() || right.is_unspecified()
        }
        (NormalizedBindAddr::V4(_), NormalizedBindAddr::V6(right)) => right.is_unspecified(),
        (NormalizedBindAddr::V6(left), NormalizedBindAddr::V4(_)) => left.is_unspecified(),
    }
}

pub(crate) fn read_engine_config_file(path: &std::path::Path) -> crate::Result<String> {
    let root = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let relative = path.file_name().ok_or_else(|| {
        crate::Error::Config("engine config path must point to a file".to_string())
    })?;
    let file = open_regular_file_beneath_root(root, Path::new(relative))?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_ENGINE_CONFIG_FILE_BYTES {
        return Err(crate::Error::Config(format!(
            "engine config file exceeds load limit ({} > {} bytes)",
            metadata.len(),
            MAX_ENGINE_CONFIG_FILE_BYTES
        )));
    }

    let mut limited = file.take(MAX_ENGINE_CONFIG_FILE_BYTES + 1);
    let mut content = String::new();
    limited.read_to_string(&mut content)?;
    if content.len() as u64 > MAX_ENGINE_CONFIG_FILE_BYTES {
        return Err(crate::Error::Config(format!(
            "engine config file exceeds load limit ({} > {} bytes)",
            content.len(),
            MAX_ENGINE_CONFIG_FILE_BYTES
        )));
    }
    Ok(content)
}
