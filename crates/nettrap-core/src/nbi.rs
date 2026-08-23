use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const NBI_SCHEMA_VERSION: u32 = 1;

fn nbi_schema_version() -> u32 {
    NBI_SCHEMA_VERSION
}

fn should_normalize_legacy_event_id(event_id: &str) -> bool {
    let event_id = event_id.trim_matches([' ', '\t']);
    event_id.is_empty()
        || (event_id.starts_with("legacy-db-")
            && !event_id
                .chars()
                .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' ')))
}

fn legacy_event_id_from_fingerprint(content_fingerprint: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in content_fingerprint.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("legacy-{hash:016x}")
}

/// Network Behavior Indicator - structured per-protocol telemetry
#[derive(Debug, Clone)]
pub struct NetworkBehaviorIndicator {
    pub event_id: String,
    pub timestamp: String,
    pub listener: String,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    // BTreeMap (not HashMap) so serialization is deterministic: indicators are
    // emitted in sorted key order on every run. HashMap iteration order is
    // randomized per process, which made JSON/JSONL/SARIF report output (and the
    // SARIF message text) differ byte-for-byte between identical runs, breaking
    // diffing, fingerprinting, and dedup in downstream SIEM/Code-Scanning tools.
    pub indicators: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
struct NetworkBehaviorIndicatorSerde {
    #[serde(default = "nbi_schema_version")]
    schema_version: u32,
    event_id: String,
    timestamp: String,
    listener: String,
    protocol: String,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    process_name: Option<String>,
    process_pid: Option<u32>,
    indicators: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct NetworkBehaviorIndicatorRef<'a> {
    schema_version: u32,
    event_id: &'a str,
    timestamp: &'a str,
    listener: &'a str,
    protocol: &'a str,
    src_ip: &'a str,
    src_port: u16,
    dst_ip: &'a str,
    dst_port: u16,
    process_name: Option<&'a str>,
    process_pid: Option<u32>,
    indicators: &'a BTreeMap<String, String>,
}

impl Serialize for NetworkBehaviorIndicator {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        NetworkBehaviorIndicatorRef {
            schema_version: NBI_SCHEMA_VERSION,
            event_id: &self.event_id,
            timestamp: &self.timestamp,
            listener: &self.listener,
            protocol: &self.protocol,
            src_ip: &self.src_ip,
            src_port: self.src_port,
            dst_ip: &self.dst_ip,
            dst_port: self.dst_port,
            process_name: self.process_name.as_deref(),
            process_pid: self.process_pid,
            indicators: &self.indicators,
        }
        .serialize(serializer)
    }
}

impl NetworkBehaviorIndicator {
    /// Maximum number of indicator key/value pairs accepted in one NBI event.
    pub const MAX_INDICATORS: usize = 64;

    pub fn new(
        listener: &str,
        protocol: &str,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            listener: listener.to_string(),
            protocol: protocol.to_string(),
            src_ip: canonicalize_nbi_ip(src_ip),
            src_port,
            dst_ip: canonicalize_nbi_ip(dst_ip),
            dst_port,
            process_name: None,
            process_pid: None,
            indicators: BTreeMap::new(),
        }
    }

    pub fn with_process(mut self, name: Option<String>, pid: Option<u32>) -> Self {
        self.process_name = normalize_optional_process_name(name);
        self.process_pid = pid;
        self
    }

    /// Add or update an indicator field.
    ///
    /// Returns `false` when adding a new key would exceed [`Self::MAX_INDICATORS`].
    /// Updating an existing key is always allowed and does not grow the event.
    pub fn add(&mut self, key: impl Into<String>, value: impl Into<String>) -> bool {
        let key = crate::sanitize::single_line(&key.into());
        if key.trim().is_empty() {
            return false;
        }
        let value = crate::sanitize::single_line(&value.into());
        if !self.indicators.contains_key(&key) && self.indicators.len() >= Self::MAX_INDICATORS {
            return false;
        }
        self.indicators.insert(key, value);
        true
    }

    /// Validate resource bounds for events reconstructed from untrusted storage or reports.
    pub fn validate_resource_bounds(&self) -> Result<()> {
        validate_bounded_text("event_id", &self.event_id)?;
        validate_nonempty_text("event_id", &self.event_id)?;
        if self.event_id != self.event_id.trim() {
            return Err(Error::Parse("NBI event_id must not be padded".to_string()));
        }
        validate_bounded_text("timestamp", &self.timestamp)?;
        validate_nonempty_text("timestamp", &self.timestamp)?;
        validate_nbi_timestamp(&self.timestamp)?;
        validate_bounded_text("listener", &self.listener)?;
        validate_nonempty_text("listener", &self.listener)?;
        if self.listener != self.listener.trim() {
            return Err(Error::Parse("NBI listener must not be padded".to_string()));
        }
        validate_bounded_text("protocol", &self.protocol)?;
        validate_nonempty_text("protocol", &self.protocol)?;
        if self.protocol != self.protocol.trim() {
            return Err(Error::Parse("NBI protocol must not be padded".to_string()));
        }
        validate_nbi_ip("src_ip", &self.src_ip)?;
        validate_nbi_ip("dst_ip", &self.dst_ip)?;
        if let Some(process_name) = &self.process_name {
            validate_bounded_text("process_name", process_name)?;
            validate_nonempty_text("process_name", process_name)?;
        }

        let indicator_count = self.indicators.len();
        if indicator_count > Self::MAX_INDICATORS {
            let event_id = resource_bound_event_id(&self.event_id);
            return Err(Error::Parse(format!(
                "NBI event '{}' has too many indicators ({} > {})",
                event_id,
                indicator_count,
                Self::MAX_INDICATORS
            )));
        }

        for (key, value) in &self.indicators {
            validate_bounded_text("indicator key", key)?;
            validate_nonempty_text("indicator key", key)?;
            validate_bounded_text("indicator value", value)?;
        }

        Ok(())
    }

    pub fn with_fresh_event_id(mut self) -> Self {
        self.event_id = uuid::Uuid::new_v4().to_string();
        self
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| Error::Storage(format!("JSON serialization failed: {}", e)))
    }

    pub fn content_fingerprint(&self) -> String {
        let mut indicators: Vec<_> = self.indicators.iter().collect();
        indicators
            .sort_unstable_by(|left, right| left.0.cmp(right.0).then_with(|| left.1.cmp(right.1)));

        let mut fingerprint = String::new();
        push_fingerprint_field(&mut fingerprint, "timestamp", &self.timestamp);
        push_fingerprint_field(&mut fingerprint, "listener", &self.listener);
        push_fingerprint_field(&mut fingerprint, "protocol", &self.protocol);
        push_fingerprint_field(&mut fingerprint, "src_ip", &self.src_ip);
        push_fingerprint_field(&mut fingerprint, "src_port", &self.src_port.to_string());
        push_fingerprint_field(&mut fingerprint, "dst_ip", &self.dst_ip);
        push_fingerprint_field(&mut fingerprint, "dst_port", &self.dst_port.to_string());
        push_fingerprint_option_field(
            &mut fingerprint,
            "process_name",
            self.process_name.as_deref(),
        );
        let process_pid = self.process_pid.map(|pid| pid.to_string());
        push_fingerprint_option_field(&mut fingerprint, "process_pid", process_pid.as_deref());

        fingerprint.push_str("indicators[");
        fingerprint.push_str(&indicators.len().to_string());
        fingerprint.push_str("]=");
        for (key, value) in indicators {
            push_fingerprint_field(&mut fingerprint, key, value);
        }

        fingerprint
    }

    pub fn normalized_event_id(&self) -> String {
        if should_normalize_legacy_event_id(&self.event_id) {
            legacy_event_id_from_fingerprint(&self.content_fingerprint())
        } else {
            self.event_id.clone()
        }
    }
}

impl<'de> Deserialize<'de> for NetworkBehaviorIndicator {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = NetworkBehaviorIndicatorSerde::deserialize(deserializer)?;
        if helper.schema_version != NBI_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(format!(
                "unsupported NBI schema_version {}; expected {}",
                helper.schema_version, NBI_SCHEMA_VERSION
            )));
        }
        let src_ip = parse_nbi_ip_for_deserialize("src_ip", &helper.src_ip)
            .map_err(serde::de::Error::custom)?;
        let dst_ip = parse_nbi_ip_for_deserialize("dst_ip", &helper.dst_ip)
            .map_err(serde::de::Error::custom)?;
        let protocol = parse_nbi_protocol_for_deserialize(&helper.protocol)
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            event_id: helper.event_id,
            timestamp: helper.timestamp,
            listener: helper.listener,
            protocol,
            src_ip,
            src_port: helper.src_port,
            dst_ip,
            dst_port: helper.dst_port,
            process_name: normalize_optional_process_name(helper.process_name),
            process_pid: helper.process_pid,
            indicators: helper.indicators,
        })
    }
}

fn push_fingerprint_field(fingerprint: &mut String, key: &str, value: &str) {
    fingerprint.push_str(key);
    fingerprint.push('[');
    fingerprint.push_str(&value.len().to_string());
    fingerprint.push_str("]=");
    fingerprint.push_str(value);
    fingerprint.push('|');
}

fn push_fingerprint_option_field(fingerprint: &mut String, key: &str, value: Option<&str>) {
    match value {
        Some(value) => push_fingerprint_field(fingerprint, key, value),
        None => push_fingerprint_field(fingerprint, key, ""),
    }
}

fn resource_bound_event_id(event_id: &str) -> String {
    let event_id = crate::sanitize::single_line(event_id);
    if event_id.is_empty() {
        "<missing>".to_string()
    } else {
        event_id
    }
}

fn canonicalize_nbi_ip(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(ip) => std::net::IpAddr::from(crate::types::IpAddress::from(ip)).to_string(),
        Err(_) => ip.to_string(),
    }
}

fn normalize_optional_process_name(name: Option<String>) -> Option<String> {
    name.and_then(|name| {
        let name = crate::sanitize::single_line(&name);
        if name.trim().is_empty() {
            None
        } else {
            Some(name)
        }
    })
}

fn parse_nbi_ip_for_deserialize(field: &str, value: &str) -> Result<String> {
    let ip = value.parse::<std::net::IpAddr>().map_err(|err| {
        Error::Parse(format!(
            "NBI {} contains invalid IP '{}': {}",
            field, value, err
        ))
    })?;
    Ok(std::net::IpAddr::from(crate::types::IpAddress::from(ip)).to_string())
}

fn parse_nbi_protocol_for_deserialize(value: &str) -> Result<String> {
    if value.trim_matches([' ', '\t']) != value
        || value.is_empty()
        || value
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return Err(Error::Parse(format!(
            "NBI protocol '{}' contains unsafe line-break or control characters",
            value
        )));
    }

    Ok(value.to_ascii_uppercase())
}

fn validate_bounded_text(field: &str, value: &str) -> Result<()> {
    validate_text_length(field, value)?;

    if value
        .chars()
        .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return Err(Error::Parse(format!(
            "NBI {} contains unsafe line-break or control characters",
            field
        )));
    }

    Ok(())
}

fn validate_nonempty_text(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::Parse(format!("NBI {} must not be empty", field)));
    }
    Ok(())
}

fn validate_nbi_timestamp(value: &str) -> Result<()> {
    chrono::DateTime::parse_from_rfc3339(value).map_err(|err| {
        Error::Parse(format!(
            "NBI timestamp '{}' is not valid RFC3339: {}",
            value, err
        ))
    })?;
    Ok(())
}

fn validate_nbi_ip(field: &str, value: &str) -> Result<()> {
    validate_bounded_text(field, value)?;
    value.parse::<std::net::IpAddr>().map_err(|err| {
        Error::Parse(format!(
            "NBI {} contains invalid IP '{}': {}",
            field, value, err
        ))
    })?;
    Ok(())
}

fn validate_text_length(field: &str, value: &str) -> Result<()> {
    let char_count = value.chars().count();
    if char_count > crate::sanitize::SINGLE_LINE_MAX_CHARS {
        return Err(Error::Parse(format!(
            "NBI {} exceeds text limit ({} > {} characters)",
            field,
            char_count,
            crate::sanitize::SINGLE_LINE_MAX_CHARS
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{NBI_SCHEMA_VERSION, NetworkBehaviorIndicator, should_normalize_legacy_event_id};
    use std::collections::BTreeMap;

    #[test]
    fn legacy_event_ids_normalize_blank_and_prefixed_values() {
        assert!(should_normalize_legacy_event_id(""));
        assert!(should_normalize_legacy_event_id("legacy-db-123"));
    }

    #[test]
    fn legacy_event_ids_reject_unicode_whitespace_and_control_padding() {
        assert!(!should_normalize_legacy_event_id("\u{00a0}legacy-db-123"));
        assert!(!should_normalize_legacy_event_id("legacy-db-123\u{2003}"));
        assert!(!should_normalize_legacy_event_id("legacy-db-123\n"));
    }

    #[test]
    fn normalized_event_id_preserves_nonlegacy_values() {
        let mut indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "127.0.0.1", 1, "127.0.0.1", 2);
        indicator.event_id = "event-123".to_string();

        assert_eq!(indicator.normalized_event_id(), "event-123");
    }

    #[test]
    fn nbi_json_includes_schema_version() {
        let indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "127.0.0.1", 1, "127.0.0.1", 2);

        let value = serde_json::to_value(indicator).expect("serialize NBI");

        assert_eq!(value["schema_version"], NBI_SCHEMA_VERSION);
    }

    #[test]
    fn nbi_deserialization_treats_missing_schema_version_as_v1() {
        let indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "127.0.0.1", 1, "127.0.0.1", 2);
        let mut value = serde_json::to_value(&indicator).expect("serialize NBI");
        value
            .as_object_mut()
            .expect("NBI serializes as an object")
            .remove("schema_version");

        let decoded: NetworkBehaviorIndicator =
            serde_json::from_value(value).expect("legacy NBI should decode as v1");

        assert_eq!(decoded.event_id, indicator.event_id);
    }

    #[test]
    fn nbi_deserialization_rejects_unknown_schema_version() {
        let indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "127.0.0.1", 1, "127.0.0.1", 2);
        let mut value = serde_json::to_value(indicator).expect("serialize NBI");
        value["schema_version"] = (NBI_SCHEMA_VERSION + 1).into();

        let err = serde_json::from_value::<NetworkBehaviorIndicator>(value)
            .expect_err("unknown schema version should fail");

        assert!(err.to_string().contains("unsupported NBI schema_version"));
    }

    #[test]
    fn add_bounds_and_sanitizes_indicator_fields() {
        let mut indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "127.0.0.1", 1, "127.0.0.1", 2);
        let key = format!("{}{}", "k".repeat(300), "\nname");
        let value = format!("{}{}", "v".repeat(300), "\u{2028}secret");

        assert!(indicator.add(key, value));

        let (key, value) = indicator
            .indicators
            .iter()
            .next()
            .expect("indicator should be present");
        assert_eq!(key.chars().count(), 240);
        assert_eq!(value.chars().count(), 240);
        assert!(!key.chars().any(char::is_control));
        assert!(!value.chars().any(char::is_control));
        assert!(!value.contains('\u{2028}'));
    }

    #[test]
    fn add_rejects_blank_indicator_keys() {
        let mut indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "127.0.0.1", 1, "127.0.0.1", 2);

        assert!(!indicator.add(" \t\n", "value"));
        assert!(indicator.indicators.is_empty());
    }

    #[test]
    fn validate_resource_bounds_rejects_invalid_ip_text() {
        let indicator = NetworkBehaviorIndicator {
            event_id: "event-123".to_string(),
            timestamp: "2026-07-02T00:00:00Z".to_string(),
            listener: "listener".to_string(),
            protocol: "TCP".to_string(),
            src_ip: "not-an-ip".to_string(),
            src_port: 1,
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 2,
            process_name: None,
            process_pid: None,
            indicators: BTreeMap::new(),
        };

        let err = indicator.validate_resource_bounds().unwrap_err();

        assert!(err.to_string().contains("src_ip"));
        assert!(err.to_string().contains("invalid IP"));
    }

    #[test]
    fn validate_resource_bounds_rejects_empty_protocol() {
        let indicator = NetworkBehaviorIndicator {
            event_id: "event-123".to_string(),
            timestamp: "2026-07-02T00:00:00Z".to_string(),
            listener: "listener".to_string(),
            protocol: String::new(),
            src_ip: "127.0.0.1".to_string(),
            src_port: 1,
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 2,
            process_name: None,
            process_pid: None,
            indicators: BTreeMap::new(),
        };

        let err = indicator.validate_resource_bounds().unwrap_err();

        assert!(err.to_string().contains("protocol"));
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_resource_bounds_rejects_padded_listener() {
        let indicator = NetworkBehaviorIndicator {
            event_id: "event-123".to_string(),
            timestamp: "2026-07-02T00:00:00Z".to_string(),
            listener: " listener ".to_string(),
            protocol: "TCP".to_string(),
            src_ip: "127.0.0.1".to_string(),
            src_port: 1,
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 2,
            process_name: None,
            process_pid: None,
            indicators: BTreeMap::new(),
        };

        let err = indicator.validate_resource_bounds().unwrap_err();

        assert!(err.to_string().contains("listener"));
        assert!(err.to_string().contains("must not be padded"));
    }

    #[test]
    fn validate_resource_bounds_rejects_padded_protocol() {
        let indicator = NetworkBehaviorIndicator {
            event_id: "event-123".to_string(),
            timestamp: "2026-07-02T00:00:00Z".to_string(),
            listener: "listener".to_string(),
            protocol: " TCP ".to_string(),
            src_ip: "127.0.0.1".to_string(),
            src_port: 1,
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 2,
            process_name: None,
            process_pid: None,
            indicators: BTreeMap::new(),
        };

        let err = indicator.validate_resource_bounds().unwrap_err();

        assert!(err.to_string().contains("protocol"));
        assert!(err.to_string().contains("must not be padded"));
    }

    #[test]
    fn validate_resource_bounds_rejects_whitespace_only_event_id() {
        let indicator = NetworkBehaviorIndicator {
            event_id: "   ".to_string(),
            timestamp: "2026-07-02T00:00:00Z".to_string(),
            listener: "listener".to_string(),
            protocol: "TCP".to_string(),
            src_ip: "127.0.0.1".to_string(),
            src_port: 1,
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 2,
            process_name: None,
            process_pid: None,
            indicators: BTreeMap::new(),
        };

        let err = indicator.validate_resource_bounds().unwrap_err();

        assert!(err.to_string().contains("event_id"));
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_resource_bounds_rejects_padded_event_id() {
        let indicator = NetworkBehaviorIndicator {
            event_id: " event-123 ".to_string(),
            timestamp: "2026-07-02T00:00:00Z".to_string(),
            listener: "listener".to_string(),
            protocol: "TCP".to_string(),
            src_ip: "127.0.0.1".to_string(),
            src_port: 1,
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 2,
            process_name: None,
            process_pid: None,
            indicators: BTreeMap::new(),
        };

        let err = indicator.validate_resource_bounds().unwrap_err();

        assert!(err.to_string().contains("event_id"));
        assert!(err.to_string().contains("must not be padded"));
    }

    #[test]
    fn validate_resource_bounds_rejects_whitespace_only_process_name() {
        let indicator = NetworkBehaviorIndicator {
            event_id: "event-123".to_string(),
            timestamp: "2026-07-02T00:00:00Z".to_string(),
            listener: "listener".to_string(),
            protocol: "TCP".to_string(),
            src_ip: "127.0.0.1".to_string(),
            src_port: 1,
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 2,
            process_name: Some("   ".to_string()),
            process_pid: Some(42),
            indicators: BTreeMap::new(),
        };

        let err = indicator.validate_resource_bounds().unwrap_err();

        assert!(err.to_string().contains("process_name"));
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_resource_bounds_rejects_empty_listener() {
        let indicator = NetworkBehaviorIndicator {
            event_id: "event-123".to_string(),
            timestamp: "2026-07-02T00:00:00Z".to_string(),
            listener: String::new(),
            protocol: "TCP".to_string(),
            src_ip: "127.0.0.1".to_string(),
            src_port: 1,
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 2,
            process_name: None,
            process_pid: None,
            indicators: BTreeMap::new(),
        };

        let err = indicator.validate_resource_bounds().unwrap_err();

        assert!(err.to_string().contains("listener"));
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_resource_bounds_rejects_empty_timestamp() {
        let indicator = NetworkBehaviorIndicator {
            event_id: "event-123".to_string(),
            timestamp: String::new(),
            listener: "listener".to_string(),
            protocol: "TCP".to_string(),
            src_ip: "127.0.0.1".to_string(),
            src_port: 1,
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 2,
            process_name: None,
            process_pid: None,
            indicators: BTreeMap::new(),
        };

        let err = indicator.validate_resource_bounds().unwrap_err();

        assert!(err.to_string().contains("timestamp"));
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_resource_bounds_rejects_invalid_timestamp_format() {
        let indicator = NetworkBehaviorIndicator {
            event_id: "event-123".to_string(),
            timestamp: "not-a-timestamp".to_string(),
            listener: "listener".to_string(),
            protocol: "TCP".to_string(),
            src_ip: "127.0.0.1".to_string(),
            src_port: 1,
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 2,
            process_name: None,
            process_pid: None,
            indicators: BTreeMap::new(),
        };

        let err = indicator.validate_resource_bounds().unwrap_err();

        assert!(err.to_string().contains("RFC3339"));
    }

    #[test]
    fn add_rejects_new_indicators_beyond_runtime_limit() {
        let mut indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "127.0.0.1", 1, "127.0.0.1", 2);
        for index in 0..NetworkBehaviorIndicator::MAX_INDICATORS {
            assert!(indicator.add(format!("key-{index}"), "value"));
        }

        assert!(!indicator.add("overflow", "value"));
        assert_eq!(
            indicator.indicators.len(),
            NetworkBehaviorIndicator::MAX_INDICATORS
        );
        assert!(indicator.validate_resource_bounds().is_ok());

        assert!(indicator.add("key-0", "updated"));
        assert_eq!(
            indicator.indicators.get("key-0").map(String::as_str),
            Some("updated")
        );
    }

    #[test]
    fn validate_resource_bounds_rejects_too_many_indicators() {
        let mut indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "127.0.0.1", 1, "127.0.0.1", 2);
        for index in 0..=NetworkBehaviorIndicator::MAX_INDICATORS {
            indicator
                .indicators
                .insert(format!("key-{index}"), "value".to_string());
        }

        let err = indicator.validate_resource_bounds().unwrap_err();

        assert!(err.to_string().contains("too many indicators"));
        assert!(
            err.to_string()
                .contains(&NetworkBehaviorIndicator::MAX_INDICATORS.to_string())
        );
    }

    #[test]
    fn validate_resource_bounds_rejects_oversized_indicator_text() {
        let mut indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "127.0.0.1", 1, "127.0.0.1", 2);
        indicator.indicators.insert(
            "key".to_string(),
            "v".repeat(crate::sanitize::SINGLE_LINE_MAX_CHARS + 1),
        );

        let err = indicator.validate_resource_bounds().unwrap_err();

        assert!(err.to_string().contains("indicator value"));
        assert!(err.to_string().contains("exceeds text limit"));
    }

    #[test]
    fn validate_resource_bounds_rejects_indicator_line_breaks() {
        let mut indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "127.0.0.1", 1, "127.0.0.1", 2);
        indicator
            .indicators
            .insert("line\nkey".to_string(), "value".to_string());

        let err = indicator.validate_resource_bounds().unwrap_err();

        assert!(err.to_string().contains("indicator key"));
        assert!(err.to_string().contains("unsafe"));
    }

    #[test]
    fn validate_resource_bounds_rejects_empty_indicator_keys() {
        let mut indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "127.0.0.1", 1, "127.0.0.1", 2);
        indicator
            .indicators
            .insert(String::new(), "value".to_string());

        let err = indicator.validate_resource_bounds().unwrap_err();

        assert!(err.to_string().contains("indicator key"));
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_resource_bounds_rejects_event_id_line_breaks() {
        let mut indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "127.0.0.1", 1, "127.0.0.1", 2);
        indicator.event_id = "event\n123".to_string();

        let err = indicator.validate_resource_bounds().unwrap_err();

        assert!(err.to_string().contains("event_id"));
        assert!(err.to_string().contains("unsafe"));
    }

    #[test]
    fn with_process_bounds_and_sanitizes_process_name() {
        let indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "127.0.0.1", 1, "127.0.0.1", 2)
                .with_process(Some(format!("{}{}", "p".repeat(300), "\nsecret")), Some(42));
        let process_name = indicator
            .process_name
            .as_deref()
            .expect("process name should be present");

        assert_eq!(process_name.chars().count(), 240);
        assert!(!process_name.chars().any(char::is_control));
        assert_eq!(indicator.process_pid, Some(42));
    }

    #[test]
    fn with_process_drops_blank_process_name() {
        let indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "127.0.0.1", 1, "127.0.0.1", 2)
                .with_process(Some(String::new()), Some(42));

        assert_eq!(indicator.process_name, None);
        assert_eq!(indicator.process_pid, Some(42));
    }

    #[test]
    fn with_process_drops_whitespace_only_process_name() {
        let indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "127.0.0.1", 1, "127.0.0.1", 2)
                .with_process(Some(" \t ".to_string()), Some(42));

        assert_eq!(indicator.process_name, None);
        assert_eq!(indicator.process_pid, Some(42));
    }

    #[test]
    fn new_canonicalizes_ipv4_mapped_addresses() {
        let indicator = NetworkBehaviorIndicator::new(
            "listener",
            "tcp",
            "::ffff:192.0.2.10",
            1,
            "::ffff:198.51.100.7",
            2,
        );

        assert_eq!(indicator.src_ip, "192.0.2.10");
        assert_eq!(indicator.dst_ip, "198.51.100.7");
    }

    #[test]
    fn new_preserves_invalid_ip_text_for_observability() {
        let indicator =
            NetworkBehaviorIndicator::new("listener", "tcp", "not-an-ip", 1, "also-bad", 2);

        assert_eq!(indicator.src_ip, "not-an-ip");
        assert_eq!(indicator.dst_ip, "also-bad");
    }

    #[test]
    fn deserialize_canonicalizes_ipv4_mapped_addresses() {
        let indicator: NetworkBehaviorIndicator = serde_json::from_str(
            r#"{
                "event_id":"event-1",
                "timestamp":"2026-01-01T00:00:00Z",
                "listener":"listener",
                "protocol":"tcp",
                "src_ip":"::ffff:192.0.2.10",
                "src_port":12345,
                "dst_ip":"::ffff:198.51.100.7",
                "dst_port":80,
                "process_name":null,
                "process_pid":null,
                "indicators":{}
            }"#,
        )
        .unwrap();

        assert_eq!(indicator.src_ip, "192.0.2.10");
        assert_eq!(indicator.dst_ip, "198.51.100.7");
    }

    #[test]
    fn deserialize_canonicalizes_protocol_case() {
        let indicator: NetworkBehaviorIndicator = serde_json::from_str(
            r#"{
                "event_id":"event-1",
                "timestamp":"2026-01-01T00:00:00Z",
                "listener":"listener",
                "protocol":"dns",
                "src_ip":"192.0.2.10",
                "src_port":12345,
                "dst_ip":"198.51.100.7",
                "dst_port":80,
                "process_name":null,
                "process_pid":null,
                "indicators":{}
            }"#,
        )
        .unwrap();

        assert_eq!(indicator.protocol, "DNS");
    }

    #[test]
    fn deserialize_drops_blank_process_name() {
        let indicator: NetworkBehaviorIndicator = serde_json::from_str(
            r#"{
                "event_id":"event-1",
                "timestamp":"2026-01-01T00:00:00Z",
                "listener":"listener",
                "protocol":"tcp",
                "src_ip":"192.0.2.10",
                "src_port":12345,
                "dst_ip":"198.51.100.7",
                "dst_port":80,
                "process_name":"",
                "process_pid":null,
                "indicators":{}
            }"#,
        )
        .unwrap();

        assert_eq!(indicator.process_name, None);
    }

    #[test]
    fn deserialize_drops_whitespace_only_process_name() {
        let indicator: NetworkBehaviorIndicator = serde_json::from_str(
            r#"{
                "event_id":"event-1",
                "timestamp":"2026-01-01T00:00:00Z",
                "listener":"listener",
                "protocol":"tcp",
                "src_ip":"192.0.2.10",
                "src_port":12345,
                "dst_ip":"198.51.100.7",
                "dst_port":80,
                "process_name":" \t ",
                "process_pid":null,
                "indicators":{}
            }"#,
        )
        .unwrap();

        assert_eq!(indicator.process_name, None);
    }

    #[test]
    fn deserialize_rejects_protocol_with_whitespace_padding() {
        let err = serde_json::from_str::<NetworkBehaviorIndicator>(
            r#"{
                "event_id":"event-1",
                "timestamp":"2026-01-01T00:00:00Z",
                "listener":"listener",
                "protocol":" tcp ",
                "src_ip":"127.0.0.1",
                "src_port":12345,
                "dst_ip":"198.51.100.7",
                "dst_port":80,
                "process_name":null,
                "process_pid":null,
                "indicators":{}
            }"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("protocol"));
        assert!(
            err.to_string()
                .contains("unsafe line-break or control characters")
        );
    }

    #[test]
    fn deserialize_rejects_invalid_ip_text() {
        let err = serde_json::from_str::<NetworkBehaviorIndicator>(
            r#"{
                "event_id":"event-1",
                "timestamp":"2026-01-01T00:00:00Z",
                "listener":"listener",
                "protocol":"tcp",
                "src_ip":"not-an-ip",
                "src_port":12345,
                "dst_ip":"198.51.100.7",
                "dst_port":80,
                "process_name":null,
                "process_pid":null,
                "indicators":{}
            }"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("src_ip"));
        assert!(err.to_string().contains("invalid IP"));
    }

    #[test]
    fn deserialize_rejects_missing_required_destination_ip() {
        let err = serde_json::from_str::<NetworkBehaviorIndicator>(
            r#"{
                "event_id":"event-1",
                "timestamp":"2026-01-01T00:00:00Z",
                "listener":"listener",
                "protocol":"tcp",
                "src_ip":"127.0.0.1",
                "src_port":12345,
                "dst_port":80,
                "process_name":null,
                "process_pid":null,
                "indicators":{}
            }"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("missing field `dst_ip`"));
    }

    #[test]
    fn deserialize_rejects_missing_event_id() {
        let err = serde_json::from_str::<NetworkBehaviorIndicator>(
            r#"{
                "timestamp":"2026-01-01T00:00:00Z",
                "listener":"listener",
                "protocol":"tcp",
                "src_ip":"127.0.0.1",
                "src_port":12345,
                "dst_ip":"198.51.100.7",
                "dst_port":80,
                "process_name":null,
                "process_pid":null,
                "indicators":{}
            }"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("missing field `event_id`"));
    }
}
