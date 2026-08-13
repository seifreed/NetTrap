use serde::{Deserialize, Serialize};

use crate::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ProcessInfo {
    pid: ProcessId,
    name: String,
    path: Option<String>,
    command_line: Option<String>,
    user: Option<String>,
    parent_pid: Option<ProcessId>,
    created_at: Option<Timestamp>,
}

impl ProcessInfo {
    pub fn new(pid: ProcessId, name: impl Into<String>) -> Self {
        let name = normalize_process_name(pid, name.into());
        Self {
            pid,
            name,
            path: None,
            command_line: None,
            user: None,
            parent_pid: None,
            created_at: None,
        }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = normalize_optional_text(path.into());
        self
    }

    pub fn with_command_line(mut self, cmd: impl Into<String>) -> Self {
        self.command_line = normalize_optional_text(cmd.into());
        self
    }

    pub fn unknown() -> Self {
        Self {
            pid: 0,
            name: "<unknown>".to_string(),
            path: None,
            command_line: None,
            user: None,
            parent_pid: None,
            created_at: None,
        }
    }

    pub fn pid(&self) -> ProcessId {
        self.pid
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn command_line(&self) -> Option<&str> {
        self.command_line.as_deref()
    }

    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    pub fn parent_pid(&self) -> Option<ProcessId> {
        self.parent_pid
    }

    pub fn created_at(&self) -> Option<Timestamp> {
        self.created_at
    }
}

impl<'de> Deserialize<'de> for ProcessInfo {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = ProcessInfoSerde::deserialize(deserializer)?;
        Ok(Self {
            pid: helper.pid,
            name: normalize_process_name(helper.pid, helper.name),
            path: helper.path.and_then(normalize_optional_text),
            command_line: helper.command_line.and_then(normalize_optional_text),
            user: helper.user.and_then(normalize_optional_text),
            parent_pid: helper.parent_pid,
            created_at: helper.created_at,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ProcessInfoSerde {
    pid: ProcessId,
    name: String,
    path: Option<String>,
    command_line: Option<String>,
    user: Option<String>,
    parent_pid: Option<ProcessId>,
    created_at: Option<Timestamp>,
}

fn normalize_process_name(pid: ProcessId, name: String) -> String {
    let name = crate::sanitize::single_line(&name);
    let name = name.trim();
    if name.is_empty() {
        format!("pid-{}", pid)
    } else {
        name.to_string()
    }
}

fn normalize_optional_text(value: String) -> Option<String> {
    let value = crate::sanitize::single_line(&value);
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum AttributionConfidence {
    #[default]
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Definitive = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribution {
    pub process: ProcessInfo,
    pub confidence: AttributionConfidence,
    pub method: AttributionMethod,
    pub timestamp: Timestamp,
}

impl Attribution {
    pub fn new(
        process: ProcessInfo,
        confidence: AttributionConfidence,
        method: AttributionMethod,
    ) -> Self {
        Self {
            process,
            confidence,
            method,
            timestamp: now(),
        }
    }

    pub fn unknown() -> Self {
        Self {
            process: ProcessInfo::unknown(),
            confidence: AttributionConfidence::None,
            method: AttributionMethod::None,
            timestamp: now(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttributionMethod {
    None,
    SocketTable,
    ConnectionTable,
    KernelHook,
    Procfs,
    Wfp,
    Heuristic,
}

impl std::fmt::Display for AttributionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttributionMethod::None => write!(f, "none"),
            AttributionMethod::SocketTable => write!(f, "socket_table"),
            AttributionMethod::ConnectionTable => write!(f, "connection_table"),
            AttributionMethod::KernelHook => write!(f, "kernel_hook"),
            AttributionMethod::Procfs => write!(f, "procfs"),
            AttributionMethod::Wfp => write!(f, "wfp"),
            AttributionMethod::Heuristic => write!(f, "heuristic"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProcessInfo;

    #[test]
    fn process_info_new_replaces_blank_name_with_pid_placeholder() {
        let info = ProcessInfo::new(4242, "   ");

        assert_eq!(info.name, "pid-4242");
    }

    #[test]
    fn process_info_new_trims_padded_name() {
        let info = ProcessInfo::new(4242, "  curl  ");

        assert_eq!(info.name, "curl");
    }

    #[test]
    fn process_info_deserialize_replaces_blank_name_with_pid_placeholder() {
        let json = r#"{
            "pid": 17,
            "name": "\u00a0\t\n",
            "path": null,
            "command_line": null,
            "user": null,
            "parent_pid": null,
            "created_at": null
        }"#;

        let info: ProcessInfo =
            serde_json::from_str(json).expect("process info should deserialize");

        assert_eq!(info.name, "pid-17");
    }

    #[test]
    fn process_info_deserialize_trims_padded_name() {
        let json = r#"{
            "pid": 17,
            "name": "  curl  ",
            "path": null,
            "command_line": null,
            "user": null,
            "parent_pid": null,
            "created_at": null
        }"#;

        let info: ProcessInfo =
            serde_json::from_str(json).expect("process info should deserialize");

        assert_eq!(info.name, "curl");
    }

    #[test]
    fn process_info_with_command_line_preserves_padding_when_not_blank() {
        let info = ProcessInfo::new(4242, "curl").with_command_line("  curl --help  ");

        assert_eq!(info.command_line(), Some("  curl --help  "));
    }

    #[test]
    fn process_info_with_command_line_drops_whitespace_only_command_line() {
        let info = ProcessInfo::new(4242, "curl").with_command_line("   ");

        assert_eq!(info.command_line(), None);
    }

    #[test]
    fn process_info_with_path_preserves_padding_when_not_blank() {
        let info = ProcessInfo::new(4242, "curl").with_path("  /bin/curl  ");

        assert_eq!(info.path(), Some("  /bin/curl  "));
    }

    #[test]
    fn process_info_with_path_drops_whitespace_only_path() {
        let info = ProcessInfo::new(4242, "curl").with_path("   ");

        assert_eq!(info.path(), None);
    }

    #[test]
    fn process_info_deserialize_preserves_padding_when_not_blank() {
        let json = r#"{
            "pid": 17,
            "name": "curl",
            "path": null,
            "command_line": "  curl --help  ",
            "user": null,
            "parent_pid": null,
            "created_at": null
        }"#;

        let info: ProcessInfo =
            serde_json::from_str(json).expect("process info should deserialize");

        assert_eq!(info.command_line(), Some("  curl --help  "));
    }

    #[test]
    fn process_info_deserialize_drops_whitespace_only_command_line() {
        let json = r#"{
            "pid": 17,
            "name": "curl",
            "path": null,
            "command_line": " \u0009 \n ",
            "user": null,
            "parent_pid": null,
            "created_at": null
        }"#;

        let info: ProcessInfo =
            serde_json::from_str(json).expect("process info should deserialize");

        assert_eq!(info.command_line(), None);
    }

    #[test]
    fn process_info_deserialize_preserves_padding_in_path_when_not_blank() {
        let json = r#"{
            "pid": 17,
            "name": "curl",
            "path": "  /bin/curl  ",
            "command_line": null,
            "user": null,
            "parent_pid": null,
            "created_at": null
        }"#;

        let info: ProcessInfo =
            serde_json::from_str(json).expect("process info should deserialize");

        assert_eq!(info.path(), Some("  /bin/curl  "));
    }

    #[test]
    fn process_info_deserialize_drops_whitespace_only_path() {
        let json = r#"{
            "pid": 17,
            "name": "curl",
            "path": "   ",
            "command_line": null,
            "user": null,
            "parent_pid": null,
            "created_at": null
        }"#;

        let info: ProcessInfo =
            serde_json::from_str(json).expect("process info should deserialize");

        assert_eq!(info.path(), None);
    }

    #[test]
    fn process_info_deserialize_drops_whitespace_only_user() {
        let json = r#"{
            "pid": 17,
            "name": "curl",
            "path": null,
            "command_line": null,
            "user": "   ",
            "parent_pid": null,
            "created_at": null
        }"#;

        let info: ProcessInfo =
            serde_json::from_str(json).expect("process info should deserialize");

        assert_eq!(info.user(), None);
    }
}
