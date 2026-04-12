use serde::{Deserialize, Serialize};

use crate::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: ProcessId,
    pub name: String,
    pub path: Option<String>,
    pub command_line: Option<String>,
    pub user: Option<String>,
    pub parent_pid: Option<ProcessId>,
    pub created_at: Option<Timestamp>,
}

impl ProcessInfo {
    pub fn new(pid: ProcessId, name: impl Into<String>) -> Self {
        Self {
            pid,
            name: name.into(),
            path: None,
            command_line: None,
            user: None,
            parent_pid: None,
            created_at: None,
        }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_command_line(mut self, cmd: impl Into<String>) -> Self {
        self.command_line = Some(cmd.into());
        self
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    pub fn with_parent(mut self, pid: ProcessId) -> Self {
        self.parent_pid = Some(pid);
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

    pub fn kernel() -> Self {
        Self {
            pid: 0,
            name: "<kernel>".to_string(),
            path: None,
            command_line: None,
            user: None,
            parent_pid: None,
            created_at: None,
        }
    }

    pub fn is_unknown(&self) -> bool {
        self.pid == 0 && self.name == "<unknown>"
    }

    pub fn is_kernel(&self) -> bool {
        self.pid == 0 && self.name == "<kernel>"
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

impl AttributionConfidence {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn from_u8(level: u8) -> Self {
        match level {
            0 => AttributionConfidence::None,
            1 => AttributionConfidence::Low,
            2 => AttributionConfidence::Medium,
            3 => AttributionConfidence::High,
            4.. => AttributionConfidence::Definitive,
        }
    }

    pub fn is_reliable(&self) -> bool {
        matches!(
            self,
            AttributionConfidence::High | AttributionConfidence::Definitive
        )
    }
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

    pub fn with_method(mut self, method: AttributionMethod) -> Self {
        self.method = method;
        self
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
