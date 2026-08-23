//! Runtime policies that do not depend on a concrete listener or platform adapter.

pub mod health;
mod policy;
mod runtime;

pub use health::RuntimeHealth;
pub use policy::{FlowDecision, ParseFlowDecisionError};
pub use runtime::{RuntimeHost, RuntimeRunner};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupMode {
    Standard,
    ApiOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownReason {
    Signal,
    StopFlag,
    Fatal(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimePlan {
    mode: StartupMode,
    allow_zero_listeners: bool,
}

impl RuntimePlan {
    pub const fn standard(allow_zero_listeners: bool) -> Self {
        Self {
            mode: StartupMode::Standard,
            allow_zero_listeners,
        }
    }

    pub const fn api_only() -> Self {
        Self {
            mode: StartupMode::ApiOnly,
            allow_zero_listeners: true,
        }
    }

    pub const fn mode(self) -> StartupMode {
        self.mode
    }

    pub const fn allow_zero_listeners(self) -> bool {
        self.allow_zero_listeners
    }

    pub const fn listener_driven_outputs_enabled(self) -> bool {
        self.mode.listener_driven_outputs_enabled()
    }
}

impl StartupMode {
    pub const fn listener_driven_outputs_enabled(self) -> bool {
        matches!(self, Self::Standard)
    }
}

pub fn validate_listener_presence(
    mode: StartupMode,
    allow_zero_listeners: bool,
    has_spawnable_listeners: bool,
) -> nettrap_core::Result<()> {
    if allow_zero_listeners || matches!(mode, StartupMode::ApiOnly) || has_spawnable_listeners {
        return Ok(());
    }

    Err(nettrap_core::Error::Config(
        "No spawnable listeners remain after config expansion/filtering".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_mode_requires_spawnable_listener_by_default() {
        let result = validate_listener_presence(StartupMode::Standard, false, false);

        assert!(result.is_err());
    }

    #[test]
    fn api_only_mode_allows_zero_listeners() {
        let result = validate_listener_presence(StartupMode::ApiOnly, false, false);

        assert!(result.is_ok());
    }

    #[test]
    fn explicit_zero_listener_policy_allows_standard_mode() {
        let result = validate_listener_presence(StartupMode::Standard, true, false);

        assert!(result.is_ok());
    }

    #[test]
    fn standard_runtime_plan_preserves_zero_listener_policy() {
        let plan = RuntimePlan::standard(true);

        assert_eq!(plan.mode(), StartupMode::Standard);
        assert!(plan.allow_zero_listeners());
        assert!(plan.listener_driven_outputs_enabled());
    }

    #[test]
    fn api_only_runtime_plan_allows_zero_listeners_without_listener_outputs() {
        let plan = RuntimePlan::api_only();

        assert_eq!(plan.mode(), StartupMode::ApiOnly);
        assert!(plan.allow_zero_listeners());
        assert!(!plan.listener_driven_outputs_enabled());
    }
}
