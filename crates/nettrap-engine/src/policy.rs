use std::fmt;
use std::str::FromStr;

/// Action selected for an intercepted flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowDecision {
    Pass,
    Capture,
    Emulate,
    Sinkhole,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowPolicyRule {
    Default,
    ListenerEmulationDisabled,
}

impl FlowPolicyRule {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default_decision",
            Self::ListenerEmulationDisabled => "listener.emulate_response=false",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowPolicyResolution {
    decision: FlowDecision,
    rule: FlowPolicyRule,
}

impl FlowPolicyResolution {
    pub const fn decision(self) -> FlowDecision {
        self.decision
    }

    pub const fn rule(self) -> FlowPolicyRule {
        self.rule
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowPolicy {
    default_decision: FlowDecision,
}

impl FlowPolicy {
    pub const fn new(default_decision: FlowDecision) -> Self {
        Self { default_decision }
    }

    pub const fn resolve(self, emulate_response: bool) -> FlowPolicyResolution {
        if matches!(self.default_decision, FlowDecision::Emulate) && !emulate_response {
            return FlowPolicyResolution {
                decision: FlowDecision::Capture,
                rule: FlowPolicyRule::ListenerEmulationDisabled,
            };
        }

        FlowPolicyResolution {
            decision: self.default_decision,
            rule: FlowPolicyRule::Default,
        }
    }
}

impl FlowDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Capture => "capture",
            Self::Emulate => "emulate",
            Self::Sinkhole => "sinkhole",
            Self::Block => "block",
        }
    }
}

impl fmt::Display for FlowDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseFlowDecisionError;

impl fmt::Display for ParseFlowDecisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unsupported flow decision")
    }
}

impl std::error::Error for ParseFlowDecisionError {}

impl FromStr for FlowDecision {
    type Err = ParseFlowDecisionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pass" | "passthrough" => Ok(Self::Pass),
            "capture" => Ok(Self::Capture),
            "emulate" | "intercept" => Ok(Self::Emulate),
            "sinkhole" => Ok(Self::Sinkhole),
            "block" => Ok(Self::Block),
            _ => Err(ParseFlowDecisionError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_decision_parse_supported_values_and_migration_aliases() {
        assert_eq!("pass".parse(), Ok(FlowDecision::Pass));
        assert_eq!("passthrough".parse(), Ok(FlowDecision::Pass));
        assert_eq!("capture".parse(), Ok(FlowDecision::Capture));
        assert_eq!("emulate".parse(), Ok(FlowDecision::Emulate));
        assert_eq!("intercept".parse(), Ok(FlowDecision::Emulate));
        assert_eq!("sinkhole".parse(), Ok(FlowDecision::Sinkhole));
        assert_eq!("block".parse(), Ok(FlowDecision::Block));
        assert!("drop".parse::<FlowDecision>().is_err());
    }

    #[test]
    fn test_flow_policy_resolve_disables_only_emulation() {
        let disabled = FlowPolicy::new(FlowDecision::Emulate).resolve(false);
        assert_eq!(disabled.decision(), FlowDecision::Capture);
        assert_eq!(disabled.rule(), FlowPolicyRule::ListenerEmulationDisabled);

        let blocked = FlowPolicy::new(FlowDecision::Block).resolve(false);
        assert_eq!(blocked.decision(), FlowDecision::Block);
        assert_eq!(blocked.rule(), FlowPolicyRule::Default);
    }
}
