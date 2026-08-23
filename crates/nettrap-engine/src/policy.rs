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
}
