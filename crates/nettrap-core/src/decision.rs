use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyDecision {
    Intercept,
    Emulate,
    Passthrough,
    Block,
    Sinkhole,
    Drop,
}

impl Default for PolicyDecision {
    fn default() -> Self {
        PolicyDecision::Intercept
    }
}

impl std::fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyDecision::Intercept => write!(f, "intercept"),
            PolicyDecision::Emulate => write!(f, "emulate"),
            PolicyDecision::Passthrough => write!(f, "passthrough"),
            PolicyDecision::Block => write!(f, "block"),
            PolicyDecision::Sinkhole => write!(f, "sinkhole"),
            PolicyDecision::Drop => write!(f, "drop"),
        }
    }
}

impl PolicyDecision {
    pub fn should_intercept(&self) -> bool {
        matches!(self, PolicyDecision::Intercept | PolicyDecision::Emulate)
    }

    pub fn should_block(&self) -> bool {
        matches!(self, PolicyDecision::Block | PolicyDecision::Drop)
    }

    pub fn should_emulate(&self) -> bool {
        matches!(self, PolicyDecision::Emulate)
    }

    pub fn allows_passthrough(&self) -> bool {
        matches!(self, PolicyDecision::Passthrough)
    }
}
