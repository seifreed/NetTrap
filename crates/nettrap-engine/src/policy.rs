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

/// Attributes available to ordered flow-policy rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowPolicyContext<'a> {
    pub listener: &'a str,
    pub protocol: &'a str,
    pub source_host: Option<&'a str>,
    pub destination_host: Option<&'a str>,
    pub destination_port: Option<u16>,
    pub process_name: Option<&'a str>,
}

/// One ordered policy rule. All populated matchers must match; rules are
/// evaluated in declaration order and the first match wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowPolicyRuleSpec {
    pub listener: Option<String>,
    pub protocol: Option<String>,
    pub source_host: Option<String>,
    pub destination_host: Option<String>,
    pub destination_port: Option<u16>,
    pub process_name: Option<String>,
    pub decision: FlowDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowPolicyResolution {
    decision: FlowDecision,
    rule: FlowPolicyRule,
    rule_index: Option<usize>,
}

impl FlowPolicyResolution {
    pub const fn decision(self) -> FlowDecision {
        self.decision
    }

    pub const fn rule(self) -> FlowPolicyRule {
        self.rule
    }

    pub const fn rule_index(self) -> Option<usize> {
        self.rule_index
    }

    pub fn rule_label(self) -> String {
        self.rule_index.map_or_else(
            || self.rule.as_str().to_string(),
            |index| format!("flow_rules[{}]", index + 1),
        )
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
                rule_index: None,
            };
        }

        FlowPolicyResolution {
            decision: self.default_decision,
            rule: FlowPolicyRule::Default,
            rule_index: None,
        }
    }
}

/// Runtime policy that combines the stable default policy with ordered rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredFlowPolicy {
    default: FlowPolicy,
    rules: Vec<FlowPolicyRuleSpec>,
}

impl ConfiguredFlowPolicy {
    pub fn new(default_decision: FlowDecision, rules: Vec<FlowPolicyRuleSpec>) -> Self {
        Self {
            default: FlowPolicy::new(default_decision),
            rules,
        }
    }

    pub fn resolve_for_context(
        &self,
        context: FlowPolicyContext<'_>,
        emulate_response: bool,
    ) -> FlowPolicyResolution {
        if let Some((index, rule)) = self
            .rules
            .iter()
            .enumerate()
            .find(|(_, rule)| rule.matches(context))
        {
            return FlowPolicyResolution {
                decision: rule.decision,
                rule: FlowPolicyRule::Default,
                rule_index: Some(index),
            };
        }

        self.default.resolve(emulate_response)
    }
}

impl FlowPolicyRuleSpec {
    fn matches(&self, context: FlowPolicyContext<'_>) -> bool {
        self.listener
            .as_deref()
            .is_none_or(|value| value.eq_ignore_ascii_case(context.listener))
            && self
                .protocol
                .as_deref()
                .is_none_or(|value| value.eq_ignore_ascii_case(context.protocol))
            && self.source_host.as_deref().is_none_or(|value| {
                context
                    .source_host
                    .is_some_and(|candidate| value.eq_ignore_ascii_case(candidate))
            })
            && self.destination_host.as_deref().is_none_or(|value| {
                context
                    .destination_host
                    .is_some_and(|candidate| value.eq_ignore_ascii_case(candidate))
            })
            && self
                .destination_port
                .is_none_or(|value| context.destination_port == Some(value))
            && self.process_name.as_deref().is_none_or(|value| {
                context
                    .process_name
                    .is_some_and(|candidate| value.eq_ignore_ascii_case(candidate))
            })
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
        assert_eq!(disabled.rule_index(), None);

        let blocked = FlowPolicy::new(FlowDecision::Block).resolve(false);
        assert_eq!(blocked.decision(), FlowDecision::Block);
        assert_eq!(blocked.rule(), FlowPolicyRule::Default);
    }

    #[test]
    fn test_flow_policy_uses_first_matching_ordered_rule() {
        let policy = ConfiguredFlowPolicy::new(
            FlowDecision::Emulate,
            vec![
                FlowPolicyRuleSpec {
                    listener: Some("http".to_string()),
                    protocol: Some("tcp".to_string()),
                    source_host: None,
                    destination_host: None,
                    destination_port: Some(443),
                    process_name: None,
                    decision: FlowDecision::Block,
                },
                FlowPolicyRuleSpec {
                    listener: Some("http".to_string()),
                    protocol: None,
                    source_host: None,
                    destination_host: None,
                    destination_port: None,
                    process_name: None,
                    decision: FlowDecision::Capture,
                },
            ],
        );
        let resolution = policy.resolve_for_context(
            FlowPolicyContext {
                listener: "HTTP",
                protocol: "TCP",
                source_host: Some("127.0.0.1"),
                destination_host: Some("10.0.0.1"),
                destination_port: Some(443),
                process_name: None,
            },
            true,
        );

        assert_eq!(resolution.decision(), FlowDecision::Block);
        assert_eq!(resolution.rule(), FlowPolicyRule::Default);
        assert_eq!(resolution.rule_index(), Some(0));
        assert_eq!(resolution.rule_label(), "flow_rules[1]");
    }

    #[test]
    fn test_flow_policy_requires_all_populated_matchers() {
        let policy = ConfiguredFlowPolicy::new(
            FlowDecision::Emulate,
            vec![FlowPolicyRuleSpec {
                listener: Some("http".to_string()),
                protocol: None,
                source_host: None,
                destination_host: None,
                destination_port: None,
                process_name: Some("curl".to_string()),
                decision: FlowDecision::Sinkhole,
            }],
        );
        let unmatched = policy.resolve_for_context(
            FlowPolicyContext {
                listener: "http",
                protocol: "tcp",
                source_host: None,
                destination_host: None,
                destination_port: Some(80),
                process_name: None,
            },
            true,
        );

        assert_eq!(unmatched.decision(), FlowDecision::Emulate);
        assert_eq!(unmatched.rule(), FlowPolicyRule::Default);
    }
}
