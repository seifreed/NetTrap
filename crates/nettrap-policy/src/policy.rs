use hashbrown::HashMap;

use crate::prelude::*;

#[derive(Debug, Clone)]
pub struct PolicyContext<'a> {
    pub flow: &'a Flow,
    pub packet: Option<&'a Packet>,
}

pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
    default_decision: PolicyDecision,
    stats: parking_lot::RwLock<PolicyStats>,
}

#[derive(Debug, Default, Clone)]
pub struct PolicyStats {
    pub total_evaluations: u64,
    pub decisions: HashMap<String, u64>,
}

impl PolicyEngine {
    pub fn new(default_decision: PolicyDecision) -> Self {
        Self {
            rules: Vec::new(),
            default_decision,
            stats: parking_lot::RwLock::new(PolicyStats::default()),
        }
    }

    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        self.rules.sort_by(|a, b| a.priority.cmp(&b.priority));
    }

    pub fn add_rules(&mut self, rules: impl IntoIterator<Item = PolicyRule>) {
        self.rules.extend(rules);
        self.rules.sort_by(|a, b| a.priority.cmp(&b.priority));
    }

    pub fn remove_rule(&mut self, id: &str) -> bool {
        let len = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.rules.len() < len
    }

    pub fn clear_rules(&mut self) {
        self.rules.clear();
    }

    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    pub fn evaluate(&self, ctx: &PolicyContext) -> PolicyDecision {
        self.stats.write().total_evaluations += 1;

        for rule in &self.rules {
            if rule.matches(ctx) {
                self.increment_decision(rule.decision);
                return rule.decision;
            }
        }

        self.increment_decision(self.default_decision);
        self.default_decision
    }

    pub fn decide(&self, flow: &Flow) -> PolicyDecision {
        let ctx = PolicyContext { flow, packet: None };
        self.evaluate(&ctx)
    }

    pub fn decide_with_packet(&self, flow: &Flow, packet: &Packet) -> PolicyDecision {
        let ctx = PolicyContext {
            flow,
            packet: Some(packet),
        };
        self.evaluate(&ctx)
    }

    pub fn stats(&self) -> PolicyStats {
        self.stats.read().clone()
    }

    pub fn increment_decision(&self, decision: PolicyDecision) {
        let mut stats = self.stats.write();
        let key = decision.to_string();
        *stats.decisions.entry(key).or_insert(0) += 1;
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(PolicyDecision::default())
    }
}
