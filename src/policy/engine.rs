use crate::context::request::RequestContext;
use crate::policy::decision::{Decision, DecisionSource};

use super::{matcher, rules::Rule};

pub struct PolicyEngine {
    pub rules: Vec<Rule>,
}

impl PolicyEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    pub fn evaluate(&self, ctx: &RequestContext) -> Option<Decision> {
        let mut matched: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|r| matcher::matches(r, ctx))
            .collect();

        if matched.is_empty() {
            return None;
        }

        matched.sort_by_key(|r| std::cmp::Reverse(r.priority));

        let rule = matched[0];

        Some(map_action(&rule.action, &rule.name))
    }
}

fn map_action(action: &str, rule_name: &str) -> Decision {
    match action {
        "allow" => Decision::Allow {
            reason: rule_name.to_string(),
            source: DecisionSource::Rule,
        },

        "block" => Decision::Block {
            reason: rule_name.to_string(),
            source: DecisionSource::Rule,
        },

        "throttle" => Decision::Throttle {
            reason: rule_name.to_string(),
            source: DecisionSource::Rule,
        },

        _ => Decision::Allow {
            reason: "unknown".into(),
            source: DecisionSource::Rule,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::request::RequestContext;
    use crate::policy::rules::Rule;

    fn ctx(path: &str) -> RequestContext {
        RequestContext {
            ip: "1.2.3.4".into(),
            path: path.into(),
            method: "GET".into(),
            user_agent: None,
        }
    }

    #[test]
    fn no_rules_returns_none() {
        let engine = PolicyEngine::new(vec![]);
        assert!(engine.evaluate(&ctx("/anything")).is_none());
    }

    #[test]
    fn matching_rule_returns_decision() {
        let engine = PolicyEngine::new(vec![Rule {
            name: "block_api".into(),
            path_contains: Some("/api".into()),
            method: None,
            user_agent_contains: None,
            action: "block".into(),
            priority: 10,
        }]);
        let d = engine.evaluate(&ctx("/api/users"));
        assert!(matches!(d, Some(Decision::Block { .. })));
    }

    #[test]
    fn non_matching_rule_returns_none() {
        let engine = PolicyEngine::new(vec![Rule {
            name: "block_api".into(),
            path_contains: Some("/api".into()),
            method: None,
            user_agent_contains: None,
            action: "block".into(),
            priority: 10,
        }]);
        assert!(engine.evaluate(&ctx("/login")).is_none());
    }

    #[test]
    fn highest_priority_wins() {
        let engine = PolicyEngine::new(vec![
            Rule {
                name: "allow_api".into(),
                path_contains: Some("/api".into()),
                method: None,
                user_agent_contains: None,
                action: "allow".into(),
                priority: 10,
            },
            Rule {
                name: "block_api".into(),
                path_contains: Some("/api".into()),
                method: None,
                user_agent_contains: None,
                action: "block".into(),
                priority: 100,
            },
        ]);
        let d = engine.evaluate(&ctx("/api/data")).unwrap();
        assert!(matches!(d, Decision::Block { reason, .. } if reason == "block_api"));
    }
}
