use crate::policy::rules::Rule;

#[derive(Debug)]
pub struct ValidationError {
    pub rule_name: String,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rule '{}': {}", self.rule_name, self.message)
    }
}

pub fn validate_rules(rules: &[Rule]) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    for rule in rules {
        if rule.name.is_empty() {
            errors.push(ValidationError {
                rule_name: "(unnamed)".into(),
                message: "rule name cannot be empty".into(),
            });
        }

        let valid_actions = ["allow", "block", "throttle"];
        if !valid_actions.contains(&rule.action.as_str()) {
            errors.push(ValidationError {
                rule_name: rule.name.clone(),
                message: format!(
                    "invalid action '{}', must be one of: allow, block, throttle",
                    rule.action
                ),
            });
        }

        if rule.priority == 0 {
            errors.push(ValidationError {
                rule_name: rule.name.clone(),
                message: "priority must be greater than 0".into(),
            });
        }

        let has_matcher = rule.path_contains.is_some()
            || rule.method.is_some()
            || rule.user_agent_contains.is_some();

        if !has_matcher {
            errors.push(ValidationError {
                rule_name: rule.name.clone(),
                message: "rule must have at least one matcher (path_contains, method, or user_agent_contains)".into(),
            });
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::rules::Rule;

    fn valid_rule() -> Rule {
        Rule {
            name: "test_rule".into(),
            path_contains: Some("/api".into()),
            method: None,
            user_agent_contains: None,
            action: "block".into(),
            priority: 1,
        }
    }

    #[test]
    fn valid_rule_passes() {
        assert!(validate_rules(&[valid_rule()]).is_ok());
    }

    #[test]
    fn empty_name_fails() {
        let mut r = valid_rule();
        r.name = "".into();
        assert!(validate_rules(&[r]).is_err());
    }

    #[test]
    fn invalid_action_fails() {
        let mut r = valid_rule();
        r.action = "destroy".into();
        assert!(validate_rules(&[r]).is_err());
    }

    #[test]
    fn zero_priority_fails() {
        let mut r = valid_rule();
        r.priority = 0;
        assert!(validate_rules(&[r]).is_err());
    }

    #[test]
    fn no_matchers_fails() {
        let r = Rule {
            name: "test".into(),
            path_contains: None,
            method: None,
            user_agent_contains: None,
            action: "allow".into(),
            priority: 1,
        };
        assert!(validate_rules(&[r]).is_err());
    }

    #[test]
    fn multiple_errors_collected() {
        let r = Rule {
            name: "".into(),
            path_contains: None,
            method: None,
            user_agent_contains: None,
            action: "nuke".into(),
            priority: 0,
        };
        let errs = validate_rules(&[r]).unwrap_err();
        assert!(errs.len() >= 3);
    }
}
