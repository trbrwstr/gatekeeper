use crate::context::request::RequestContext;
use super::rules::Rule;

pub fn matches(rule: &Rule, ctx: &RequestContext) -> bool {
    if let Some(ref path) = rule.path_contains {
        if !ctx.path.contains(path) {
            return false;
        }
    }

    if let Some(ref method) = rule.method {
        if !ctx.method.eq_ignore_ascii_case(method) {
            return false;
        }
    }

    if let Some(ref agents) = rule.user_agent_contains {
        if let Some(ref ua) = ctx.user_agent {
            if !agents.iter().any(|a| ua.contains(a)) {
                return false;
            }
        } else {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::request::RequestContext;
    use crate::policy::rules::Rule;

    fn ctx(path: &str, method: &str, ua: Option<&str>) -> RequestContext {
        RequestContext {
            ip: "127.0.0.1".into(),
            path: path.into(),
            method: method.into(),
            user_agent: ua.map(|s| s.into()),
        }
    }

    fn rule(
        path: Option<&str>,
        method: Option<&str>,
        ua: Option<Vec<&str>>,
    ) -> Rule {
        Rule {
            name: "test".into(),
            path_contains: path.map(|s| s.into()),
            method: method.map(|s| s.into()),
            user_agent_contains: ua.map(|v| v.into_iter().map(String::from).collect()),
            action: "block".into(),
            priority: 1,
        }
    }

    #[test]
    fn matches_path() {
        let r = rule(Some("/api"), None, None);
        assert!(matches(&r, &ctx("/api/users", "GET", None)));
        assert!(!matches(&r, &ctx("/login", "GET", None)));
    }

    #[test]
    fn matches_method() {
        let r = rule(None, Some("POST"), None);
        assert!(matches(&r, &ctx("/any", "POST", None)));
        assert!(!matches(&r, &ctx("/any", "GET", None)));
    }

    #[test]
    fn matches_user_agent() {
        let r = rule(None, None, Some(vec!["curl", "wget"]));
        assert!(matches(&r, &ctx("/x", "GET", Some("curl/7.0"))));
        assert!(matches(&r, &ctx("/x", "GET", Some("wget/1.0"))));
        assert!(!matches(&r, &ctx("/x", "GET", Some("Mozilla"))));
        assert!(!matches(&r, &ctx("/x", "GET", None)));
    }

    #[test]
    fn matches_combined() {
        let r = rule(Some("/api"), Some("GET"), Some(vec!["curl"]));
        assert!(matches(&r, &ctx("/api/v1", "GET", Some("curl/7"))));
        assert!(!matches(&r, &ctx("/api/v1", "POST", Some("curl/7"))));
        assert!(!matches(&r, &ctx("/login", "GET", Some("curl/7"))));
    }

    #[test]
    fn empty_matchers_matches_everything() {
        let r = rule(None, None, None);
        assert!(matches(&r, &ctx("/anything", "DELETE", Some("bot"))));
    }

    #[test]
    fn method_matching_is_case_insensitive() {
        let r = rule(None, Some("POST"), None);
        assert!(matches(&r, &ctx("/any", "post", None)));
        assert!(matches(&r, &ctx("/any", "Post", None)));
        assert!(matches(&r, &ctx("/any", "POST", None)));

        let r2 = rule(None, Some("get"), None);
        assert!(matches(&r2, &ctx("/any", "GET", None)));
        assert!(matches(&r2, &ctx("/any", "get", None)));
    }
}
