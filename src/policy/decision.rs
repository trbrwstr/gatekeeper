#[derive(Debug, Clone)]
pub enum Decision {
    Allow {
        reason: String,
        source: DecisionSource,
    },

    Block {
        reason: String,
        source: DecisionSource,
    },

    Throttle {
        reason: String,
        source: DecisionSource,
    },
}

#[derive(Debug, Clone)]
pub enum DecisionSource {
    Rule,
    RateLimit,
    Wasm,
    ThreatFeed,
}

impl std::fmt::Display for DecisionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecisionSource::Rule => write!(f, "rule"),
            DecisionSource::RateLimit => write!(f, "rate_limit"),
            DecisionSource::Wasm => write!(f, "wasm"),
            DecisionSource::ThreatFeed => write!(f, "threat_feed"),
        }
    }
}
