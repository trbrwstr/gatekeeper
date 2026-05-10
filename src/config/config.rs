use serde::Deserialize;
use std::fs;

use crate::policy::rules::Rule;
use super::validate::validate_rules;

#[derive(Deserialize, Clone)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub wasm_rules: Option<Vec<WasmRuleConfig>>,
    pub threat_feeds: Option<Vec<ThreatFeedConfig>>,
    pub users: Option<Vec<UserConfig>>,
}

#[derive(Deserialize, Clone)]
pub struct WasmRuleConfig {
    pub name: String,
    pub path: String,
    pub priority: u32,
}

#[derive(Deserialize, Clone)]
pub struct ThreatFeedConfig {
    pub name: String,
    pub url: String,
    pub refresh_secs: u64,
    pub feed_type: String,
}

#[derive(Deserialize, Clone)]
pub struct UserConfig {
    pub username: String,
    pub password_hash: String,
    pub role: String,
}

pub fn load_config(path: &str) -> Result<Config, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read config: {}", e))?;

    let config: Config = toml::from_str(&content)
        .map_err(|e| format!("invalid config: {}", e))?;

    if let Err(errors) = validate_rules(&config.rules) {
        let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
        return Err(format!(
            "config has {} validation error(s): {}",
            errors.len(),
            msgs.join("; ")
        ));
    }

    Ok(config)
}
