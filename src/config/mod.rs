pub mod reload;
pub mod validate;

use serde::Deserialize;
use std::fs;

use crate::config::validate::validate_rules;
use crate::policy::rules::Rule;

#[derive(Deserialize, Clone)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub wasm_rules: Option<Vec<WasmRuleConfig>>,
    pub threat_feeds: Option<Vec<ThreatFeedConfig>>,
    pub users: Option<Vec<UserConfig>>,

    /// When false (the default), `X-Forwarded-For` / `X-Real-IP` are ignored
    /// and the TCP peer address is used as the client IP. Only enable this
    /// when Gatekeeper sits behind a trusted proxy that overwrites these
    /// headers, otherwise clients can spoof their source IP to bypass rate
    /// limiting and IP blocklists.
    #[serde(default)]
    pub trust_proxy_headers: bool,

    /// Maximum allowed request body size in bytes. Requests advertising a
    /// larger `Content-Length` are rejected with 413 before any upstream
    /// connection is made.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
}

fn default_max_body_bytes() -> usize {
    10 * 1024 * 1024
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
