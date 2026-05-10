use std::time::Duration;
use tokio::time;
use tracing::{error, info};

use crate::config::config::ThreatFeedConfig;
use super::ThreatStore;

pub async fn run_feed(config: ThreatFeedConfig, store: ThreatStore) {
    let mut interval = time::interval(Duration::from_secs(config.refresh_secs));

    loop {
        interval.tick().await;

        info!("refreshing threat feed: {}", config.name);

        match fetch_feed(&config.url).await {
            Ok(entries) => {
                let mut data = store.write().await;
                match config.feed_type.as_str() {
                    "ip" => {
                        data.blocked_ips.clear();
                        for entry in entries {
                            data.blocked_ips.insert(entry);
                        }
                    }
                    "user_agent" => {
                        data.blocked_user_agents.clear();
                        for entry in entries {
                            data.blocked_user_agents.insert(entry);
                        }
                    }
                    _ => {
                        error!("unknown feed type: {}", config.feed_type);
                    }
                }
                info!("threat feed '{}' updated ({} blocked IPs, {} blocked UAs)",
                    config.name, data.blocked_ips.len(), data.blocked_user_agents.len());
            }
            Err(e) => {
                error!("failed to fetch threat feed '{}': {}", config.name, e);
            }
        }
    }
}

async fn fetch_feed(url: &str) -> Result<Vec<String>, reqwest::Error> {
    let response = reqwest::get(url).await?;
    let body = response.text().await?;

    let entries: Vec<String> = body
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    Ok(entries)
}
