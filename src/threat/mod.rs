pub mod feeds;

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::config::ThreatFeedConfig;

pub type ThreatStore = Arc<RwLock<ThreatData>>;

#[derive(Default)]
pub struct ThreatData {
    pub blocked_ips: HashSet<String>,
    pub blocked_user_agents: HashSet<String>,
}

impl ThreatData {
    pub fn is_ip_blocked(&self, ip: &str) -> bool {
        self.blocked_ips.contains(ip)
    }

    pub fn is_ua_blocked(&self, ua: &str) -> bool {
        self.blocked_user_agents.iter().any(|blocked| ua.contains(blocked))
    }
}

pub fn new_threat_store() -> ThreatStore {
    Arc::new(RwLock::new(ThreatData::default()))
}

pub async fn start_feeds(configs: Vec<ThreatFeedConfig>, store: ThreatStore) {
    for config in configs {
        let store = store.clone();
        tokio::spawn(async move {
            feeds::run_feed(config, store).await;
        });
    }
}
