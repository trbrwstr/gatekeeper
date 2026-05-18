pub mod feeds;

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;

use crate::config::ThreatFeedConfig;

pub type ThreatStore = Arc<RwLock<ThreatData>>;

/// Handles to the currently running per-feed refresh tasks. Tracked so that a
/// config reload can cancel the old tasks instead of leaking a growing set of
/// background loops that keep overwriting the threat store.
pub type FeedHandles = Arc<Mutex<Vec<JoinHandle<()>>>>;

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

pub fn new_feed_handles() -> FeedHandles {
    Arc::new(Mutex::new(Vec::new()))
}

pub async fn start_feeds(
    configs: Vec<ThreatFeedConfig>,
    store: ThreatStore,
    handles: &FeedHandles,
) {
    let mut guard = handles.lock().await;
    for handle in guard.drain(..) {
        handle.abort();
    }
    for config in configs {
        let store = store.clone();
        guard.push(tokio::spawn(async move {
            feeds::run_feed(config, store).await;
        }));
    }
}
