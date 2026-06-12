use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::app_state::SharedWasmEngine;
use crate::auth::users::UserStore;
use crate::config::{load_config, Config};
use crate::policy::engine::PolicyEngine;
use crate::threat::{FeedHandles, ThreatStore};

pub type SharedEngine = Arc<ArcSwap<PolicyEngine>>;

pub fn shared_engine(config: &Config) -> SharedEngine {
    Arc::new(ArcSwap::from_pointee(PolicyEngine::new(config.rules.clone())))
}

/// Atomically swap in a freshly loaded config. Shared by the file watcher and
/// the admin reload endpoint so the reload semantics stay identical and the
/// previous threat-feed tasks are always cancelled before new ones start.
pub async fn apply_config(
    new_config: Config,
    engine: &SharedEngine,
    user_store: &UserStore,
    wasm_engine: &SharedWasmEngine,
    threat_store: &ThreatStore,
    feed_handles: &FeedHandles,
) {
    engine.store(Arc::new(PolicyEngine::new(new_config.rules)));
    crate::auth::users::reload_users(user_store, &new_config.users).await;

    let new_wasm = new_config
        .wasm_rules
        .as_ref()
        .map(|wasm_configs| crate::wasm::WasmEngine::new(wasm_configs));
    *wasm_engine.write().await = new_wasm;

    {
        let mut data = threat_store.write().await;
        data.blocked_ips.clear();
        data.blocked_user_agents.clear();
    }
    crate::threat::start_feeds(
        new_config.threat_feeds.unwrap_or_default(),
        threat_store.clone(),
        feed_handles,
    )
    .await;
}

pub async fn watch_config(
    config_path: String,
    engine: SharedEngine,
    user_store: UserStore,
    wasm_engine: SharedWasmEngine,
    threat_store: ThreatStore,
    feed_handles: FeedHandles,
) {
    let (tx, mut rx) = mpsc::channel::<()>(1);

    let path = config_path.clone();
    std::thread::spawn(move || {
        let rt_tx = tx;
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    if matches!(event.kind, EventKind::Modify(_)) {
                        let _ = rt_tx.blocking_send(());
                    }
                }
            },
            notify::Config::default(),
        )
        .expect("failed to create file watcher");

        watcher
            .watch(Path::new(&path), RecursiveMode::NonRecursive)
            .expect("failed to watch config file");

        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    });

    while rx.recv().await.is_some() {
        tokio::time::sleep(Duration::from_millis(100)).await;

        info!("config file changed, reloading...");

        match load_config(&config_path) {
            Ok(new_config) => {
                apply_config(
                    new_config,
                    &engine,
                    &user_store,
                    &wasm_engine,
                    &threat_store,
                    &feed_handles,
                )
                .await;
                info!("config reloaded successfully");
            }
            Err(e) => {
                error!("config reload failed: {}, keeping previous config", e);
            }
        }
    }
}
