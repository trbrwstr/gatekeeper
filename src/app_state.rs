use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};

use crate::auth::users::UserStore;
use crate::config::reload::SharedEngine;
use crate::security::rate_limit::RateLimiter;
use crate::threat::ThreatStore;
use crate::wasm::WasmEngine;

pub type SharedWasmEngine = Arc<RwLock<Option<WasmEngine>>>;

pub struct AppState {
    pub rate_limiter: Mutex<RateLimiter>,
    pub policy_engine: SharedEngine,
    pub log_tx: mpsc::Sender<String>,
    pub config_path: String,
    pub wasm_engine: SharedWasmEngine,
    pub threat_store: ThreatStore,
    pub user_store: UserStore,
}
