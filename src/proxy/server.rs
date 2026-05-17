use axum::routing::{any, get};
use axum::{http::StatusCode, response::IntoResponse};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

use crate::admin;
use crate::app_state::AppState;
use crate::config::config::load_config;
use crate::config::reload::{shared_engine, watch_config};
use crate::metrics;
use crate::proxy::handler;
use crate::security::rate_limit::RateLimiter;

pub async fn run(port: u16, upstream: String, central: Option<String>, config_path: String, log_file: String) {
    let config = load_config(&config_path).expect("failed to load config");

    let (tx, rx) = mpsc::channel(1000);

    tokio::spawn(async move {
        crate::log::worker::start(rx, log_file).await;
    });

    let engine = shared_engine(&config);

    let wasm_engine = Arc::new(tokio::sync::RwLock::new(
        config.wasm_rules.as_ref().map(|wasm_configs| {
            crate::wasm::WasmEngine::new(wasm_configs)
        }),
    ));

    let threat_store = crate::threat::new_threat_store();
    if let Some(ref feeds) = config.threat_feeds {
        crate::threat::start_feeds(feeds.clone(), threat_store.clone()).await;
    }

    let user_store = crate::auth::users::init_user_store(&config.users);

    tokio::spawn(watch_config(
        config_path.clone(),
        engine.clone(),
        user_store.clone(),
        wasm_engine.clone(),
        threat_store.clone(),
    ));

    if let Some(central_addr) = central {
        let node_id = format!("node-{}", port);
        let client = crate::grpc::client::NodeClient::new(
            node_id,
            central_addr,
            engine.clone(),
        );
        tokio::spawn(async move {
            client.start_sync_loop().await;
        });
    }

    let state = Arc::new(AppState {
        rate_limiter: Mutex::new(RateLimiter::new(10, 5)),
        policy_engine: engine,
        log_tx: tx,
        config_path,
        wasm_engine,
        threat_store,
        user_store,
    });

    let app = admin::admin_router()
        .route("/metrics", get(prometheus_handler)
            .layer(axum::middleware::from_fn(crate::auth::require_auth)))
        .route("/*path", any(handler))
        .with_state((upstream, state));

    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    tracing::info!("Gatekeeper running on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind to address");

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    ).await {
        tracing::error!("server error: {}", e);
    }
}

fn metrics_http_response(result: Result<String, metrics::MetricsError>) -> impl IntoResponse {
    match result {
        Ok(body) => (StatusCode::OK, body).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "metrics scrape failed").into_response(),
    }
}

async fn prometheus_handler() -> impl IntoResponse {
    metrics_http_response(metrics::metrics_endpoint())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_response_is_500_when_encoder_fails() {
        let response = metrics_http_response(Err(metrics::MetricsError::Encode(
            prometheus::Error::Msg("forced".to_string()),
        )));
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
