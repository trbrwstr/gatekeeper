use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::app_state::AppState;
use crate::auth::{jwt, users};
use crate::config::config::load_config;
use crate::config::validate::validate_rules;
use crate::metrics;
use crate::policy::engine::PolicyEngine;
use crate::policy::rules::Rule;

pub fn api_router() -> Router<(String, Arc<AppState>)> {
    Router::new()
        .route("/admin/api/stats", get(stats_handler))
        .route("/admin/api/rules", get(rules_handler))
        .route("/admin/api/rules/validate", post(validate_handler))
        .route("/admin/api/reload", post(reload_handler))
}

pub fn user_api_router() -> Router<(String, Arc<AppState>)> {
    Router::new()
        .route("/admin/api/users", get(list_users_handler).post(add_user_handler))
        .route("/admin/api/users/:username", delete(remove_user_handler))
}

pub fn login_router() -> Router<(String, Arc<AppState>)> {
    Router::new().route("/admin/api/login", post(login_handler))
}

#[derive(Serialize)]
struct StatsResponse {
    metrics_text: String,
}

async fn stats_handler() -> impl IntoResponse {
    let metrics_text = metrics::metrics_endpoint()
        .unwrap_or_else(|e| format!("# {}\n", e));

    Json(StatsResponse { metrics_text })
    match metrics::metrics_endpoint() {
        Ok(metrics_text) => Json(StatsResponse { metrics_text }).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "metrics scrape failed").into_response(),
    }
}

async fn rules_handler(
    State((_, state)): State<(String, Arc<AppState>)>,
) -> impl IntoResponse {
    let engine = state.policy_engine.load();
    Json(engine.rules.clone())
}

#[derive(Deserialize)]
struct ValidateRequest {
    rules: Vec<Rule>,
}

#[derive(Serialize)]
struct ValidateResponse {
    valid: bool,
    errors: Vec<String>,
}

async fn validate_handler(Json(payload): Json<ValidateRequest>) -> impl IntoResponse {
    match validate_rules(&payload.rules) {
        Ok(()) => Json(ValidateResponse {
            valid: true,
            errors: vec![],
        }),
        Err(errors) => Json(ValidateResponse {
            valid: false,
            errors: errors.iter().map(|e| e.to_string()).collect(),
        }),
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login_handler(
    State((_, state)): State<(String, Arc<AppState>)>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let store = state.user_store.read().await;
    let has_users = !store.is_empty();
    drop(store);

    if has_users {
        match users::authenticate(&state.user_store, &payload.username, &payload.password).await {
            Some(role) => {
                let token = jwt::issue_token(&payload.username, &role);
                (StatusCode::OK, Json(serde_json::json!({ "token": token }))).into_response()
            }
            None => (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(),
        }
    } else {
        let admin_user = match std::env::var("GATEKEEPER_ADMIN_USER") {
            Ok(u) => u,
            Err(_) => return (StatusCode::UNAUTHORIZED, "no users configured and GATEKEEPER_ADMIN_USER not set").into_response(),
        };
        let admin_pass = match std::env::var("GATEKEEPER_ADMIN_PASS") {
            Ok(p) => p,
            Err(_) => return (StatusCode::UNAUTHORIZED, "no users configured and GATEKEEPER_ADMIN_PASS not set").into_response(),
        };

        if payload.username == admin_user && payload.password == admin_pass {
            let token = jwt::issue_token(&payload.username, "admin");
            (StatusCode::OK, Json(serde_json::json!({ "token": token }))).into_response()
        } else {
            (StatusCode::UNAUTHORIZED, "invalid credentials").into_response()
        }
    }
}

async fn reload_handler(
    State((_, state)): State<(String, Arc<AppState>)>,
) -> impl IntoResponse {
    match load_config(&state.config_path) {
        Ok(new_config) => {
            let new_engine = PolicyEngine::new(new_config.rules);
            state.policy_engine.store(Arc::new(new_engine));
            users::reload_users(&state.user_store, &new_config.users).await;

            let new_wasm = new_config.wasm_rules.as_ref().map(|wasm_configs| {
                crate::wasm::WasmEngine::new(wasm_configs)
            });
            *state.wasm_engine.write().await = new_wasm;

            if let Some(ref feeds) = new_config.threat_feeds {
                let mut data = state.threat_store.write().await;
                data.blocked_ips.clear();
                data.blocked_user_agents.clear();
                drop(data);
                crate::threat::start_feeds(feeds.clone(), state.threat_store.clone()).await;
            }

            (StatusCode::OK, "config reloaded successfully".to_string())
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            format!("config reload failed: {}", e),
        ),
    }
}

async fn list_users_handler(
    State((_, state)): State<(String, Arc<AppState>)>,
) -> impl IntoResponse {
    Json(users::list_users(&state.user_store).await)
}

#[derive(Deserialize)]
struct AddUserRequest {
    username: String,
    password: String,
    role: String,
}

async fn add_user_handler(
    State((_, state)): State<(String, Arc<AppState>)>,
    Json(payload): Json<AddUserRequest>,
) -> impl IntoResponse {
    match users::add_user(&state.user_store, &payload.username, &payload.password, &payload.role).await {
        Ok(()) => (StatusCode::CREATED, "user created").into_response(),
        Err(e) => (StatusCode::CONFLICT, e).into_response(),
    }
}

async fn remove_user_handler(
    State((_, state)): State<(String, Arc<AppState>)>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    match users::remove_user(&state.user_store, &username).await {
        Ok(()) => (StatusCode::OK, "user removed").into_response(),
        Err(e) => (StatusCode::NOT_FOUND, e).into_response(),
    }
}
