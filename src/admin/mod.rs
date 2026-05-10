pub mod api;

use axum::{routing::get, Router};
use rust_embed::Embed;
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::extract::Path;
use std::sync::Arc;

use crate::app_state::AppState;

#[derive(Embed)]
#[folder = "src/admin/ui/"]
struct Assets;

pub fn admin_router() -> Router<(String, Arc<AppState>)> {
    api::api_router()
        .layer(axum::middleware::from_fn(crate::auth::require_admin))
        .merge(
            api::user_api_router()
                .layer(axum::middleware::from_fn(crate::auth::require_user_admin)),
        )
        .merge(api::login_router())
        .route("/admin", get(index_handler))
        .route("/admin/assets/*file", get(static_handler))
}

async fn index_handler() -> impl IntoResponse {
    match Assets::get("index.html") {
        Some(content) => Html(
            std::str::from_utf8(content.data.as_ref())
                .unwrap_or("")
                .to_string(),
        )
        .into_response(),
        None => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

async fn static_handler(Path(path): Path<String>) -> impl IntoResponse {
    match Assets::get(&path) {
        Some(content) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            Response::builder()
                .header(header::CONTENT_TYPE, mime.as_ref())
                .body(axum::body::Body::from(content.data.to_vec()))
                .unwrap()
        }
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(axum::body::Body::from("Not found"))
            .unwrap(),
    }
}
