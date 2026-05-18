pub mod forward;
pub mod server;

use axum::{
    body::Body,
    extract::State,
    http::{Request, Response, StatusCode},
};
use std::sync::Arc;

use crate::{
    app_state::AppState,
    context::request::RequestContext,
    log::audit,
    metrics,
    policy::decision::{Decision, DecisionSource},
};

pub async fn handler(
    State((upstream, state)): State<(String, Arc<AppState>)>,
    req: Request<Body>,
) -> Response<Body> {
    let start = std::time::Instant::now();

    if let Some(len) = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
    {
        if len > state.max_body_bytes {
            return Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Body::from("Request body too large"))
                .unwrap();
        }
    }

    // Also cap streamed bodies that omit (or understate) Content-Length so a
    // chunked upload cannot exhaust memory; exceeding the cap aborts the
    // forwarded request rather than buffering it.
    let (parts, body) = req.into_parts();
    let req = Request::from_parts(
        parts,
        Body::new(http_body_util::Limited::new(body, state.max_body_bytes)),
    );

    let ctx = RequestContext::from(&req, state.trust_proxy_headers);

    // 1. Check threat feeds
    let threat_block = {
        let threat_data = state.threat_store.read().await;
        if threat_data.is_ip_blocked(&ctx.ip) {
            Some(Decision::Block {
                reason: "threat feed: blocked IP".into(),
                source: DecisionSource::ThreatFeed,
            })
        } else if ctx.user_agent.as_ref().is_some_and(|ua| threat_data.is_ua_blocked(ua)) {
            Some(Decision::Block {
                reason: "threat feed: blocked user agent".into(),
                source: DecisionSource::ThreatFeed,
            })
        } else {
            None
        }
    };

    // 2. Check WASM rules
    let wasm_decision = if threat_block.is_none() {
        let wasm = state.wasm_engine.read().await;
        wasm.as_ref().and_then(|w| w.evaluate(&ctx))
    } else {
        None
    };

    // 3. Check policy engine, 4. Fall back to rate limiter
    let decision = if let Some(d) = threat_block {
        d
    } else if let Some(d) = wasm_decision {
        d
    } else {
        let engine = state.policy_engine.load();
        if let Some(d) = engine.evaluate(&ctx) {
            d
        } else {
            let mut limiter = state.rate_limiter.lock().await;
            if limiter.check(&ctx.ip) {
                Decision::Allow {
                    reason: "rate_ok".into(),
                    source: DecisionSource::RateLimit,
                }
            } else {
                Decision::Block {
                    reason: "rate_limited".into(),
                    source: DecisionSource::RateLimit,
                }
            }
        }
    };

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    let latency = duration_ms as u128;

    let (decision_str, source) = match &decision {
        Decision::Allow { source, .. } => ("allow", source),
        Decision::Block { source, .. } => ("block", source),
        Decision::Throttle { source, .. } => ("throttle", source),
    };
    let source_str = &source.to_string();

    metrics::record_request(decision_str, source_str, duration_ms);
    audit::log(&state.log_tx, &ctx, &decision, latency).await;

    enforce(decision, req, &upstream, &ctx.ip).await
}

async fn enforce(
    decision: Decision,
    req: Request<Body>,
    upstream: &str,
    client_ip: &str,
) -> Response<Body> {
    match decision {
        Decision::Allow { .. } => {
            match forward::forward(req, upstream, client_ip).await {
                Ok(res) => res,
                Err(_) => Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("Upstream error"))
                    .unwrap(),
            }
        }

        Decision::Block { .. } => Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("Blocked by policy"))
            .unwrap(),

        Decision::Throttle { .. } => {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;

            match forward::forward(req, upstream, client_ip).await {
                Ok(res) => res,
                Err(_) => Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("Upstream error"))
                    .unwrap(),
            }
        }
    }
}
