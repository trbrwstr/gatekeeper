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

    let ctx = RequestContext::from(&req);

    // 1. Check threat feeds
    let threat_block = {
        let threat_data = state.threat_store.read().await;
        if threat_data.is_ip_blocked(&ctx.ip) {
            Some(Decision::Block {
                reason: "threat feed: blocked IP".into(),
                source: DecisionSource::ThreatFeed,
            })
        } else if ctx.user_agent.as_ref().map_or(false, |ua| threat_data.is_ua_blocked(ua)) {
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

    enforce(decision, req, &upstream).await
}

async fn enforce(
    decision: Decision,
    req: Request<Body>,
    upstream: &str,
) -> Response<Body> {
    match decision {
        Decision::Allow { .. } => {
            match forward::forward(req, upstream).await {
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

            match forward::forward(req, upstream).await {
                Ok(res) => res,
                Err(_) => Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("Upstream error"))
                    .unwrap(),
            }
        }
    }
}
