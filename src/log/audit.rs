use serde::Serialize;
use tokio::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::context::request::RequestContext;
use crate::policy::decision::Decision;

#[derive(Serialize)]
struct AuditEvent {
    timestamp: u64,
    ip: String,
    path: String,
    method: String,
    decision: String,
    reason: String,
    source: String,
    latency_ms: u128,
}

pub async fn log(
    tx: &mpsc::Sender<String>,
    ctx: &RequestContext,
    decision: &Decision,
    latency: u128,
) {
    let (decision_str, reason, source) = match decision {
        Decision::Allow { reason, source } => ("allow", reason, source),
        Decision::Block { reason, source } => ("block", reason, source),
        Decision::Throttle { reason, source } => ("throttle", reason, source),
    };

    let event = AuditEvent {
        timestamp: now(),
        ip: ctx.ip.clone(),
        path: ctx.path.clone(),
        method: ctx.method.clone(),
        decision: decision_str.to_string(),
        reason: reason.clone(),
        source: source.to_string(),
        latency_ms: latency,
    };

    let json = match serde_json::to_string(&event) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("failed to serialize audit event: {}", e);
            return;
        }
    };

    if let Err(e) = tx.send(json).await {
        tracing::error!("failed to send audit event: {}", e);
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
