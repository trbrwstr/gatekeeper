use std::sync::Arc;
use tonic::{Request, Response, Status};
use tokio::sync::RwLock;

use super::proto::policy_sync_server::{PolicySync, PolicySyncServer};
use super::proto::{
    Ack, HeartbeatRequest, HeartbeatResponse, MetricsReport, RuleProto,
    SyncRequest, SyncResponse,
};
use crate::policy::rules::Rule;

pub struct PolicySyncService {
    rules: Arc<RwLock<Vec<Rule>>>,
    version: Arc<RwLock<u64>>,
}

impl PolicySyncService {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            rules: Arc::new(RwLock::new(rules)),
            version: Arc::new(RwLock::new(1)),
        }
    }

}

#[tonic::async_trait]
impl PolicySync for PolicySyncService {
    async fn sync_rules(
        &self,
        request: Request<SyncRequest>,
    ) -> Result<Response<SyncResponse>, Status> {
        let req = request.into_inner();
        let current_version = *self.version.read().await;

        if req.last_version >= current_version {
            return Ok(Response::new(SyncResponse {
                version: current_version,
                rules: vec![],
                changed: false,
            }));
        }

        let rules = self.rules.read().await;
        let rule_protos: Vec<RuleProto> = rules
            .iter()
            .map(|r| RuleProto {
                name: r.name.clone(),
                path_contains: r.path_contains.clone().unwrap_or_default(),
                method: r.method.clone().unwrap_or_default(),
                user_agent_contains: r.user_agent_contains.clone().unwrap_or_default(),
                action: r.action.clone(),
                priority: r.priority,
            })
            .collect();

        Ok(Response::new(SyncResponse {
            version: current_version,
            rules: rule_protos,
            changed: true,
        }))
    }

    async fn report_metrics(
        &self,
        request: Request<MetricsReport>,
    ) -> Result<Response<Ack>, Status> {
        let report = request.into_inner();
        tracing::info!(
            "node={} total={} blocked={} throttled={} avg_latency={:.2}ms",
            report.node_id,
            report.requests_total,
            report.requests_blocked,
            report.requests_throttled,
            report.avg_latency_ms,
        );

        Ok(Response::new(Ack { success: true }))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let req = request.into_inner();
        tracing::debug!("heartbeat from node={} uptime={}s", req.node_id, req.uptime_secs);

        Ok(Response::new(HeartbeatResponse {
            acknowledged: true,
            message: "ok".to_string(),
        }))
    }
}

// The auth interceptor closure must return `Result<_, tonic::Status>` per
// tonic's `Interceptor` trait, so the large-error lint cannot be boxed away.
#[allow(clippy::result_large_err)]
pub async fn run_grpc_server(addr: &str, rules: Vec<Rule>) -> Result<(), Box<dyn std::error::Error>> {
    let expected_token = std::env::var("GATEKEEPER_CLUSTER_TOKEN").map_err(|_| {
        "GATEKEEPER_CLUSTER_TOKEN must be set in central mode so nodes can authenticate"
    })?;
    if expected_token.len() < 16 {
        return Err("GATEKEEPER_CLUSTER_TOKEN must be at least 16 characters".into());
    }

    let service = PolicySyncService::new(rules);

    let addr = addr.parse()?;
    tracing::info!("gRPC policy server listening on {}", addr);

    let auth = move |req: Request<()>| -> Result<Request<()>, Status> {
        let provided = req
            .metadata()
            .get("x-cluster-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if crate::auth::users::constant_time_eq(provided.as_bytes(), expected_token.as_bytes()) {
            Ok(req)
        } else {
            Err(Status::unauthenticated("invalid or missing cluster token"))
        }
    };

    tonic::transport::Server::builder()
        .add_service(PolicySyncServer::with_interceptor(service, auth))
        .serve(addr)
        .await?;

    Ok(())
}
