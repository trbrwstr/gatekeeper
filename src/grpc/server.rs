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

    pub fn into_service(self) -> PolicySyncServer<Self> {
        PolicySyncServer::new(self)
    }

    #[allow(dead_code)]
    pub async fn update_rules(&self, rules: Vec<Rule>) {
        let mut current = self.rules.write().await;
        *current = rules;
        let mut ver = self.version.write().await;
        *ver += 1;
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

pub async fn run_grpc_server(addr: &str, rules: Vec<Rule>) -> Result<(), Box<dyn std::error::Error>> {
    let service = PolicySyncService::new(rules);

    let addr = addr.parse()?;
    tracing::info!("gRPC policy server listening on {}", addr);

    tonic::transport::Server::builder()
        .add_service(service.into_service())
        .serve(addr)
        .await?;

    Ok(())
}
