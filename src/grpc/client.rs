use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use tokio::time;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

use super::proto::policy_sync_client::PolicySyncClient;
use super::proto::{HeartbeatRequest, MetricsReport, SyncRequest};
use crate::config::reload::SharedEngine;
use crate::policy::engine::PolicyEngine;
use crate::policy::rules::Rule;

static CLUSTER_TOKEN: Lazy<String> = Lazy::new(|| {
    std::env::var("GATEKEEPER_CLUSTER_TOKEN")
        .expect("GATEKEEPER_CLUSTER_TOKEN must be set in node mode to authenticate to central")
});

// The `Result<_, Status>` shape is dictated by tonic's `Interceptor` trait,
// so the large-error lint cannot be satisfied by boxing here.
#[allow(clippy::result_large_err)]
fn attach_token(mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
    let value = CLUSTER_TOKEN
        .parse()
        .map_err(|_| tonic::Status::internal("cluster token is not a valid header value"))?;
    req.metadata_mut().insert("x-cluster-token", value);
    Ok(req)
}

type AuthInterceptor = fn(tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status>;
type GrpcClient = PolicySyncClient<InterceptedService<Channel, AuthInterceptor>>;

pub struct NodeClient {
    node_id: String,
    central_addr: String,
    engine: SharedEngine,
    started_at: Instant,
}

impl NodeClient {
    pub fn new(node_id: String, central_addr: String, engine: SharedEngine) -> Self {
        Self {
            node_id,
            central_addr,
            engine,
            started_at: Instant::now(),
        }
    }

    async fn connect(&self) -> Result<GrpcClient, Box<dyn std::error::Error>> {
        let channel = Channel::from_shared(self.central_addr.clone())?
            .connect()
            .await?;
        Ok(PolicySyncClient::with_interceptor(
            channel,
            attach_token as AuthInterceptor,
        ))
    }

    pub async fn start_sync_loop(&self) {
        let mut last_version: u64 = 0;
        let mut interval = time::interval(Duration::from_secs(10));
        let mut client: Option<GrpcClient> = None;

        loop {
            interval.tick().await;

            if client.is_none() {
                match self.connect().await {
                    Ok(c) => client = Some(c),
                    Err(e) => {
                        tracing::warn!("failed to connect to central: {}", e);
                        continue;
                    }
                }
            }

            let c = client.as_mut().unwrap();

            match self.sync_rules(c, &mut last_version).await {
                Ok(true) => tracing::info!("rules synced from central (v{})", last_version),
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!("sync failed: {}", e);
                    client = None;
                    continue;
                }
            }

            if let Err(e) = self.send_heartbeat(c).await {
                tracing::warn!("heartbeat failed: {}", e);
                client = None;
                continue;
            }

            let snap = crate::metrics::snapshot();
            if let Err(e) = self.report_metrics(
                c,
                snap.requests_total,
                snap.requests_blocked,
                snap.requests_throttled,
                snap.rate_limit_hits,
                snap.avg_latency_ms,
            ).await {
                tracing::warn!("metrics report failed: {}", e);
                client = None;
            }
        }
    }

    async fn sync_rules(&self, client: &mut GrpcClient, last_version: &mut u64) -> Result<bool, Box<dyn std::error::Error>> {
        let response = client
            .sync_rules(SyncRequest {
                node_id: self.node_id.clone(),
                last_version: *last_version,
            })
            .await?;

        let resp = response.into_inner();

        if !resp.changed {
            return Ok(false);
        }

        let rules: Vec<Rule> = resp
            .rules
            .into_iter()
            .map(|r| Rule {
                name: r.name,
                path_contains: if r.path_contains.is_empty() {
                    None
                } else {
                    Some(r.path_contains)
                },
                method: if r.method.is_empty() {
                    None
                } else {
                    Some(r.method)
                },
                user_agent_contains: if r.user_agent_contains.is_empty() {
                    None
                } else {
                    Some(r.user_agent_contains)
                },
                action: r.action,
                priority: r.priority,
            })
            .collect();

        let new_engine = PolicyEngine::new(rules);
        self.engine.store(Arc::new(new_engine));
        *last_version = resp.version;

        Ok(true)
    }

    async fn send_heartbeat(&self, client: &mut GrpcClient) -> Result<(), Box<dyn std::error::Error>> {
        client
            .heartbeat(HeartbeatRequest {
                node_id: self.node_id.clone(),
                uptime_secs: self.started_at.elapsed().as_secs(),
            })
            .await?;

        Ok(())
    }

    async fn report_metrics(
        &self,
        client: &mut GrpcClient,
        total: u64,
        blocked: u64,
        throttled: u64,
        rate_limited: u64,
        avg_latency: f64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        client
            .report_metrics(MetricsReport {
                node_id: self.node_id.clone(),
                requests_total: total,
                requests_blocked: blocked,
                requests_throttled: throttled,
                rate_limit_hits: rate_limited,
                avg_latency_ms: avg_latency,
            })
            .await?;

        Ok(())
    }
}
