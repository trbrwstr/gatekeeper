pub mod middleware;

use once_cell::sync::Lazy;
use opentelemetry::metrics::{Counter, Histogram, Meter, MeterProvider as _};
use opentelemetry::KeyValue;
use opentelemetry_prometheus::exporter;
use opentelemetry_sdk::metrics::MeterProvider;
use prometheus::Registry;

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

pub static METRICS: Lazy<AppMetrics> = Lazy::new(|| {
    let prometheus_exporter = exporter()
        .with_registry(REGISTRY.clone())
        .build()
        .expect("failed to build prometheus exporter");

    let provider = MeterProvider::builder()
        .with_reader(prometheus_exporter)
        .build();
    let meter = provider.meter("gatekeeper");

    AppMetrics::new(&meter)
});

pub struct AppMetrics {
    pub requests_total: Counter<u64>,
    pub requests_blocked: Counter<u64>,
    pub requests_throttled: Counter<u64>,
    pub rate_limit_hits: Counter<u64>,
    pub request_duration_ms: Histogram<f64>,
}

impl AppMetrics {
    fn new(meter: &Meter) -> Self {
        Self {
            requests_total: meter
                .u64_counter("gatekeeper_requests_total")
                .with_description("Total number of requests processed")
                .init(),
            requests_blocked: meter
                .u64_counter("gatekeeper_requests_blocked")
                .with_description("Total number of requests blocked")
                .init(),
            requests_throttled: meter
                .u64_counter("gatekeeper_requests_throttled")
                .with_description("Total number of requests throttled")
                .init(),
            rate_limit_hits: meter
                .u64_counter("gatekeeper_rate_limit_hits")
                .with_description("Total number of rate limit triggers")
                .init(),
            request_duration_ms: meter
                .f64_histogram("gatekeeper_request_duration_ms")
                .with_description("Request processing duration in milliseconds")
                .init(),
        }
    }
}

pub fn record_request(decision: &str, source: &str, duration_ms: f64) {
    let attrs = &[
        KeyValue::new("decision", decision.to_string()),
        KeyValue::new("source", source.to_string()),
    ];

    METRICS.requests_total.add(1, attrs);
    METRICS.request_duration_ms.record(duration_ms, attrs);

    match decision {
        "block" => METRICS.requests_blocked.add(1, attrs),
        "throttle" => METRICS.requests_throttled.add(1, attrs),
        _ => {}
    }

    if source == "rate_limit" && decision == "block" {
        METRICS.rate_limit_hits.add(1, attrs);
    }
}

pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_blocked: u64,
    pub requests_throttled: u64,
    pub rate_limit_hits: u64,
    pub avg_latency_ms: f64,
}

pub fn snapshot() -> MetricsSnapshot {
    let families = REGISTRY.gather();
    let mut snap = MetricsSnapshot {
        requests_total: 0,
        requests_blocked: 0,
        requests_throttled: 0,
        rate_limit_hits: 0,
        avg_latency_ms: 0.0,
    };

    for family in &families {
        let name = family.get_name();
        let metrics = family.get_metric();
        match name {
            "gatekeeper_requests_total" => {
                snap.requests_total =
                    metrics.iter().map(|m| m.get_counter().get_value() as u64).sum();
            }
            "gatekeeper_requests_blocked" => {
                snap.requests_blocked =
                    metrics.iter().map(|m| m.get_counter().get_value() as u64).sum();
            }
            "gatekeeper_requests_throttled" => {
                snap.requests_throttled =
                    metrics.iter().map(|m| m.get_counter().get_value() as u64).sum();
            }
            "gatekeeper_rate_limit_hits" => {
                snap.rate_limit_hits =
                    metrics.iter().map(|m| m.get_counter().get_value() as u64).sum();
            }
            "gatekeeper_request_duration_ms" => {
                let count: f64 = metrics
                    .iter()
                    .map(|m| m.get_histogram().get_sample_count() as f64)
                    .sum();
                let sum: f64 =
                    metrics.iter().map(|m| m.get_histogram().get_sample_sum()).sum();
                if count > 0.0 {
                    snap.avg_latency_ms = sum / count;
                }
            }
            _ => {}
        }
    }

    snap
}

pub fn metrics_endpoint() -> String {
    use prometheus::Encoder;

    let encoder = prometheus::TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
