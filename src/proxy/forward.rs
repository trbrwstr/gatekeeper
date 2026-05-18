use anyhow::Context;
use axum::body::Body;
use axum::http::header::{HeaderName, HeaderValue, CONNECTION, HOST};
use axum::http::{Request, Response};
use hyper::Uri;
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use once_cell::sync::Lazy;

static CLIENT: Lazy<Client<HttpsConnector<HttpConnector>, Body>> = Lazy::new(|| {
    let https = HttpsConnector::new();
    Client::builder(TokioExecutor::new()).build(https)
});

// Connection-specific headers that must not be forwarded to the upstream
// (RFC 9110 §7.6.1).
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub async fn forward(
    req: Request<Body>,
    upstream: &str,
    client_ip: &str,
) -> anyhow::Result<Response<Body>> {
    let uri_string = format!(
        "{}{}",
        upstream,
        req.uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );

    let uri: Uri = uri_string.parse().context("invalid upstream URI")?;
    let upstream_host = uri.authority().map(|a| a.as_str().to_string());

    let method = req.method().clone();
    let mut headers = req.headers().clone();

    let original_host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Strip hop-by-hop headers, including any extra ones the client listed in
    // its Connection header, so they are not leaked to the upstream.
    let mut connection_listed: Vec<HeaderName> = Vec::new();
    if let Some(conn) = headers.get(CONNECTION) {
        if let Ok(s) = conn.to_str() {
            for token in s.split(',') {
                if let Ok(h) = HeaderName::from_bytes(token.trim().as_bytes()) {
                    connection_listed.push(h);
                }
            }
        }
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    for name in connection_listed {
        headers.remove(&name);
    }

    // Route by the upstream's authority rather than forwarding the client's
    // Host, which would otherwise misroute name-based virtual hosts.
    headers.remove(HOST);
    if let Some(host) = &upstream_host {
        if let Ok(v) = HeaderValue::from_str(host) {
            headers.insert(HOST, v);
        }
    }

    // Standard forwarding metadata for the upstream.
    let xff = match headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        Some(existing) => format!("{}, {}", existing, client_ip),
        None => client_ip.to_string(),
    };
    if let Ok(v) = HeaderValue::from_str(&xff) {
        headers.insert("x-forwarded-for", v);
    }
    if let Some(host) = original_host {
        if let Ok(v) = HeaderValue::from_str(&host) {
            headers.insert("x-forwarded-host", v);
        }
    }
    // Gatekeeper's listener is plaintext HTTP.
    headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));

    let mut builder = Request::builder().method(method).uri(uri);
    *builder
        .headers_mut()
        .context("failed to access request headers")? = headers;
    let new_req = builder
        .body(req.into_body())
        .context("failed to build forwarded request")?;

    Ok(CLIENT.request(new_req).await.map(|res| res.map(Body::new))?)
}
