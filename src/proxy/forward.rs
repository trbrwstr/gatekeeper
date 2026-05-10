use anyhow::Context;
use axum::body::Body;
use axum::http::{Request, Response};
use hyper::Uri;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use once_cell::sync::Lazy;

static CLIENT: Lazy<Client<HttpConnector, Body>> =
    Lazy::new(|| {
        let connector = HttpConnector::new();
        Client::builder(TokioExecutor::new()).build(connector)
    });

pub async fn forward(
    req: Request<Body>,
    upstream: &str,
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

    let mut new_req = Request::builder()
        .method(req.method())
        .uri(uri);

    *new_req
        .headers_mut()
        .context("failed to access request headers")? = req.headers().clone();

    let body = req.into_body();
    let new_req = new_req.body(body).context("failed to build forwarded request")?;

    Ok(CLIENT.request(new_req).await.map(|res| res.map(Body::new))?)
}
