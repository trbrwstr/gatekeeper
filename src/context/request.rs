use axum::http::Request;

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub ip: String,
    pub method: String,
    pub path: String,
    pub user_agent: Option<String>,
}

impl RequestContext {
    pub fn from<B>(req: &Request<B>) -> Self {
        let headers = req.headers();

        Self {
            ip: extract_ip(req),
            method: req.method().to_string(),
            path: req.uri().path().to_string(),
            user_agent: headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
        }
    }
}

fn extract_ip<B>(req: &Request<B>) -> String {
    if let Some(forwarded) = req.headers().get("x-real-ip") {
        if let Ok(val) = forwarded.to_str() {
            return val.trim().to_string();
        }
    }

    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(val) = forwarded.to_str() {
            return val.split(',').next().unwrap_or("unknown").trim().to_string();
        }
    }

    req.extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
