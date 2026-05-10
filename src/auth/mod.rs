pub mod jwt;
pub mod roles;
pub mod users;

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
    middleware::Next,
};

use self::roles::{Permission, Role};

fn extract_claims(req: &Request<Body>) -> Result<jwt::Claims, Response<Body>> {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !auth_header.starts_with("Bearer ") {
        return Err(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("Missing or invalid Authorization header"))
            .unwrap());
    }

    let token = &auth_header[7..];

    jwt::verify_token(token).map_err(|_| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("Invalid token"))
            .unwrap()
    })
}

fn forbidden() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from("Insufficient permissions"))
        .unwrap()
}

pub async fn require_auth(
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    match extract_claims(&req) {
        Ok(_) => next.run(req).await,
        Err(resp) => resp,
    }
}

pub async fn require_admin(
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    match extract_claims(&req) {
        Ok(claims) => {
            let role = Role::from_str(&claims.role);
            if role.has_permission(Permission::ManageRules) {
                next.run(req).await
            } else {
                forbidden()
            }
        }
        Err(resp) => resp,
    }
}

pub async fn require_user_admin(
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    match extract_claims(&req) {
        Ok(claims) => {
            let role = Role::from_str(&claims.role);
            if role.has_permission(Permission::ManageUsers) {
                next.run(req).await
            } else {
                forbidden()
            }
        }
        Err(resp) => resp,
    }
}
