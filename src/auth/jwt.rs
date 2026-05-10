use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

static SECRET: Lazy<String> = Lazy::new(|| {
    std::env::var("GATEKEEPER_JWT_SECRET")
        .expect("GATEKEEPER_JWT_SECRET environment variable must be set")
});
const EXPIRY_HOURS: u64 = 24;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: u64,
}

pub fn issue_token(username: &str, role: &str) -> String {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + (EXPIRY_HOURS * 3600);

    let claims = Claims {
        sub: username.to_string(),
        role: role.to_string(),
        exp: expiration,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .expect("failed to encode JWT token")
}

pub fn verify_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET.as_bytes()),
        &Validation::default(),
    )?;

    Ok(token_data.claims)
}
