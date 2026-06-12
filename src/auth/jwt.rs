use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const MIN_SECRET_LEN: usize = 32;
const PLACEHOLDER_SECRET: &str = "change-me-to-a-strong-random-secret";

static SECRET: Lazy<String> = Lazy::new(|| {
    let secret = std::env::var("GATEKEEPER_JWT_SECRET")
        .expect("GATEKEEPER_JWT_SECRET environment variable must be set");

    if secret.len() < MIN_SECRET_LEN {
        panic!(
            "GATEKEEPER_JWT_SECRET must be at least {} characters of high-entropy randomness; \
             a weak secret allows JWTs to be forged and the admin API to be taken over",
            MIN_SECRET_LEN
        );
    }
    if secret == PLACEHOLDER_SECRET {
        panic!(
            "GATEKEEPER_JWT_SECRET is still set to the example placeholder; \
             generate a unique random secret before running"
        );
    }

    secret
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
