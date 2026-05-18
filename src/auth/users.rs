use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::Serialize;

use crate::config::UserConfig;

pub type UserStore = Arc<RwLock<HashMap<String, UserEntry>>>;

#[derive(Clone)]
pub struct UserEntry {
    pub password_hash: String,
    pub role: String,
}

pub fn init_user_store(users: &Option<Vec<UserConfig>>) -> UserStore {
    let mut map = HashMap::new();
    if let Some(users) = users {
        for u in users {
            map.insert(
                u.username.clone(),
                UserEntry {
                    password_hash: u.password_hash.clone(),
                    role: u.role.clone(),
                },
            );
        }
    }
    Arc::new(RwLock::new(map))
}

pub async fn reload_users(store: &UserStore, users: &Option<Vec<UserConfig>>) {
    let mut map = store.write().await;
    map.clear();
    if let Some(users) = users {
        for u in users {
            map.insert(
                u.username.clone(),
                UserEntry {
                    password_hash: u.password_hash.clone(),
                    role: u.role.clone(),
                },
            );
        }
    }
}

pub async fn authenticate(store: &UserStore, username: &str, password: &str) -> Option<String> {
    let users = store.read().await;
    let entry = users.get(username)?;
    let parsed_hash = PasswordHash::new(&entry.password_hash).ok()?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .ok()?;
    Some(entry.role.clone())
}

#[derive(Serialize)]
pub struct UserInfo {
    pub username: String,
    pub role: String,
}

pub async fn list_users(store: &UserStore) -> Vec<UserInfo> {
    let users = store.read().await;
    users
        .iter()
        .map(|(username, entry)| UserInfo {
            username: username.clone(),
            role: entry.role.clone(),
        })
        .collect()
}

pub async fn add_user(
    store: &UserStore,
    username: &str,
    password: &str,
    role: &str,
) -> Result<(), String> {
    let hash = hash_password(password)?;
    let mut users = store.write().await;
    if users.contains_key(username) {
        return Err(format!("user '{}' already exists", username));
    }
    users.insert(
        username.to_string(),
        UserEntry {
            password_hash: hash,
            role: role.to_string(),
        },
    );
    Ok(())
}

pub async fn remove_user(store: &UserStore, username: &str) -> Result<(), String> {
    let mut users = store.write().await;
    if users.remove(username).is_none() {
        return Err(format!("user '{}' not found", username));
    }
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("failed to hash password: {}", e))?;
    Ok(hash.to_string())
}

/// Length-independent-content comparison used for the env-var admin
/// credential fallback so login does not leak the secret via response timing.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn constant_time_eq_matches_only_identical_bytes() {
        assert!(constant_time_eq(b"correct horse", b"correct horse"));
        assert!(!constant_time_eq(b"correct horse", b"correct horsa"));
        assert!(!constant_time_eq(b"short", b"longer value"));
        assert!(constant_time_eq(b"", b""));
    }
}
