use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Rule {
    pub name: String,
    pub path_contains: Option<String>,
    pub method: Option<String>,
    pub user_agent_contains: Option<Vec<String>>,
    pub action: String,
    pub priority: u32,
}
