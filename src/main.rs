mod app_state;
mod cli;

mod context {
    pub mod request;
}

mod proxy;
mod security {
    pub mod rate_limit;
}

mod policy {
    pub mod decision;
    pub mod engine;
    pub mod matcher;
    pub mod replay;
    pub mod rules;
}

mod config {
    pub mod config;
    pub mod validate;
    pub mod reload;
}

mod log {
    pub mod audit;
    pub mod inspect;
    pub mod worker;
}

pub mod metrics;
mod admin;
mod auth;
mod wasm;
mod grpc;
mod threat;

use clap::Parser;
use cli::{Cli, Commands};

use crate::config::config::load_config;
use crate::policy::engine::PolicyEngine;
use crate::policy::replay;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run { port, upstream, mode, central, config, log_file } => {
            match mode.as_str() {
                "central" => {
                    let cfg = load_config(&config).expect("failed to load config");
                    if let Err(e) = grpc::server::run_grpc_server(
                        &format!("0.0.0.0:{}", port + 1),
                        cfg.rules,
                    ).await {
                        eprintln!("gRPC server error: {}", e);
                    }
                }
                "node" => {
                    proxy::server::run(port, upstream, central, config, log_file).await;
                }
                _ => {
                    proxy::server::run(port, upstream, None, config, log_file).await;
                }
            }
        }

        Commands::Test { file } => {
            let config = load_config(&file).expect("failed to load config");
            println!("Config valid: {} rules loaded", config.rules.len());
        }

        Commands::Inspect {
            file,
            decision,
            ip,
        } => {
            log::inspect::inspect(&file, decision, ip);
        }

        Commands::Replay { file } => {
            let config = load_config("config.toml").expect("failed to load config");
            let engine = PolicyEngine::new(config.rules);
            replay::replay(&file, &engine);
        }

        Commands::HashPassword { password } => {
            match crate::auth::users::hash_password(&password) {
                Ok(hash) => println!("{}", hash),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
