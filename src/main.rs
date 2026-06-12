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

mod config;

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
use std::process::ExitCode;

use crate::config::load_config;
use crate::policy::engine::PolicyEngine;
use crate::policy::replay;

#[tokio::main]
async fn main() -> ExitCode {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run { port, upstream, mode, central, config, log_file } => {
            match mode.as_str() {
                "central" => {
                    let cfg = load_config(&config).expect("failed to load config");
                    // Bind loopback by default so the rule-sync control plane
                    // is not exposed on all interfaces. Set GATEKEEPER_GRPC_ADDR
                    // (e.g. 0.0.0.0:8081) to expose it to remote nodes.
                    let bind = std::env::var("GATEKEEPER_GRPC_ADDR")
                        .unwrap_or_else(|_| format!("127.0.0.1:{}", port + 1));
                    if let Err(e) = grpc::server::run_grpc_server(&bind, cfg.rules).await {
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
            if log::inspect::inspect(&file, decision, ip).is_err() {
                return ExitCode::FAILURE;
            }
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

    ExitCode::SUCCESS
}
