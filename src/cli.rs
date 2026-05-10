use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "gatekeeper")]
#[command(about = "Local-first API security proxy")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Run {
        #[arg(short, long, default_value = "8080")]
        port: u16,

        #[arg(short, long, default_value = "http://127.0.0.1:3000")]
        upstream: String,

        #[arg(short, long, default_value = "standalone")]
        mode: String,

        #[arg(long)]
        central: Option<String>,

        #[arg(short = 'f', long, default_value = "config.toml")]
        config: String,

        #[arg(long, default_value = "gatekeeper.log")]
        log_file: String,
    },

    Test {
        #[arg(short, long)]
        file: String,
    },

    Inspect {
        #[arg(short, long)]
        file: String,

        #[arg(long)]
        decision: Option<String>,

        #[arg(long)]
        ip: Option<String>,
    },

    Replay {
        #[arg(short, long)]
        file: String,
    },

    HashPassword {
        #[arg(short, long)]
        password: String,
    },
}
