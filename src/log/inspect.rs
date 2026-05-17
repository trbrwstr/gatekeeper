use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Deserialize)]
pub struct AuditEvent {
    pub timestamp: u64,
    pub ip: String,
    pub path: String,
    pub method: String,
    pub decision: String,
    pub reason: String,
    pub source: String,
    pub latency_ms: u128,
}

pub fn inspect(
    file: &str,
    decision_filter: Option<String>,
    ip_filter: Option<String>,
) {
    let file = match File::open(file) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("failed to open log file: {}", err);
            return;
        }
    };
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                eprintln!("failed to read log line: {}", err);
                continue;
            }
        };

        match serde_json::from_str::<AuditEvent>(&line) {
            Ok(event) => {
                if let Some(ref filter) = decision_filter {
                    if &event.decision != filter {
                        continue;
                    }
                }

                if let Some(ref filter) = ip_filter {
                    if &event.ip != filter {
                        continue;
                    }
                }

                println!(
                    "{} [{}] {} {} -> {} ({}) [src:{}] [{}ms]",
                    event.timestamp,
                    event.decision.to_uppercase(),
                    event.method,
                    event.path,
                    event.reason,
                    event.ip,
                    event.source,
                    event.latency_ms
                );
            }

            Err(err) => {
                eprintln!("invalid log line: {}", err);
            }
        }
    }
}
