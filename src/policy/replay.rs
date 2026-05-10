use crate::context::request::RequestContext;
use crate::policy::engine::PolicyEngine;

use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Deserialize)]
struct ReplayEvent {
    ip: String,
    path: String,
    method: String,
}

pub fn replay(file: &str, engine: &PolicyEngine) {
    let file = File::open(file).expect("failed to open replay file");
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("error reading line: {}", e);
                continue;
            }
        };

        if let Ok(event) = serde_json::from_str::<ReplayEvent>(&line) {
            let ctx = RequestContext {
                ip: event.ip,
                path: event.path,
                method: event.method,
                user_agent: None,
            };

            let result = engine.evaluate(&ctx);

            println!("{:?} -> {:?}", ctx.path, result);
        }
    }
}
