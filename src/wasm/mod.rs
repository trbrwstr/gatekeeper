pub mod runtime;
pub mod host;

use crate::context::request::RequestContext;
use crate::policy::decision::Decision;
use crate::config::config::WasmRuleConfig;

pub struct WasmEngine {
    modules: Vec<WasmModule>,
}

struct WasmModule {
    name: String,
    priority: u32,
    runtime: runtime::WasmRuntime,
}

impl WasmEngine {
    pub fn new(configs: &[WasmRuleConfig]) -> Self {
        let modules = configs
            .iter()
            .filter_map(|cfg| {
                match runtime::WasmRuntime::new(&cfg.path) {
                    Ok(rt) => Some(WasmModule {
                        name: cfg.name.clone(),
                        priority: cfg.priority,
                        runtime: rt,
                    }),
                    Err(e) => {
                        tracing::error!("failed to load WASM module '{}': {}", cfg.name, e);
                        None
                    }
                }
            })
            .collect();

        Self { modules }
    }

    pub fn evaluate(&self, ctx: &RequestContext) -> Option<Decision> {
        let mut results: Vec<(u32, Decision)> = Vec::new();

        for module in &self.modules {
            if let Some(decision) = module.runtime.evaluate(ctx) {
                tracing::debug!("WASM module '{}' returned decision: {:?}", module.name, decision);
                results.push((module.priority, decision));
            }
        }

        if results.is_empty() {
            return None;
        }

        results.sort_by_key(|(priority, _)| std::cmp::Reverse(*priority));
        Some(results.remove(0).1)
    }
}
