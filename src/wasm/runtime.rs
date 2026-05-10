use wasmtime::*;
use serde::{Serialize, Deserialize};

use crate::context::request::RequestContext;
use crate::policy::decision::{Decision, DecisionSource};
use super::host;

#[derive(Serialize)]
struct WasmInput {
    ip: String,
    path: String,
    method: String,
    user_agent: Option<String>,
}

#[derive(Deserialize)]
struct WasmOutput {
    action: String,
    reason: String,
}

pub struct WasmRuntime {
    engine: Engine,
    module: Module,
}

impl WasmRuntime {
    pub fn new(path: &str) -> Result<Self, anyhow::Error> {
        let engine = Engine::default();
        let module = Module::from_file(&engine, path)?;

        Ok(Self { engine, module })
    }

    pub fn evaluate(&self, ctx: &RequestContext) -> Option<Decision> {
        let mut store = Store::new(&self.engine, ());
        let mut linker = Linker::new(&self.engine);

        if let Err(e) = host::add_host_functions(&mut linker) {
            tracing::error!("failed to register WASM host functions: {}", e);
            return None;
        }

        let instance = match linker.instantiate(&mut store, &self.module) {
            Ok(inst) => inst,
            Err(e) => {
                tracing::error!("WASM instantiation failed: {}", e);
                return None;
            }
        };

        let memory = instance.get_memory(&mut store, "memory")?;
        let alloc_fn = instance.get_typed_func::<i32, i32>(&mut store, "alloc").ok()?;
        let evaluate_fn = instance.get_typed_func::<(i32, i32), i32>(&mut store, "evaluate").ok()?;

        let input = WasmInput {
            ip: ctx.ip.clone(),
            path: ctx.path.clone(),
            method: ctx.method.clone(),
            user_agent: ctx.user_agent.clone(),
        };

        let input_json = serde_json::to_vec(&input).ok()?;
        let input_len = input_json.len() as i32;

        let input_ptr = alloc_fn.call(&mut store, input_len).ok()?;

        memory.data_mut(&mut store)[input_ptr as usize..(input_ptr as usize + input_len as usize)]
            .copy_from_slice(&input_json);

        let output_ptr = evaluate_fn.call(&mut store, (input_ptr, input_len)).ok()?;

        let data = memory.data(&store);
        let output_len_bytes = &data[output_ptr as usize..output_ptr as usize + 4];
        let output_len = i32::from_le_bytes(output_len_bytes.try_into().ok()?) as usize;
        let output_start = output_ptr as usize + 4;
        let output_bytes = &data[output_start..output_start + output_len];

        let output: WasmOutput = serde_json::from_slice(output_bytes).ok()?;

        let decision = match output.action.as_str() {
            "allow" => Decision::Allow {
                reason: output.reason,
                source: DecisionSource::Wasm,
            },
            "block" => Decision::Block {
                reason: output.reason,
                source: DecisionSource::Wasm,
            },
            "throttle" => Decision::Throttle {
                reason: output.reason,
                source: DecisionSource::Wasm,
            },
            _ => return None,
        };

        Some(decision)
    }
}
