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

/// Upper bound on the fuel a single rule evaluation may consume. Prevents a
/// malicious or buggy module from hanging the request handler with an infinite
/// loop; exceeding it traps the call and the module simply yields no decision.
const FUEL_LIMIT: u64 = 100_000_000;

/// Upper bound on the JSON output a module may return, so it cannot drive a
/// huge host-side allocation.
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

fn read_range(data: &[u8], ptr: i32, len: usize) -> Option<&[u8]> {
    let start = usize::try_from(ptr).ok()?;
    let end = start.checked_add(len)?;
    data.get(start..end)
}

pub struct WasmRuntime {
    engine: Engine,
    module: Module,
}

impl WasmRuntime {
    pub fn new(path: &str) -> Result<Self, anyhow::Error> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config)?;
        let module = Module::from_file(&engine, path)?;

        Ok(Self { engine, module })
    }

    pub fn evaluate(&self, ctx: &RequestContext) -> Option<Decision> {
        let mut store = Store::new(&self.engine, ());
        store.set_fuel(FUEL_LIMIT).ok()?;
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
        let input_len = i32::try_from(input_json.len()).ok()?;

        let input_ptr = alloc_fn.call(&mut store, input_len).ok()?;

        {
            let mem = memory.data_mut(&mut store);
            let start = usize::try_from(input_ptr).ok()?;
            let end = start.checked_add(input_json.len())?;
            mem.get_mut(start..end)?.copy_from_slice(&input_json);
        }

        let output_ptr = evaluate_fn.call(&mut store, (input_ptr, input_len)).ok()?;

        let data = memory.data(&store);
        let output_len_bytes = read_range(data, output_ptr, 4)?;
        let output_len = i32::from_le_bytes(output_len_bytes.try_into().ok()?);
        let output_len = usize::try_from(output_len).ok()?;
        if output_len > MAX_OUTPUT_BYTES {
            tracing::error!("WASM module returned oversized output ({} bytes)", output_len);
            return None;
        }
        let output_bytes = read_range(data, output_ptr.checked_add(4)?, output_len)?;

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
