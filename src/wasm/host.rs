use wasmtime::*;

pub fn add_host_functions(linker: &mut Linker<()>) -> Result<(), anyhow::Error> {
    linker.func_wrap("env", "host_log", |mut caller: Caller<'_, ()>, ptr: i32, len: i32| {
        let memory = caller.get_export("memory")
            .and_then(|e| e.into_memory());

        if let Some(mem) = memory {
            let data = mem.data(&caller);
            let start = ptr as usize;
            let end = start + len as usize;
            if end <= data.len() {
                if let Ok(msg) = std::str::from_utf8(&data[start..end]) {
                    tracing::info!("[WASM] {}", msg);
                }
            }
        }
    })?;

    linker.func_wrap("env", "host_get_time", || -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    })?;

    Ok(())
}
