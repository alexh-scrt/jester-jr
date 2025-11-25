//! WASM runtime management

use wasmtime::*;
use tracing::{debug, info};

/// WASM runtime for executing validators
pub struct WasmRuntime {
    engine: Engine,
    linker: Linker<()>,
}

impl WasmRuntime {
    /// Create a new WASM runtime
    pub fn new() -> Result<Self, String> {
        info!("🔧 Initializing WASM runtime");

        // Configure engine for optimal performance
        let mut config = Config::new();
        config.wasm_simd(true); // Enable SIMD
        config.wasm_bulk_memory(true); // Enable bulk memory operations
        config.wasm_multi_memory(true); // Enable multiple memories
        
        let engine = Engine::new(&config)
            .map_err(|e| format!("Failed to create WASM engine: {}", e))?;

        // Create linker for host functions
        let mut linker = Linker::new(&engine);

        // Register host functions
        Self::register_host_functions(&mut linker)?;

        info!("✅ WASM runtime initialized");

        Ok(Self { engine, linker })
    }

    /// Register host functions that WASM validators can call
    fn register_host_functions(linker: &mut Linker<()>) -> Result<(), String> {
        // Example: Log function
        linker.func_wrap("env", "log", |_caller: Caller<'_, ()>, ptr: i32, len: i32| {
            debug!("WASM log: ptr={}, len={}", ptr, len);
        }).map_err(|e| format!("Failed to register log function: {}", e))?;

        Ok(())
    }

    /// Get engine reference
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Get linker reference
    pub fn linker(&self) -> &Linker<()> {
        &self.linker
    }
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new().expect("Failed to create WASM runtime")
    }
}