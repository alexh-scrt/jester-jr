//! WASM validator loader

use super::WasmRuntime;
use crate::validators::*;
use async_trait::async_trait;
use std::sync::Arc;
use tracing::debug;
use wasmtime::*;

/// WASM validator wrapper
pub struct WasmValidator {
    name: String,
    runtime: Arc<WasmRuntime>,
    module: Module,
    config: serde_json::Value,
}

impl WasmValidator {
    /// Load a WASM validator from file
    pub fn from_file(
        name: String,
        path: &str,
        config: serde_json::Value,
        runtime: Arc<WasmRuntime>,
    ) -> Result<Self, String> {
        debug!("Loading WASM validator: {} from {}", name, path);

        // Read WASM file
        let wasm_bytes = std::fs::read(path)
            .map_err(|e| format!("Failed to read WASM file '{}': {}", path, e))?;

        // Compile module
        let module = Module::from_binary(runtime.engine(), &wasm_bytes)
            .map_err(|e| format!("Failed to compile WASM module '{}': {}", path, e))?;

        debug!("✅ WASM validator '{}' loaded successfully", name);

        Ok(Self {
            name,
            runtime,
            module,
            config,
        })
    }

    /// Execute WASM validator
    fn execute_wasm(
        &self,
        ctx: &ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        // Create instance
        let mut store = Store::new(self.runtime.engine(), ());
        let instance = self.runtime.linker()
            .instantiate(&mut store, &self.module)
            .map_err(|e| ValidationError::WasmError(format!("Failed to instantiate: {}", e)))?;

        // Get memory
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| ValidationError::WasmError("WASM module missing 'memory' export".to_string()))?;

        // Serialize context to JSON
        let ctx_json = serde_json::to_vec(ctx)
            .map_err(|e| ValidationError::WasmError(format!("Failed to serialize context: {}", e)))?;

        // Allocate memory in WASM
        let alloc_fn = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|e| ValidationError::WasmError(format!("WASM module missing 'alloc' function: {}", e)))?;

        let ptr = alloc_fn.call(&mut store, ctx_json.len() as i32)
            .map_err(|e| ValidationError::WasmError(format!("Failed to allocate memory: {}", e)))?;

        // Write context to WASM memory
        memory.write(&mut store, ptr as usize, &ctx_json)
            .map_err(|e| ValidationError::WasmError(format!("Failed to write to WASM memory: {}", e)))?;

        // Call validate function
        let validate_fn = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "validate")
            .map_err(|e| ValidationError::WasmError(format!("WASM module missing 'validate' function: {}", e)))?;

        let result_ptr = validate_fn.call(&mut store, (ptr, ctx_json.len() as i32))
            .map_err(|e| ValidationError::WasmError(format!("WASM validation failed: {}", e)))?;

        // Read result length (first 4 bytes at result_ptr)
        let mut len_bytes = [0u8; 4];
        memory.read(&store, result_ptr as usize, &mut len_bytes)
            .map_err(|e| ValidationError::WasmError(format!("Failed to read result length: {}", e)))?;
        let result_len = u32::from_le_bytes(len_bytes) as usize;

        // Read result JSON
        let mut result_json = vec![0u8; result_len];
        memory.read(&store, (result_ptr + 4) as usize, &mut result_json)
            .map_err(|e| ValidationError::WasmError(format!("Failed to read result: {}", e)))?;

        // Deserialize result
        let result: ValidationResult = serde_json::from_slice(&result_json)
            .map_err(|e| ValidationError::WasmError(format!("Failed to parse result: {}", e)))?;

        // Free memory in WASM
        let free_fn = instance
            .get_typed_func::<(i32, i32), ()>(&mut store, "free")
            .map_err(|e| ValidationError::WasmError(format!("WASM module missing 'free' function: {}", e)))?;

        let _ = free_fn.call(&mut store, (ptr, ctx_json.len() as i32));
        let _ = free_fn.call(&mut store, (result_ptr, (result_len + 4) as i32));

        Ok(result)
    }
}

#[async_trait]
impl Validator for WasmValidator {
    async fn validate(
        &self,
        ctx: &ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        // Execute in thread pool to avoid blocking
        let self_clone = self.clone_for_execution();
        let ctx_clone = ctx.clone();

        tokio::task::spawn_blocking(move || {
            self_clone.execute_wasm(&ctx_clone)
        })
        .await
        .map_err(|e| ValidationError::RuntimeError(format!("WASM execution panicked: {}", e)))?
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn validator_type(&self) -> ValidatorType {
        ValidatorType::Wasm
    }
}

impl WasmValidator {
    /// Clone for execution in thread pool
    fn clone_for_execution(&self) -> Self {
        Self {
            name: self.name.clone(),
            runtime: Arc::clone(&self.runtime),
            module: self.module.clone(),
            config: self.config.clone(),
        }
    }
}