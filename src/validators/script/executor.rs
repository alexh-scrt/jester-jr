//! Rhai script executor

use crate::validators::*;
use async_trait::async_trait;
use rhai::{AST, Engine, Map, Scope};
use std::sync::Arc;
use tracing::{debug, error};

/// Rhai script validator
pub struct RhaiValidator {
    name: String,
    engine: Arc<Engine>,
    ast: Arc<AST>,
    config: serde_json::Value,
}

impl RhaiValidator {
    /// Create a new Rhai validator from a script file
    pub fn from_file(
        name: String,
        path: &str,
        config: serde_json::Value,
    ) -> Result<Self, String> {
        debug!("Loading Rhai script: {} from {}", name, path);

        // Create Rhai engine
        let mut engine = Engine::new();

        // Register custom types (make ValidationContext available to scripts)
        Self::register_types(&mut engine);

        // Compile script
        let ast = engine.compile_file(path.into())
            .map_err(|e| format!("Failed to compile script '{}': {}", path, e))?;

        // Verify script has 'validate' function
        if !ast.iter_functions().any(|f| f.name == "validate") {
            return Err(format!("Script '{}' missing 'validate' function", path));
        }

        Ok(Self {
            name,
            engine: Arc::new(engine),
            ast: Arc::new(ast),
            config,
        })
    }

    /// Register custom types with Rhai engine
    fn register_types(_engine: &mut Engine) {
        // TODO: Register ValidationContext methods
        // For now, we'll pass context as a Dynamic map
    }

    /// Convert ValidationContext to Rhai Map
    fn context_to_map(ctx: &ValidationContext) -> Map {
        let mut map = Map::new();
        
        map.insert("method".into(), ctx.method.clone().into());
        map.insert("path".into(), ctx.path.clone().into());
        map.insert("client_ip".into(), ctx.client_ip.to_string().into());
        
        // Convert headers to map
        let mut headers_map = Map::new();
        for (k, v) in &ctx.headers {
            headers_map.insert(k.clone().into(), v.clone().into());
        }
        map.insert("headers".into(), headers_map.into());
        
        // Add config as JSON string (simplified)
        let config_str = serde_json::to_string(&ctx.config).unwrap_or_default();
        map.insert("config_json".into(), config_str.into());
        
        map
    }

    /// Convert Rhai Map to ValidationResult
    fn map_to_result(map: Map) -> Result<ValidationResult, ValidationError> {
        let result_type = map.get("result")
            .and_then(|v| v.clone().try_cast::<String>())
            .ok_or_else(|| ValidationError::ScriptError("Missing 'result' field".to_string()))?;

        match result_type.as_str() {
            "allow" => Ok(ValidationResult::Allow),
            "deny" => {
                let status_code = map.get("status_code")
                    .and_then(|v| v.as_int().ok())
                    .unwrap_or(403) as u16;
                
                let reason = map.get("reason")
                    .and_then(|v| v.clone().try_cast::<String>())
                    .unwrap_or_else(|| "Access denied".to_string());

                Ok(ValidationResult::Deny {
                    status_code,
                    reason,
                    log_level: LogLevel::Warn,
                    internal_message: None,
                })
            }
            _ => Err(ValidationError::ScriptError(
                format!("Invalid result type: {}", result_type)
            )),
        }
    }
}

#[async_trait]
impl Validator for RhaiValidator {
    async fn validate(
        &self,
        ctx: &ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        // Convert context to Rhai map
        let ctx_map = Self::context_to_map(ctx);

        // Execute script in blocking task to avoid blocking async runtime
        let engine = Arc::clone(&self.engine);
        let ast = Arc::clone(&self.ast);
        
        let result = tokio::task::spawn_blocking(move || {
            let result_map: Map = engine
                .call_fn(&mut Scope::new(), &ast, "validate", (ctx_map,))
                .map_err(|e| ValidationError::ScriptError(format!("Script execution failed: {}", e)))?;

            // Convert result
            Self::map_to_result(result_map)
        }).await
        .map_err(|e| ValidationError::RuntimeError(format!("Script task panicked: {}", e)))??;

        Ok(result)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn validator_type(&self) -> ValidatorType {
        ValidatorType::Script
    }
}