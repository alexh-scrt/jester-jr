//! Validator registry - central management of all validators

use super::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Validator configuration from TOML
#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorConfig {
    /// Validator name (unique identifier)
    #[allow(dead_code)]
    pub name: String,

    /// Validator type (builtin, script, wasm, dylib)
    #[serde(rename = "type")]
    pub validator_type: ValidatorType,

    /// Path to validator file (for script, wasm, dylib)
    #[serde(default)]
    pub path: Option<String>,

    /// Validator-specific configuration
    #[serde(default)]
    pub config: serde_json::Value,

    /// Timeout in seconds (default: 5)
    #[serde(default = "default_timeout")]
    #[allow(dead_code)]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    5
}

/// Registry of all loaded validators
pub struct ValidatorRegistry {
    /// Loaded validators by name
    validators: HashMap<String, Arc<dyn Validator>>,

    /// WASM runtime engine (will be initialized when needed)
    wasm_engine: Option<wasmtime::Engine>,

    /// Shared state for validators
    state: Arc<ValidatorState>,
}

impl ValidatorRegistry {
    /// Create a new validator registry
    pub fn new() -> Self {
        let mut registry = Self {
            validators: HashMap::new(),
            wasm_engine: None,
            state: Arc::new(ValidatorState::new()),
        };

        // Register built-in validators
        registry.register_builtin_validators();

        registry
    }

    /// Register all built-in validators
    fn register_builtin_validators(&mut self) {
        info!("🔧 Registering built-in validators");

        // Register available built-in validators
        self.register_validator("jwt", Arc::new(builtin::JwtValidator::new()));
        self.register_validator("api_key", Arc::new(builtin::ApiKeyValidator::new()));
        self.register_validator("jester_secret", Arc::new(builtin::JesterSecretValidator::new()));

        info!("✅ Registered {} built-in validators", self.validators.len());
    }

    /// Register a validator
    pub fn register_validator(&mut self, name: &str, validator: Arc<dyn Validator>) {
        debug!("Registering validator: {} ({})", name, validator.validator_type());
        self.validators.insert(name.to_string(), validator);
    }

    /// Get a validator by name
    pub fn get(&self, name: &str) -> Option<Arc<dyn Validator>> {
        self.validators.get(name).cloned()
    }

    /// Get all validator names
    #[allow(dead_code)]
    pub fn validator_names(&self) -> Vec<String> {
        self.validators.keys().cloned().collect()
    }

    /// Get shared state
    pub fn state(&self) -> Arc<ValidatorState> {
        Arc::clone(&self.state)
    }

    /// Load validators from configuration
    ///
    /// # Arguments
    /// * `configs` - Map of validator name to configuration
    ///
    /// # Returns
    /// * `Ok(())` - All validators loaded successfully
    /// * `Err(String)` - If any validator failed to load
    pub async fn load_from_config(
        &mut self,
        configs: &HashMap<String, ValidatorConfig>,
    ) -> Result<(), String> {
        info!("🔧 Loading {} validators from configuration", configs.len());

        for (name, config) in configs {
            if let Err(e) = self.load_validator(name, config).await {
                error!("❌ Failed to load validator '{}': {}", name, e);
                return Err(format!("Failed to load validator '{}': {}", name, e));
            }
        }

        info!("✅ Successfully loaded {} validators", configs.len());
        Ok(())
    }

    /// Load a single validator
    async fn load_validator(
        &mut self,
        name: &str,
        config: &ValidatorConfig,
    ) -> Result<(), String> {
        debug!("Loading validator: {} (type: {})", name, config.validator_type);

        match config.validator_type {
            ValidatorType::Builtin => {
                // Built-in validators are already registered, but need configuration
                if let Some(_validator) = self.validators.get(name) {
                    debug!("Initializing built-in validator '{}' with config", name);
                    
                    // We need to clone the validator to get a mutable reference
                    // This is a limitation of the current architecture where validators are stored as Arc<dyn Validator>
                    // For now, we'll handle initialization differently for built-ins
                    match name {
                        "jester_secret" => {
                            // Re-create the validator with proper initialization
                            let mut new_validator = builtin::JesterSecretValidator::new();
                            new_validator.initialize(&config.config)?;
                            self.register_validator(name, Arc::new(new_validator));
                            Ok(())
                        }
                        "api_key" => {
                            let mut new_validator = builtin::ApiKeyValidator::new();
                            new_validator.initialize(&config.config)?;
                            self.register_validator(name, Arc::new(new_validator));
                            Ok(())
                        }
                        "jwt" => {
                            let mut new_validator = builtin::JwtValidator::new();
                            new_validator.initialize(&config.config)?;
                            self.register_validator(name, Arc::new(new_validator));
                            Ok(())
                        }
                        _ => {
                            debug!("Built-in validator '{}' found but no initialization handler", name);
                            Ok(())
                        }
                    }
                } else {
                    Err(format!("Built-in validator '{}' not found", name))
                }
            }
            ValidatorType::Script => {
                let path = config.path.as_ref()
                    .ok_or_else(|| format!("Script validator '{}' missing 'path'", name))?;
                self.load_script_validator(name, path, config).await
            }
            ValidatorType::Wasm => {
                let path = config.path.as_ref()
                    .ok_or_else(|| format!("WASM validator '{}' missing 'path'", name))?;
                self.load_wasm_validator(name, path, config).await
            }
            ValidatorType::Dylib => {
                // TODO: Implement in future phase
                Err("Dynamic library validators not yet implemented".to_string())
            }
        }
    }

    /// Load a Rhai script validator
    async fn load_script_validator(
        &mut self,
        name: &str,
        path: &str,
        config: &ValidatorConfig,
    ) -> Result<(), String> {
        let validator = script::RhaiValidator::from_file(
            name.to_string(),
            path,
            config.config.clone(),
        )?;

        self.register_validator(name, Arc::new(validator));
        Ok(())
    }

    /// Load a WASM validator
    async fn load_wasm_validator(
        &mut self,
        name: &str,
        path: &str,
        config: &ValidatorConfig,
    ) -> Result<(), String> {
        // Initialize WASM runtime if needed
        self.ensure_wasm_runtime()?;

        let runtime = Arc::new(wasm::WasmRuntime::new()?);
        let validator = wasm::WasmValidator::from_file(
            name.to_string(),
            path,
            config.config.clone(),
            runtime,
        )?;

        self.register_validator(name, Arc::new(validator));
        Ok(())
    }

    /// Initialize WASM runtime if needed
    fn ensure_wasm_runtime(&mut self) -> Result<(), String> {
        if self.wasm_engine.is_none() {
            debug!("Initializing WASM engine");
            let engine = wasmtime::Engine::default();
            self.wasm_engine = Some(engine);
        }
        Ok(())
    }

    /// Shutdown all validators
    #[allow(dead_code)]
    pub async fn shutdown(&self) {
        info!("🔄 Shutting down validators");

        for (name, validator) in &self.validators {
            debug!("Shutting down validator: {}", name);
            if let Err(e) = validator.shutdown().await {
                warn!("⚠️  Failed to shutdown validator '{}': {}", name, e);
            }
        }

        info!("✅ All validators shut down");
    }
}

impl Default for ValidatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ValidatorRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatorRegistry")
            .field("validators", &self.validators.keys().collect::<Vec<_>>())
            .field("wasm_engine", &self.wasm_engine.is_some())
            .finish()
    }
}