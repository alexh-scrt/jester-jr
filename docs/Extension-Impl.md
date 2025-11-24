# 🎯 Detailed Implementation Plan: Jester Jr Extension Framework

## 📋 Project Overview

**Objective**: Build a comprehensive, production-ready validator extension framework for Jester Jr that supports three backend types (Built-in, Rhai Scripts, WASM) with the first WASM extension being Secret Network API key validation.

**Timeline**: 2-3 weeks  
**Primary Developer**: TBD  
**Language**: Rust 2024 Edition

---

## 🗂️ Phase 0: Project Structure & Dependencies

### **Task 0.1: Update Project Structure**

Create new directory structure:

```
jester-jr/
├── src/
│   ├── main.rs                    # Existing
│   ├── config/                    # Existing
│   ├── parsers/                   # Existing
│   ├── routing/                   # Existing
│   ├── tls/                       # Existing
│   └── validators/                # NEW MODULE
│       ├── mod.rs                 # Main validator module
│       ├── traits.rs              # Core traits and types
│       ├── registry.rs            # Validator registry
│       ├── context.rs             # ValidationContext struct
│       ├── result.rs              # ValidationResult types
│       ├── builtin/               # Built-in validators
│       │   ├── mod.rs
│       │   ├── jwt.rs
│       │   ├── api_key.rs
│       │   └── basic_auth.rs
│       ├── script/                # Rhai script support
│       │   ├── mod.rs
│       │   └── executor.rs
│       └── wasm/                  # WASM support
│           ├── mod.rs
│           ├── loader.rs
│           └── runtime.rs
├── validators/                    # NEW DIRECTORY
│   ├── examples/                  # Example validators
│   │   ├── simple_api_key.rhai
│   │   └── header_check.rhai
│   └── sdk/                       # WASM validator SDK
│       ├── Cargo.toml
│       ├── src/
│       │   └── lib.rs
│       └── README.md
├── extensions/                    # NEW DIRECTORY - Future WASM extensions
│   └── secret_network_auth/       # First extension (Phase 5)
│       ├── Cargo.toml
│       ├── src/
│       │   └── lib.rs
│       └── README.md
├── docs/
│   └── VALIDATORS.md              # NEW DOCUMENTATION
└── Cargo.toml                     # Update with new dependencies
```

### **Task 0.2: Update Dependencies**

**File**: `Cargo.toml`

```toml
[package]
name = "jester-jr"
version = "0.2.0"  # Bump version
edition = "2024"

[dependencies]
# Existing dependencies
serde = { version = "1.0", features = ["derive"] }
toml = "0.9.8"
regex = "1.10"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }
rustls = "0.23"
rustls-pemfile = "2.1"

# NEW: Validator framework dependencies
rhai = { version = "1.19", features = ["sync", "serde"] }  # Scripting engine
wasmtime = "27.0"                                           # WASM runtime
serde_json = "1.0"                                          # JSON serialization
async-trait = "0.1"                                         # Async trait support

# NEW: Built-in validator dependencies
jsonwebtoken = "9.3"                                        # JWT validation
base64 = "0.22"                                             # Base64 encoding/decoding
chrono = "0.4"                                              # Time handling

[dev-dependencies]
tempfile = "3.8"
mockito = "1.5"                                             # HTTP mocking for tests

[workspace]
members = [
    ".",
    "validators/sdk",           # WASM validator SDK
    "extensions/secret_network_auth",  # First extension (added in Phase 5)
]
```

---

## 📐 Phase 1: Core Validator Infrastructure

**Duration**: 2-3 days  
**Goal**: Establish the foundation - traits, types, and context structs

### **Task 1.1: Define Core Traits**

**File**: `src/validators/traits.rs`

```rust
//! Core validator traits and interfaces
//!
//! This module defines the fundamental abstractions for the validator framework.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::Level;

/// The core validator trait that all validators must implement.
///
/// Validators can be synchronous (for simple checks) or asynchronous
/// (for network calls, database lookups, etc.)
#[async_trait]
pub trait Validator: Send + Sync {
    /// Validate a request
    ///
    /// # Arguments
    /// * `ctx` - The validation context containing request data and config
    ///
    /// # Returns
    /// * `Ok(ValidationResult)` - The validation result
    /// * `Err(ValidationError)` - If validation could not be performed
    async fn validate(
        &self,
        ctx: &ValidationContext,
    ) -> Result<ValidationResult, ValidationError>;

    /// Get validator name (for logging and debugging)
    fn name(&self) -> &str;

    /// Get validator version
    fn version(&self) -> &str;

    /// Get validator type (builtin, script, wasm, dylib)
    fn validator_type(&self) -> ValidatorType;

    /// Initialize the validator with configuration
    ///
    /// Called once when the validator is loaded
    fn initialize(&mut self, config: &serde_json::Value) -> Result<(), String> {
        let _ = config; // Default implementation ignores config
        Ok(())
    }

    /// Shutdown hook - called before validator is dropped
    ///
    /// Useful for cleaning up resources (connections, file handles, etc.)
    async fn shutdown(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Type of validator backend
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidatorType {
    Builtin,
    Script,
    Wasm,
    Dylib,
}

impl std::fmt::Display for ValidatorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidatorType::Builtin => write!(f, "builtin"),
            ValidatorType::Script => write!(f, "script"),
            ValidatorType::Wasm => write!(f, "wasm"),
            ValidatorType::Dylib => write!(f, "dylib"),
        }
    }
}
```

### **Task 1.2: Define ValidationContext**

**File**: `src/validators/context.rs`

```rust
//! Validation context - data passed to validators

use crate::parsers::HttpRequest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Context provided to validators during validation
///
/// Contains all information about the request and configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationContext {
    /// HTTP method (GET, POST, etc.)
    pub method: String,

    /// Request path
    pub path: String,

    /// HTTP version
    pub version: String,

    /// All HTTP headers (lowercase keys)
    pub headers: HashMap<String, String>,

    /// Client IP address
    pub client_ip: IpAddr,

    /// Listener name this request came from
    pub listener_name: String,

    /// Route name (if matched)
    pub route_name: Option<String>,

    /// Validator-specific configuration from TOML
    pub config: serde_json::Value,

    /// Shared state across validators
    ///
    /// Useful for rate limiting, caching, etc.
    pub state: Arc<ValidatorState>,
}

/// Shared state that validators can read/write to
///
/// This enables validators to:
/// - Share rate limiting counters
/// - Cache validation results
/// - Store temporary session data
#[derive(Default)]
pub struct ValidatorState {
    /// Generic key-value store
    pub data: parking_lot::RwLock<HashMap<String, serde_json::Value>>,
}

impl ValidationContext {
    /// Create a new validation context from an HTTP request
    pub fn from_request(
        request: &HttpRequest,
        client_ip: IpAddr,
        listener_name: String,
        route_name: Option<String>,
        config: serde_json::Value,
        state: Arc<ValidatorState>,
    ) -> Self {
        Self {
            method: request.method.clone(),
            path: request.path.clone(),
            version: request.version.clone(),
            headers: request.headers.clone(),
            client_ip,
            listener_name,
            route_name,
            config,
            state,
        }
    }

    /// Get a header value (case-insensitive)
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(&name.to_lowercase())
    }

    /// Check if a header exists (case-insensitive)
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.contains_key(&name.to_lowercase())
    }
}

impl ValidatorState {
    /// Create a new validator state
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a value from state
    pub fn get(&self, key: &str) -> Option<serde_json::Value> {
        self.data.read().get(key).cloned()
    }

    /// Set a value in state
    pub fn set(&self, key: String, value: serde_json::Value) {
        self.data.write().insert(key, value);
    }

    /// Remove a value from state
    pub fn remove(&self, key: &str) -> Option<serde_json::Value> {
        self.data.write().remove(key)
    }

    /// Clear all state
    pub fn clear(&self) {
        self.data.write().clear();
    }
}
```

### **Task 1.3: Define ValidationResult Types**

**File**: `src/validators/result.rs`

```rust
//! Validation result types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::Level;

/// Result of validation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ValidationResult {
    /// Request is valid, proceed with proxying
    Allow,

    /// Request is valid, but modify it before proxying
    AllowWithModification {
        /// Headers to add to the request
        #[serde(default)]
        add_headers: HashMap<String, String>,

        /// Headers to remove from the request
        #[serde(default)]
        remove_headers: Vec<String>,

        /// Optional path rewriting
        #[serde(skip_serializing_if = "Option::is_none")]
        rewrite_path: Option<String>,

        /// Optional message to log
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },

    /// Request is invalid, deny it
    Deny {
        /// HTTP status code to return
        status_code: u16,

        /// Reason for denial (sent to client)
        reason: String,

        /// Log level for this denial
        #[serde(default = "default_log_level")]
        log_level: LogLevel,

        /// Optional detailed message (for internal logging only)
        #[serde(skip_serializing_if = "Option::is_none")]
        internal_message: Option<String>,
    },
}

/// Log level for validation events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LogLevel> for Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Trace => Level::TRACE,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Error => Level::ERROR,
        }
    }
}

fn default_log_level() -> LogLevel {
    LogLevel::Warn
}

/// Error type for validator failures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationError {
    /// Configuration error (validator misconfigured)
    ConfigError(String),

    /// Network error (external service unreachable)
    NetworkError(String),

    /// Runtime error (unexpected validator behavior)
    RuntimeError(String),

    /// Timeout (validator took too long)
    Timeout,

    /// Script error (for Rhai validators)
    ScriptError(String),

    /// WASM error (for WASM validators)
    WasmError(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::ConfigError(msg) => write!(f, "Config error: {}", msg),
            ValidationError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            ValidationError::RuntimeError(msg) => write!(f, "Runtime error: {}", msg),
            ValidationError::Timeout => write!(f, "Validation timeout"),
            ValidationError::ScriptError(msg) => write!(f, "Script error: {}", msg),
            ValidationError::WasmError(msg) => write!(f, "WASM error: {}", msg),
        }
    }
}

impl std::error::Error for ValidationError {}

impl ValidationResult {
    /// Check if result is Allow or AllowWithModification
    pub fn is_allowed(&self) -> bool {
        matches!(self, ValidationResult::Allow | ValidationResult::AllowWithModification { .. })
    }

    /// Check if result is Deny
    pub fn is_denied(&self) -> bool {
        matches!(self, ValidationResult::Deny { .. })
    }
}
```

### **Task 1.4: Create Module Entry Point**

**File**: `src/validators/mod.rs`

```rust
//! Validator framework for Jester Jr
//!
//! This module provides a flexible, extensible system for request validation
//! with support for built-in validators, Rhai scripts, WASM modules, and
//! dynamic libraries.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │       Validator Registry                │
//! ├─────────────────────────────────────────┤
//! │  • Load validators from config          │
//! │  • Manage validator lifecycle           │
//! │  • Execute validation chains            │
//! └────────┬────────────────────────────────┘
//!          │
//!          ├──> Built-in Validators (JWT, API Key, etc.)
//!          ├──> Rhai Script Validators
//!          ├──> WASM Validators
//!          └──> Dynamic Library Validators
//! ```
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use jester_jr::validators::*;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create registry
//! let mut registry = ValidatorRegistry::new();
//!
//! // Load validators from config
//! registry.load_from_config(&config).await?;
//!
//! // Get a validator
//! let jwt_validator = registry.get("jwt").unwrap();
//!
//! // Validate a request
//! let result = jwt_validator.validate(&context).await?;
//! # Ok(())
//! # }
//! ```

pub mod builtin;
pub mod context;
pub mod registry;
pub mod result;
pub mod script;
pub mod traits;
pub mod wasm;

// Re-export commonly used types
pub use context::{ValidationContext, ValidatorState};
pub use registry::{ValidatorConfig, ValidatorRegistry};
pub use result::{LogLevel, ValidationError, ValidationResult};
pub use traits::{Validator, ValidatorType};
```

---

## 🏗️ Phase 2: Validator Registry

**Duration**: 1-2 days  
**Goal**: Central registry for loading and managing validators

### **Task 2.1: Configuration Structures**

**File**: `src/validators/registry.rs` (Part 1)

```rust
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
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    5
}

/// Registry of all loaded validators
pub struct ValidatorRegistry {
    /// Loaded validators by name
    validators: HashMap<String, Arc<dyn Validator>>,

    /// WASM runtime engine
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

        // TODO: Implement in Phase 3
        // self.register_validator("jwt", Arc::new(builtin::JwtValidator::new()));
        // self.register_validator("api_key", Arc::new(builtin::ApiKeyValidator::new()));
        // self.register_validator("basic_auth", Arc::new(builtin::BasicAuthValidator::new()));

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
    pub fn validator_names(&self) -> Vec<String> {
        self.validators.keys().cloned().collect()
    }

    /// Get shared state
    pub fn state(&self) -> Arc<ValidatorState> {
        Arc::clone(&self.state)
    }
}

impl Default for ValidatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}
```

### **Task 2.2: Validator Loading Logic**

**File**: `src/validators/registry.rs` (Part 2 - add to existing file)

```rust
// Add these methods to ValidatorRegistry impl block

impl ValidatorRegistry {
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
                // Built-in validators are already registered
                if self.validators.contains_key(name) {
                    debug!("Validator '{}' is built-in, already registered", name);
                    Ok(())
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
                Err(format!("Dynamic library validators not yet implemented"))
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
        // TODO: Implement in Phase 3
        Err(format!("Script validators not yet implemented"))
    }

    /// Load a WASM validator
    async fn load_wasm_validator(
        &mut self,
        name: &str,
        path: &str,
        config: &ValidatorConfig,
    ) -> Result<(), String> {
        // TODO: Implement in Phase 4
        Err(format!("WASM validators not yet implemented"))
    }

    /// Shutdown all validators
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
```

---

## 🔨 Phase 3: Built-in Validators & Rhai Support

**Duration**: 2-3 days  
**Goal**: Implement built-in validators and Rhai scripting support

### **Task 3.1: JWT Validator**

**File**: `src/validators/builtin/jwt.rs`

```rust
//! JWT (JSON Web Token) validator

use crate::validators::*;
use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{debug, warn};

/// JWT validator configuration
#[derive(Debug, Clone, Deserialize)]
struct JwtConfig {
    /// JWT signing secret (for HS256, HS384, HS512)
    #[serde(default)]
    secret: Option<String>,

    /// Public key for RS256, RS384, RS512, ES256, ES384 (PEM format)
    #[serde(default)]
    public_key: Option<String>,

    /// Expected issuer (iss claim)
    #[serde(default)]
    issuer: Option<String>,

    /// Expected audience (aud claim)
    #[serde(default)]
    audience: Option<String>,

    /// Required algorithms (default: HS256)
    #[serde(default = "default_algorithms")]
    algorithms: Vec<String>,

    /// Header name containing JWT (default: Authorization)
    #[serde(default = "default_header_name")]
    header_name: String,

    /// Prefix to strip from header value (default: "Bearer ")
    #[serde(default = "default_header_prefix")]
    header_prefix: String,
}

fn default_algorithms() -> Vec<String> {
    vec!["HS256".to_string()]
}

fn default_header_name() -> String {
    "authorization".to_string()
}

fn default_header_prefix() -> String {
    "Bearer ".to_string()
}

/// JWT validator
pub struct JwtValidator {
    config: Option<JwtConfig>,
}

impl JwtValidator {
    pub fn new() -> Self {
        Self { config: None }
    }

    /// Extract JWT from request headers
    fn extract_token(&self, ctx: &ValidationContext) -> Option<String> {
        let config = self.config.as_ref()?;
        let header_value = ctx.get_header(&config.header_name)?;
        
        Some(
            header_value
                .strip_prefix(&config.header_prefix)
                .unwrap_or(header_value)
                .to_string()
        )
    }

    /// Validate JWT token
    fn validate_token(&self, token: &str, config: &JwtConfig) -> Result<TokenClaims, String> {
        // Decode header to get algorithm
        let header = decode_header(token)
            .map_err(|e| format!("Invalid JWT header: {}", e))?;

        // Check if algorithm is allowed
        let algo_str = format!("{:?}", header.alg);
        if !config.algorithms.contains(&algo_str) {
            return Err(format!("Algorithm {} not allowed", algo_str));
        }

        // Build validation rules
        let mut validation = Validation::new(header.alg);
        if let Some(ref issuer) = config.issuer {
            validation.set_issuer(&[issuer]);
        }
        if let Some(ref audience) = config.audience {
            validation.set_audience(&[audience]);
        }

        // Choose decoding key based on algorithm
        let key = if matches!(header.alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
            // HMAC algorithms use secret
            let secret = config.secret.as_ref()
                .ok_or("HMAC algorithm requires 'secret' in config")?;
            DecodingKey::from_secret(secret.as_bytes())
        } else {
            // RSA/ECDSA algorithms use public key
            let public_key = config.public_key.as_ref()
                .ok_or("RSA/ECDSA algorithm requires 'public_key' in config")?;
            DecodingKey::from_rsa_pem(public_key.as_bytes())
                .map_err(|e| format!("Invalid public key: {}", e))?
        };

        // Decode and validate
        let token_data = decode::<TokenClaims>(token, &key, &validation)
            .map_err(|e| format!("JWT validation failed: {}", e))?;

        Ok(token_data.claims)
    }
}

/// JWT claims (standard + custom)
#[derive(Debug, Serialize, Deserialize)]
struct TokenClaims {
    /// Subject (user ID)
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,

    /// Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,

    /// Audience
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,

    /// Expiration time
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,

    /// Not before
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,

    /// Issued at
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i64>,

    /// Custom claims
    #[serde(flatten)]
    custom: serde_json::Map<String, serde_json::Value>,
}

#[async_trait]
impl Validator for JwtValidator {
    async fn validate(
        &self,
        ctx: &ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        let config = self.config.as_ref()
            .ok_or_else(|| ValidationError::ConfigError("JWT validator not initialized".to_string()))?;

        // Extract token
        let token = match self.extract_token(ctx) {
            Some(t) => t,
            None => {
                return Ok(ValidationResult::Deny {
                    status_code: 401,
                    reason: format!("Missing {} header", config.header_name),
                    log_level: LogLevel::Warn,
                    internal_message: None,
                });
            }
        };

        // Validate token
        match self.validate_token(&token, config) {
            Ok(claims) => {
                debug!("✅ JWT validated for subject: {:?}", claims.sub);
                
                // Optionally add claims as headers
                let mut add_headers = HashMap::new();
                if let Some(sub) = claims.sub {
                    add_headers.insert("X-User-ID".to_string(), sub);
                }

                if add_headers.is_empty() {
                    Ok(ValidationResult::Allow)
                } else {
                    Ok(ValidationResult::AllowWithModification {
                        add_headers,
                        remove_headers: vec![],
                        rewrite_path: None,
                        message: Some("JWT validated".to_string()),
                    })
                }
            }
            Err(e) => {
                warn!("🚫 JWT validation failed: {}", e);
                Ok(ValidationResult::Deny {
                    status_code: 401,
                    reason: "Invalid or expired token".to_string(),
                    log_level: LogLevel::Warn,
                    internal_message: Some(e),
                })
            }
        }
    }

    fn name(&self) -> &str {
        "jwt"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn validator_type(&self) -> ValidatorType {
        ValidatorType::Builtin
    }

    fn initialize(&mut self, config: &serde_json::Value) -> Result<(), String> {
        self.config = Some(
            serde_json::from_value(config.clone())
                .map_err(|e| format!("Invalid JWT config: {}", e))?
        );
        Ok(())
    }
}
```

### **Task 3.2: Simple API Key Validator**

**File**: `src/validators/builtin/api_key.rs`

```rust
//! Simple API key validator

use crate::validators::*;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;
use tracing::{debug, warn};

/// API key validator configuration
#[derive(Debug, Clone, Deserialize)]
struct ApiKeyConfig {
    /// Valid API keys
    valid_keys: HashSet<String>,

    /// Header name containing API key (default: X-API-Key)
    #[serde(default = "default_header_name")]
    header_name: String,
}

fn default_header_name() -> String {
    "x-api-key".to_string()
}

/// Simple API key validator
pub struct ApiKeyValidator {
    config: Option<ApiKeyConfig>,
}

impl ApiKeyValidator {
    pub fn new() -> Self {
        Self { config: None }
    }
}

#[async_trait]
impl Validator for ApiKeyValidator {
    async fn validate(
        &self,
        ctx: &ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        let config = self.config.as_ref()
            .ok_or_else(|| ValidationError::ConfigError("API key validator not initialized".to_string()))?;

        // Get API key from header
        let api_key = match ctx.get_header(&config.header_name) {
            Some(key) => key,
            None => {
                return Ok(ValidationResult::Deny {
                    status_code: 401,
                    reason: format!("Missing {} header", config.header_name),
                    log_level: LogLevel::Warn,
                    internal_message: None,
                });
            }
        };

        // Check if key is valid
        if config.valid_keys.contains(api_key) {
            debug!("✅ Valid API key");
            Ok(ValidationResult::Allow)
        } else {
            warn!("🚫 Invalid API key");
            Ok(ValidationResult::Deny {
                status_code: 403,
                reason: "Invalid API key".to_string(),
                log_level: LogLevel::Warn,
                internal_message: Some(format!("Key: {}", api_key)),
            })
        }
    }

    fn name(&self) -> &str {
        "api_key"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn validator_type(&self) -> ValidatorType {
        ValidatorType::Builtin
    }

    fn initialize(&mut self, config: &serde_json::Value) -> Result<(), String> {
        self.config = Some(
            serde_json::from_value(config.clone())
                .map_err(|e| format!("Invalid API key config: {}", e))?
        );
        Ok(())
    }
}
```

### **Task 3.3: Built-in Module Entry**

**File**: `src/validators/builtin/mod.rs`

```rust
//! Built-in validators

mod api_key;
mod jwt;

pub use api_key::ApiKeyValidator;
pub use jwt::JwtValidator;
```

### **Task 3.4: Rhai Script Support**

**File**: `src/validators/script/mod.rs`

```rust
//! Rhai script validator support

mod executor;

pub use executor::RhaiValidator;
```

**File**: `src/validators/script/executor.rs`

```rust
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
    fn register_types(engine: &mut Engine) {
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
        
        // Add config
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

        // Execute script
        let result_map: Map = self.engine
            .call_fn(&mut Scope::new(), &self.ast, "validate", (ctx_map,))
            .map_err(|e| ValidationError::ScriptError(format!("Script execution failed: {}", e)))?;

        // Convert result
        Self::map_to_result(result_map)
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
```

### **Task 3.5: Example Rhai Scripts**

**File**: `validators/examples/simple_api_key.rhai`

```rust
// Simple API key validator example
// 
// This script checks if the X-API-Key header contains a valid key

fn validate(ctx) {
    // Parse config
    let config = parse_json(ctx.config_json);
    let valid_keys = config.valid_keys;
    
    // Get API key from headers
    let api_key = ctx.headers.get("x-api-key");
    
    if api_key == () {
        return #{
            result: "deny",
            reason: "Missing X-API-Key header",
            status_code: 401
        };
    }
    
    // Check if key is valid
    if valid_keys.contains(api_key) {
        return #{ result: "allow" };
    } else {
        return #{
            result: "deny",
            reason: "Invalid API key",
            status_code: 403
        };
    }
}

// Helper function to parse JSON config
fn parse_json(json_str) {
    // This is a simplified version - in reality, Rhai has JSON support
    return #{
        valid_keys: ["key1", "key2", "key3"]
    };
}
```

**File**: `validators/examples/header_check.rhai`

```rust
// Header check validator example
//
// This script checks if specific headers are present

fn validate(ctx) {
    // Required headers
    let required = ["authorization", "x-request-id", "x-client-version"];
    
    for header in required {
        if ctx.headers.get(header) == () {
            return #{
                result: "deny",
                reason: `Missing required header: ${header}`,
                status_code: 400
            };
        }
    }
    
    return #{ result: "allow" };
}
```

---

## 🔮 Phase 4: WASM Support Infrastructure

**Duration**: 3-4 days  
**Goal**: Build WASM runtime and validator SDK

### **Task 4.1: WASM Runtime Setup**

**File**: `src/validators/wasm/mod.rs`

```rust
//! WASM validator support

mod loader;
mod runtime;

pub use loader::WasmValidator;
pub use runtime::WasmRuntime;
```

### **Task 4.2: WASM Runtime Implementation**

**File**: `src/validators/wasm/runtime.rs`

```rust
//! WASM runtime management

use wasmtime::*;
use std::sync::Arc;
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
        linker.func_wrap("env", "log", |caller: Caller<'_, ()>, ptr: i32, len: i32| {
            // TODO: Implement logging from WASM
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
```

### **Task 4.3: WASM Validator Loader**

**File**: `src/validators/wasm/loader.rs`

```rust
//! WASM validator loader

use super::WasmRuntime;
use crate::validators::*;
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, error, warn};
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
```

### **Task 4.4: WASM Validator SDK**

**File**: `validators/sdk/Cargo.toml`

```toml
[package]
name = "jester-jr-validator-sdk"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[profile.release]
opt-level = "z"     # Optimize for size
lto = true          # Enable link-time optimization
codegen-units = 1   # Better optimization
panic = "abort"     # Smaller binary
strip = true        # Strip symbols
```

**File**: `validators/sdk/src/lib.rs`

```rust
//! Jester Jr WASM Validator SDK
//!
//! This SDK provides helper functions and types for building WASM validators.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Validation context passed to validators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationContext {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub client_ip: String,
    pub listener_name: String,
    pub route_name: Option<String>,
    pub config: serde_json::Value,
}

/// Validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ValidationResult {
    Allow,
    AllowWithModification {
        #[serde(default)]
        add_headers: HashMap<String, String>,
        #[serde(default)]
        remove_headers: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rewrite_path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    Deny {
        status_code: u16,
        reason: String,
    },
}

/// Memory allocation function (exported to host)
#[no_mangle]
pub extern "C" fn alloc(len: i32) -> *mut u8 {
    let mut buf = Vec::with_capacity(len as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Memory deallocation function (exported to host)
#[no_mangle]
pub extern "C" fn free(ptr: i32, len: i32) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr as *mut u8, len as usize, len as usize);
    }
}

/// Helper macro to define a validator
#[macro_export]
macro_rules! define_validator {
    ($validate_fn:ident) => {
        #[no_mangle]
        pub extern "C" fn validate(ctx_ptr: i32, ctx_len: i32) -> i32 {
            use $crate::{ValidationContext, ValidationResult};

            // Read context
            let ctx_bytes = unsafe {
                std::slice::from_raw_parts(ctx_ptr as *const u8, ctx_len as usize)
            };

            let ctx: ValidationContext = match serde_json::from_slice(ctx_bytes) {
                Ok(c) => c,
                Err(_) => {
                    let error_result = ValidationResult::Deny {
                        status_code: 500,
                        reason: "Failed to parse context".to_string(),
                    };
                    return serialize_result(error_result);
                }
            };

            // Call user's validation function
            let result = $validate_fn(ctx);

            // Serialize and return result
            serialize_result(result)
        }

        fn serialize_result(result: ValidationResult) -> i32 {
            let result_json = match serde_json::to_vec(&result) {
                Ok(j) => j,
                Err(_) => {
                    return 0; // Indicate error
                }
            };

            // Allocate memory for result (4 bytes length + data)
            let total_len = 4 + result_json.len();
            let result_ptr = $crate::alloc(total_len as i32);

            // Write length
            let len_bytes = (result_json.len() as u32).to_le_bytes();
            unsafe {
                std::ptr::copy_nonoverlapping(
                    len_bytes.as_ptr(),
                    result_ptr,
                    4
                );

                // Write result JSON
                std::ptr::copy_nonoverlapping(
                    result_json.as_ptr(),
                    result_ptr.add(4),
                    result_json.len()
                );
            }

            result_ptr as i32
        }
    };
}
```

**File**: `validators/sdk/README.md`

```markdown
# Jester Jr Validator SDK

Build WASM validators for Jester Jr using Rust.

## Quick Start

1. Create a new Rust project:
```bash
cargo new --lib my_validator
cd my_validator
```

2. Add SDK dependency to `Cargo.toml`:
```toml
[dependencies]
jester-jr-validator-sdk = { path = "../../validators/sdk" }
serde_json = "1.0"

[lib]
crate-type = ["cdylib"]
```

3. Write your validator in `src/lib.rs`:
```rust
use jester_jr_validator_sdk::*;

fn my_validate(ctx: ValidationContext) -> ValidationResult {
    // Your validation logic here
    if ctx.headers.get("x-api-key") == Some(&"secret".to_string()) {
        ValidationResult::Allow
    } else {
        ValidationResult::Deny {
            status_code: 403,
            reason: "Invalid API key".to_string(),
        }
    }
}

define_validator!(my_validate);
```

4. Build WASM:
```bash
cargo build --target wasm32-wasi --release
```

5. Use in Jester Jr config:
```toml
[validators.my_validator]
type = "wasm"
path = "./target/wasm32-wasi/release/my_validator.wasm"
```
```

---

## 🚀 Phase 5: Secret Network Extension

**Duration**: 2-3 days (AFTER framework is complete)  
**Goal**: Build first real-world WASM validator

### **Task 5.1: Secret Network Extension Structure**

**File**: `extensions/secret_network_auth/Cargo.toml`

```toml
[package]
name = "secret-network-auth"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
jester-jr-validator-sdk = { path = "../../validators/sdk" }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Secret Network dependencies
# TODO: Add Secret Network SDK dependencies here

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

### **Task 5.2: Implementation (Placeholder)**

**File**: `extensions/secret_network_auth/src/lib.rs`

```rust
//! Secret Network API Key Validator
//!
//! This validator checks API keys against a Secret Network smart contract.

use jester_jr_validator_sdk::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    contract_address: String,
    rpc_url: String,
}

fn validate_secret_network(ctx: ValidationContext) -> ValidationResult {
    // Parse config
    let config: Config = match serde_json::from_value(ctx.config) {
        Ok(c) => c,
        Err(_) => {
            return ValidationResult::Deny {
                status_code: 500,
                reason: "Invalid configuration".to_string(),
            };
        }
    };

    // Get API key from header
    let api_key = match ctx.headers.get("x-api-key") {
        Some(key) => key,
        None => {
            return ValidationResult::Deny {
                status_code: 401,
                reason: "Missing X-API-Key header".to_string(),
            };
        }
    };

    // TODO: Query Secret Network smart contract
    // For now, this is a placeholder
    
    // Placeholder: Accept all keys for testing
    ValidationResult::Allow
}

define_validator!(validate_secret_network);
```

---

## 🔗 Phase 6: Integration with Main Proxy

**Duration**: 1-2 days  
**Goal**: Wire validators into request handling

### **Task 6.1: Update Config Structures**

**File**: `src/config/config.rs` (additions)

```rust
// Add to existing Config struct

#[derive(Debug, Deserialize)]
pub struct Config {
    // ... existing fields ...
    
    /// Validator registry configuration
    #[serde(default)]
    pub validators: HashMap<String, ValidatorConfigEntry>,
}

/// Validator configuration entry
#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorConfigEntry {
    #[serde(rename = "type")]
    pub validator_type: String,
    
    #[serde(default)]
    pub path: Option<String>,
    
    #[serde(default)]
    pub config: serde_json::Value,
    
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    5
}

// Add to RouteConfig

#[derive(Debug, Deserialize, Clone)]
pub struct RouteConfig {
    // ... existing fields ...
    
    /// Validators to apply to this route
    #[serde(default)]
    pub validators: Vec<RouteValidatorConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteValidatorConfig {
    /// Validator name (from registry)
    pub validator: String,
    
    /// What to do on validation failure
    #[serde(default = "default_on_failure")]
    pub on_failure: String, // "deny" | "allow" | "continue"
    
    /// Override config for this route
    #[serde(default)]
    pub override_config: Option<serde_json::Value>,
}

fn default_on_failure() -> String {
    "deny".to_string()
}
```

### **Task 6.2: Update Main Proxy Logic**

**File**: `src/main.rs` (additions)

```rust
// Add at top of file
mod validators;
use validators::{ValidatorRegistry, ValidationContext, ValidationResult};

// In main() function, after loading config:

// Initialize validator registry
let mut validator_registry = ValidatorRegistry::new();

// Load validators from config
info!("🔧 Loading validators");
let validator_configs: HashMap<String, validators::ValidatorConfig> = 
    config.validators.iter()
        .map(|(name, entry)| {
            (name.clone(), validators::ValidatorConfig {
                name: name.clone(),
                validator_type: match entry.validator_type.as_str() {
                    "builtin" => validators::ValidatorType::Builtin,
                    "script" => validators::ValidatorType::Script,
                    "wasm" => validators::ValidatorType::Wasm,
                    "dylib" => validators::ValidatorType::Dylib,
                    _ => validators::ValidatorType::Builtin,
                },
                path: entry.path.clone(),
                config: entry.config.clone(),
                timeout_seconds: entry.timeout_seconds,
            })
        })
        .collect();

if let Err(e) = validator_registry.load_from_config(&validator_configs).await {
    error!("❌ Failed to load validators: {}", e);
    std::process::exit(1);
}

let validator_registry = Arc::new(validator_registry);

// Pass validator_registry to listeners...
```

### **Task 6.3: Execute Validators in Request Handler**

**File**: `src/main.rs` (in request handling function)

```rust
// Add this function

#[instrument(skip(request, route, validator_registry))]
async fn execute_validators(
    request: &HttpRequest,
    route: &CompiledRoute,
    client_ip: std::net::IpAddr,
    listener_name: &str,
    validator_registry: Arc<ValidatorRegistry>,
) -> Result<(), (u16, String)> {
    // Execute each validator in the chain
    for validator_config in &route.validators {
        let validator = match validator_registry.get(&validator_config.validator) {
            Some(v) => v,
            None => {
                warn!("⚠️  Validator '{}' not found", validator_config.validator);
                if validator_config.on_failure == "deny" {
                    return Err((500, "Validator not found".to_string()));
                }
                continue;
            }
        };

        // Build validation context
        let config = validator_config.override_config.clone()
            .unwrap_or_else(|| serde_json::Value::Null);
        
        let ctx = ValidationContext::from_request(
            request,
            client_ip,
            listener_name.to_string(),
            route.name.clone(),
            config,
            validator_registry.state(),
        );

        // Execute validator with timeout
        let timeout_duration = std::time::Duration::from_secs(5);
        let result = match tokio::time::timeout(
            timeout_duration,
            validator.validate(&ctx)
        ).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                warn!("⚠️  Validator '{}' error: {}", validator_config.validator, e);
                if validator_config.on_failure == "deny" {
                    return Err((500, format!("Validation error: {}", e)));
                }
                continue;
            }
            Err(_) => {
                warn!("⚠️  Validator '{}' timed out", validator_config.validator);
                if validator_config.on_failure == "deny" {
                    return Err((504, "Validation timeout".to_string()));
                }
                continue;
            }
        };

        // Handle result
        match result {
            ValidationResult::Allow => {
                debug!("✅ Validator '{}' allowed request", validator_config.validator);
            }
            ValidationResult::AllowWithModification { add_headers, .. } => {
                debug!("✅ Validator '{}' allowed with modifications", validator_config.validator);
                // TODO: Apply header modifications
            }
            ValidationResult::Deny { status_code, reason, .. } => {
                warn!("🚫 Validator '{}' denied request: {}", validator_config.validator, reason);
                if validator_config.on_failure == "deny" {
                    return Err((status_code, reason));
                } else if validator_config.on_failure == "continue" {
                    continue;
                }
            }
        }
    }

    Ok(())
}

// Call this in handle_plain_connection_with_routing before forwarding:

// Execute validators
if let Err((status_code, reason)) = execute_validators(
    &request,
    route_match.route,
    peer_addr.ip(),
    &listener.name,
    Arc::clone(&validator_registry),
).await {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n\r\n{}",
        status_code,
        match status_code {
            401 => "Unauthorized",
            403 => "Forbidden",
            500 => "Internal Server Error",
            504 => "Gateway Timeout",
            _ => "Error",
        },
        reason.len(),
        reason
    );
    client_writer.write_all(response.as_bytes())?;
    return Ok(());
}
```

---

## 📚 Phase 7: Documentation & Testing

**Duration**: 2 days  
**Goal**: Comprehensive docs and tests

### **Task 7.1: Main Documentation**

**File**: `docs/VALIDATORS.md`

```markdown
# 🔐 Jester Jr Validator Framework

Complete guide to the validator extension system.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Built-in Validators](#built-in-validators)
4. [Rhai Script Validators](#rhai-script-validators)
5. [WASM Validators](#wasm-validators)
6. [Configuration](#configuration)
7. [Writing Custom Validators](#writing-custom-validators)
8. [Performance](#performance)
9. [Troubleshooting](#troubleshooting)

... (detailed documentation follows)
```

### **Task 7.2: Unit Tests**

Create comprehensive test files:
- `src/validators/tests/test_registry.rs`
- `src/validators/tests/test_builtin.rs`
- `src/validators/tests/test_script.rs`
- `src/validators/tests/test_wasm.rs`

### **Task 7.3: Integration Tests**

**File**: `tests/validator_integration.rs`

```rust
//! Integration tests for validator framework

#[cfg(test)]
mod tests {
    // TODO: Add integration tests
}
```

---

## ✅ Phase 8: Example Configuration

**File**: `jester-jr-validators-example.toml`

```toml
# Jester Jr with Validators - Example Configuration

[global]
log_level = "info"
timeout_seconds = 30

# ═══════════════════════════════════════════════════════════
# VALIDATOR REGISTRY
# ═══════════════════════════════════════════════════════════

[validators.jwt]
type = "builtin"
config = { 
    secret = "your-secret-key",
    issuer = "auth.example.com",
    audience = "api"
}

[validators.simple_api_key]
type = "script"
path = "./validators/examples/simple_api_key.rhai"
config = { valid_keys = ["key1", "key2", "key3"] }

[validators.secret_network]
type = "wasm"
path = "./extensions/secret_network_auth.wasm"
config = {
    contract_address = "secret1...",
    rpc_url = "https://lcd.mainnet.secretsaturn.net"
}

# ═══════════════════════════════════════════════════════════
# LISTENER WITH VALIDATORS
# ═══════════════════════════════════════════════════════════

[listener."api"]
ip = "0.0.0.0"
port = 8080
default_action = "reject"

[[listener."api".routes]]
name = "public-api"
path_prefix = "/api/public"
backend = "127.0.0.1:9090"
strip_prefix = true

[[listener."api".routes.validators]]
validator = "simple_api_key"
on_failure = "deny"

[[listener."api".routes]]
name = "protected-api"
path_prefix = "/api/protected"
backend = "127.0.0.1:9091"
strip_prefix = true

[[listener."api".routes.validators]]
validator = "jwt"
on_failure = "deny"

[[listener."api".routes]]
name = "blockchain-api"
path_prefix = "/api/blockchain"
backend = "127.0.0.1:9092"
strip_prefix = true

[[listener."api".routes.validators]]
validator = "secret_network"
on_failure = "deny"
```

---

## 📋 Implementation Checklist

### Phase 0: Setup ✓
- [ ] Create directory structure
- [ ] Update `Cargo.toml` with dependencies
- [ ] Create module structure

### Phase 1: Core Infrastructure
- [ ] Define `Validator` trait (`traits.rs`)
- [ ] Implement `ValidationContext` (`context.rs`)
- [ ] Implement `ValidationResult` types (`result.rs`)
- [ ] Create module entry point (`mod.rs`)

### Phase 2: Registry
- [ ] Implement `ValidatorRegistry` structure
- [ ] Implement validator loading logic
- [ ] Add config parsing

### Phase 3: Built-in & Scripts
- [ ] Implement JWT validator
- [ ] Implement API key validator
- [ ] Implement Rhai script executor
- [ ] Create example Rhai scripts
- [ ] Register built-in validators

### Phase 4: WASM Support
- [ ] Create WASM runtime
- [ ] Implement WASM loader
- [ ] Create validator SDK
- [ ] Test SDK with example validator

### Phase 5: Secret Network (Later)
- [ ] Design Secret Network validator
- [ ] Implement smart contract integration
- [ ] Test with Secret testnet

### Phase 6: Integration
- [ ] Update config structures
- [ ] Wire validators into proxy
- [ ] Implement validator execution chain
- [ ] Add error handling

### Phase 7: Documentation
- [ ] Write `VALIDATORS.md`
- [ ] Write unit tests
- [ ] Write integration tests
- [ ] Create examples

### Phase 8: Polish
- [ ] Performance optimization
- [ ] Error message improvements
- [ ] Add metrics/monitoring hooks

---

## 🎯 Success Criteria

1. ✅ JWT validation works with HS256 and RS256
2. ✅ Rhai script validators execute correctly
3. ✅ WASM validators load and execute
4. ✅ Validator SDK compiles to WASM
5. ✅ All tests pass
6. ✅ Documentation is complete
7. ✅ Example configuration works end-to-end

---

## 📞 Next Steps for Developer

After reviewing this plan:

1. **Start with Phase 0**: Set up the directory structure and dependencies
2. **Proceed sequentially**: Each phase builds on the previous
3. **Test incrementally**: Don't move to next phase until current works
4. **Ask questions**: If any design needs clarification
