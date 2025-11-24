# 🎯 Comprehensive Design: Multi-Backend Validator System for Jester Jr

## 📋 Design Goals Summary

✅ **Three-tier validator system**: Scripting → WASM → Dynamic Libs  
✅ **Smart contract integration** (blockchain API validation)  
✅ **Network calls** (auth servers, databases, smart contracts)  
✅ **Request modification** (add headers, rewrite, etc.)  
✅ **Performance-critical** (faster than Caddy)  
✅ **DevOps/SysAdmin friendly** (clear config, good errors)

---

## 🏗️ Proposed Architecture

### **1. Validator Trait Hierarchy**

```rust
// Core trait that all validators implement
pub trait Validator: Send + Sync {
    /// Validate a request
    fn validate(
        &self,
        ctx: &ValidationContext,
    ) -> Result<ValidationResult, ValidationError>;
    
    /// Validator metadata
    fn name(&self) -> &str;
    fn version(&self) -> &str;
}

/// Context provided to validators
pub struct ValidationContext<'a> {
    pub request: &'a HttpRequest,
    pub headers: &'a HashMap<String, String>,
    pub path: &'a str,
    pub method: &'a str,
    pub client_ip: std::net::IpAddr,
    
    // Config from TOML
    pub config: &'a toml::Value,
    
    // Shared state (for rate limiting, caching, etc.)
    pub state: Arc<ValidatorState>,
}

/// Result of validation
pub enum ValidationResult {
    /// Request is valid, proceed
    Allow,
    
    /// Request is valid, but modify it
    AllowWithModification {
        add_headers: HashMap<String, String>,
        remove_headers: Vec<String>,
        rewrite_path: Option<String>,
    },
    
    /// Request is invalid
    Deny {
        status_code: u16,
        reason: String,
        log_level: LogLevel,
    },
}

pub enum ValidationError {
    ConfigError(String),
    NetworkError(String),
    RuntimeError(String),
    Timeout,
}
```

---

## 🔧 Configuration Design

### **Global Validator Registry**

```toml
# ═══════════════════════════════════════════════════════════
# VALIDATOR REGISTRY
# ═══════════════════════════════════════════════════════════

[validators]

# Built-in validators (no path needed)
[validators.jwt]
type = "builtin"
config = { issuer = "auth.example.com", audience = "api" }

# Scripting validators (Rhai - Rust scripting language)
[validators.simple_api_key]
type = "script"
path = "./validators/api_key.rhai"
config = { valid_keys = ["key1", "key2", "key3"] }

# WASM validators
[validators.smart_contract_auth]
type = "wasm"
path = "./validators/secret_network_auth.wasm"
config = { contract_address = "secret1...", rpc_url = "https://..." }

# Dynamic library validators (maximum performance)
[validators.advanced_rate_limiter]
type = "dylib"
path = "./validators/librate_limiter.so"
config = { max_requests = 1000, window_seconds = 60 }

# Database lookup validator
[validators.user_db_lookup]
type = "wasm"
path = "./validators/postgres_auth.wasm"
config = { 
    db_url = "postgresql://localhost/auth",
    query = "SELECT active FROM users WHERE api_key = $1"
}
```

### **Using Validators in Routes**

```toml
[[listener."public-api".routes]]
name = "api-v1-users"
path_prefix = "/api/v1/users"
backend = "127.0.0.1:9090"
strip_prefix = true

# Chain multiple validators (executed in order)
[[listener."public-api".routes.validators]]
name = "Rate limiting first"
validator = "advanced_rate_limiter"
on_failure = "deny"  # deny | allow | continue

[[listener."public-api".routes.validators]]
name = "Smart contract auth"
validator = "smart_contract_auth"
on_failure = "deny"

[[listener."public-api".routes.validators]]
name = "JWT validation"
validator = "jwt"
on_failure = "deny"

# Override validator config per-route
[[listener."public-api".routes.validators]]
name = "Custom rate limit for this route"
validator = "advanced_rate_limiter"
on_failure = "deny"
override_config = { max_requests = 500 }  # Override global config
```

---

## 🎨 Implementation Strategy

### **Phase 1: Core Validator Infrastructure** (Week 1)

**Files to create:**
```
src/
  validators/
    mod.rs              # Main module
    trait.rs            # Validator trait definitions
    registry.rs         # Validator registry and loading
    builtin/
      mod.rs
      jwt.rs            # Built-in JWT validator
      api_key.rs        # Built-in API key validator
      basic_auth.rs     # Built-in basic auth
```

**Key code:**

```rust
// src/validators/registry.rs

use std::collections::HashMap;
use std::sync::Arc;

pub struct ValidatorRegistry {
    validators: HashMap<String, Arc<dyn Validator>>,
    wasm_runtime: wasmtime::Engine,
}

impl ValidatorRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            validators: HashMap::new(),
            wasm_runtime: wasmtime::Engine::default(),
        };
        
        // Register built-in validators
        registry.register_builtin();
        
        registry
    }
    
    fn register_builtin(&mut self) {
        self.validators.insert(
            "jwt".to_string(),
            Arc::new(JwtValidator::new())
        );
        self.validators.insert(
            "api_key".to_string(),
            Arc::new(ApiKeyValidator::new())
        );
    }
    
    pub fn load_from_config(
        &mut self,
        config: &ValidatorConfig
    ) -> Result<(), String> {
        match config.validator_type.as_str() {
            "builtin" => Ok(()), // Already loaded
            "script" => self.load_script_validator(config),
            "wasm" => self.load_wasm_validator(config),
            "dylib" => self.load_dylib_validator(config),
            _ => Err(format!("Unknown validator type: {}", config.validator_type))
        }
    }
    
    pub fn get(&self, name: &str) -> Option<Arc<dyn Validator>> {
        self.validators.get(name).cloned()
    }
}
```

---

### **Phase 2: Scripting Support (Rhai)** (Week 1-2)

**Why Rhai?**
- ✅ Pure Rust (no external dependencies)
- ✅ Fast (JIT compilation)
- ✅ Safe (sandboxed)
- ✅ Easy syntax (similar to Rust/JavaScript)

**Example Rhai validator:**

```rust
// validators/api_key.rhai

// Validator function - must be named 'validate'
fn validate(ctx) {
    // Access request data
    let auth_header = ctx.headers.get("authorization");
    
    if auth_header == () {
        return #{ 
            result: "deny",
            reason: "Missing Authorization header",
            status_code: 401
        };
    }
    
    // Extract API key
    let api_key = auth_header.replace("Bearer ", "");
    
    // Check against valid keys from config
    let valid_keys = ctx.config.valid_keys;
    
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
```

**Loading Rhai validators:**

```rust
// src/validators/script.rs

use rhai::{Engine, AST};

pub struct RhaiValidator {
    engine: Engine,
    ast: AST,
    name: String,
}

impl RhaiValidator {
    pub fn from_file(path: &str, name: String) -> Result<Self, String> {
        let mut engine = Engine::new();
        
        // Register custom types
        engine.register_type::<ValidationContext>();
        
        let ast = engine.compile_file(path.into())
            .map_err(|e| format!("Failed to compile script: {}", e))?;
        
        Ok(Self { engine, ast, name })
    }
}

impl Validator for RhaiValidator {
    fn validate(&self, ctx: &ValidationContext) -> Result<ValidationResult, ValidationError> {
        // Call the 'validate' function in the script
        let result: rhai::Map = self.engine
            .call_fn(&mut rhai::Scope::new(), &self.ast, "validate", (ctx.clone(),))
            .map_err(|e| ValidationError::RuntimeError(e.to_string()))?;
        
        // Parse result
        match result.get("result").and_then(|v| v.as_str()) {
            Some("allow") => Ok(ValidationResult::Allow),
            Some("deny") => {
                let reason = result.get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Access denied")
                    .to_string();
                let status_code = result.get("status_code")
                    .and_then(|v| v.as_int())
                    .unwrap_or(403) as u16;
                
                Ok(ValidationResult::Deny {
                    status_code,
                    reason,
                    log_level: LogLevel::Warn,
                })
            }
            _ => Err(ValidationError::RuntimeError("Invalid script result".to_string()))
        }
    }
    
    fn name(&self) -> &str { &self.name }
    fn version(&self) -> &str { "1.0.0" }
}
```

---

### **Phase 3: WASM Support** (Week 2-3)

**Dependencies:**
```toml
[dependencies]
wasmtime = "27"
```

**WASM Validator Interface (Rust → WASM):**

```rust
// validators/wasm_interface.rs

// This is what WASM validators must implement
#[repr(C)]
pub struct WasmValidationContext {
    pub method_ptr: *const u8,
    pub method_len: usize,
    pub path_ptr: *const u8,
    pub path_len: usize,
    pub headers_json_ptr: *const u8,
    pub headers_json_len: usize,
    pub config_json_ptr: *const u8,
    pub config_json_len: usize,
}

#[repr(C)]
pub struct WasmValidationResult {
    pub result_type: u8, // 0 = allow, 1 = deny, 2 = allow_with_modification
    pub status_code: u16,
    pub reason_ptr: *mut u8,
    pub reason_len: usize,
    pub modified_headers_json_ptr: *mut u8,
    pub modified_headers_json_len: usize,
}

// WASM validators export this function
extern "C" {
    pub fn validate(ctx: *const WasmValidationContext) -> WasmValidationResult;
}
```

**Example WASM Validator (Rust):**

```rust
// validators/secret_network_auth/src/lib.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize)]
struct Config {
    contract_address: String,
    rpc_url: String,
}

#[no_mangle]
pub extern "C" fn validate(ctx_ptr: *const u8, ctx_len: usize) -> *mut u8 {
    // Deserialize context
    let ctx_bytes = unsafe { std::slice::from_raw_parts(ctx_ptr, ctx_len) };
    let ctx: ValidationContext = serde_json::from_slice(ctx_bytes).unwrap();
    
    // Get API key from header
    let api_key = match ctx.headers.get("x-api-key") {
        Some(key) => key,
        None => {
            let result = ValidationResult::Deny {
                status_code: 401,
                reason: "Missing X-API-Key header".to_string(),
            };
            return serialize_result(result);
        }
    };
    
    // Parse config
    let config: Config = serde_json::from_value(ctx.config.clone()).unwrap();
    
    // Call smart contract to validate API key
    match query_secret_contract(&config.contract_address, &config.rpc_url, api_key) {
        Ok(valid) if valid => {
            let result = ValidationResult::Allow;
            serialize_result(result)
        }
        Ok(_) => {
            let result = ValidationResult::Deny {
                status_code: 403,
                reason: "Invalid API key".to_string(),
            };
            serialize_result(result)
        }
        Err(e) => {
            let result = ValidationResult::Deny {
                status_code: 500,
                reason: format!("Smart contract error: {}", e),
            };
            serialize_result(result)
        }
    }
}

fn query_secret_contract(
    address: &str,
    rpc_url: &str,
    api_key: &str
) -> Result<bool, String> {
    // TODO: Implement Secret Network smart contract query
    // This will use your smart contract implementation
    Ok(true)
}

fn serialize_result(result: ValidationResult) -> *mut u8 {
    let json = serde_json::to_vec(&result).unwrap();
    let ptr = json.as_ptr() as *mut u8;
    std::mem::forget(json); // Prevent deallocation
    ptr
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum ValidationResult {
    Allow,
    Deny { status_code: u16, reason: String },
}

#[derive(Deserialize)]
struct ValidationContext {
    headers: HashMap<String, String>,
    path: String,
    method: String,
    config: serde_json::Value,
}
```

**Compile WASM validator:**
```bash
cd validators/secret_network_auth
cargo build --target wasm32-wasi --release
cp target/wasm32-wasi/release/secret_network_auth.wasm ../../validators/
```

---

### **Phase 4: Dynamic Library Support** (Week 3)

**For maximum performance validators** (rate limiting, complex logic):

```rust
// src/validators/dylib.rs

use libloading::{Library, Symbol};

pub struct DylibValidator {
    _library: Library, // Keep alive
    validate_fn: Symbol<'static, ValidateFn>,
    name: String,
}

type ValidateFn = unsafe extern "C" fn(
    *const ValidationContext,
    *mut ValidationResult
) -> i32;

impl DylibValidator {
    pub fn from_path(path: &str, name: String) -> Result<Self, String> {
        let library = unsafe {
            Library::new(path)
                .map_err(|e| format!("Failed to load library: {}", e))?
        };
        
        let validate_fn = unsafe {
            library.get(b"validate")
                .map_err(|e| format!("Failed to find validate function: {}", e))?
        };
        
        // Leak library to make Symbol 'static
        let validate_fn = unsafe { std::mem::transmute(validate_fn) };
        let library = unsafe { std::mem::transmute(library) };
        
        Ok(Self { _library: library, validate_fn, name })
    }
}
```

---

## 📊 Performance Comparison

| Validator Type | Overhead   | Use Case                                   |
| -------------- | ---------- | ------------------------------------------ |
| Built-in       | **<0.1ms** | JWT, Basic Auth, Simple API keys           |
| Rhai Script    | **~0.5ms** | Simple business logic, config-based rules  |
| WASM           | **~1-2ms** | Network calls, DB lookups, smart contracts |
| Dynamic Lib    | **<0.1ms** | Rate limiting, complex algorithms          |

---
