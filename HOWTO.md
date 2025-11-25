# 🚀 Jester Jr Extension Development HOWTO

## 📖 Table of Contents

1. [Introduction](#introduction)
2. [Technology Overview](#technology-overview)
3. [Development Environment Setup](#development-environment-setup)
4. [Rhai Extensions](#rhai-extensions)
5. [WASM Extensions](#wasm-extensions)
6. [Testing & Debugging](#testing--debugging)
7. [Deployment & Configuration](#deployment--configuration)
8. [Complete Examples](#complete-examples)
9. [Troubleshooting](#troubleshooting)
10. [Performance Guide](#performance-guide)

---

## 🌟 Introduction

Jester Jr is a high-performance reverse proxy built in Rust with an extensible validator architecture. This guide teaches you how to create custom extensions to validate, modify, or control incoming requests without rebuilding the entire proxy.

### Why Extensions?

**🎯 Benefits:**
- **Zero downtime deployment** - Add new validation logic without restarting
- **Language flexibility** - Write in Rust (WASM) or simple scripts (Rhai)
- **Performance** - Near-native speed with proper caching
- **Security** - Sandboxed execution prevents system compromise
- **Maintainability** - Separate business logic from core proxy code

**🏗️ Extension Types:**

| Type | Overhead | Use Case | Language |
|------|----------|----------|----------|
| **Built-in** | <0.1ms | JWT, API keys, basic auth | Rust (compiled) |
| **Rhai Script** | ~0.5ms | Simple rules, config-based logic | Rhai (scripting) |
| **WASM** | 1-2ms | Complex logic, network calls, databases | Rust → WASM |
| **Dynamic Lib** | <0.1ms | Performance-critical algorithms | Rust (native) |

This guide focuses on **Rhai** and **WASM** extensions as they provide the best balance of flexibility and performance.

---

## 🔧 Technology Overview

### What is Rhai?

[Rhai](https://rhai.rs/) is a small, fast scripting language designed for embedding in Rust applications.

**Key Features:**
- **Rust-like syntax** - Familiar to Rust developers
- **Type safety** - Strong typing with runtime checks  
- **Fast execution** - JIT compilation and optimizations
- **Sandboxed** - Cannot access file system or network directly
- **Easy integration** - Native Rust types and functions

**Example Rhai Code:**
```rust
fn validate(ctx) {
    let api_key = ctx.headers.get("x-api-key");
    if api_key == () {
        return #{ 
            result: "deny", 
            reason: "Missing API key",
            status_code: 401 
        };
    }
    
    let valid_keys = ["sk-prod-123", "sk-staging-456"];
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

### What is WASM?

[WebAssembly (WASM)](https://webassembly.org/) is a binary instruction format that runs in a secure, sandboxed environment at near-native speed.

**Key Features:**
- **Near-native performance** - Compiled binary execution
- **Memory safety** - Protected linear memory model
- **Language agnostic** - Compile from Rust, C++, Go, etc.
- **Sandboxed** - Cannot access host system without explicit permissions
- **Portable** - Runs consistently across platforms

**WASM in Jester Jr:**
- Compiled from Rust using the provided SDK
- Executes in [Wasmtime](https://wasmtime.dev/) runtime
- Communicates via JSON serialization
- Limited to 5-second execution timeout

### Architecture Overview

```
Request → [Jester Jr Proxy] → [Validator Chain] → Backend
                                     ↓
                          ┌─────────────────────┐
                          │   Validator Types   │
                          ├─────────────────────┤
                          │ Built-in (native)   │
                          │ Rhai (scripted)     │
                          │ WASM (compiled)     │
                          │ Dynamic Lib (native)│
                          └─────────────────────┘
```

**Request Flow:**
1. Request arrives at Jester Jr proxy
2. Route configuration determines which validators to run
3. Each validator receives ValidationContext with request data
4. Validator returns Allow/Deny/AllowWithModification
5. If allowed, request forwards to backend
6. Response can be modified by validators on return path

---

## 🛠️ Development Environment Setup

### Prerequisites

**Required Software:**
```bash
# Rust toolchain (latest stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update stable

# WASM target (for WASM validators)
rustup target add wasm32-wasip1

# Python (for testing and config generation)
python3 --version  # Should be 3.7+
```

**Optional Tools:**
```bash
# WASM debugging and inspection
cargo install twiggy      # WASM binary analyzer
cargo install wasm-pack   # WASM packaging tool

# Code formatting and linting
rustup component add rustfmt clippy
```

### Clone and Build Jester Jr

```bash
# Clone the repository
git clone <repository-url>
cd jester-jr

# Build the project
cargo build --release

# Verify validators are working
cargo test --lib validators
```

### Directory Structure Understanding

```
jester-jr/
├── src/
│   ├── validators/              # Core validator framework
│   │   ├── traits.rs            # Validator trait definition
│   │   ├── context.rs           # ValidationContext type
│   │   ├── registry.rs          # Validator loading and management
│   │   ├── builtin/            # Built-in validators
│   │   ├── script/             # Rhai script support
│   │   └── wasm/               # WASM runtime and loader
├── validators/                  # Extension files
│   ├── examples/               # Example Rhai scripts
│   ├── sdk/                    # WASM validator SDK
│   └── *.wasm                  # Compiled WASM validators
├── examples/                   # Complete example projects
└── scripts/                   # Helper scripts
```

---

## 📜 Rhai Extensions

### Understanding the Rhai Environment

Jester Jr provides a sandboxed Rhai environment with access to request data but no file system or network access.

**Available Context:**
```rust
// What your Rhai script receives
ctx = #{
    method: "GET",                    // HTTP method
    path: "/api/users",              // Request path
    headers: #{                      // Headers as map
        "authorization": "Bearer ...",
        "x-api-key": "sk-123",
        "user-agent": "curl/7.68.0"
    },
    client_ip: "192.168.1.100",      // Client IP address
    config_json: "{...}"             // Your validator config as JSON string
}
```

### Writing Your First Rhai Validator

Let's create a simple API key validator:

**File: `validators/examples/my_api_validator.rhai`**
```rust
// API Key Validator - checks X-API-Key header
fn validate(ctx) {
    // Get the API key from headers
    let api_key = ctx.headers.get("x-api-key");
    
    // Check if header exists
    if api_key == () {
        return #{
            result: "deny",
            reason: "Missing X-API-Key header", 
            status_code: 401
        };
    }
    
    // Define valid keys (in real world, load from config)
    let valid_keys = [
        "sk-prod-secure-key-123",
        "sk-staging-test-456",
        "sk-dev-local-789"
    ];
    
    // Validate the key
    if valid_keys.contains(api_key) {
        return #{
            result: "allow"
        };
    } else {
        return #{
            result: "deny",
            reason: "Invalid API key",
            status_code: 403
        };
    }
}
```

### Advanced Rhai Features

**Working with JSON Configuration:**
```rust
// In your Rhai script
fn validate(ctx) {
    // Parse JSON config (simplified - you'll get this as a string)
    let config_str = ctx.config_json;
    
    // For now, we simulate config parsing
    // In the future, Jester Jr will provide JSON parsing functions
    
    // Extract header name from path or use default
    let header_name = "x-api-key";
    if ctx.path.contains("/admin") {
        header_name = "x-admin-key";
    }
    
    let api_key = ctx.headers.get(header_name);
    
    if api_key == () {
        return #{
            result: "deny",
            reason: `Missing ${header_name} header`,
            status_code: 401
        };
    }
    
    // Rest of validation...
}
```

**Request Modification:**
```rust
fn validate(ctx) {
    // Allow request but modify it
    return #{
        result: "allow_with_modification",
        add_headers: #{
            "x-validated-by": "rhai-validator",
            "x-request-id": "req-12345",
            "x-processing-time": "0.5ms"
        },
        remove_headers: ["x-debug-token"],
        rewrite_path: "/v2" + ctx.path  // Upgrade API version
    };
}
```

**Advanced Logic Examples:**
```rust
// Rate limiting by IP (simplified)
fn validate(ctx) {
    let client_ip = ctx.client_ip;
    
    // Simulate rate limiting logic
    if client_ip.contains("192.168.1.") {
        // Local network - always allow
        return #{ result: "allow" };
    }
    
    // External IPs - check method
    if ctx.method == "POST" || ctx.method == "PUT" || ctx.method == "DELETE" {
        // Require auth for write operations
        let auth = ctx.headers.get("authorization");
        if auth == () {
            return #{
                result: "deny",
                reason: "Authentication required for write operations",
                status_code: 401
            };
        }
    }
    
    return #{ result: "allow" };
}
```

### Rhai Best Practices

**✅ Do:**
- Keep scripts simple and focused
- Use descriptive variable names
- Return early on failure conditions
- Validate all inputs before use
- Use consistent error messages

**❌ Don't:**
- Write complex algorithms (use WASM instead)
- Assume headers exist (always check)
- Create deep nested logic (prefer flat structure)
- Use magic numbers (define constants)

**Performance Tips:**
- Cache expensive computations using early returns
- Use string comparisons efficiently
- Prefer array lookups over complex conditionals
- Keep the number of operations low

### Testing Rhai Validators

**Manual Testing:**
```bash
# Create test configuration
cat > test-rhai.toml << EOF
[validators.my_api]
type = "script"
path = "./validators/examples/my_api_validator.rhai"

[listener."test"]
ip = "127.0.0.1"
port = 8080

[[listener."test".routes]]
name = "api"
path_prefix = "/api"
backend = "127.0.0.1:9090"

[[listener."test".routes.validators]]
validator = "my_api"
on_failure = "deny"
EOF

# Start Jester Jr with test config
./target/release/jester-jr test-rhai.toml &

# Test the validator
curl -H "X-API-Key: sk-prod-secure-key-123" http://localhost:8080/api/test  # Should work
curl http://localhost:8080/api/test  # Should fail with 401
curl -H "X-API-Key: invalid" http://localhost:8080/api/test  # Should fail with 403
```

---

## 🦀 WASM Extensions

### Understanding the WASM SDK

Jester Jr provides a Rust SDK for creating WASM validators. The SDK handles:
- **Serialization** - Converting between Rust types and JSON
- **Memory management** - Safe allocation/deallocation  
- **Error handling** - Consistent error reporting
- **Host communication** - Function exports and imports

**SDK Location:** `validators/sdk/`

### Creating Your First WASM Validator

Let's build a database-backed user validator step by step.

#### Step 1: Create Project Structure

```bash
mkdir -p examples/user-db-validator
cd examples/user-db-validator
```

**File: `Cargo.toml`**
```toml
[package]
name = "user-db-validator"
version = "0.1.0"
edition = "2024"

[workspace]
# Empty workspace to exclude from parent

[lib]
crate-type = ["cdylib"]

[dependencies]
jester-jr-validator-sdk = { path = "../../validators/sdk" }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# For HTTP requests (if needed)
# ureq = { version = "2.0", default-features = false, features = ["json"] }

[profile.release]
opt-level = "z"     # Optimize for size
lto = true          # Link-time optimization
codegen-units = 1   # Better optimization
panic = "abort"     # Smaller binary
strip = true        # Strip debug symbols
```

#### Step 2: Implement the Validator

**File: `src/lib.rs`**
```rust
//! User Database Validator
//! 
//! This validator checks if a user exists and is active in a database
//! by making an HTTP call to a user service API.

use jester_jr_validator_sdk::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Configuration for this validator
#[derive(Debug, Deserialize)]
struct Config {
    /// Base URL for the user service
    user_service_url: String,
    /// API key for the user service
    service_api_key: Option<String>,
    /// Which header contains the user ID
    user_id_header: Option<String>,
    /// Required user status
    required_status: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            user_service_url: "http://localhost:3000".to_string(),
            service_api_key: None,
            user_id_header: Some("x-user-id".to_string()),
            required_status: Some("active".to_string()),
        }
    }
}

/// User information returned by the service
#[derive(Debug, Deserialize)]
struct User {
    id: String,
    email: String,
    status: String,
    roles: Vec<String>,
}

/// Main validator function
fn validate_user_db(ctx: ValidationContext) -> ValidationResult {
    // Parse configuration
    let config: Config = match serde_json::from_value(ctx.config.clone()) {
        Ok(config) => config,
        Err(e) => {
            return ValidationResult::Deny {
                status_code: 500,
                reason: format!("Invalid validator configuration: {}", e),
            };
        }
    };

    // Extract user ID from headers
    let user_id_header = config.user_id_header.as_deref().unwrap_or("x-user-id");
    let user_id = match ctx.headers.get(user_id_header) {
        Some(id) if !id.is_empty() => id,
        _ => {
            return ValidationResult::Deny {
                status_code: 401,
                reason: format!("Missing or empty {} header", user_id_header),
            };
        }
    };

    // Query user service (simulated - in real implementation you'd make HTTP request)
    match query_user_service(&config, user_id) {
        Ok(user) => {
            // Check user status
            let required_status = config.required_status.as_deref().unwrap_or("active");
            if user.status != required_status {
                return ValidationResult::Deny {
                    status_code: 403,
                    reason: format!("User status '{}' does not meet requirement '{}'", 
                                  user.status, required_status),
                };
            }

            // User is valid - add tracking headers
            let mut add_headers = HashMap::new();
            add_headers.insert("X-User-Email".to_string(), user.email);
            add_headers.insert("X-User-Status".to_string(), user.status);
            add_headers.insert("X-User-Roles".to_string(), user.roles.join(","));
            add_headers.insert("X-Validated-By".to_string(), "user-db-wasm".to_string());

            ValidationResult::AllowWithModification {
                add_headers,
                remove_headers: vec![],
                rewrite_path: None,
                message: Some(format!("User {} validated successfully", user_id)),
            }
        }
        Err(e) => {
            ValidationResult::Deny {
                status_code: 503,
                reason: format!("User service error: {}", e),
            }
        }
    }
}

/// Query the user service for user information
/// 
/// In a real implementation, this would make an HTTP request.
/// For this example, we'll simulate the response.
fn query_user_service(config: &Config, user_id: &str) -> Result<User, String> {
    // Simulate API call delay and logic
    
    // Simulate different responses based on user ID
    match user_id {
        "user123" => Ok(User {
            id: "user123".to_string(),
            email: "alice@example.com".to_string(),
            status: "active".to_string(),
            roles: vec!["user".to_string(), "admin".to_string()],
        }),
        "user456" => Ok(User {
            id: "user456".to_string(),
            email: "bob@example.com".to_string(),
            status: "suspended".to_string(),
            roles: vec!["user".to_string()],
        }),
        "user789" => Ok(User {
            id: "user789".to_string(),
            email: "carol@example.com".to_string(),
            status: "active".to_string(),
            roles: vec!["user".to_string()],
        }),
        _ => Err("User not found".to_string()),
    }

    // Real implementation would look like:
    // 
    // let url = format!("{}/users/{}", config.user_service_url, user_id);
    // let mut request = ureq::get(&url);
    // 
    // if let Some(api_key) = &config.service_api_key {
    //     request = request.set("Authorization", &format!("Bearer {}", api_key));
    // }
    // 
    // let response = request.call()
    //     .map_err(|e| format!("HTTP request failed: {}", e))?;
    // 
    // let user: User = response.into_json()
    //     .map_err(|e| format!("JSON parsing failed: {}", e))?;
    // 
    // Ok(user)
}

// Export the validator using the SDK macro
define_validator!(validate_user_db);
```

#### Step 3: Build the WASM Module

```bash
# Build for WASM target
cargo build --release --target wasm32-wasip1

# Copy to validators directory
cp target/wasm32-wasip1/release/user_db_validator.wasm ../../validators/
```

#### Step 4: Create Configuration

**File: `user-validator-config.toml`**
```toml
# User Database Validator Configuration

[validators.user_db]
type = "wasm"
path = "./validators/user_db_validator.wasm"
timeout_seconds = 5
config = {
    user_service_url = "http://user-service:3000",
    service_api_key = "service-key-123",
    user_id_header = "x-user-id",
    required_status = "active"
}

[listener."api"]
ip = "0.0.0.0"
port = 8080

[[listener."api".routes]]
name = "user-api"
path_prefix = "/api/users"
backend = "127.0.0.1:9090"

[[listener."api".routes.validators]]
validator = "user_db"
on_failure = "deny"
```

### Advanced WASM Features

#### HTTP Requests in WASM

For real HTTP requests, you can use `ureq` with careful feature selection:

```toml
[dependencies]
ureq = { version = "2.0", default-features = false, features = ["json"] }
```

```rust
fn make_http_request(url: &str, api_key: Option<&str>) -> Result<serde_json::Value, String> {
    let mut request = ureq::get(url);
    
    if let Some(key) = api_key {
        request = request.set("Authorization", &format!("Bearer {}", key));
    }
    
    let response = request
        .timeout(std::time::Duration::from_secs(3))
        .call()
        .map_err(|e| format!("HTTP request failed: {}", e))?;
    
    let json: serde_json::Value = response
        .into_json()
        .map_err(|e| format!("Failed to parse JSON: {}", e))?;
    
    Ok(json)
}
```

#### Error Handling Patterns

```rust
// Robust error handling
fn validate_with_error_handling(ctx: ValidationContext) -> ValidationResult {
    let result = std::panic::catch_unwind(|| {
        // Your validation logic here
        do_actual_validation(ctx)
    });
    
    match result {
        Ok(validation_result) => validation_result,
        Err(_) => ValidationResult::Deny {
            status_code: 500,
            reason: "Validator panicked - check logs".to_string(),
        },
    }
}

fn do_actual_validation(ctx: ValidationContext) -> ValidationResult {
    // Validation logic with proper error handling
    let config = parse_config(&ctx.config)?;
    let user_data = fetch_user_data(&config, &ctx)?;
    validate_user_permissions(user_data, &ctx)
}
```

#### Memory Optimization

```rust
// Efficient string handling
fn efficient_string_ops(input: &str) -> String {
    // Avoid unnecessary allocations
    if input.is_empty() {
        return String::new();
    }
    
    // Use string slicing when possible
    let trimmed = input.trim();
    if trimmed.len() == input.len() {
        input.to_string()  // No allocation if no trim needed
    } else {
        trimmed.to_string()
    }
}

// Reuse allocations
fn process_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    let mut result = HashMap::with_capacity(headers.len());
    
    for (key, value) in headers {
        let normalized_key = key.to_lowercase();
        result.insert(normalized_key, value.clone());
    }
    
    result
}
```

### WASM Best Practices

**✅ Performance:**
- Minimize memory allocations
- Use `&str` instead of `String` when possible
- Batch operations instead of multiple small calls
- Cache expensive computations
- Set appropriate timeout values

**✅ Security:**
- Validate all inputs thoroughly
- Use safe string operations
- Handle panics gracefully
- Limit external network calls
- Sanitize data before logging

**✅ Maintainability:**
- Use clear error messages
- Document configuration options
- Provide sensible defaults
- Use semantic versioning
- Include usage examples

**❌ Avoid:**
- Large binary sizes (optimize for `z`)
- Infinite loops or long computations
- Unsafe memory operations
- Exposing sensitive data in headers
- Complex multi-threading (WASM is single-threaded)

---

## 🧪 Testing & Debugging

### Unit Testing WASM Validators

**File: `tests/integration_test.rs`**
```rust
use jester_jr_validator_sdk::*;
use serde_json::json;
use std::collections::HashMap;

#[test]
fn test_valid_user() {
    let mut headers = HashMap::new();
    headers.insert("x-user-id".to_string(), "user123".to_string());
    
    let ctx = ValidationContext {
        method: "GET".to_string(),
        path: "/api/users".to_string(),
        version: "HTTP/1.1".to_string(),
        headers,
        client_ip: "192.168.1.100".to_string(),
        listener_name: "test".to_string(),
        route_name: Some("api".to_string()),
        config: json!({
            "user_service_url": "http://localhost:3000",
            "user_id_header": "x-user-id",
            "required_status": "active"
        }),
    };
    
    let result = validate_user_db(ctx);
    
    match result {
        ValidationResult::AllowWithModification { add_headers, .. } => {
            assert!(add_headers.contains_key("X-User-Email"));
            assert_eq!(add_headers.get("X-User-Status"), Some(&"active".to_string()));
        }
        _ => panic!("Expected AllowWithModification, got: {:?}", result),
    }
}

#[test]
fn test_missing_user_id() {
    let ctx = ValidationContext {
        method: "GET".to_string(),
        path: "/api/users".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: HashMap::new(), // No user ID header
        client_ip: "192.168.1.100".to_string(),
        listener_name: "test".to_string(),
        route_name: Some("api".to_string()),
        config: json!({
            "user_service_url": "http://localhost:3000",
            "user_id_header": "x-user-id",
            "required_status": "active"
        }),
    };
    
    let result = validate_user_db(ctx);
    
    match result {
        ValidationResult::Deny { status_code, reason } => {
            assert_eq!(status_code, 401);
            assert!(reason.contains("Missing or empty x-user-id header"));
        }
        _ => panic!("Expected Deny, got: {:?}", result),
    }
}

#[test]  
fn test_suspended_user() {
    let mut headers = HashMap::new();
    headers.insert("x-user-id".to_string(), "user456".to_string());
    
    let ctx = ValidationContext {
        method: "GET".to_string(),
        path: "/api/users".to_string(),
        version: "HTTP/1.1".to_string(),
        headers,
        client_ip: "192.168.1.100".to_string(),
        listener_name: "test".to_string(),
        route_name: Some("api".to_string()),
        config: json!({
            "user_service_url": "http://localhost:3000",
            "user_id_header": "x-user-id",
            "required_status": "active"
        }),
    };
    
    let result = validate_user_db(ctx);
    
    match result {
        ValidationResult::Deny { status_code, reason } => {
            assert_eq!(status_code, 403);
            assert!(reason.contains("suspended"));
        }
        _ => panic!("Expected Deny, got: {:?}", result),
    }
}
```

Run tests with:
```bash
cargo test
```

### Integration Testing with Jester Jr

**Test Script: `test-validator.sh`**
```bash
#!/bin/bash

set -e

echo "🧪 Testing User Database Validator"

# Start a mock user service
python3 -c "
import json
import http.server
import socketserver
from urllib.parse import urlparse

class UserServiceHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/users/user123':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {
                'id': 'user123',
                'email': 'alice@example.com',
                'status': 'active',
                'roles': ['user', 'admin']
            }
            self.wfile.write(json.dumps(response).encode())
        elif path == '/users/user456':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {
                'id': 'user456',
                'email': 'bob@example.com',
                'status': 'suspended',
                'roles': ['user']
            }
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'User not found')
            
    def log_message(self, format, *args):
        pass  # Suppress logs

with socketserver.TCPServer(('', 3000), UserServiceHandler) as httpd:
    print('Mock user service running on :3000')
    httpd.serve_forever()
" &
USER_SERVICE_PID=$!

sleep 1

# Start backend API
python3 -c "
import http.server
import socketserver

class BackendHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{\"message\": \"Hello from backend\"}')
        
    def log_message(self, format, *args):
        pass

with socketserver.TCPServer(('', 9090), BackendHandler) as httpd:
    httpd.serve_forever()
" &
BACKEND_PID=$!

sleep 1

# Start Jester Jr with our validator
./target/release/jester-jr user-validator-config.toml &
PROXY_PID=$!

sleep 2

echo "🧪 Running tests..."

echo "✅ Test 1: Valid user (should pass)"
response=$(curl -s -H "X-User-ID: user123" http://localhost:8080/api/users)
echo "Response: $response"

echo "✅ Test 2: No user ID (should fail with 401)"
curl -s -w "Status: %{http_code}\n" http://localhost:8080/api/users

echo "✅ Test 3: Suspended user (should fail with 403)"
curl -s -w "Status: %{http_code}\n" -H "X-User-ID: user456" http://localhost:8080/api/users

echo "✅ Test 4: Non-existent user (should fail with 503)"
curl -s -w "Status: %{http_code}\n" -H "X-User-ID: nonexistent" http://localhost:8080/api/users

# Cleanup
kill $PROXY_PID $BACKEND_PID $USER_SERVICE_PID 2>/dev/null
wait 2>/dev/null

echo "🎉 Tests completed!"
```

### Debugging Techniques

**1. Add Debug Logging:**
```rust
use log::{debug, info, warn, error};

fn validate_with_logging(ctx: ValidationContext) -> ValidationResult {
    debug!("Validator called for path: {}", ctx.path);
    debug!("Headers: {:?}", ctx.headers);
    
    let result = do_validation(ctx);
    
    match &result {
        ValidationResult::Allow => info!("Request allowed"),
        ValidationResult::Deny { reason, .. } => warn!("Request denied: {}", reason),
        ValidationResult::AllowWithModification { message, .. } => {
            info!("Request modified: {}", message.as_deref().unwrap_or("No message"));
        }
    }
    
    result
}
```

**2. Use Jester Jr's Debug Mode:**
```bash
# Run with debug logging
RUST_LOG=debug ./target/release/jester-jr config.toml

# Filter to validator logs only
RUST_LOG=jester_jr::validators=debug ./target/release/jester-jr config.toml
```

**3. WASM Binary Analysis:**
```bash
# Analyze WASM binary size
twiggy top validators/user_db_validator.wasm

# Check exports
wasm-objdump -x validators/user_db_validator.wasm | grep export
```

**4. Performance Profiling:**
```bash
# Profile with perf
perf record --call-graph=dwarf ./target/release/jester-jr config.toml
perf report

# Memory profiling with valgrind
valgrind --tool=massif ./target/release/jester-jr config.toml
```

---

## 🚀 Deployment & Configuration

### Production Configuration

**File: `production.toml`**
```toml
[global]
log_level = "info"
timeout_seconds = 30
# metrics_endpoint = "127.0.0.1:9090/metrics"  # Future feature

# ═══════════════════════════════════════════════════════════
# VALIDATOR REGISTRY
# ═══════════════════════════════════════════════════════════

# API Key validation for external services
[validators.api_key]
type = "builtin"
config = { 
    valid_keys = ["sk-prod-xxx", "sk-prod-yyy"],
    header_name = "x-api-key"
}

# JWT validation for user sessions
[validators.jwt_auth]
type = "builtin"
config = {
    secret = "${JWT_SECRET}",           # Environment variable
    issuer = "auth.yourcompany.com",
    audience = "api",
    algorithms = ["HS256"],
    required_claims = ["sub", "exp", "iat"]
}

# Rate limiting script
[validators.rate_limit]
type = "script"
path = "./validators/examples/rate_limiter.rhai"
timeout_seconds = 1
config = {
    max_requests_per_minute = 60,
    burst_limit = 10
}

# User database validation
[validators.user_db]
type = "wasm"
path = "./validators/user_db_validator.wasm"
timeout_seconds = 5
config = {
    user_service_url = "${USER_SERVICE_URL}",
    service_api_key = "${USER_SERVICE_API_KEY}",
    user_id_header = "x-user-id",
    required_status = "active",
    cache_ttl_seconds = 300
}

# File-based API key validation
[validators.file_api_keys]
type = "wasm"  
path = "./validators/simple_api_validator.wasm"
timeout_seconds = 2
config = {
    valid_keys = [
        "${API_KEY_1}",
        "${API_KEY_2}",
        "${API_KEY_3}"
    ],
    header_name = "authorization",
    case_sensitive = true
}

# ═══════════════════════════════════════════════════════════
# PRODUCTION LISTENERS
# ═══════════════════════════════════════════════════════════

# Public API (rate limited)
[listener."public-api"]
ip = "0.0.0.0"
port = 8080
default_action = "reject"

[[listener."public-api".routes]]
name = "health-check"
path_prefix = "/health"
backend = "127.0.0.1:3000"
# No validators - public endpoint

[[listener."public-api".routes]]
name = "public-endpoints"
path_prefix = "/api/public"
backend = "127.0.0.1:3000"
strip_prefix = true

[[listener."public-api".routes.validators]]
validator = "rate_limit"
on_failure = "deny"

# Partner API (API key required)
[listener."partner-api"]
ip = "0.0.0.0"
port = 8081
default_action = "reject"

[[listener."partner-api".routes]]
name = "partner-endpoints"
path_prefix = "/api/partner"
backend = "127.0.0.1:3001"
strip_prefix = true

[[listener."partner-api".routes.validators]]
validator = "file_api_keys"
on_failure = "deny"

[[listener."partner-api".routes.validators]]
validator = "rate_limit"
on_failure = "deny"

# User API (JWT + User DB validation)
[listener."user-api"]
ip = "0.0.0.0"
port = 8082
default_action = "reject"

[[listener."user-api".routes]]
name = "user-endpoints"
path_prefix = "/api/user"
backend = "127.0.0.1:3002"
strip_prefix = true

[[listener."user-api".routes.validators]]
validator = "jwt_auth"
on_failure = "deny"

[[listener."user-api".routes.validators]]
validator = "user_db"
on_failure = "deny"

# Admin API (Multiple validators)
[listener."admin-api"]
ip = "0.0.0.0"
port = 8083
default_action = "reject"

[[listener."admin-api".routes]]
name = "admin-endpoints"
path_prefix = "/api/admin"
backend = "127.0.0.1:3003"
strip_prefix = true

[[listener."admin-api".routes.validators]]
validator = "api_key"          # Admin API key
on_failure = "deny"

[[listener."admin-api".routes.validators]]
validator = "jwt_auth"         # Valid JWT
on_failure = "deny"

[[listener."admin-api".routes.validators]]
validator = "user_db"          # Active user in DB
on_failure = "deny"
```

### Environment Variables

**File: `.env`**
```bash
# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-here-make-it-long-and-random

# User Service Configuration  
USER_SERVICE_URL=http://user-service:3000
USER_SERVICE_API_KEY=service-key-production-123

# API Keys (rotate regularly)
API_KEY_1=sk-prod-partner-1-secure-key-2024
API_KEY_2=sk-prod-partner-2-secure-key-2024
API_KEY_3=sk-prod-internal-service-key-2024

# Monitoring (future)
METRICS_ENABLED=true
TRACING_ENDPOINT=http://jaeger:14268/api/traces
```

**Loading Environment Variables:**
```bash
# Load environment and start
export $(grep -v '^#' .env | xargs)
./target/release/jester-jr production.toml
```

### Security Best Practices

**🔒 Configuration Security:**
- Store secrets in environment variables, not config files
- Use different API keys for different environments
- Rotate keys regularly
- Limit validator timeouts to prevent DoS
- Review validator logs for suspicious activity

**🔒 WASM Security:**
- Validate all inputs in validators
- Use timeouts to prevent infinite loops  
- Limit memory usage
- Don't expose internal system information
- Sanitize data before logging

**🔒 Network Security:**
- Use TLS for all external validator calls
- Validate SSL certificates  
- Use VPCs/network isolation when possible
- Monitor external service dependencies
- Implement circuit breakers for external calls

### Monitoring & Observability

**Log Analysis:**
```bash
# Monitor validator performance
tail -f jester-jr.log | grep "validator_duration"

# Track validation failures
tail -f jester-jr.log | grep "validation_denied" | jq '.'

# Monitor specific validator
tail -f jester-jr.log | grep "validator_name=user_db"
```

**Metrics to Track:**
- Validator execution time
- Success/failure rates per validator
- Cache hit rates (for cached validators)
- External service response times
- Memory usage of WASM modules

**Health Checks:**
```bash
# Create validator health check endpoint
curl http://localhost:8080/health/validators
```

### Deployment Strategies

**Blue-Green Deployment:**
```bash
# Build new validators
cargo build --release --target wasm32-wasip1

# Test in staging environment
./target/release/jester-jr staging.toml

# Deploy to production (atomic replacement)
cp target/wasm32-wasip1/release/*.wasm /var/jester-jr/validators/
systemctl reload jester-jr  # Hot reload new validators
```

**Canary Deployment:**
```toml
# Route 10% of traffic to new validator version
[[listener."api".routes]]
name = "canary-test"
path_prefix = "/api/v2"
backend = "127.0.0.1:3000"

[[listener."api".routes.validators]]
validator = "new_validator_v2"
on_failure = "deny"
```

---

## 📚 Complete Examples

### Example 1: Simple Rate Limiter (Rhai)

This example shows how to implement basic rate limiting using Rhai scripts.

**File: `validators/examples/simple_rate_limiter.rhai`**
```rust
// Simple Rate Limiter
// Tracks requests per IP address and enforces limits
// Note: This is a simplified version - production rate limiters
// should use Redis or similar for shared state

fn validate(ctx) {
    // Configuration (in real world, parse from ctx.config_json)
    let max_requests_per_minute = 60;
    let burst_limit = 10;
    
    let client_ip = ctx.client_ip;
    let current_time = 1640995200; // Simulate current timestamp
    
    // Simulate rate limiting logic
    // In a real implementation, you'd need persistent storage
    
    // For demo purposes, implement simple rules:
    
    // 1. Block known bad IPs
    let blocked_ips = ["192.168.1.100", "10.0.0.5"];
    if blocked_ips.contains(client_ip) {
        return #{
            result: "deny",
            reason: "IP address is blocked",
            status_code: 429
        };
    }
    
    // 2. Different limits for different paths
    let path = ctx.path;
    let method = ctx.method;
    
    // Stricter limits for write operations
    if method == "POST" || method == "PUT" || method == "DELETE" {
        if path.contains("/admin") {
            // Admin operations: very strict
            return check_admin_rate_limit(ctx, client_ip);
        } else {
            // Regular write operations: moderate limits
            return check_write_rate_limit(ctx, client_ip);
        }
    }
    
    // Regular GET requests: generous limits
    return check_read_rate_limit(ctx, client_ip);
}

fn check_admin_rate_limit(ctx, client_ip) {
    // Admin operations: 5 requests per minute max
    
    // Simulate checking against a hypothetical rate limit store
    // In reality, you'd check Redis/database
    
    // For demo: block if IP contains certain patterns
    if client_ip.contains("192.168.2.") {
        return #{
            result: "deny",
            reason: "Admin rate limit exceeded (5/min)",
            status_code: 429
        };
    }
    
    return #{
        result: "allow_with_modification",
        add_headers: #{
            "x-rate-limit": "admin-tier",
            "x-rate-limit-remaining": "4"
        }
    };
}

fn check_write_rate_limit(ctx, client_ip) {
    // Write operations: 20 requests per minute
    
    let auth_header = ctx.headers.get("authorization");
    
    // Authenticated users get higher limits
    if auth_header != () {
        return #{
            result: "allow_with_modification",
            add_headers: #{
                "x-rate-limit": "authenticated-write",
                "x-rate-limit-remaining": "19"
            }
        };
    }
    
    // Unauthenticated users: stricter limits
    if client_ip.contains("192.168.3.") {
        return #{
            result: "deny",
            reason: "Write rate limit exceeded for unauthenticated user",
            status_code: 429
        };
    }
    
    return #{
        result: "allow_with_modification",
        add_headers: #{
            "x-rate-limit": "anonymous-write",
            "x-rate-limit-remaining": "9"
        }
    };
}

fn check_read_rate_limit(ctx, client_ip) {
    // Read operations: 100 requests per minute
    
    // Very generous - most requests should pass
    return #{
        result: "allow_with_modification",
        add_headers: #{
            "x-rate-limit": "read-operations",
            "x-rate-limit-remaining": "99",
            "x-rate-limit-window": "60s"
        }
    };
}
```

**Configuration:**
```toml
[validators.rate_limiter]
type = "script"
path = "./validators/examples/simple_rate_limiter.rhai"
timeout_seconds = 1

[listener."api"]
ip = "0.0.0.0"
port = 8080

[[listener."api".routes]]
name = "all-endpoints"
path_prefix = "/"
backend = "127.0.0.1:9090"

[[listener."api".routes.validators]]
validator = "rate_limiter"
on_failure = "deny"
```

### Example 2: Multi-Tenant Authorization (WASM)

This example shows a complex WASM validator that handles multi-tenant authorization with role-based access control.

**File: `examples/multi-tenant-auth/Cargo.toml`**
```toml
[package]
name = "multi-tenant-auth"
version = "0.1.0"
edition = "2024"

[workspace]

[lib]
crate-type = ["cdylib"]

[dependencies]
jester-jr-validator-sdk = { path = "../../validators/sdk" }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.22"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

**File: `examples/multi-tenant-auth/src/lib.rs`**
```rust
//! Multi-Tenant Authorization Validator
//!
//! This validator implements role-based access control across multiple tenants.
//! It extracts tenant and user information from JWT tokens and validates
//! permissions against a simulated permission database.

use jester_jr_validator_sdk::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Configuration for the multi-tenant validator
#[derive(Debug, Deserialize)]
struct Config {
    /// JWT secret for token verification
    jwt_secret: String,
    /// Default tenant if none specified
    default_tenant: Option<String>,
    /// Permission service endpoint
    permission_service_url: Option<String>,
    /// Cache TTL for permissions (seconds)
    cache_ttl: Option<u64>,
}

/// JWT claims structure
#[derive(Debug, Deserialize)]
struct JwtClaims {
    sub: String,                    // User ID
    tenant_id: Option<String>,      // Tenant ID
    roles: Vec<String>,             // User roles
    permissions: Option<Vec<String>>, // Direct permissions
    exp: u64,                       // Expiration
    iat: u64,                       // Issued at
}

/// Tenant configuration
#[derive(Debug, Clone)]
struct TenantConfig {
    id: String,
    name: String,
    allowed_roles: HashSet<String>,
    resource_permissions: HashMap<String, Vec<String>>,
}

/// Permission check result
#[derive(Debug)]
enum PermissionResult {
    Allowed { user_id: String, tenant_id: String, roles: Vec<String> },
    Denied { reason: String },
    Error { reason: String },
}

/// Main validator function
fn validate_multi_tenant(ctx: ValidationContext) -> ValidationResult {
    // Parse configuration
    let config: Config = match serde_json::from_value(ctx.config.clone()) {
        Ok(config) => config,
        Err(e) => {
            return ValidationResult::Deny {
                status_code: 500,
                reason: format!("Invalid validator configuration: {}", e),
            };
        }
    };

    // Extract JWT token
    let token = match extract_jwt_token(&ctx) {
        Some(token) => token,
        None => {
            return ValidationResult::Deny {
                status_code: 401,
                reason: "Missing or invalid Authorization header".to_string(),
            };
        }
    };

    // Verify and decode JWT
    let claims = match verify_jwt_token(&token, &config.jwt_secret) {
        Ok(claims) => claims,
        Err(e) => {
            return ValidationResult::Deny {
                status_code: 401,
                reason: format!("Invalid JWT token: {}", e),
            };
        }
    };

    // Extract tenant from claims or use default
    let tenant_id = claims.tenant_id
        .or_else(|| config.default_tenant.clone())
        .unwrap_or_else(|| "default".to_string());

    // Check permissions
    match check_permissions(&claims, &tenant_id, &ctx) {
        PermissionResult::Allowed { user_id, tenant_id, roles } => {
            // Add enrichment headers
            let mut add_headers = HashMap::new();
            add_headers.insert("X-User-ID".to_string(), user_id);
            add_headers.insert("X-Tenant-ID".to_string(), tenant_id);
            add_headers.insert("X-User-Roles".to_string(), roles.join(","));
            add_headers.insert("X-Validated-By".to_string(), "multi-tenant-auth".to_string());

            ValidationResult::AllowWithModification {
                add_headers,
                remove_headers: vec!["authorization".to_string()], // Remove for security
                rewrite_path: None,
                message: Some("Multi-tenant authorization successful".to_string()),
            }
        }
        PermissionResult::Denied { reason } => {
            ValidationResult::Deny {
                status_code: 403,
                reason,
            }
        }
        PermissionResult::Error { reason } => {
            ValidationResult::Deny {
                status_code: 500,
                reason,
            }
        }
    }
}

/// Extract JWT token from Authorization header
fn extract_jwt_token(ctx: &ValidationContext) -> Option<String> {
    let auth_header = ctx.headers.get("authorization")?;
    
    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        Some(token.trim().to_string())
    } else {
        None
    }
}

/// Verify JWT token and extract claims
fn verify_jwt_token(token: &str, secret: &str) -> Result<JwtClaims, String> {
    // Simple JWT verification (in production, use a proper JWT library)
    
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    // Decode payload (skip signature verification for demo)
    let payload = parts[1];
    let decoded = base64::decode_config(payload, base64::URL_SAFE_NO_PAD)
        .map_err(|_| "Failed to decode JWT payload")?;
    
    let claims: JwtClaims = serde_json::from_slice(&decoded)
        .map_err(|_| "Failed to parse JWT claims")?;

    // Basic expiration check
    let current_time = 1640995200; // Simulate current timestamp
    if claims.exp < current_time {
        return Err("Token has expired".to_string());
    }

    Ok(claims)
}

/// Check if user has permission for the requested resource
fn check_permissions(
    claims: &JwtClaims,
    tenant_id: &str,
    ctx: &ValidationContext,
) -> PermissionResult {
    // Load tenant configuration
    let tenant_config = match load_tenant_config(tenant_id) {
        Ok(config) => config,
        Err(e) => {
            return PermissionResult::Error {
                reason: format!("Failed to load tenant config: {}", e),
            };
        }
    };

    // Check if user has any valid roles for this tenant
    let user_roles: HashSet<String> = claims.roles.iter().cloned().collect();
    let allowed_roles = &tenant_config.allowed_roles;
    
    if user_roles.is_disjoint(allowed_roles) {
        return PermissionResult::Denied {
            reason: format!(
                "User roles {:?} not allowed for tenant {}",
                claims.roles, tenant_id
            ),
        };
    }

    // Check resource-specific permissions
    let resource_path = extract_resource_path(&ctx.path);
    let required_permission = format!("{}:{}", ctx.method.to_lowercase(), resource_path);

    if let Some(allowed_permissions) = tenant_config.resource_permissions.get(&resource_path) {
        // Check if user's roles grant the required permission
        let has_permission = claims.roles.iter().any(|role| {
            allowed_permissions.iter().any(|perm| {
                perm == &required_permission || perm == "*" || perm.ends_with(":*")
            })
        });

        if !has_permission {
            return PermissionResult::Denied {
                reason: format!(
                    "User lacks permission '{}' for resource '{}'",
                    required_permission, resource_path
                ),
            };
        }
    }

    PermissionResult::Allowed {
        user_id: claims.sub.clone(),
        tenant_id: tenant_id.to_string(),
        roles: claims.roles.clone(),
    }
}

/// Load tenant configuration (simulated database lookup)
fn load_tenant_config(tenant_id: &str) -> Result<TenantConfig, String> {
    // Simulate tenant configurations
    match tenant_id {
        "acme-corp" => {
            let mut resource_permissions = HashMap::new();
            resource_permissions.insert(
                "users".to_string(),
                vec!["get:users".to_string(), "post:users".to_string()]
            );
            resource_permissions.insert(
                "admin".to_string(),
                vec!["*".to_string()] // Admin access to everything
            );

            Ok(TenantConfig {
                id: "acme-corp".to_string(),
                name: "ACME Corporation".to_string(),
                allowed_roles: ["user", "admin", "manager"].iter().map(|s| s.to_string()).collect(),
                resource_permissions,
            })
        }
        "startups-inc" => {
            let mut resource_permissions = HashMap::new();
            resource_permissions.insert(
                "users".to_string(),
                vec!["get:users".to_string()]
            );

            Ok(TenantConfig {
                id: "startups-inc".to_string(),
                name: "Startups Inc".to_string(),
                allowed_roles: ["user"].iter().map(|s| s.to_string()).collect(),
                resource_permissions,
            })
        }
        "default" => {
            let mut resource_permissions = HashMap::new();
            resource_permissions.insert(
                "public".to_string(),
                vec!["get:public".to_string()]
            );

            Ok(TenantConfig {
                id: "default".to_string(),
                name: "Default Tenant".to_string(),
                allowed_roles: ["guest"].iter().map(|s| s.to_string()).collect(),
                resource_permissions,
            })
        }
        _ => Err(format!("Unknown tenant: {}", tenant_id)),
    }
}

/// Extract resource name from request path
fn extract_resource_path(path: &str) -> String {
    // Extract resource from path like "/api/v1/users/123" -> "users"
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    
    // Skip common prefixes
    let resource_part = parts.iter()
        .skip_while(|&&part| part == "api" || part.starts_with('v'))
        .next()
        .unwrap_or(&"unknown");
    
    resource_part.to_string()
}

// Export the validator
define_validator!(validate_multi_tenant);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_extract_resource_path() {
        assert_eq!(extract_resource_path("/api/v1/users"), "users");
        assert_eq!(extract_resource_path("/api/v2/admin/settings"), "admin");
        assert_eq!(extract_resource_path("/users/123"), "users");
        assert_eq!(extract_resource_path("/unknown/path"), "unknown");
    }

    #[test]
    fn test_tenant_config_loading() {
        let config = load_tenant_config("acme-corp").unwrap();
        assert_eq!(config.id, "acme-corp");
        assert!(config.allowed_roles.contains("admin"));
    }
}
```

**Configuration:**
```toml
[validators.multi_tenant]
type = "wasm"
path = "./validators/multi_tenant_auth.wasm"
timeout_seconds = 5
config = {
    jwt_secret = "your-super-secret-jwt-key",
    default_tenant = "default",
    cache_ttl = 300
}

# Different APIs for different tenants
[listener."tenant-api"]
ip = "0.0.0.0"
port = 8080

[[listener."tenant-api".routes]]
name = "user-management"
path_prefix = "/api/v1/users"
backend = "127.0.0.1:3000"

[[listener."tenant-api".routes.validators]]
validator = "multi_tenant"
on_failure = "deny"

[[listener."tenant-api".routes]]
name = "admin-panel"
path_prefix = "/api/v1/admin"
backend = "127.0.0.1:3001"

[[listener."tenant-api".routes.validators]]
validator = "multi_tenant"
on_failure = "deny"
```

**Test Script:**
```bash
#!/bin/bash

# Generate test JWT tokens (use a proper JWT library in production)
echo "Testing multi-tenant authorization..."

# Test 1: Valid admin user for ACME Corp
jwt_admin="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwidGVuYW50X2lkIjoiYWNtZS1jb3JwIiwicm9sZXMiOlsiYWRtaW4iXSwiZXhwIjoxNjQwOTk1MjAwfQ.signature"

echo "✅ Admin user accessing users endpoint:"
curl -H "Authorization: Bearer $jwt_admin" http://localhost:8080/api/v1/users

# Test 2: Regular user trying to access admin endpoint
jwt_user="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyNDU2IiwidGVuYW50X2lkIjoic3RhcnR1cHMtaW5jIiwicm9sZXMiOlsidXNlciJdLCJleHAiOjE2NDA5OTUyMDB9.signature"

echo "❌ Regular user trying to access admin endpoint:"
curl -w "Status: %{http_code}\n" -H "Authorization: Bearer $jwt_user" http://localhost:8080/api/v1/admin

echo "Tests completed!"
```

### Example 3: External Service Integration

This shows how to integrate with external services like databases, APIs, or smart contracts.

**File: `validators/examples/external_service_check.rhai`**
```rust
// External Service Integration Example
// This demonstrates how to structure validators that would
// call external services (simulated here)

fn validate(ctx) {
    let api_key = ctx.headers.get("x-api-key");
    
    if api_key == () {
        return #{
            result: "deny",
            reason: "Missing API key",
            status_code: 401
        };
    }
    
    // Simulate external service calls
    // In WASM validators, you can make real HTTP requests
    
    // 1. Check API key against user database
    let user_info = check_user_database(api_key);
    if user_info.error != () {
        return #{
            result: "deny",
            reason: user_info.error,
            status_code: 403
        };
    }
    
    // 2. Check rate limits in Redis
    let rate_limit_info = check_rate_limits(user_info.user_id, ctx.client_ip);
    if rate_limit_info.exceeded {
        return #{
            result: "deny",
            reason: "Rate limit exceeded",
            status_code: 429
        };
    }
    
    // 3. Check permissions for specific resource
    let resource = extract_resource_from_path(ctx.path);
    let permission_check = check_permissions(user_info.user_id, resource, ctx.method);
    if !permission_check.allowed {
        return #{
            result: "deny", 
            reason: permission_check.reason,
            status_code: 403
        };
    }
    
    // All checks passed - allow with enrichment
    return #{
        result: "allow_with_modification",
        add_headers: #{
            "x-user-id": user_info.user_id,
            "x-user-tier": user_info.tier,
            "x-rate-limit-remaining": rate_limit_info.remaining.to_string(),
            "x-permissions": permission_check.permissions.join(",")
        }
    };
}

// Simulated external service calls
// In WASM, these would be real HTTP requests

fn check_user_database(api_key) {
    // Simulate database lookup
    if api_key == "sk-valid-user-123" {
        return #{
            user_id: "user-123",
            tier: "premium",
            status: "active",
            error: ()
        };
    } else if api_key == "sk-valid-user-456" {
        return #{
            user_id: "user-456", 
            tier: "basic",
            status: "active",
            error: ()
        };
    } else {
        return #{
            error: "Invalid API key"
        };
    }
}

fn check_rate_limits(user_id, client_ip) {
    // Simulate Redis rate limit check
    // Different limits based on user tier
    
    if user_id == "user-123" {  // Premium user
        return #{
            exceeded: false,
            remaining: 1000,
            window: "3600"
        };
    } else if user_id == "user-456" {  // Basic user  
        return #{
            exceeded: false,
            remaining: 100,
            window: "3600"
        };
    } else {
        return #{
            exceeded: true,
            remaining: 0,
            window: "3600"
        };
    }
}

fn check_permissions(user_id, resource, method) {
    // Simulate permission service call
    
    let user_permissions = get_user_permissions(user_id);
    let required_permission = method.to_lower() + ":" + resource;
    
    if user_permissions.contains(required_permission) || user_permissions.contains("*") {
        return #{
            allowed: true,
            permissions: user_permissions
        };
    } else {
        return #{
            allowed: false,
            reason: `No permission for ${required_permission}`,
            permissions: []
        };
    }
}

fn get_user_permissions(user_id) {
    if user_id == "user-123" {  // Premium user - more permissions
        return ["get:users", "post:users", "get:reports", "post:reports"];
    } else if user_id == "user-456" {  // Basic user - limited permissions
        return ["get:users"];
    } else {
        return [];
    }
}

fn extract_resource_from_path(path) {
    // Extract resource name from path
    let parts = path.split("/");
    
    // Find the resource part (skip /api/v1 etc.)
    for part in parts {
        if part != "" && part != "api" && !part.starts_with("v") {
            return part;
        }
    }
    
    return "unknown";
}
```

---

## 🐛 Troubleshooting

### Common Issues and Solutions

#### 1. WASM Compilation Errors

**Error:** `rust-lld: error: duplicate symbol: free`
```bash
# Solution: Rename allocation functions in SDK
# This was fixed in the SDK, but if you encounter similar issues:

# Check your allocation functions don't conflict with libc
grep -r "free\|alloc" validators/sdk/src/
```

**Error:** `wasm32-wasip1 target not found`
```bash
# Solution: Install the WASM target
rustup target add wasm32-wasip1

# Verify installation
rustup target list | grep wasm
```

**Error:** `failed to resolve: use of undeclared crate or module`
```bash
# Solution: Check dependencies in Cargo.toml
[dependencies]
jester-jr-validator-sdk = { path = "../../validators/sdk" }

# Ensure the path is correct relative to your validator project
```

#### 2. Rhai Script Errors

**Error:** Script compilation fails
```rust
// Check syntax - Rhai is strict about syntax
fn validate(ctx) {  // ✅ Correct
    return #{ result: "allow" };
}

fn validate(ctx)   // ❌ Missing opening brace
    return #{ result: "allow" };
}
```

**Error:** `Function 'validate' not found`
```rust
// Solution: Ensure your function is named exactly 'validate'
fn validate(ctx) {  // ✅ Correct name
    // ...
}

fn validation(ctx) {  // ❌ Wrong name
    // ...
}
```

**Error:** Headers not accessible
```rust
// Check header access pattern
let api_key = ctx.headers.get("x-api-key");  // ✅ Correct

if api_key == () {  // ✅ Correct null check
    // Header doesn't exist
}

if api_key == null {  // ❌ Use () not null
    // This won't work in Rhai
}
```

#### 3. Configuration Issues

**Error:** Validator not loading
```bash
# Check Jester Jr logs
RUST_LOG=debug ./target/release/jester-jr config.toml 2>&1 | grep validator

# Common issues:
# 1. Wrong file path
# 2. Missing config section
# 3. Invalid TOML syntax
```

**Error:** Configuration parsing fails
```toml
# ✅ Correct configuration
[validators.my_validator]
type = "wasm"
path = "./validators/my_validator.wasm"
config = { key = "value" }

# ❌ Missing quotes
[validators.my_validator]
type = wasm  # Missing quotes
path = ./validators/my_validator.wasm  # Missing quotes
```

#### 4. Runtime Errors

**Error:** Validator timeout
```toml
# Solution: Increase timeout or optimize validator
[validators.slow_validator]
type = "wasm"
path = "./validators/slow_validator.wasm"
timeout_seconds = 10  # Increase from default 5
```

**Error:** Memory allocation issues
```rust
// Solution: Optimize memory usage in WASM validators
fn validate_optimized(ctx: ValidationContext) -> ValidationResult {
    // Reuse allocations where possible
    let mut headers = HashMap::with_capacity(ctx.headers.len());
    
    // Use string slicing instead of cloning
    let path = ctx.path.trim_start_matches('/');
    
    // Early returns to avoid unnecessary processing
    if path.is_empty() {
        return ValidationResult::Deny {
            status_code: 400,
            reason: "Empty path".to_string(),
        };
    }
    
    // ... rest of validation
}
```

### Debugging Techniques

#### 1. Enable Debug Logging
```bash
# Full debug logging
RUST_LOG=debug ./target/release/jester-jr config.toml

# Validator-specific logging
RUST_LOG=jester_jr::validators=debug ./target/release/jester-jr config.toml

# Include line numbers and modules
RUST_LOG=jester_jr::validators=debug,jester_jr::validators::wasm=trace ./target/release/jester-jr config.toml
```

#### 2. Add Debug Output to Validators
```rust
// In WASM validators
fn validate_with_debug(ctx: ValidationContext) -> ValidationResult {
    // Log important information (will appear in Jester Jr logs)
    eprintln!("DEBUG: Validator called for path: {}", ctx.path);
    eprintln!("DEBUG: Headers: {:?}", ctx.headers);
    
    let result = do_validation(ctx);
    
    eprintln!("DEBUG: Validation result: {:?}", result);
    
    result
}
```

```rust
// In Rhai scripts (use print for debugging)
fn validate(ctx) {
    print(`Validating request to: ${ctx.path}`);
    print(`Client IP: ${ctx.client_ip}`);
    
    // ... validation logic
    
    let result = #{ result: "allow" };
    print(`Result: ${result.result}`);
    
    return result;
}
```

#### 3. Test Validators in Isolation
```bash
# Create minimal test config
cat > test-validator.toml << EOF
[validators.test]
type = "wasm"
path = "./validators/my_validator.wasm"

[listener."test"]
ip = "127.0.0.1"
port = 8080

[[listener."test".routes]]
name = "test-route"
path_prefix = "/"
backend = "127.0.0.1:9090"

[[listener."test".routes.validators]]
validator = "test"
on_failure = "deny"
EOF

# Start simple backend
python3 -c "
import http.server, socketserver
with socketserver.TCPServer(('', 9090), http.server.BaseHTTPRequestHandler) as httpd:
    httpd.serve_forever()
" &

# Test validator
./target/release/jester-jr test-validator.toml
```

### Performance Troubleshooting

#### 1. Measure Validator Performance
```bash
# Add timing logs to see slow validators
RUST_LOG=info ./target/release/jester-jr config.toml 2>&1 | grep "validator_duration"
```

#### 2. Profile WASM Validators
```bash
# Analyze WASM binary size
twiggy top validators/my_validator.wasm

# Find the largest functions
twiggy dominators validators/my_validator.wasm
```

#### 3. Optimize Based on Metrics
```rust
// Optimize hot paths in validators
fn optimized_validation(ctx: ValidationContext) -> ValidationResult {
    // Cache expensive operations
    static mut CACHED_CONFIG: Option<ParsedConfig> = None;
    
    let config = unsafe {
        if CACHED_CONFIG.is_none() {
            CACHED_CONFIG = Some(parse_config(&ctx.config));
        }
        CACHED_CONFIG.as_ref().unwrap()
    };
    
    // Fast path for common cases
    if ctx.method == "GET" && ctx.path.starts_with("/health") {
        return ValidationResult::Allow;
    }
    
    // ... more validation logic
}
```

---

## ⚡ Performance Guide

### Performance Characteristics

| Validator Type | Startup Time | Runtime Overhead | Memory Usage | Best For |
|----------------|--------------|------------------|--------------|----------|
| **Built-in** | ~0ms | <0.1ms | Low | Simple, high-frequency checks |
| **Rhai Script** | ~1ms | 0.3-0.8ms | Low-Medium | Dynamic rules, moderate complexity |
| **WASM** | ~5ms | 0.5-2ms | Medium | Complex logic, external calls |
| **Dynamic Lib** | ~1ms | <0.1ms | Low | Performance-critical algorithms |

### Optimization Strategies

#### 1. Choose the Right Validator Type
```rust
// ✅ Use built-in for simple checks
[validators.simple_api_key]
type = "builtin"
config = { valid_keys = ["key1", "key2"] }

// ✅ Use Rhai for simple business logic
[validators.business_rules]
type = "script"
path = "./validators/business_rules.rhai"

// ✅ Use WASM for complex operations
[validators.external_auth]
type = "wasm"
path = "./validators/external_auth.wasm"
```

#### 2. Optimize WASM Validators

**Binary Size Optimization:**
```toml
[profile.release]
opt-level = "z"        # Optimize for size
lto = true             # Link-time optimization
codegen-units = 1      # Better optimization
panic = "abort"        # Smaller binary
strip = true           # Remove debug symbols
```

**Memory Optimization:**
```rust
// Minimize allocations
fn efficient_validator(ctx: ValidationContext) -> ValidationResult {
    // Use &str instead of String where possible
    let path = ctx.path.as_str();
    
    // Reuse collections
    let mut headers = HashMap::with_capacity(ctx.headers.len());
    
    // Early returns
    if path.is_empty() {
        return ValidationResult::Deny {
            status_code: 400,
            reason: "Invalid path".to_string(),
        };
    }
    
    // Batch operations
    let (valid_key, user_id) = match validate_and_extract(&ctx) {
        Some(result) => result,
        None => return ValidationResult::Deny {
            status_code: 401,
            reason: "Invalid credentials".to_string(),
        },
    };
    
    ValidationResult::Allow
}
```

#### 3. Optimize Rhai Scripts

```rust
// ✅ Efficient Rhai patterns
fn validate(ctx) {
    // Cache expensive operations at top level
    let valid_keys = ["key1", "key2", "key3"];
    let admin_paths = ["/admin", "/manage"];
    
    let path = ctx.path;
    let method = ctx.method;
    
    // Use early returns
    if method == "OPTIONS" {
        return #{ result: "allow" };
    }
    
    // Use efficient lookups
    let is_admin_path = admin_paths.any(|prefix| path.starts_with(prefix));
    if is_admin_path {
        return check_admin_access(ctx);
    }
    
    // Regular validation
    return check_regular_access(ctx);
}

fn check_admin_access(ctx) {
    // Specialized admin validation
    let admin_key = ctx.headers.get("x-admin-key");
    return if admin_key == "admin-secret" {
        #{ result: "allow" }
    } else {
        #{ result: "deny", reason: "Admin access required", status_code: 403 }
    };
}
```

### Caching Strategies

#### 1. Validator-Level Caching
```rust
// Cache configuration parsing
use std::sync::OnceLock;

static PARSED_CONFIG: OnceLock<ParsedConfig> = OnceLock::new();

fn get_config(raw_config: &serde_json::Value) -> &ParsedConfig {
    PARSED_CONFIG.get_or_init(|| {
        parse_config(raw_config)
    })
}
```

#### 2. External Service Caching
```rust
// Cache external API responses
use std::collections::HashMap;
use std::time::{Duration, Instant};

struct CacheEntry<T> {
    data: T,
    expires_at: Instant,
}

static mut USER_CACHE: Option<HashMap<String, CacheEntry<UserInfo>>> = None;

fn get_user_info_cached(user_id: &str) -> Result<UserInfo, String> {
    let cache = unsafe { USER_CACHE.get_or_insert_with(HashMap::new) };
    
    // Check cache first
    if let Some(entry) = cache.get(user_id) {
        if Instant::now() < entry.expires_at {
            return Ok(entry.data.clone());
        }
        // Entry expired, remove it
        cache.remove(user_id);
    }
    
    // Fetch from external service
    let user_info = fetch_user_from_service(user_id)?;
    
    // Cache the result
    cache.insert(user_id.to_string(), CacheEntry {
        data: user_info.clone(),
        expires_at: Instant::now() + Duration::from_secs(300), // 5 min TTL
    });
    
    Ok(user_info)
}
```

### Monitoring Performance

#### 1. Built-in Metrics
```bash
# Monitor validator performance
tail -f jester-jr.log | grep "validator_duration" | jq '.'

# Example output:
# {
#   "timestamp": "2024-01-01T12:00:00Z",
#   "level": "INFO", 
#   "validator_name": "user_auth",
#   "validator_duration_ms": 1.2,
#   "result": "allow"
# }
```

#### 2. Custom Metrics in Validators
```rust
fn validate_with_metrics(ctx: ValidationContext) -> ValidationResult {
    let start = std::time::Instant::now();
    
    let result = do_validation(ctx);
    
    let duration = start.elapsed();
    eprintln!("METRIC: validation_duration_ms={}", duration.as_millis());
    
    result
}
```

#### 3. Load Testing
```bash
# Simple load test script
#!/bin/bash

echo "🚀 Load testing validators..."

# Start Jester Jr
./target/release/jester-jr config.toml &
PROXY_PID=$!
sleep 2

# Run concurrent requests
for i in {1..100}; do
    curl -s -H "X-API-Key: test-key" http://localhost:8080/api/test &
done

wait

# Check performance logs
echo "📊 Performance Summary:"
tail -n 100 jester-jr.log | grep "validator_duration" | \
jq -r '.validator_duration_ms' | \
awk '{
    sum += $1; 
    count++; 
    if($1 > max) max = $1; 
    if(min == 0 || $1 < min) min = $1
} 
END {
    print "Average: " sum/count "ms"
    print "Min: " min "ms" 
    print "Max: " max "ms"
}'

kill $PROXY_PID
```

### Production Recommendations

1. **Validator Ordering**: Put fastest validators first to fail fast
2. **Timeouts**: Set appropriate timeouts based on validator complexity
3. **Caching**: Implement caching for expensive operations
4. **Monitoring**: Track validator performance and failure rates
5. **Circuit Breakers**: Implement fallback behavior for external services
6. **Resource Limits**: Monitor memory and CPU usage of WASM validators

This completes the comprehensive HOWTO guide for creating Jester Jr extensions. The guide covers everything from basic concepts to advanced optimization techniques, providing developers with the knowledge needed to create efficient and reliable validators.