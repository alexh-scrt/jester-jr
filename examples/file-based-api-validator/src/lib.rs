//! File-Based API Key Validator (WASM)
//!
//! This validator checks API keys against a master list loaded from master_keys.txt
//! The keys are passed through the configuration at startup.
//!
//! Configuration format:
//! ```toml
//! [validators.file_api_key]
//! type = "wasm"
//! path = "./validators/simple_api_validator.wasm"
//! config = {
//!     valid_keys = ["key1", "key2", "key3"],  # Loaded from master_keys.txt
//!     header_name = "x-api-key",              # Optional: default is "x-api-key"
//!     case_sensitive = true                   # Optional: default is true
//! }
//! ```

use jester_jr_validator_sdk::*;
use serde_json::Value;
use std::collections::HashMap;

/// Validate API key against master keys list
fn validate_file_based_api_key(ctx: ValidationContext) -> ValidationResult {
    // Parse configuration
    let config = &ctx.config;
    
    // Extract valid keys from config
    let valid_keys: Vec<String> = match config.get("valid_keys") {
        Some(Value::Array(keys)) => {
            keys.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        }
        Some(Value::String(single_key)) => {
            vec![single_key.clone()]
        }
        _ => {
            return ValidationResult::Deny {
                status_code: 500,
                reason: "Validator misconfigured: missing 'valid_keys' in config".to_string(),
            };
        }
    };

    if valid_keys.is_empty() {
        return ValidationResult::Deny {
            status_code: 500,
            reason: "Validator misconfigured: no valid keys provided".to_string(),
        };
    }

    // Get header name (default to "x-api-key")
    let header_name = config
        .get("header_name")
        .and_then(|v| v.as_str())
        .unwrap_or("x-api-key")
        .to_lowercase();

    // Get case sensitivity setting (default to true)
    let case_sensitive = config
        .get("case_sensitive")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // Extract API key from headers
    let api_key = match ctx.headers.get(&header_name) {
        Some(key) => key,
        None => {
            return ValidationResult::Deny {
                status_code: 401,
                reason: format!("Missing required header: {}", header_name),
            };
        }
    };

    // Validate the API key
    let key_valid = if case_sensitive {
        valid_keys.contains(api_key)
    } else {
        let api_key_lower = api_key.to_lowercase();
        valid_keys.iter().any(|k| k.to_lowercase() == api_key_lower)
    };

    if key_valid {
        // API key is valid - add tracking headers and allow
        let mut add_headers = HashMap::new();
        add_headers.insert("X-Validated-By".to_string(), "file-based-wasm-validator".to_string());
        add_headers.insert("X-API-Key-Valid".to_string(), "true".to_string());
        
        // Optionally add a hash of the API key for logging (first 8 chars for security)
        let key_prefix = if api_key.len() > 8 {
            format!("{}***", &api_key[..8])
        } else {
            "***".to_string()
        };
        add_headers.insert("X-API-Key-Prefix".to_string(), key_prefix);

        ValidationResult::AllowWithModification {
            add_headers,
            remove_headers: vec![],
            rewrite_path: None,
            message: Some(format!(
                "API key validated from master_keys.txt ({} keys checked)",
                valid_keys.len()
            )),
        }
    } else {
        ValidationResult::Deny {
            status_code: 403,
            reason: "Invalid API key".to_string(),
        }
    }
}

// Export the validator using the SDK macro
define_validator!(validate_file_based_api_key);