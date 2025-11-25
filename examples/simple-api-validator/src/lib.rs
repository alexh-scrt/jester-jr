//! Simple API Key Validator (WASM)
//!
//! This validator checks if the X-API-Key header contains a valid key

use jester_jr_validator_sdk::*;
use serde_json::Value;
use std::collections::HashMap;

fn validate_api_key(ctx: ValidationContext) -> ValidationResult {
    // Parse config to get valid keys
    let valid_keys: Vec<String> = match ctx.config.get("valid_keys") {
        Some(Value::Array(keys)) => {
            keys.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        }
        _ => {
            return ValidationResult::Deny {
                status_code: 500,
                reason: "Invalid validator configuration".to_string(),
            };
        }
    };

    // Get API key from headers
    let api_key = match ctx.headers.get("x-api-key") {
        Some(key) => key,
        None => {
            return ValidationResult::Deny {
                status_code: 401,
                reason: "Missing X-API-Key header".to_string(),
            };
        }
    };

    // Check if key is valid
    if valid_keys.contains(api_key) {
        // Add user info header
        let mut add_headers = HashMap::new();
        add_headers.insert("X-Validated-By".to_string(), "wasm-validator".to_string());

        ValidationResult::AllowWithModification {
            add_headers,
            remove_headers: vec![],
            rewrite_path: None,
            message: Some("API key validated by WASM".to_string()),
        }
    } else {
        ValidationResult::Deny {
            status_code: 403,
            reason: "Invalid API key".to_string(),
        }
    }
}

// Define the validator using the SDK macro
define_validator!(validate_api_key);