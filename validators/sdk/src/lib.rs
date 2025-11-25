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
#[unsafe(no_mangle)]
pub extern "C" fn validator_alloc(len: i32) -> *mut u8 {
    let mut buf = Vec::with_capacity(len as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Memory deallocation function (exported to host)
#[unsafe(no_mangle)]
pub extern "C" fn validator_free(ptr: i32, len: i32) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr as *mut u8, len as usize, len as usize);
    }
}

/// Helper macro to define a validator
#[macro_export]
macro_rules! define_validator {
    ($validate_fn:ident) => {
        #[unsafe(no_mangle)]
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
            let result_ptr = $crate::validator_alloc(total_len as i32);

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