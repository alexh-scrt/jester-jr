//! Core validator traits and interfaces
//!
//! This module defines the fundamental abstractions for the validator framework.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

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
        ctx: &super::ValidationContext,
    ) -> Result<super::ValidationResult, super::ValidationError>;

    /// Get validator name (for logging and debugging)
    #[allow(dead_code)]
    fn name(&self) -> &str;

    /// Get validator version
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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