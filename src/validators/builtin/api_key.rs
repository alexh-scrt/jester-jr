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