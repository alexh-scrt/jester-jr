//! Jester-Secret validator with IP blacklisting

use crate::validators::*;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;
use tracing::{debug, warn};

/// Jester-Secret validator configuration
#[derive(Debug, Clone, Deserialize)]
struct JesterSecretConfig {
    /// Valid secret keys
    valid_keys: HashSet<String>,

    /// Header name containing secret key (default: jester-secret)
    #[serde(default = "default_header_name")]
    header_name: String,

    /// TTL in hours for blacklist entries (default: 24 hours)
    #[serde(default = "default_blacklist_ttl_hours")]
    blacklist_ttl_hours: u32,
}

fn default_header_name() -> String {
    "jester-secret".to_string()
}

fn default_blacklist_ttl_hours() -> u32 {
    24 // 24 hours default
}

/// Jester-Secret validator that blacklists IPs on missing/invalid secrets
pub struct JesterSecretValidator {
    config: Option<JesterSecretConfig>,
}

impl JesterSecretValidator {
    pub fn new() -> Self {
        Self { config: None }
    }
}

#[async_trait]
impl Validator for JesterSecretValidator {
    async fn validate(
        &self,
        ctx: &ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        let config = self.config.as_ref()
            .ok_or_else(|| ValidationError::ConfigError("Jester-Secret validator not initialized".to_string()))?;

        // Extract client IP for potential blacklisting
        let client_ip = ctx.client_ip;

        // Get secret from header
        let secret = match ctx.get_header(&config.header_name) {
            Some(key) => key,
            None => {
                warn!("🚫 Missing {} header from IP {}", config.header_name, client_ip);
                return Ok(ValidationResult::BlacklistIP {
                    ip: client_ip,
                    status_code: 401,
                    reason: format!("Missing {} header", "*** secret ***"),
                    log_level: LogLevel::Warn,
                    ttl_hours: Some(config.blacklist_ttl_hours),
                    internal_message: Some(format!("IP {} blacklisted for missing secret header", client_ip)),
                });
            }
        };

        // Check if secret is valid
        if config.valid_keys.contains(secret) {
            debug!("✅ Valid Jester-Secret from IP {}", client_ip);
            Ok(ValidationResult::Allow)
        } else {
            warn!("🚫 Invalid Jester-Secret from IP {}: {}", client_ip, secret);
            Ok(ValidationResult::BlacklistIP {
                ip: client_ip,
                status_code: 403,
                reason: "Invalid Jester-Secret".to_string(),
                log_level: LogLevel::Warn,
                ttl_hours: Some(config.blacklist_ttl_hours),
                internal_message: Some(format!("IP {} blacklisted for invalid secret: {}", client_ip, secret)),
            })
        }
    }

    fn name(&self) -> &str {
        "jester_secret"
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
                .map_err(|e| format!("Invalid Jester-Secret config: {}", e))?
        );

        let config = self.config.as_ref().unwrap();
        
        // Validate configuration
        if config.valid_keys.is_empty() {
            return Err("Jester-Secret validator requires at least one valid key".to_string());
        }

        if config.blacklist_ttl_hours == 0 {
            return Err("Blacklist TTL must be greater than 0".to_string());
        }

        debug!("Initialized Jester-Secret validator with {} valid keys, TTL: {}h", 
               config.valid_keys.len(), config.blacklist_ttl_hours);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::collections::HashMap;

    fn create_test_validator() -> JesterSecretValidator {
        let mut validator = JesterSecretValidator::new();
        let config = serde_json::json!({
            "valid_keys": ["test-secret-123", "another-key"],
            "header_name": "jester-secret",
            "blacklist_ttl_hours": 2
        });
        validator.initialize(&config).unwrap();
        validator
    }

    fn create_test_context(headers: HashMap<String, String>, ip: IpAddr) -> ValidationContext {
        use crate::validators::ValidatorState;
        use std::sync::Arc;
        
        ValidationContext {
            method: "GET".to_string(),
            path: "/test".to_string(),
            version: "HTTP/1.1".to_string(),
            headers,
            client_ip: ip,
            listener_name: "test".to_string(),
            route_name: None,
            config: serde_json::Value::Null,
            state: Arc::new(ValidatorState::new()),
        }
    }

    #[tokio::test]
    async fn test_valid_secret() {
        let validator = create_test_validator();
        let mut headers = HashMap::new();
        headers.insert("jester-secret".to_string(), "test-secret-123".to_string());
        
        let ctx = create_test_context(headers, Ipv4Addr::new(192, 168, 1, 100).into());
        let result = validator.validate(&ctx).await.unwrap();
        
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_invalid_secret() {
        let validator = create_test_validator();
        let mut headers = HashMap::new();
        headers.insert("jester-secret".to_string(), "wrong-secret".to_string());
        
        let test_ip = Ipv4Addr::new(192, 168, 1, 100).into();
        let ctx = create_test_context(headers, test_ip);
        let result = validator.validate(&ctx).await.unwrap();
        
        assert!(result.should_blacklist_ip());
        assert_eq!(result.get_blacklist_ip().unwrap(), test_ip);
    }

    #[tokio::test]
    async fn test_missing_secret() {
        let validator = create_test_validator();
        let headers = HashMap::new(); // No jester-secret header
        
        let test_ip = Ipv4Addr::new(10, 0, 0, 1).into();
        let ctx = create_test_context(headers, test_ip);
        let result = validator.validate(&ctx).await.unwrap();
        
        assert!(result.should_blacklist_ip());
        assert_eq!(result.get_blacklist_ip().unwrap(), test_ip);
    }

}