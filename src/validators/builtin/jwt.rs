//! JWT (JSON Web Token) validator

use crate::validators::*;
use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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