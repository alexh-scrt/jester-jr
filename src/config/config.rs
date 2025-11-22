//! Configuration structures and rule compilation for Jester Jr.
//!
//! This module provides the core configuration types used to configure the proxy
//! server and define filtering rules. It handles TOML deserialization and compiles
//! filtering rules with regex patterns for efficient runtime evaluation.
//!
//! ## New in v0.2.0: TLS Configuration
//! Added optional TLS settings for HTTPS support.
//!
//! ## Author
//! a13x.h.cc@gmail.com

use serde::Deserialize;
use regex::Regex;
use std::fs;
use std::path::Path;

/// Main configuration structure
#[derive(Debug, Deserialize)]
pub struct Config {
    pub proxy: ProxySettings,
    #[serde(default)]
    pub tls: Option<TlsSettings>,  // NEW: Optional TLS configuration
    #[serde(default)]
    pub request_rules: Vec<RequestRule>,
    #[serde(default)]
    pub response_rules: Vec<ResponseRule>,
}

/// Proxy server settings
#[derive(Debug, Deserialize)]
pub struct ProxySettings {
    pub listen_address: String,
    pub backend_address: String,
    pub timeout_seconds: u64,
}

/// TLS/SSL settings (new in v0.2.0)
///
/// Configuration for enabling HTTPS support with certificate-based encryption.
///
/// # Example TOML
/// ```toml
/// [tls]
/// enabled = true
/// cert_file = "./certs/cert.pem"
/// key_file = "./certs/key.pem"
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct TlsSettings {
    /// Whether TLS is enabled
    pub enabled: bool,
    
    /// Path to the certificate file (PEM format)
    pub cert_file: String,
    
    /// Path to the private key file (PEM format, PKCS#8)
    pub key_file: String,
}

/// Request filtering rule (from TOML)
#[derive(Debug, Deserialize)]
pub struct RequestRule {
    pub name: String,
    pub action: RuleAction,
    #[serde(default)]
    pub path_regex: Option<String>,
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    #[serde(default)]
    pub require_header: Option<String>,
}

/// Response filtering rule (from TOML)
#[derive(Debug, Deserialize)]
pub struct ResponseRule {
    pub name: String,
    pub action: RuleAction,
    #[serde(default)]
    pub status_codes: Option<Vec<u16>>,
    #[serde(default)]
    pub max_size_bytes: Option<usize>,
}

/// Action to take when a rule matches
#[derive(Debug, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Deny,
}

/// Compiled request rule with pre-compiled regex
#[derive(Clone)]
pub struct CompiledRequestRule {
    pub name: String,
    pub action: RuleAction,
    pub path_pattern: Option<Regex>,
    pub methods: Option<Vec<String>>,
    pub require_header: Option<String>,
}

/// Compiled response rule
#[derive(Clone)]
pub struct CompiledResponseRule {
    pub name: String,
    pub action: RuleAction,
    pub status_codes: Option<Vec<u16>>,
    pub max_size_bytes: Option<usize>,
}

/// Result of evaluating a rule
#[derive(Debug, PartialEq)]
pub enum RuleResult {
    Allow,
    Deny(String),
    Continue,  // Rule doesn't apply, check next rule
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
    
    /// Compile request rules (pre-compile regex patterns)
    pub fn compile_request_rules(&self) -> Result<Vec<CompiledRequestRule>, Box<dyn std::error::Error>> {
        let mut compiled = Vec::new();
        
        for rule in &self.request_rules {
            let path_pattern = if let Some(pattern_str) = &rule.path_regex {
                Some(Regex::new(pattern_str)?)
            } else {
                None
            };
            
            compiled.push(CompiledRequestRule {
                name: rule.name.clone(),
                action: rule.action.clone(),
                path_pattern,
                methods: rule.methods.clone(),
                require_header: rule.require_header.clone(),
            });
        }
        
        Ok(compiled)
    }
    
    /// Compile response rules
    pub fn compile_response_rules(&self) -> Vec<CompiledResponseRule> {
        self.response_rules.iter().map(|rule| {
            CompiledResponseRule {
                name: rule.name.clone(),
                action: rule.action.clone(),
                status_codes: rule.status_codes.clone(),
                max_size_bytes: rule.max_size_bytes,
            }
        }).collect()
    }
}

impl CompiledRequestRule {
    /// Evaluate this rule against a request
    pub fn evaluate(&self, method: &str, path: &str, headers: &std::collections::HashMap<String, String>) -> RuleResult {
        // Check if this rule applies to the request
        
        // Check path pattern
        if let Some(pattern) = &self.path_pattern {
            if !pattern.is_match(path) {
                return RuleResult::Continue;  // Path doesn't match, skip this rule
            }
        }
        
        // Check methods
        if let Some(methods) = &self.methods {
            let method_upper = method.to_uppercase();
            if !methods.iter().any(|m| m.to_uppercase() == method_upper) {
                return RuleResult::Continue;  // Method doesn't match, skip this rule
            }
        }
        
        // Check required header - this is a special condition
        // When combined with other conditions (like path), ALL must match
        if let Some(header_name) = &self.require_header {
            let header_present = headers.contains_key(&header_name.to_lowercase());
            
            if !header_present {
                // Header is missing
                if self.action == RuleAction::Deny {
                    // DENY + missing required header = Deny immediately
                    return RuleResult::Deny(format!("Missing required header: {}", header_name));
                } else {
                    // ALLOW + missing required header = Continue (can't allow without it)
                    return RuleResult::Continue;
                }
            }
            // If header IS present, we fall through to check final action
            // But we need to make sure other conditions were checked first
        }
        
        // Rule applies - return the action
        match self.action {
            RuleAction::Allow => RuleResult::Allow,
            RuleAction::Deny => RuleResult::Deny(format!("Blocked by rule: {}", self.name)),
        }
    }
}

impl CompiledResponseRule {
    /// Evaluate this rule against a response
    pub fn evaluate(&self, status_code: u16, content_length: Option<usize>) -> RuleResult {
        let mut rule_applies = false;
        
        // Check status codes - if specified, status must match for rule to apply
        if let Some(codes) = &self.status_codes {
            if !codes.contains(&status_code) {
                return RuleResult::Continue;  // Status code doesn't match
            }
            rule_applies = true;
        }
        
        // Check content length - if specified, this is the condition being checked
        if let Some(max_size) = self.max_size_bytes {
            if let Some(size) = content_length {
                if size > max_size {
                    // Size exceeded - this specific condition triggers the action
                    return match self.action {
                        RuleAction::Deny => RuleResult::Deny(format!(
                            "Response size {} exceeds limit {} (rule: {})",
                            size, max_size, self.name
                        )),
                        RuleAction::Allow => RuleResult::Allow,
                    };
                } else {
                    // Size is under limit - rule doesn't apply
                    return RuleResult::Continue;
                }
            }
            // If content_length is None but max_size is set, we can't check, so continue
            return RuleResult::Continue;
        }
        
        // If we got here and rule applies (status matched), apply the action
        if rule_applies {
            match self.action {
                RuleAction::Allow => RuleResult::Allow,
                RuleAction::Deny => RuleResult::Deny(format!("Blocked by rule: {}", self.name)),
            }
        } else {
            // No conditions matched
            RuleResult::Continue
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let toml_str = r#"
[proxy]
listen_address = "127.0.0.1:8080"
backend_address = "127.0.0.1:9090"
timeout_seconds = 30

[[request_rules]]
name = "Block admin"
action = "deny"
path_regex = "^/admin/.*"
methods = ["GET", "POST"]

[[response_rules]]
name = "Block errors"
action = "deny"
status_codes = [500, 502, 503]
"#;
        
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.proxy.listen_address, "127.0.0.1:8080");
        assert_eq!(config.request_rules.len(), 1);
        assert_eq!(config.response_rules.len(), 1);
    }

    #[test]
    fn test_parse_config_with_tls() {
        let toml_str = r#"
[proxy]
listen_address = "127.0.0.1:8443"
backend_address = "127.0.0.1:9090"
timeout_seconds = 30

[tls]
enabled = true
cert_file = "./certs/cert.pem"
key_file = "./certs/key.pem"
"#;
        
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.tls.is_some());
        let tls = config.tls.unwrap();
        assert!(tls.enabled);
        assert_eq!(tls.cert_file, "./certs/cert.pem");
        assert_eq!(tls.key_file, "./certs/key.pem");
    }

    #[test]
    fn test_request_rule_path_match() {
        let rule = CompiledRequestRule {
            name: "Test".to_string(),
            action: RuleAction::Deny,
            path_pattern: Some(Regex::new("^/admin/.*").unwrap()),
            methods: None,
            require_header: None,
        };
        
        let headers = std::collections::HashMap::new();
        
        // Should match /admin/users
        let result = rule.evaluate("GET", "/admin/users", &headers);
        assert!(matches!(result, RuleResult::Deny(_)));
        
        // Should not match /api/users
        let result = rule.evaluate("GET", "/api/users", &headers);
        assert_eq!(result, RuleResult::Continue);
    }

    #[test]
    fn test_request_rule_method_match() {
        let rule = CompiledRequestRule {
            name: "Test".to_string(),
            action: RuleAction::Deny,
            path_pattern: None,
            methods: Some(vec!["POST".to_string(), "PUT".to_string()]),
            require_header: None,
        };
        
        let headers = std::collections::HashMap::new();
        
        // Should match POST
        let result = rule.evaluate("POST", "/anything", &headers);
        assert!(matches!(result, RuleResult::Deny(_)));
        
        // Should not match GET
        let result = rule.evaluate("GET", "/anything", &headers);
        assert_eq!(result, RuleResult::Continue);
    }

    #[test]
    fn test_request_rule_require_header() {
        let rule = CompiledRequestRule {
            name: "Test".to_string(),
            action: RuleAction::Deny,
            path_pattern: None,
            methods: None,
            require_header: Some("Authorization".to_string()),
        };
        
        let mut headers = std::collections::HashMap::new();
        
        // Should deny when header missing
        let result = rule.evaluate("GET", "/api", &headers);
        assert!(matches!(result, RuleResult::Deny(_)));
        
        // Should continue when header present
        headers.insert("authorization".to_string(), "Bearer token".to_string());
        let result = rule.evaluate("GET", "/api", &headers);
        assert_eq!(result, RuleResult::Continue);
    }

    #[test]
    fn test_response_rule_status_code() {
        let rule = CompiledResponseRule {
            name: "Test".to_string(),
            action: RuleAction::Deny,
            status_codes: Some(vec![500, 502, 503]),
            max_size_bytes: None,
        };
        
        // Should match 500
        let result = rule.evaluate(500, None);
        assert!(matches!(result, RuleResult::Deny(_)));
        
        // Should not match 200
        let result = rule.evaluate(200, None);
        assert_eq!(result, RuleResult::Continue);
    }

    #[test]
    fn test_response_rule_size_limit() {
        let rule = CompiledResponseRule {
            name: "Test".to_string(),
            action: RuleAction::Deny,
            status_codes: None,
            max_size_bytes: Some(1000),
        };
        
        // Should deny when size exceeds limit
        let result = rule.evaluate(200, Some(2000));
        assert!(matches!(result, RuleResult::Deny(_)));
        
        // Should continue when size under limit
        let result = rule.evaluate(200, Some(500));
        assert_eq!(result, RuleResult::Continue);
    }
}