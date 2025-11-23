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
use std::collections::HashMap;

/// Main configuration structure
#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub global: GlobalSettings,
    
    #[serde(default)]
    pub listener: HashMap<String, ListenerConfig>,
    
    // Keep for backward compatibility (will be deprecated)
    #[serde(default)]
    pub proxy: Option<ProxySettings>,
    
    #[serde(default)]
    pub tls: Option<TlsSettings>,
    
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

/// Global settings that apply to all listeners
#[derive(Debug, Deserialize, Clone)]
pub struct GlobalSettings {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            timeout_seconds: 30,
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_timeout() -> u64 {
    30
}

/// Configuration for a single listener
#[derive(Debug, Deserialize, Clone)]
pub struct ListenerConfig {
    pub ip: String,
    pub port: u16,
    
    #[serde(default)]
    pub description: Option<String>,
    
    #[serde(default)]
    pub default_backend: Option<String>,
    
    #[serde(default = "default_action")]
    pub default_action: String,
    
    #[serde(default)]
    pub tls: Option<TlsSettings>,
    
    #[serde(default)]
    pub request_rules: Vec<RequestRule>,
    
    #[serde(default)]
    pub response_rules: Vec<ResponseRule>,
    
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

fn default_action() -> String {
    "reject".to_string()
}

/// Route configuration (path-based routing)
#[derive(Debug, Deserialize, Clone)]
pub struct RouteConfig {
    #[serde(default)]
    pub name: Option<String>,
    
    #[serde(default)]
    pub path_prefix: Option<String>,
    
    #[serde(default)]
    pub path_regex: Option<String>,
    
    pub backend: String,
    
    #[serde(default)]
    pub strip_prefix: bool,
    
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    
    #[serde(default)]
    pub request_rules: Vec<RequestRule>,
    
    #[serde(default)]
    pub response_rules: Vec<ResponseRule>,
}

/// Request filtering rule (from TOML)
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
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

/// Compiled listener configuration with pre-compiled regexes
#[derive(Clone)]
pub struct CompiledListener {
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub description: Option<String>,
    pub default_backend: Option<String>,
    pub default_action: String,
    pub tls: Option<TlsSettings>,
    pub request_rules: Vec<CompiledRequestRule>,
    pub response_rules: Vec<CompiledResponseRule>,
    pub routes: Vec<CompiledRoute>,
    pub timeout_seconds: u64,
}

/// Compiled route with pre-compiled regex
#[derive(Clone)]
pub struct CompiledRoute {
    pub name: Option<String>,
    pub path_prefix: Option<String>,
    pub path_pattern: Option<Regex>,
    pub backend: String,
    pub strip_prefix: bool,
    pub timeout_seconds: u64,
    pub request_rules: Vec<CompiledRequestRule>,
    pub response_rules: Vec<CompiledResponseRule>,
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
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        // Check for backward compatibility or new format
        if self.listener.is_empty() && self.proxy.is_none() {
            return Err("Configuration must have either listeners or proxy settings".to_string());
        }
        
        // Validate each listener
        for (name, listener) in &self.listener {
            self.validate_listener(name, listener)?;
        }
        
        Ok(())
    }
    
    fn validate_listener(&self, name: &str, listener: &ListenerConfig) -> Result<(), String> {
        // Validate IP address format
        if listener.ip.is_empty() {
            return Err(format!("Listener '{}': IP address cannot be empty", name));
        }
        
        // Validate port range
        if listener.port == 0 {
            return Err(format!("Listener '{}': Port cannot be 0", name));
        }
        
        // Validate default_action
        if listener.default_action != "reject" && listener.default_action != "forward" {
            return Err(format!(
                "Listener '{}': default_action must be 'reject' or 'forward', got '{}'",
                name, listener.default_action
            ));
        }
        
        // If default_action is "forward", default_backend must be set
        if listener.default_action == "forward" && listener.default_backend.is_none() {
            return Err(format!(
                "Listener '{}': default_action 'forward' requires default_backend to be set",
                name
            ));
        }
        
        // Validate TLS configuration if enabled
        if let Some(tls) = &listener.tls {
            if tls.enabled {
                if tls.cert_file.is_empty() {
                    return Err(format!("Listener '{}': TLS cert_file cannot be empty", name));
                }
                if tls.key_file.is_empty() {
                    return Err(format!("Listener '{}': TLS key_file cannot be empty", name));
                }
            }
        }
        
        // Validate routes
        for (i, route) in listener.routes.iter().enumerate() {
            self.validate_route(name, i, route)?;
        }
        
        Ok(())
    }
    
    fn validate_route(&self, listener_name: &str, index: usize, route: &RouteConfig) -> Result<(), String> {
        let default_name = format!("route-{}", index);
        let route_name = route.name.as_deref()
            .unwrap_or(&default_name);
        
        // Must have either path_prefix or path_regex, but not both
        match (&route.path_prefix, &route.path_regex) {
            (None, None) => {
                return Err(format!(
                    "Listener '{}', route '{}': must have either path_prefix or path_regex",
                    listener_name, route_name
                ));
            }
            (Some(_), Some(_)) => {
                return Err(format!(
                    "Listener '{}', route '{}': cannot have both path_prefix and path_regex",
                    listener_name, route_name
                ));
            }
            _ => {}
        }
        
        // If strip_prefix is true, must use path_prefix (not regex)
        if route.strip_prefix && route.path_prefix.is_none() {
            return Err(format!(
                "Listener '{}', route '{}': strip_prefix requires path_prefix (not path_regex)",
                listener_name, route_name
            ));
        }
        
        // Validate backend format (should be address:port)
        if !route.backend.contains(':') {
            return Err(format!(
                "Listener '{}', route '{}': backend must be in format 'address:port', got '{}'",
                listener_name, route_name, route.backend
            ));
        }
        
        // Validate path_regex if present
        if let Some(regex_str) = &route.path_regex {
            Regex::new(regex_str).map_err(|e| format!(
                "Listener '{}', route '{}': invalid regex '{}': {}",
                listener_name, route_name, regex_str, e
            ))?;
        }
        
        Ok(())
    }
    
    /// Compile all listeners
    pub fn compile_listeners(&self) -> Result<Vec<CompiledListener>, Box<dyn std::error::Error>> {
        let mut compiled = Vec::new();
        
        for (name, listener) in &self.listener {
            compiled.push(self.compile_listener(name.clone(), listener)?);
        }
        
        Ok(compiled)
    }
    
    fn compile_listener(&self, name: String, listener: &ListenerConfig) -> Result<CompiledListener, Box<dyn std::error::Error>> {
        // Compile listener-level request rules
        let request_rules = self.compile_request_rules_list(&listener.request_rules)?;
        
        // Compile listener-level response rules
        let response_rules = self.compile_response_rules_list(&listener.response_rules);
        
        // Compile all routes
        let mut routes = Vec::new();
        for route in &listener.routes {
            routes.push(self.compile_route(route, listener)?);
        }
        
        // Determine timeout (listener-specific or global)
        let timeout_seconds = self.global.timeout_seconds;
        
        Ok(CompiledListener {
            name,
            ip: listener.ip.clone(),
            port: listener.port,
            description: listener.description.clone(),
            default_backend: listener.default_backend.clone(),
            default_action: listener.default_action.clone(),
            tls: listener.tls.clone(),
            request_rules,
            response_rules,
            routes,
            timeout_seconds,
        })
    }
    
    fn compile_route(&self, route: &RouteConfig, _listener: &ListenerConfig) -> Result<CompiledRoute, Box<dyn std::error::Error>> {
        // Compile path regex if present
        let path_pattern = if let Some(regex_str) = &route.path_regex {
            Some(Regex::new(regex_str)?)
        } else {
            None
        };
        
        // Compile route-specific request rules
        let request_rules = self.compile_request_rules_list(&route.request_rules)?;
        
        // Compile route-specific response rules
        let response_rules = self.compile_response_rules_list(&route.response_rules);
        
        // Determine timeout (route > listener > global)
        let timeout_seconds = route.timeout_seconds
            .unwrap_or(self.global.timeout_seconds);
        
        Ok(CompiledRoute {
            name: route.name.clone(),
            path_prefix: route.path_prefix.clone(),
            path_pattern,
            backend: route.backend.clone(),
            strip_prefix: route.strip_prefix,
            timeout_seconds,
            request_rules,
            response_rules,
        })
    }
    
    fn compile_request_rules_list(&self, rules: &[RequestRule]) -> Result<Vec<CompiledRequestRule>, Box<dyn std::error::Error>> {
        let mut compiled = Vec::new();
        for rule in rules {
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
    
    fn compile_response_rules_list(&self, rules: &[ResponseRule]) -> Vec<CompiledResponseRule> {
        rules.iter().map(|rule| {
            CompiledResponseRule {
                name: rule.name.clone(),
                action: rule.action.clone(),
                status_codes: rule.status_codes.clone(),
                max_size_bytes: rule.max_size_bytes,
            }
        }).collect()
    }
    
    /// Convert old single-listener format to new multi-listener format
    pub fn migrate_from_legacy(&mut self) {
        // If using old format (proxy settings), convert to new format
        if let Some(proxy) = &self.proxy {
            if self.listener.is_empty() {
                let mut listener_config = ListenerConfig {
                    ip: proxy.listen_address.split(':').next()
                        .unwrap_or("0.0.0.0").to_string(),
                    port: proxy.listen_address.split(':').nth(1)
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(8080),
                    description: Some("Migrated from legacy config".to_string()),
                    default_backend: Some(proxy.backend_address.clone()),
                    default_action: "forward".to_string(),
                    tls: self.tls.clone(),
                    request_rules: self.request_rules.clone(),
                    response_rules: self.response_rules.clone(),
                    routes: vec![],
                };
                
                // Create a single catch-all route
                listener_config.routes.push(RouteConfig {
                    name: Some("default".to_string()),
                    path_prefix: Some("/".to_string()),
                    path_regex: None,
                    backend: proxy.backend_address.clone(),
                    strip_prefix: false,
                    timeout_seconds: Some(proxy.timeout_seconds),
                    request_rules: vec![],
                    response_rules: vec![],
                });
                
                self.listener.insert("default".to_string(), listener_config);
                
                println!("⚠️  Migrated legacy configuration to new multi-listener format");
                println!("   Consider updating your config file to use the new format");
            }
        }
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
        assert_eq!(config.proxy.as_ref().unwrap().listen_address, "127.0.0.1:8080");
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