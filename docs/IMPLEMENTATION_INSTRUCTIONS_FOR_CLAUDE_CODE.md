# 🤖 Implementation Instructions for Claude Code

## Overview

These are detailed, step-by-step instructions for implementing the multi-listener configuration system in Jester Jr. Follow these instructions sequentially to add support for:

- Multiple named listeners (different IP:port combinations)
- Path-based routing per listener
- Route-specific backends
- Hierarchical filtering rules (listener-level + route-level)
- Path prefix stripping
- Configurable default routes

---

## 📋 Prerequisites

Before starting, ensure:
- Current Jester Jr v0.1.0 is working
- You understand the current single-listener architecture
- Rust 1.75+ and Cargo are installed
- You have read `MULTI_LISTENER_CONFIG_DESIGN.md` for context

---

## 🎯 Implementation Phases

### Phase 1: Update Configuration Structures (src/config/config.rs)

**Goal**: Extend the configuration to support multiple listeners with routes.

#### Step 1.1: Add new structures at the top of the file

```rust
// After existing imports, add:
use std::collections::HashMap;
```

#### Step 1.2: Update the main Config struct

**Current structure:**
```rust
pub struct Config {
    pub proxy: ProxySettings,
    pub tls: Option<TlsSettings>,
    pub request_rules: Vec<RequestRule>,
    pub response_rules: Vec<ResponseRule>,
}
```

**New structure (replace the above):**
```rust
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
```

#### Step 1.3: Add GlobalSettings structure

```rust
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
```

#### Step 1.4: Add ListenerConfig structure

```rust
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
```

#### Step 1.5: Add RouteConfig structure

```rust
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
```

#### Step 1.6: Add compiled structures

```rust
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
```

#### Step 1.7: Add validation method to Config

```rust
impl Config {
    // Keep existing from_file method
    
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
        let route_name = route.name.as_deref()
            .unwrap_or(&format!("route-{}", index));
        
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
    
    fn compile_route(&self, route: &RouteConfig, listener: &ListenerConfig) -> Result<CompiledRoute, Box<dyn std::error::Error>> {
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
}
```

#### Step 1.8: Add backward compatibility method

```rust
impl Config {
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
```

#### Step 1.9: Update exports in src/config/mod.rs

```rust
pub use config::{
    Config,
    GlobalSettings,
    ListenerConfig,
    RouteConfig,
    TlsSettings,
    CompiledListener,
    CompiledRoute,
    CompiledRequestRule,
    CompiledResponseRule,
    RuleResult,
};
```

---

### Phase 2: Add Route Matching Logic (src/routing.rs - NEW FILE)

**Goal**: Create a new module to handle route matching and path rewriting.

#### Step 2.1: Create src/routing/mod.rs

```rust
//! Routing module for path-based request routing
//!
//! Handles matching incoming requests to configured routes
//! and rewriting paths when necessary.

use crate::config::{CompiledRoute, CompiledListener};

/// Result of route matching
pub struct RouteMatch<'a> {
    pub route: &'a CompiledRoute,
    pub rewritten_path: String,
}

/// Match a request path against routes in order
pub fn match_route<'a>(
    listener: &'a CompiledListener,
    path: &str,
) -> Option<RouteMatch<'a>> {
    for route in &listener.routes {
        if let Some(rewritten_path) = matches_route(route, path) {
            return Some(RouteMatch {
                route,
                rewritten_path,
            });
        }
    }
    None
}

/// Check if a path matches a route and return rewritten path
fn matches_route(route: &CompiledRoute, path: &str) -> Option<String> {
    // Try prefix matching first
    if let Some(prefix) = &route.path_prefix {
        if path.starts_with(prefix) {
            let rewritten = if route.strip_prefix {
                // Remove the prefix
                let stripped = path.strip_prefix(prefix).unwrap_or(path);
                // Ensure it starts with /
                if stripped.is_empty() || !stripped.starts_with('/') {
                    format!("/{}", stripped)
                } else {
                    stripped.to_string()
                }
            } else {
                path.to_string()
            };
            return Some(rewritten);
        }
    }
    
    // Try regex matching
    if let Some(pattern) = &route.path_pattern {
        if pattern.is_match(path) {
            // Regex matches don't support strip_prefix
            return Some(path.to_string());
        }
    }
    
    None
}

/// Get the default backend for a listener (if configured)
pub fn get_default_backend(listener: &CompiledListener) -> Option<&str> {
    if listener.default_action == "forward" {
        listener.default_backend.as_deref()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CompiledRoute, TlsSettings};
    use regex::Regex;
    
    #[test]
    fn test_prefix_match() {
        let route = CompiledRoute {
            name: Some("test".to_string()),
            path_prefix: Some("/api/v1".to_string()),
            path_pattern: None,
            backend: "127.0.0.1:8080".to_string(),
            strip_prefix: false,
            timeout_seconds: 30,
            request_rules: vec![],
            response_rules: vec![],
        };
        
        assert!(matches_route(&route, "/api/v1/users").is_some());
        assert!(matches_route(&route, "/api/v2/users").is_none());
    }
    
    #[test]
    fn test_prefix_strip() {
        let route = CompiledRoute {
            name: Some("test".to_string()),
            path_prefix: Some("/api/v1".to_string()),
            path_pattern: None,
            backend: "127.0.0.1:8080".to_string(),
            strip_prefix: true,
            timeout_seconds: 30,
            request_rules: vec![],
            response_rules: vec![],
        };
        
        let rewritten = matches_route(&route, "/api/v1/users").unwrap();
        assert_eq!(rewritten, "/users");
        
        let rewritten = matches_route(&route, "/api/v1").unwrap();
        assert_eq!(rewritten, "/");
    }
    
    #[test]
    fn test_regex_match() {
        let route = CompiledRoute {
            name: Some("test".to_string()),
            path_prefix: None,
            path_pattern: Some(Regex::new("^/api/v[12]/.*").unwrap()),
            backend: "127.0.0.1:8080".to_string(),
            strip_prefix: false,
            timeout_seconds: 30,
            request_rules: vec![],
            response_rules: vec![],
        };
        
        assert!(matches_route(&route, "/api/v1/users").is_some());
        assert!(matches_route(&route, "/api/v2/users").is_some());
        assert!(matches_route(&route, "/api/v3/users").is_none());
    }
}
```

#### Step 2.2: Add routing module to main.rs

```rust
// Add after existing mod declarations
mod routing;
```

---

### Phase 3: Update Main Server Logic (src/main.rs)

**Goal**: Modify main.rs to handle multiple listeners.

#### Step 3.1: Update main() function

**Current:**
```rust
fn main() {
    // ... config loading ...
    let request_rules = config.compile_request_rules()?;
    let response_rules = config.compile_response_rules();
    run_server(config, request_rules, response_rules, tls_config)?;
}
```

**New:**
```rust
fn main() {
    // Load configuration
    let args: Vec<String> = env::args().collect();
    let config_path = if args.len() > 1 {
        &args[1]
    } else {
        "jester-jr.toml"
    };
    
    println!("🔧 Loading configuration from: {}", config_path);
    
    let mut config = match Config::from_file(config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("❌ Failed to load config: {}", e);
            std::process::exit(1);
        }
    };
    
    // Migrate legacy config if needed
    config.migrate_from_legacy();
    
    // Validate configuration
    if let Err(e) = config.validate() {
        eprintln!("❌ Configuration validation failed: {}", e);
        std::process::exit(1);
    }
    
    // Compile all listeners
    let listeners = match config.compile_listeners() {
        Ok(listeners) => {
            println!("✅ Compiled {} listener(s)", listeners.len());
            for listener in &listeners {
                println!("   • {} → {}:{}", 
                    listener.name, listener.ip, listener.port);
                println!("     Routes: {}", listener.routes.len());
                if let Some(desc) = &listener.description {
                    println!("     Description: {}", desc);
                }
            }
            listeners
        }
        Err(e) => {
            eprintln!("❌ Failed to compile listeners: {}", e);
            std::process::exit(1);
        }
    };
    
    // Start all listeners
    if let Err(e) = run_multi_listeners(listeners) {
        eprintln!("❌ Server error: {}", e);
        std::process::exit(1);
    }
}
```

#### Step 3.2: Add run_multi_listeners function

```rust
use std::sync::Arc;
use std::thread;

fn run_multi_listeners(listeners: Vec<CompiledListener>) -> Result<(), std::io::Error> {
    if listeners.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "No listeners configured"
        ));
    }
    
    let mut handles = vec![];
    
    for listener in listeners {
        let handle = thread::spawn(move || {
            if let Err(e) = run_single_listener(listener) {
                eprintln!("❌ Listener error: {}", e);
            }
        });
        handles.push(handle);
    }
    
    // Wait for all listener threads
    for handle in handles {
        let _ = handle.join();
    }
    
    Ok(())
}
```

#### Step 3.3: Add run_single_listener function

```rust
use std::net::TcpListener;
use std::time::Duration;

fn run_single_listener(listener: CompiledListener) -> Result<(), std::io::Error> {
    let listen_addr = format!("{}:{}", listener.ip, listener.port);
    let timeout = Duration::from_secs(listener.timeout_seconds);
    
    // Load TLS config if enabled
    let tls_config = if let Some(tls_settings) = &listener.tls {
        if tls_settings.enabled {
            match tls::create_tls_config(&tls_settings.cert_file, &tls_settings.key_file) {
                Ok(config) => {
                    println!("🔒 TLS enabled for {}", listener.name);
                    Some(config)
                }
                Err(e) => {
                    eprintln!("❌ Failed to initialize TLS for {}: {}", listener.name, e);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("TLS init failed: {}", e)
                    ));
                }
            }
        } else {
            None
        }
    } else {
        None
    };
    
    let tcp_listener = TcpListener::bind(&listen_addr)?;
    let protocol = if tls_config.is_some() { "https" } else { "http" };
    
    println!("\n🃏 Listener '{}' active on {}://{}", 
        listener.name, protocol, listen_addr);
    println!("   Routes: {}", listener.routes.len());
    println!("   Default action: {}", listener.default_action);
    if let Some(backend) = &listener.default_backend {
        println!("   Default backend: {}", backend);
    }
    
    // Wrap listener in Arc for sharing across threads
    let listener_arc = Arc::new(listener);
    
    for stream in tcp_listener.incoming() {
        match stream {
            Ok(stream) => {
                let listener_clone = Arc::clone(&listener_arc);
                let tls_cfg_clone = tls_config.clone();
                
                thread::spawn(move || {
                    if let Err(e) = handle_connection_with_routing(
                        stream,
                        listener_clone,
                        timeout,
                        timeout,
                        tls_cfg_clone,
                    ) {
                        eprintln!("⚠️  Error handling connection: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("⚠️  Failed to accept connection: {}", e);
            }
        }
    }
    
    Ok(())
}
```

#### Step 3.4: Add handle_connection_with_routing function

```rust
use crate::routing::{match_route, get_default_backend};

fn handle_connection_with_routing(
    client_stream: TcpStream,
    listener: Arc<CompiledListener>,
    read_timeout: Duration,
    write_timeout: Duration,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), std::io::Error> {
    let peer_addr = client_stream.peer_addr()?;
    println!("\n✨ New connection from: {} [{}]", peer_addr, listener.name);
    
    client_stream.set_read_timeout(Some(read_timeout))?;
    client_stream.set_write_timeout(Some(write_timeout))?;
    
    // Parse request to get path for routing
    // (You'll need to parse the request first to know the path)
    
    // For now, let's create a helper function
    // We'll implement this in the next step
    
    if let Some(tls_cfg) = tls_config {
        handle_tls_connection_with_routing(
            client_stream,
            listener,
            read_timeout,
            write_timeout,
            tls_cfg,
        )
    } else {
        handle_plain_connection_with_routing(
            client_stream,
            listener,
            read_timeout,
            write_timeout,
        )
    }
}
```

---

### Phase 4: Update Connection Handlers

**Goal**: Modify existing connection handlers to use routing logic.

#### Step 4.1: Update handle_plain_connection

**Instructions:**
1. Rename `handle_plain_connection` to `handle_plain_connection_with_routing`
2. Change signature to accept `Arc<CompiledListener>` instead of individual rules
3. After parsing HTTP request, call `match_route()` to find backend
4. If no route matches, check `get_default_backend()` or return 404
5. Apply listener-level rules first, then route-level rules
6. Use the matched route's `backend` instead of global `backend_addr`
7. Forward to `route.rewritten_path` instead of original path

**Pseudocode:**
```rust
fn handle_plain_connection_with_routing(
    client_stream: TcpStream,
    listener: Arc<CompiledListener>,
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<(), std::io::Error> {
    // ... existing setup code ...
    
    // Parse request
    let request = HttpRequest::parse(&mut client_reader)?;
    
    // Match route
    let route_match = match routing::match_route(&listener, &request.path) {
        Some(m) => m,
        None => {
            // No route matched
            if let Some(backend) = routing::get_default_backend(&listener) {
                // Forward to default backend with original path
                return forward_to_backend(
                    &request,
                    backend,
                    &request.path,
                    client_writer,
                    &listener.request_rules,
                    &listener.response_rules,
                    read_timeout,
                    write_timeout,
                );
            } else {
                // Return 404
                let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
                client_writer.write_all(response.as_bytes())?;
                return Ok(());
            }
        }
    };
    
    // Apply listener-level request rules
    if let Err(reason) = evaluate_rules(&request, &listener.request_rules) {
        // Blocked by listener-level rule
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{}",
            reason.len(), reason
        );
        client_writer.write_all(response.as_bytes())?;
        return Ok(());
    }
    
    // Apply route-level request rules
    if let Err(reason) = evaluate_rules(&request, &route_match.route.request_rules) {
        // Blocked by route-level rule
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{}",
            reason.len(), reason
        );
        client_writer.write_all(response.as_bytes())?;
        return Ok(());
    }
    
    // Forward to matched backend with rewritten path
    forward_to_backend(
        &request,
        &route_match.route.backend,
        &route_match.rewritten_path,
        client_writer,
        &listener.response_rules,  // Listener-level
        &route_match.route.response_rules,  // Route-level
        read_timeout,
        write_timeout,
    )
}
```

#### Step 4.2: Update handle_tls_connection

Follow similar pattern as above for TLS connections.

---

### Phase 5: Testing

#### Step 5.1: Create test configuration

Create `test-multi-listener.toml`:
```toml
[global]
log_level = "info"
timeout_seconds = 30

[listener."test-api"]
ip = "127.0.0.1"
port = 8080
description = "Test API listener"
default_action = "reject"

[listener."test-api".tls]
enabled = false

[[listener."test-api".routes]]
name = "component1"
path_prefix = "/component1"
backend = "127.0.0.1:9090"
strip_prefix = true

[[listener."test-api".routes]]
name = "component2"
path_prefix = "/component2"
backend = "127.0.0.1:9091"
strip_prefix = true
```

#### Step 5.2: Test commands

```bash
# Build
cargo build --release

# Run
./target/release/jester-jr test-multi-listener.toml

# Test routing
curl http://127.0.0.1:8080/component1/test  # Should forward to 9090 as /test
curl http://127.0.0.1:8080/component2/test  # Should forward to 9091 as /test
curl http://127.0.0.1:8080/unknown          # Should return 404
```

---

## 📊 Implementation Checklist

Use this to track your progress:

### Phase 1: Configuration
- [ ] Add new imports and structures
- [ ] Update Config struct
- [ ] Add GlobalSettings
- [ ] Add ListenerConfig
- [ ] Add RouteConfig
- [ ] Add CompiledListener and CompiledRoute
- [ ] Implement validate() method
- [ ] Implement compile_listeners() method
- [ ] Implement migrate_from_legacy()
- [ ] Update exports in mod.rs
- [ ] Run `cargo check` - should compile

### Phase 2: Routing
- [ ] Create src/routing/mod.rs
- [ ] Implement match_route()
- [ ] Implement matches_route()
- [ ] Implement get_default_backend()
- [ ] Add unit tests
- [ ] Run `cargo test routing` - should pass

### Phase 3: Server Logic
- [ ] Update main() function
- [ ] Add run_multi_listeners()
- [ ] Add run_single_listener()
- [ ] Add handle_connection_with_routing()
- [ ] Add routing module to main.rs
- [ ] Run `cargo check` - should compile

### Phase 4: Connection Handlers
- [ ] Update handle_plain_connection
- [ ] Update handle_tls_connection
- [ ] Implement merged rule evaluation
- [ ] Test path rewriting
- [ ] Run `cargo check` - should compile

### Phase 5: Testing
- [ ] Create test configuration
- [ ] Start test backends
- [ ] Test basic routing
- [ ] Test path prefix stripping
- [ ] Test default routes
- [ ] Test TLS with routing
- [ ] Test merged rules

---

## 🚨 Common Pitfalls to Avoid

1. **Arc cloning**: Remember `Arc::clone()` is cheap, only increments counter
2. **Path rewriting**: Ensure rewritten paths always start with `/`
3. **Rule order**: Listener rules evaluate BEFORE route rules
4. **Default backend**: Only used when `default_action = "forward"`
5. **Thread safety**: Wrap shared state in `Arc`

---

## 📝 Notes for Implementation

- Keep backward compatibility with legacy config format
- Use the `migrate_from_legacy()` method to convert old configs
- Test both plain HTTP and TLS modes
- Ensure all error messages include listener and route names for debugging
- Add comprehensive logging throughout

---

## 🎯 Success Criteria

Your implementation is complete when:
1. ✅ All compilation checks pass (`cargo check`)
2. ✅ All tests pass (`cargo test`)
3. ✅ Can load multi-listener configuration
4. ✅ Each listener binds to correct IP:port
5. ✅ Routes match correctly (prefix and regex)
6. ✅ Path rewriting works
7. ✅ Rules evaluate in correct order (listener → route)
8. ✅ Default routes work
9. ✅ TLS works with routing
10. ✅ Legacy configs still work

---

## 📚 Reference Files

- Configuration design: `MULTI_LISTENER_CONFIG_DESIGN.md`
- Current implementation: Review existing `src/main.rs` and `src/config/config.rs`
- Example configs: See design document for complete examples

---

**Good luck with the implementation! 🚀**

This is a significant enhancement but follows clear patterns. Take it one phase at a time, test incrementally, and don't hesitate to add extra logging during development.