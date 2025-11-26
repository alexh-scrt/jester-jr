//! Validation context - data passed to validators

use crate::parsers::HttpRequest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Context provided to validators during validation
///
/// Contains all information about the request and configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationContext {
    /// HTTP method (GET, POST, etc.)
    pub method: String,

    /// Request path
    pub path: String,

    /// HTTP version
    pub version: String,

    /// All HTTP headers (lowercase keys)
    pub headers: HashMap<String, String>,

    /// Client IP address
    pub client_ip: IpAddr,

    /// Listener name this request came from
    pub listener_name: String,

    /// Route name (if matched)
    pub route_name: Option<String>,

    /// Validator-specific configuration from TOML
    pub config: serde_json::Value,

    /// Shared state across validators
    ///
    /// Useful for rate limiting, caching, etc.
    #[serde(skip)]
    #[allow(dead_code)]
    pub state: Arc<ValidatorState>,
}

/// Shared state that validators can read/write to
///
/// This enables validators to:
/// - Share rate limiting counters
/// - Cache validation results
/// - Store temporary session data
#[derive(Default, Debug)]
pub struct ValidatorState {
    /// Generic key-value store
    #[allow(dead_code)]
    pub data: parking_lot::RwLock<HashMap<String, serde_json::Value>>,
}

impl ValidationContext {
    /// Create a new validation context from an HTTP request
    pub fn from_request(
        request: &HttpRequest,
        client_ip: IpAddr,
        listener_name: String,
        route_name: Option<String>,
        config: serde_json::Value,
        state: Arc<ValidatorState>,
    ) -> Self {
        Self {
            method: request.method.clone(),
            path: request.path.clone(),
            version: request.version.clone(),
            headers: request.headers.clone(),
            client_ip,
            listener_name,
            route_name,
            config,
            state,
        }
    }

    /// Get a header value (case-insensitive)
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(&name.to_lowercase())
    }

    /// Check if a header exists (case-insensitive)
    #[allow(dead_code)]
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.contains_key(&name.to_lowercase())
    }
}

impl ValidatorState {
    /// Create a new validator state
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a value from state
    #[allow(dead_code)]
    pub fn get(&self, key: &str) -> Option<serde_json::Value> {
        self.data.read().get(key).cloned()
    }

    /// Set a value in state
    #[allow(dead_code)]
    pub fn set(&self, key: String, value: serde_json::Value) {
        self.data.write().insert(key, value);
    }

    /// Remove a value from state
    #[allow(dead_code)]
    pub fn remove(&self, key: &str) -> Option<serde_json::Value> {
        self.data.write().remove(key)
    }

    /// Clear all state
    #[allow(dead_code)]
    pub fn clear(&self) {
        self.data.write().clear();
    }
}