//! Validation result types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::Level;

/// Result of validation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ValidationResult {
    /// Request is valid, proceed with proxying
    Allow,

    /// Request is valid, but modify it before proxying
    AllowWithModification {
        /// Headers to add to the request
        #[serde(default)]
        add_headers: HashMap<String, String>,

        /// Headers to remove from the request
        #[serde(default)]
        remove_headers: Vec<String>,

        /// Optional path rewriting
        #[serde(skip_serializing_if = "Option::is_none")]
        rewrite_path: Option<String>,

        /// Optional message to log
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },

    /// Request is invalid, deny it
    Deny {
        /// HTTP status code to return
        status_code: u16,

        /// Reason for denial (sent to client)
        reason: String,

        /// Log level for this denial
        #[serde(default = "default_log_level")]
        log_level: LogLevel,

        /// Optional detailed message (for internal logging only)
        #[serde(skip_serializing_if = "Option::is_none")]
        internal_message: Option<String>,
    },

    /// Request is invalid, deny it and blacklist the IP
    BlacklistIP {
        /// IP address to blacklist
        ip: IpAddr,

        /// HTTP status code to return
        status_code: u16,

        /// Reason for denial and blacklisting
        reason: String,

        /// Log level for this denial
        #[serde(default = "default_log_level")]
        log_level: LogLevel,

        /// TTL in hours for blacklist entry (None = use default)
        #[serde(skip_serializing_if = "Option::is_none")]
        ttl_hours: Option<u32>,

        /// Optional detailed message (for internal logging only)
        #[serde(skip_serializing_if = "Option::is_none")]
        internal_message: Option<String>,
    },
}

/// Log level for validation events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LogLevel> for Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Trace => Level::TRACE,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Error => Level::ERROR,
        }
    }
}

fn default_log_level() -> LogLevel {
    LogLevel::Warn
}

/// Error type for validator failures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationError {
    /// Configuration error (validator misconfigured)
    ConfigError(String),

    /// Network error (external service unreachable)
    NetworkError(String),

    /// Runtime error (unexpected validator behavior)
    RuntimeError(String),

    /// Timeout (validator took too long)
    Timeout,

    /// Script error (for Rhai validators)
    ScriptError(String),

    /// WASM error (for WASM validators)
    WasmError(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::ConfigError(msg) => write!(f, "Config error: {}", msg),
            ValidationError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            ValidationError::RuntimeError(msg) => write!(f, "Runtime error: {}", msg),
            ValidationError::Timeout => write!(f, "Validation timeout"),
            ValidationError::ScriptError(msg) => write!(f, "Script error: {}", msg),
            ValidationError::WasmError(msg) => write!(f, "WASM error: {}", msg),
        }
    }
}

impl std::error::Error for ValidationError {}

impl ValidationResult {
    /// Check if result is Allow or AllowWithModification
    #[allow(dead_code)]
    pub fn is_allowed(&self) -> bool {
        matches!(self, ValidationResult::Allow | ValidationResult::AllowWithModification { .. })
    }

    /// Check if result is Deny or BlacklistIP
    #[allow(dead_code)]
    pub fn is_denied(&self) -> bool {
        matches!(self, ValidationResult::Deny { .. } | ValidationResult::BlacklistIP { .. })
    }

    /// Check if result requires IP blacklisting
    #[allow(dead_code)]
    pub fn should_blacklist_ip(&self) -> bool {
        matches!(self, ValidationResult::BlacklistIP { .. })
    }

    /// Get the IP to blacklist if this result requires blacklisting
    #[allow(dead_code)]
    pub fn get_blacklist_ip(&self) -> Option<IpAddr> {
        match self {
            ValidationResult::BlacklistIP { ip, .. } => Some(*ip),
            _ => None,
        }
    }
}