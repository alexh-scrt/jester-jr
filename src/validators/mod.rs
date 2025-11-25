//! Validator framework for Jester Jr
//!
//! This module provides a flexible, extensible system for request validation
//! with support for built-in validators, Rhai scripts, WASM modules, and
//! dynamic libraries.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │       Validator Registry                │
//! ├─────────────────────────────────────────┤
//! │  • Load validators from config          │
//! │  • Manage validator lifecycle           │
//! │  • Execute validation chains            │
//! └────────┬────────────────────────────────┘
//!          │
//!          ├──> Built-in Validators (JWT, API Key, etc.)
//!          ├──> Rhai Script Validators
//!          ├──> WASM Validators
//!          └──> Dynamic Library Validators
//! ```
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use jester_jr::validators::*;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create registry
//! let mut registry = ValidatorRegistry::new();
//!
//! // Load validators from config
//! registry.load_from_config(&config).await?;
//!
//! // Get a validator
//! let jwt_validator = registry.get("jwt").unwrap();
//!
//! // Validate a request
//! let result = jwt_validator.validate(&context).await?;
//! # Ok(())
//! # }
//! ```

pub mod builtin;
pub mod context;
pub mod registry;
pub mod result;
pub mod script;
pub mod traits;
pub mod wasm;

// Re-export commonly used types
pub use context::{ValidationContext, ValidatorState};
pub use registry::{ValidatorConfig, ValidatorRegistry};
pub use result::{LogLevel, ValidationError, ValidationResult};
pub use traits::{Validator, ValidatorType};