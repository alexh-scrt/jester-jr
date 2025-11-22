//! Configuration module for Jester Jr.
//!
//! This module handles loading TOML-based configuration files and compiling
//! filter rules for request and response filtering.
//!
//! ## Author
//! a13x.h.cc@gmail.com

mod config;

pub use config::{
    Config,
    CompiledRequestRule,
    CompiledResponseRule,
    RuleResult,
};
