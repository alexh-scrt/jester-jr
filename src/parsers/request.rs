//! HTTP request parsing and filtering.
//!
//! This module provides the `HttpRequest` type which parses HTTP/1.1 request
//! headers while leaving the body in the stream for efficient proxying.
//!
//! ## Author
//! a13x.h.cc@gmail.com

use crate::config::{CompiledRequestRule, RuleResult};
use std::collections::HashMap;
use std::io::BufRead;
use tracing::{debug, warn};

/// Represents a parsed HTTP request with headers and metadata.
///
/// This structure contains the parsed components of an HTTP request including
/// the request line (method, path, version) and all headers. The raw header
/// bytes are preserved for efficient forwarding to the backend server.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub raw_headers: Vec<u8>, // Original header bytes for forwarding
    pub content_length: Option<usize>,
}

impl HttpRequest {
    /// Parse HTTP request from a buffered reader
    /// Reads ONLY the headers, leaving the body in the stream for streaming
    #[tracing::instrument(skip(reader), level = "debug")]
    pub fn parse<R: BufRead>(reader: &mut R) -> Result<Self, String> {
        let mut raw_headers = Vec::new();
        let mut lines = Vec::new();
        debug!("Starting HTTP request parse");

        // Read lines until we hit the empty line that separates headers from body
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => return Err("Connection closed while reading headers".to_string()),
                Ok(_) => {
                    // Store raw bytes for forwarding
                    raw_headers.extend_from_slice(line.as_bytes());

                    // Check if we've reached the end of headers
                    if line == "\r\n" || line == "\n" {
                        break;
                    }

                    lines.push(line.trim_end().to_string());
                }
                Err(e) => {
                    warn!(error = ?e, "Error reading headers");
                    return Err(format!("Error reading headers: {}", e));
                }
            }
        }

        if lines.is_empty() {
            return Err("Empty request".to_string());
        }

        // Parse the request line: "GET /path HTTP/1.1"
        let request_line_parts: Vec<&str> = lines[0].split_whitespace().collect();
        if request_line_parts.len() < 3 {
            return Err("Invalid request line".to_string());
        }

        let method = request_line_parts[0].to_string();
        let path = request_line_parts[1].to_string();
        let version = request_line_parts[2].to_string();
        debug!(%method, %path, %version, header_lines = lines.len().saturating_sub(1), "Parsed request line");

        // Parse headers
        let mut headers = HashMap::new();
        for line in &lines[1..] {
            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(key.to_lowercase(), value);
            }
        }

        // Extract Content-Length if present
        let content_length = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok());

        Ok(HttpRequest {
            method,
            path,
            version,
            headers,
            raw_headers,
            content_length,
        })
    }

    /// Check if this request should be allowed based on filtering rules
    /// Evaluates rules in order, first matching rule wins
    pub fn should_allow(&self, rules: &[CompiledRequestRule]) -> Result<(), String> {
        // If no rules, allow by default
        if rules.is_empty() {
            return Ok(());
        }

        // Evaluate each rule in order
        for rule in rules {
            match rule.evaluate(&self.method, &self.path, &self.headers) {
                RuleResult::Allow => {
                    return Ok(()); // Explicitly allowed
                }
                RuleResult::Deny(reason) => {
                    return Err(reason); // Denied with reason
                }
                RuleResult::Continue => {
                    // Rule doesn't apply, check next rule
                    continue;
                }
            }
        }

        // No rules matched - default is to allow
        Ok(())
    }

    /// Get a specific header value
    #[allow(unused)]
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(&name.to_lowercase())
    }

    /// Check if request has a body
    pub fn has_body(&self) -> bool {
        self.content_length.is_some() && self.content_length.unwrap() > 0
    }
}
