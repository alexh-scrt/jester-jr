//! HTTP response parsing and filtering.
//!
//! This module provides the `HttpResponse` type which parses HTTP/1.1 response
//! headers while leaving the body in the stream for efficient proxying.
//!
//! ## Author
//! a13x.h.cc@gmail.com

use std::collections::HashMap;
use std::io::BufRead;
use crate::config::{CompiledResponseRule, RuleResult};

/// Represents a parsed HTTP response with headers and metadata.
///
/// This structure contains the parsed components of an HTTP response including
/// the status line (version, status code, status text) and all headers. The raw
/// header bytes are preserved for efficient forwarding to the client.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub raw_headers: Vec<u8>,  // Original header bytes for forwarding
    pub content_length: Option<usize>,
}

impl HttpResponse {
    /// Parse HTTP response from a buffered reader
    /// Reads ONLY the headers, leaving the body in the stream for streaming
    pub fn parse<R: BufRead>(reader: &mut R) -> Result<Self, String> {
        let mut raw_headers = Vec::new();
        let mut lines = Vec::new();

        // Read lines until we hit the empty line
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => return Err("Connection closed while reading response headers".to_string()),
                Ok(_) => {
                    raw_headers.extend_from_slice(line.as_bytes());

                    if line == "\r\n" || line == "\n" {
                        break;
                    }

                    lines.push(line.trim_end().to_string());
                }
                Err(e) => return Err(format!("Error reading response headers: {}", e)),
            }
        }

        if lines.is_empty() {
            return Err("Empty response".to_string());
        }

        // Parse the status line: "HTTP/1.1 200 OK"
        let status_line_parts: Vec<&str> = lines[0].splitn(3, ' ').collect();
        if status_line_parts.len() < 3 {
            return Err("Invalid status line".to_string());
        }

        let version = status_line_parts[0].to_string();
        let status_code = status_line_parts[1].parse::<u16>()
            .map_err(|_| "Invalid status code")?;
        let status_text = status_line_parts[2].to_string();

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
        let content_length = headers.get("content-length")
            .and_then(|v| v.parse::<usize>().ok());

        Ok(HttpResponse {
            version,
            status_code,
            status_text,
            headers,
            raw_headers,
            content_length,
        })
    }

    /// Check if this response should be allowed based on filtering rules
    pub fn should_allow(&self, rules: &[CompiledResponseRule]) -> Result<(), String> {
        // If no rules, allow by default
        if rules.is_empty() {
            return Ok(());
        }

        // Evaluate each rule in order
        for rule in rules {
            match rule.evaluate(self.status_code, self.content_length) {
                RuleResult::Allow => {
                    return Ok(());  // Explicitly allowed
                }
                RuleResult::Deny(reason) => {
                    return Err(reason);  // Denied with reason
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

    /// Check if response has a body
    pub fn has_body(&self) -> bool {
        // Responses to HEAD requests have no body
        // 1xx, 204, and 304 responses have no body
        if self.status_code < 200 || self.status_code == 204 || self.status_code == 304 {
            return false;
        }

        self.content_length.is_some() && self.content_length.unwrap() > 0
    }
}
