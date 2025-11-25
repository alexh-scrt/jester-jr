//! Routing module for path-based request routing
//!
//! Handles matching incoming requests to configured routes
//! and rewriting paths when necessary.

use crate::config::{CompiledListener, CompiledRoute};
use tracing::debug;

/// Result of route matching
pub struct RouteMatch<'a> {
    pub route: &'a CompiledRoute,
    pub rewritten_path: String,
}

/// Match a request path against routes in order
pub fn match_route<'a>(listener: &'a CompiledListener, path: &str) -> Option<RouteMatch<'a>> {
    debug!(
        path,
        routes = listener.routes.len(),
        "Attempting to match route"
    );
    for route in &listener.routes {
        debug!(
            route_name = route.name.as_deref().unwrap_or("unnamed"),
            prefix = ?route.path_prefix,
            regex = route.path_pattern.as_ref().map(|p| p.as_str()),
            "Evaluating route"
        );
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
            debug!(%path, %prefix, "Matched path prefix");
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
            debug!(%path, regex = pattern.as_str(), "Matched regex");
            // Regex matches don't support strip_prefix
            return Some(path.to_string());
        }
    }

    debug!(%path, "No route match");
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
            validators: vec![],
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
            validators: vec![],
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
            validators: vec![],
        };

        assert!(matches_route(&route, "/api/v1/users").is_some());
        assert!(matches_route(&route, "/api/v2/users").is_some());
        assert!(matches_route(&route, "/api/v3/users").is_none());
    }
}
