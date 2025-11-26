//! TLS failure tracking system for detecting repeated handshake failures
//!
//! This module tracks TLS handshake failures per IP address and can trigger
//! automatic blacklisting when failure thresholds are exceeded within a time window.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// TLS failure entry tracking failures for a specific IP
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlsFailureEntry {
    /// IP address
    ip: IpAddr,
    /// Number of consecutive failures
    failure_count: u32,
    /// Timestamp of first failure in current window (Unix timestamp)
    first_failure_at: u64,
    /// Timestamp of most recent failure (Unix timestamp)
    last_failure_at: u64,
    /// Types of TLS errors encountered
    error_types: Vec<String>,
}

impl TlsFailureEntry {
    fn new(ip: IpAddr, error_type: String) -> Self {
        let now = current_timestamp();
        Self {
            ip,
            failure_count: 1,
            first_failure_at: now,
            last_failure_at: now,
            error_types: vec![error_type],
        }
    }

    /// Add a new failure, potentially resetting the window if too much time has passed
    fn add_failure(&mut self, error_type: String, time_window_minutes: u32) {
        let now = current_timestamp();
        let window_seconds = (time_window_minutes as u64) * 60;

        // If this failure is outside the time window, reset the tracking
        if now > self.first_failure_at + window_seconds {
            debug!("Resetting failure window for IP {} - outside time window", self.ip);
            self.failure_count = 1;
            self.first_failure_at = now;
            self.error_types.clear();
            self.error_types.push(error_type);
        } else {
            // Within time window, increment failure count
            self.failure_count += 1;
            self.error_types.push(error_type);
            
            // Keep only last 10 error types to prevent memory bloat
            if self.error_types.len() > 10 {
                self.error_types.remove(0);
            }
        }
        
        self.last_failure_at = now;
    }

    /// Check if this entry has exceeded the failure threshold within the time window
    fn exceeds_threshold(&self, max_attempts: u32, time_window_minutes: u32) -> bool {
        let now = current_timestamp();
        let window_seconds = (time_window_minutes as u64) * 60;
        
        // Check if we're still within the time window
        let within_window = now <= self.first_failure_at + window_seconds;
        let exceeds_count = self.failure_count >= max_attempts;
        
        within_window && exceeds_count
    }

    /// Check if this entry is expired and can be cleaned up
    fn is_expired(&self, time_window_minutes: u32) -> bool {
        let now = current_timestamp();
        let window_seconds = (time_window_minutes as u64) * 60;
        
        // Entry is expired if the most recent failure is outside the time window
        now > self.last_failure_at + window_seconds
    }
}

/// Configuration for TLS failure tracking
#[derive(Debug, Clone)]
pub struct TlsFailureConfig {
    /// Enable TLS failure tracking and blacklisting
    pub enabled: bool,
    /// Maximum number of failures before blacklisting
    pub max_attempts: u32,
    /// Time window in minutes for counting failures
    pub time_window_minutes: u32,
    /// TTL in hours for blacklist entries created from TLS failures
    pub blacklist_ttl_hours: u32,
}

impl Default for TlsFailureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_attempts: 3,
            time_window_minutes: 5,
            blacklist_ttl_hours: 24,
        }
    }
}

/// Thread-safe TLS failure tracker
#[derive(Debug)]
pub struct TlsFailureTracker {
    /// Failure entries by IP address
    failures: Arc<RwLock<HashMap<IpAddr, TlsFailureEntry>>>,
    /// Configuration
    config: TlsFailureConfig,
    /// Last cleanup time
    last_cleanup: Arc<RwLock<u64>>,
}

impl TlsFailureTracker {
    /// Create a new TLS failure tracker
    pub fn new(config: TlsFailureConfig) -> Self {
        Self {
            failures: Arc::new(RwLock::new(HashMap::new())),
            config,
            last_cleanup: Arc::new(RwLock::new(current_timestamp())),
        }
    }

    /// Record a TLS failure for an IP address
    /// 
    /// Returns true if the IP should be blacklisted (threshold exceeded)
    pub fn record_failure(&self, ip: IpAddr, error_type: String) -> bool {
        if !self.config.enabled {
            return false;
        }

        let mut failures = self.failures.write();
        
        match failures.get_mut(&ip) {
            Some(entry) => {
                debug!("Recording additional TLS failure for IP {}: {}", ip, error_type);
                entry.add_failure(error_type, self.config.time_window_minutes);
                
                let should_blacklist = entry.exceeds_threshold(
                    self.config.max_attempts, 
                    self.config.time_window_minutes
                );
                
                if should_blacklist {
                    warn!(
                        "🚫 IP {} exceeded TLS failure threshold: {} failures in {} minutes. Error types: {:?}",
                        ip,
                        entry.failure_count,
                        self.config.time_window_minutes,
                        entry.error_types
                    );
                    
                    // Remove the entry since we're blacklisting (no need to track further)
                    failures.remove(&ip);
                }
                
                should_blacklist
            },
            None => {
                debug!("Recording first TLS failure for IP {}: {}", ip, error_type);
                let entry = TlsFailureEntry::new(ip, error_type);
                failures.insert(ip, entry);
                
                // First failure never triggers blacklist
                false
            }
        }
    }

    /// Get current failure count for an IP
    #[allow(dead_code)]
    pub fn get_failure_count(&self, ip: IpAddr) -> u32 {
        let failures = self.failures.read();
        failures.get(&ip).map(|e| e.failure_count).unwrap_or(0)
    }

    /// Get all tracked IPs and their failure counts (for debugging/monitoring)
    #[allow(dead_code)]
    pub fn get_all_failures(&self) -> HashMap<IpAddr, (u32, Vec<String>)> {
        let failures = self.failures.read();
        failures
            .iter()
            .map(|(ip, entry)| (*ip, (entry.failure_count, entry.error_types.clone())))
            .collect()
    }

    /// Clean up expired failure entries
    /// This should be called periodically to prevent memory leaks
    pub fn cleanup_expired(&self) {
        let mut last_cleanup = self.last_cleanup.write();
        let now = current_timestamp();
        
        // Only cleanup every 5 minutes to avoid excessive overhead
        if now < *last_cleanup + 300 {
            return;
        }
        
        let mut failures = self.failures.write();
        let initial_count = failures.len();
        
        failures.retain(|ip, entry| {
            let expired = entry.is_expired(self.config.time_window_minutes);
            if expired {
                debug!("Cleaning up expired TLS failure entry for IP {}", ip);
            }
            !expired
        });
        
        let removed_count = initial_count - failures.len();
        if removed_count > 0 {
            info!("🧹 Cleaned up {} expired TLS failure entries", removed_count);
        }
        
        *last_cleanup = now;
    }

    /// Get configuration
    pub fn config(&self) -> &TlsFailureConfig {
        &self.config
    }

    /// Update configuration (useful for runtime config changes)
    #[allow(dead_code)]
    pub fn update_config(&mut self, config: TlsFailureConfig) {
        info!("📝 Updating TLS failure tracker config: enabled={}, max_attempts={}, window={}min", 
               config.enabled, config.max_attempts, config.time_window_minutes);
        self.config = config;
        
        // If disabled, clear all tracking
        if !self.config.enabled {
            let mut failures = self.failures.write();
            failures.clear();
            info!("🧹 Cleared all TLS failure tracking (disabled)");
        }
    }

    /// Get statistics about current tracking
    #[allow(dead_code)]
    pub fn get_stats(&self) -> TlsFailureStats {
        let failures = self.failures.read();
        let total_tracked_ips = failures.len();
        let total_failures: u32 = failures.values().map(|e| e.failure_count).sum();
        
        TlsFailureStats {
            enabled: self.config.enabled,
            tracked_ips: total_tracked_ips,
            total_failures,
            max_attempts: self.config.max_attempts,
            time_window_minutes: self.config.time_window_minutes,
        }
    }
}

/// Statistics about TLS failure tracking
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct TlsFailureStats {
    pub enabled: bool,
    pub tracked_ips: usize,
    pub total_failures: u32,
    pub max_attempts: u32,
    pub time_window_minutes: u32,
}

/// Get current Unix timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

/// TLS error classification for better tracking
pub fn classify_tls_error(error: &str) -> String {
    if error.contains("InvalidContentType") {
        "InvalidContentType".to_string()
    } else if error.contains("Connection closed") || error.contains("UnexpectedEof") {
        "ConnectionClosed".to_string()
    } else if error.contains("timeout") || error.contains("TimedOut") {
        "Timeout".to_string()
    } else if error.contains("InvalidData") {
        "InvalidData".to_string()
    } else if error.contains("handshake") {
        "HandshakeError".to_string()
    } else {
        "Other".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread;
    use std::time::Duration;

    fn create_test_tracker() -> TlsFailureTracker {
        let config = TlsFailureConfig {
            enabled: true,
            max_attempts: 3,
            time_window_minutes: 1, // 1 minute for faster testing
            blacklist_ttl_hours: 1,
        };
        TlsFailureTracker::new(config)
    }

    #[test]
    fn test_single_failure_no_blacklist() {
        let tracker = create_test_tracker();
        let ip = Ipv4Addr::new(192, 168, 1, 100).into();
        
        let should_blacklist = tracker.record_failure(ip, "TestError".to_string());
        assert!(!should_blacklist);
        assert_eq!(tracker.get_failure_count(ip), 1);
    }

    #[test]
    fn test_threshold_exceeded() {
        let tracker = create_test_tracker();
        let ip = Ipv4Addr::new(192, 168, 1, 100).into();
        
        // Record failures up to threshold
        assert!(!tracker.record_failure(ip, "Error1".to_string()));
        assert_eq!(tracker.get_failure_count(ip), 1);
        
        assert!(!tracker.record_failure(ip, "Error2".to_string()));
        assert_eq!(tracker.get_failure_count(ip), 2);
        
        // Third failure should trigger blacklisting
        assert!(tracker.record_failure(ip, "Error3".to_string()));
        
        // After blacklisting, entry should be removed
        assert_eq!(tracker.get_failure_count(ip), 0);
    }

    #[test]
    fn test_disabled_tracker() {
        let config = TlsFailureConfig {
            enabled: false,
            ..TlsFailureConfig::default()
        };
        let tracker = TlsFailureTracker::new(config);
        let ip = Ipv4Addr::new(192, 168, 1, 100).into();
        
        // Should never blacklist when disabled
        for _ in 0..10 {
            assert!(!tracker.record_failure(ip, "Error".to_string()));
        }
        assert_eq!(tracker.get_failure_count(ip), 0);
    }

    #[test]
    fn test_error_classification() {
        assert_eq!(classify_tls_error("received corrupt message of type InvalidContentType"), "InvalidContentType");
        assert_eq!(classify_tls_error("Connection closed during handshake"), "ConnectionClosed");
        assert_eq!(classify_tls_error("TLS handshake timeout"), "Timeout");
        assert_eq!(classify_tls_error("Some other error"), "Other");
    }

    #[test]
    fn test_stats() {
        let tracker = create_test_tracker();
        let ip1 = Ipv4Addr::new(192, 168, 1, 1).into();
        let ip2 = Ipv4Addr::new(192, 168, 1, 2).into();
        
        tracker.record_failure(ip1, "Error1".to_string());
        tracker.record_failure(ip1, "Error2".to_string());
        tracker.record_failure(ip2, "Error1".to_string());
        
        let stats = tracker.get_stats();
        assert!(stats.enabled);
        assert_eq!(stats.tracked_ips, 2);
        assert_eq!(stats.total_failures, 3);
        assert_eq!(stats.max_attempts, 3);
        assert_eq!(stats.time_window_minutes, 1);
    }
}