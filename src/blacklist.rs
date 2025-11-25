//! IP blacklist management with persistence and TTL support

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

/// Blacklist entry with expiration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlacklistEntry {
    /// IP address
    ip: IpAddr,
    /// Reason for blacklisting
    reason: String,
    /// When this entry was created (Unix timestamp)
    created_at: u64,
    /// When this entry expires (Unix timestamp), None for permanent
    expires_at: Option<u64>,
}

/// Persistent blacklist data structure
#[derive(Debug, Serialize, Deserialize)]
struct BlacklistData {
    entries: Vec<BlacklistEntry>,
}

/// Thread-safe IP blacklist manager
#[derive(Debug)]
pub struct IpBlacklist {
    /// Active blacklist entries (IP -> Entry)
    entries: Arc<RwLock<HashMap<IpAddr, BlacklistEntry>>>,
    /// File path for persistence
    file_path: String,
    /// Default TTL in hours for new entries
    default_ttl_hours: Option<u32>,
}

impl IpBlacklist {
    /// Create a new IP blacklist
    pub fn new(file_path: String, default_ttl_hours: Option<u32>) -> Self {
        let blacklist = Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            file_path,
            default_ttl_hours,
        };

        // Load existing blacklist from file
        if let Err(e) = blacklist.load_from_file() {
            warn!("Failed to load blacklist from file: {}", e);
        }

        blacklist
    }

    /// Check if an IP is blacklisted
    pub fn is_blacklisted(&self, ip: IpAddr) -> bool {
        let entries = self.entries.read();
        
        if let Some(entry) = entries.get(&ip) {
            // Check if entry has expired
            if let Some(expires_at) = entry.expires_at {
                let now = current_timestamp();
                if now >= expires_at {
                    // Entry expired, but don't remove here to avoid write lock
                    // Cleanup will happen in background or on next save
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    /// Add an IP to the blacklist
    pub fn add_ip(&self, ip: IpAddr, reason: String, ttl_hours: Option<u32>) -> Result<(), String> {
        let now = current_timestamp();
        let ttl_to_use = ttl_hours.or(self.default_ttl_hours);
        let expires_at = ttl_to_use.map(|hours| now + (hours as u64 * 3600));

        let entry = BlacklistEntry {
            ip,
            reason: reason.clone(),
            created_at: now,
            expires_at,
        };

        {
            let mut entries = self.entries.write();
            entries.insert(ip, entry);
        }

        info!("🚫 Blacklisted IP {}: {}", ip, reason);
        
        // Persist to file
        if let Err(e) = self.save_to_file() {
            error!("Failed to persist blacklist: {}", e);
            return Err(format!("Failed to persist blacklist: {}", e));
        }

        Ok(())
    }

    /// Remove an IP from the blacklist
    pub fn remove_ip(&self, ip: IpAddr) -> bool {
        let removed = {
            let mut entries = self.entries.write();
            entries.remove(&ip).is_some()
        };

        if removed {
            info!("✅ Removed IP {} from blacklist", ip);
            if let Err(e) = self.save_to_file() {
                error!("Failed to persist blacklist after removal: {}", e);
            }
        }

        removed
    }

    /// Get all blacklisted IPs (for monitoring/debugging)
    pub fn get_blacklisted_ips(&self) -> Vec<IpAddr> {
        let entries = self.entries.read();
        let now = current_timestamp();
        
        entries
            .values()
            .filter(|entry| {
                // Filter out expired entries
                entry.expires_at.map_or(true, |expires_at| now < expires_at)
            })
            .map(|entry| entry.ip)
            .collect()
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&self) -> usize {
        let now = current_timestamp();
        let mut removed_count = 0;

        {
            let mut entries = self.entries.write();
            let initial_count = entries.len();
            
            entries.retain(|_ip, entry| {
                if let Some(expires_at) = entry.expires_at {
                    if now >= expires_at {
                        debug!("Removing expired blacklist entry for IP {}", entry.ip);
                        return false;
                    }
                }
                true
            });
            
            removed_count = initial_count - entries.len();
        }

        if removed_count > 0 {
            info!("🧹 Cleaned up {} expired blacklist entries", removed_count);
            if let Err(e) = self.save_to_file() {
                error!("Failed to persist blacklist after cleanup: {}", e);
            }
        }

        removed_count
    }

    /// Get blacklist statistics
    pub fn stats(&self) -> BlacklistStats {
        let entries = self.entries.read();
        let now = current_timestamp();
        let total = entries.len();
        let expired = entries
            .values()
            .filter(|entry| {
                entry.expires_at.map_or(false, |expires_at| now >= expires_at)
            })
            .count();
        let active = total - expired;

        BlacklistStats {
            total_entries: total,
            active_entries: active,
            expired_entries: expired,
        }
    }

    /// Load blacklist from file
    fn load_from_file(&self) -> Result<(), String> {
        let path = Path::new(&self.file_path);
        
        if !path.exists() {
            debug!("Blacklist file doesn't exist, starting with empty blacklist");
            return Ok(());
        }

        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read blacklist file: {}", e))?;

        if content.trim().is_empty() {
            debug!("Blacklist file is empty");
            return Ok(());
        }

        let data: BlacklistData = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse blacklist file: {}", e))?;

        let mut loaded_count = 0;
        let now = current_timestamp();

        {
            let mut entries = self.entries.write();
            entries.clear();

            for entry in data.entries {
                // Skip expired entries during load
                if let Some(expires_at) = entry.expires_at {
                    if now >= expires_at {
                        debug!("Skipping expired entry for IP {} during load", entry.ip);
                        continue;
                    }
                }

                entries.insert(entry.ip, entry);
                loaded_count += 1;
            }
        }

        info!("📁 Loaded {} entries from blacklist file", loaded_count);
        Ok(())
    }

    /// Save blacklist to file
    fn save_to_file(&self) -> Result<(), String> {
        // Create directory if it doesn't exist
        let path = Path::new(&self.file_path);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("Failed to create blacklist directory: {}", e))?;
        }

        let entries: Vec<BlacklistEntry> = {
            let entries_guard = self.entries.read();
            entries_guard.values().cloned().collect()
        };

        let data = BlacklistData { entries };

        let json = serde_json::to_string_pretty(&data)
            .map_err(|e| format!("Failed to serialize blacklist: {}", e))?;

        // Use atomic write by writing to temporary file first
        let temp_path = format!("{}.tmp", self.file_path);
        std::fs::write(&temp_path, json)
            .map_err(|e| format!("Failed to write temporary blacklist file: {}", e))?;

        std::fs::rename(&temp_path, &self.file_path)
            .map_err(|e| format!("Failed to rename temporary blacklist file: {}", e))?;

        debug!("💾 Saved blacklist to file: {}", self.file_path);
        Ok(())
    }
}

/// Blacklist statistics
#[derive(Debug)]
pub struct BlacklistStats {
    pub total_entries: usize,
    pub active_entries: usize,
    pub expired_entries: usize,
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tempfile::NamedTempFile;

    #[test]
    fn test_blacklist_basic_operations() {
        let temp_file = NamedTempFile::new().unwrap();
        let blacklist = IpBlacklist::new(temp_file.path().to_string_lossy().to_string(), None);

        let test_ip: IpAddr = Ipv4Addr::new(192, 168, 1, 100).into();

        // Initially not blacklisted
        assert!(!blacklist.is_blacklisted(test_ip));

        // Add to blacklist
        blacklist.add_ip(test_ip, "Test reason".to_string(), None).unwrap();
        assert!(blacklist.is_blacklisted(test_ip));

        // Remove from blacklist
        assert!(blacklist.remove_ip(test_ip));
        assert!(!blacklist.is_blacklisted(test_ip));

        // Can't remove again
        assert!(!blacklist.remove_ip(test_ip));
    }

    #[test]
    fn test_blacklist_persistence() {
        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path().to_string_lossy().to_string();
        let test_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

        // Create blacklist and add entry
        {
            let blacklist = IpBlacklist::new(file_path.clone(), None);
            blacklist.add_ip(test_ip, "Persistent test".to_string(), None).unwrap();
            assert!(blacklist.is_blacklisted(test_ip));
        }

        // Create new blacklist instance - should load from file
        {
            let blacklist = IpBlacklist::new(file_path, None);
            assert!(blacklist.is_blacklisted(test_ip));
        }
    }
}