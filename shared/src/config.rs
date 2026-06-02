//! Server Configuration — loads and manages FreeMode server config.
//! 
//! Implements FiveM-style server configuration with slots, ports, password, etc.

use serde::{Deserialize, Serialize};
use std::fs;

// ============================================================================
// Types
// ============================================================================

/// Server configuration loaded from config.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server display name.
    pub name: String,
    /// Number of player slots.
    pub slots: u32,
    /// Maximum number of players.
    pub max_players: u32,
    /// Base network port.
    pub base_port: u32,
    /// Server password (empty = no password).
    pub password: String,
    /// Country code (e.g., "US", "UK").
    pub country_code: String,
    /// Locale timezone (e.g., "UTC").
    #[serde(default = "default_time_zone")]
    pub locale_time_zone: String,
    /// Locale language (e.g., "en").
    #[serde(default = "default_language")]
    pub locale_language: String,
    /// Resources directory path.
    #[serde(default = "default_resources_dir")]
    pub resources_dir: String,
    /// Optional hostname for discovery.
    pub hostname: Option<String>,
}

// ============================================================================
// Default values
// ============================================================================

fn default_time_zone() -> String {
    "UTC".to_string()
}

fn default_language() -> String {
    "en".to_string()
}

fn default_resources_dir() -> String {
    "resources".to_string()
}

// ============================================================================
// Public API
// ============================================================================

/// Loads server configuration from a JSON file.
pub fn load_config(path: &str) -> Result<ServerConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file '{}': {}", path, e))?;

    let config: ServerConfig = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse config file '{}': {}", path, e))?;

    Ok(config)
}

/// Creates a default server configuration.
pub fn default_config() -> ServerConfig {
    ServerConfig {
        name: "FreeMode Server".to_string(),
        slots: 32,
        max_players: 32,
        base_port: 30120,
        password: "".to_string(),
        country_code: "US".to_string(),
        locale_time_zone: default_time_zone(),
        locale_language: default_language(),
        resources_dir: default_resources_dir(),
        hostname: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = default_config();
        assert_eq!(config.name, "FreeMode Server");
        assert_eq!(config.slots, 32);
        assert_eq!(config.base_port, 30120);
    }
}