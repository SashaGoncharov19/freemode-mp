//! FreeMode Launcher — Entry point and orchestration.
//! 
//! Orchestrates the launcher workflow: game path detection, executable loading,
//! GUI display, and server connection management.
//!
//! All config/servers.json loading is non-fatal — missing files never crash the game.

mod game_path;
mod gui;

use freemode_sdk::crypto;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ============================================================================
// Main entry point
// ============================================================================

fn main() {
    // Initialize logging to file (never panics).
    if let Err(e) = freemode_log::init_logger() {
        eprintln!("Failed to init logger: {}", e);
    }

    freemode_log::info!("FreeMode Launcher starting...");

    // Load configuration safely — always succeeds.
    let config_path = config_file_path();
    let config_json = freemode_log::load_config_safely(&config_path);
    
    // Find game path (uses platform registry keys).
    let game_path = game_path::find_game_path();

    if let Some(ref gp) = game_path {
        freemode_log::info!("Game path detected: {}", gp.display());

        // Verify game executable exists.
        let gta5_exe = gp.join("GTA5.exe");
        if gta5_exe.exists() {
            freemode_log::info!("GTA5.exe found at: {}", gta5_exe.display());
            
            // Get build info for this GTA5 version.
            let build_info = game_path::get_game_build(&gta5_exe);
            if let Some(ref bi) = build_info {
                freemode_log::info!("Game build detected: {} (build {})", bi.game_version, bi.build_number);
            } else {
                freemode_log::warn!("Could not determine game build — using defaults");
            }
        } else {
            freemode_log::error!("GTA5.exe NOT FOUND at {}", gta5_exe.display());
        }
    } else {
        freemode_log::critical!("No GTA V installation detected. Please set the game path in config.");
        std::process::exit(1);
    }

    // Load server list safely — returns defaults if missing/invalid.
    let servers_path = PathBuf::from("servers.json");
    let server_list_json = freemode_log::read_servers_json(&servers_path);
    
    let server_count = match &server_list_json {
        Some(list) => list.len(),
        None => {
            // Use built-in default.
            freemode_log::load!("Using default server (no servers.json found)");
            1
        }
    };
    
    freemode_log::info!("Server list loaded: {} servers available", server_count);

    // Run the launcher GUI.
    let game_path = game_path.unwrap_or_else(|| PathBuf::from("."));
    let server_entries = server_list_json
        .map(|list| {
            list.into_iter()
                .filter_map(|v| {
                    let name = v.get("name")?.as_str()?.to_string();
                    let ip = v.get("ip")?.as_str()?.to_string();
                    let port = v.get("port")?.as_u64()? as u16;
                    Some(crate::ServerEntry { name, ip, port, icon: None })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![crate::ServerEntry {
            name: "FreeMode Main".to_string(),
            ip: "127.0.0.1".to_string(),
            port: 30120,
            icon: None,
        }]);

    gui::run_launcher_gui(game_path.clone(), server_entries);
}

// ============================================================================
// Configuration
// ============================================================================

/// Launcher configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to GTA V installation.
    pub game_path: Option<String>,
    /// Selected server address.
    pub selected_server: Option<String>,
    /// Whether to auto-start on Windows login.
    pub autorun: bool,
    /// Launcher theme ("dark" or "light").
    pub theme: String,
    /// Last connected server address.
    pub last_server: Option<String>,
}

impl Config {
    /// Loads configuration from disk or creates defaults — never panics.
    pub fn load_or_default() -> Self {
        let config_path = config_file_path();

        if let Some(value) = freemode_log::read_config_json(&config_path) {
            if let Ok(game_path) = value.get("game_path") {
                // Parse successfully.
            }
            return serde_json::from_value(value).unwrap_or_else(|_| Self::default());
        }

        Self::default()
    }

    /// Saves configuration to disk — never panics.
    pub fn save(&self) {
        let config_path = config_file_path();

        if let Ok(contents) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(config_path, contents);
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            game_path: None,
            selected_server: None,
            autorun: false,
            theme: "dark".to_string(),
            last_server: None,
        }
    }
}

/// Returns the path to the configuration file (stored next to launcher executable).
fn config_file_path() -> PathBuf {
    // Store config next to the launcher executable for portability.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let mut p = dir.to_path_buf();
            p.push("config.json");
            return p;
        }
    }
    // Fallback: user config directory.
    dirs::config_dir().map(|d| d.join("freemode").join("config.json"))
        .unwrap_or_else(|| PathBuf::from("config.json"))
}

// ============================================================================
// Server list
// ============================================================================

/// A single server entry in the server list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    /// Display name of the server.
    pub name: String,
    /// IP address or hostname.
    pub ip: String,
    /// Port number.
    pub port: u16,
    /// Optional icon URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

// ============================================================================
// Utility functions
// ============================================================================

/// Computes SHA256 hash of a file for integrity verification — returns None on any error.
pub fn file_sha256(path: &Path) -> Option<Vec<u8>> {
    if !path.exists() {
        freemode_log::debug!("File not found for hash: {}", path.display());
        return None;
    }

    match std::fs::read(path) {
        Ok(contents) => {
            let mut hasher = crypto::sha256::Sha256Hasher::new();
            Some(hasher.compute(&contents))
        }
        Err(e) => {
            freemode_log::error!("Failed to read file for hash: {}: {}", path.display(), e);
            None
        }
    }
}

/// Logs a DLL injection event — used by the injector module.
pub fn log_inject_event(step: &str, details: &str) {
    freemode_log::inject!("{} — {}", step, details);
}

/// Logs a DLL load event with success/failure status.
pub fn log_dll_load_result(dll_name: &str, success: bool, details: &str) {
    if success {
        freemode_log::load!("Loaded {} — {}", dll_name, details);
    } else {
        freemode_log::error!("Failed to load {} — {}", dll_name, details);
    }
}

/// Logs a hook result.
pub fn log_hook_result(func_name: &str, success: bool, details: &str) {
    if success {
        freemode_log::hook!("Hooked {} — {}", func_name, details);
    } else {
        freemode_log::error!("Failed to hook {} — {}", func_name, details);
    }
}