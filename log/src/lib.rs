//! FreeMode MP injection logger — logs all inject, load, hook steps to file.
//!
//! Writes structured logs to `<launcher_folder>/freemode-inject.log` so that:
//! - Missing config.json or servers.json does NOT crash the game
//! - Every inject step, DLL load, and hook attempt is recorded
//! - Even if logging fails, it never panics — all errors are caught internally

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::Local;
use once_cell::sync::Lazy;

// ============================================================================
// Log levels for injection diagnostics
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Inject,
    Load,
    Hook,
    Warning,
    Error,
    Critical,
}

impl LogLevel {
    pub fn tag(&self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => " INFO ",
            LogLevel::Inject => "INJECT",
            LogLevel::Load => "LOAD  ",
            LogLevel::Hook => "HOOK  ",
            LogLevel::Warning => " WARN ",
            LogLevel::Error => " ERROR ",
            LogLevel::Critical => "CRITC",
        }
    }
}

// ============================================================================
// Logger singleton — file-based logging
// ============================================================================

static LOGGER: Lazy<Mutex<Option<FileLogger>>> = Lazy::new(|| Mutex::new(None));

pub struct FileLogger {
    log_path: PathBuf,
    file: Option<File>,
}

impl FileLogger {
    pub fn new(log_path: PathBuf) -> Self {
        Self { log_path, file: None }
    }

    fn open_file(&mut self) -> Result<(), String> {
        if self.file.is_some() { return Ok(()); }
        match OpenOptions::new().create(true).append(true).open(&self.log_path) {
            Ok(f) => { self.file = Some(f); Ok(()) }
            Err(e) => Err(format!("Failed to open log file '{}': {}", self.log_path.display(), e)),
        }
    }

    pub fn log(&mut self, level: LogLevel, message: &str) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        if self.file.is_none() { let _ = self.open_file(); }
        let entry = format!("[{}] [{}] {}\n", timestamp, level.tag(), message);
        eprint!("{}", entry);
        if let Some(ref mut file) = self.file {
            let _ = file.write_all(entry.as_bytes());
        }
    }
}

// ============================================================================
// Public logging API
// ============================================================================

pub fn init_logger() -> Result<(), String> {
    let log_path = get_log_file_path();
    let mut logger = LOGGER.lock().unwrap();
    *logger = Some(FileLogger::new(log_path.clone()));
    write(LogLevel::Info, &format!("Logging initialized: {}", log_path.display()));
    Ok(())
}

pub fn write(level: LogLevel, message: &str) {
    let mut logger = LOGGER.lock().unwrap();
    if let Some(ref mut l) = *logger {
        l.log(level, message);
    } else {
        eprintln!("[{}] {}", level.tag(), message);
    }
}

pub fn get_log_file_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("freemode-inject.log")))
        .unwrap_or_else(|| PathBuf::from("freemode-inject.log"))
}

// ============================================================================
// Convenience macros
// ============================================================================

#[macro_export] macro_rules! info { ($($arg:tt)*) => { let msg = format!($($arg)*); $crate::write($crate::LogLevel::Info, &msg); } }
#[macro_export] macro_rules! debug { ($($arg:tt)*) => { let msg = format!($($arg)*); $crate::write($crate::LogLevel::Debug, &msg); } }
#[macro_export] macro_rules! inject { ($($arg:tt)*) => { let msg = format!($($arg)*); $crate::write($crate::LogLevel::Inject, &msg); } }
#[macro_export] macro_rules! load { ($($arg:tt)*) => { let msg = format!($($arg)*); $crate::write($crate::LogLevel::Load, &msg); } }
#[macro_export] macro_rules! hook { ($($arg:tt)*) => { let msg = format!($($arg)*); $crate::write($crate::LogLevel::Hook, &msg); } }
#[macro_export] macro_rules! warn { ($($arg:tt)*) => { let msg = format!($($arg)*); $crate::write($crate::LogLevel::Warning, &msg); } }
#[macro_export] macro_rules! error { ($($arg:tt)*) => { let msg = format!($($arg)*); $crate::write($crate::LogLevel::Error, &msg); } }
#[macro_export] macro_rules! critical { ($($arg:tt)*) => { let msg = format!($($arg)*); $crate::write($crate::LogLevel::Critical, &msg); } }

// ============================================================================
// Safe wrappers for file operations (never panics)
// ============================================================================

pub fn read_config_json(path: &std::path::Path) -> Option<serde_json::Value> {
    std::fs::read_to_string(path).ok().and_then(|contents| {
        serde_json::from_str(&contents).ok()
    }).or_else(|| {
        debug!("Config file not found (safe, using defaults): {}", path.display());
        None
    })
}

pub fn read_servers_json(path: &std::path::Path) -> Option<Vec<serde_json::Value>> {
    std::fs::read_to_string(path).ok().and_then(|contents| {
        serde_json::from_str(&contents).ok()
    }).or_else(|| {
        debug!("Servers file not found (safe, using defaults): {}", path.display());
        None
    })
}

pub fn load_config_safely(config_path: &std::path::Path) -> serde_json::Value {
    read_config_json(config_path).unwrap_or_else(|| {
        info!("Using default config (no valid config.json found)");
        serde_json::json!({"game_path":null,"selected_server":null,"autorun":false,"theme":"dark","last_server":null})
    })
}

pub fn load_servers_safely(servers_path: &std::path::Path) -> Vec<serde_json::Value> {
    read_servers_json(servers_path).unwrap_or_else(|| {
        info!("Using default server list (no servers.json found)");
        vec![serde_json::json!({"name":"FreeMode Main","ip":"127.0.0.1","port":30120})]
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_logger_creation() {
        assert!(super::get_log_file_path().ends_with("freemode-inject.log"));
    }
}