//! FreeMode MP injection logger — logs all inject, load, hook steps to file.
//!
//! Writes structured logs to `<launcher_folder>/freemode-inject.log` so that:
//! - Missing config.json or servers.json does NOT crash the game
//! - Every inject step, DLL load, and hook attempt is recorded
//! - Even if logging fails, it never panics — all errors are caught internally

use std::fs::OpenOptions;
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
    /// Returns the short tag shown in logs.
    pub fn tag(&self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => " INFO ",
            LogLevel::Inject => " INJECT",
            LogLevel::Load => " LOAD  ",
            LogLevel::Hook => " HOOK  ",
            LogLevel::Warning => " WARN ",
            LogLevel::Error => " ERROR ",
            LogLevel::Critical => "CRITCAL",
        }
    }

    /// Returns the CSS color for console output.
    pub fn color(&self) -> &str {
        match self {
            LogLevel::Debug => "#94a3b8",
            LogLevel::Info => "#93c5fd",
            LogLevel::Inject => "#86efac",
            LogLevel::Load => "#fcd34d",
            LogLevel::Hook => "#a78bfa",
            LogLevel::Warning => "#fbbf24",
            LogLevel::Error => "#f87171",
            LogLevel::Critical => "#ef4444",
        }
    }
}

// ============================================================================
// Logger singleton — file-based logging
// ============================================================================

/// The global logger instance.
static LOGGER: Lazy<Mutex<Option<FileLogger>>> = Lazy::new(|| Mutex::new(None));

/// A file-based logger that appends to a single log file.
pub struct FileLogger {
    /// Path to the log file.
    log_path: PathBuf,
    /// Handle to the log file (appended).
    file: Option<OpenOptions>,
}

impl FileLogger {
    /// Creates a new file logger writing to `log_path`.
    pub fn new(log_path: PathBuf) -> Self {
        Self {
            log_path: log_path.clone(),
            file: None,
        }
    }

    /// Opens the log file for appending.
    fn open_file(&mut self) -> Result<(), String> {
        if self.file.is_some() {
            return Ok(()); // Already open.
        }

        let mut opts = OpenOptions::new();
        opts.create(true).append(true);

        match opts.open(&self.log_path) {
            Ok(f) => {
                self.file = Some(opts.open(&self.log_path).unwrap_or(f));
                Ok(())
            }
            Err(e) => Err(format!("Failed to open log file '{}': {}", self.log_path.display(), e)),
        }
    }

    /// Writes a log entry.
    pub fn log(&mut self, level: LogLevel, message: &str) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");

        // Always attempt to open the file first.
        if self.file.is_none() {
            let _ = self.open_file();
        }

        let entry = format!("[{}] [{}] {}\n", timestamp, level.tag(), message);

        eprint!("{}", entry); // Print to stderr for visibility.

        if let Some(ref file) = self.file {
            let _ = file.write_all(entry.as_bytes());
        }
    }
}

// ============================================================================
// Public logging API
// ============================================================================

/// Initializes the global logger with a log file path next to the launcher exe.
pub fn init_logger() -> Result<(), String> {
    let log_path = get_log_file_path();
    let mut logger = LOGGER.lock().unwrap();
    *logger = Some(FileLogger::new(log_path));
    info!("Logging initialized: {}", log_path.display());
    Ok(())
}

/// Writes a message at the given level.
pub fn write(level: LogLevel, message: &str) {
    let mut logger = LOGGER.lock().unwrap();
    if let Some(ref mut l) = *logger {
        l.log(level, message);
    } else {
        // Logger not initialized — just print to stderr.
        eprintln!("[{}] {}", level.tag(), message);
    }
}

/// Gets the path where logs are written (next to launcher exe).
pub fn get_log_file_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            return parent.join("freemode-inject.log");
        }
    }
    // Fallback: current directory.
    PathBuf::from("freemode-inject.log")
}

// ============================================================================
// Convenience macros for different log levels
// ============================================================================

/// Logs an info-level message.
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        let msg = format!($($arg)*);
        $crate::write($crate::LogLevel::Info, &msg);
    };
}

/// Logs a debug-level message.
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        let msg = format!($($arg)*);
        $crate::write($crate::LogLevel::Debug, &msg);
    };
}

/// Logs an inject event (DLL loading, injection steps).
#[macro_export]
macro_rules! inject {
    ($($arg:tt)*) => {
        let msg = format!($($arg)*);
        $crate::write($crate::LogLevel::Inject, &msg);
    };
}

/// Logs a DLL load event.
#[macro_export]
macro_rules! load {
    ($($arg:tt)*) => {
        let msg = format!($($arg)*);
        $crate::write($crate::LogLevel::Load, &msg);
    };
}

/// Logs a hook event (IAT, vtable patching).
#[macro_export]
macro_rules! hook {
    ($($arg:tt)*) => {
        let msg = format!($($arg)*);
        $crate::write($crate::LogLevel::Hook, &msg);
    };
}

/// Logs a warning (non-fatal).
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        let msg = format!($($arg)*);
        $crate::write($crate::LogLevel::Warning, &msg);
    };
}

/// Logs an error (serious but may not crash the game).
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        let msg = format!($($arg)*);
        $crate::write($crate::LogLevel::Error, &msg);
    };
}

/// Logs a critical error (game stability may be affected).
#[macro_export]
macro_rules! critical {
    ($($arg:tt)*) => {
        let msg = format!($($arg)*);
        $crate::write($crate::LogLevel::Critical, &msg);
    };
}

// ============================================================================
// Safe wrappers for file operations (never panics)
// ============================================================================

/// Reads a JSON config file safely — returns None on any error.
pub fn read_config_json(path: &std::path::Path) -> Option<serde_json::Value> {
    match std::fs::read_to_string(path) {
        Ok(contents) => match serde_json::from_str(&contents) {
            Ok(value) => Some(value),
            Err(e) => {
                warn!("Failed to parse {}: {}", path.display(), e);
                None
            }
        },
        Err(e) => {
            debug!("Config file not found (safe, using defaults): {}: {}", path.display(), e);
            None
        }
    }
}

/// Reads a JSON servers list file safely — returns empty vec on any error.
pub fn read_servers_json(path: &std::path::Path) -> Option<Vec<serde_json::Value>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => match serde_json::from_str(&contents) {
            Ok(value) => Some(value),
            Err(e) => {
                warn!("Failed to parse {}: {}", path.display(), e);
                None
            }
        },
        Err(e) => {
            debug!("Servers file not found (safe, using defaults): {}: {}", path.display(), e);
            None
        }
    }
}

/// Checks if a file exists safely.
pub fn file_exists(path: &std::path::Path) -> bool {
    path.exists()
}

// ============================================================================
// Non-fatal wrappers (never panic — always return Result or Option)
// ============================================================================

/// Safely loads config — never panics, returns default on any error.
pub fn load_config_safely(config_path: &std::path::Path) -> serde_json::Value {
    if let Some(value) = read_config_json(config_path) {
        value
    } else {
        info!("Using default config (no valid config.json found)");
        serde_json::json!({
            "game_path": null,
            "selected_server": null,
            "autorun": false,
            "theme": "dark",
            "last_server": null
        })
    }
}

/// Safely loads server list — never panics, returns empty vec on any error.
pub fn load_servers_safely(servers_path: &std::path::Path) -> Vec<serde_json::Value> {
    if let Some(value) = read_servers_json(servers_path) {
        value
    } else {
        info!("Using default server list (no servers.json found)");
        vec![serde_json::json!({
            "name": "FreeMode Main",
            "ip": "127.0.0.1",
            "port": 30120
        })]
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_logger_creation() {
        assert!(super::get_log_file_path().ends_with("freemode-inject.log"));
    }
}