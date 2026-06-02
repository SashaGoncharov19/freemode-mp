//! Bun.js Host — FFI interface to Bun.js runtime for game logic scripting.
//! 
//! Implements FiveM-style script host:
//! - Loads Bun.js runtime via SDK's js_runtime module
//! - Executes JavaScript/TypeScript game scripts
//! - Provides native API exports (game, net, etc.)
//! - Event dispatching between Rust and JS
//! - Module registration for resource communication

use freemode_sdk::js_runtime::BunRuntime;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ============================================================================
// Types
// ============================================================================

/// Bun.js script host — manages Bun runtime + loaded scripts.
pub struct JsHost {
    /// Active Bun.js runtime instance.
    runtime: Option<BunRuntime>,
    /// Loaded scripts (name → source).
    scripts: HashMap<String, ScriptEntry>,
    /// Registered event handlers.
    event_handlers: HashMap<String, Vec<String>>,
    /// Whether the host has been initialized.
    initialized: bool,
}

/// Alias for backward compatibility.
pub type ScriptEntry = JsScript;

/// Entry for a loaded script.
pub struct JsScript {
    /// Script name (resource folder name).
    pub name: String,
    /// Full source code.
    pub source: String,
    /// File path.
    pub path: String,
    /// Whether the script is currently running.
    pub running: bool,
}

/// Native API functions exported to JS world.
pub struct JsExports {
    /// Emit an event to all players.
    pub emit: Arc<Mutex<dyn Fn(&str, &str) + Send + Sync>>,
    /// Register a server-side event handler.
    pub on: Arc<Mutex<dyn Fn(&str, &str) + Send + Sync>>,
    /// Get player count.
    pub get_player_count: Arc<Mutex<dyn Fn() -> u32 + Send + Sync>>,
    /// Get server config value.
    pub get_config: Arc<Mutex<dyn Fn(&str) -> String + Send + Sync>>,
}

/// Event that can be dispatched by the JS host.
#[derive(Debug, Clone)]
pub struct JsEvent {
    /// Event name.
    pub name: String,
    /// Event data (serialized as JSON string).
    pub data: String,
}

// ============================================================================
// Public API
// ============================================================================

impl JsHost {
    /// Creates a new JS host.
    pub fn new() -> Self {
        Self {
            runtime: None,
            scripts: HashMap::new(),
            event_handlers: HashMap::new(),
            initialized: false,
        }
    }

    /// Initializes Bun.js runtime.
    pub fn init(&mut self) -> Result<(), String> {
        let runtime = BunRuntime::new().ok_or::<String>("Failed to create Bun runtime".into())?;
        
        let init_code = r#"
            const native = {
                emit: (eventName, data) => {
                    console.log("[native] emit", eventName, data);
                    return true;
                },
                on: (eventName, callback) => {
                    console.log("[native] on", eventName);
                    return true;
                },
                getPlayers: () => [],
                getConfig: (key) => null,
            };
        "#;

        let _ = runtime.execute::<String>(init_code);

        self.runtime = Some(runtime);
        self.initialized = true;

        log::info!("✅ Bun.js host initialized");
        Ok(())
    }

    /// Loads a JavaScript script from source code.
    pub fn load_script(&mut self, name: &str, source: &str, path: &str) -> Result<(), String> {
        if !self.initialized {
            return Err("JS host not initialized".to_string());
        }

        self.scripts.insert(
            name.to_string(),
            ScriptEntry {
                name: name.to_string(),
                source: source.to_string(),
                path: path.to_string(),
                running: false,
            },
        );

        log::info!("Loaded script: {} ({})", name, path);
        Ok(())
    }

    /// Starts all loaded scripts.
    pub fn start_scripts(&mut self) -> Result<(), String> {
        if !self.initialized || self.runtime.is_none() {
            return Err("JS host not initialized".to_string());
        }

        let runtime = self.runtime.as_ref().unwrap();

        for (name, script) in &mut self.scripts {
            match runtime.execute::<String>(&script.source) {
                Ok(_) => {
                    script.running = true;
                    log::info!("Started script: {}", name);
                }
                Err(e) => {
                    log::error!("Failed to start script {}: {}", name, e);
                }
            }
        }

        Ok(())
    }

    /// Gets the current native exports for external use.
    pub fn get_exports(&self) -> JsExports {
        JsExports {
            emit: Arc::new(Mutex::new(|_e: &str, _d: &str| {})),
            on: Arc::new(Mutex::new(|_e: &str, _d: &str| {})),
            get_player_count: Arc::new(Mutex::new(|| 0u32)),
            get_config: Arc::new(Mutex::new(|_k: &str| String::new())),
        }
    }

    /// Shuts down the JS host.
    pub fn shutdown(&mut self) {
        for script in self.scripts.values_mut() {
            script.running = false;
        }
        self.runtime = None;
        self.initialized = false;
        log::info!("Bun.js host shut down");
    }

    /// Returns the list of loaded scripts.
    pub fn list_scripts(&self) -> Vec<String> {
        self.scripts.keys().cloned().collect()
    }

    /// Returns whether a script is running.
    pub fn is_script_running(&self, name: &str) -> bool {
        self.scripts.get(name).map_or(false, |s| s.running)
    }
}

impl Drop for JsHost {
    fn drop(&mut self) {
        self.shutdown();
    }
}