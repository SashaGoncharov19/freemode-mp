//! FreeMode Server Library — GTA V multiplayer server core with Bun.js runtime.
//! 
//! Provides:
//! - TCP/UDP networking per player slot (max 32 slots)
//! - Entity registry with network synchronization
//! - Bun.js script host for game logic
//! - Connection management with crypto handshake

mod network;
mod js_host;
mod script_loader;
mod entity_registry;
mod connection_manager;

use freemode_shared::config::ServerConfig;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

// ============================================================================
// Types
// ============================================================================

/// Main server instance.
#[allow(dead_code)]
pub struct FreeModeServer {
    /// Server configuration.
    config: ServerConfig,
    /// Network manager (TCP/UDP servers per slot).
    network_manager: Arc<Mutex<network::NetworkManager>>,
    /// Entity registry for synced entities.
    entity_registry: Arc<Mutex<entity_registry::EntityRegistry>>,
    /// Bun.js script host.
    js_host: Arc<Mutex<js_host::JsHost>>,
    /// Connection manager for player slots.
    connection_manager: Arc<Mutex<connection_manager::ConnectionManager>>,
    /// Event listeners per event name.
    event_listeners: Arc<Mutex<HashMap<String, Vec<Box<dyn Fn(&ServerEvent) + Send + Sync>>>>>,
    /// Whether the server is running.
    running: bool,
}

/// Server-level event for broadcasting.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ServerEvent {
    /// Player connected to server.
    PlayerConnected { player_id: u32, name: String, addr: std::net::SocketAddr },
    /// Player disconnected from server.
    PlayerDisconnected { player_id: u32, reason: String },
    /// New entity spawned in the world.
    EntitySpawned { entity_id: u64, entity_type: String },
    /// Existing entity despawned.
    EntityDespawned { entity_id: u64 },
    /// Chat message broadcast.
    ChatMessage { sender_id: u32, sender_name: String, text: String },
    /// Script loaded/updated.
    ScriptLoaded { name: String },
}

// ============================================================================
// Global state
// ============================================================================

static mut G_SERVER: Option<*mut FreeModeServer> = None;

// ============================================================================
// Public API
// ============================================================================

/// Creates a new server instance with the given config.
#[allow(dead_code)]
pub fn create_server(config: ServerConfig) -> Result<*mut FreeModeServer, String> {
    unsafe {
        let server = Box::into_raw(Box::new(FreeModeServer {
            config,
            network_manager: Arc::new(Mutex::new(network::NetworkManager::new())),
            entity_registry: Arc::new(Mutex::new(entity_registry::EntityRegistry::new())),
            js_host: Arc::new(Mutex::new(js_host::JsHost::new())),
            connection_manager: Arc::new(Mutex::new(connection_manager::ConnectionManager::new(MAX_PLAYERS))),
            event_listeners: Arc::new(Mutex::new(HashMap::new())),
            running: false,
        }));

        G_SERVER = Some(server);
        Ok(server)
    }
}

/// Starts the server (network + JS host).
#[allow(dead_code)]
pub fn start_server(server: &mut FreeModeServer) -> Result<(), String> {
    // Start network servers for each player slot.
    {
        let mut nm = server.network_manager.lock().unwrap();
        nm.start(&server.config)?;
    }

    // Initialize Bun.js host and load scripts.
    {
        let mut js = server.js_host.lock().unwrap();
        js.init()?;

        // Load all scripts from the resources directory.
        script_loader::load_all_scripts(&mut js, &server.config.resources_dir)?;
    }

    // Start connection manager.
    {
        let mut cm = server.connection_manager.lock().unwrap();
        cm.initialize()?;
    }

    server.running = true;
    Ok(())
}

/// Stops the server gracefully.
#[allow(dead_code)]
pub fn stop_server(server: &mut FreeModeServer) {
    server.running = false;

    // Stop network servers.
    {
        let mut nm = server.network_manager.lock().unwrap();
        nm.stop();
    }

    // Shutdown Bun.js host.
    {
        let mut js = server.js_host.lock().unwrap();
        js.shutdown();
    }

    // Clear all entities.
    {
        let mut er = server.entity_registry.lock().unwrap();
        er.clear_all();
    }
}

/// Broadcasts a server event to all connected clients and registered listeners.
#[allow(dead_code)]
pub fn broadcast_event(server: &mut FreeModeServer, event: ServerEvent) {
    // Notify registered listeners.
    let mut handlers = server.event_listeners.lock().unwrap();
    if let Some(handler_list) = handlers.get_mut("global") {
        for handler in handler_list {
            handler(&event);
        }
    }
}

/// Registers an event listener.
#[allow(dead_code)]
pub fn on_event<F>(server: &mut FreeModeServer, event_name: &str, handler: F) 
where F: Fn(&ServerEvent) + Send + Sync + 'static {
    let mut handlers = server.event_listeners.lock().unwrap();
    handlers.entry(event_name.to_string())
        .or_insert_with(Vec::new)
        .push(Box::new(handler));
}

/// Shuts down the server singleton.
#[allow(dead_code)]
pub fn shutdown() {
    unsafe {
        // Use raw pointer access to avoid mutable static reference rules.
        let ptr = &raw mut G_SERVER;
        let opt = std::ptr::read(ptr);
        if let Some(p) = opt {
            drop(Box::from_raw(p));
            std::ptr::write(ptr, None);
        }
    }
}

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of player slots.
pub const MAX_PLAYERS: u32 = 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_server() {
        let config = ServerConfig::default();
        let server_ptr = create_server(config).unwrap();
        unsafe {
            let mut server = Box::from_raw(server_ptr);
            start_server(&mut *server).unwrap();
            stop_server(&mut *server);
            // Re-box to avoid double-free
            let _ = Box::from_raw(server_ptr);
        }
    }
}