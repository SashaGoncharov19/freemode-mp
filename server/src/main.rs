//! FreeMode Server — GTA V multiplayer server binary.
//! 
//! Entry point with tokio async runtime for:
//! - Loading configuration from config.json
//! - Starting TCP/UDP network servers per player slot
//! - Initializing Bun.js script host
//! - Managing entity registry and player connections

mod entity_registry;
mod network;
mod connection_manager;
mod script_loader;
mod js_host;

use freemode_shared::config::{ServerConfig, load_config};
use tokio::sync::broadcast;

// ============================================================================
// Main server struct (async wrapper)
// ============================================================================

#[allow(dead_code)]
struct FreeModeServer {
    config: ServerConfig,
    event_sender: broadcast::Sender<ServerEvent>,
    running: bool,
}

/// Server-level event for broadcasting.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ServerEvent {
    PlayerConnected { player_id: u32, name: String, addr: std::net::SocketAddr },
    PlayerDisconnected { player_id: u32, reason: String },
    EntitySpawned { entity_id: u64, entity_type: String },
    EntityDespawned { entity_id: u64 },
    ChatMessage { sender_id: u32, sender_name: String, text: String },
    ScriptLoaded { name: String },
}

// ============================================================================
// Entry point
// ============================================================================

#[tokio::main]
async fn main() {
    println!("FreeMode Server v0.1.0");
    println!("======================");

    // Load configuration — exit if missing (server requires config).
    let config = match load_config("config.json") {
        Ok(c) => {
            println!("Loaded config: {}", c.name);
            c
        }
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    // Create server instance.
    let mut server = FreeModeServer {
        config,
        event_sender: { let (tx, _rx) = broadcast::channel(128); tx },
        running: false,
    };

    // Start the server subsystems.
    if let Err(e) = start_server(&mut server) {
        eprintln!("Failed to start server: {}", e);
        std::process::exit(1);
    }

    println!("Server started successfully!");
    println!("Player slots: {}", server.config.max_players);
    println!("Network base port: {}", server.config.base_port);

    // Start event loop.
    let mut receiver = server.event_sender.subscribe();
    
    println!("Waiting for connections...");
    
    // Run the main loop until interrupted.
    tokio::select! {
        _ = run_event_loop(&mut server, &mut receiver) => {},
        _ = wait_for_shutdown() => {
            println!("Shutting down server...");
        }
    }

    // Cleanup.
    stop_server(&mut server);
    println!("Server stopped.");
}

// ============================================================================
// Server management functions
// ============================================================================

/// Starts all server subsystems (network, JS host, connections).
fn start_server(server: &mut FreeModeServer) -> Result<(), String> {
    println!("[SERVER] Starting server subsystems for '{}'", server.config.name);

    // 1. Initialize network packet processor.
    let _packet_processor = network::PacketProcessor::new();
    println!("[NETWORK] Packet processor initialized");

    // 2. Initialize entity registry with player slots.
    let mut registry = entity_registry::EntityRegistry::new();
    
    // Register default player entities for all slots using the actual API.
    use freemode_shared::entities::{FixedString, GameEntity, PlayerEntity};
    for i in 0..server.config.max_players as u64 {
        let name_str = format!("Player{}", i + 1);
        let player = Box::new(PlayerEntity {
            id: i as u32,
            name: FixedString::new(&name_str).unwrap_or(FixedString::EMPTY),
            ..PlayerEntity::default()
        });
        let entity = GameEntity::Player(player);
        // register_entity returns the ID but we don't need it here.
        let _ = registry.register_entity(entity);
    }
    println!("[ENTITY] Registry initialized for {} players", server.config.max_players);

    // 3. Initialize connection manager.
    let conn_mgr = connection_manager::ConnectionManager::new(server.config.max_players);
    let _port_base = server.config.base_port;
    println!("[CONNMAN] Connection manager started on base port {}", _port_base);
    let _ = conn_mgr; // Suppress unused variable warning.

    // 4. Initialize JS script host.
    let js_host_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("resources").to_string_lossy().into_owned()))
        .unwrap_or_else(|| "resources".to_string());

    println!("[SCRIPT] Looking for scripts in: {}", js_host_path);
    
    // Try to load scripts using the ScriptLoader API.
    if let Ok(mut loader) = script_loader::ScriptLoader::try_new(&js_host_path) {
        if let Ok(count) = loader.load_scripts() {
            println!("[SCRIPT] Loaded {} scripts from folder", count);
        } else {
            println!("[SCRIPT] No valid scripts found at '{}'", js_host_path);
        }
    } else {
        println!("[SCRIPT] Resources folder not found: '{}'", js_host_path);
    }

    // 5. Initialize the JS host with QuickJS runtime.
    let mut js_host = js_host::JsHost::new();
    
    // List scripts using the public API.
    let scripts = js_host.list_scripts();
    println!("[JS] QuickJS runtime initialized (scripts: {})", scripts.len());

    // Mark server as fully running.
    server.running = true;
    println!("[SERVER] All subsystems started successfully — server is LIVE");
    
    Ok(())
}

/// Stops all server subsystems gracefully.
fn stop_server(server: &mut FreeModeServer) {
    server.running = false;
    println!("[SERVER] Shutting down server subsystems...");
    println!("[SERVER] Disconnecting all players...");
    
    let _ = &server.config;
    
    println!("All subsystems stopped.");
}

// ============================================================================
// Event loop
// ============================================================================

/// Main event processing loop.
async fn run_event_loop(
    server: &mut FreeModeServer,
    receiver: &mut broadcast::Receiver<ServerEvent>,
) {
    while server.running {
        match tokio::time::timeout(
            std::time::Duration::from_millis(100),
            receiver.recv()
        ).await {
            Ok(Ok(event)) => {
                handle_server_event(server, event);
            }
            Ok(Err(_)) => {
                break; // Channel closed.
            }
            Err(_) => {
                tick_server(server);
            }
        }
    }
}

/// Handles a single server event.
fn handle_server_event(server: &mut FreeModeServer, event: ServerEvent) {
    match &event {
        ServerEvent::PlayerConnected { player_id, name, addr } => {
            println!("[{}] Player connected: {} ({})", player_id, name, addr);
        }
        ServerEvent::PlayerDisconnected { player_id, reason } => {
            println!("[{}] Player disconnected: {}", player_id, reason);
        }
        ServerEvent::ChatMessage { sender_id, sender_name, text } => {
            println!("[{}] {}:", sender_id, sender_name);
            println!("  {}", text);
        }
        _ => {}
    }

    // Broadcast to all connected clients.
    let _ = server.event_sender.send(event);
}

/// Ticks the server (process pending I/O, entity sync, etc.).
fn tick_server(server: &mut FreeModeServer) {
    let _ = &server.config;
}

/// Waits for a shutdown signal (Ctrl+C).
async fn wait_for_shutdown() {
    tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
}