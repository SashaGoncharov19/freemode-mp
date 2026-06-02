//! Network module — TCP/UDP servers per player slot.
//! 
//! Implements FiveM-style networking:
//! - TCP server for packet communication (port 30120 + slot offset)
//! - UDP server for unreliable packets (port 30120 + slot offset + 1)
//! - Per-slot address binding (slot * 2 ports starting from BASE_PORT)

mod packet_processor;

use freemode_shared::config::ServerConfig;
use std::net::SocketAddr;

// ============================================================================
// Constants
// ============================================================================

/// Base port for the first player slot.
pub const BASE_PORT: u16 = 30120;

// ============================================================================
// Network Manager
// ============================================================================

/// Manages TCP and UDP servers for all player slots.
pub struct NetworkManager {
    /// Listening addresses for TCP (one per active slot).
    tcp_listeners: Vec<SocketAddr>,
    /// Listening address for UDP (base).
    udp_addr: SocketAddr,
    /// Whether the network manager is running.
    running: bool,
}

impl NetworkManager {
    /// Creates a new network manager.
    pub fn new() -> Self {
        Self {
            tcp_listeners: Vec::new(),
            udp_addr: SocketAddr::from(([0, 0, 0, 0], BASE_PORT)),
            running: false,
        }
    }

    /// Starts the network servers based on config.
    pub fn start(&mut self, config: &ServerConfig) -> Result<(), String> {
        let max_slots = config.max_players.min(32);

        // Create TCP listeners for each slot.
        self.tcp_listeners.clear();
        for slot in 0..max_slots {
            let port = (BASE_PORT as u32 + slot as u32 * 2) as u16;
            let addr = SocketAddr::from(([0, 0, 0, 0], port));

            // In production, use tokio::net::TcpListener.
            self.tcp_listeners.push(addr);
        }

        // Set UDP base address.
        self.udp_addr = SocketAddr::from(([0, 0, 0, 0], BASE_PORT));

        self.running = true;
        Ok(())
    }

    /// Stops all network servers.
    pub fn stop(&mut self) {
        self.tcp_listeners.clear();
        self.running = false;
    }

    /// Gets the TCP address for a specific player slot.
    #[allow(dead_code)]
    pub fn tcp_addr_for_slot(&self, slot: u32) -> Option<SocketAddr> {
        if slot >= self.tcp_listeners.len() as u32 {
            return None;
        }
        Some(self.tcp_listeners[slot as usize])
    }

    /// Gets the UDP base address.
    #[allow(dead_code)]
    pub fn udp_addr(&self) -> SocketAddr {
        self.udp_addr
    }

    /// Whether the network manager is running.
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.running
    }
}

// Re-export packet processor.
#[allow(dead_code)]
pub use packet_processor::PacketProcessor;
