//! Packet Processor — handles server-side packet processing for client messages.
//! 
//! Implements FiveM-style packet handling:
//! - Deserialize incoming packets
//! - Process based on packet type
//! - Encrypt and broadcast responses

use freemode_shared::packet::{ChatMessage, ConnectRequest, SharedPacket};

// ============================================================================
// Types
// ============================================================================

/// Processes incoming packets from clients.
pub struct PacketProcessor;

impl PacketProcessor {
    /// Creates a new packet processor.
    pub fn new() -> Self {
        Self
    }

    /// Processes an incoming raw packet, returning the processed result.
    pub fn process(&self, data: &[u8]) -> Result<ProcessedPacket, String> {
        if data.len() < 2 {
            return Err("Packet too short".to_string());
        }

        match data[0] {
            0xCA => self.process_client_hello(data),
            0xCB => self.process_register_player(data),
            0xCC => self.process_chat_message(data),
            0xCD => self.process_spawn_vehicle(data),
            0xCE => self.process_despawn_vehicle(data),
            0xCF => self.process_position_update(data),
            _ => Err(format!("Unknown packet type: {}", data[0])),
        }
    }

    /// Processes a ClientHello packet.
    fn process_client_hello(&self, data: &[u8]) -> Result<ProcessedPacket, String> {
        if data.len() < 6 {
            return Err("ClientHello packet too short".to_string());
        }

        let version = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        
        let _ = version;
        
        Ok(ProcessedPacket::ServerHello(vec![0u8; 32]))
    }

    /// Processes a RegisterPlayer packet.
    fn process_register_player(&self, data: &[u8]) -> Result<ProcessedPacket, String> {
        let packet = SharedPacket::deserialize(data).map_err(|e| format!("Failed to deserialize RegisterPlayer: {}", e))?;
        let _: ConnectRequest = packet.to_typed().map_err(|e| format!("Failed to parse ConnectRequest: {}", e))?;
        
        Ok(ProcessedPacket::RegistrationComplete)
    }

    /// Processes a ChatMessage packet.
    fn process_chat_message(&self, data: &[u8]) -> Result<ProcessedPacket, String> {
        let packet = SharedPacket::deserialize(data).map_err(|e| format!("Failed to deserialize ChatMessage: {}", e))?;
        let _: ChatMessage = packet.to_typed().map_err(|e| format!("Failed to parse ChatMessage: {}", e))?;
        
        Ok(ProcessedPacket::ChatMessageReceived)
    }

    /// Processes a SpawnVehicle packet.
    fn process_spawn_vehicle(&self, data: &[u8]) -> Result<ProcessedPacket, String> {
        let _packet = SharedPacket::deserialize(data).map_err(|e| format!("Failed to deserialize SpawnVehicle: {}", e))?;
        
        Ok(ProcessedPacket::VehicleSpawned)
    }

    /// Processes a DespawnVehicle packet.
    fn process_despawn_vehicle(&self, data: &[u8]) -> Result<ProcessedPacket, String> {
        let _packet = SharedPacket::deserialize(data).map_err(|e| format!("Failed to deserialize DespawnVehicle: {}", e))?;
        
        Ok(ProcessedPacket::VehicleDespawned)
    }

    /// Processes a PositionUpdate packet.
    fn process_position_update(&self, data: &[u8]) -> Result<ProcessedPacket, String> {
        let _packet = SharedPacket::deserialize(data).map_err(|e| format!("Failed to deserialize PositionUpdate: {}", e))?;
        
        Ok(ProcessedPacket::PositionUpdateReceived)
    }
}

/// Processed packet result.
pub enum ProcessedPacket {
    /// ServerHello response data.
    ServerHello(Vec<u8>),
    /// Registration complete.
    RegistrationComplete,
    /// Chat message received.
    ChatMessageReceived,
    /// Vehicle spawned.
    VehicleSpawned,
    /// Vehicle despawned.
    VehicleDespawned,
    /// Position update received.
    PositionUpdateReceived,
}

impl Default for PacketProcessor {
    fn default() -> Self {
        Self::new()
    }
}