//! Network protocol definitions for FreeMode.
//! 
//! Defines the binary packet format used for communication between
//! launcher, client DLL, and server core.

use serde::{Deserialize, Serialize};

/// Magic bytes that identify a FreeMode packet header.
pub const PACKET_MAGIC: u32 = 0x46524D00; // "FRM\0"

/// Current protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum packet payload size (1 MB).
pub const MAX_PACKET_SIZE: usize = 1024 * 1024;

/// Message types for communication between client and server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// Client → Server: Initial connection request.
    ConnectRequest = 1,
    
    /// Server → Client: Connection accepted.
    ConnectResponse = 2,
    
    /// Client → Server: Player spawned in the world.
    PlayerSpawned = 3,
    
    /// Server → Client: Sync entity to client.
    SyncEntity = 4,
    
    /// Client → Server: Entity state update.
    EntityStateUpdate = 5,
    
    /// Server → Client: Destroy entity on client.
    DestroyEntity = 6,
    
    /// Client ↔ Server: Chat message.
    ChatMessage = 7,
    
    /// Client → Server: Request resource list.
    ResourceListRequest = 8,
    
    /// Server → Client: Send resource list.
    ResourceListResponse = 9,
    
    /// Server → Client: Kick player.
    KickPlayer = 10,
    
    /// Server → Client: Ban player.
    BanPlayer = 11,
    
    /// Client ↔ Server: RPC call.
    RpcCall = 12,
    
    /// Client ↔ Server: RPC response.
    RpcResponse = 13,
    
    /// Keep-alive heartbeat.
    Heartbeat = 14,
    
    /// Server → Client: Game build update.
    BuildUpdate = 15,
    
    /// Reserved for future use.
    Reserved = 0xFF,
}

impl Default for MessageType {
    fn default() -> Self {
        MessageType::Reserved
    }
}

/// A network packet with header + payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    /// Magic bytes (FRM).
    pub magic: u32,
    /// Protocol version.
    pub version: u16,
    /// Message type identifier.
    pub msg_type: MessageType,
    /// Sequence number for ordering verification.
    pub sequence: u32,
    /// Payload length in bytes.
    pub payload_len: u32,
    /// Raw payload data.
    pub payload: Vec<u8>,
}

impl Packet {
    /// Creates a new empty packet with the given message type.
    pub fn new(msg_type: MessageType) -> Self {
        Self {
            magic: PACKET_MAGIC,
            version: PROTOCOL_VERSION,
            msg_type,
            sequence: 0,
            payload_len: 0,
            payload: Vec::new(),
        }
    }

    /// Creates a new packet with the given message type and payload.
    pub fn with_payload(msg_type: MessageType, payload: Vec<u8>) -> Self {
        let payload_len = payload.len() as u32;
        Self {
            magic: PACKET_MAGIC,
            version: PROTOCOL_VERSION,
            msg_type,
            sequence: 0,
            payload_len,
            payload,
        }
    }

    /// Serializes the packet to bytes.
    pub fn serialize(&self) -> Result<Vec<u8>, PacketError> {
        if self.magic != PACKET_MAGIC {
            return Err(PacketError::InvalidMagic);
        }
        
        if self.version != PROTOCOL_VERSION {
            return Err(PacketError::VersionMismatch);
        }

        if self.payload.len() > MAX_PACKET_SIZE {
            return Err(PacketError::PayloadTooLarge);
        }

        let mut buf = Vec::new();
        
        // Write header (16 bytes): magic(4) + version(2) + msg_type(1) + sequence(4) + payload_len(4)
        buf.extend_from_slice(&self.magic.to_be_bytes());
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.push(self.msg_type as u8);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.payload_len.to_be_bytes());
        
        // Write payload
        buf.extend_from_slice(&self.payload);

        Ok(buf)
    }

    /// Deserializes a packet from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < 16 {
            return Err(PacketError::PacketTooSmall);
        }

        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != PACKET_MAGIC {
            return Err(PacketError::InvalidMagic);
        }

        let version = u16::from_be_bytes([data[4], data[5]]);
        let msg_type = match data[6] {
            1 => MessageType::ConnectRequest,
            2 => MessageType::ConnectResponse,
            3 => MessageType::PlayerSpawned,
            4 => MessageType::SyncEntity,
            5 => MessageType::EntityStateUpdate,
            6 => MessageType::DestroyEntity,
            7 => MessageType::ChatMessage,
            8 => MessageType::ResourceListRequest,
            9 => MessageType::ResourceListResponse,
            10 => MessageType::KickPlayer,
            11 => MessageType::BanPlayer,
            12 => MessageType::RpcCall,
            13 => MessageType::RpcResponse,
            14 => MessageType::Heartbeat,
            15 => MessageType::BuildUpdate,
            _ => return Err(PacketError::UnknownMessageType),
        };

        let sequence = u32::from_be_bytes([data[7], data[8], data[9], data[10]]);
        let payload_len = u32::from_be_bytes([data[11], data[12], data[13], data[14]]) as usize;
        
        if 16 + payload_len > data.len() {
            return Err(PacketError::TruncatedPayload);
        }

        if payload_len > MAX_PACKET_SIZE {
            return Err(PacketError::PayloadTooLarge);
        }

        let payload = data[16..(16 + payload_len)].to_vec();

        Ok(Self {
            magic,
            version,
            msg_type,
            sequence,
            payload_len: payload_len as u32,
            payload,
        })
    }
}

/// Errors that can occur during packet processing.
#[derive(Debug, Clone)]
pub enum PacketError {
    InvalidMagic,
    VersionMismatch,
    PacketTooSmall,
    TruncatedPayload,
    PayloadTooLarge,
    UnknownMessageType,
    SerializationError(String),
    DeserializationError(String),
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "Invalid packet magic"),
            Self::VersionMismatch => write!(f, "Protocol version mismatch"),
            Self::PacketTooSmall => write!(f, "Packet too small for header"),
            Self::TruncatedPayload => write!(f, "Truncated payload"),
            Self::PayloadTooLarge => write!(f, "Payload too large"),
            Self::UnknownMessageType => write!(f, "Unknown message type"),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
            Self::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
        }
    }
}

impl std::error::Error for PacketError {}

/// Player state for synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerState {
    /// Unique player ID.
    pub id: u32,
    /// Player name.
    pub name: String,
    /// Position (x, y, z).
    pub position: [f32; 3],
    /// Rotation (pitch, roll, yaw).
    pub rotation: [f32; 3],
    /// Health.
    pub health: f32,
    /// Armor.
    pub armor: f32,
    /// Current vehicle ID (0 if not in a vehicle).
    pub vehicle_id: u32,
}

impl Default for PlayerState {
    fn default() -> Self {
        Self {
            id: 0,
            name: String::new(),
            position: [0.0, 0.0, 0.0],
            rotation: [0.0, 0.0, 0.0],
            health: 100.0,
            armor: 0.0,
            vehicle_id: 0,
        }
    }
}

/// Entity type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum EntityType {
    Player = 0,
    Vehicle = 1,
    Object = 2,
    PickUp = 3,
    Projectile = 4,
}

/// Entity data for synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityState {
    /// Entity type.
    pub entity_type: EntityType,
    /// Unique entity ID.
    pub id: u32,
    /// Model hash (integer).
    pub model_hash: u32,
    /// Position (x, y, z).
    pub position: [f32; 3],
    /// Rotation (pitch, roll, yaw).
    pub rotation: [f32; 3],
    /// Velocity (vx, vy, vz).
    pub velocity: [f32; 3],
    /// Current health.
    pub health: f32,
    /// Current heading (degrees).
    pub heading: f32,
    /// Is this entity streamed in?
    pub is_streamed_in: bool,
}

impl Default for EntityState {
    fn default() -> Self {
        Self {
            entity_type: EntityType::Object,
            id: 0,
            model_hash: 0,
            position: [0.0, 0.0, 0.0],
            rotation: [0.0, 0.0, 0.0],
            velocity: [0.0, 0.0, 0.0],
            health: 0.0,
            heading: 0.0,
            is_streamed_in: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_serialization() {
        let packet = Packet::with_payload(
            MessageType::ChatMessage,
            vec![1, 2, 3, 4],
        );
        
        let serialized = packet.serialize().unwrap();
        assert_eq!(serialized.len(), 16 + 4); // header + payload
        
        let deserialized = Packet::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.msg_type, MessageType::ChatMessage);
        assert_eq!(deserialized.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_packet_magic_validation() {
        let bad_data: Vec<u8> = (0..16).collect();
        let result = Packet::deserialize(&bad_data);
        assert!(result.is_err());
    }
}