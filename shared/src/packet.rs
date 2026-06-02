//! Binary packet format for FreeMode client-server communication.
//! 
//! This module provides the wire protocol used to exchange data between
//! client DLL and server core. It is designed to be lightweight, deterministic,
//! and compatible with both Rust serialization (bincode) and custom binary encoding.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Constants
// ============================================================================

/// Magic bytes that identify a FreeMode shared packet header.
pub const SHARED_PACKET_MAGIC: u32 = 0x534D504B; // "SMPK"

/// Current shared protocol version.
pub const SHARED_PROTOCOL_VERSION: u16 = 1;

/// Maximum packet payload size (512 KB).
pub const MAX_SHARED_PACKET_SIZE: usize = 512 * 1024;

// ============================================================================
// Packet structure
// ============================================================================

/// A shared binary packet with header + bincode-serialized payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedPacket {
    /// Magic bytes (SMPK).
    pub magic: u32,
    /// Protocol version.
    pub version: u16,
    /// Packet category (determines routing).
    pub category: PacketCategory,
    /// Message type within the category.
    pub msg_type: u8,
    /// Sequence number for ordering.
    pub sequence: u32,
    /// Flags bitfield.
    pub flags: u16,
    /// Payload length in bytes.
    pub payload_len: u32,
    /// Raw payload (bincode-serialized data).
    pub payload: Vec<u8>,
}

impl SharedPacket {
    /// Creates a new packet with the given category and message type.
    pub fn new(category: PacketCategory, msg_type: u8) -> Self {
        Self {
            magic: SHARED_PACKET_MAGIC,
            version: SHARED_PROTOCOL_VERSION,
            category,
            msg_type,
            sequence: 0,
            flags: 0,
            payload_len: 0,
            payload: Vec::new(),
        }
    }

    /// Creates a new packet with pre-serialized payload.
    pub fn with_payload(category: PacketCategory, msg_type: u8, payload: Vec<u8>) -> Self {
        let payload_len = payload.len() as u32;
        Self {
            magic: SHARED_PACKET_MAGIC,
            version: SHARED_PROTOCOL_VERSION,
            category,
            msg_type,
            sequence: 0,
            flags: 0,
            payload_len,
            payload,
        }
    }

    /// Serializes the packet to raw bytes for transmission.
    pub fn serialize(&self) -> Result<Vec<u8>, PacketError> {
        if self.magic != SHARED_PACKET_MAGIC {
            return Err(PacketError::InvalidMagic);
        }

        if self.payload.len() > MAX_SHARED_PACKET_SIZE {
            return Err(PacketError::PayloadTooLarge);
        }

        let mut buf = Vec::new();

        // Write header: magic(4) + version(2) + category(1) + msg_type(1) + sequence(4) + flags(2) + payload_len(4) = 18 bytes
        buf.extend_from_slice(&self.magic.to_le_bytes());
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.push(self.category as u8);
        buf.push(self.msg_type);
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf.extend_from_slice(&self.payload_len.to_le_bytes());

        // Write payload
        buf.extend_from_slice(&self.payload);

        Ok(buf)
    }

    /// Deserializes a packet from raw bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < 18 {
            return Err(PacketError::PacketTooSmall);
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != SHARED_PACKET_MAGIC {
            return Err(PacketError::InvalidMagic);
        }

        let version = u16::from_le_bytes([data[4], data[5]]);
        let category = match data[6] {
            0 => PacketCategory::Client,
            1 => PacketCategory::Server,
            2 => PacketCategory::Entity,
            3 => PacketCategory::Resource,
            4 => PacketCategory::Network,
            _ => return Err(PacketError::UnknownCategory),
        };
        let msg_type = data[7];
        let sequence = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let flags = u16::from_le_bytes([data[12], data[13]]);
        let payload_len = u32::from_le_bytes([data[14], data[15], data[16], data[17]]) as usize;

        if 18 + payload_len > data.len() {
            return Err(PacketError::TruncatedPayload);
        }

        let payload = data[18..(18 + payload_len)].to_vec();

        Ok(Self {
            magic,
            version,
            category,
            msg_type,
            sequence,
            flags,
            payload_len: payload_len as u32,
            payload,
        })
    }

    /// Serializes a typed value into the packet payload using bincode.
    pub fn from_typed<T: Serialize>(category: PacketCategory, msg_type: u8, value: &T) -> Result<Self, PacketError> {
        let payload = bincode::serialize(value).map_err(|e| PacketError::SerializationError(e.to_string()))?;
        Ok(Self::with_payload(category, msg_type, payload))
    }

    /// Deserializes the packet payload into a typed value using bincode.
    pub fn to_typed<T: for<'de> Deserialize<'de>>(&self) -> Result<T, PacketError> {
        bincode::deserialize(&self.payload).map_err(|e| PacketError::DeserializationError(e.to_string()))
    }
}

// ============================================================================
// Packet categories
// ============================================================================

/// Categories determine which handler receives the packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketCategory {
    /// Client → Server messages.
    Client = 0,
    /// Server → Client messages.
    Server = 1,
    /// Entity synchronization data.
    Entity = 2,
    /// Resource management messages.
    Resource = 3,
    /// Network-level control messages.
    Network = 4,
}

// ============================================================================
// Packet flags
// ============================================================================

/// Bitfield flags for packet options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketFlags {
    bits: u16,
}

impl PacketFlags {
    pub const EMPTY: Self = Self { bits: 0 };
    pub const RELIABLE: Self = Self { bits: 0x0001 };
    pub const REPLICATED: Self = Self { bits: 0x0002 };
    pub const UNSEQUENCED: Self = Self { bits: 0x0004 };

    pub fn has(&self, flag: Self) -> bool {
        self.bits & flag.bits != 0
    }

    pub fn with(self, flag: Self) -> Self {
        Self { bits: self.bits | flag.bits }
    }
}

// ============================================================================
// Error types
// ============================================================================

/// Errors that can occur during packet processing.
#[derive(Debug, Clone)]
pub enum PacketError {
    InvalidMagic,
    VersionMismatch,
    PacketTooSmall,
    TruncatedPayload,
    PayloadTooLarge,
    UnknownCategory,
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
            Self::PayloadTooLarge => write!(f, "Payload exceeds maximum size"),
            Self::UnknownCategory => write!(f, "Unknown packet category"),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
            Self::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
        }
    }
}

impl std::error::Error for PacketError {}

// ============================================================================
// Typed message types for each category
// ============================================================================

/// Client-to-server messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientToServerMsg {
    ConnectRequest(ConnectRequest),
    ChatMessage(ChatMessage),
    EntityStateUpdate(EntityStateUpdate),
    RpcCall(RpcCall),
    Heartbeat(Heartbeat),
}

/// Server-to-client messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerToClientMsg {
    ConnectResponse(ConnectResponse),
    SyncEntities(Vec<EntitySyncData>),
    DestroyEntity(EntityDestroy),
    ChatMessage(ChatMessage),
    RpcResponse(RpcResponse),
    KickPlayer(KickReason),
    HeartbeatAck(HeartbeatAck),
}

/// Entity synchronization data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySyncData {
    pub entity_id: u32,
    pub entity_type: u8,
    pub position: [f32; 3],
    pub rotation: [f32; 3],
    pub velocity: [f32; 3],
    pub health: f32,
    pub heading: f32,
    pub model_hash: u32,
    pub is_streamed_in: bool,
}

/// Connect request from client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub client_version: u16,
    pub product_key: String,
    pub game_build: i32,
    pub challenge_response: String,
    pub player_name: String,
}

/// Connect response from server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectResponse {
    pub accepted: bool,
    pub player_id: u32,
    pub server_version: u16,
    pub reason: String,
}

/// Chat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub sender_id: u32,
    pub sender_name: String,
    pub text: String,
    pub is_system: bool,
}

/// Entity state update from client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityStateUpdate {
    pub entity_id: u32,
    pub position: [f32; 3],
    pub rotation: [f32; 3],
    pub velocity: [f32; 3],
    pub health: f32,
}

/// Entity destroy notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityDestroy {
    pub entity_id: u32,
    pub entity_type: u8,
}

/// RPC call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcCall {
    pub rpc_id: u32,
    pub target: String,
    pub args: HashMap<String, String>,
}

/// RPC response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub rpc_id: u32,
    pub success: bool,
    pub result: String,
}

/// Kick reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KickReason {
    pub reason: String,
}

/// Heartbeat request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat;

/// Heartbeat response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatAck {
    pub timestamp: u64,
    pub player_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_serialization() {
        let packet = SharedPacket::with_payload(
            PacketCategory::Client,
            1,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        );

        let serialized = packet.serialize().unwrap();
        assert_eq!(serialized.len(), 18 + 4); // header + payload

        let deserialized = SharedPacket::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.category, PacketCategory::Client);
        assert_eq!(deserialized.msg_type, 1);
        assert_eq!(deserialized.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_typed_packet() {
        let msg = ChatMessage {
            sender_id: 42,
            sender_name: "TestPlayer".to_string(),
            text: "Hello!".to_string(),
            is_system: false,
        };

        let packet = SharedPacket::from_typed(PacketCategory::Server, 7, &msg).unwrap();
        let received: ChatMessage = packet.to_typed().unwrap();

        assert_eq!(received.sender_id, 42);
        assert_eq!(received.text, "Hello!");
    }
}