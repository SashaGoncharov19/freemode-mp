//! Network types for FreeMode client-server communication.
//! 
//! Provides addresses, endpoints, and connection state structures.

use serde::{Deserialize, Serialize};

// ============================================================================
// Address types
// ============================================================================

/// Network address for server connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerAddress {
    /// Hostname or IP address.
    pub host: String,
    /// Port number.
    pub port: u16,
}

impl ServerAddress {
    /// Creates a new server address.
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }

    /// Parses an address from a string in "host:port" format.
    pub fn parse(addr: &str) -> Result<Self, AddressParseError> {
        let (host, port) = addr.rsplit_once(':')
            .ok_or(AddressParseError::InvalidFormat)?;
        
        let port: u16 = port.parse()
            .map_err(|_| AddressParseError::InvalidPort)?;
        
        if host.is_empty() {
            return Err(AddressParseError::EmptyHost);
        }
        
        Ok(Self { host: host.to_string(), port })
    }

    /// Returns the address in "host:port" format.
    pub fn to_string_full(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl std::fmt::Display for ServerAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Error type for address parsing failures.
#[derive(Debug, Clone)]
pub enum AddressParseError {
    InvalidFormat,
    InvalidPort,
    EmptyHost,
}

impl std::fmt::Display for AddressParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "Invalid address format (expected host:port)"),
            Self::InvalidPort => write!(f, "Invalid port number"),
            Self::EmptyHost => write!(f, "Empty host"),
        }
    }
}

impl std::error::Error for AddressParseError {}

// ============================================================================
// Connection states
// ============================================================================

/// Connection state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConnectionState {
    /// Initial state before any connection attempt.
    Disconnected = 0,
    /// Attempting to resolve the server address.
    Resolving = 1,
    /// Attempting to connect to the server.
    Connecting = 2,
    /// Connection established, performing handshake.
    Handshaking = 3,
    /// Connected and authenticated, loading resources.
    Loading = 4,
    /// Fully connected and playing.
    Connected = 5,
    /// Disconnect initiated by client or server.
    Disconnecting = 6,
}

impl ConnectionState {
    /// Returns whether the connection is active (not disconnected).
    pub fn is_active(&self) -> bool {
        matches!(self, 
            Self::Connecting | Self::Handshaking | 
            Self::Loading | Self::Connected
        )
    }

    /// Returns whether the connection can send/receive game data.
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Connected)
    }
}

/// Connection rejection reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DisconnectReason {
    /// No specific reason given.
    Unknown = 0,
    /// Invalid or missing product key.
    InvalidProductKey = 1,
    /// Server is full.
    ServerFull = 2,
    /// Connection timeout.
    Timeout = 3,
    /// Protocol version mismatch.
    VersionMismatch = 4,
    /// Game build not supported.
    BuildNotSupported = 5,
    /// Anti-cheat violation.
    AntiCheat = 6,
    /// Player kicked by admin.
    Kicked = 7,
    /// Player banned.
    Banned = 8,
}

impl DisconnectReason {
    /// Returns a human-readable reason string.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Unknown => "Disconnected",
            Self::InvalidProductKey => "Invalid product key",
            Self::ServerFull => "Server is full",
            Self::Timeout => "Connection timeout",
            Self::VersionMismatch => "Protocol version mismatch",
            Self::BuildNotSupported => "Game build not supported",
            Self::AntiCheat => "Anti-cheat violation",
            Self::Kicked => "Kicked by administrator",
            Self::Banned => "You have been banned",
        }
    }
}

// ============================================================================
// Connection info
// ============================================================================

/// Information about the current server connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// Server address.
    pub server_address: ServerAddress,
    /// Current connection state.
    pub state: ConnectionState,
    /// Player's assigned ID on the server.
    pub player_id: u32,
    /// Server protocol version.
    pub server_version: u16,
    /// Round-trip latency in milliseconds.
    pub ping_ms: u32,
    /// Connection start timestamp (milliseconds).
    pub connected_at: u64,
}

impl Default for ConnectionInfo {
    fn default() -> Self {
        Self {
            server_address: ServerAddress {
                host: String::new(),
                port: 30120, // Default FiveM port
            },
            state: ConnectionState::Disconnected,
            player_id: 0,
            server_version: 0,
            ping_ms: 0,
            connected_at: 0,
        }
    }
}

/// Configuration for the network connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Maximum packet size (bytes).
    pub max_packet_size: usize,
    /// Connection timeout in milliseconds.
    pub connect_timeout_ms: u32,
    /// Heartbeat interval in milliseconds.
    pub heartbeat_interval_ms: u32,
    /// Maximum players allowed on server.
    pub max_players: u32,
    /// Enable TLS encryption.
    pub use_tls: bool,
    /// Server validation public key hash.
    pub server_key_hash: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            max_packet_size: 131072, // 128 KB
            connect_timeout_ms: 30000,
            heartbeat_interval_ms: 5000,
            max_players: 32,
            use_tls: true,
            server_key_hash: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_address_parse() {
        let addr = ServerAddress::parse("127.0.0.1:30120").unwrap();
        assert_eq!(addr.host, "127.0.0.1");
        assert_eq!(addr.port, 30120);
    }

    #[test]
    fn test_server_address_display() {
        let addr = ServerAddress::new("example.com".to_string(), 8080);
        assert_eq!(format!("{}", addr), "example.com:8080");
    }

    #[test]
    fn test_connection_state() {
        assert!(!ConnectionState::Disconnected.is_active());
        assert!(ConnectionState::Connected.is_active());
        assert!(ConnectionState::Connected.is_ready());
        assert!(!ConnectionState::Loading.is_ready());
    }
}