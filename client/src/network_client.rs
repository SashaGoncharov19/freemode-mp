//! Cross-platform network client for FreeMode.
//! 
//! Provides TCP/UDP communication with the game server.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

/// State of the network connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
}

/// Network client for communicating with the game server.
pub struct NetworkClient {
    /// Remote server IP address.
    server_ip: String,
    /// Remote server port.
    server_port: u16,
    /// TCP connection state.
    state: ConnectionState,
    /// TCP stream (non-blocking).
    tcp_stream: Option<TcpStream>,
    /// UDP socket for unreliable packets.
    udp_socket: Option<UdpSocket>,
    /// Local bind address.
    local_addr: Option<SocketAddr>,
}

// ============================================================================
// Implementation
// ============================================================================

impl NetworkClient {
    /// Create a new network client.
    pub fn new(server_ip: String, server_port: u16) -> Self {
        NetworkClient {
            server_ip,
            server_port,
            state: ConnectionState::Disconnected,
            tcp_stream: None,
            udp_socket: None,
            local_addr: None,
        }
    }

    /// Connect to the server via TCP.
    pub fn connect(&mut self) -> Result<(), String> {
        self.state = ConnectionState::Connecting;

        // Create TCP connection.
        let addr = format!("{}:{}", self.server_ip, self.server_port);
        let stream = match TcpStream::connect(&addr) {
            Ok(s) => s,
            Err(e) => {
                self.state = ConnectionState::Disconnected;
                return Err(format!("TCP connect failed: {}", e));
            }
        };

        // Set non-blocking mode and timeout.
        stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| format!("Read timeout: {}", e))?;
        stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|e| format!("Write timeout: {}", e))?;

        // Bind local UDP socket.
        let udp = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                self.state = ConnectionState::Disconnected;
                return Err(format!("UDP bind failed: {}", e));
            }
        };

        self.tcp_stream = Some(stream);
        self.udp_socket = Some(udp);
        self.state = ConnectionState::Connected;

        Ok(())
    }

    /// Disconnect from the server.
    pub fn disconnect(&mut self) -> Result<(), String> {
        self.tcp_stream = None;
        self.udp_socket = None;
        self.local_addr = None;
        self.state = ConnectionState::Disconnected;
        Ok(())
    }

    /// Send raw bytes over TCP.
    pub fn send_raw(&mut self, data: &[u8]) -> Result<(), String> {
        match self.tcp_stream.as_mut() {
            Some(ref mut stream) => {
                stream.write_all(data).map_err(|e| format!("TCP write error: {}", e))?;
                Ok(())
            }
            None => Err("Not connected".to_string()),
        }
    }

    /// Receive raw bytes from TCP.
    pub fn recv_raw(&mut self, buf: &mut [u8; 4096]) -> Result<usize, String> {
        match self.tcp_stream.as_mut() {
            Some(ref mut stream) => {
                match stream.read(buf) {
                    Ok(n) => Ok(n),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0), // No data available
                    Err(e) => Err(format!("TCP read error: {}", e)),
                }
            }
            None => Err("Not connected".to_string()),
        }
    }

    /// Send a chat message to the server.
    pub fn send_chat(&mut self, message: &str) -> bool {
        // Chat packet format: [1u8 (packet_id)][len: u32][message bytes]
        let id: u32 = 0x05; // CHAT_MESSAGE packet ID
        let msg_bytes = message.as_bytes();
        let len = msg_bytes.len() as u32;

        let mut buf = Vec::with_capacity(1 + 4 + msg_bytes.len());
        buf.push(id as u8);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(msg_bytes);

        match self.send_raw(buf.as_slice()) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Send a spawn vehicle packet.
    pub fn send_spawn(&mut self, model_id: u32) -> bool {
        let id: u32 = 0x06; // SPAWN_VEHICLE packet ID
        let mut buf = vec![id as u8];
        buf.extend_from_slice(&model_id.to_le_bytes());
        self.send_raw(&buf).is_ok()
    }

    /// Send a position update packet.
    pub fn send_position(&mut self, x: f32, y: f32, z: f32) -> bool {
        let id: u32 = 0x07; // POSITION_UPDATE packet ID
        let mut buf = Vec::with_capacity(1 + 12);
        buf.push(id as u8);
        buf.extend_from_slice(&x.to_le_bytes());
        buf.extend_from_slice(&y.to_le_bytes());
        buf.extend_from_slice(&z.to_le_bytes());
        self.send_raw(&buf).is_ok()
    }

    /// Receive data from UDP.
    pub fn recv_udp(&mut self, buf: &mut [u8; 4096]) -> Result<(usize, SocketAddr), String> {
        match self.udp_socket.as_ref() {
            Some(udp) => {
                match udp.recv_from(buf) {
                    Ok((n, addr)) => Ok((n, addr)),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok((0, SocketAddr::from(([0, 0, 0, 0], 0)))),
                    Err(e) => Err(format!("UDP recv error: {}", e)),
                }
            }
            None => Err("Not connected".to_string()),
        }
    }

    /// Send data via UDP.
    pub fn send_udp(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, String> {
        match self.udp_socket.as_mut() {
            Some(udp) => {
                udp.send_to(data, addr).map_err(|e| format!("UDP send error: {}", e))
            }
            None => Err("Not connected".to_string()),
        }
    }

    /// Get the current connection state.
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Get local address.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Set local address.
    pub fn set_local_addr(&mut self, addr: SocketAddr) {
        self.local_addr = Some(addr);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_client() {
        let client = NetworkClient::new("127.0.0.1".to_string(), 30120);
        assert_eq!(client.state(), ConnectionState::Disconnected);
    }
}