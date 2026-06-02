//! FreeMode Shared Library — Common types and utilities for client/server.
//! 
//! This crate provides shared data structures used by both the client DLL
//! and server core, ensuring consistent serialization and protocol behavior.

pub mod packet;
pub mod entities;
pub mod network;
pub mod config;

pub use packet::*;
pub use entities::*;
pub use network::*;
pub use config::*;

/// Shared library version.
pub const SHARED_VERSION: &str = env!("CARGO_PKG_VERSION");