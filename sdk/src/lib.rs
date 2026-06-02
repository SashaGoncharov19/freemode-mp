//! FreeMode SDK
//! 
//! This crate provides shared utilities, protocol definitions, and runtime
//! integration (Bun.js) used by both the launcher, client DLL, and server core.

pub mod crypto;
pub mod protocol;
pub mod build_detection;
pub mod js_runtime;
pub mod shared_memory;

// Re-export for convenience.
pub use crypto::{sha1, sha256, sha256_bytes, hmac_sha1, hmac_sha256, crc32};
pub use protocol::*;
pub use build_detection::{KnownBuild, GameBuildInfo, detect_game_build, DEFAULT_DLL_REDIRECTS};
pub use js_runtime::BunRuntime;

/// SDK version string.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the full SDK identifier.
pub fn sdk_identifier() -> String {
    format!("freemode-sdk/{}", SDK_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_identifier() {
        let id = sdk_identifier();
        assert!(id.starts_with("freemode-sdk/"));
    }
}