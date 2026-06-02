//! Cryptographic utilities for FreeMode.
//! 
//! Provides SHA1 and SHA256 hashing functions used for:
//! - File integrity verification (game cache checksums)
//! - Authentication challenge-response
//! - Packet message authentication

use sha2::Sha256;
use sha2::Digest;
use sha1::Sha1;
use hex::encode as encode_hex;
use hmac::{Hmac, Mac};

/// Returns a new SHA256 hasher that produces raw 32-byte output.
pub fn sha256_hasher() -> RawSha256Hasher {
    RawSha256Hasher::new()
}

/// A simple SHA256 hasher that returns raw bytes.
pub struct RawSha256Hasher {
    ctx: Sha256,
}

impl RawSha256Hasher {
    pub fn new() -> Self {
        RawSha256Hasher {
            ctx: Sha256::new(),
        }
    }

    pub fn compute(mut self, data: &[u8]) -> [u8; 32] {
        self.ctx.update(data);
        self.ctx.finalize().into()
    }
}

impl std::ops::Deref for RawSha256Hasher {
    type Target = Sha256;

    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}

impl std::ops::DerefMut for RawSha256Hasher {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ctx
    }
}

/// Computes the SHA1 hash of the given data and returns it as a lowercase hex string.
pub fn sha1(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    encode_hex(hasher.finalize())
}

/// Computes the SHA256 hash of the given data and returns it as a lowercase hex string.
pub fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    encode_hex(hasher.finalize())
}

/// Computes the SHA256 hash of the given data and returns raw bytes.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// HMAC type alias for SHA1.
type HmacSha1 = Hmac<Sha1>;

/// Computes HMAC-SHA1 with the given key.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    encode_hex(mac.finalize().into_bytes())
}

/// HMAC type alias for SHA256.
type HmacSha256 = Hmac<Sha256>;

/// Computes HMAC-SHA256 with the given key.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    encode_hex(mac.finalize().into_bytes())
}

/// Computes a CRC32 checksum (used for quick data integrity checks).
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1() {
        let hash = sha1(b"hello");
        assert_eq!(hash, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    }

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello");
        assert_eq!(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_crc32() {
        let checksum = crc32(b"hello");
        assert_eq!(checksum, 0x3619a8e9);
    }
}