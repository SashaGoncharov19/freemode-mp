//! Game cache — stub implementation for SHA1 checksums + delta updates.

use std::path::PathBuf;

/// Checksum type for game files (stub).
pub type Checksum = [u8; 20];

/// Represents a single game file in the cache (stub).
#[derive(Debug, Clone)]
pub struct GameCacheEntry {
    pub filename: String,
    pub checksums: Vec<Checksum>,
    pub remote_path: String,
    pub local_path: PathBuf,
}

/// Manages the game file cache (stub - not used in current launch flow).
pub struct GameCache {
    base_dir: PathBuf,
}

impl GameCache {
    pub fn new(base_dir: &std::path::Path) -> Self {
        Self { base_dir: base_dir.to_path_buf() }
    }
    pub fn register_file(&mut self, _filename: &str, _remote_path: &str, _initial_checksum: Checksum) {}
    pub fn get_current_checksum(&self, _filename: &str) -> Option<Checksum> { None }
    pub fn is_cached(&self, _filename: &str) -> bool { false }
    pub fn get_local_path(&self, _filename: &str) -> Option<PathBuf> { None }
    pub fn calculate_checksum(_path: &std::path::Path) -> Result<Checksum, String> { Ok([0u8; 20]) }
    pub fn update_checksum(&mut self, _filename: &str, _new_checksum: Checksum) {}
}

/// Generate a random checksum (stub).
pub fn generate_random_checksum() -> Checksum { [0u8; 20] }
/// Compare two checksums for equality.
pub fn checksums_equal(a: &Checksum, b: &Checksum) -> bool { a == b }