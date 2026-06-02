//! Game cache — SHA1 checksums + delta updates for efficient game file management.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Checksum type for game files.
pub type Checksum = [u8; 20]; // SHA1 hash

/// Represents a single game file in the cache.
#[derive(Debug, Clone)]
pub struct GameCacheEntry {
    /// Original filename in the game
    pub filename: String,
    /// List of known checksums (oldest first)
    pub checksums: Vec<Checksum>,
    /// Remote CDN path for this file
    pub remote_path: String,
    /// Local cached path
    pub local_path: PathBuf,
    /// Delta entries for incremental updates
    pub deltas: Vec<DeltaEntry>,
    /// File size in bytes
    pub size: u64,
}

/// Represents a delta update between two versions of a file.
#[derive(Debug, Clone)]
pub struct DeltaEntry {
    /// Source checksum (old version)
    pub from_checksum: Checksum,
    /// Target checksum (new version)
    pub to_checksum: Checksum,
    /// Path to the delta patch file
    pub patch_path: PathBuf,
    /// Size of the delta patch
    pub patch_size: u64,
}

/// Manages the game file cache.
pub struct GameCache {
    /// Base directory for cached files
    pub base_dir: PathBuf,
    /// Cache entries
    pub entries: HashMap<String, GameCacheEntry>,
}

impl GameCache {
    /// Create a new game cache with the given base directory.
    pub fn new(base_dir: &Path) -> Self {
        // Create cache subdirectories
        fs::create_dir_all(base_dir.join("cache")).ok();
        fs::create_dir_all(base_dir.join("deltas")).ok();

        Self {
            base_dir: base_dir.to_path_buf(),
            entries: HashMap::new(),
        }
    }

    /// Register a new game file in the cache.
    pub fn register_file(&mut self, filename: &str, remote_path: &str, initial_checksum: Checksum) {
        let entry = GameCacheEntry {
            filename: filename.to_string(),
            checksums: vec![initial_checksum],
            remote_path: remote_path.to_string(),
            local_path: self.base_dir.join("cache").join(filename),
            deltas: Vec::new(),
            size: 0,
        };

        self.entries.insert(filename.to_string(), entry);
    }

    /// Get the current checksum for a file.
    pub fn get_current_checksum(&self, filename: &str) -> Option<Checksum> {
        self.entries.get(filename).and_then(|e| {
            e.checksums.last().copied()
        })
    }

    /// Check if a file is in the cache and valid.
    pub fn is_cached(&self, filename: &str) -> bool {
        if let Some(entry) = self.entries.get(filename) {
            entry.local_path.exists()
        } else {
            false
        }
    }

    /// Get the local path for a cached file.
    pub fn get_local_path(&self, filename: &str) -> Option<PathBuf> {
        self.entries.get(filename).map(|e| e.local_path.clone())
    }

    /// Add a delta update for a file.
    pub fn add_delta(&mut self, filename: &str, from: Checksum, to: Checksum, patch_path: PathBuf, patch_size: u64) {
        if let Some(entry) = self.entries.get_mut(filename) {
            entry.deltas.push(DeltaEntry {
                from_checksum: from,
                to_checksum: to,
                patch_path,
                patch_size,
            });
        }
    }

    /// Get available delta updates for a file.
    pub fn get_available_deltas(&self, filename: &str) -> Vec<&DeltaEntry> {
        self.entries.get(filename)
            .map(|e| e.deltas.iter().collect())
            .unwrap_or_default()
    }

    /// Calculate SHA1 checksum of a file.
    pub fn calculate_checksum(path: &Path) -> io::Result<Checksum> {
        use sha1::{Sha1, Digest};

        let mut file = fs::File::open(path)?;
        let mut hasher = Sha1::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hasher.finalize().into())
    }

    /// Apply a delta patch to a file.
    pub fn apply_delta(&self, filename: &str, delta: &DeltaEntry) -> io::Result<PathBuf> {
        // This would implement bsdiff/bspatch algorithm
        // For now, return a placeholder
        let output_path = self.base_dir.join("cache").join(format!("{}_patched", filename));
        
        // In a real implementation, this would:
        // 1. Read the source file (from_checksum version)
        // 2. Read the delta patch
        // 3. Apply bspatch algorithm
        // 4. Write the result to output_path
        
        Ok(output_path)
    }

    /// Update the checksum for a file after downloading.
    pub fn update_checksum(&mut self, filename: &str, new_checksum: Checksum) {
        if let Some(entry) = self.entries.get_mut(filename) {
            entry.checksums.push(new_checksum);
        }
    }

    /// Get the latest checksum for a file.
    pub fn get_latest_checksum(&self, filename: &str) -> Option<Checksum> {
        self.entries.get(filename).and_then(|e| e.checksums.last().copied())
    }

    /// Get all registered filenames.
    pub fn get_all_filenames(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// Get the size of a cached file.
    pub fn get_file_size(&self, filename: &str) -> Option<u64> {
        self.entries.get(filename).map(|e| e.size)
    }

    /// Update the size of a cached file.
    pub fn update_file_size(&mut self, filename: &str, size: u64) {
        if let Some(entry) = self.entries.get_mut(filename) {
            entry.size = size;
        }
    }
}

/// Generate a random checksum for testing.
pub fn generate_random_checksum() -> Checksum {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut checksum = [0u8; 20];
    rng.fill(&mut checksum);
    checksum
}

/// Compare two checksums for equality.
pub fn checksums_equal(a: &Checksum, b: &Checksum) -> bool {
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_basic() {
        let temp_dir = std::env::temp_dir().join("freemode_test_cache");
        let cache = GameCache::new(&temp_dir);

        let checksum = generate_random_checksum();
        cache.register_file("test.rpf", "https://cdn.freemode/test.rpf", checksum);

        assert!(cache.get_current_checksum("test.rpf").is_some());
        assert_eq!(cache.get_current_checksum("test.rpf").unwrap(), checksum);
    }

    #[test]
    fn test_delta_management() {
        let temp_dir = std::env::temp_dir().join("freemode_test_delta");
        let mut cache = GameCache::new(&temp_dir);

        let from = generate_random_checksum();
        let to = generate_random_checksum();
        
        cache.register_file("test.rpf", "https://cdn.freemode/test.rpf", from);
        cache.add_delta("test.rpf", from, to, PathBuf::from("/patch.delta"), 1024);

        let deltas = cache.get_available_deltas("test.rpf");
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].from_checksum, from);
        assert_eq!(deltas[0].to_checksum, to);
    }
}
