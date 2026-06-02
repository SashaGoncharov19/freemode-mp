//! SDK — Delta compression for efficient network communication.
//!
//! Implements delta compression algorithms to minimize network bandwidth usage
//! by only sending changed data between sync frames.

use std::collections::HashMap;
use std::io::{Read, Write, Cursor};

/// Delta compression context.
#[derive(Debug, Clone)]
pub struct DeltaContext {
    /// Previous state hash
    previous_hash: u64,
    /// Previous state data
    previous_state: Vec<u8>,
    /// Compression level
    compression_level: u8,
}

/// Delta entry for compression.
#[derive(Debug, Clone)]
pub struct DeltaEntry {
    /// Offset in original data
    pub offset: usize,
    /// Length of data
    pub length: usize,
    /// New data
    pub data: Vec<u8>,
}

/// Delta compression result.
#[derive(Debug, Clone)]
pub struct DeltaResult {
    /// Whether compression was successful
    pub success: bool,
    /// Original size
    pub original_size: usize,
    /// Compressed size
    pub compressed_size: usize,
    /// Compressed data
    pub compressed_data: Vec<u8>,
    /// Delta entries
    pub delta_entries: Vec<DeltaEntry>,
}

/// Create a new delta context.
pub fn create_delta_context(compression_level: u8) -> DeltaContext {
    DeltaContext {
        previous_hash: 0,
        previous_state: Vec::new(),
        compression_level: compression_level.min(9),
    }
}

/// Calculate hash of state data.
pub fn calculate_state_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    
    for byte in data {
        hash ^= *byte as u64;
        hash *= 0x100000001b3;
    }
    
    hash
}

/// Calculate delta between two states.
pub fn calculate_delta(old_state: &[u8], new_state: &[u8]) -> DeltaResult {
    let original_size = new_state.len();
    let mut delta_entries = Vec::new();
    let mut compressed_data = Vec::new();
    
    if old_state.len() != new_state.len() {
        // Different sizes, send full data
        delta_entries.push(DeltaEntry {
            offset: 0,
            length: new_state.len(),
            data: new_state.to_vec(),
        });
        
        return DeltaResult {
            success: true,
            original_size,
            compressed_size: new_state.len(),
            compressed_data: new_state.to_vec(),
            delta_entries,
        };
    }
    
    // Find changed regions using byte-by-byte comparison
    let mut in_changed_region = false;
    let mut region_start = 0;
    
    for (i, (old_byte, new_byte)) in old_state.iter().zip(new_state.iter()).enumerate() {
        if old_byte != new_byte && !in_changed_region {
            // Start of changed region
            in_changed_region = true;
            region_start = i;
        } else if old_byte == new_byte && in_changed_region {
            // End of changed region
            delta_entries.push(DeltaEntry {
                offset: region_start,
                length: i - region_start,
                data: new_state[region_start..i].to_vec(),
            });
            in_changed_region = false;
        }
    }
    
    // Handle last changed region
    if in_changed_region {
        delta_entries.push(DeltaEntry {
            offset: region_start,
            length: new_state.len() - region_start,
            data: new_state[region_start..].to_vec(),
        });
    }
    
    // Serialize delta entries
    for entry in &delta_entries {
        compressed_data.extend_from_slice(&entry.offset.to_le_bytes());
        compressed_data.extend_from_slice(&entry.length.to_le_bytes());
        compressed_data.extend_from_slice(&entry.data);
    }
    
    DeltaResult {
        success: true,
        original_size,
        compressed_size: compressed_data.len(),
        compressed_data,
        delta_entries,
    }
}

/// Apply delta to state.
pub fn apply_delta(base_state: &[u8], delta: &[u8]) -> Result<Vec<u8>, String> {
    let mut cursor = Cursor::new(delta);
    let mut result = base_state.to_vec();
    
    loop {
        // Read offset
        let mut offset_buf = [0u8; 4];
        match cursor.read_exact(&mut offset_buf) {
            Ok(_) => {},
            Err(_) => break,
        }
        let offset = u32::from_le_bytes(offset_buf) as usize;
        
        // Read length
        let mut length_buf = [0u8; 4];
        match cursor.read_exact(&mut length_buf) {
            Ok(_) => {},
            Err(_) => break,
        }
        let length = u32::from_le_bytes(length_buf) as usize;
        
        // Read data
        let mut data = vec![0u8; length];
        match cursor.read_exact(&mut data) {
            Ok(_) => {},
            Err(_) => return Err("Failed to read delta data".to_string()),
        }
        
        // Apply delta
        if offset + length > result.len() {
            return Err("Delta offset out of bounds".to_string());
        }
        
        result[offset..offset + length] = data;
    }
    
    Ok(result)
}

/// Compress state data.
pub fn compress_state(state: &[u8], compression_level: u8) -> Vec<u8> {
    if compression_level == 0 {
        return state.to_vec();
    }
    
    // Simple run-length encoding for demonstration
    let mut compressed = Vec::new();
    let mut run_length = 1;
    
    for i in 0..state.len() {
        if i + 1 < state.len() && state[i] == state[i + 1] && run_length < 255 {
            run_length += 1;
        } else {
            if run_length > 1 {
                compressed.push(0); // Run length marker
                compressed.push(run_length);
                compressed.push(state[i]);
            } else {
                compressed.push(state[i]);
            }
            run_length = 1;
        }
    }
    
    compressed
}

/// Decompress state data.
pub fn decompress_state(compressed: &[u8]) -> Vec<u8> {
    let mut decompressed = Vec::new();
    let mut i = 0;
    
    while i < compressed.len() {
        if compressed[i] == 0 && i + 2 < compressed.len() {
            // Run length encoded
            let run_length = compressed[i + 1] as usize;
            let value = compressed[i + 2];
            
            for _ in 0..run_length {
                decompressed.push(value);
            }
            
            i += 3;
        } else {
            decompressed.push(compressed[i]);
            i += 1;
        }
    }
    
    decompressed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delta_context_creation() {
        let context = create_delta_context(5);
        assert_eq!(context.compression_level, 5);
    }

    #[test]
    fn test_state_hash() {
        let data1 = vec![1, 2, 3, 4, 5];
        let data2 = vec![1, 2, 3, 4, 5];
        let data3 = vec![1, 2, 3, 4, 6];
        
        assert_eq!(calculate_state_hash(&data1), calculate_state_hash(&data2));
        assert_ne!(calculate_state_hash(&data1), calculate_state_hash(&data3));
    }

    #[test]
    fn test_delta_calculation() {
        let old_state = vec![1, 2, 3, 4, 5];
        let new_state = vec![1, 2, 6, 4, 5];
        
        let delta = calculate_delta(&old_state, &new_state);
        assert!(delta.success);
        assert_eq!(delta.delta_entries.len(), 1);
        assert_eq!(delta.delta_entries[0].offset, 2);
        assert_eq!(delta.delta_entries[0].length, 1);
        assert_eq!(delta.delta_entries[0].data, vec![6]);
    }

    #[test]
    fn test_delta_application() {
        let base_state = vec![1, 2, 3, 4, 5];
        let delta_data = vec![
            2, 0, 0, 0, // offset: 2
            1, 0, 0, 0, // length: 1
            6, // data: 6
        ];
        
        let result = apply_delta(&base_state, &delta_data).unwrap();
        assert_eq!(result, vec![1, 2, 6, 4, 5]);
    }

    #[test]
    fn test_compression() {
        let state = vec![1, 1, 1, 1, 1, 2, 2, 2, 3, 3];
        let compressed = compress_state(&state, 5);
        let decompressed = decompress_state(&compressed);
        
        assert_eq!(decompressed, state);
    }

    #[test]
    fn test_compression_no_change() {
        let state = vec![1, 2, 3, 4, 5];
        let compressed = compress_state(&state, 0);
        
        assert_eq!(compressed, state);
    }

    #[test]
    fn test_delta_different_sizes() {
        let old_state = vec![1, 2, 3];
        let new_state = vec![1, 2, 3, 4, 5];
        
        let delta = calculate_delta(&old_state, &new_state);
        assert!(delta.success);
        assert_eq!(delta.delta_entries.len(), 1);
        assert_eq!(delta.delta_entries[0].data, new_state);
    }
}
