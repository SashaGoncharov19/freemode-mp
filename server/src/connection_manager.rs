//! Connection Manager — manages player slots and connection state per slot.
//! 
//! Implements FiveM-style connection management:
//! - Player slot allocation (max 32)
//! - Connection state per slot
//! - Server config integration

use std::collections::HashMap;

// ============================================================================
// Types
// ============================================================================

/// Manages player connections across slots.
pub struct ConnectionManager {
    /// Maximum number of player slots.
    max_slots: u32,
    /// Connection state per slot.
    slots: Vec<Option<SlotState>>,
    /// Player ID to slot mapping.
    player_to_slot: HashMap<u32, u32>,
}

/// State of a single player slot.
#[derive(Clone)]
pub struct SlotState {
    /// Whether the slot is occupied.
    occupied: bool,
    /// Player ID connected to this slot.
    player_id: Option<u32>,
    /// Player name.
    player_name: Option<String>,
    /// Connection address.
    addr: Option<std::net::SocketAddr>,
}

// ============================================================================
// Public API
// ============================================================================

impl ConnectionManager {
    /// Creates a new connection manager with the given number of slots.
    pub fn new(max_slots: u32) -> Self {
        Self {
            max_slots,
            slots: vec![None; max_slots as usize],
            player_to_slot: HashMap::new(),
        }
    }

    /// Initializes all slots.
    #[allow(dead_code)]
    pub fn initialize(&mut self) -> Result<(), String> {
        for slot in self.slots.iter_mut() {
            *slot = Some(SlotState {
                occupied: false,
                player_id: None,
                player_name: None,
                addr: None,
            });
        }
        Ok(())
    }

    /// Ticks the connection manager.
    #[allow(dead_code)]
    pub fn tick(&self) {
        // In production, process pending connections and disconnects.
    }

    /// Finds an empty slot for a player.
    #[allow(dead_code)]
    pub fn allocate_slot(&mut self, player_id: u32, name: &str, addr: std::net::SocketAddr) -> Option<u32> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if let Some(state) = slot {
                if !state.occupied {
                    state.occupied = true;
                    state.player_id = Some(player_id);
                    state.player_name = Some(name.to_string());
                    state.addr = Some(addr);

                    self.player_to_slot.insert(player_id, i as u32);
                    return Some(i as u32);
                }
            }
        }
        None // No available slots.
    }

    /// Deallocates a slot for a player.
    #[allow(dead_code)]
    pub fn deallocate_slot(&mut self, player_id: u32) {
        if let Some(&slot_idx) = self.player_to_slot.get(&player_id) {
            if let Some(slot) = self.slots.get_mut(slot_idx as usize) {
                if let Some(state) = slot {
                    state.occupied = false;
                    state.player_id = None;
                    state.player_name = None;
                    state.addr = None;
                }
            }
            self.player_to_slot.remove(&player_id);
        }
    }

    /// Gets the number of occupied slots.
    #[allow(dead_code)]
    pub fn occupied_count(&self) -> u32 {
        self.slots.iter().filter(|s| s.as_ref().map(|st| st.occupied).unwrap_or(false)).count() as u32
    }

    /// Gets the maximum number of slots.
    #[allow(dead_code)]
    pub fn max_slots(&self) -> u32 {
        self.max_slots
    }
}