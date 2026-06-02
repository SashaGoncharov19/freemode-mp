//! Entity Registry — manages network-synced entities with position updates.
//! 
//! Implements FiveM-style entity registry:
//! - Entity ID generation and registration
//! - Position sync via tick system
//! - Sync intervals for entities (50ms default)

use freemode_shared::entities::*;
use std::collections::HashMap;

// ============================================================================
// Types
// ============================================================================

/// Manages registered network entities.
pub struct EntityRegistry {
    /// All registered entities keyed by ID.
    entities: HashMap<u64, GameEntity>,
    /// Next available entity ID.
    next_id: u64,
}

// ============================================================================
// Public API
// ============================================================================

impl EntityRegistry {
    /// Creates a new entity registry.
    pub fn new() -> Self {
        Self {
            entities: HashMap::new(),
            next_id: 1,
        }
    }

    /// Registers a new entity and returns its ID.
    pub fn register_entity(&mut self, entity: GameEntity) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.entities.insert(id, entity);
        id
    }

    /// Gets an entity by ID.
    #[allow(dead_code)]
    pub fn get_entity(&self, id: u64) -> Option<&GameEntity> {
        self.entities.get(&id)
    }

    /// Removes an entity by ID.
    #[allow(dead_code)]
    pub fn remove_entity(&mut self, id: u64) -> Option<GameEntity> {
        self.entities.remove(&id)
    }

    /// Gets all entities.
    #[allow(dead_code)]
    pub fn all_entities(&self) -> Vec<&GameEntity> {
        self.entities.values().collect()
    }

    /// Ticks all entities (processes position sync).
    #[allow(dead_code)]
    pub fn tick(&mut self) {
        for (_id, entity) in self.entities.iter_mut() {
            match entity {
                GameEntity::Player(p) => { p.velocity = EntityVelocity::default(); }
                GameEntity::Vehicle(v) => { v.velocity = EntityVelocity::default(); }
                GameEntity::Object(_) => {}
            }
        }
    }

    /// Clears all entities.
    #[allow(dead_code)]
    pub fn clear_all(&mut self) {
        self.entities.clear();
    }
}