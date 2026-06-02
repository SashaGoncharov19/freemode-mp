//! Entity definitions for FreeMode.
//! 
//! Provides shared data structures representing game entities
//! (players, vehicles, objects) used for synchronization and state management.

use serde::{Deserialize, Serialize};
use bytemuck::{Pod, Zeroable};

// ============================================================================
// Entity base types
// ============================================================================

/// Base size for fixed-size entity data in shared memory.
pub const ENTITY_DATA_SIZE: usize = 256;

/// Fixed-size string buffer for entity names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedString {
    data: [u8; ENTITY_DATA_SIZE],
    len: usize,
}

impl FixedString {
    pub const EMPTY: Self = Self { data: [0u8; ENTITY_DATA_SIZE], len: 0 };

    pub fn new(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.len() > ENTITY_DATA_SIZE {
            return None;
        }
        let mut data = [0u8; ENTITY_DATA_SIZE];
        data[..bytes.len()].copy_from_slice(bytes);
        Some(Self { data, len: bytes.len() })
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.data[..self.len]).unwrap_or("")
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for FixedString {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Serialize for FixedString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for FixedString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).ok_or_else(|| serde::de::Error::custom("String too long"))
    }
}

/// Position and rotation data packed for SIMD-friendly serialization.
#[derive(Debug, Clone, Copy, Pod, Zeroable, Serialize, Deserialize)]
#[repr(C)]
pub struct EntityTransform {
    /// Position (x, y, z) in world coordinates.
    pub position: [f32; 3],
    /// Rotation (pitch, roll, yaw) in radians.
    pub rotation: [f32; 3],
}

impl Default for EntityTransform {
    fn default() -> Self {
        Self {
            position: [0.0, 0.0, 0.0],
            rotation: [0.0, 0.0, 0.0],
        }
    }
}

impl EntityTransform {
    pub fn new(position: [f32; 3], rotation: [f32; 3]) -> Self {
        Self { position, rotation }
    }

    /// Computes the distance to another position.
    pub fn distance_to(&self, other: &[f32; 3]) -> f32 {
        let dx = self.position[0] - other[0];
        let dy = self.position[1] - other[1];
        let dz = self.position[2] - other[2];
        (dx * dx + dy * dy + dz * dz).sqrt()
    }
}

/// Velocity data for physics simulation.
#[derive(Debug, Clone, Copy, Pod, Zeroable, Serialize, Deserialize)]
#[repr(C)]
pub struct EntityVelocity {
    /// Linear velocity (vx, vy, vz) in units/sec.
    pub linear: [f32; 3],
}

impl Default for EntityVelocity {
    fn default() -> Self {
        Self { linear: [0.0, 0.0, 0.0] }
    }
}

// ============================================================================
// Entity types
// ============================================================================

/// Unique identifier for game entities.
pub type EntityId = u32;

/// Model hash identifying the visual/behavioral template.
pub type ModelHash = u32;

/// Network stream synchronization tick rate (Hz).
pub const STREAM_SYNC_RATE: u32 = 30;

/// Player-specific entity data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerEntity {
    /// Unique network ID for this player.
    pub id: EntityId,
    /// Display name (fixed buffer).
    pub name: FixedString,
    /// Current transform (position + rotation).
    pub transform: EntityTransform,
    /// Current velocity.
    pub velocity: EntityVelocity,
    /// Health (0 = dead, 200 = max for GTA V).
    pub health: f32,
    /// Armor value (0-100).
    pub armor: f32,
    /// Is the player currently in a vehicle?
    pub in_vehicle: bool,
    /// Vehicle handle if in a vehicle, 0 otherwise.
    pub vehicle_handle: EntityId,
}

impl Default for PlayerEntity {
    fn default() -> Self {
        Self {
            id: 0,
            name: FixedString::EMPTY,
            transform: EntityTransform::default(),
            velocity: EntityVelocity::default(),
            health: 200.0,
            armor: 0.0,
            in_vehicle: false,
            vehicle_handle: 0,
        }
    }
}

/// Vehicle class enumeration for GTA V.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum VehicleClass {
    Empty = 0,
    SportsClassic = 1,
    Sports = 2,
    Super = 3,
    Muscle = 4,
    Sedan = 5,
    SUV = 7,
    OffRoad = 8,
    Motorcycles = 11,
    Boat = 13,
    Helicopter = 15,
    Plane = 16,
}

/// Vehicle-specific entity data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VehicleEntity {
    /// Unique network ID for this vehicle.
    pub id: EntityId,
    /// Model hash of the vehicle.
    pub model_hash: ModelHash,
    /// Current transform.
    pub transform: EntityTransform,
    /// Current velocity.
    pub velocity: EntityVelocity,
    /// Health (0 = destroyed).
    pub health: f32,
    /// Max health for this vehicle type.
    pub max_health: f32,
    /// Vehicle class.
    pub vehicle_class: VehicleClass,
    /// Current gear (transmission state).
    pub gear: i32,
    /// Engine on/off state.
    pub engine_on: bool,
    /// Is this vehicle a mission vehicle (script spawned)?
    pub is_mission_vehicle: bool,
}

/// Object-specific entity data (props, static objects).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameObjectEntity {
    /// Unique network ID for this object.
    pub id: EntityId,
    /// Model hash of the object.
    pub model_hash: ModelHash,
    /// Current transform.
    pub transform: EntityTransform,
    /// Health (0 = destroyed).
    pub health: f32,
    /// Is this object stationary?
    pub is_static: bool,
}

/// Union type for any entity in the game world.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GameEntity {
    Player(Box<PlayerEntity>),
    Vehicle(Box<VehicleEntity>),
    Object(Box<GameObjectEntity>),
}

impl GameEntity {
    /// Returns the entity ID.
    pub fn id(&self) -> EntityId {
        match self {
            Self::Player(p) => p.id,
            Self::Vehicle(v) => v.id,
            Self::Object(o) => o.id,
        }
    }

    /// Returns the entity type as a u8.
    pub fn type_id(&self) -> u8 {
        match self {
            Self::Player(_) => 0,
            Self::Vehicle(_) => 1,
            Self::Object(_) => 2,
        }
    }

    /// Returns the current transform.
    pub fn transform(&self) -> &EntityTransform {
        match self {
            Self::Player(p) => &p.transform,
            Self::Vehicle(v) => &v.transform,
            Self::Object(o) => &o.transform,
        }
    }

    /// Returns the current health.
    pub fn health(&self) -> f32 {
        match self {
            Self::Player(p) => p.health,
            Self::Vehicle(v) => v.health,
            Self::Object(o) => o.health,
        }
    }

    /// Returns the model hash.
    pub fn model_hash(&self) -> ModelHash {
        match self {
            Self::Player(_) => 0,
            Self::Vehicle(v) => v.model_hash,
            Self::Object(o) => o.model_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_string() {
        let s = FixedString::new("Hello").unwrap();
        assert_eq!(s.as_str(), "Hello");
        assert_eq!(s.len(), 5);
        
        let empty = FixedString::EMPTY;
        assert!(empty.is_empty());
    }

    #[test]
    fn test_entity_transform() {
        let pos = [1.0, 2.0, 3.0];
        let rot = [0.1, 0.2, 0.3];
        let t = EntityTransform::new(pos, rot);
        
        let other = [4.0, 5.0, 6.0];
        let dist = t.distance_to(&other);
        assert!(dist > 0.0);
    }

    #[test]
    fn test_game_entity() {
        let player = GameEntity::Player(Box::new(PlayerEntity::default()));
        assert_eq!(player.type_id(), 0);

        let vehicle = GameEntity::Vehicle(Box::new(VehicleEntity {
            id: 1,
            model_hash: 0x12345678,
            transform: EntityTransform::default(),
            velocity: EntityVelocity::default(),
            health: 1000.0,
            max_health: 1000.0,
            vehicle_class: VehicleClass::Sports,
            gear: 0,
            engine_on: true,
            is_mission_vehicle: false,
        }));
        assert_eq!(vehicle.type_id(), 1);
    }
}