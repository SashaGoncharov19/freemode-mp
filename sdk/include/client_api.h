#ifndef FREEMODE_CLIENT_API_H
#define FREEMODE_CLIENT_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// ============================================================================
// Client-side JS Plugin API (C FFI)
// ============================================================================

/// Player handle (client-side).
typedef uint32_t player_handle;

/// Vehicle handle.
typedef uint32_t vehicle_handle;

/// Object handle.
typedef uint32_t object_handle;

/// Event callback type for client events.
/// @param user_data User-provided pointer
/// @param arg1 First argument (can be a pointer to data)
/// @param arg2 Second argument (can be a pointer to data)
/// @param arg_size Size of each argument buffer in bytes
typedef void (*client_event_callback)(void* user_data, const void* arg1, const void* arg2, size_t arg_size);

// ============================================================================
// Player events
// ============================================================================

/// Called when a player spawns.
/// @param player_id The player's ID
/// @param position Pointer to [x, y, z] (f32)
void on_player_spawned(uint32_t player_id, const float* position);

/// Called when a player despawns.
/// @param player_id The player's ID
void on_player_despawned(uint32_t player_id);

/// Called when a player connects.
/// @param player_id The player's ID
/// @param name Player name (null-terminated)
void on_player_connect(uint32_t player_id, const char* name);

/// Called when a player disconnects.
/// @param player_id The player's ID
/// @param reason Disconnect reason string (null-terminated)
void on_player_disconnect(uint32_t player_id, const char* reason);

// ============================================================================
// Vehicle events
// ============================================================================

/// Called when a vehicle is created.
/// @param vehicle_id The vehicle's ID
/// @param model_hash Model hash
/// @param position Pointer to [x, y, z] (f32)
void on_vehicle_created(uint32_t vehicle_id, uint32_t model_hash, const float* position);

/// Called when a vehicle is destroyed.
/// @param vehicle_id The vehicle's ID
void on_vehicle_destroyed(uint32_t vehicle_id);

/// Called when a player enters a vehicle.
/// @param player_id Player ID
/// @param vehicle_id Vehicle ID
/// @param seat Seat index (-1 = driver)
void on_player_enter_vehicle(uint32_t player_id, uint32_t vehicle_id, int32_t seat);

/// Called when a player exits a vehicle.
/// @param player_id Player ID
/// @param vehicle_id Vehicle ID
void on_player_exit_vehicle(uint32_t player_id, uint32_t vehicle_id);

// ============================================================================
// Object events
// ============================================================================

/// Called when an object is created.
/// @param object_id The object's ID
/// @param model_hash Model hash
void on_object_created(uint32_t object_id, uint32_t model_hash);

/// Called when an object is destroyed.
/// @param object_id The object's ID
void on_object_destroyed(uint32_t object_id);

// ============================================================================
// Chat events
// ============================================================================

/// Called when a chat message is received.
/// @param player_id Player ID (0 for system messages)
/// @param message Message text (null-terminated)
void on_chat_message(uint32_t player_id, const char* message);

// ============================================================================
// Resource events
// ============================================================================

/// Called when the client resources are starting.
void on_client_start();

/// Called when the client resources are stopping.
void on_client_stop();

// ============================================================================
// Utility functions
// ============================================================================

/// Gets the local player's ID.
/// @return The local player handle (0 if not spawned)
uint32_t get_local_player_id(void);

/// Sends a chat message to all players.
/// @param message Message text (null-terminated)
void send_chat_message(const char* message);

/// Logs a message to the client console.
/// @param message Message text (null-terminated)
void log_message(const char* message);

/// Gets the current game timestamp in milliseconds.
/// @return Timestamp in milliseconds
uint64_t get_game_timestamp_ms(void);

/// Sleeps for the specified number of milliseconds (Yield for JS event loop).
/// @param ms Milliseconds to sleep
void sleep_milliseconds(uint32_t ms);

#ifdef __cplusplus
}
#endif

#endif /* FREEMODE_CLIENT_API_H */