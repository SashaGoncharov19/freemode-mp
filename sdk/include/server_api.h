#ifndef FREEMODE_SERVER_API_H
#define FREEMODE_SERVER_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// ============================================================================
// Server-side JS Plugin API (C FFI)
// ============================================================================

/// Player handle (server-side).
typedef uint32_t player_handle;

/// Vehicle handle.
typedef uint32_t vehicle_handle;

/// Object handle.
typedef uint32_t object_handle;

/// Resource handle.
typedef uint32_t resource_handle;

// ============================================================================
// Player events
// ============================================================================

/// Called when a player connects.
/// @param player_id The player's ID
/// @param name Player name (null-terminated)
/// @param setKickReason If not NULL, set the kick reason (caller frees)
/// @return 0 if allowed, non-zero to reject connection
uint32_t on_player_connect(uint32_t player_id, const char* name, char* setKickReason);

/// Called when a player disconnects.
/// @param player_id The player's ID
/// @param reason Disconnect reason string (null-terminated)
void on_player_disconnect(uint32_t player_id, const char* reason);

/// Sets the player's display name.
/// @param player_id Player ID
/// @param name New name (null-terminated)
void set_player_name(uint32_t player_id, const char* name);

/// Gets the player's current name.
/// @param player_id Player ID
/// @param buffer Output buffer for the name
/// @param buffer_size Size of output buffer
/// @return Number of characters written (excluding null terminator)
size_t get_player_name(uint32_t player_id, char* buffer, size_t buffer_size);

/// Kicks a player.
/// @param player_id Player ID
/// @param reason Reason string (null-terminated)
void kick_player(uint32_t player_id, const char* reason);

/// Bans a player.
/// @param player_id Player ID
/// @param reason Reason string (null-terminated)
void ban_player(uint32_t player_id, const char* reason);

/// Gives the player some money.
/// @param player_id Player ID
/// @param currency Currency type (0 = cash, 1 = bank)
/// @param amount Amount to add (negative to remove)
void give_player_money(uint32_t player_id, int currency, int64_t amount);

/// Gets the player's money.
/// @param player_id Player ID
/// @param currency Currency type (0 = cash, 1 = bank)
/// @return Money amount
int64_t get_player_money(uint32_t player_id, int currency);

// ============================================================================
// Entity events
// ============================================================================

/// Called when any entity is created.
void on_entity_created(void);

/// Spawns a new vehicle.
/// @param model_hash Model hash of the vehicle
/// @param position Pointer to [x, y, z] (f32)
/// @param rotation Pointer to [pitch, roll, yaw] (f32)
/// @return Vehicle handle (0 on failure)
vehicle_handle spawn_vehicle(uint32_t model_hash, const float* position, const float* rotation);

/// Spawns a new object.
/// @param model_hash Model hash of the object
/// @param position Pointer to [x, y, z] (f32)
/// @param rotation Pointer to [pitch, roll, yaw] (f32)
/// @return Object handle (0 on failure)
object_handle spawn_object(uint32_t model_hash, const float* position, const float* rotation);

/// Destroys a vehicle.
/// @param vehicle_id Vehicle ID
void destroy_vehicle(vehicle_handle vehicle_id);

/// Destroys an object.
/// @param object_id Object ID
void destroy_object(object_handle object_id);

/// Sets entity position.
/// @param entity_id Entity handle
/// @param position Pointer to [x, y, z] (f32)
void set_entity_position(uint32_t entity_id, const float* position);

/// Gets entity position.
/// @param entity_id Entity handle
/// @param position Output buffer for [x, y, z] (must be at least 12 bytes)
int get_entity_position(uint32_t entity_id, float* position);

/// Sets entity health.
/// @param entity_id Entity handle
/// @param health New health value
void set_entity_health(uint32_t entity_id, float health);

/// Gets entity health.
/// @param entity_id Entity handle
/// @return Current health
float get_entity_health(uint32_t entity_id);

// ============================================================================
// World events
// ============================================================================

/// Sets the game time.
/// @param hour Hour (0-23)
/// @param minute Minute (0-59)
void set_game_time(int hour, int minute);

/// Gets the current game time.
/// @param hour Output for hour (NULL to skip)
/// @param minute Output for minute (NULL to skip)
void get_game_time(int* hour, int* minute);

/// Sets the weather override.
/// @param weather Weather type string (null-terminated): "EXTRASUNNY", "CLEAR", etc.
void set_weather(const char* weather);

/// Forces rain.
/// @param start If true, start rain; if false, stop rain.
void set_rain(int start);

// ============================================================================
// Audio events
// ============================================================================

/// Plays a sound for all players.
/// @param sound_library Sound library name (null-terminated)
/// @param sound_name Sound name (null-terminated)
void play_sound_for_all(const char* sound_library, const char* sound_name);

/// Plays a sound for a specific player.
/// @param player_id Player ID
/// @param sound_library Sound library name (null-terminated)
/// @param sound_name Sound name (null-terminated)
void play_sound_for_player(uint32_t player_id, const char* sound_library, const char* sound_name);

// ============================================================================
// Resource events
// ============================================================================

/// Called when the server is starting.
void on_server_start();

/// Called when the server is stopping.
void on_server_stop();

/// Starts a resource dynamically.
/// @param name Resource name (null-terminated)
/// @return Resource handle (0 on failure)
resource_handle start_resource(const char* name);

/// Stops a resource dynamically.
/// @param name Resource name (null-terminated)
/// @return 0 on success, non-zero on failure
int stop_resource(const char* name);

// ============================================================================
// Utility functions
// ============================================================================

/// Logs a message to the server console.
/// @param level Log level ("INFO", "WARNING", "ERROR")
/// @param message Message text (null-terminated)
void log_message(const char* level, const char* message);

/// Gets the current server timestamp in milliseconds.
/// @return Timestamp in milliseconds
uint64_t get_server_timestamp_ms(void);

/// Broadcasts a chat message to all connected players.
/// @param sender Sender name (null-terminated)
/// @param message Message text (null-terminated)
void broadcast_chat(const char* sender, const char* message);

/// Executes a command as if typed by the server console.
/// @param command Command string (null-terminated)
void execute_console_command(const char* command);

#ifdef __cplusplus
}
#endif

#endif /* FREEMODE_SERVER_API_H */