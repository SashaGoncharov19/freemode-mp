/**
 * FreeMode Client-Side JavaScript API
 * 
 * Type definitions for client-side JS plugins using Bun.js runtime.
 * These types are exposed to the JS environment by the FreeMode client DLL.
 */

// ============================================================================
// Core types
// ============================================================================

/** Represents a game entity handle */
type EntityHandle = number;

/** 3D position vector */
interface Vector3 {
    x: number;
    y: number;
    z: number;
}

/** Rotation vector (pitch, roll, yaw in radians) */
interface Rotation {
    pitch: number;
    roll: number;
    yaw: number;
}

/** Game weather types */
type WeatherType = 
    | "EXTRASUNNY"
    | "CLEAR"
    | "CLOUDS"
    | "OVERCAST"
    | "RAIN"
    | "SMOG"
    | "FOGGY"
    | "XMAS"
    | "SNOWING"
    | "THUNDER"
    | "NEUTRAL";

/** Currency type for money operations */
type CurrencyType = "CASH" | "BANK";

// ============================================================================
// Player API
// ============================================================================

declare namespace client {
    /** Gets the local player's handle */
    function getLocalPlayer(): EntityHandle;

    /** Gets a player by handle */
    function getPlayer(handle: number): Player | null;

    /** Gets all connected players */
    function getPlayers(): Player[];

    /** Gets all players in a radius of the given position */
    function getPlayersInRange(position: Vector3, radius: number): Player[];

    /** Player object representing a connected player */
    interface Player {
        readonly handle: number;
        name: string;
        readonly team: number | null;
        readonly ping: number;
        readonly money: Record<CurrencyType, number>;
        
        position: Vector3;
        rotation: Rotation;
        
        /** Set player health (0-200) */
        setHealth(health: number): void;
        
        /** Get current health */
        getHealth(): number;
        
        /** Set player armor (0-100) */
        setArmor(armor: number): void;
        
        /** Get current armor */
        getArmor(): number;
        
        /** Teleport player to position */
        teleport(position: Vector3, rotation: Rotation): void;
        
        /** Kick player from server */
        kick(reason?: string): void;
        
        /** Ban player from server */
        ban(reason?: string): void;
    }
}

// ============================================================================
// Vehicle API
// ============================================================================

declare namespace client {
    /** Spawns a vehicle with the given model hash at position */
    function createVehicle(modelHash: number, position: Vector3, rotation?: Rotation): Vehicle | null;

    /** Gets a vehicle by handle */
    function getVehicle(handle: number): Vehicle | null;

    /** Gets all current vehicles */
    function getAllVehicles(): Vehicle[];

    /** Vehicle object representing a spawned vehicle */
    interface Vehicle {
        readonly handle: EntityHandle;
        modelHash: number;
        readonly model: string;
        
        position: Vector3;
        rotation: Rotation;
        heading: number;
        
        setHealth(health: number): void;
        getHealth(): number;
        
        /** Set vehicle speed */
        setSpeed(speed: number): void;
        
        /** Get vehicle speed */
        getSpeed(): number;
        
        explode(): void;
        
        delete(): void;
        
        /** Check if vehicle is currently in the world */
        exists(): boolean;
    }
}

// ============================================================================
// Object API (prop/object spawning)
// ============================================================================

declare namespace client {
    /** Spawns a game object with given model hash */
    function createObject(modelHash: number, position: Vector3, rotation?: Rotation): GameObject | null;

    /** Gets an object by handle */
    function getObject(handle: number): GameObject | null;

    /** Gets all current objects */
    function getAllObjects(): GameObject[];

    /** Game object (props, buildings, etc) */
    interface GameObject {
        readonly handle: EntityHandle;
        modelHash: number;
        
        position: Vector3;
        rotation: Rotation;
        
        setHealth(health: number): void;
        getHealth(): number;
        
        delete(): void;
        exists(): boolean;
    }
}

// ============================================================================
// World API
// ============================================================================

declare namespace client {
    /** Sets the current game time */
    function setGameTime(hour: number, minute: number): void;

    /** Gets the current game time */
    function getGameTime(): { hour: number; minute: number };

    /** Sets the weather override */
    function setWeather(weather: WeatherType): void;

    /** Toggles rain effect */
    function setRain(enabled: boolean): void;

    /** Sets the visibility distance (draw distance) */
    function setVisibilityDistance(distance: number): void;

    /** Gets the current game time in milliseconds */
    function getTimestamp(): number;
}

// ============================================================================
// Audio API
// ============================================================================

declare namespace client {
    /** Plays a sound for all players */
    function playSound(library: string, name: string): void;

    /** Plays a sound for a specific player */
    function playSoundForPlayer(player: EntityHandle, library: string, name: string): void;

    /** Plays a localized sound (e.g. from a radio station) */
    function playRadio(radioStation: string): void;
}

// ============================================================================
// Chat API
// ============================================================================

declare namespace client {
    /** Sends a chat message to all connected players */
    function broadcastChat(message: string, sender?: string): void;

    /** Sends a chat message to a specific player */
    function sendPlayerChat(player: EntityHandle, message: string): void;
}

// ============================================================================
// Resource API
// ============================================================================

declare namespace client {
    /** Starts a resource by name */
    function startResource(name: string): boolean;

    /** Stops a resource by name */
    function stopResource(name: string): boolean;

    /** Gets the current resource name */
    function getCurrentResourceName(): string;

    /** Gets a resource by name */
    function getResourceByName(name: string): Resource | null;

    interface Resource {
        readonly name: string;
        readonly state: "starting" | "started" | "stopping" | "stopped";
        readonly author: string;
        readonly description: string;
    }
}

// ============================================================================
// Event System
// ============================================================================

declare namespace client {
    /** Register a callback for an event */
    function on(eventName: string, callback: (...args: any[]) => void): void;

    /** Remove an event listener */
    function off(eventName: string, callback: (...args: any[]) => void): void;

    /** Trigger an event to the server */
    function triggerServerEvent(eventName: string, ...args: any[]): void;

    /** Register a callback for a server-sent event */
    function onServerEvent(eventName: string, callback: (...args: any[]) => void): void;

    // ========================================================================
    // Built-in events
    // ========================================================================
    
    /** Called when the client starts */
    function onClientStart(callback: () => void): void;

    /** Called when the client stops */
    function onClientStop(callback: () => void): void;

    /** Called when a player spawns */
    function onPlayerSpawn(playerId: number, position: Vector3): void;

    /** Called when a player despawns */
    function onPlayerDespawn(playerId: number): void;

    /** Called when a player connects */
    function onPlayerConnect(playerId: number, name: string): void;

    /** Called when a player disconnects */
    function onPlayerDisconnect(playerId: number, reason: string): void;

    /** Called when a vehicle is created */
    function onVehicleCreated(vehicleId: number, modelHash: number, position: Vector3): void;

    /** Called when a vehicle is destroyed */
    function onVehicleDestroyed(vehicleId: number): void;

    /** Called when a player enters a vehicle */
    function onPlayerEnterVehicle(playerId: number, vehicleId: number, seat: number): void;

    /** Called when a player exits a vehicle */
    function onPlayerExitVehicle(playerId: number, vehicleId: number): void;

    /** Called when an object is created */
    function onObjectCreated(objectId: number, modelHash: number): void;

    /** Called when an object is destroyed */
    function onObjectDestroyed(objectId: number): void;

    /** Called when a chat message is received */
    function onChatMessage(playerId: number, message: string): void;
}

// ============================================================================
// Utility functions (global scope)
// ============================================================================

/** Logs a message to the console */
declare function log(message: string, level?: "info" | "warning" | "error"): void;

/** Sleeps/yields for the specified milliseconds (non-blocking) */
declare function sleep(ms: number): Promise<void>;

/** Converts a string to its game hash */
declare function getHashKey(text: string): number;

/** Checks if a game hash is a valid object hash */
declare function isObject(hash: number): boolean;

/** Checks if a game hash is a valid vehicle hash */
declare function isVehicle(hash: number): boolean;

/** Checks if a game hash is a valid player model hash */
declare function isPlayerModel(hash: number): boolean;
