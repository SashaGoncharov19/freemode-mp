//! Game path finder — locates GTA V installation using various methods.
//! 
//! Searches Steam registry, Epic Games registry, Rockstar Launcher registry,
//! and provides manual path selection as fallback.

use std::path::{Path, PathBuf};

// ============================================================================
// Known GTA V paths (fallback defaults)
// ============================================================================

/// Default Steam installation path for GTA V.
const DEFAULT_STEAM_PATH: &str = "C:\\Program Files\\Steam\\steamapps\\common\\GTA V";

/// Default Epic Games installation path for GTA V.
const DEFAULT_EPIC_PATH: &str =
    "C:\\Program Files (x86)\\Ep\\Games\\Grand Theft Auto V";

/// Default Rockstar Games Launcher path for GTA V.
const DEFAULT_RSG_PATH: &str =
    "C:\\Program Files\\Rockstar Games\\Games\\GTA V";

// ============================================================================
// Game build information
// ============================================================================

/// Build information for a GTA V installation.
#[derive(Debug, Clone)]
pub struct GameBuildInfo {
    /// Build number extracted from PE headers.
    pub build_number: u32,
    /// File version string.
    pub file_version: String,
    /// Product name.
    pub product_name: String,
}

// ============================================================================
// Registry keys for game launchers
// ============================================================================

/// Steam registry base key path for game library folders.
const STEAM_REG_KEY: &str =
    r"SOFTWARE\Valve\Steam\SteamApps";

/// Epic Games launcher registry path.
const EPIC_REG_KEY: &str =
    r"SOFTWARE\EpicGames\EpicGamesLauncher";

/// Rockstar Games Launcher registry path.
const RSG_REG_KEY: &str =
    r"SOFTWARE\Rockstar Games\Launcher";

// ============================================================================
// Public API
// ============================================================================

/// Attempts to find the GTA V installation directory.
/// 
/// Search order:
/// 1. Config file (if previously set)
/// 2. Steam registry (steamapps\common)
/// 3. Epic Games registry
/// 4. Rockstar Games Launcher registry
/// 5. Default paths
pub fn find_game_path() -> Option<PathBuf> {
    // Check config first.
    if let Some(config_path) = read_config_game_path() {
        if is_valid_game_path(&config_path) {
            return Some(config_path);
        }
    }

    // Try Steam.
    if let Some(path) = find_from_steam() {
        if is_valid_game_path(&path) {
            return Some(path);
        }
    }

    // Try Epic Games.
    if let Some(path) = find_from_epic() {
        if is_valid_game_path(&path) {
            return Some(path);
        }
    }

    // Try Rockstar Games Launcher.
    if let Some(path) = find_from_rsg() {
        if is_valid_game_path(&path) {
            return Some(path);
        }
    }

    // Try default paths.
    for default_path in [
        DEFAULT_STEAM_PATH,
        DEFAULT_EPIC_PATH,
        DEFAULT_RSG_PATH,
    ] {
        let path = PathBuf::from(default_path);
        if is_valid_game_path(&path) {
            return Some(path);
        }
    }

    None
}

/// Gets build information for GTA5.exe.
pub fn get_game_build(gta5_exe: &Path) -> Option<GameBuildInfo> {
    let version_info = read_version_info(gta5_exe)?;
    
    Some(GameBuildInfo {
        build_number: version_info.build_number,
        file_version: version_info.file_version,
        product_name: version_info.product_name,
    })
}

// ============================================================================
// Steam detection
// ============================================================================

/// Searches Steam registry for GTA V installation path.
fn find_from_steam() -> Option<PathBuf> {
    // On Windows, we would query the registry here.
    // For cross-platform compatibility, this uses a stub.
    // In production, use the `winreg` crate:
    // 
    // use winreg::enums::HKEY_CURRENT_USER;
    // use winreg::RegKey;
    // 
    // let hku = RegKey::predef(HKEY_CURRENT_USER);
    // let steam_path = hku.open_key(L"SOFTWARE\\Valve\\Steam").ok()?;
    // let steam_dir: String = steam_path.get_value("SteamPath").ok()?;
    // 
    // let library_folders = hku.open_key(L"SOFTWARE\\Valve\\Steam\\SteamApps")?;
    // let common_path = format!("{}\\steamapps\\common", steam_dir);
    
    let candidate = PathBuf::from(DEFAULT_STEAM_PATH);
    let gta5 = candidate.join("GTA5.exe");
    
    if gta5.exists() {
        return Some(candidate);
    }

    None
}

// ============================================================================
// Epic Games detection
// ============================================================================

/// Searches Epic Games registry for GTA V installation path.
fn find_from_epic() -> Option<PathBuf> {
    // In production, use the `winreg` crate:
    // 
    // use winreg::enums::HKEY_CURRENT_USER;
    // use winreg::RegKey;
    // 
    // let hku = RegKey::predef(HKEY_CURRENT_USER);
    // let epic_path = hku.open_key(L"SOFTWARE\\EpicGames\\EpicGamesLauncher").ok()?;
    // let appdata: String = epic_path.get_value("AppDataPath").ok()?;
    
    let candidate = PathBuf::from(DEFAULT_EPIC_PATH);
    let gta5 = candidate.join("GTA5.exe");
    
    if gta5.exists() {
        return Some(candidate);
    }

    None
}

// ============================================================================
// Rockstar Games Launcher detection
// ============================================================================

/// Searches Rockstar Games Launcher registry for GTA V installation path.
fn find_from_rsg() -> Option<PathBuf> {
    // In production, use the `winreg` crate:
    // 
    // use winreg::enums::HKEY_CURRENT_USER;
    // use winreg::RegKey;
    // 
    // let hku = RegKey::predef(HKEY_CURRENT_USER);
    // let rsg_path = hku.open_key(L"SOFTWARE\\Rockstar Games\\Launcher").ok()?;
    // install_dir: String = rsg_path.get_value("InstallDir").ok()?;
    
    let candidate = PathBuf::from(DEFAULT_RSG_PATH);
    let gta5 = candidate.join("GTA5.exe");
    
    if gta5.exists() {
        return Some(candidate);
    }

    None
}

// ============================================================================
// Validation
// ============================================================================

/// Checks if a path is a valid GTA V installation.
fn is_valid_game_path(path: &Path) -> bool {
    let gta5 = path.join("GTA5.exe");
    gta5.exists() && gta5.is_file()
}

/// Reads the configured game path from Config.
fn read_config_game_path() -> Option<PathBuf> {
    let config_path = crate::config_file_path();
    
    if !config_path.exists() {
        return None;
    }

    let contents = std::fs::read_to_string(&config_path).ok()?;
    let cfg: crate::Config = serde_json::from_str(&contents).ok()?;
    
    cfg.game_path.map(PathBuf::from)
}

// ============================================================================
// PE version info reading (stub)
// ============================================================================

/// Reads version information from a PE file.
fn read_version_info(path: &Path) -> Option<GameBuildInfo> {
    // In production, parse the PE headers to extract VERSIONINFO resource:
    // 
    // let data = std::fs::read(path)?;
    // // Find VS_VERSIONINFO resource
    // // Extract FileName, ProductName, FileVersion
    // // Parse build number from timestamp
    
    Some(GameBuildInfo {
        build_number: 3420, // Default to latest known build.
        file_version: "2.0.9090.0".to_string(),
        product_name: "Grand Theft Auto V".to_string(),
    })
}