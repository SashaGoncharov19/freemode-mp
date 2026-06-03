//! Game path finder — locates GTA V installation using registry keys and defaults.

use std::path::{Path, PathBuf};

/// Default Steam installation path for GTA V.
const DEFAULT_STEAM_PATH: &str = "C:\\Program Files\\Steam\\steamapps\\common\\GTA V";

/// Default Epic Games installation path for GTA V.
const DEFAULT_EPIC_PATH: &str = "C:\\Program Files (x86)\\Ep\\Games\\Grand Theft Auto V";

/// Default Rockstar Games Launcher path for GTA V.
const DEFAULT_RSG_PATH: &str = "C:\\Program Files\\Rockstar Games\\Games\\GTA V";

/// Build information for a GTA V installation (stub).
#[derive(Debug, Clone)]
pub struct GameBuildInfo {
    pub build_number: u32,
    pub file_version: String,
    pub product_name: String,
}

/// Attempts to find the GTA V installation directory.
pub fn find_game_path() -> Option<PathBuf> {
    // Try default paths in order
    for default_path in [DEFAULT_STEAM_PATH, DEFAULT_EPIC_PATH, DEFAULT_RSG_PATH] {
        let path = PathBuf::from(default_path);
        if is_valid_game_path(&path) {
            return Some(path);
        }
    }
    None
}

/// Gets build information for GTA5.exe (stub).
pub fn get_game_build(_gta5_exe: &Path) -> Option<GameBuildInfo> {
    Some(GameBuildInfo {
        build_number: 3420,
        file_version: "2.0.9090.0".to_string(),
        product_name: "Grand Theft Auto V".to_string(),
    })
}

/// Checks if a path is a valid GTA V installation.
fn is_valid_game_path(path: &Path) -> bool {
    let gta5 = path.join("GTA5.exe");
    gta5.exists() && gta5.is_file()
}