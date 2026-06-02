//! GTA V build detection system.
//! 
//! Provides functionality to detect the current GTA V build number
//! based on PE headers and CFI (Control Flow Integrity) frame tables,
//! following FiveM's approach for version-specific targeting.

/// Known GTA V build numbers with their entry points and descriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum KnownBuild {
    /// Patch 2026-1 (latest)
    Patch2026_1 = 3717,
    /// Winter 2025 update
    Winter2025 = 3593,
    /// Summer 2025 update  
    Summer2025 = 3545,
    /// Spring 2025 update
    Spring2025 = 3487,
    /// Patch 2025-1
    Patch2025_1 = 3420,
    /// Winter 2024 update
    Winter2024 = 3383,
    /// Summer 2024 update
    Summer2024 = 3323,
    /// Spring 2024 update
    Spring2024 = 3258,
    /// Patch 2024-1
    Patch2024_1 = 3207,
    /// Autumn 2023 update
    Autumn2023 = 3112,
    /// Summer 2023 update
    Summer2023 = 3034,
    /// Patch 2023-1
    Patch2023_1 = 2945,
    /// Legacy build (base)
    Legacy = 2751,
}

impl KnownBuild {
    /// Returns the trigger entry point address for this build.
    pub fn trigger_ep(&self) -> Option<u64> {
        match self {
            Self::Patch2026_1 => Some(0x14187C378),
            Self::Winter2025 => Some(0x141878F9C),
            Self::Summer2025 => Some(0x14186EF24),
            Self::Spring2025 => Some(0x141865B80),
            Self::Patch2025_1 => Some(0x14185E7A8),
            Self::Winter2024 => Some(0x14183A2F0),
            Self::Summer2024 => Some(0x1417F9C18),
            Self::Spring2024 => Some(0x1417D5E40),
            Self::Patch2024_1 => Some(0x1417B1A68),
            Self::Autumn2023 => Some(0x14178C690),
            Self::Summer2023 => Some(0x14175D2B8),
            Self::Patch2023_1 => Some(0x141738EE0),
            Self::Legacy => Some(0x14175DE00),
        }
    }

    /// Returns the build number as an integer.
    pub fn build_number(&self) -> i32 {
        *self as i32
    }

    /// Returns a human-readable name for this build.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Patch2026_1 => "Patch 2026-1",
            Self::Winter2025 => "Winter 2025",
            Self::Summer2025 => "Summer 2025",
            Self::Spring2025 => "Spring 2025",
            Self::Patch2025_1 => "Patch 2025-1",
            Self::Winter2024 => "Winter 2024",
            Self::Summer2024 => "Summer 2024",
            Self::Spring2024 => "Spring 2024",
            Self::Patch2024_1 => "Patch 2024-1",
            Self::Autumn2023 => "Autumn 2023",
            Self::Summer2023 => "Summer 2023",
            Self::Patch2023_1 => "Patch 2023-1",
            Self::Legacy => "Legacy (build 2751)",
        }
    }

    /// Returns the expected GTA V executable name for this build.
    pub fn exe_name(&self) -> &'static str {
        "GTA5.exe"
    }

    /// Returns the list of DLL suffixes that should be redirected for this build.
    pub fn dll_redirects(&self) -> &'static [DllRedirect] {
        match self {
            _ => DEFAULT_DLL_REDIRECTS,
        }
    }
}

/// A single DLL redirection rule.
#[derive(Debug, Clone, Copy)]
pub struct DllRedirect {
    /// The suffix to match (e.g., "xlive.dll").
    pub suffix: &'static str,
    /// The target file path or name.
    pub target: &'static str,
}

/// Default DLL redirection rules (FiveM-style).
pub const DEFAULT_DLL_REDIRECTS: &[DllRedirect] = &[
    DllRedirect {
        suffix: "xlive.dll",
        target: "", // INVALID_HANDLE_VALUE
    },
    DllRedirect {
        suffix: "d3d9.dll",
        target: "SwiftShaderD3D9_64.dll",
    },
    DllRedirect {
        suffix: "xinput1_3.dll",
        target: "xinput1_4.dll",
    },
    DllRedirect {
        suffix: "xinput1_2.dll",
        target: "xinput1_4.dll",
    },
    DllRedirect {
        suffix: "xinput1_1.dll",
        target: "xinput1_4.dll",
    },
    DllRedirect {
        suffix: "d3dcompiler_43.dll",
        target: "d3dcompiler_47.dll",
    },
    DllRedirect {
        suffix: "d3dcompiler_44.dll",
        target: "d3dcompiler_47.dll",
    },
    DllRedirect {
        suffix: "d3dcompiler_46.dll",
        target: "d3dcompiler_47.dll",
    },
];

/// Detected GTA build information.
#[derive(Debug, Clone)]
pub struct GameBuildInfo {
    /// The detected build number.
    pub build_number: i32,
    /// The matching known build (if any).
    pub known_build: Option<KnownBuild>,
    /// The trigger entry point address.
    pub trigger_ep: Option<u64>,
    /// Whether this build is supported.
    pub is_supported: bool,
}

impl GameBuildInfo {
    /// Creates a new unsupported game build info.
    pub fn unsupported(build_number: i32) -> Self {
        Self {
            build_number,
            known_build: None,
            trigger_ep: None,
            is_supported: false,
        }
    }

    /// Creates a new supported game build info.
    pub fn supported(kb: KnownBuild) -> Self {
        Self {
            build_number: kb.build_number(),
            known_build: Some(kb),
            trigger_ep: kb.trigger_ep(),
            is_supported: true,
        }
    }

    /// Gets the game build as an i32.
    pub fn as_i32(&self) -> i32 {
        self.build_number
    }
}

/// Detects the current GTA V build number from a loaded module.
pub fn detect_game_build(_module_base: *mut std::ffi::c_void) -> GameBuildInfo {
    #[cfg(windows)]
    {
        // MVP stub - will use PE header parsing when fully implemented.
        let _ = _module_base;
        GameBuildInfo::unsupported(-1)
    }

    #[cfg(not(windows))]
    {
        let _ = _module_base;
        GameBuildInfo::unsupported(-1)
    }
}

/// Finds a known build by PE timestamp.
fn find_build_by_timestamp(_timestamp: u32) -> Option<KnownBuild> {
    // MVP stub - full implementation will match against known GTA V build timestamps.
    let _ = _timestamp;
    None
}

/// Gets the current build info for a given module handle.
pub fn get_current_game_build() -> GameBuildInfo {
    // MVP stub - will be implemented with real PE parsing.
    GameBuildInfo::unsupported(-1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_build_trigger_ep() {
        for kb in [
            KnownBuild::Patch2026_1,
            KnownBuild::Winter2025,
            KnownBuild::Legacy,
        ] {
            assert!(kb.trigger_ep().is_some());
        }
    }

    #[test]
    fn test_dll_redirects() {
        let redirects = KnownBuild::Patch2026_1.dll_redirects();
        assert!(!redirects.is_empty());
        
        // Check that xlive.dll redirect has empty target (INVALID_HANDLE_VALUE)
        let xlive = redirects.iter().find(|r| r.suffix == "xlive.dll");
        assert!(xlive.is_some());
        assert_eq!(xlive.unwrap().target, "");
    }
}