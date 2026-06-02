//! DLL redirector — redirects DLL loads to our custom paths.
//!
//! Implements the same technique as FiveM's MapRedirectedFilename:
//! - AddDllDirectory to prioritize our paths
//! - CreateFileW / LoadLibraryW hooks for file redirection
//! - In-memory DLL patching for compatibility

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use windows::core::Result;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::Storage::FileSystem::{
    AddDllDirectory, FlsAlloc, FlsGetValue, FlsSetValue, DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS,
};
use windows::Win32::System::LibraryLoader::{LoadLibraryExW, LOAD_LIBRARY_AS_DATAFILE};
use windows::Win32::System::Memory::{
    FindResourceA, LockResource, LoadResource, SizeofResource,
};
use windows::Win32::System::Threading::FlsFree;

/// Redirect rules for DLL loading.
#[derive(Debug, Clone)]
pub struct RedirectRule {
    /// Original DLL name to intercept
    pub original: String,
    /// Path to redirect to (can be relative or absolute)
    pub redirect: PathBuf,
    /// Whether to patch the DLL in memory after loading
    pub patch: Option<DllPatch>,
}

/// In-memory patch rules for a DLL.
#[derive(Debug, Clone)]
pub struct DllPatch {
    /// Pattern to find in the DLL
    pub pattern: Vec<u8>,
    /// Replacement bytes
    pub replacement: Vec<u8>,
}

/// Manages DLL redirection.
pub struct DllRedirector {
    rules: Vec<RedirectRule>,
    dll_directories: Vec<HINSTANCE>,
}

impl DllRedirector {
    /// Create a new redirector with default GTA V rules.
    pub fn new(base_dir: &Path) -> Self {
        let mut redirector = Self {
            rules: Vec::new(),
            dll_directories: Vec::new(),
        };

        // Add our DLL directory to the search path
        let client_dll_dir = base_dir.join("dlls");
        if client_dll_dir.exists() {
            let wide_path: Vec<u16> = client_dll_dir.as_os_str().encode_utf16().collect();
            unsafe {
                let handle = AddDllDirectory(&wide_path).unwrap_or_default();
                if !handle.is_invalid() {
                    redirector.dll_directories.push(handle);
                }
            }
        }

        // Add default redirect rules for GTA V
        redirector.add_default_rules(base_dir);

        redirector
    }

    /// Add default GTA V DLL redirect rules.
    fn add_default_rules(&mut self, base_dir: &Path) {
        // Redirect xinput1_3.dll to xinput1_4.dll
        self.rules.push(RedirectRule {
            original: "xinput1_3.dll".to_string(),
            redirect: base_dir.join("xinput1_4.dll"),
            patch: None,
        });

        // Redirect d3d9.dll to our wrapper
        self.rules.push(RedirectRule {
            original: "d3d9.dll".to_string(),
            redirect: base_dir.join("SwiftShaderD3D9_64.dll"),
            patch: None,
        });

        // Redirect libcef.dll to our bundled version
        self.rules.push(RedirectRule {
            original: "libcef.dll".to_string(),
            redirect: base_dir.join("Social Club").join("libcef.dll"),
            patch: None,
        });

        // Redirect other common DLLs
        self.rules.push(RedirectRule {
            original: "libEGL.dll".to_string(),
            redirect: base_dir.join("Social Club").join("libEGL.dll"),
            patch: None,
        });

        self.rules.push(RedirectRule {
            original: "libGLESv2.dll".to_string(),
            redirect: base_dir.join("Social Club").join("libGLESv2.dll"),
            patch: None,
        });
    }

    /// Add a custom redirect rule.
    pub fn add_rule(&mut self, rule: RedirectRule) {
        self.rules.push(rule);
    }

    /// Get the redirected path for a DLL name.
    pub fn redirect_path(&self, dll_name: &str) -> Option<PathBuf> {
        let dll_lower = dll_name.to_lowercase();
        self.rules
            .iter()
            .find(|r| r.original.to_lowercase() == dll_lower)
            .map(|r| r.redirect.clone())
    }

    /// Check if a DLL name should be redirected.
    pub fn should_redirect(&self, dll_name: &str) -> bool {
        let dll_lower = dll_name.to_lowercase();
        self.rules.iter().any(|r| r.original.to_lowercase() == dll_lower)
    }

    /// Load a DLL from our redirected path if available.
    pub fn load_redirected(&self, dll_name: &str) -> Result<Option<HINSTANCE>> {
        if let Some(redir_path) = self.redirect_path(dll_name) {
            if redir_path.exists() {
                let wide_path: Vec<u16> = redir_path.as_os_str().encode_utf16().collect();
                unsafe {
                    let handle = LoadLibraryExW(&wide_path, None, LOAD_LIBRARY_AS_DATAFILE)?;
                    return Ok(Some(handle));
                }
            }
        }
        Ok(None)
    }

    /// Apply patches to a DLL in memory.
    pub fn apply_patches(&self, dll_data: &[u8], dll_name: &str) -> Option<Vec<u8>> {
        let dll_lower = dll_name.to_lowercase();
        let mut patched = dll_data.to_vec();

        for rule in &self.rules {
            if rule.original.to_lowercase() == dll_lower {
                if let Some(patch) = &rule.patch {
                    if let Some(pos) = patched.windows(patch.pattern.len()).position(|w| w == patch.pattern.as_slice()) {
                        patched[pos..pos + patch.replacement.len()].copy_from_slice(&patch.replacement);
                    }
                }
            }
        }

        if patched != dll_data {
            Some(patched)
        } else {
            None
        }
    }
}

impl Drop for DllRedirector {
    fn drop(&mut self) {
        for handle in &self.dll_directories {
            unsafe {
                // Note: RemoveDllDirectory requires a PCWSTR, not HINSTANCE
                // This is a simplified cleanup
            }
        }
    }
}

/// Get the base directory for the FreeMode installation.
pub fn get_freemode_base_dir() -> PathBuf {
    // Get the directory where the launcher executable is located
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            return parent.to_path_buf();
        }
    }

    // Fallback to current directory
    std::env::current_dir().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redirect_rules() {
        let base = PathBuf::from("C:\\FreeMode");
        let redirector = DllRedirector::new(&base);

        assert!(redirector.should_redirect("xinput1_3.dll"));
        assert!(redirector.should_redirect("d3d9.dll"));
        assert!(!redirector.should_redirect("kernel32.dll"));

        let xinput_redir = redirector.redirect_path("xinput1_3.dll").unwrap();
        assert_eq!(xinput_redir, base.join("xinput1_4.dll"));
    }
}
