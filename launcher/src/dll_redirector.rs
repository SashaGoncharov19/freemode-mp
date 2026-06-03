//! DLL redirector — stub implementation for now.
//! Actual redirection handled by hooks::init_redirection_data() and detour functions in client DLL.

use std::path::{Path, PathBuf};

/// Redirect rules for DLL loading.
#[derive(Debug, Clone)]
pub struct RedirectRule {
    pub original: String,
    pub redirect: PathBuf,
}

/// Manages DLL redirection (stub - uses global redirection data from hooks).
pub struct DllRedirector {
    rules: Vec<RedirectRule>,
}

impl DllRedirector {
    pub fn new(_base_dir: &Path) -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, _rule: RedirectRule) {}

    pub fn redirect_path(&self, _dll_name: &str) -> Option<PathBuf> { None }
    pub fn should_redirect(&self, _dll_name: &str) -> bool { false }
}

/// Get the base directory for the FreeMode installation.
pub fn get_freemode_base_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
}
