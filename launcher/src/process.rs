//! Process management — stub implementation for job objects and process detection.

use std::ptr::null_mut;

/// Manages a game process via Windows Job Object (stub - not used in current launch flow).
pub struct JobManager {
    _dummy: usize,
}

impl JobManager {
    pub fn new(_name: &str) -> Result<Self, String> {
        Ok(JobManager { _dummy: 0 })
    }

    pub fn add_process(&self, _process_handle: u64) -> Result<(), String> { Ok(()) }
    pub fn is_process_in_job(&self, _process_handle: u64) -> Result<bool, String> { Ok(false) }
    pub fn handle(&self) -> u64 { 0 }
}

/// Information about a running process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

/// Wait for a process to appear by name (stub - no sysinfo dependency needed).
pub fn wait_for_process(name: &str, _timeout_secs: u64) -> Option<u32> {
    let _ = name;
    let _ = _timeout_secs;
    None
}

/// Get information about a running process (stub).
pub fn get_process_info(_pid: u32) -> Option<ProcessInfo> { None }