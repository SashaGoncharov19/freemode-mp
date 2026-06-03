//! Snapshot injector — VEH handler + hardware breakpoints for GTA5.exe injection.
//! Simplified stub module that provides the interface for FiveM-style snapshot injection.

use std::sync::Arc;

/// Injection state tracking.
#[derive(Debug, Clone)]
pub struct InjectorState {
    /// Whether injection is complete
    pub injected: bool,
    /// Whether the process is suspended
    pub suspended: bool,
    /// Number of VEH hits
    pub veh_hits: u32,
    /// Number of hardware breakpoint hits
    pub hw_bp_hits: u32,
}

/// Snapshot injector (stub - actual injection handled in main.rs)
pub struct SnapshotInjector {
    process_handle: u64,
    thread_handle: u64,
    state: Arc<InjectorState>,
}

impl SnapshotInjector {
    pub fn new(_gta5_path: &std::path::Path, _args: &str) -> Result<Self, String> {
        Ok(SnapshotInjector {
            process_handle: 0,
            thread_handle: 0,
            state: Arc::new(InjectorState {
                injected: false,
                suspended: true,
                veh_hits: 0,
                hw_bp_hits: 0,
            }),
        })
    }

    pub fn add_hw_breakpoint(&mut self, _address: u64, _length: u8, _breakpoint_type: u8) {
        // Stub
    }

    pub fn set_veh_handler(&mut self, _handler: usize) {
        // Stub - VEH handled separately
    }

    pub fn inject(&mut self) -> Result<(), String> {
        Arc::get_mut(&mut self.state).unwrap().injected = true;
        Arc::get_mut(&mut self.state).unwrap().suspended = false;
        Ok(())
    }

    pub fn resume(&self) -> Result<(), String> {
        Ok(())
    }

    pub fn suspend(&self) -> Result<(), String> {
        Ok(())
    }

    pub fn wait_for_exit(&self, _timeout_ms: u32) -> Result<bool, String> {
        Ok(false)
    }

    pub fn process_handle(&self) -> u64 { self.process_handle }
    pub fn thread_handle(&self) -> u64 { self.thread_handle }
    pub fn state(&self) -> Arc<InjectorState> { Arc::clone(&self.state) }
}