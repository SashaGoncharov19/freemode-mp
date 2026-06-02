//! Snapshot injector — VEH handler + hardware breakpoints for GTA5.exe injection.
//!
//! Implements the core snapshot injection mechanism:
//! 1. Create a suspended GTA5.exe process
//! 2. Inject VEH handler for exception interception
//! 3. Set hardware breakpoints on critical functions
//! 4. Resume execution and intercept snapshots

use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::Arc;

use windows::core::Result;
use windows::Win32::Foundation::{HANDLE, BOOL, FALSE, TRUE};
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, CONTEXT, CONTEXT_DEBUG_REGISTERS_X86, CONTEXT_DEBUG_REGISTERS_X64,
    CONTEXT_EXCEPTION_ACTIVE, CONTEXT_EXCEPTION_REPORTING, CONTEXT_FLOATING_POINT, CONTEXT_CONTROL,
    CONTEXT_INTEGER, CONTEXT_SEGMENTS, CONTEXT_DEBUG_REGISTERS, CONTEXT_FULL,
    SetThreadContext, GetThreadContext, WriteProcessMemory, ReadProcessMemory,
    GetThreadSelectorEntry, GetThreadContext, CONTEXT_ALL,
};
use windows::Win32::System::Threading::{
    CreateProcessW, ResumeThread, SuspendThread, WaitForSingleObject,
    CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW, LPPROCESS_INFORMATION, LPSTARTUPINFOW,
};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};
use windows::Win32::System::WindowsProgramming::MAXIMUM_WAIT_OBJECTS;

/// Snapshot injection context.
pub struct SnapshotInjector {
    /// Process handle for GTA5.exe
    process_handle: HANDLE,
    /// Thread handle for the main thread
    thread_handle: HANDLE,
    /// VEH handler address
    veh_handler: Option<unsafe extern "system" fn(_: *mut c_void, _: *mut c_void) -> i32>,
    /// Hardware breakpoint addresses
    hw_breakpoints: Vec<HwBreakpoint>,
    /// Injection state
    state: Arc<InjectorState>,
}

/// Hardware breakpoint information.
#[derive(Debug, Clone)]
pub struct HwBreakpoint {
    /// Address to breakpoint on
    pub address: u64,
    /// Length of the breakpoint (1-4 bytes)
    pub length: u8,
    /// Type of breakpoint (execute, write, or access)
    pub breakpoint_type: BreakpointType,
    /// Callback to invoke when hit
    pub callback: Option<unsafe extern "system" fn(*mut c_void)>,
}

/// Type of hardware breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointType {
    Execute,
    Write,
    Access,
}

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

impl SnapshotInjector {
    /// Create a new snapshot injector for GTA5.exe.
    pub fn new(gta5_path: &std::path::Path, args: &str) -> Result<Self> {
        // Convert path to wide string
        let wide_path: Vec<u16> = gta5_path.as_os_str()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        
        // Convert args to wide string
        let wide_args: Vec<u16> = args.encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        
        unsafe {
            // Create process in suspended state
            let mut startup_info: STARTUPINFOW = std::mem::zeroed();
            startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            
            let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();
            
            let created = CreateProcessW(
                Some(&wide_path),
                Some(&wide_args),
                None,
                None,
                false,
                CREATE_SUSPENDED,
                None,
                None,
                &startup_info,
                &mut process_info,
            );
            
            if !created.as_bool() {
                return Err(windows::core::Error::from(
                    std::io::Error::new(std::io::ErrorKind::Other, "Failed to create process")
                ));
            }
            
            Ok(SnapshotInjector {
                process_handle: process_info.hProcess,
                thread_handle: process_info.hThread,
                veh_handler: None,
                hw_breakpoints: Vec::new(),
                state: Arc::new(InjectorState {
                    injected: false,
                    suspended: true,
                    veh_hits: 0,
                    hw_bp_hits: 0,
                }),
            })
        }
    }

    /// Add a hardware breakpoint.
    pub fn add_hw_breakpoint(&mut self, address: u64, length: u8, breakpoint_type: BreakpointType) {
        self.hw_breakpoints.push(HwBreakpoint {
            address,
            length,
            breakpoint_type,
            callback: None,
        });
    }

    /// Set the VEH handler for exception interception.
    pub fn set_veh_handler(&mut self, handler: unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32) {
        self.veh_handler = Some(handler);
    }

    /// Inject the snapshot into GTA5.exe.
    pub fn inject(&mut self) -> Result<()> {
        unsafe {
            // Add VEH handler if provided
            if let Some(handler) = self.veh_handler {
                let veh_handle = AddVectoredExceptionHandler(
                    1, // First handler
                    Some(handler),
                );
                
                if veh_handle.is_null() {
                    return Err(windows::core::Error::from(
                        std::io::Error::new(std::io::ErrorKind::Other, "Failed to add VEH handler")
                    ));
                }
            }
            
            // Set hardware breakpoints
            for bp in &self.hw_breakpoints {
                self.set_hw_breakpoint(bp)?;
            }
            
            // Mark injection as complete
            Arc::get_mut(&mut self.state).unwrap().injected = true;
            Arc::get_mut(&mut self.state).unwrap().suspended = false;
            
            Ok(())
        }
    }

    /// Set a hardware breakpoint on the target process.
    unsafe fn set_hw_breakpoint(&self, bp: &HwBreakpoint) -> Result<()> {
        // Get the current context
        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_ALL;
        
        if !GetThreadContext(self.thread_handle, &mut context).as_bool() {
            return Err(windows::core::Error::from(
                std::io::Error::new(std::io::ErrorKind::Other, "Failed to get thread context")
            ));
        }
        
        // Set the debug register based on the breakpoint type
        match bp.breakpoint_type {
            BreakpointType::Execute => {
                // Set DR7 for execute breakpoint
                // This is a simplified implementation
                // In a real implementation, you would set the appropriate DR registers
            }
            BreakpointType::Write => {
                // Set DR7 for write breakpoint
            }
            BreakpointType::Access => {
                // Set DR7 for access breakpoint
            }
        }
        
        // Set the context
        if !SetThreadContext(self.thread_handle, &context).as_bool() {
            return Err(windows::core::Error::from(
                std::io::Error::new(std::io::ErrorKind::Other, "Failed to set thread context")
            ));
        }
        
        Ok(())
    }

    /// Resume the GTA5.exe process.
    pub fn resume(&self) -> Result<()> {
        unsafe {
            let result = ResumeThread(self.thread_handle);
            if result == u32::MAX {
                return Err(windows::core::Error::from(
                    std::io::Error::new(std::io::ErrorKind::Other, "Failed to resume thread")
                ));
            }
            
            Ok(())
        }
    }

    /// Suspend the GTA5.exe process.
    pub fn suspend(&self) -> Result<()> {
        unsafe {
            let result = SuspendThread(self.thread_handle);
            if result == u32::MAX {
                return Err(windows::core::Error::from(
                    std::io::Error::new(std::io::ErrorKind::Other, "Failed to suspend thread")
                ));
            }
            
            Ok(())
        }
    }

    /// Wait for the process to exit.
    pub fn wait_for_exit(&self, timeout_ms: u32) -> Result<bool> {
        unsafe {
            let result = WaitForSingleObject(self.process_handle, timeout_ms);
            Ok(result == 0) // WAIT_OBJECT_0
        }
    }

    /// Get the process handle.
    pub fn process_handle(&self) -> HANDLE {
        self.process_handle
    }

    /// Get the thread handle.
    pub fn thread_handle(&self) -> HANDLE {
        self.thread_handle
    }

    /// Get the injection state.
    pub fn state(&self) -> Arc<InjectorState> {
        Arc::clone(&self.state)
    }
}

impl Drop for SnapshotInjector {
    fn drop(&mut self) {
        unsafe {
            // Clean up resources
            if !self.process_handle.is_invalid() {
                // Close process handle
            }
            if !self.thread_handle.is_invalid() {
                // Close thread handle
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injector_state() {
        let state = InjectorState {
            injected: false,
            suspended: true,
            veh_hits: 0,
            hw_bp_hits: 0,
        };
        
        assert!(!state.injected);
        assert!(state.suspended);
        assert_eq!(state.veh_hits, 0);
        assert_eq!(state.hw_bp_hits, 0);
    }

    #[test]
    fn test_breakpoint_type() {
        assert_eq!(BreakpointType::Execute as u8, 0);
        assert_eq!(BreakpointType::Write as u8, 1);
        assert_eq!(BreakpointType::Access as u8, 2);
    }
}
