//! Snapshot Injector — VEH-based process injection (FiveM-style).

use std::ptr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
pub use windows::Win32::Foundation::*;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::*;
#[cfg(windows)]
pub use windows::Win32::System::LibraryLoader::*;
#[cfg(windows)]
pub use windows::Win32::System::Threading::*;

const EXCEPTION_BREAKPOINT: u32 = 0x8000_0002;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

static mut G_TRIGGER_ADDRESS: usize = 0;

pub struct SnapshotInjector {
    process_handle: HANDLE,
    process_id: u32,
    veh_installed: bool,
}

impl SnapshotInjector {
    pub fn new() -> Self {
        Self {
            process_handle: INVALID_HANDLE_VALUE,
            process_id: 0,
            veh_installed: false,
        }
    }
    
    pub fn initialize(&mut self, _exe_path: &str) -> std::result::Result<(), String> {
        #[cfg(windows)]
        unsafe {
            let startup_info = STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                ..std::mem::zeroed()
            };
            let mut process_info = PROCESS_INFORMATION {
                hProcess: HANDLE(ptr::null_mut()),
                hThread: HANDLE(ptr::null_mut()),
                dwProcessId: 0,
                dwThreadId: 0,
            };
            
            let wide_path: Vec<u16> = _exe_path.encode_utf16().chain(std::iter::once(0)).collect();
            let result = CreateProcessW(
                PCWSTR(ptr::null()),
                PCWSTR(wide_path.as_ptr() as *mut u16),
                None,
                None,
                false,
                CREATE_SUSPENDED,
                None,
                None,
                &mut startup_info as *mut _,
                &mut process_info as *mut _,
            );
            
            if !result.ok().is_ok() {
                return Err(format!("CreateProcessW failed"));
            }
            
            self.process_handle = process_info.hProcess;
            self.process_id = process_info.dwProcessId;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = _exe_path;
            Err("Not available on non-Windows".to_string())
        }
    }
    
    pub fn install_veh(&mut self) -> std::result::Result<(), String> {
        unsafe {
            G_TRIGGER_ADDRESS = 0x14175DE00;
            let result = AddVectoredExceptionHandler(1, Some(snapshot_veh_handler));
            if result as usize != 0 {
                self.veh_installed = true;
                Ok(())
            } else {
                Err("Failed to install VEH".to_string())
            }
        }
    }
    
    pub fn remove_veh(&mut self) {
        self.veh_installed = false;
    }
    
    pub fn resume_process(&mut self) -> std::result::Result<(), String> {
        #[cfg(windows)]
        unsafe {
            let result = ResumeThread(self.process_handle);
            if result == u32::MAX {
                return Err("ResumeThread failed".to_string());
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            Err("Not available on non-Windows".to_string())
        }
    }
    
    pub fn process_handle(&self) -> HANDLE {
        self.process_handle
    }
    
    pub fn process_id(&self) -> u32 {
        self.process_id
    }
}

impl Drop for SnapshotInjector {
    fn drop(&mut self) {
        if !self.process_handle.0.is_null() {
            #[cfg(windows)]
            unsafe { let _ = TerminateProcess(self.process_handle, 0); }
        }
    }
}

#[cfg(windows)]
extern "system" fn snapshot_veh_handler(_exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    EXCEPTION_CONTINUE_EXECUTION
}

pub fn get_trigger_ep_for_build(build_number: u32) -> usize {
    match build_number {
        3420 | 3410 | 3400 => 0x14187C378,
        3383 | 3370 | 3360 => 0x141878F9C,
        3323 | 3310 | 3300 => 0x141875A20,
        3256 | 3240 | 3230 => 0x141871D48,
        3193 | 3178 | 3160 => 0x14186E5C0,
        3110 | 3095 | 3080 => 0x14186A8E8,
        2961 | 2944 | 2900 => 0x141866C10,
        _ => 0x14175DE00,
    }
}

pub fn is_game_build_or_greater(current_build: u32, target_build: u32) -> bool {
    current_build >= target_build
}

pub fn detect_game_build(_game_module_base: usize) -> Option<u32> {
    let _ = _game_module_base;
    Some(3420)
}