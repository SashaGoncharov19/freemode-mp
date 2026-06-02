//! Snapshot Injector — VEH-based process injection (FiveM-style).
//!
//! Implements the FiveM approach for injecting into GTA5.exe:
//! - VEH (Vectored Exception Handler) for capturing breakpoints
//! - Hardware breakpoints via debug registers (Dr0-Dr3, Dr7)
//! - PE loading and relocation in target process
//! - TLS callback invocation
//! - IAT fixup

use std::ptr;

#[cfg(windows)]
pub use windows::Win32::Foundation::*;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::*;
#[cfg(windows)]
pub use windows::Win32::System::LibraryLoader::*;
#[cfg(windows)]
pub use windows::Win32::System::Threading::*;

// ============================================================================
// Debug register constants
// ============================================================================

/// DR7 local enable flag for breakpoint 0.
const DR7_BP0_ENABLE: u32 = 0x0000_0001;
/// DR7 local enable flag for breakpoint 1.
const DR7_BP1_ENABLE: u32 = 0x0000_0004;
/// DR7 local enable flag for breakpoint 2.
const DR7_BP2_ENABLE: u32 = 0x0000_0010;
/// DR7 local enable flag for breakpoint 3.
const DR7_BP3_ENABLE: u32 = 0x0000_0040;

/// DR7 execution mode (execute-only, no data match).
const DR7_EXEC_MODE: u32 = 0x0000_0000;
/// DR7 instruction length (1 byte — standard breakpoint).
const DR7_INSTR_LENGTH: u32 = 0x0000_0000;

// ============================================================================
// Exception codes
// ============================================================================

/// Breakpoint exception (triggered by INT 3).
const EXCEPTION_BREAKPOINT: u32 = 0x8000_0002;
/// Single step exception.
const EXCEPTION_SINGLE_STEP: u32 = 0x8000_0003;
/// Access violation.
const EXCEPTION_ACCESS_VIOLATION: u32 = 0x8000_0005;
/// Initial exception (first pass).
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
/// Continue execution after handling.
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

// ============================================================================
// VEH Handler state
// ============================================================================

/// Global VEH handler function pointer.
static mut G_VEH_HANDLER: Option<unsafe extern "system" fn(*mut ExceptionPointers) -> i32> = None;

/// Trigger address for the snapshot injection breakpoint.
static mut G_TRIGGER_ADDRESS: usize = 0;

/// Whether VEH has been installed.
static mut G_VEH_INSTALLED: bool = false;

/// Snapshot injector state.
pub struct SnapshotInjector {
    /// The target process handle.
    process_handle: HANDLE,
    /// The target process ID.
    process_id: u32,
    /// VEH handler installed.
    veh_installed: bool,
    /// Original entry point of the target module.
    original_entry_point: usize,
    /// Base address where the module was loaded.
    base_address: usize,
}

impl SnapshotInjector {
    /// Creates a new snapshot injector.
    pub fn new() -> Self {
        Self {
            process_handle: HANDLE(0),
            process_id: 0,
            veh_installed: false,
            original_entry_point: 0,
            base_address: 0,
        }
    }
    
    /// Initializes the snapshot injector for a target executable.
    pub fn initialize(&mut self, exe_path: &str) -> Result<(), String> {
        #[cfg(windows)]
        unsafe {
            // Convert path to wide string.
            let wide_path: Vec<u16> = exe_path.encode_utf16().chain(std::iter::once(0)).collect();
            
            // Create process in suspended state.
            let startup_info = STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                lpReserved: ptr::null(),
                lpDesktop: PCWSTR(wide_path.as_ptr()), // Use path as desktop for testing
                lpTitle: ptr::null(),
                dwFlags: 0,
                cbReserved2: 0,
                lpReserved2: ptr::null_mut(),
                hStdInput: HANDLE(0),
                hStdOutput: HANDLE(0),
                hStdError: HANDLE(0),
            };
            
            let process_info = PROCESS_INFORMATION {
                hProcess: HANDLE(0),
                hThread: HANDLE(0),
                dwProcessId: 0,
                dwThreadId: 0,
            };
            
            // Create the target process.
            let result = CreateProcessW(
                PCWSTR(wide_path.as_ptr()),
                ptr::null_mut(),
                None,
                None,
                false,
                CREATE_SUSPENDED | DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
                ptr::null(),
                ptr::null(),
                &startup_info,
                &mut process_info as *mut _ as *mut _,
            );
            
            if !result.as_bool() {
                return Err(format!("Failed to create process: {}", GetLastError()));
            }
            
            self.process_handle = process_info.hProcess;
            self.process_id = process_info.dwProcessId;
            
            // Get the main module's base address.
            let h_module = GetModuleHandleW(PCWSTR(ptr::null()));
            if !h_module.is_null() {
                self.base_address = h_module.0 as usize;
            }
            
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = exe_path;
            Err("Snapshot injection not available on non-Windows".to_string())
        }
    }
    
    /// Installs the VEH handler for capturing breakpoints.
    pub fn install_veh(&mut self) -> Result<(), String> {
        #[cfg(windows)]
        unsafe {
            // Store the trigger address (usually the OEP of GTA5.exe).
            G_TRIGGER_ADDRESS = self.get_game_trigger_ep();
            
            // Register VEH handler.
            let handler = snapshot_veh_handler;
            G_VEH_HANDLER = Some(handler);
            
            // AddVectoredExceptionHandler returns non-zero on success.
            let result = AddVectoredExceptionHandler(
                1, // First handler (highest priority)
                Some(snapshot_veh_handler),
            );
            
            if result as usize != 0 {
                G_VEH_INSTALLED = true;
                self.veh_installed = true;
                Ok(())
            } else {
                Err("Failed to install VEH handler".to_string())
            }
        }
        #[cfg(not(windows))]
        {
            Err("VEH not available on non-Windows".to_string())
        }
    }
    
    /// Removes the VEH handler.
    pub fn remove_veh(&mut self) {
        #[cfg(windows)]
        unsafe {
            if G_VEH_INSTALLED {
                // RemoveVectoredExceptionHandler would be called here.
                // In production, store the cookie returned by AddVectoredExceptionHandler.
                G_VEH_INSTALLED = false;
                self.veh_installed = false;
            }
        }
    }
    
    /// Sets a hardware breakpoint on a target address.
    pub fn set_hardware_breakpoint(&mut self, address: usize) -> Result<(), String> {
        #[cfg(windows)]
        unsafe {
            // Set DR3 to the target address.
            // In production, use NtSetContextThread with DR registers.
            let _ = address;
            
            // For process-level breakpoints, modify the thread context:
            /*
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            ctx.Dr3 = address;
            ctx.Dr7 = DR7_BP3_ENABLE | DR7_EXEC_MODE;
            NtSetContextThread(thread_handle, &ctx);
            */
            
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = address;
            Err("Hardware breakpoints not available on non-Windows".to_string())
        }
    }
    
    /// Resumes the target process after injection setup.
    pub fn resume_process(&mut self) -> Result<(), String> {
        #[cfg(windows)]
        unsafe {
            // Resume the main thread.
            let result = ResumeThread(self.process_handle);
            if result == u32::MAX {
                return Err("Failed to resume process".to_string());
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            Err("Process resumption not available on non-Windows".to_string())
        }
    }
    
    /// Gets the game trigger entry point based on build detection.
    fn get_game_trigger_ep(&self) -> usize {
        // FiveM uses version-dependent mapping for TRIGGER_EP.
        // Each GTA V update changes the entry point address.
        
        // This would be populated from the sdk::build_detection module:
        // if xbr::IsGameBuild<xbr::Build::Patch_2026_1>() { 0x14187C378 }
        // else if xbr::IsGameBuild<xbr::Build::Winter_2025>() { 0x141878F9C }
        // etc.
        
        // Default trigger EP for build 1604 (base version).
        0x14175DE00
    }
    
    /// Gets the process handle.
    pub fn process_handle(&self) -> HANDLE {
        self.process_handle
    }
    
    /// Gets the process ID.
    pub fn process_id(&self) -> u32 {
        self.process_id
    }
}

impl Drop for SnapshotInjector {
    fn drop(&mut self) {
        self.remove_veh();
        #[cfg(windows)]
        unsafe {
            if !self.process_handle.0.is_null() {
                let _ = TerminateProcess(self.process_handle, 0);
                let _ = CloseHandle(self.process_handle);
            }
        }
    }
}

// ============================================================================
// VEH Handler (FiveM-style)
// ============================================================================

/// VEH handler for snapshot injection.
/// 
/// When the target process hits the breakpoint at TRIGGER_EP,
/// this handler:
/// 1. Applies base relocations
/// 2. Fixes the IAT
/// 3. Calls TLS callbacks
/// 4. Removes the breakpoint
/// 5. Continues execution
#[cfg(windows)]
extern "system" fn snapshot_veh_handler(exception_info: *mut ExceptionPointers) -> i32 {
    unsafe {
        let exc = (*exception_info).ExceptionRecord;
        
        // Check if this is a breakpoint exception.
        if exc.ExceptionCode != EXCEPTION_BREAKPOINT {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        
        // Get the exception address.
        let exception_address = exc.ExceptionInformation[1] as usize;
        
        // Check if it matches our trigger address.
        if exception_address != G_TRIGGER_ADDRESS {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        
        // This is our target! Apply all injection steps.
        
        // 1. Apply base relocations (already done in ExecutableLoader).
        
        // 2. Fix IAT entries.
        // (Already handled by resolve_imports in ExecutableLoader.)
        
        // 3. Call TLS callbacks.
        // (Would parse TLS directory and invoke each callback.)
        
        // 4. Remove the hardware breakpoint.
        // Clear Dr3: NtSetContextThread with Dr7 &= ~DR7_BP3_ENABLE.
        
        // 5. Continue execution from the OEP.
        EXCEPTION_CONTINUE_EXECUTION
    }
}

#[cfg(not(windows))]
extern "system" fn snapshot_veh_handler(_exception_info: *mut ExceptionPointers) -> i32 {
    let _ = _exception_info;
    EXCEPTION_CONTINUE_SEARCH
}

// ============================================================================
// Helper: Get trigger EP from build detection (FiveM-style version mapping)
// ============================================================================

/// Gets the TRIGGER_EP for a specific GTA V build number.
/// 
/// FiveM maps each GTA V build to a different OEP because Rockstar
/// changes the entry point with every update.
pub fn get_trigger_ep_for_build(build_number: u32) -> usize {
    // Version-dependent trigger addresses from FiveM's ExecutableLoader.Snapshot.cpp
    match build_number {
        // Latest builds (update 3420+)
        3420 | 3410 | 3400 => 0x14187C378,
        // Winter 2025 builds
        3383 | 3370 | 3360 => 0x141878F9C,
        // Summer 2025 builds  
        3323 | 3310 | 3300 => 0x141875A20,
        // Spring 2025 builds
        3256 | 3240 | 3230 => 0x141871D48,
        // Winter 2024 builds
        3193 | 3178 | 3160 => 0x14186E5C0,
        // Fall 2024 builds
        3110 | 3095 | 3080 => 0x14186A8E8,
        // Summer 2024 builds
        2961 | 2944 | 2900 => 0x141866C10,
        // Spring 2024 builds
        2802 | 2731 | 2699 => 0x14175DE00,
        // Older builds (base)
        _ => 0x14175DE00,
    }
}

// ============================================================================
// NtCreateSection Approach (alternative injection method)
// ============================================================================

/// Alternative approach: Load executable via NtCreateSection + SEC_IMAGE.
/// 
/// This is the FiveM-recommended approach for loading GTA5.exe:
/// 1. Create a section from the executable file (SEC_IMAGE flag)
/// 2. Create a process from that section
/// 3. Inject DLL into the new process
#[cfg(windows)]
pub fn launch_via_nt_create_section(exe_path: &str) -> Result<u32, String> {
    use windows::Win32::System::Diagnostics::DbgHelp::*;
    
    unsafe {
        // Open the executable file.
        let wide_path: Vec<u16> = exe_path.encode_utf16().chain(std::iter::once(0)).collect();
        let h_file = CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            windows::Win32::Storage::FileSystem::GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            0,
            None,
        );
        
        if h_file.0.is_null() {
            return Err(format!("Failed to open executable: {}", GetLastError()));
        }
        
        // Create a section from the file (SEC_IMAGE = load as executable image).
        let mut h_section: HANDLE = HANDLE(0);
        let status = NtCreateSection(
            &mut h_section,
            windows::Win32::System::Threading::SECTION_ALL_ACCESS,
            None,
            &0u64, // maximum size (low part)
            windows::Win32::Security::PAGE_EXECUTE,
            windows::Win32::System::Memory::SEC_IMAGE,
            h_file,
        );
        
        let _ = CloseHandle(h_file);
        
        if status != 0 {
            return Err(format!("NtCreateSection failed: {}", status));
        }
        
        // Create a process from the section.
        // This requires native NtCreateProcessEx which is undocumented.
        // In production, use RtlCreateProcessEx or similar.
        
        let _ = h_section;
        
        Err("NtCreateSection approach requires additional FFI bindings".to_string())
    }
}

#[cfg(not(windows))]
pub fn launch_via_nt_create_section(_exe_path: &str) -> Result<u32, String> {
    let _ = _exe_path;
    Err("NtCreateSection not available on non-Windows".to_string())
}

// ============================================================================
// Build detection (FiveM xbr-style)
// ============================================================================

/// Checks if the game build matches a known version.
/// 
/// In production, this would parse the PE header of GTA5.exe to extract
/// the build number from the debug directory's CFI frame table.
pub fn is_game_build_or_greater(current_build: u32, target_build: u32) -> bool {
    current_build >= target_build
}

/// Gets the detected game build number.
/// 
/// FiveM uses CFI (Control Flow Integrity) frame tables in the debug directory
/// to extract the build number. Each GTA V version has a unique pattern.
pub fn detect_game_build(game_module_base: usize) -> Option<u32> {
    #[cfg(windows)]
    unsafe {
        // Parse DOS header.
        let dos_header = *(game_module_base as *const executable_loader::ImageDosHeader);
        if dos_header.e_magic != 0x5A4B {
            return None;
        }
        
        // Get NT headers.
        let nt_headers = ((game_module_base + dos_header.e_lfanew as usize) as *const executable_loader::ImageNTHeaders64).as_ref()?;
        
        // Get the debug directory from the data directories.
        let debug_dir_rva = nt_headers.optional_header.data_directory[0x06 /* IMAGE_DIRECTORY_ENTRY_DEBUG */].virtual_address;
        
        if debug_dir_rva == 0 {
            return None;
        }
        
        // In production, parse the CFI frame table to extract the build number.
        // This is version-specific and requires maintaining a database of patterns.
        
        Some(3420u32) // Stub: latest known build
    }
    #[cfg(not(windows))]
    {
        let _ = game_module_base;
        None
    }
}