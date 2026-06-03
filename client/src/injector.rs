//! VEH Snapshot Injector — handles GTA5.exe loading via NtCreateSection + VEH.
//! 
//! This module implements the FiveM-style snapshot injection pipeline:
//! 1. Create section from GTA5.exe (SEC_IMAGE)
//! 2. Map view as executable memory
//! 3. Set up VEH handler for exception trapping
//! 4. Apply relocations, fix IAT, execute TLS callbacks
//! 5. Remove VEH and continue execution

use std::ptr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
use windows::Win32::Foundation::*;
#[cfg(windows)]
use windows::Win32::System::Diagnostics::Debug::*;
#[cfg(windows)]
use windows::Win32::System::Memory::*;
#[cfg(windows)]
use windows::Win32::System::Threading::*;

// Non-Windows stubs.
#[cfg(not(windows))]
type HANDLE = isize;
#[cfg(not(windows))]
type PCWSTR = *const u16;
#[cfg(not(windows))]
pub const SEC_IMAGE: u32 = 0x001_0000;
#[cfg(not(windows))]
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// ============================================================================
// Constants
// ============================================================================

/// VEH handler handle (set during injection).
pub static mut VEH_HANDLER_HANDLE: Option<usize> = None;

/// Trigger EP address — set based on game build version.
static mut TRIGGER_EP: usize = 0;

/// Maximum size for the executable image.
const MAX_IMAGE_SIZE: usize = 64 * 1024 * 1024; // 64 MB

// ============================================================================
// Shared context between launcher and game process
// ============================================================================

/// HostSharedData shared context — passed from launcher to game process.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SharedContext {
    /// Version info.
    pub major_version: u32,
    pub minor_version: u32,
    pub patch_level: u32,
    pub build_number: u32,

    /// Game paths (set by launcher).
    pub game_install_path: Vec<u16>,
    pub launch_options: Vec<u16>,
    pub steam_game_path: Vec<u16>,
    pub epic_game_path: Vec<u16>,
    pub rsg_game_path: Vec<u16>,

    /// Server name.
    pub server_name: [u8; 64],

    /// Callbacks from game to launcher (non-Windows stubs).
    pub notify_loading: usize,
}

// ============================================================================
// PE header types
// ============================================================================

#[repr(C)]
struct DosHeader {
    e_magic: u16,
    _e_cblp: u16,
    _e_cp: u16,
    _e_crlc: u16,
    _e_cparhdr: u16,
    _e_minalloc: u16,
    _e_maxalloc: u16,
    _e_ss: u16,
    _e_csp: u16,
    _e_flinit: u16,
    _e_flmaxrs: u16,
    _e_flsum: u16,
    _e_lfarlc: u16,
    _e_ovno: u16,
    _e_res: [u16; 4],
    _e_oemid: u16,
    _e_oeminfo: u16,
    _e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
struct FileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[cfg(windows)]
#[repr(C)]
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

/// ImageOptionalHeader — we only parse what we need.
#[repr(C)]
struct ImageOptionalHeader {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    // ImageExtensionFnsPointer (*PFN)
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    _major_operating_system_version: u16,
    _minor_operating_system_version: u16,
    _major_image_version: u16,
    _minor_image_version: u16,
    _major_subsystem_version: u16,
    _minor_subsystem_version: u16,
    _win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    _check_sum: u32,
    _subsystem: u16,
    _dll_flags: u16,
}

#[repr(C)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    _number_of_relocations: u16,
    _number_of_linenumbers: u16,
    characteristics: u32,
}

// ============================================================================
// Trigger addresses (build-specific)
// ============================================================================

/// Returns the trigger address for the current build.
fn get_trigger_ep(_build_number: u32) -> usize {
    // stub — in production this would be build-specific.
    unsafe { TRIGGER_EP }
}

/// Checks if a given address is the trigger address.
pub fn is_trigger_address(addr: usize) -> bool {
    #[allow(unused_variables)]
    let ep = get_trigger_ep(0);
    addr == ep || (ep != 0 && addr >= ep && addr < ep + 16)
}

// ============================================================================
// Section creation and snapshot injection (Windows-only)
// ============================================================================

/// Creates a section handle from the GTA5.exe file path.
#[cfg(windows)]
pub fn create_section_from_image(gta_path: std::ffi::OsString) -> windows_core::Result<HANDLE> {
    unsafe {
        let wide_path: Vec<u16> = gta_path.encode_wide().chain(std::iter::once(0)).collect();
        let file_handle = CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )?;

        // Stub NtCreateSection — in production, call via ntdll.dll.
        let section = HANDLE(ptr::null_mut());
        Ok(section)
    }
}

#[cfg(not(windows))]
pub fn create_section_from_image(_: std::ffi::OsString) -> Result<HANDLE, String> {
    Err("Not available on non-Windows".to_string())
}

/// Injects a snapshot by creating a section from the GTA5.exe path and mapping it.
#[cfg(windows)]
pub fn inject_snapshot(gta_path: std::ffi::OsString) -> windows_core::Result<(*mut c_void, usize)> {
    let _ = gta_path;
    unsafe {
        let base_address = VirtualAlloc(
            None,
            MAX_IMAGE_SIZE,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );

        if base_address.is_null() {
            return Err(windows_core::Error::from_win32());
        }

        Ok((base_address, MAX_IMAGE_SIZE))
    }
}

#[cfg(not(windows))]
pub fn inject_snapshot(_: std::ffi::OsString) -> Result<(*mut std::ffi::c_void, usize), String> {
    Err("Not available on non-Windows".to_string())
}

// ============================================================================
// VEH (Vectored Exception Handling)
// ============================================================================

/// Installs a VEH handler for snapshot injection.
#[cfg(windows)]
pub fn install_veh_handler() -> usize {
    unsafe {
        AddVectoredExceptionHandler(1, Some(snapshot_handler)) as usize
    }
}

/// Removes a previously installed VEH handler.
#[cfg(windows)]
pub fn remove_veh_handler(cookie: usize) {
    unsafe { RemoveVectoredExceptionHandler(std::mem::transmute(cookie)); }
}

/// VEH exception handler for snapshot injection.
extern "system" fn snapshot_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    #[cfg(windows)]
    unsafe {
        let exc = (*(*exception_info).ExceptionRecord).ExceptionCode;
        // EXCEPTION_BREAKPOINT = 0x80000003, check NTSTATUS value
        if exc.0 != 0x80000003 && exc.0 != 0xC0000005 {
            return 0; // EXCEPTION_CONTINUE_SEARCH
        }

        let exception_addr = (*(*exception_info).ExceptionRecord).ExceptionInformation[1] as usize;
        if !is_trigger_address(exception_addr) {
            return 0;
        }

        let gta_module = GetModuleHandleW(PCWSTR(ptr::null()));
        let module_base = match gta_module {
            Ok(h) => h.0 as usize,
            Err(_) => 0,
        };
        if module_base != 0 {
            apply_relocations(module_base);
            fix_iat(module_base);
            execute_tls_callbacks(module_base);
        }

        (*(*exception_info).ContextRecord).ContextFlags = CONTEXT_ALL;
        (*(*exception_info).ContextRecord).Rip = exception_addr as u64;
        1 // EXCEPTION_CONTINUE_EXECUTION
    }
    #[cfg(not(windows))]
    {
        -1
    }
}

// ============================================================================
// PE Parsing and Relocation Application
// ============================================================================

/// Applies relocations to the mapped image (simplified).
pub fn apply_relocations(_base: usize) {
    // stub — in production, parse PE headers and apply base relocations.
}

/// Fixes the Import Address Table (IAT) for the mapped image.
#[cfg(windows)]
pub fn fix_iat(_base: usize) {
    // stub — in production, parse PE IAT and call LoadLibrary/GetProcAddress.
}

/// Executes TLS callbacks for the mapped image.
#[cfg(windows)]
pub fn execute_tls_callbacks(_base: usize) {
    // stub — in production, iterate TLS directory and call callbacks.
}

// ============================================================================
// Windows FFI helpers
// ============================================================================

#[cfg(windows)]
mod ffi_helpers {
    pub const SECTION_ALL_ACCESS: u32 = 0x10000000;
    pub const GENERIC_READ: u32 = 0x80000000;
    pub const FILE_SHARE_READ: u32 = 0x00000001;
    pub const OPEN_EXISTING: u32 = 3;
    pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

    pub use windows::Win32::System::Memory::{VirtualAlloc, MapViewOfFile, UnmapViewOfFile};
}

// ============================================================================
// DLL Injection from Launcher Folder (FiveM-style redirector)
// ============================================================================

/// Injects the FreeMode client DLL into GTA5.exe using AddDllDirectory + LoadLibrary.
#[cfg(windows)]
pub fn inject_dll_from_launcher_folder(_gta5_process: HANDLE) -> windows_core::Result<()> {
    unsafe {
        // Get the launcher executable's directory.
        let launcher_exe = std::env::current_exe()?;
        
        let launcher_dir = launcher_exe.parent()
            .ok_or_else(|| windows_core::Error::from_win32())?;
        
        // Path to our client DLL: <launcher_folder>/freemode-client.dll
        let dll_path = launcher_dir.join("freemode-client.dll");
        
        if !dll_path.exists() {
            return Err(windows_core::Error::from_win32());
        }
        
        // Convert to wide string.
        let _wide_dll: Vec<u16> = dll_path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        
        // Open the target process.
        let process = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
            false,
            0, // Stub: would use GetProcessId()
        )?;
        
        // Allocate memory in target process for path.
        let remote_path = VirtualAllocEx(
            process,
            None,
            0,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        );
        
        if remote_path.is_null() {
            let _ = CloseHandle(process);
            return Err(windows_core::Error::from_win32());
        }
        
        // Create remote thread that calls LoadLibraryW.
        let h_kernel32 = GetModuleHandleW(PCWSTR(b"kernel32.dll\0".as_ptr() as *const u16))?;
        let load_library_addr = GetProcAddress(
            h_kernel32,
            windows_core::PCSTR(b"LoadLibraryW\0".as_ptr()),
        )?;
        
        if load_library_addr.is_none() {
            let _ = VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
            let _ = CloseHandle(process);
            return Err(windows_core::Error::from_win32());
        }
        
        let thread = CreateRemoteThread(
            process,
            None,
            0,
            Some(std::mem::transmute(load_library_addr.unwrap())),
            Some(remote_path as *const c_void),
            0,
            None,
        )?;
        
        if thread.0.is_null() {
            let _ = VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
            let _ = CloseHandle(process);
            return Err(windows_core::Error::from_win32());
        }
        
        // Wait for the thread to complete.
        let _ = WaitForSingleObject(thread, INFINITE);
        
        // Cleanup.
        let _ = VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        let _ = CloseHandle(thread);
        let _ = CloseHandle(process);
        
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn inject_dll_from_launcher_folder(_: HANDLE) -> Result<(), String> {
    Err("DLL injection not available on non-Windows".to_string())
}

/// Gets the path to the client DLL relative to the launcher folder.
pub fn get_client_dll_path() -> Option<std::path::PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return Some(dir.join("freemode-client.dll"));
        }
    }
    None
}

// ============================================================================
// Public API
// ============================================================================

/// Initializes the injector module.
pub fn init() {
    // Install VEH handler for snapshot injection.
    #[cfg(windows)]
    unsafe {
        VEH_HANDLER_HANDLE = Some(install_veh_handler());
    }
}

/// Shutdown the injector.
pub fn shutdown() {
    #[cfg(windows)]
    unsafe {
        if let Some(cookie) = VEH_HANDLER_HANDLE {
            remove_veh_handler(cookie);
        }
        VEH_HANDLER_HANDLE = None;
    }
}

/// Gets the trigger address for snapshot injection.
pub fn get_trigger_ep_addr() -> usize {
    unsafe { TRIGGER_EP }
}