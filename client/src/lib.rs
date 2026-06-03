// FreeMode Client DLL — GTA V client-side runtime module.
//
// This DLL is injected into GTA5.exe and provides:
// - VEH-based snapshot injection
// - API hooking (CreateFileW, LoadLibrary, etc.)
// - DirectX 11 hook for rendering overrides
// - CEF IPC bridge for webview communication
// - HostSharedData integration for launcher communication
// - Comprehensive logging of all inject/hook/load events

#![cfg(windows)]

mod injector;
mod hooks;
mod iat_hook;
mod executable_loader;
mod snapshot_injector;
mod d3d11_hook;
mod cef_bridge;

mod network_client;

use std::ptr;

// Windows FFI.
use windows::Win32::Foundation::{HANDLE, HMODULE};
use windows::Win32::Storage::FileSystem::{MapViewOfFile, FILE_MAP_ALL_ACCESS};
use windows::Win32::Security::SECURITY_ATTRIBUTES;

// DLL process attach/detach constants (available via Win32_Foundation feature).
const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;

// INVALID_HANDLE_VALUE constant for Windows.
const INVALID_HANDLE_VALUE: HANDLE = HANDLE(std::ptr::null_mut());

// TRUE constant for BOOL.
const FALSE: i32 = 0;
const TRUE: i32 = 1;

// ============================================================================
// Constants
// ============================================================================

/// Maximum shared context size.
const MAX_SHARED_CTX_SIZE: usize = 4 * 1024; // 4 KB

// ============================================================================
// Global state (mutable statics — require unsafe access)
// ============================================================================

static mut SHARED_CONTEXT_PTR: *mut SharedContextData = ptr::null_mut();
static mut IS_INITIALIZED: bool = false;
static mut G_HOOK_MANAGER: Option<HooksManager> = None;
static mut G_D3D11_HOOK: Option<d3d11_hook::D3D11HookManager> = None;

/// HostSharedData shared context data passed between launcher and game.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SharedContextData {
    pub major_version: u32,
    pub minor_version: u32,
    pub patch_level: u32,
    pub build_number: u32,
    pub game_install_path_len: u32,
    pub game_install_path: [u16; 256],
    pub launch_options_len: u32,
    pub launch_options: [u16; 64],
    pub steam_game_path_len: u32,
    pub steam_game_path: [u16; 256],
    pub epic_game_path_len: u32,
    pub epic_game_path: [u16; 256],
    pub rsg_game_path_len: u32,
    pub rsg_game_path: [u16; 256],
    pub server_name_len: u32,
    pub server_name: [u8; 64],
}

impl Default for SharedContextData {
    fn default() -> Self {
        SharedContextData {
            major_version: 1,
            minor_version: 0,
            patch_level: 0,
            build_number: 0,
            game_install_path_len: 0,
            game_install_path: [0; 256],
            launch_options_len: 0,
            launch_options: [0; 64],
            steam_game_path_len: 0,
            steam_game_path: [0; 256],
            epic_game_path_len: 0,
            epic_game_path: [0; 256],
            rsg_game_path_len: 0,
            rsg_game_path: [0; 256],
            server_name_len: 0,
            server_name: [0; 64],
        }
    }
}

/// Simple hooks manager wrapper.
struct HooksManager;

/// Global shared context data (in-process).
static mut SHARED_CONTEXT_DATA: SharedContextData = SharedContextData {
    major_version: 0,
    minor_version: 0,
    patch_level: 0,
    build_number: 0,
    game_install_path_len: 0,
    game_install_path: [0; 256],
    launch_options_len: 0,
    launch_options: [0; 64],
    steam_game_path_len: 0,
    steam_game_path: [0; 256],
    epic_game_path_len: 0,
    epic_game_path: [0; 256],
    rsg_game_path_len: 0,
    rsg_game_path: [0; 256],
    server_name_len: 0,
    server_name: [0; 64],
};

use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;

type PCWSTR = windows_core::PCWSTR;

// ============================================================================
// DllMain entry point
// ============================================================================

#[no_mangle]
pub extern "system" fn DllMain(module: HMODULE, reason: u32, _: *mut std::ffi::c_void) -> bool {
    if reason == DLL_PROCESS_ATTACH {
        unsafe { _dll_attach(module); }
    } else if reason == DLL_PROCESS_DETACH {
        unsafe { _dll_detach(); }
    }
    true
}

unsafe fn _dll_attach(_module: HMODULE) {
    // Initialize logging immediately.
    let _ = freemode_log::init_logger();
    freemode_log::info!("Client DLL DllMain called");

    // Initialize HostSharedData shared context.
    _initialize_shared_context();

    // Apply API hooks for game modification.
    if G_HOOK_MANAGER.is_none() {
        G_HOOK_MANAGER = Some(HooksManager);

        // Log hook application attempts.
        let result = hooks::apply_hooks();
        if result {
            freemode_log::hook!("All hooks applied successfully");
        } else {
            freemode_log::error!("Failed to apply some hooks");
        }
    }

    // Initialize DirectX 11 hook for rendering overrides.
    if G_D3D11_HOOK.is_none() {
        G_D3D11_HOOK = Some(d3d11_hook::D3D11HookManager::new());
        d3d11_hook::init();
        freemode_log::info!("D3D11 hook system initialized");
    }

    // Log successful initialization.
    IS_INITIALIZED = true;
    freemode_log::inject!("Client DLL fully initialized — all systems ready");
}

unsafe fn _dll_detach() {
    // Cleanup DirectX 11 hooks.
    if let Some(ref mut hook) = G_D3D11_HOOK {
        hook.unhook_all();
        hook.overlay_shaders = None;
        hook.dirty = false;
    }
    G_D3D11_HOOK = None;

    // Release API hooks.
    if let Some(_) = G_HOOK_MANAGER.take() {
        hooks::unapply_hooks();
    }

    // Unmap shared context.
    if !SHARED_CONTEXT_PTR.is_null() {
        unsafe {
            windows::Win32::Storage::FileSystem::UnmapViewOfFile(SHARED_CONTEXT_PTR as *const std::ffi::c_void);
        }
        SHARED_CONTEXT_PTR = ptr::null_mut();
    }

    IS_INITIALIZED = false;
    freemode_log::warn!("Client DLL detached — cleanup complete");
}

// ============================================================================
// Shared Context Helpers
// ============================================================================

/// Initializes the shared context memory mapping for launcher communication.
fn _initialize_shared_context() {
    let shm_name: Vec<u16> = OsStr::new("Global\\FreeModeShm")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // Create the shared memory mapping file.
        let h_map = windows::Win32::Storage::FileSystem::CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            None,
            SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: ptr::null_mut(),
                bInheritHandle: TRUE != FALSE,
            },
            0,
            MAX_SHARED_CTX_SIZE as u32,
            PCWSTR(shm_name.as_ptr()),
        );

        if h_map.is_null() {
            freemode_log::error!("Failed to create shared memory for launcher communication");
            return;
        }

        let ptr = MapViewOfFile(
            h_map,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            MAX_SHARED_CTX_SIZE,
        );

        if ptr.is_null() {
            freemode_log::error!("Failed to map shared memory view");
            return;
        }

        let ctx = std::ptr::addr_of_mut!(SHARED_CONTEXT_DATA).cast::<SharedContextData>();
        *ctx = SharedContextData::default();
        SHARED_CONTEXT_PTR = ctx;

        freemode_log::load!("HostSharedData shared memory initialized: Global\\FreeModeShm");
    }
}

// ============================================================================
// Exported Functions
// ============================================================================

/// Initializes the client DLL. Returns true on success, false on failure.
#[no_mangle]
pub extern "system" fn FreeModeClientInit() -> bool {
    unsafe { IS_INITIALIZED }
}

/// Gets the shared context data pointer.
#[no_mangle]
pub extern "system" fn FreeModeGetSharedContext() -> *mut SharedContextData {
    unsafe { SHARED_CONTEXT_PTR.cast::<SharedContextData>() }
}

/// Returns the version of the client DLL as a null-terminated string.
#[no_mangle]
pub extern "system" fn FreeModeClientVersion() -> *const std::ffi::c_char {
    b"0.1.0\0".as_ptr() as *const std::ffi::c_char
}

/// Shuts down the client DLL.
#[no_mangle]
pub extern "system" fn FreeModeClientShutdown() {
    unsafe { _dll_detach(); }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Converts a &str to a null-terminated PCWSTR (wide string).
#[allow(dead_code)]
fn str_to_pcw(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Gets the current process module base address.
#[allow(dead_code)]
fn get_module_base() -> *mut std::ffi::c_void {
    unsafe {
        let name = str_to_pcw("GTA5.exe");
        let hmod = windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR(name.as_ptr())).unwrap_or_default();
        hmod.0 as *mut std::ffi::c_void
    }
}