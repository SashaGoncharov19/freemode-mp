// FreeMode Client DLL — GTA V client-side runtime module.

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
use windows_core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, HMODULE};

const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;
const INVALID_HANDLE_VALUE: HANDLE = HANDLE(std::ptr::null_mut());

// Raw FFI for shared memory since windows crate v0.58 doesn't export these functions
extern "system" {
    fn CreateFileMappingW(hFile: isize, lpAttributes: *const core::ffi::c_void, flProtect: u32, dwMaximumSizeHigh: u32, dwMaximumSizeLow: u32, lpName: PCWSTR) -> isize;
    fn MapViewOfFile(hFile: isize, dwDesiredAccess: u32, dwFileOffsetHigh: u32, dwFileOffsetLow: u32, dwNumberOfBytesToMap: usize) -> *mut core::ffi::c_void;
    fn UnmapViewOfFile(lpBaseAddress: *const core::ffi::c_void) -> i32;
}

const PAGE_READWRITE: u32 = 0x04;
const FILE_MAP_ALL_ACCESS: u32 = 0x000F001F;

static mut SHARED_CONTEXT_PTR: *mut SharedContextData = ptr::null_mut();
static mut IS_INITIALIZED: bool = false;
static mut G_HOOK_MANAGER: Option<HooksManager> = None;
static mut G_D3D11_HOOK: Option<d3d11_hook::D3D11HookManager> = None;

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
            major_version: 1, minor_version: 0, patch_level: 0, build_number: 0,
            game_install_path_len: 0, game_install_path: [0; 256],
            launch_options_len: 0, launch_options: [0; 64],
            steam_game_path_len: 0, steam_game_path: [0; 256],
            epic_game_path_len: 0, epic_game_path: [0; 256],
            rsg_game_path_len: 0, rsg_game_path: [0; 256],
            server_name_len: 0, server_name: [0; 64],
        }
    }
}

struct HooksManager;

static mut SHARED_CONTEXT_DATA: SharedContextData = SharedContextData {
    major_version: 0, minor_version: 0, patch_level: 0, build_number: 0,
    game_install_path_len: 0, game_install_path: [0; 256],
    launch_options_len: 0, launch_options: [0; 64],
    steam_game_path_len: 0, steam_game_path: [0; 256],
    epic_game_path_len: 0, epic_game_path: [0; 256],
    rsg_game_path_len: 0, rsg_game_path: [0; 256],
    server_name_len: 0, server_name: [0; 64],
};

#[no_mangle]
pub extern "system" fn DllMain(module: HMODULE, reason: u32, _: *mut core::ffi::c_void) -> bool {
    if reason == DLL_PROCESS_ATTACH { unsafe { _dll_attach(module); } }
    else if reason == DLL_PROCESS_DETACH { unsafe { _dll_detach(); } }
    true
}

unsafe fn _dll_attach(_module: HMODULE) {
    let _ = freemode_log::init_logger();
    freemode_log::info!("Client DLL DllMain called");
    _initialize_shared_context();
    if G_HOOK_MANAGER.is_none() {
        G_HOOK_MANAGER = Some(HooksManager);
        let result = hooks::apply_hooks();
        if result { freemode_log::hook!("All hooks applied successfully"); }
        else { freemode_log::error!("Failed to apply some hooks"); }
    }
    if G_D3D11_HOOK.is_none() {
        G_D3D11_HOOK = Some(d3d11_hook::D3D11HookManager::new());
        d3d11_hook::init();
        freemode_log::info!("D3D11 hook system initialized");
    }
    IS_INITIALIZED = true;
    freemode_log::inject!("Client DLL fully initialized — all systems ready");
}

unsafe fn _dll_detach() {
    if let Some(ref mut hook) = G_D3D11_HOOK {
        hook.unhook_all();
        hook.overlay_shaders = None;
        hook.dirty = false;
    }
    G_D3D11_HOOK = None;
    if let Some(_) = G_HOOK_MANAGER.take() { hooks::unapply_hooks(); }
    if !SHARED_CONTEXT_PTR.is_null() {
        unsafe { let _ = UnmapViewOfFile(SHARED_CONTEXT_PTR as *const core::ffi::c_void); }
        SHARED_CONTEXT_PTR = ptr::null_mut();
    }
    IS_INITIALIZED = false;
    freemode_log::warn!("Client DLL detached — cleanup complete");
}

fn _initialize_shared_context() {
    unsafe {
        let shm_name_wide = wide_str("Global\\FreeModeShm");

        let h_map = CreateFileMappingW(
            INVALID_HANDLE_VALUE.0 as isize,
            std::ptr::null(),
            PAGE_READWRITE,
            0,
            4096u32,
            PCWSTR(shm_name_wide.as_ptr()),
        );

        if h_map == 0 {
            freemode_log::error!("Failed to create shared memory for launcher communication");
            return;
        }

        let ptr = MapViewOfFile(
            h_map,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            4096,
        );

        if ptr.is_null() {
            freemode_log::error!("Failed to map shared memory view");
            return;
        }

        ptr::copy_nonoverlapping(
            ptr as *const u8,
            std::ptr::addr_of_mut!(SHARED_CONTEXT_DATA) as *mut u8,
            std::mem::size_of::<SharedContextData>(),
        );
        SHARED_CONTEXT_PTR = std::ptr::addr_of_mut!(SHARED_CONTEXT_DATA);

        freemode_log::load!("HostSharedData shared memory initialized: Global\\FreeModeShm");
    }
}

#[no_mangle]
pub extern "system" fn FreeModeClientInit() -> bool { unsafe { IS_INITIALIZED } }

#[no_mangle]
pub extern "system" fn FreeModeGetSharedContext() -> *mut SharedContextData {
    unsafe { SHARED_CONTEXT_PTR.cast::<SharedContextData>() }
}

#[no_mangle]
pub extern "system" fn FreeModeClientVersion() -> *const core::ffi::c_char {
    b"0.1.0\0".as_ptr() as *const core::ffi::c_char
}

#[no_mangle]
pub extern "system" fn FreeModeClientShutdown() { unsafe { _dll_detach(); } }

fn wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}

#[allow(dead_code)]
fn get_module_base() -> *mut core::ffi::c_void {
    unsafe {
        let name = wide_str("GTA5.exe");
        let hmod = windows::Win32::System::LibraryLoader::GetModuleHandleW(Some(&PCWSTR(name.as_ptr()))).unwrap_or_default();
        hmod.0 as *mut core::ffi::c_void
    }
}