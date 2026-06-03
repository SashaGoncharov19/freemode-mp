//! API Hooking system — implements IAT hooking for DLL redirection and function hooks.

use std::os::windows::ffi::OsStrExt;

use windows_core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, HMODULE};
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::{
    GetModuleHandleW, LoadLibraryW, SetDefaultDllDirectories,
    AddDllDirectory, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
};

pub use crate::iat_hook::ImportHook;

static mut G_REDIRECTION_DATA: Vec<(String, String)> = Vec::new();

pub static mut ORIG_CREATEFILEW: usize = 0;
pub static mut ORIG_LOADLIBRARYW: usize = 0;
pub static mut ORIG_GETFILEATTRIBUTESW: usize = 0;
pub static mut ORIG_ADDDLLDIRECTORY: usize = 0;

static IS_HOOKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// Store hooked imports for unhooking
static mut G_HOOKED_IMPORTS: Vec<ImportHook> = Vec::new();

pub fn apply_hooks() -> bool {
    if IS_HOOKED.load(std::sync::atomic::Ordering::SeqCst) { return true; }
    
    register_dll_directories();
    init_redirection_data();
    
    #[cfg(windows)]
    unsafe {
        let gta5_base = get_gta5_module_base();
        
        // Hook kernel32.dll imports in our own process (we're injected into GTA5)
        match crate::iat_hook::hook_imports_in_module(
            0,
            "kernel32.dll",
            "LoadLibraryW\0",
            LoadLibraryW_detour_wrapper,
        ) {
            Ok(mut hook) => {
                if hook.hook().is_ok() {
                    G_HOOKED_IMPORTS.push(hook);
                    ORIG_LOADLIBRARYW = LoadLibraryW_detour_wrapper as usize;
                }
            }
            Err(_) => {}
        }
        
        match crate::iat_hook::hook_imports_in_module(
            0,
            "kernel32.dll",
            "CreateFileW\0",
            CreateFileW_detour_wrapper,
        ) {
            Ok(mut hook) => {
                if hook.hook().is_ok() {
                    G_HOOKED_IMPORTS.push(hook);
                    ORIG_CREATEFILEW = CreateFileW_detour_wrapper as usize;
                }
            }
            Err(_) => {}
        }
        
        match crate::iat_hook::hook_imports_in_module(
            0,
            "kernel32.dll",
            "GetFileAttributesW\0",
            GetFileAttributesW_detour_wrapper,
        ) {
            Ok(mut hook) => {
                if hook.hook().is_ok() {
                    G_HOOKED_IMPORTS.push(hook);
                    ORIG_GETFILEATTRIBUTESW = GetFileAttributesW_detour_wrapper as usize;
                }
            }
            Err(_) => {}
        }
        
        match crate::iat_hook::hook_imports_in_module(
            0,
            "kernel32.dll",
            "AddDllDirectory\0",
            AddDllDirectory_detour_wrapper,
        ) {
            Ok(mut hook) => {
                if hook.hook().is_ok() {
                    G_HOOKED_IMPORTS.push(hook);
                    ORIG_ADDDLLDIRECTORY = AddDllDirectory_detour_wrapper as usize;
                }
            }
            Err(_) => {}
        }
    }
    
    IS_HOOKED.store(true, std::sync::atomic::Ordering::SeqCst);
    true
}

pub fn unapply_hooks() {
    if !IS_HOOKED.load(std::sync::atomic::Ordering::SeqCst) { return; }
    
    #[cfg(windows)]
    unsafe {
        for hook in G_HOOKED_IMPORTS.drain(..) {
            let _ = hook.unhook();
        }
    }
    
    IS_HOOKED.store(false, std::sync::atomic::Ordering::SeqCst);
    unsafe { G_REDIRECTION_DATA.clear(); }
}

pub fn init_redirection_data() {
    unsafe {
        if !G_REDIRECTION_DATA.is_empty() { return; }
        
        // Block xlive.dll (Steam anti-cheat bypass - same as FiveM)
        G_REDIRECTION_DATA.push(("xlive.dll".into(), "INVALID_HANDLE".into()));
        
        // Redirect d3d9.dll to SwiftShader for compatibility
        G_REDIRECTION_DATA.push(("d3d9.dll".into(), r#"bin\SwiftShaderD3D9_64.dll"#.into()));
        
        // Redirect xinput1_3.dll to xinput1_4.dll for controller support
        G_REDIRECTION_DATA.push(("xinput1_3.dll".into(), r#"bin\xinput1_4.dll"#.into()));
        
        // Redirect xinput1_1.dll as well
        G_REDIRECTION_DATA.push(("xinput1_1.dll".into(), r#"bin\xinput1_4.dll"#.into()));
    }
}

pub fn map_redirected_filename(orig_filename: &str) -> String {
    unsafe {
        for (suffix, prefix) in G_REDIRECTION_DATA.iter() {
            if orig_filename.to_lowercase().ends_with(&suffix.to_lowercase()) {
                return format!("{}{}", prefix, &orig_filename[orig_filename.len() - suffix.len()..]);
            }
        }
        orig_filename.to_string()
    }
}

fn register_dll_directories() {
    #[cfg(windows)]
    unsafe {
        let module_path = get_module_path();
        let mut bin_dir = module_path.clone();
        if let Some(parent) = bin_dir.parent() { bin_dir = parent.to_path_buf(); }
        bin_dir.push("bin");
        let wide_path: Vec<u16> = bin_dir.as_os_str().encode_wide().chain(std::iter::once(0u16)).collect();
        let _ = AddDllDirectory(PCWSTR(wide_path.as_ptr()));
        let _ = SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
    }
}

#[cfg(windows)]
fn get_gta5_module_base() -> usize {
    unsafe {
        let wide_name: Vec<u16> = "GTA5.exe\0".encode_utf16().collect();
        let hmod = GetModuleHandleW(PCWSTR(wide_name.as_ptr())).unwrap_or_default();
        if !hmod.0.is_null() { return hmod.0 as usize; }
        
        let wide_name2: Vec<u16> = "rsgta5.exe\0".encode_utf16().collect();
        let hmod2 = GetModuleHandleW(PCWSTR(wide_name2.as_ptr())).unwrap_or_default();
        if !hmod2.0.is_null() { return hmod2.0 as usize; }
        
        let hmod3 = GetModuleHandleW(None).unwrap_or_default();
        hmod3.0 as usize
    }
}

#[cfg(windows)]
fn get_module_path() -> std::path::PathBuf {
    unsafe {
        let h_mod = GetModuleHandleW(None).unwrap_or_default();
        let mut buffer: [u16; 260] = [0u16; 260];
        let len = windows::Win32::System::LibraryLoader::GetModuleFileNameW(h_mod, &mut buffer);
        if len > 0 { return std::path::PathBuf::from(String::from_utf16_lossy(&buffer[..len as usize])); }
        std::path::PathBuf::new()
    }
}

#[cfg(not(windows))]
fn get_module_path() -> std::path::PathBuf {
    std::path::PathBuf::new()
}

// Wrapper functions that match the iat_hook fn() -> usize signature
// These store a global pointer to the actual detour function and its arguments
static mut G_CURRENT_DETOUR_FN: usize = 0;
static mut G_DETOUR_ARG1: PCWSTR = PCWSTR(std::ptr::null());
static mut G_DETOUR_ARG2: HANDLE = HANDLE(std::ptr::null_mut());
static mut G_DETOUR_ARG3: u32 = 0;
static mut G_DETOUR_ARG4: u32 = 0;
static mut G_DETOUR_ARG5: u32 = 0;
static mut G_DETOUR_ARG6: *mut std::ffi::c_void = std::ptr::null_mut();
static mut G_DETOUR_ARG7: HANDLE = HANDLE(std::ptr::null_mut());

extern "system" fn LoadLibraryW_detour_wrapper() -> usize {
    unsafe {
        let lib_name = String::from_utf16_lossy(&std::slice::from_raw_parts(G_DETOUR_ARG1.0, strlen_w(G_DETOUR_ARG1)));
        
        if lib_name.to_lowercase() == "xlive.dll" { return 0; }
        
        let redirected = map_redirected_filename(&lib_name);
        if redirected != lib_name {
            let wide_path: Vec<u16> = redirected.encode_utf16().chain(std::iter::once(0u16)).collect();
            match LoadLibraryW(PCWSTR(wide_path.as_ptr())) {
                Ok(h) => return h.0 as usize,
                Err(_) => return 0,
            }
        }
        
        if ORIG_LOADLIBRARYW != 0 {
            let orig_fn: extern "system" fn(PCWSTR) -> HMODULE = std::mem::transmute(ORIG_LOADLIBRARYW);
            let result = orig_fn(G_DETOUR_ARG1);
            return result.0 as usize;
        }
        
        match LoadLibraryW(G_DETOUR_ARG1) {
            Ok(h) => h.0 as usize,
            Err(_) => 0,
        }
    }
}

extern "system" fn CreateFileW_detour_wrapper() -> usize {
    unsafe {
        let orig_len = strlen_w(G_DETOUR_ARG1);
        let orig_filename = String::from_utf16_lossy(&std::slice::from_raw_parts(G_DETOUR_ARG1.0, orig_len));
        let redirected = map_redirected_filename(&orig_filename);
        
        if redirected != orig_filename {
            let wide_path: Vec<u16> = redirected.encode_utf16().chain(std::iter::once(0u16)).collect();
            match windows::Win32::Storage::FileSystem::CreateFileW(
                PCWSTR(wide_path.as_ptr()),
                G_DETOUR_ARG3,
                windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(G_DETOUR_ARG4),
                None,
                windows::Win32::Storage::FileSystem::FILE_CREATION_DISPOSITION(G_DETOUR_ARG5),
                windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(G_DETOUR_ARG5),
                G_DETOUR_ARG7,
            ) {
                Ok(h) => return h.0 as usize,
                Err(_) => {}
            }
        }
        
        if ORIG_CREATEFILEW != 0 {
            let orig_fn: extern "system" fn(PCWSTR, u32, u32, *mut std::ffi::c_void, u32, u32, HANDLE) -> HANDLE =
                std::mem::transmute(ORIG_CREATEFILEW);
            return orig_fn(G_DETOUR_ARG1, G_DETOUR_ARG3, G_DETOUR_ARG4, G_DETOUR_ARG6, G_DETOUR_ARG5, G_DETOUR_ARG5, G_DETOUR_ARG7).0 as usize;
        }
        
        -1isize as usize
    }
}

extern "system" fn GetFileAttributesW_detour_wrapper() -> usize {
    unsafe {
        let orig_len = strlen_w(G_DETOUR_ARG1);
        let orig_filename = String::from_utf16_lossy(&std::slice::from_raw_parts(G_DETOUR_ARG1.0, orig_len));
        let redirected = map_redirected_filename(&orig_filename);
        
        if redirected != orig_filename {
            let wide_path: Vec<u16> = redirected.encode_utf16().chain(std::iter::once(0u16)).collect();
            return windows::Win32::Storage::FileSystem::GetFileAttributesW(PCWSTR(wide_path.as_ptr())) as usize;
        }
        
        if ORIG_GETFILEATTRIBUTESW != 0 {
            let orig_fn: extern "system" fn(PCWSTR) -> u32 = std::mem::transmute(ORIG_GETFILEATTRIBUTESW);
            return orig_fn(G_DETOUR_ARG1) as usize;
        }
        
        windows::Win32::Storage::FileSystem::GetFileAttributesW(G_DETOUR_ARG1) as usize
    }
}

extern "system" fn AddDllDirectory_detour_wrapper() -> usize {
    0
}

pub fn is_blocked_dll(name: &str) -> bool { name.to_lowercase() == "xlive.dll" }

#[cfg(windows)]
unsafe fn strlen_w(ptr: PCWSTR) -> usize {
    let mut len = 0;
    while *(ptr.0.add(len)) != 0 { len += 1; }
    len
}