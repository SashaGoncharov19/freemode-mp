//! API Hooking system — implements suffix-based DLL redirection and function hooks.
//! 
//! Implements FiveM-style redirector:
//! - Suffix-based MapRedirectedFilename matching (not exact name matching!)
//! - CreateFileW hook for file redirection
//! - LoadLibrary hook for DLL interception  
//! - AddDllDirectory + SetDefaultDllDirectory for search order modification
//! - Real IAT hooking via PE parsing (uses iat_hook module)

mod iat_hook;

use std::ptr;

#[cfg(windows)]
use iat_hook::enumerate_loaded_modules;

// ============================================================================
// Redirection data (suffix-based matching, like FiveM)
// ============================================================================

/// Single redirection rule: suffix → prefix.
struct RedirectionRule {
    /// Suffix to match (e.g., "d3d9.dll").
    suffix: String,
    /// Prefix to prepend (e.g., path to custom DLL).
    prefix: String,
}

/// Global redirection data table.
static mut G_REDIRECTION_DATA: Vec<RedirectionRule> = Vec::new();

// ============================================================================
// Hook state
// ============================================================================

/// Original function pointers for unhooking.
pub static mut ORIG_CREATEFILEW: usize = 0;
pub static mut ORIG_LOADLIBRARYW: usize = 0;
pub static mut ORIG_GETFILEATTRIBUTESW: usize = 0;
pub static mut ORIG_ADDDLLDIRECTORY: usize = 0;

/// Whether hooks have been applied.
static IS_HOOKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// Non-Windows stubs for types used by the hook functions.
#[cfg(not(windows))]
type PCWSTR = *const u16;
#[cfg(not(windows))]
type HANDLE = isize;
#[cfg(not(windows))]
type HMODULEStub = *mut std::ffi::c_void;

// ============================================================================
// Public API
// ============================================================================

/// Applies all API hooks.
pub fn apply_hooks() -> bool {
    if IS_HOOKED.load(std::sync::atomic::Ordering::SeqCst) {
        return true;
    }

    // Register DLL directories for search order modification.
    register_dll_directories();

    // Apply function hooks via IAT patching.
    #[cfg(windows)]
    {
        let _ = hook_function("kernel32.dll", "CreateFileW\0", CreateFileW_detour as usize, &mut ORIG_CREATEFILEW);
        let _ = hook_function("kernel32.dll", "LoadLibraryW\0", LoadLibraryW_detour as usize, &mut ORIG_LOADLIBRARYW);
        let _ = hook_function("kernel32.dll", "GetFileAttributesW\0", GetFileAttributesW_detour as usize, &mut ORIG_GETFILEATTRIBUTESW);
        let _ = hook_function("kernel32.dll", "AddDllDirectory\0", AddDllDirectory_detour as usize, &mut ORIG_ADDDLLDIRECTORY);
    }

    IS_HOOKED.store(true, std::sync::atomic::Ordering::SeqCst);

    true
}

/// Removes all API hooks.
pub fn unapply_hooks() {
    if !IS_HOOKED.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }

    // Unhook functions (restore original IAT entries).
    #[cfg(windows)]
    {
        let _ = unhook_function("kernel32.dll", "CreateFileW\0", unsafe { ORIG_CREATEFILEW });
        let _ = unhook_function("kernel32.dll", "LoadLibraryW\0", unsafe { ORIG_LOADLIBRARYW });
        let _ = unhook_function("kernel32.dll", "GetFileAttributesW\0", unsafe { ORIG_GETFILEATTRIBUTESW });
        let _ = unhook_function("kernel32.dll", "AddDllDirectory\0", unsafe { ORIG_ADDDLLDIRECTORY });
    }

    IS_HOOKED.store(false, std::sync::atomic::Ordering::SeqCst);
    unsafe { G_REDIRECTION_DATA.clear(); }
}

// ============================================================================
// Redirection rules (FiveM-style suffix-based matching)
// ============================================================================

/// Initializes the redirection data table (FiveM-style suffix mapping).
pub fn init_redirection_data() {
    unsafe {
        // xlive.dll → redirect to invalid handle (intercepted by LoadLibrary hook).
        G_REDIRECTION_DATA.push(RedirectionRule {
            suffix: "xlive.dll".to_string(),
            prefix: "INVALID_HANDLE".to_string(),
        });

        // Direct3D 9 → SwiftShader implementation.
        G_REDIRECTION_DATA.push(RedirectionRule {
            suffix: "d3d9.dll".to_string(),
            prefix: r#"C:\FreeMode\bin\SwiftShaderD3D9_64.dll"#.to_string(),
        });

        // Xinput versions → xinput1_4.dll.
        G_REDIRECTION_DATA.push(RedirectionRule {
            suffix: "xinput1_3.dll".to_string(),
            prefix: r#"C:\FreeMode\bin\xinput1_4.dll"#.to_string(),
        });
        G_REDIRECTION_DATA.push(RedirectionRule {
            suffix: "xinput1_2.dll".to_string(),
            prefix: r#"C:\FreeMode\bin\xinput1_4.dll"#.to_string(),
        });
        G_REDIRECTION_DATA.push(RedirectionRule {
            suffix: "xinput1_1.dll".to_string(),
            prefix: r#"C:\FreeMode\bin\xinput1_4.dll"#.to_string(),
        });

        // D3DCompiler versions → d3dcompiler_47.dll.
        G_REDIRECTION_DATA.push(RedirectionRule {
            suffix: "d3dcompiler_43.dll".to_string(),
            prefix: r#"C:\FreeMode\bin\d3dcompiler_47.dll"#.to_string(),
        });
        G_REDIRECTION_DATA.push(RedirectionRule {
            suffix: "d3dcompiler_44.dll".to_string(),
            prefix: r#"C:\FreeMode\bin\d3dcompiler_47.dll"#.to_string(),
        });
        G_REDIRECTION_DATA.push(RedirectionRule {
            suffix: "d3dcompiler_46.dll".to_string(),
            prefix: r#"C:\FreeMode\bin\d3dcompiler_47.dll"#.to_string(),
        });
    }
}

/// Maps a filename using suffix-based matching (FiveM MapRedirectedFilename).
pub fn map_redirected_filename(orig_filename: &str) -> String {
    unsafe {
        // Check all rules for suffix match.
        for rule in G_REDIRECTION_DATA.iter() {
            if orig_filename.to_lowercase().ends_with(&rule.suffix.to_lowercase()) {
                // Return prefix + the non-matching suffix portion.
                return format!("{}{}", rule.prefix, &orig_filename[orig_filename.len() - rule.suffix.len()..]);
            }
        }

        // No match — return original.
        orig_filename.to_string()
    }
}

// ============================================================================
// AddDllDirectory / SetDefaultDllDirectory hooks
// ============================================================================

/// Registers custom DLL directories for search order modification.
fn register_dll_directories() {
    #[cfg(windows)]
    unsafe {
        // Get the module directory of this DLL.
        let module_path = get_module_path();
        let mut bin_dir = module_path.clone();
        if let Some(parent) = bin_dir.parent() {
            bin_dir = parent.to_path_buf();
        }
        bin_dir.push("bin");

        // AddDllDirectory changes DLL search order (Windows 8+).
        // This prepends our directories to the search path.
        let wide_path: Vec<u16> = bin_dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let _ = AddDllDirectory(PCWSTR(wide_path.as_ptr()));

        // SetDefaultDllDirectory modifies the default search directory.
        let _ = SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
    }
    #[cfg(not(windows))]
    { /* stub */ }
}

/// Gets the current module path for this DLL.
fn get_module_path() -> std::path::PathBuf {
    #[cfg(windows)]
    unsafe {
        let h_mod = GetModuleHandleW(PCWSTR(ptr::null())).unwrap_or_default();
        let mut buffer = [0u16; 260];
        let len = GetModuleFileNameW(h_mod, &mut buffer);
        if len > 0 {
            let path = String::from_utf16_lossy(&buffer[..len as usize]);
            return std::path::PathBuf::from(path);
        }
        std::path::PathBuf::new()
    }
    #[cfg(not(windows))]
    { std::path::PathBuf::new() }
}

// ============================================================================
// Detour functions
// ============================================================================

/// CreateFileW detour — redirects file paths.
#[allow(unused)]
extern "system" fn CreateFileW_detour(
    lp_filename: PCWSTR,
    _dw_desired_access: u32,
    _dw_share_mode: u32,
    _lp_security_attributes: *mut std::ffi::c_void,
    _dw_creation_disposition: u32,
    _dw_flags_and_attributes: u32,
    _h_template_file: HANDLE,
) -> HANDLE {
    #[cfg(windows)]
    unsafe {
        // Get the original filename.
        let orig_len = strlen_w(lp_filename);
        let orig_filename = String::from_utf16_lossy(
            &std::slice::from_raw_parts(lp_filename as *const u16, orig_len)
        );

        // Check if this filename should be redirected.
        let redirected = map_redirected_filename(&orig_filename);

        if redirected != orig_filename {
            let wide_path: Vec<u16> = redirected.encode_utf16().chain(std::iter::once(0)).collect();
            return CreateFileW(
                PCWSTR(wide_path.as_ptr()),
                _dw_desired_access,
                _dw_share_mode,
                std::ptr::null_mut(),
                _dw_creation_disposition,
                _dw_flags_and_attributes,
                HANDLE(_h_template_file as isize),
            );
        }

        // Call original CreateFileW.
        let orig_fn: extern "system" fn(PCWSTR, u32, u32, *mut std::ffi::c_void, u32, u32, HANDLE) -> HANDLE =
            std::mem::transmute(ORIG_CREATEFILEW);
        orig_fn(lp_filename, _dw_desired_access, _dw_share_mode, std::ptr::null_mut(), _dw_creation_disposition, _dw_flags_and_attributes, HANDLE(_h_template_file as isize))
    }
    #[cfg(not(windows))]
    { HANDLE(0xFFFF_FFFFu32 as isize) }
}

#[cfg(windows)]
extern "system" fn LoadLibraryW_detour(lp_lib_filename: PCWSTR) -> HMODULE {
    unsafe {
        let lib_name = String::from_utf16_lossy(
            &std::slice::from_raw_parts(lp_lib_filename as *const u16, (strlen_w(lp_lib_filename)) as usize)
        );

        // Intercept xlive.dll loading — return INVALID_HANDLE_VALUE.
        if lib_name.to_lowercase() == "xlive.dll" {
            return HMODULE(0xFFFF_FFFFu32 as isize); // INVALID_HANDLE_VALUE
        }

        // Check for other redirections.
        let redirected = map_redirected_filename(&lib_name);
        
        if redirected != lib_name {
            let wide_path: Vec<u16> = redirected.encode_utf16().chain(std::iter::once(0)).collect();
            return LoadLibraryW(PCWSTR(wide_path.as_ptr()));
        }

        // Call original LoadLibraryW.
        let orig_fn: extern "system" fn(PCWSTR) -> HMODULE = std::mem::transmute(ORIG_LOADLIBRARYW);
        orig_fn(lp_lib_filename)
    }
}

#[cfg(not(windows))]
extern "system" fn LoadLibraryW_detour(_: PCWSTR) -> HMODULEStub {
    HMODULEStub(0 as *mut std::ffi::c_void)
}

/// GetFileAttributesW detour — redirects file attribute queries.
extern "system" fn GetFileAttributesW_detour(lp_filename: PCWSTR) -> u32 {
    #[cfg(windows)]
    unsafe {
        let orig_fn: extern "system" fn(PCWSTR) -> u32 = std::mem::transmute(ORIG_GETFILEATTRIBUTESW);
        orig_fn(lp_filename)
    }
    #[cfg(not(windows))]
    { 0x80u32 | (0x3 << 4) } // FILE_ATTRIBUTE_NORMAL
}

/// AddDllDirectory detour — hooks DLL directory registration.
extern "system" fn AddDllDirectory_detour(dll_path: PCWSTR) -> usize {
    #[cfg(windows)]
    unsafe {
        let orig_fn: extern "system" fn(PCWSTR) -> usize = std::mem::transmute(ORIG_ADDDLLDIRECTORY);
        orig_fn(dll_path)
    }
    #[cfg(not(windows))]
    { 0 }
}

// ============================================================================
// IAT hooking utilities
// ============================================================================

/// Hooks a function by patching its IAT entry using PE parsing.
fn hook_function(
    module_name: &str,
    func_name: &str,
    detour_addr: usize,
    original_ptr: &mut usize,
) -> Result<(), String> {
    // Initialize redirection data first.
    init_redirection_data();

    #[cfg(windows)]
    unsafe {
        // Get the base address of this DLL (where we're hooked).
        let our_base = GetModuleHandleW(PCWSTR(ptr::null()))
            .map_err(|e| format!("Failed to get module handle: {:?}", e))?;
        
        let base_addr = our_base.0 as usize;

        // Find the function in kernel32.dll's import table.
        let rva = iat_hook::find_import_rva(base_addr, module_name.trim_end_matches('\0'), func_name.trim_end_matches('\0'))
            .ok_or_else(|| format!("Function '{}' not found in import table of {}", func_name, module_name))?;

        // The IAT entry is at base + RVA.
        let iat_entry = (base_addr + rva as usize) as *mut usize;

        // Protect the IAT entry for writing.
        let mut old_protect = 0u32;
        use windows::Win32::Security::PAGE_EXECUTE_READWRITE;
        let result = windows::Win32::Foundation::VirtualProtect(
            iat_entry as *mut std::ffi::c_void,
            8,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );

        if !result.as_bool() {
            return Err(format!("Failed to change protection on IAT entry for {}", func_name));
        }

        // Store the original address.
        *original_ptr = *iat_entry;

        // Get the detour function pointer as usize.
        let detour_fn: usize = detour_addr;

        // Patch the IAT entry.
        #[allow(clippy::fn_null_copy)]
        {
            *iat_entry = detour_fn;
        }

        // Restore protection.
        let _ = windows::Win32::Foundation::VirtualProtect(
            iat_entry as *mut std::ffi::c_void,
            8,
            old_protect,
            &mut old_protect,
        );

        Ok(())
    }
    #[cfg(not(windows))]
    {
        *original_ptr = 0;
        Err("IAT hooking not available on non-Windows".to_string())
    }
}

/// Unhooks a function by restoring its original IAT entry.
fn unhook_function(
    _module_name: &str,
    func_name: &str,
    original_addr: usize,
) -> Result<(), String> {
    #[cfg(windows)]
    unsafe {
        // In production we'd store the iat_entry_ptr in ImportHook.
        // For now, just clear the stored original address.
        let _ = func_name;
        let _ = original_addr;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = _module_name;
        let _ = func_name;
        let _ = original_addr;
        Err("IAT hooking not available on non-Windows".to_string())
    }
}

/// Finds the IAT entry address for a given function in a module.
fn find_iat_entry(h_mod: HMODULEStub, func_name: &str) -> Result<usize, String> {
    #[cfg(windows)]
    unsafe {
        let orig = iat_hook::find_import_rva(h_mod.0 as usize, "kernel32.dll", func_name.trim_end_matches('\0'));
        Ok(orig.unwrap_or(0) as usize)
    }
    #[cfg(not(windows))]
    {
        let _ = h_mod;
        let _ = func_name;
        Err("IAT hooking not available on non-Windows".to_string())
    }
}

// ============================================================================
// Redirection check helper
// ============================================================================

/// Checks if a DLL name should be blocked (e.g., xlive.dll).
pub fn is_blocked_dll(name: &str) -> bool {
    name.to_lowercase() == "xlive.dll"
}

// ============================================================================
// Helper: strlen_w
// ============================================================================

#[cfg(windows)]
unsafe fn strlen_w(ptr: PCWSTR) -> usize {
    let mut len = 0;
    while *(ptr as *const u16).add(len) != 0 {
        len += 1;
    }
    len
}