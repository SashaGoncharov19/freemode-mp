//! Real IAT (Import Address Table) hooking via PE parsing — FiveM pattern from Hooking.h:274-384.

use std::os::raw::c_void;

#[cfg(windows)]
use windows::Win32::Foundation::*;
#[cfg(windows)]
pub use windows::Win32::System::Threading::*;
#[cfg(windows)]
use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
#[cfg(windows)]
use windows::Win32::System::Threading::GetCurrentProcess;
#[cfg(windows)]
use windows::Win32::System::Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS, PAGE_READWRITE};
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::GetModuleHandleW;

const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000_u64;
const PE_MAGIC_PE32P: u16 = 0x20B; // PE32+

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageDosHeader {
    e_magic: u16,
    _rest: [u16; 29],
    e_lfanew: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
    data_directories: [DataDirectory; 16],
}

// IMAGE_IMPORT_DESCRIPTOR from Windows SDK — layout must match exactly
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageImportDescriptor {
    original_first_thunk: u32,
    time_date_stamp: u32,
    major_forwarder_chain: i32,
    name: u32,
    first_thunk: u32,
}

/// Check if a thunk entry is by ordinal.
fn is_ordinal_thunk64(addr_data: u64) -> bool {
    addr_data & IMAGE_ORDINAL_FLAG64 != 0
}

pub struct ImportHook {
    module_name: String,
    function_name: String,
    detour_addr: usize,
    original_addr: usize,
    iat_entry_ptr: *mut usize,
}

impl ImportHook {
    pub fn new(mn: String, fn_: String, da: usize, oa: usize, ptr: *mut usize) -> Self {
        Self { module_name: mn, function_name: fn_, detour_addr: da, original_addr: oa, iat_entry_ptr: ptr }
    }

    /// Apply the hook — VirtualProtect(PAGE_READWRITE) → patch entry → VirtualProtect(restore).
    pub fn hook(&mut self) -> Result<(), String> {
        #[cfg(windows)]
        unsafe {
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            if !VirtualProtect(
                self.iat_entry_ptr as *mut c_void,
                8,
                PAGE_READWRITE,
                &mut old_protect,
            ).is_ok() {
                return Err("VirtualProtect failed on IAT entry".to_string());
            }

            *self.iat_entry_ptr = self.detour_addr;

            let _ = VirtualProtect(
                self.iat_entry_ptr as *mut c_void,
                8,
                old_protect,
                &mut old_protect,
            );

            let hproc = GetCurrentProcess();
            let _ = FlushInstructionCache(hproc, Some(self.iat_entry_ptr as *const c_void), 8);

            Ok(())
        }

        #[cfg(not(windows))]
        { Err("Not available on non-Windows".to_string()) }
    }

    /// Unhook — restore original address.
    pub fn unhook(&self) -> Result<(), String> {
        #[cfg(windows)]
        unsafe {
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            if !VirtualProtect(
                self.iat_entry_ptr as *mut c_void,
                8,
                PAGE_READWRITE,
                &mut old_protect,
            ).is_ok() {
                return Err("VirtualProtect failed on IAT entry".to_string());
            }

            *self.iat_entry_ptr = self.original_addr;

            let _ = VirtualProtect(
                self.iat_entry_ptr as *mut c_void,
                8,
                old_protect,
                &mut old_protect,
            );

            let hproc = GetCurrentProcess();
            let _ = FlushInstructionCache(hproc, Some(self.iat_entry_ptr as *const c_void), 8);

            Ok(())
        }

        #[cfg(not(windows))]
        { Err("Not available".to_string()) }
    }

    pub fn module(&self) -> &str { &self.module_name }
    pub fn function(&self) -> &str { &self.function_name }
}

/// Walk the PE import table of the current process and hook a specific function.
/// Pattern: FiveM Hooking.h:274-384 — walk IMAGE_IMPORT_DESCRIPTOR → find module → walk thunk → VirtualProtect + patch
#[cfg(windows)]
pub fn hook_imports_in_module(_base: usize, target_module: &str, target_fn: &str, detour_fn: unsafe extern "system" fn() -> usize) -> Result<ImportHook, String> {
    unsafe {
        // Get base address of current process (like FiveM's GetModuleHandle(NULL))
        let hmod = GetModuleHandleW(None).map_err(|_| "GetModuleHandleW failed".to_string())?;
        let base_addr = hmod.0 as usize;

        let dos_header = *(base_addr as *const ImageDosHeader);

        if dos_header.e_magic != 0x5A4B { // MZ
            return Err("Not a valid PE file".to_string());
        }

        let nt_headers_ptr = (base_addr + dos_header.e_lfanew as usize) as *const ImageNtHeaders64;
        let nt = &*nt_headers_ptr;

        if nt.optional_header.magic != PE_MAGIC_PE32P {
            return Err(format!("Not a PE32+ file (magic=0x{:X})", nt.optional_header.magic));
        }

        let import_dir = nt.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if import_dir.virtual_address == 0 || import_dir.size == 0 {
            return Err("No import directory in target module".to_string());
        }

        let mut descriptor_rva: usize = import_dir.virtual_address as usize;
        let id_end = descriptor_rva + import_dir.size as usize;

        loop {
            if descriptor_rva + 20 > id_end { break; } // Safety

            let desc_ptr = (base_addr + descriptor_rva) as *const ImageImportDescriptor;
            let desc = *desc_ptr;

            if desc.name == 0 { break; } // End of array

            let name_ptr = (base_addr + desc.name as usize) as *const i8;
            let dll_name = std::ffi::CStr::from_ptr(name_ptr)
                .to_string_lossy()
                .to_lowercase();

            if dll_name == target_module.to_lowercase() {
                // Found the module — walk thunks using OriginalFirstThunk (name lookup) or FirstThunk (IAT)
                let thunk_rva = if desc.original_first_thunk != 0 {
                    desc.original_first_thunk as usize
                } else {
                    desc.first_thunk as usize
                };

                let mut i: u32 = 0;
                loop {
                    let thunk_addr = base_addr + thunk_rva + (i * 8) as usize;
                    let thunk_bytes = std::slice::from_raw_parts(
                        thunk_addr as *const u8,
                        8,
                    );
                    let addr_data = ((thunk_bytes[0] as u64) | ((thunk_bytes[1] as u64) << 8) | ((thunk_bytes[2] as u64) << 16) | ((thunk_bytes[3] as u64) << 24) | ((thunk_bytes[4] as u64) << 32) | ((thunk_bytes[5] as u64) << 40) | ((thunk_bytes[6] as u64) << 48) | ((thunk_bytes[7] as u64) << 56));

                    if addr_data == 0 { break; }

                    // IAT entry pointer (FirstThunk array)
                    let entry_addr = base_addr + desc.first_thunk as usize + (i * 8) as usize;
                    let entry_ptr = entry_addr as *mut usize;

                    if is_ordinal_thunk64(addr_data) {
                        i += 1;
                        continue;
                    }

                    // Name-based: read IMAGE_IMPORT_BY_NAME (hint at offset 0, name at offset 2)
                    let name_rva = addr_data as u32 as usize;
                    let name_ptr2 = (base_addr + name_rva + 2) as *const u8;
                    let mut len = 0usize;
                    while len < 256 {
                        if *name_ptr2.add(len) == 0 { break; }
                        len += 1;
                    }
                    let func_name_bytes: &[u8] = unsafe { std::slice::from_raw_parts(name_ptr2, len) };
                    let func_name = String::from_utf8_lossy(func_name_bytes);

                    if func_name.eq_ignore_ascii_case(target_fn) {
                        // Found it! Apply the hook using FiveM's pattern:
                        // VirtualProtect(PAGE_READWRITE) → patch → VirtualProtect(restore)
                        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                        if !VirtualProtect(entry_ptr as *mut c_void, 8, PAGE_READWRITE, &mut old_protect).is_ok() {
                            return Err("VirtualProtect failed on IAT entry".to_string());
                        }

                        let original = *entry_ptr;

                        let _ = VirtualProtect(
                            entry_ptr as *mut c_void,
                            8,
                            old_protect,
                            &mut old_protect,
                        );

                        *entry_ptr = detour_fn();

                        let hproc = GetCurrentProcess();
                        let _ = FlushInstructionCache(hproc, Some(entry_ptr as *const c_void), 8);

                        return Ok(ImportHook::new(
                            dll_name.to_string(),
                            func_name.to_string(),
                            detour_fn(),
                            original,
                            entry_ptr,
                        ));
                    }

                    i += 1;
                    if i > 10000 { break; } // Safety limit
                }

                break;
            }

            descriptor_rva += 20;
        }

        Err(format!("Module '{}' or function '{}' not found in imports", target_module, target_fn))
    }

    #[cfg(not(windows))]
    { Err("Not available".to_string()) }
}

pub fn find_import_rva(_base: usize, _tn: &str, _fn: &str) -> Option<u32> { None }

#[cfg(not(windows))]
pub fn hook_imports_in_module(_base: usize, _tn: &str, _fn: &str, _df: unsafe extern "system" fn() -> usize) -> Result<ImportHook, String> { Err("Not available".into()) }

#[cfg(not(windows))]
pub fn enumerate_loaded_modules() -> Result<Vec<(String, usize)>, String> { Ok(vec![]) }
