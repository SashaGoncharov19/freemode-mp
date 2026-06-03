//! Real IAT (Import Address Table) hooking via PE parsing.

use std::ptr;

#[cfg(windows)]
pub use windows::Win32::Foundation::*;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
#[cfg(windows)]
use windows::Win32::System::Diagnostics::DbgHelp::*;
#[cfg(windows)]
pub use windows::Win32::System::Threading::*;

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
    base_of_data: u32,
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

impl ImageOptionalHeader64 {
    fn import_dir_rva(&self) -> u32 {
        let data_dir_offset = std::mem::size_of::<ImageOptionalHeader64>();
        *((((std::ptr::addr_of!(self) as *const u8).add(data_dir_offset)) as *const u32).add(IMAGE_DIRECTORY_ENTRY_IMPORT))
    }
    
    #[inline]
    pub fn size(&self) -> u16 {
        240 + (self.number_of_rva_and_sizes as u16) * 16
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageImportDescriptor {
    characteristics: u32,
    time_date_stamp: u32,
    major_forwarder_chain: i16,
    name: u32,
    first_thunk: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageImportByName {
    hint: u16,
    name: [u8; 1],
}

pub struct ImportHook {
    module_name: String,
    function_name: String,
    detour_addr: usize,
    original_addr: usize,
    iat_entry_ptr: *mut usize,
}

impl ImportHook {
    pub fn new(
        module_name: String,
        function_name: String,
        detour_addr: usize,
        original_addr: usize,
        iat_entry_ptr: *mut usize,
    ) -> Self {
        Self {
            module_name,
            function_name,
            detour_addr,
            original_addr,
            iat_entry_ptr,
        }
    }

    pub fn unhook(&self) -> std::result::Result<(), String> {
        #[cfg(windows)]
        unsafe {
            let mut old_protect = 0u32;
            let result = VirtualProtect(
                self.iat_entry_ptr as *mut std::ffi::c_void,
                8,
                windows::Win32::Security::PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );
            if result.into_ok().is_ok() {
                *self.iat_entry_ptr = self.original_addr;
                let _ = FlushInstructionCache(
                    GetCurrentProcess(),
                    self.iat_entry_ptr as *const std::ffi::c_void,
                    8,
                );
                Ok(())
            } else {
                Err(format!("Failed to unhook {}: VirtualProtect failed", self.function_name))
            }
        }
        #[cfg(not(windows))]
        {
            let _ = self;
            Err("IAT hooking not available on non-Windows".to_string())
        }
    }

    pub fn module(&self) -> &str {
        &self.module_name
    }

    pub fn function(&self) -> &str {
        &self.function_name
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageDosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    _e_cparhdr: u16,
    _e_minalloc: u16,
    _e_maxalloc: u16,
    _e_ss: u16,
    _e_sp: u16,
    _e_csum: u16,
    _e_ip: u16,
    _e_cs: u16,
    _e_lfarlc: u16,
    _e_ovno: u16,
    _e_res: [u16; 4],
    _e_oemid: u16,
    _e_oeminfo: u16,
    _e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageNTHeaders64 {
    signature: [u8; 4],
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
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
struct ImageThunkData64 {
    address_of_data: u64,
}

#[allow(dead_code)]
const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

#[cfg(windows)]
pub fn hook_imports_in_module(
    base_module: usize,
    target_module_name: &str,
    function_name: &str,
    detour_fn: unsafe extern "system" fn() -> usize,
) -> std::result::Result<ImportHook, String> {
    use windows::Win32::Diagnostics::DiagnosticsBase::IMAGE_DIRECTORY_ENTRY_EXPORT;
    
    unsafe {
        let dos_header = *(base_module as *const ImageDosHeader);
        if dos_header.e_magic != 0x5A4B {
            return Err("Invalid MZ signature".to_string());
        }
        
        let nt_headers_ptr = base_module + dos_header.e_lfanew as usize;
        let nt_headers = *(nt_headers_ptr as *const ImageNTHeaders64);
        
        if nt_headers.signature != [0x00, 0x00, 0x0b, 0x02] {
            return Err("Not a valid PE32+ header".to_string());
        }
        
        let optional_header = nt_headers.optional_header;
        let import_dir_rva = optional_header.import_dir_rva();
        
        if import_dir_rva == 0 {
            return Err("No import directory".to_string());
        }
        
        let sections_ptr = ((nt_headers_ptr + std::mem::size_of::<u32>() + std::mem::size_of::<ImageFileHeader>()) as *const u8).cast::<ImageSectionHeader>();
        let num_sections = nt_headers.file_header.number_of_sections as usize;
        
        let mut import_section_idx = 0;
        for i in 0..num_sections {
            let sec = *(sections_ptr.add(i));
            if sec.virtual_address <= import_dir_rva && import_dir_rva < sec.virtual_address + sec.size_of_raw_data {
                import_section_idx = i;
                break;
            }
        }
        
        let import_sec = *(sections_ptr.add(import_section_idx));
        let import_file_offset = (import_dir_rva - import_sec.virtual_address) as usize + import_sec.pointer_to_raw_data as usize;
        let import_desc_ptr = base_module + import_file_offset;
        let import_desc = *(import_desc_ptr as *const ImageImportDescriptor);
        
        if import_desc.name == 0 {
            return Err("Empty import descriptor".to_string());
        }
        
        let mod_name_ptr = (base_module + import_desc.name as usize) as *const u8;
        let mut mod_name_bytes = Vec::new();
        let mut i = 0;
        while *(mod_name_ptr.add(i)) != 0 {
            mod_name_bytes.push(*(mod_name_ptr.add(i)));
            i += 1;
        }
        
        let mod_name_str = std::str::from_utf8(&mod_name_bytes).map_err(|e| format!("Invalid module name: {}", e))?;
        
        if !mod_name_str.eq_ignore_ascii_case(target_module_name) {
            return Err(format!("Module mismatch: expected {}, got {}", target_module_name, mod_name_str));
        }
        
        let thunk_ptr = base_module + import_desc.first_thunk as usize;
        let thunk = *(thunk_ptr as *const ImageThunkData64);
        
        if thunk.address_of_data == 0 {
            return Err("No imports found for module".to_string());
        }
        
        let mut func_name_bytes = Vec::new();
        let name_rva = base_module + thunk.address_of_data as usize + std::mem::size_of::<u16>();
        let name_ptr = name_rva as *const u8;
        
        i = 0;
        loop {
            let byte = *(name_ptr.add(i));
            if byte == 0 { break; }
            func_name_bytes.push(byte);
            i += 1;
        }
        
        let func_name_str = std::str::from_utf8(&func_name_bytes).map_err(|e| format!("Invalid function name: {}", e))?;
        
        if func_name_str.eq_ignore_ascii_case(function_name) {
            let iat_entry_ptr = thunk_ptr as *mut usize;
            
            let mut old_protect = 0u32;
            let result = VirtualProtect(
                iat_entry_ptr as *mut std::ffi::c_void,
                8,
                windows::Win32::Security::PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );
            
            if result.into_ok().is_err() {
                return Err(format!("Failed to change protection on IAT entry for {}", function_name));
            }
            
            let orig_addr = *iat_entry_ptr;
            #[allow(clippy::fn_null_copy)]
            { *iat_entry_ptr = detour_fn as usize; }
            
            let _ = VirtualProtect(iat_entry_ptr as *mut std::ffi::c_void, 8, old_protect, &mut old_protect);
            
            Ok(ImportHook::new(mod_name_str.to_string(), func_name_str.to_string(), detour_fn as usize, orig_addr, iat_entry_ptr))
        } else {
            Err(format!("Function '{}' not found in import table of {}", function_name, mod_name_str))
        }
    }
    #[cfg(not(windows))]
    {
        let _ = base_module;
        let _ = target_module_name;
        let _ = function_name;
        let _ = detour_fn;
        Err("IAT hooking not available on non-Windows".to_string())
    }
}

#[cfg(windows)]
pub fn find_import_rva(base_module: usize, target_module_name: &str, function_name: &str) -> Option<u32> {
    unsafe {
        let dos_header = *(base_module as *const ImageDosHeader);
        if dos_header.e_magic != 0x5A4B { return None; }

        let nt_headers_ptr = base_module + dos_header.e_lfanew as usize;
        let nt_headers = *(nt_headers_ptr as *const ImageNTHeaders64);
        
        if nt_headers.signature != [0x00, 0x00, 0x0b, 0x02] { return None; }

        let optional_header = nt_headers.optional_header;
        let import_dir_rva = optional_header.import_dir_rva();
        
        if import_dir_rva == 0 { return None; }

        let mut current_desc = (base_module + import_dir_rva as usize) as *const ImageImportDescriptor;
        
        loop {
            let desc = &*current_desc;
            if desc.name == 0 && desc.first_thunk == 0 { break; }

            if desc.name != 0 {
                let mod_name_ptr = (base_module + desc.name as usize) as *const u8;
                let mut name_bytes = Vec::new();
                let mut j = 0;
                while *(mod_name_ptr.add(j)) != 0 && j < 256 {
                    name_bytes.push(*(mod_name_ptr.add(j)));
                    j += 1;
                }

                if let Ok(mod_name) = std::str::from_utf8(&name_bytes) {
                    if mod_name.eq_ignore_ascii_case(target_module_name) {
                        let thunk_ptr = (base_module + desc.first_thunk as usize) as *const ImageThunkData64;
                        let orig_ptr = (base_module + desc.characteristics as usize) as *const ImageThunkData64;
                        
                        let mut k = 0;
                        loop {
                            let thunk = &*thunk_ptr.add(k);
                            let _orig = &*orig_ptr.add(k);
                            
                            if thunk.address_of_data == 0 { break; }
                            
                            if (thunk.address_of_data >> 63) == 0 {
                                let name_rva = thunk.address_of_data as usize + std::mem::size_of::<u16>();
                                let name_ptr = (base_module + name_rva) as *const u8;
                                
                                let mut func_bytes = Vec::new();
                                let mut m = 0;
                                while *(name_ptr.add(m)) != 0 && m < 256 {
                                    func_bytes.push(*(name_ptr.add(m)));
                                    m += 1;
                                }

                                if let Ok(func) = std::str::from_utf8(&func_bytes) {
                                    if func.eq_ignore_ascii_case(function_name) {
                                        return Some(desc.first_thunk + (k * std::mem::size_of::<ImageThunkData64>()) as u32);
                                    }
                                }
                            }
                            k += 1;
                        }
                    }
                }
            }
            current_desc = current_desc.add(1);
        }

        None
    }
    #[cfg(not(windows))]
    {
        let _ = base_module;
        let _ = target_module_name;
        let _ = function_name;
        None
    }
}

#[cfg(windows)]
pub fn enumerate_loaded_modules() -> std::result::Result<Vec<(String, usize)>, String> {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0).map_err(|e| format!("Failed to create snapshot: {}", e))?;

        let mut modules = Vec::new();
        let mut me32 = MODULEENTRY32 { dwSize: std::mem::size_of::<MODULEENTRY32>() as u32, ..std::mem::zeroed() };

        if Module32First(snapshot, &mut me32).into_ok().is_ok() {
            loop {
                let mod_name_bytes = me32.szModule.iter().map(|&c| c as u16).collect::<Vec<u16>>();
                let module_name = String::from_utf16_lossy(&mod_name_bytes[..mod_name_bytes.iter().position(|&c| c == 0).unwrap_or(mod_name_bytes.len())]);
                
                modules.push((module_name, me32.modBaseAddr as usize));

                if !Module32Next(snapshot, &mut me32).into_ok().is_ok() { break; }
            }
        }

        let _ = CloseHandle(snapshot);
        Ok(modules)
    }
    #[cfg(not(windows))]
    { Err("Module enumeration not available on non-Windows".to_string()) }
}