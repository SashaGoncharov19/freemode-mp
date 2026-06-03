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
        // The import directory is the 8th entry (index 1) in the data directories.
        // OptionalHeader size for PE32+ = 112 bytes (sizeof(Code) + sizeof(InitializedData) + sizeof(UninitializedData) + sizeof(EntryPoint) + sizeof(BaseOfCode) + sizeof(ImageBase)) 
        // Data directories start at offset 96 from the start of OptionalHeader
        let data_dir_offset = 96; // Standard offset to data directories in PE optional header
        *(self as *const ImageOptionalHeader64 as *const u8).add(data_dir_offset + (IMAGE_DIRECTORY_ENTRY_IMPORT * 8)) as u32
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
            let mut old_protect: u32 = 0;
            let result = VirtualProtect(
                self.iat_entry_ptr as *mut std::ffi::c_void,
                8,
                windows::Win32::Security::PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );
            
            if result.ok().is_ok() {
                *self.iat_entry_ptr = self.original_addr;
                let _ = FlushInstructionCache(
                    GetCurrentProcess(),
                    self.iat_entry_ptr as *const std::ffi::c_void,
                    8,
                );
                let _ = VirtualProtect(
                    self.iat_entry_ptr as *mut std::ffi::c_void,
                    8,
                    old_protect,
                    &mut old_protect,
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
        // Use the SizeOfHeaders field which contains the size of all headers
        let import_dir_rva = optional_header.size_of_headers; // This is not correct, but we need a different approach
        
        // Actually look for import directory in sections
        let sections_start = (nt_headers_ptr + 24 + std::mem::size_of::<ImageFileHeader>()) as usize;
        let num_sections = nt_headers.file_header.number_of_sections as usize;
        
        // Find section containing the import table by searching for known import module names
        let mut found = false;
        let mut result_module = String::new();
        let mut result_func = String::new();
        let mut result_iat_ptr: *mut usize = std::ptr::null_mut();
        
        for i in 0..num_sections {
            let sec = *(sections_start as *const ImageSectionHeader).add(i);
            if (&sec.name[0..=3] == b".imp" || &sec.name[0..=3] == b"Import") && sec.virtual_address != 0 {
                // Found import section
                let import_desc_rva = base_module as u32 + sec.virtual_address;
                let desc_ptr = (base_module + (import_desc_rva as usize)) as *const ImageImportDescriptor;
                
                let mut j = 0;
                loop {
                    let desc = &*desc_ptr.add(j);
                    if desc.name == 0 && desc.first_thunk == 0 {
                        break;
                    }
                    
                    let mod_name_ptr = (base_module + desc.name as usize) as *const u8;
                    let mut mod_name_bytes = Vec::new();
                    let mut k = 0;
                    while *(mod_name_ptr.add(k)) != 0 && k < 256 {
                        mod_name_bytes.push(*(mod_name_ptr.add(k)));
                        k += 1;
                    }
                    
                    if let Ok(mod_name) = std::str::from_utf8(&mod_name_bytes) {
                        if mod_name.eq_ignore_ascii_case(target_module_name) {
                            // Found target module, now find function
                            let thunk_ptr = (base_module + desc.first_thunk as usize) as *const ImageThunkData64;
                            let orig_ptr = (base_module + desc.characteristics as usize) as *const ImageThunkData64;
                            
                            let mut m = 0;
                            loop {
                                let thunk = &*thunk_ptr.add(m);
                                let _orig = &*orig_ptr.add(m);
                                
                                if thunk.address_of_data == 0 { break; }
                                
                                if (thunk.address_of_data >> 63) == 0 {
                                    let name_rva = base_module + (thunk.address_of_data as usize) + 2;
                                    let name_ptr = name_rva as *const u8;
                                    
                                    let mut func_bytes = Vec::new();
                                    let mut n = 0;
                                    while *(name_ptr.add(n)) != 0 && n < 256 {
                                        func_bytes.push(*(name_ptr.add(n)));
                                        n += 1;
                                    }
                                    
                                    if let Ok(func) = std::str::from_utf8(&func_bytes) {
                                        if func.eq_ignore_ascii_case(function_name) {
                                            result_iat_ptr = (base_module + desc.first_thunk as usize + (m * std::mem::size_of::<ImageThunkData64>())) as *mut usize;
                                            result_module = mod_name.to_string();
                                            result_func = func.to_string();
                                            found = true;
                                            break;
                                        }
                                    }
                                }
                                m += 1;
                            }
                            if found { break; }
                        }
                    }
                    j += 1;
                }
                if found { break; }
            }
        }
        
        if !found {
            return Err(format!("Function '{}' not found in import table of {}", function_name, target_module_name));
        }
        
        let iat_entry_ptr = result_iat_ptr;
        
        let mut old_protect: u32 = 0;
        let result = VirtualProtect(
            iat_entry_ptr as *mut std::ffi::c_void,
            8,
            windows::Win32::Security::PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
        
        if result.ok().is_err() {
            return Err(format!("Failed to change protection on IAT entry for {}", function_name));
        }
        
        let orig_addr = *iat_entry_ptr;
        
        // Patch the IAT entry.
        *iat_entry_ptr = detour_fn as usize;
        
        let _ = VirtualProtect(iat_entry_ptr as *mut std::ffi::c_void, 8, old_protect, &mut old_protect);
        
        Ok(ImportHook::new(target_module_name.to_string(), result_func, detour_fn as usize, orig_addr, iat_entry_ptr))
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

        // Find the import directory by scanning sections
        let sections_start = (nt_headers_ptr + 24 + std::mem::size_of::<ImageFileHeader>()) as usize;
        let num_sections = nt_headers.file_header.number_of_sections as usize;
        
        for i in 0..num_sections {
            let sec = *(sections_start as *const ImageSectionHeader).add(i);
            // Look for sections with "imp" or "i" in the name (typical import section names)
            let is_import_sec = sec.name.iter().any(|&b| b == b'i' || b == b'I') && 
                                 sec.characteristics & 0x20000000 != 0; // IMAGE_SCN_CNT_UNINITIALIZED_DATA
            
            if is_import_sec && sec.virtual_address != 0 {
                let import_desc_ptr = (base_module + sec.virtual_address as usize) as *const ImageImportDescriptor;
                
                let mut j = 0;
                loop {
                    let desc = &*import_desc_ptr.add(j);
                    if desc.name == 0 && desc.first_thunk == 0 { break; }

                    if desc.name != 0 {
                        let mod_name_ptr = (base_module + desc.name as usize) as *const u8;
                        let mut name_bytes = Vec::new();
                        let mut kk = 0;
                        while *(mod_name_ptr.add(kk)) != 0 && kk < 256 {
                            name_bytes.push(*(mod_name_ptr.add(kk)));
                            kk += 1;
                        }

                        if let Ok(mod_name) = std::str::from_utf8(&name_bytes) {
                            if mod_name.eq_ignore_ascii_case(target_module_name) {
                                let thunk_ptr = (base_module + desc.first_thunk as usize) as *const ImageThunkData64;
                                let orig_ptr = (base_module + desc.characteristics as usize) as *const ImageThunkData64;
                                
                                let mut m = 0;
                                loop {
                                    let thunk = &*thunk_ptr.add(m);
                                    let _orig = &*orig_ptr.add(m);
                                    
                                    if thunk.address_of_data == 0 { break; }
                                    
                                    if (thunk.address_of_data >> 63) == 0 {
                                        let name_rva = thunk.address_of_data as usize + 2;
                                        let name_ptr = (base_module + name_rva) as *const u8;
                                        
                                        let mut func_bytes = Vec::new();
                                        let mut nn = 0;
                                        while *(name_ptr.add(nn)) != 0 && nn < 256 {
                                            func_bytes.push(*(name_ptr.add(nn)));
                                            nn += 1;
                                        }

                                        if let Ok(func) = std::str::from_utf8(&func_bytes) {
                                            if func.eq_ignore_ascii_case(function_name) {
                                                return Some(desc.first_thunk + (m * std::mem::size_of::<ImageThunkData64>()) as u32);
                                            }
                                        }
                                    }
                                    m += 1;
                                }
                            }
                        }
                    }
                    j += 1;
                }
            }
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
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0)?;

        let mut modules = Vec::new();
        let mut me32 = MODULEENTRY32 { dwSize: std::mem::size_of::<MODULEENTRY32>() as u32, ..std::mem::zeroed() };

        if Module32First(snapshot, &mut me32).is_ok() {
            loop {
                let mod_name_bytes: Vec<u16> = me32.szModule.iter().map(|&c| c as u16).collect::<Vec<u16>>();
                let module_name = String::from_utf16_lossy(&mod_name_bytes[..mod_name_bytes.iter().position(|&c| c == 0).unwrap_or(mod_name_bytes.len())]);
                
                modules.push((module_name, me32.modBaseAddr as usize));

                if !Module32Next(snapshot, &mut me32).is_ok() { break; }
            }
        }

        let _ = CloseHandle(snapshot);
        Ok(modules)
    }
    #[cfg(not(windows))]
    { Err("Module enumeration not available on non-Windows".to_string()) }
}