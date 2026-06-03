//! Executable Loader — loads GTA5.exe into our memory space (FiveM-style).

use std::ptr;

#[cfg(windows)]
pub use windows::Win32::Foundation::*;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::*;
#[cfg(windows)]
pub use windows::Win32::System::LibraryLoader::*;
#[cfg(windows)]
pub use windows::Win32::System::Threading::*;
#[cfg(windows)]
use windows::Win32::Security::SECURITY_ATTRIBUTES;

// ============================================================================
// PE Header Structures
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageDosHeader {
    pub e_magic: u16,
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
    pub e_lfanew: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl ImageDataDirectory {
    fn new() -> Self {
        Self::default()
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    base_of_data: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characterations: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

impl ImageOptionalHeader64 {
    pub fn size(&self) -> u16 {
        240 + (self.number_of_rva_and_sizes as u16) * 16
    }
    
    pub fn import_directory(&self) -> &ImageDataDirectory {
        &self.data_directory[1]
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageNTHeaders64 {
    pub signature: [u8; 4],
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    _number_of_relocations: u16,
    _number_of_linenumbers: u16,
    pub characteristics: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageImportDescriptor {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    _major_forwarder_chain: i16,
    pub name: u32,
    pub first_thunk: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageThunkData64 {
    pub address_of_data: u64,
}

// ============================================================================
// ExecutableLoader struct
// ============================================================================

pub struct ExecutableLoader {
    orig_binary: Vec<u8>,
    module: *mut u8,
    load_limit: usize,
    entry_point: usize,
    tls_initializer: fn(*const u8) -> bool,
}

impl ExecutableLoader {
    pub fn new(binary_data: Vec<u8>) -> Self {
        Self {
            orig_binary: binary_data,
            module: ptr::null_mut(),
            load_limit: 0x140000000 + 0x60000000,
            entry_point: 0,
            tls_initializer: Self::default_tls_initializer,
        }
    }
    
    fn default_tls_initializer(_tls_dir: *const u8) -> bool {
        let _ = _tls_dir;
        true
    }
    
    pub fn set_load_limit(&mut self, limit: usize) {
        self.load_limit = limit;
    }
    
    pub fn load_into_module(&mut self, target_module: HMODULE) -> std::result::Result<bool, String> {
        #[cfg(windows)]
        unsafe {
            let base_addr = target_module.0 as usize;
            
            let dos_header = *(base_addr as *const ImageDosHeader);
            if dos_header.e_magic != 0x5A4B {
                return Ok(false);
            }
            
            let nt_headers_ptr = (base_addr + dos_header.e_lfanew as usize) as *const ImageNTHeaders64;
            if nt_headers_ptr.is_null() {
                return Ok(false);
            }
            let nt_headers = *nt_headers_ptr;
            
            if nt_headers.signature != [0x00, 0x00, 0x0b, 0x02] {
                return Ok(false);
            }
            
            let opt_header = &nt_headers.optional_header;
            
            let alloc_addr = VirtualAlloc(
                None,
                self.load_limit,
                windows::Win32::System::Memory::MEM_RESERVE | windows::Win32::System::Memory::MEM_COMMIT,
                windows::Win32::Security::PAGE_READWRITE,
            );
            
            if alloc_addr.is_null() {
                return Ok(false);
            }
            
            self.module = alloc_addr as *mut u8;
            
            std::ptr::copy_nonoverlapping(
                self.orig_binary.as_ptr(),
                self.module,
                self.orig_binary.len(),
            );
            
            if !self.apply_relocations(base_addr, &nt_headers)? {
                return Ok(false);
            }
            
            if !self.resolve_imports(base_addr, &nt_headers)? {
                return Ok(false);
            }
            
            self.setup_tls(&nt_headers);
            self.swap_pe_headers(base_addr, &nt_headers);
            
            self.entry_point = base_addr + opt_header.address_of_entry_point as usize;
            
            Ok(true)
        }
        #[cfg(not(windows))]
        {
            let _ = target_module;
            Ok(false)
        }
    }
    
    fn apply_relocations(&self, base_addr: usize, nt_headers: &ImageNTHeaders64) -> std::result::Result<bool, String> {
        #[cfg(windows)]
        unsafe {
            let opt = &nt_headers.optional_header;
            let reloc_dir = opt.data_directory[12];
            
            if reloc_dir.size == 0 || reloc_dir.virtual_address == 0 {
                return Ok(true);
            }
            
            let sections_ptr = ((base_addr + nt_headers.signature.len() + std::mem::size_of::<ImageFileHeader>()) as *const u8)
                .cast::<ImageSectionHeader>();
            let num_sections = nt_headers.file_header.number_of_sections as usize;
            
            let mut reloc_section_idx = 0;
            for i in 0..num_sections {
                let sec = *(sections_ptr.add(i));
                if sec.virtual_address <= reloc_dir.virtual_address 
                    && reloc_dir.virtual_address < sec.virtual_address + sec.size_of_raw_data {
                    reloc_section_idx = i;
                    break;
                }
            }
            
            let reloc_sec = *(sections_ptr.add(reloc_section_idx));
            let reloc_file_offset = (reloc_dir.virtual_address - reloc_sec.virtual_address) as usize 
                + reloc_sec.pointer_to_raw_data as usize;
            
            let reloc_base = (base_addr + reloc_file_offset) as *const u8;
            
            let mut offset = 0usize;
            while offset < reloc_dir.size as usize {
                let block_header_ptr = reloc_base.add(offset) as *const u8;
                let block_size = *(block_header_ptr as *const u32);
                let block_rva = *(block_header_ptr.add(4) as *const u32);
                
                if block_size == 0 { break; }
                
                let num_entries = ((block_size as usize - 8) / 2) as usize;
                
                for j in 0..num_entries {
                    let entry_ptr = block_header_ptr.add(8 + j * 2) as *const u16;
                    let entry = *entry_ptr;
                    let type_ = (entry >> 12) as u8;
                    let offset_ = (entry & 0xFFF) as u32;
                    
                    if type_ == 3 {
                        let addr_ptr = (base_addr + block_rva as usize + offset_ as usize) as *mut usize;
                        let delta = self.module as usize - opt.image_base as usize;
                        *addr_ptr = (*addr_ptr as isize + delta as isize) as usize;
                    }
                }
                
                offset += block_size as usize;
            }
            
            Ok(true)
        }
        #[cfg(not(windows))]
        {
            let _ = base_addr;
            let _ = nt_headers;
            Ok(false)
        }
    }
    
    fn resolve_imports(&self, base_addr: usize, nt_headers: &ImageNTHeaders64) -> std::result::Result<bool, String> {
        #[cfg(windows)]
        unsafe {
            let opt = &nt_headers.optional_header;
            let import_dir = opt.import_directory();
            
            if import_dir.size == 0 || import_dir.virtual_address == 0 {
                return Ok(true);
            }
            
            let sections_ptr = ((base_addr + nt_headers.signature.len() + std::mem::size_of::<ImageFileHeader>()) as *const u8)
                .cast::<ImageSectionHeader>();
            let num_sections = nt_headers.file_header.number_of_sections as usize;
            
            let mut import_section_idx = 0;
            for i in 0..num_sections {
                let sec = *(sections_ptr.add(i));
                if sec.virtual_address <= import_dir.virtual_address 
                    && import_dir.virtual_address < sec.virtual_address + sec.size_of_raw_data {
                    import_section_idx = i;
                    break;
                }
            }
            
            let import_sec = *(sections_ptr.add(import_section_idx));
            let import_file_offset = (import_dir.virtual_address - import_sec.virtual_address) as usize 
                + import_sec.pointer_to_raw_data as usize;
            
            let import_base = (base_addr + import_file_offset) as *const ImageImportDescriptor;
            
            let mut desc_idx = 0;
            loop {
                let desc = *(import_base.add(desc_idx));
                
                if desc.name == 0 && desc.first_thunk == 0 {
                    break;
                }
                
                let mod_name_ptr = (base_addr + desc.name as usize) as *const u8;
                let mut mod_name_bytes = Vec::new();
                let mut i = 0;
                while *(mod_name_ptr.add(i)) != 0 && i < 256 {
                    mod_name_bytes.push(*(mod_name_ptr.add(i)));
                    i += 1;
                }
                
                if mod_name_bytes.is_empty() {
                    desc_idx += 1;
                    continue;
                }
                
                let mod_name = std::str::from_utf8(&mod_name_bytes)
                    .map_err(|e| format!("Invalid module name: {}", e))?;
                
                let loaded_module = LoadLibraryA(windows_core::PCSTR(mod_name.as_ptr()))
                    .map_err(|e| format!("LoadLibraryA failed for {}: {:?}", mod_name, e))?;
                
                if loaded_module.0.is_null() {
                    desc_idx += 1;
                    continue;
                }
                
                let thunk_ptr = (base_addr + desc.first_thunk as usize) as *const ImageThunkData64;
                
                let mut thunk_idx = 0;
                loop {
                    let thunk = *(thunk_ptr.add(thunk_idx));
                    
                    if thunk.address_of_data == 0 { break; }
                    
                    if (thunk.address_of_data >> 63) == 0 {
                        let name_rva = thunk.address_of_data as usize + std::mem::size_of::<u16>();
                        let name_ptr = (base_addr + name_rva) as *const u8;
                        
                        let mut func_bytes = Vec::new();
                        let mut m = 0;
                        while *(name_ptr.add(m)) != 0 && m < 256 {
                            func_bytes.push(*(name_ptr.add(m)));
                            m += 1;
                        }
                        
                        if let Ok(func_name) = std::str::from_utf8(&func_bytes) {
                            let resolved = GetProcAddress(loaded_module, windows_core::PCSTR(func_name.as_ptr()));
                            if let Some(addr) = resolved {
                                let iat_ptr = (base_addr + desc.first_thunk as usize + thunk_idx * std::mem::size_of::<ImageThunkData64>()) as *mut u64;
                                *iat_ptr = addr.0 as u64;
                            }
                        }
                    }
                    
                    thunk_idx += 1;
                }
                
                desc_idx += 1;
            }
            
            Ok(true)
        }
        #[cfg(not(windows))]
        {
            let _ = base_addr;
            let _ = nt_headers;
            Ok(false)
        }
    }
    
    fn setup_tls(&self, _nt_headers: &ImageNTHeaders64) {
        #[cfg(windows)]
        unsafe {
            let opt = &_nt_headers.optional_header;
            let tls_dir = opt.data_directory[9];
            
            if tls_dir.size == 0 || tls_dir.virtual_address == 0 {
                return;
            }
            let _ = tls_dir;
        }
        let _ = self;
    }
    
    fn swap_pe_headers(&self, base_addr: usize, nt_headers: &ImageNTHeaders64) {
        #[cfg(windows)]
        unsafe {
            let header_size = std::mem::size_of::<ImageDosHeader>() 
                + std::mem::size_of::<ImageNTHeaders64>()
                + nt_headers.file_header.number_of_sections as usize * std::mem::size_of::<ImageSectionHeader>();
            
            std::ptr::copy_nonoverlapping(
                self.module as *const u8,
                base_addr as *mut u8,
                header_size.min(self.orig_binary.len()),
            );
        }
    }
    
    pub fn get_entry_point(&self) -> usize {
        self.entry_point
    }
    
    pub fn protect_sections(&self) -> std::result::Result<(), String> {
        #[cfg(windows)]
        unsafe {
            if self.module.is_null() {
                return Ok(());
            }
            
            let dos_header = *(self.module as *const ImageDosHeader);
            if dos_header.e_magic != 0x5A4B {
                return Ok(());
            }
            
            let nt_headers_ptr = (self.module as usize + dos_header.e_lfanew as usize) as *const ImageNTHeaders64;
            if nt_headers_ptr.is_null() {
                return Ok(());
            }
            let nt_headers = *nt_headers_ptr;
            
            let sections_ptr = ((self.module as usize + nt_headers.signature.len() + std::mem::size_of::<ImageFileHeader>()) as *const u8)
                .cast::<ImageSectionHeader>();
            let num_sections = nt_headers.file_header.number_of_sections as usize;
            
            for i in 0..num_sections {
                let sec = *(sections_ptr.add(i));
                if sec.size_of_raw_data == 0 { continue; }
                
                let section_addr = (self.module as usize + sec.virtual_address as usize) as *mut u8;
                let mut old_protect = 0u32;
                
                let desired_protection = if (sec.characteristics & 0x80000000) != 0 {
                    windows::Win32::Security::PAGE_EXECUTE_READWRITE
                } else if (sec.characteristics & 0x40000000) != 0 {
                    windows::Win32::Security::PAGE_EXECUTE_READ
                } else {
                    windows::Win32::Security::PAGE_READWRITE
                };
                
                let _ = VirtualProtect(
                    section_addr as *mut std::ffi::c_void,
                    sec.size_of_raw_data as usize,
                    desired_protection,
                    &mut old_protect,
                );
            }
            
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = self;
            Ok(())
        }
    }
}