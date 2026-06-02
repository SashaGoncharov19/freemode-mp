//! Executable Loader — loads GTA5.exe into our memory space (FiveM-style).
//!
//! Implements the FiveM approach for loading game executables:
//! - Reads the executable file into memory
//! - Applies base relocations manually
//! - Resolves imports from loaded modules
//! - Sets up TLS callbacks
//! - Swaps PE headers and calls the entry point

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
// PE Header Structures (used for in-memory parsing)
// ============================================================================

/// DOS header.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    pub e_lfanew: i32,
}

/// File header (IMAGE_FILE_HEADER).
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

/// Data directory entry.
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

/// Optional header (PE32+).
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
    /// Gets the size of the optional header.
    pub fn size(&self) -> u16 {
        240 + (self.number_of_rva_and_sizes as u16) * 16
    }
    
    /// Gets import directory entry.
    pub fn import_directory(&self) -> &ImageDataDirectory {
        &self.data_directory[1] // IMAGE_DIRECTORY_ENTRY_IMPORT = 1
    }
}

/// NT Headers (PE32+).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageNTHeaders64 {
    pub signature: [u8; 4],
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

/// Section header.
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
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    pub characteristics: u32,
}

// ============================================================================
// Import-related structures
// ============================================================================

/// Import descriptor (IMAGE_IMPORT_DESCRIPTOR).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageImportDescriptor {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    major_forwarder_chain: i16,
    pub name: u32,
    pub first_thunk: u32,
}

/// Thunk data for 64-bit.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageThunkData64 {
    pub address_of_data: u64,
}

// ============================================================================
// ExecutableLoader struct (FiveM-style)
// ============================================================================

/// Loads an executable into our memory space.
pub struct ExecutableLoader {
    /// Original binary data.
    orig_binary: Vec<u8>,
    /// Base address of loaded module.
    module: *mut u8,
    /// Load limit (max size).
    load_limit: usize,
    /// Entry point offset.
    entry_point: usize,
    /// Library loader callback.
    library_loader: fn(&str) -> HMODULE,
    /// Function resolver callback.
    function_resolver: fn(HMODULE, &str) -> LPVOID,
    /// TLS initializer callback.
    tls_initializer: fn(*const u8) -> bool,
    /// Target protections to apply.
    target_protections: Vec<(usize, u32, u32)>,
}

impl ExecutableLoader {
    /// Creates a new executable loader from raw binary data.
    pub fn new(binary_data: Vec<u8>) -> Self {
        Self {
            orig_binary: binary_data,
            module: ptr::null_mut(),
            load_limit: 0x140000000 + 0x60000000, // GTA V default (512 MB + 96 MB)
            entry_point: 0,
            library_loader: Self::default_library_loader,
            function_resolver: Self::default_function_resolver,
            tls_initializer: Self::default_tls_initializer,
            target_protections: Vec::new(),
        }
    }
    
    /// Default library loader callback.
    fn default_library_loader(name: &str) -> HMODULE {
        #[cfg(windows)]
        unsafe {
            let wide: Vec<u16> = std::ffi::CString::new(name)
                .map_err(|_| 0 as HMODULE)
                .unwrap_or_default()
                .as_bytes_with_nul()
                .iter()
                .copied()
                .chain(std::iter::once(0))
                .collect();
            // Use PCSTR since we're dealing with ANSI bytes.
            LoadLibraryA(windows_core::PCSTR(wide.as_ptr() as *const i8))
                .unwrap_or_default()
        }
        #[cfg(not(windows))]
        {
            let _ = name;
            0 as HMODULE
        }
    }
    
    /// Default function resolver callback.
    fn default_function_resolver(module: HMODULE, name: &str) -> LPVOID {
        #[cfg(windows)]
        unsafe {
            let cstr = std::ffi::CString::new(name).unwrap_or_default();
            GetProcAddress(module, windows_core::PCSTR(cstr.as_ptr()))
                .unwrap_or(ptr::null_mut())
        }
        #[cfg(not(windows))]
        {
            let _ = (module, name);
            ptr::null_mut()
        }
    }
    
    /// Default TLS initializer callback.
    fn default_tls_initializer(_tls_dir: *const u8) -> bool {
        let _ = _tls_dir;
        true // Stub - in production would call TLS callbacks
    }
    
    /// Sets the load limit.
    pub fn set_load_limit(&mut self, limit: usize) {
        self.load_limit = limit;
    }
    
    /// Sets a custom library loader callback.
    pub fn set_library_loader<F>(&mut self, loader: F)
    where
        F: Fn(&str) -> HMODULE + 'static,
    {
        self.library_loader = move |s| loader(s);
    }
    
    /// Sets a custom function resolver callback.
    pub fn set_function_resolver<F>(&mut self, resolver: F)
    where
        F: Fn(HMODULE, &str) -> LPVOID + 'static,
    {
        self.function_resolver = resolver;
    }
    
    /// Loads the executable into memory and applies relocations.
    pub fn load_into_module(&mut self, target_module: HMODULE) -> std::result::Result<bool, String> {
        #[cfg(windows)]
        unsafe {
            let base_addr = target_module.0 as usize;
            
            // Parse DOS header.
            let dos_header = *(base_addr as *const ImageDosHeader);
            if dos_header.e_magic != 0x5A4B {
                return Ok(false); // Invalid MZ signature
            }
            
            // Get NT headers.
            let nt_headers_ptr = (base_addr + dos_header.e_lfanew as usize) as *const ImageNTHeaders64;
            if nt_headers_ptr.is_null() {
                return Ok(false);
            }
            let nt_headers = unsafe { *nt_headers_ptr };
            
            // Validate PE32+.
            if nt_headers.signature != [0x00, 0x00, 0x0b, 0x02] {
                return Ok(false); // Not PE32+
            }
            
            let opt_header = &nt_headers.optional_header;
            
            // Allocate memory for the executable.
            let alloc_addr = VirtualAlloc(
                None,
                self.load_limit,
                windows::Win32::System::Memory::MEM_RESERVE,
                windows::Win32::Security::PAGE_READWRITE,
            );
            
            if alloc_addr.is_null() {
                return Ok(false);
            }
            
            self.module = alloc_addr as *mut u8;
            
            // Copy the binary data.
            std::ptr::copy_nonoverlapping(
                self.orig_binary.as_ptr(),
                self.module,
                self.orig_binary.len(),
            );
            
            // Apply relocations.
            if !self.apply_relocations(base_addr, &nt_headers)? {
                return Ok(false);
            }
            
            // Resolve imports.
            if !self.resolve_imports(base_addr, &nt_headers)? {
                return Ok(false);
            }
            
            // Setup TLS callbacks.
            self.setup_tls(nt_headers);
            
            // Swap PE headers (make it look like a real loaded module).
            self.swap_pe_headers(base_addr, nt_headers);
            
            // Get entry point.
            self.entry_point = base_addr + opt_header.address_of_entry_point as usize;
            
            Ok(true)
        }
        #[cfg(not(windows))]
        {
            let _ = target_module;
            Ok(false)
        }
    }
    
    /// Applies base relocations to the loaded module.
    fn apply_relocations(&self, base_addr: usize, nt_headers: &ImageNTHeaders64) -> std::result::Result<bool, String> {
        #[cfg(windows)]
        unsafe {
            let opt = &nt_headers.optional_header;
            let import_dir = opt.import_directory();
            
            if import_dir.size == 0 || import_dir.virtual_address == 0 {
                return Ok(true); // No relocations
            }
            
            // Find the section containing relocations.
            let sections_ptr = ((base_addr + nt_headers.signature.len() + std::mem::size_of::<ImageFileHeader>()) as *const u8)
                .cast::<ImageSectionHeader>();
            let num_sections = nt_headers.file_header.number_of_sections as usize;
            
            // Walk relocation entries.
            let reloc_dir = opt.data_directory[12]; // IMAGE_DIRECTORY_ENTRY_BASERELOC = 12
            if reloc_dir.size == 0 || reloc_dir.virtual_address == 0 {
                return Ok(true);
            }
            
            // Find section containing relocations.
            let mut reloc_section_idx = 0;
            for i in 0..num_sections {
                let sec = *(sections_ptr.add(i));
                if sec.virtual_address <= reloc_dir.virtual_address 
                    && reloc_dir.virtual_address < sec.virtual_address + sec.size_of_raw_data {
                    reloc_section_idx = i;
                    break;
                }
            }
            
            // Convert RVA to file offset.
            let reloc_sec = *(sections_ptr.add(reloc_section_idx));
            let reloc_file_offset = (reloc_dir.virtual_address - reloc_sec.virtual_address) as usize 
                + reloc_sec.pointer_to_raw_data as usize;
            
            let reloc_base = (base_addr + reloc_file_offset) as *const u8;
            
            // Process block by block.
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
                    
                    if type_ == 3 { // IMAGE_REL_BASED_HIGHLOW
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
    
    /// Resolves all imports for the loaded module.
    fn resolve_imports(&self, base_addr: usize, nt_headers: &ImageNTHeaders64) -> std::result::Result<bool, String> {
        #[cfg(windows)]
        unsafe {
            let opt = &nt_headers.optional_header;
            let import_dir = opt.import_directory();
            
            if import_dir.size == 0 || import_dir.virtual_address == 0 {
                return Ok(true);
            }
            
            // Find the section containing the import table.
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
                    break; // End of import table
                }
                
                // Get module name.
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
                
                // Load the module.
                let loaded_module = (self.library_loader)(mod_name);
                #[cfg(windows)]
                if loaded_module.is_null() {
                    desc_idx += 1;
                    continue;
                }
                #[cfg(not(windows))]
                if loaded_module == 0 {
                    desc_idx += 1;
                    continue;
                }
                
                // Resolve all imports from this module.
                let thunk_ptr = (base_addr + desc.first_thunk as usize) as *const ImageThunkData64;
                let orig_thunk_ptr = (base_addr + desc.characteristics as usize) as *const ImageThunkData64;
                
                let mut thunk_idx = 0;
                loop {
                    let thunk = *(thunk_ptr.add(thunk_idx));
                    let orig_thunk = *(orig_thunk_ptr.add(thunk_idx));
                    
                    if thunk.address_of_data == 0 { break; }
                    
                    // Check if imported by name (highest bit = 0).
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
                            let resolved = (self.function_resolver)(loaded_module, func_name);
                            if !resolved.is_null() {
                                let iat_ptr = (base_addr + desc.first_thunk as usize + thunk_idx * std::mem::size_of::<ImageThunkData64>()) as *mut u64;
                                *iat_ptr = resolved as u64;
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
    
    /// Sets up TLS callbacks.
    fn setup_tls(&self, _nt_headers: &ImageNTHeaders64) {
        #[cfg(windows)]
        unsafe {
            let opt = &_nt_headers.optional_header;
            let tls_dir = opt.data_directory[9]; // IMAGE_DIRECTORY_ENTRY_TLS = 9
            
            if tls_dir.size == 0 || tls_dir.virtual_address == 0 {
                return;
            }
            
            // In production, walk TLS directory and call callbacks.
            let _ = tls_dir;
        }
        let _ = self;
    }
    
    /// Swaps PE headers to make the module look legitimate.
    fn swap_pe_headers(&self, base_addr: usize, nt_headers: &ImageNTHeaders64) {
        #[cfg(windows)]
        unsafe {
            // Copy our loaded binary's headers over the original.
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
    
    /// Gets the entry point address.
    pub fn get_entry_point(&self) -> usize {
        self.entry_point
    }
    
    /// Protects sections according to FiveM's RWX_TEST approach.
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
            let nt_headers = unsafe { *nt_headers_ptr };
            let sections_ptr = ((self.module as usize + nt_headers.signature.len() + std::mem::size_of::<ImageFileHeader>()) as *const u8)
                .cast::<ImageSectionHeader>();
            let num_sections = nt_headers.file_header.number_of_sections as usize;
            
            for i in 0..num_sections {
                let sec = *(sections_ptr.add(i));
                if sec.size_of_raw_data == 0 { continue; }
                
                let section_addr = (self.module as usize + sec.virtual_address as usize) as *mut u8;
                let mut old_protect = 0u32;
                
                // Apply appropriate protection based on characteristics.
                let desired_protection = if (sec.characteristics & 0x80000000) != 0 {
                    windows::Win32::Security::PAGE_EXECUTE_READWRITE // MEM_EXECUTE | IMAGE_SCN_MEM_EXECUTE
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
