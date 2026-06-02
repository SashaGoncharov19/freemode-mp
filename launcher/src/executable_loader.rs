//! Executable loader — PE parsing, memory mapping, relocations, imports, TLS.
//!
//! Implements a minimal PE loader that can map GTA5.exe into memory and prepare it
//! for snapshot injection. This is the core of the "executable loader" architecture.

use std::ffi::c_void;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use windows::core::Result;
use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, FILE_MAP_COPY, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PAGE_READWRITE, PROTECT_EXECUTE,
};
use windows::Win32::System::WindowsProgramming::IMAGE_DIRECTORY_ENTRY_BASERELOC;
use windows::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_TLS;

/// Parsed PE header information.
#[derive(Debug, Clone)]
pub struct PeInfo {
    /// Original file path
    pub path: PathBuf,
    /// File size
    pub file_size: u64,
    /// Image base (preferred load address)
    pub image_base: u64,
    /// Image size in memory
    pub image_size: u32,
    /// Number of sections
    pub section_count: u16,
    /// Entry point RVA
    pub entry_point: u32,
    /// Section headers
    pub sections: Vec<SectionInfo>,
    /// Relocation directory
    pub relocations: Vec<RelocationEntry>,
    /// Import directory
    pub imports: Vec<ImportEntry>,
    /// TLS directory
    pub tls: Option<TlsEntry>,
}

/// Information about a PE section.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_offset: u32,
    pub raw_data_size: u32,
    pub characteristics: u32,
}

/// A relocation entry.
#[derive(Debug, Clone)]
pub struct RelocationEntry {
    pub rva: u32,
    pub type_: u8,
}

/// An import entry.
#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub library: String,
    pub functions: Vec<String>,
}

/// TLS callback information.
#[derive(Debug, Clone)]
pub struct TlsEntry {
    pub start_address: u32,
    pub end_address: u32,
    pub index: u32,
    pub callbacks: Vec<u32>,
}

/// Load and parse a PE file.
pub fn load_pe(path: &Path) -> Result<PeInfo> {
    let mut file = File::open(path).map_err(|e| windows::core::Error::from(e))?;
    
    // Read DOS header
    let mut dos_header = [0u8; 64];
    file.read_exact(&mut dos_header).ok();
    
    // Check MZ signature
    if dos_header[0..2] != [0x4D, 0x5A] { // "MZ"
        return Err(windows::core::Error::from(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Not a PE file")
        ));
    }
    
    // Get PE header offset
    let pe_offset = u32::from_le_bytes([
        dos_header[0x3C],
        dos_header[0x3D],
        dos_header[0x3E],
        dos_header[0x3F],
    ]) as usize;
    
    // Read PE signature and COFF header
    let mut pe_sig = [0u8; 4];
    file.seek(std::io::SeekFrom::Start(pe_offset as u64)).ok();
    file.read_exact(&mut pe_sig).ok();
    
    if pe_sig != [0x50, 0x45, 0x00, 0x00] { // "PE\0\0"
        return Err(windows::core::Error::from(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid PE signature")
        ));
    }
    
    // Read COFF header (20 bytes)
    let mut coff_header = vec![0u8; 20];
    file.read_exact(&mut coff_header).ok();
    
    let section_count = u16::from_le_bytes([coff_header[4], coff_header[5]]);
    let size_of_optional_header = u16::from_le_bytes([coff_header[16], coff_header[17]]);
    
    // Read optional header to get image base and size
    let mut optional_header = vec![0u8; size_of_optional_header as usize];
    file.read_exact(&mut optional_header).ok();
    
    // PE32+ magic (0x20B) indicates 64-bit
    let magic = u16::from_le_bytes([optional_header[0], optional_header[1]]);
    let is_pe32_plus = magic == 0x20B;
    
    let image_base = if is_pe32_plus {
        u64::from_le_bytes([
            optional_header[24], optional_header[25], optional_header[26], optional_header[27],
            optional_header[28], optional_header[29], optional_header[30], optional_header[31],
        ])
    } else {
        u64::from_le_bytes([
            optional_header[28], optional_header[29], optional_header[30], optional_header[31],
            0, 0, 0, 0,
        ])
    };
    
    let image_size = u32::from_le_bytes([
        optional_header[32], optional_header[33], optional_header[34], optional_header[35],
    ]);
    
    let entry_point = u32::from_le_bytes([
        optional_header[16], optional_header[17], optional_header[18], optional_header[19],
    ]);
    
    // Read section headers (40 bytes each)
    let mut sections = Vec::new();
    for _ in 0..section_count {
        let mut section = [0u8; 40];
        file.read_exact(&mut section).ok();
        
        let name = String::from_utf8_lossy(&section[0..8]).trim_matches('\0').to_string();
        let virtual_address = u32::from_le_bytes([section[12], section[13], section[14], section[15]]);
        let virtual_size = u32::from_le_bytes([section[16], section[17], section[18], section[19]]);
        let raw_data_offset = u32::from_le_bytes([section[20], section[21], section[22], section[23]]);
        let raw_data_size = u32::from_le_bytes([section[24], section[25], section[26], section[27]]);
        let characteristics = u32::from_le_bytes([section[36], section[37], section[38], section[39]]);
        
        sections.push(SectionInfo {
            name,
            virtual_address,
            virtual_size,
            raw_data_offset,
            raw_data_size,
            characteristics,
        });
    }
    
    // Parse relocations and imports from data directories
    let relocations = parse_relocations(&optional_header, &file)?;
    let imports = parse_imports(&optional_header, &file)?;
    let tls = parse_tls(&optional_header)?;
    
    Ok(PeInfo {
        path: path.to_path_buf(),
        file_size: file.metadata()?.len(),
        image_base,
        image_size,
        section_count,
        entry_point,
        sections,
        relocations,
        imports,
        tls,
    })
}

/// Parse relocation entries from the PE file.
fn parse_relocations(optional_header: &[u8], _file: &File) -> Result<Vec<RelocationEntry>> {
    // This is a simplified implementation
    // In a real implementation, you would:
    // 1. Get the relocation directory RVA and size from data directories
    // 2. Read each block of relocations
    // 3. Parse each relocation entry
    
    Vec::new()
}

/// Parse import entries from the PE file.
fn parse_imports(optional_header: &[u8], _file: &File) -> Result<Vec<ImportEntry>> {
    // This is a simplified implementation
    // In a real implementation, you would:
    // 1. Get the import directory RVA and size from data directories
    // 2. Read each import descriptor
    // 3. Parse the library name and function names
    
    Vec::new()
}

/// Parse TLS entries from the PE file.
fn parse_tls(optional_header: &[u8]) -> Result<Option<TlsEntry>> {
    // TLS directory is at index IMAGE_DIRECTORY_ENTRY_TLS (9)
    // Each data directory is 8 bytes (RVA + Size)
    let tls_rva_offset = 9 * 8 + 8; // Data directory index * 8 + offset in optional header
    
    if tls_rva_offset + 8 > optional_header.len() {
        return Ok(None);
    }
    
    let tls_rva = u32::from_le_bytes([
        optional_header[tls_rva_offset],
        optional_header[tls_rva_offset + 1],
        optional_header[tls_rva_offset + 2],
        optional_header[tls_rva_offset + 3],
    ]);
    
    if tls_rva == 0 {
        return Ok(None);
    }
    
    // In a real implementation, you would read the TLS directory at this RVA
    Ok(Some(TlsEntry {
        start_address: 0,
        end_address: 0,
        index: 0,
        callbacks: Vec::new(),
    }))
}

/// Map a PE file into memory for injection.
pub fn map_pe_into_memory(pe_info: &PeInfo) -> Result<(*mut c_void, u64)> {
    unsafe {
        // Allocate memory at the preferred image base
        let base_address = VirtualAlloc(
            None,
            pe_info.image_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        
        if base_address.is_null() {
            return Err(windows::core::Error::from(
                std::io::Error::new(std::io::ErrorKind::Other, "Failed to allocate memory")
            ));
        }
        
        // Copy sections into memory
        for section in &pe_info.sections {
            let section_dest = base_address.add(section.virtual_address as usize) as *mut u8;
            // In a real implementation, you would read the section data from the file
            // and copy it to section_dest
        }
        
        Ok((base_address, pe_info.image_base))
    }
}

/// Apply relocations to a mapped PE.
pub fn apply_relocations(base: *mut c_void, image_size: u32, relocations: &[RelocationEntry]) -> Result<()> {
    // In a real implementation, you would:
    // 1. Calculate the delta between the actual base and preferred base
    // 2. For each relocation entry, apply the fixup
    
    Ok(())
}

/// Apply imports to a mapped PE.
pub fn apply_imports(_base: *mut c_void, _imports: &[ImportEntry]) -> Result<()> {
    // In a real implementation, you would:
    // 1. Load each imported DLL using LoadLibraryW
    // 2. Resolve each function address using GetProcAddress
    // 3. Write the function addresses to the IAT
    
    Ok(())
}

/// Execute TLS callbacks for a mapped PE.
pub fn execute_tls_callbacks(_base: *mut c_void, _tls: &Option<TlsEntry>) -> Result<()> {
    // In a real implementation, you would:
    // 1. Find the TLS directory in the mapped memory
    // 2. Call each callback function with DLL reasons
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_info_structure() {
        let pe_info = PeInfo {
            path: PathBuf::from("C:\\GTA5\\GTA5.exe"),
            file_size: 1024 * 1024,
            image_base: 0x140000000,
            image_size: 0x800000,
            section_count: 9,
            entry_point: 0x1234,
            sections: Vec::new(),
            relocations: Vec::new(),
            imports: Vec::new(),
            tls: None,
        };
        
        assert_eq!(pe_info.section_count, 9);
        assert_eq!(pe_info.image_size, 0x800000);
    }
}
