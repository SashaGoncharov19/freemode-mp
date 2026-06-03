//! Executable loader — stub PE parsing implementation.
//! Actual PE loading not needed for DLL injection approach.

use std::ffi::c_void;
use std::path::PathBuf;

/// Parsed PE header information (stub).
#[derive(Debug, Clone)]
pub struct PeInfo {
    pub path: PathBuf,
    pub file_size: u64,
    pub image_base: u64,
    pub image_size: u32,
    pub section_count: u16,
    pub entry_point: u32,
    pub sections: Vec<SectionInfo>,
    pub relocations: Vec<RelocationEntry>,
    pub imports: Vec<ImportEntry>,
    pub tls: Option<TlsEntry>,
}

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_offset: u32,
    pub raw_data_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone)]
pub struct RelocationEntry {
    pub rva: u32,
    pub type_: u8,
}

#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub library: String,
    pub functions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TlsEntry {
    pub start_address: u32,
    pub end_address: u32,
    pub index: u32,
    pub callbacks: Vec<u32>,
}

/// Load and parse a PE file (stub - returns empty info).
pub fn load_pe(_path: &std::path::Path) -> Result<PeInfo, String> {
    Ok(PeInfo {
        path: _path.to_path_buf(),
        file_size: 0,
        image_base: 0x140000000,
        image_size: 0x800000,
        section_count: 9,
        entry_point: 0,
        sections: Vec::new(),
        relocations: Vec::new(),
        imports: Vec::new(),
        tls: None,
    })
}

/// Map a PE file into memory (stub).
pub fn map_pe_into_memory(_pe_info: &PeInfo) -> Result<(*mut c_void, u64), String> {
    Ok((std::ptr::null_mut(), _pe_info.image_base))
}

/// Apply relocations to a mapped PE (stub).
pub fn apply_relocations(_base: *mut c_void, _image_size: u32, _relocations: &[RelocationEntry]) -> Result<(), String> {
    Ok(())
}

/// Apply imports to a mapped PE (stub).
pub fn apply_imports(_base: *mut c_void, _imports: &[ImportEntry]) -> Result<(), String> {
    Ok(())
}

/// Execute TLS callbacks for a mapped PE (stub).
pub fn execute_tls_callbacks(_base: *mut c_void, _tls: &Option<TlsEntry>) -> Result<(), String> {
    Ok(())
}