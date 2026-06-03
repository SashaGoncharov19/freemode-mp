//! VEH Snapshot Injector — handles GTA5.exe loading via NtCreateSection + VEH.

use core::ffi::c_void;
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
use windows::Win32::Foundation::*;
#[cfg(windows)]
pub use windows::Win32::System::Threading::*;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_MODE, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES};
#[cfg(windows)]
use windows::Win32::System::Memory::{VirtualAlloc, VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, VirtualFreeEx, MEM_RELEASE};
#[cfg(windows)]
use windows::Win32::System::Diagnostics::Debug::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_POINTERS, WriteProcessMemory};
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

const MAX_IMAGE_SIZE: usize = 64 * 1024 * 1024;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SharedContext {
    pub major_version: u32,
    pub minor_version: u32,
    pub patch_level: u32,
    pub build_number: u32,
    pub game_install_path: Vec<u16>,
    pub launch_options: Vec<u16>,
    pub steam_game_path: Vec<u16>,
    pub epic_game_path: Vec<u16>,
    pub rsg_game_path: Vec<u16>,
    pub server_name: [u8; 64],
    pub notify_loading: usize,
}

#[cfg(windows)]
pub fn create_section_from_image(gta_path: std::ffi::OsString) -> windows_core::Result<HANDLE> {
    unsafe {
        let wide_path: Vec<u16> = gta_path.encode_wide().chain(std::iter::once(0u16)).collect();
        let handle = CreateFileW(
            windows_core::PCWSTR(wide_path.as_ptr()),
            0x80000000u32,
            FILE_SHARE_MODE(0x00000001),
            None,
            FILE_CREATION_DISPOSITION(3),
            FILE_FLAGS_AND_ATTRIBUTES(0x80),
            None,
        )?;
        Ok(handle)
    }
}

#[cfg(not(windows))]
pub fn create_section_from_image(_: std::ffi::OsString) -> Result<HANDLE, String> { Err("Not available".into()) }

#[cfg(windows)]
pub fn inject_snapshot(gta_path: std::ffi::OsString) -> windows_core::Result<(*mut c_void, usize)> {
    unsafe {
        let wide_path: Vec<u16> = gta_path.encode_wide().chain(std::iter::once(0u16)).collect();
        let _file_handle = CreateFileW(
            windows_core::PCWSTR(wide_path.as_ptr()),
            0x80000000u32,
            FILE_SHARE_MODE(0x00000001),
            None,
            FILE_CREATION_DISPOSITION(3),
            FILE_FLAGS_AND_ATTRIBUTES(0x80),
            None,
        ).map_err(|_| windows_core::Error::from_win32())?;

        let base_address = VirtualAlloc(None, MAX_IMAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if base_address.is_null() { return Err(windows_core::Error::from_win32()); }

        Ok((base_address, MAX_IMAGE_SIZE))
    }
}

#[cfg(not(windows))]
pub fn inject_snapshot(_: std::ffi::OsString) -> Result<(*mut c_void, usize), String> { Err("Not available".into()) }

#[cfg(windows)]
pub fn install_veh_handler() -> usize {
    unsafe { AddVectoredExceptionHandler(1, Some(snapshot_veh_handler)) as usize }
}

#[cfg(windows)]
pub fn remove_veh_handler(cookie: usize) {
    unsafe { RemoveVectoredExceptionHandler(std::mem::transmute(cookie)); }
}

extern "system" fn snapshot_veh_handler(_exception_info: *mut EXCEPTION_POINTERS) -> i32 { -1 }

#[cfg(windows)]
pub fn inject_dll_from_launcher_folder(_gta5_process: HANDLE) -> windows_core::Result<()> {
    unsafe {
        let launcher_exe = std::env::current_exe().map_err(|_| windows_core::Error::from_win32())?;
        let dll_path = launcher_exe.parent().map(|p| p.join("freemode-client.dll"))
            .ok_or_else(|| windows_core::Error::from_win32())?;
        if !dll_path.exists() { return Err(windows_core::Error::from_win32()); }

        let wide_dll: Vec<u16> = dll_path.as_os_str().encode_wide()
            .chain(std::iter::once(0u16)).collect();

        let process = OpenProcess(PROCESS_ACCESS_RIGHTS(0x001F0FFF), false, 0)
            .map_err(|_| windows_core::Error::from_win32())?;

        let remote_ptr = VirtualAllocEx(process, None, wide_dll.len() * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if remote_ptr.is_null() { return Err(windows_core::Error::from_win32()); }

        let mut bytes_written = 0;
        let _ = WriteProcessMemory(process, remote_ptr, wide_dll.as_ptr() as *const c_void, wide_dll.len() * 2, Some(&mut bytes_written));

        let h_kernel32 = GetModuleHandleW(windows_core::PCWSTR(b"kernel32.dll\0".as_ptr() as *const u16))
            .map_err(|_| windows_core::Error::from_win32())?;
        let load_library_addr = GetProcAddress(h_kernel32, windows_core::PCSTR(b"LoadLibraryW\0".as_ptr()))
            .ok_or_else(|| windows_core::Error::from_win32())?;

        let thread = CreateRemoteThread(
            process, None, 0,
            Some(std::mem::transmute(load_library_addr as usize)),
            Some(remote_ptr), 0, None,
        ).map_err(|_| windows_core::Error::from_win32())?;

        if thread.is_invalid() { return Err(windows_core::Error::from_win32()); }
        let _ = WaitForSingleObject(thread, INFINITE);
        let _ = VirtualFreeEx(process, remote_ptr, 0, MEM_RELEASE);
        let _ = CloseHandle(thread);
        let _ = CloseHandle(process);
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn inject_dll_from_launcher_folder(_: HANDLE) -> Result<(), String> { Err("Not available".into()) }

pub fn get_client_dll_path() -> Option<std::path::PathBuf> {
    std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.join("freemode-client.dll")))
}

pub fn init() {}
pub fn shutdown() {}
pub fn get_trigger_ep_addr() -> usize { 0 }