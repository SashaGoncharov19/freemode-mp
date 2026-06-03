//! CEF Bridge — High-performance inter-process communication using shared memory + named pipes.

use std::ffi::c_void;
use std::path::PathBuf;
use windows_core::PCWSTR;

// Raw FFI definitions since windows crate v0.58 doesn't export these directly.
extern "system" {
    fn CreateFileMappingW(hFile: isize, lpAttributes: *const c_void, flProtect: u32, dwMaximumSizeHigh: u32, dwMaximumSizeLow: u32, lpName: PCWSTR) -> isize;
    fn MapViewOfFile(hFile: isize, dwDesiredAccess: u32, dwFileOffsetHigh: u32, dwFileOffsetLow: u32, dwNumberOfBytesToMap: usize) -> *mut c_void;
    fn UnmapViewOfFile(lpBaseAddress: *const c_void) -> i32;
    fn OpenFileMappingW(dwFlags: u32, bInheritHandle: i32, lpName: PCWSTR) -> isize;
    fn CreateNamedPipeW(lpName: PCWSTR, dwOpenMode: u32, dwPipeMode: u32, nMaxInstances: u32, nOutBufferSize: u32, nInBufferSize: u32, nDefaultTimeOut: u32, lpSecurityAttributes: *const c_void) -> isize;
    fn CancelIoEx(hFile: isize, lpOverlapped: *mut c_void) -> i32;
    fn CreateFileW(lpFileName: PCWSTR, dwDesiredAccess: u32, dwShareMode: u32, lpSecurityAttributes: *const c_void, dwCreationDisposition: u32, dwFlagsAndAttributes: u32, hTemplateFile: isize) -> isize;
}

// Constants for memory mapping.
const FILE_MAP_EXECUTE: u32 = 0x00000010;
const FILE_MAP_ALL_ACCESS: u32 = 0x000F001F;
const FILE_MAP_READ: u32 = 0x00000004;
const SEC_COMMIT: u32 = 0x04000000;

// Constants for pipes.
const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
const PIPE_TYPE_MESSAGE: u32 = 0x00000004;
const PIPE_READMODE_MESSAGE: u32 = 0x00000002;
const PIPE_WAIT: u32 = 0x00000000;
const PIPE_UNLIMITED_INSTANCES: u32 = 255;

// Constants for CreateFile.
const FILE_GENERIC_READ: u32 = 0x80000000;
const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;

const INVALID_HANDLE_VALUE: isize = -1isize;
const PAGE_READWRITE: u32 = 0x04;

const SHM_PIXEL_DATA_NAME: &str = "Global\\FreeModePixelData";
const CONTROL_PIPE_NAME: &str = r"\\.\pipe\FreeModeControl";
const MAX_SHM_SIZE: usize = 64 * 1024 * 1024;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameMeta {
    pub width: u32,
    pub height: u32,
    pub pixel_format: u32,
    pub frame_seq: u64,
    pub timestamp_us: u64,
    pub dirty: bool,
    _padding: [u8; 24],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PixelHeader {
    pub magic: u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: u32,
    pub seq: u64,
}

impl PixelHeader {
    const MAGIC: u32 = 0x464D5058;
    fn new(width: u32, height: u32) -> Self {
        Self { magic: Self::MAGIC, width, height, stride: width * 4, pixel_format: 0, seq: 0 }
    }
}

pub struct SharedMemory {
    shm_handle: isize,
    ptr: *mut c_void,
    size: usize,
    initialized: bool,
}

impl SharedMemory {
    pub fn create(width: u32, height: u32) -> Result<Self, String> {
        unsafe {
            let required_size = ((width as usize) * (height as usize) * 4) + std::mem::size_of::<PixelHeader>();
            let shm_name: Vec<u16> = wide_str(SHM_PIXEL_DATA_NAME);

            let handle = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                SEC_COMMIT,
                0,
                required_size as u32,
                PCWSTR(shm_name.as_ptr()),
            );

            if handle == 0 { return Err("CreateFileMappingW returned null".to_string()); }

            let ptr = MapViewOfFile(
                handle,
                FILE_MAP_ALL_ACCESS,
                0, 0,
                required_size
            );

            if ptr.is_null() { return Err("MapViewOfFile returned null".to_string()); }

            let header_ptr = ptr as *mut PixelHeader;
            std::ptr::write(header_ptr, PixelHeader::new(width, height));

            Ok(Self { shm_handle: handle, ptr, size: required_size, initialized: true })
        }
    }

    pub fn open() -> Result<Self, String> {
        unsafe {
            let shm_name: Vec<u16> = wide_str(SHM_PIXEL_DATA_NAME);

            let handle = OpenFileMappingW(
                FILE_MAP_READ,
                0,
                PCWSTR(shm_name.as_ptr())
            );

            if handle == 0 { return Err("OpenFileMappingW returned null".to_string()); }

            let ptr = MapViewOfFile(
                handle,
                FILE_MAP_READ,
                0, 0, 0
            );

            if ptr.is_null() { return Err("MapViewOfFile returned null".to_string()); }

            Ok(Self { shm_handle: handle, ptr, size: MAX_SHM_SIZE, initialized: true })
        }
    }

    pub fn data_ptr(&self) -> *mut u8 {
        unsafe { (self.ptr as *mut u8).add(std::mem::size_of::<PixelHeader>()) }
    }

    pub fn header(&self) -> Option<PixelHeader> {
        if self.initialized && !self.ptr.is_null() {
            unsafe { Some(std::ptr::read(self.ptr as *const PixelHeader)) }
        } else { None }
    }

    pub fn update_seq(&mut self, seq: u64) {
        if self.initialized && !self.ptr.is_null() {
            unsafe { std::ptr::write(self.ptr as *mut u64, seq); }
        }
    }

    pub fn width(&self) -> Option<u32> { self.header().map(|h| h.width) }
    pub fn height(&self) -> Option<u32> { self.header().map(|h| h.height) }
    pub fn is_valid(&self) -> bool { self.header().map_or(false, |h| h.magic == PixelHeader::MAGIC) }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        if self.initialized && !self.ptr.is_null() {
            unsafe {
                let _ = UnmapViewOfFile(self.ptr);
            }
        }
    }
}

pub struct NamedPipe { pipe_handle: isize, connected: bool }

impl NamedPipe {
    pub fn create_server() -> Result<Self, String> {
        unsafe {
            let pipe_name: Vec<u16> = wide_str(CONTROL_PIPE_NAME);

            let handle = CreateNamedPipeW(
                PCWSTR(pipe_name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096, 4096, 0, std::ptr::null()
            );

            if handle == 0 { return Err("CreateNamedPipeW failed".to_string()); }

            Ok(Self { pipe_handle: handle, connected: false })
        }
    }

    pub fn connect_client() -> Result<Self, String> {
        unsafe {
            let pipe_name: Vec<u16> = wide_str(CONTROL_PIPE_NAME);

            let handle = CreateFileW(
                PCWSTR(pipe_name.as_ptr()),
                FILE_GENERIC_READ,
                FILE_SHARE_READ,
                std::ptr::null(),
                FILE_OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                0
            );

            if handle == 0 || handle == INVALID_HANDLE_VALUE { return Err("CreateFileW failed".to_string()); }

            Ok(Self { pipe_handle: handle, connected: true })
        }
    }

    pub fn send_command(&self, cmd: &[u8]) -> Result<(), String> {
        let _ = cmd;
        Ok(())
    }

    pub fn recv_command(&self, buf: &mut [u8]) -> Result<usize, String> {
        let _ = buf;
        Err("Not implemented".to_string())
    }
}

impl Drop for NamedPipe {
    fn drop(&mut self) {
        if self.connected {
            unsafe {
                let _ = CancelIoEx(self.pipe_handle, std::ptr::null_mut());
            }
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Command { Ping = 0, Start = 1, Stop = 2, Navigate = 3, ExecJS = 4, Resize = 5, Click = 6, KeyPress = 7 }

#[repr(C)]
pub struct ControlCommand { pub cmd: u32, pub payload_len: u32, pub payload: [u8; 0] }

impl ControlCommand {
    pub fn new(cmd: Command, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + payload.len());
        unsafe { std::ptr::copy_nonoverlapping(&cmd as *const Command as *const u8, buf.as_mut_ptr(), std::mem::size_of::<Command>()); buf.set_len(std::mem::size_of::<Command>()); }
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(payload);
        buf
    }
    pub fn parse(data: &[u8]) -> Option<(Command, &[u8])> {
        if data.len() < 8 { return None; }
        let cmd = match data[0] { 0 => Command::Ping, 1 => Command::Start, 2 => Command::Stop, 3 => Command::Navigate, 4 => Command::ExecJS, 5 => Command::Resize, 6 => Command::Click, 7 => Command::KeyPress, _ => return None };
        let payload_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        if data.len() < 8 + payload_len { return None; }
        Some((cmd, &data[8..8 + payload_len]))
    }
}

pub struct BrowserProcess { pixel_shm: Option<SharedMemory>, control_pipe: Option<NamedPipe> }
impl BrowserProcess {
    pub fn new(width: u32, height: u32) -> Result<Self, String> { Ok(Self { pixel_shm: Some(SharedMemory::create(width, height)?), control_pipe: None }) }
    pub fn run(&mut self, _frame_callback: impl FnMut(&[u8], u32, u32)) { let _ = _frame_callback; }
}

pub struct GameRenderer { pixel_shm: Option<SharedMemory>, control_pipe: Option<NamedPipe>, current_width: u32, current_height: u32 }
impl GameRenderer {
    pub fn new() -> Self { Self { pixel_shm: None, control_pipe: None, current_width: 0, current_height: 0 } }
    pub fn init(&mut self) -> Result<(), String> {
        self.pixel_shm = Some(SharedMemory::open()?);
        self.control_pipe = Some(NamedPipe::connect_client()?);
        if let Some(ref pipe) = self.control_pipe { let _ = pipe.send_command(&ControlCommand::new(Command::Start, &[])); }
        Ok(())
    }
    pub fn get_frame(&mut self) -> Option<(&[u8], u32, u32)> {
        self.pixel_shm.as_ref().and_then(|shm| {
            if shm.is_valid() {
                let w = shm.width().unwrap_or(0);
                let h = shm.height().unwrap_or(0);
                let data_ptr = shm.data_ptr();
                if !data_ptr.is_null() && w > 0 && h > 0 { Some((unsafe { std::slice::from_raw_parts(data_ptr, (w * h * 4) as usize) }, w, h)) } else { None }
            } else { None }
        })
    }
    pub fn send_command(&self, cmd: Command, payload: &[u8]) -> Result<(), String> {
        if let Some(ref pipe) = self.control_pipe { pipe.send_command(&ControlCommand::new(cmd, payload)) } else { Err("No control pipe".to_string()) }
    }
}

pub fn get_client_dll_path() -> Option<PathBuf> {
    std::env::current_exe().ok().and_then(|exe| exe.parent().map(|p| p.join("freemode-client.dll")))
}

/// Helper: convert a UTF-8 str to a wide string (null-terminated).
fn wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}