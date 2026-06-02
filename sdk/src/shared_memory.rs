// Cross-process shared memory utilities for FreeMode (Windows only).
// 
// On non-Windows platforms this module provides stub implementations.

#[cfg(target_os = "windows")]
mod sys {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    /// The shared memory prefix used by FreeMode processes.
    pub const SHARED_DATA_PREFIX: &str = "CFX_";
    pub const SHARED_DATA_SUFFIX: &str = "_SharedData_";

    extern "system" {
        fn CreateFileMappingW(
            hfile: isize,
            lpAttributes: *mut core::ffi::c_void,
            dwDesiredAccess: u32,
            dwMaximumSizeHigh: u32,
            dwMaximumSizeLow: u32,
            lpName: *const u16,
        ) -> isize;

        fn MapViewOfFile(
            hFileMappingObject: isize,
            dwDesiredAccess: u32,
            dwFileOffsetHigh: u32,
            dwFileOffsetLow: u32,
            dwNumberOfBytesToMap: usize,
        ) -> *mut core::ffi::c_void;

        fn UnmapViewOfFile(lpBaseAddress: *const core::ffi::c_void) -> i32;

        fn CloseHandle(hObject: isize) -> i32;
    }

    const PAGE_READWRITE: u32 = 0x04;
    const FILE_MAP_READ: u32 = 0x0004;

    /// Represents a piece of shared data accessible across processes.
    pub struct SharedMemory<T> {
        mapping_handle: isize,
        data_ptr: *mut T,
        _marker: std::marker::PhantomData<T>,
    }

    unsafe impl<T: Send + Sync> Send for SharedMemory<T> {}
    unsafe impl<T: Send + Sync> Sync for SharedMemory<T> {}

    impl<T> SharedMemory<T> {
        pub fn open(name: &str) -> Option<Self> {
            Self::open_with_flags(name, true)
        }

        pub fn open_with_flags(name: &str, _init_if_new: bool) -> Option<Self> {
            let full_name = format!("{0}{1}{2}{3}", SHARED_DATA_PREFIX, name, SHARED_DATA_SUFFIX, name);
            let wide_name: Vec<u16> = OsStr::new(&full_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mapping_handle = unsafe {
                CreateFileMappingW(
                    -1isize,
                    ptr::null_mut(),
                    PAGE_READWRITE,
                    0,
                    u32::try_from(std::mem::size_of::<T>()).unwrap_or(u32::MAX),
                    wide_name.as_ptr(),
                )
            };

            if mapping_handle == 0 {
                return None;
            }

            let data_ptr = unsafe {
                MapViewOfFile(
                    mapping_handle,
                    FILE_MAP_READ,
                    0,
                    0,
                    std::mem::size_of::<T>(),
                )
            } as *mut T;

            if data_ptr.is_null() {
                return None;
            }

            Some(SharedMemory {
                mapping_handle,
                data_ptr,
                _marker: std::marker::PhantomData,
            })
        }

        pub fn data_mut(&mut self) -> &mut T {
            unsafe { &mut *self.data_ptr }
        }

        pub fn data(&self) -> &T {
            unsafe { &*self.data_ptr }
        }

        pub fn as_ptr(&self) -> *mut T {
            self.data_ptr
        }
    }

    impl<T> Drop for SharedMemory<T> {
        fn drop(&mut self) {
            unsafe {
                if !self.data_ptr.is_null() {
                    let _ = UnmapViewOfFile(self.data_ptr as *const core::ffi::c_void);
                    self.data_ptr = ptr::null_mut();
                }
                let _ = CloseHandle(self.mapping_handle);
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub use sys::*;

/// Shared context data exchanged between launcher and game processes.
#[derive(Debug, Clone, Copy)]
pub struct HostSharedContext {
    pub launch_mode: [u8; 16],
    pub product_key: [u8; 16],
    pub game_build: i32,
    pub game_pid: u32,
    pub is_main_process: bool,
    pub reserved: [u8; 64],
}

impl Default for HostSharedContext {
    fn default() -> Self {
        HostSharedContext {
            launch_mode: [0u8; 16],
            product_key: [0u8; 16],
            game_build: 0,
            game_pid: 0,
            is_main_process: false,
            reserved: [0u8; 64],
        }
    }
}

impl HostSharedContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_launch_mode(&mut self, mode: &str) {
        let bytes = mode.as_bytes();
        let len = std::cmp::min(bytes.len(), self.launch_mode.len());
        self.launch_mode[..len].copy_from_slice(&bytes[..len]);
    }

    pub fn set_product_key(&mut self, key: &str) {
        let bytes = key.as_bytes();
        let len = std::cmp::min(bytes.len(), self.product_key.len());
        self.product_key[..len].copy_from_slice(&bytes[..len]);
    }

    pub fn launch_mode_str(&self) -> &str {
        std::str::from_utf8(&self.launch_mode)
            .unwrap_or("")
            .trim_end_matches('\0')
    }

    pub fn product_key_str(&self) -> &str {
        std::str::from_utf8(&self.product_key)
            .unwrap_or("")
            .trim_end_matches('\0')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_context() {
        let mut ctx = HostSharedContext::new();
        ctx.set_launch_mode("server");
        ctx.set_product_key("freemode");
        ctx.game_build = 3717;
        ctx.game_pid = 1234;
        ctx.is_main_process = true;

        assert_eq!(ctx.launch_mode_str(), "server");
        assert_eq!(ctx.product_key_str(), "freemode");
        assert_eq!(ctx.game_build, 3717);
        assert_eq!(ctx.game_pid, 1234);
        assert!(ctx.is_main_process);
    }
}

#[cfg(not(target_os = "windows"))]
pub struct SharedMemory<T> {
    _marker: std::marker::PhantomData<T>,
}

#[cfg(not(target_os = "windows"))]
impl<T> SharedMemory<T> {
    pub fn open(_name: &str) -> Option<Self> { None }
    pub fn open_with_flags(_name: &str, _init_if_new: bool) -> Option<Self> { None }
    pub fn data_mut(&mut self) -> &mut T { panic!("shared_memory not available on this platform") }
    pub fn data(&self) -> &T { panic!("shared_memory not available on this platform") }
    pub fn as_ptr(&self) -> *mut T { std::ptr::null_mut() }
}