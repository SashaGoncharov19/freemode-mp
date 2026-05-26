#![cfg(windows)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use windows::Win32::Foundation::{BOOL, HINSTANCE};
use windows::Win32::System::Console::AllocConsole;
use windows::Win32::System::LibraryLoader::DisableThreadLibraryCalls;

// The DLL entry point
#[unsafe(no_mangle)]
#[allow(non_snake_case, unused_variables)]
pub extern "system" fn DllMain(
    dll_module: HINSTANCE,
    call_reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> BOOL {
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;

    match call_reason {
        DLL_PROCESS_ATTACH => {
            unsafe {
                DisableThreadLibraryCalls(dll_module).ok();
            }
            // Spawn a new thread so we don't block DllMain
            thread::spawn(move || {
                main_thread();
            });
        }
        DLL_PROCESS_DETACH => {
            // Cleanup
        }
        _ => {}
    }

    BOOL(1)
}

fn main_thread() {
    // Allocate a console window for the game process
    unsafe {
        AllocConsole().ok();
    }

    println!("========================================");
    println!("     FreeMode - Client Injected!        ");
    println!("========================================");
    println!("Connecting to server at 127.0.0.1:8080...");

    match TcpStream::connect("127.0.0.1:8080") {
        Ok(mut stream) => {
            println!("Successfully connected to server!");
            
            let msg = b"Hello from GTA V injected Rust payload!\n";
            if let Err(e) = stream.write_all(msg) {
                println!("Failed to send data: {}", e);
            }

            let mut buffer = [0; 512];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => {
                        println!("Connection closed by server.");
                        break;
                    }
                    Ok(n) => {
                        let text = String::from_utf8_lossy(&buffer[..n]);
                        println!("Received from server: {}", text);
                    }
                    Err(e) => {
                        println!("Error reading from connection: {}", e);
                        break;
                    }
                }
            }
        }
        Err(e) => {
            println!("Failed to connect to server: {}", e);
            println!("Make sure your server is running on 127.0.0.1:8080");
        }
    }

    // Keep the console open so the user can read the output
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
