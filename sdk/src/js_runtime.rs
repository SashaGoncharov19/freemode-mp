// JS runtime integration — stub for MVP.
// Full Bun.js FFI will be implemented once Windows builds are verified.

#[cfg(target_os = "windows")]
pub use bun_impl::BunRuntime;

#[cfg(target_os = "windows")]
mod bun_impl {
    pub struct BunRuntime;

    impl BunRuntime {
        pub fn new() -> Option<Self> {
            Some(BunRuntime)
        }

        pub fn initialize(&mut self) -> Result<(), String> {
            Err("Bun.js FTI not yet implemented".to_string())
        }

        #[allow(dead_code)]
        pub fn execute<T: std::fmt::Display>(&self, _code: &str) -> Result<T, String> {
            Err("Bun.js FFI not yet implemented".to_string())
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub struct BunRuntime;

#[cfg(not(target_os = "windows"))]
impl BunRuntime {
    #[allow(dead_code)]
    pub fn new() -> Option<Self> { Some(BunRuntime) }
    #[allow(dead_code)]
    pub fn initialize(&mut self) -> Result<(), String> {
        Err("Bun.js not available on this platform".to_string())
    }
    #[allow(dead_code)]
    pub fn execute<T: std::fmt::Display>(&self, _code: &str) -> Result<T, String> {
        Err("Bun.js not available on this platform".to_string())
    }
}
