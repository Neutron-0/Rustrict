#[cfg(not(windows))]
compile_error!("Rustrict is built specifically for Windows (Windows 10/11 x64).");

pub mod windows;
pub use windows::*;
