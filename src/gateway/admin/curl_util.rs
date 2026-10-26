//! Safe native curl execution and temporary payload helpers for Windows.
//!
//! Provides secure execution of native `curl.exe` without leaking credentials
//! on the command line or keeping persistent temporary files on disk.

use crate::gateway::admin::plan::AdminError;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Locate native `curl.exe` safely on Windows, checking System32 before PATH.
pub fn find_curl() -> Result<PathBuf, AdminError> {
    #[cfg(windows)]
    {
        if let Ok(sysroot) = std::env::var("SystemRoot") {
            let candidate = PathBuf::from(sysroot).join(r"System32\curl.exe");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
        let default_sys32 = PathBuf::from(r"C:\Windows\System32\curl.exe");
        if default_sys32.exists() {
            return Ok(default_sys32);
        }
    }

    if let Ok(path_var) = std::env::var("PATH") {
        let separator = if cfg!(windows) { ';' } else { ':' };
        for dir in path_var.split(separator) {
            let p = Path::new(dir.trim());
            #[cfg(windows)]
            let candidate = p.join("curl.exe");
            #[cfg(not(windows))]
            let candidate = p.join("curl");

            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    Err(AdminError::CommunicationError(
        "Native HTTPS client (curl) not found. Ensure Windows curl is available in System32 / PATH.".into(),
    ))
}

/// RAII guard for temporary request payload files.
/// Guarantees immediate cleanup upon Drop regardless of success, failure, or timeout.
pub struct AutoCleanFile {
    path: PathBuf,
}

impl AutoCleanFile {
    /// Creates a temporary file in `%TEMP%` with a collision-resistant name and writes content.
    pub fn create(prefix: &str, suffix: &str, content: &[u8]) -> Result<Self, AdminError> {
        let temp_dir = std::env::temp_dir();
        let pid = std::process::id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let count = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let filename = format!("{}_{}_{}_{}{}", prefix, pid, timestamp, count, suffix);
        let path = temp_dir.join(filename);

        let mut file = File::create(&path).map_err(|e| {
            AdminError::CommunicationError(format!(
                "Failed to create secure temporary payload file: {}",
                e
            ))
        })?;
        file.write_all(content).map_err(|e| {
            AdminError::CommunicationError(format!(
                "Failed to write payload to temporary file: {}",
                e
            ))
        })?;
        file.flush().map_err(|e| {
            AdminError::CommunicationError(format!("Failed to flush temporary payload file: {}", e))
        })?;

        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for AutoCleanFile {
    fn drop(&mut self) {
        // Securely zero file contents on disk before unlinking
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&self.path) {
            if let Ok(meta) = f.metadata() {
                let len = meta.len() as usize;
                if len > 0 {
                    let zeroes = vec![0u8; len.min(65536)];
                    let mut remaining = len;
                    while remaining > 0 {
                        let to_write = remaining.min(zeroes.len());
                        if f.write_all(&zeroes[..to_write]).is_err() {
                            break;
                        }
                        remaining -= to_write;
                    }
                    let _ = f.flush();
                }
            }
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_curl_resolves_existing_executable() {
        let curl = find_curl();
        assert!(
            curl.is_ok(),
            "find_curl must succeed on Windows: {:?}",
            curl.err()
        );
        let path = curl.unwrap();
        assert!(path.exists(), "Resolved curl path must exist: {:?}", path);
    }

    #[test]
    fn test_auto_clean_file_lifecycle() {
        let payload = b"<test>payload</test>";
        let file_path;
        {
            let guard = AutoCleanFile::create("test_rustrict_guard", ".tmp", payload)
                .expect("Failed to create AutoCleanFile");
            file_path = guard.path().to_path_buf();
            assert!(
                file_path.exists(),
                "Temporary file must exist during guard lifetime"
            );
            let read_back = std::fs::read(&file_path).expect("Failed to read temp file");
            assert_eq!(read_back, payload);
        }
        assert!(
            !file_path.exists(),
            "Temporary file must be deleted upon Drop"
        );
    }
}
