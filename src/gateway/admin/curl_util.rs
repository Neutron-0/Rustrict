//! Safe native curl execution and temporary payload helpers for Windows.
//!
//! Provides execution of native `curl.exe` without leaking credentials
//! on the command line, using protected stdin pipes for authentication configuration
//! and isolated temporary files with best-effort sanitization and immediate RAII cleanup on drop.

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
        // Best-effort in-place overwrite before removal to reduce plaintext remnants
        // in unallocated filesystem sectors. Note: this does NOT guarantee cryptographic
        // erasure on wear-leveling SSDs, copy-on-write filesystems, or storage snapshots.
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

/// Maximum permitted stdout/stderr retained buffer size for router administrative subprocesses (2 MiB).
pub const MAX_SUBPROCESS_OUTPUT_BYTES: usize = 2 * 1024 * 1024;

/// Drains an arbitrary Read stream into a bounded buffer, continuing to drain into a discard buffer upon reaching max_bytes.
pub fn read_bounded_pipe<R: std::io::Read>(mut reader: R, max_bytes: usize) -> (Vec<u8>, bool) {
    let mut retained = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut truncated = false;

    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if retained.len() < max_bytes {
                    let to_take = n.min(max_bytes - retained.len());
                    retained.extend_from_slice(&chunk[..to_take]);
                    if to_take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }

    (retained, truncated)
}

/// Bounded output from a child process execution.
#[derive(Debug, Clone)]
pub struct BoundedChildOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub exit_code: i32,
}

/// Waits for a child process to terminate within a timeout, draining stdout and stderr through background
/// reader threads with bounded memory buffers.
pub fn wait_child_bounded(
    mut child: std::process::Child,
    max_output_bytes: usize,
    timeout: std::time::Duration,
    operation_desc: &str,
) -> Result<BoundedChildOutput, AdminError> {
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let stdout_handle = std::thread::spawn(move || {
        if let Some(pipe) = stdout_pipe {
            read_bounded_pipe(pipe, max_output_bytes)
        } else {
            (Vec::new(), false)
        }
    });

    let stderr_handle = std::thread::spawn(move || {
        if let Some(pipe) = stderr_pipe {
            read_bounded_pipe(pipe, max_output_bytes)
        } else {
            (Vec::new(), false)
        }
    });

    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_handle.join();
                    let _ = stderr_handle.join();
                    return Err(AdminError::Timeout(format!(
                        "Operation '{}' timed out after {:.1}s",
                        operation_desc,
                        timeout.as_secs_f64()
                    )));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(AdminError::CommunicationError(format!(
                    "Error monitoring process for '{}': {}",
                    operation_desc, e
                )));
            }
        }
    };

    let (stdout, stdout_truncated) = stdout_handle.join().unwrap_or_default();
    let (stderr, stderr_truncated) = stderr_handle.join().unwrap_or_default();
    let exit_code = status.code().unwrap_or(-1);

    Ok(BoundedChildOutput {
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        exit_code,
    })
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

    #[test]
    fn test_read_bounded_pipe_within_limit() {
        let data = b"Hello, router administrative interface!";
        let cursor = std::io::Cursor::new(data);
        let (retained, truncated) = read_bounded_pipe(cursor, 1024);
        assert_eq!(retained, data);
        assert!(!truncated);
    }

    #[test]
    fn test_read_bounded_pipe_exceeding_limit() {
        let data = vec![b'X'; 50 * 1024]; // 50 KiB
        let cursor = std::io::Cursor::new(&data);
        let (retained, truncated) = read_bounded_pipe(cursor, 10 * 1024); // 10 KiB cap
        assert_eq!(retained.len(), 10 * 1024);
        assert!(truncated);
    }
}
