pub mod router_emulator;

use std::fs;
use std::path::{Path, PathBuf};

#[allow(unused_imports)]
pub use router_emulator::{FailMode, RecordedRequest, RouterEmulator, SimulatedRouterState};

#[allow(dead_code)]
pub struct TestTempDir {
    path: PathBuf,
}

#[allow(dead_code)]
impl TestTempDir {
    pub fn new(prefix: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("rustrict_test_{}_{}_{}", prefix, pid, now));
        let _ = fs::create_dir_all(&path);
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
