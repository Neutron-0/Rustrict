use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

/// Represents an immutable configuration snapshot captured from a router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterConfigSnapshot {
    pub id: String,
    pub timestamp_unix: u64,
    pub provider_name: String,
    pub raw_content: String,
    pub sha256: String,
}

/// Represents the line-by-line diff between two configuration snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigDiff {
    pub added_lines: Vec<String>,
    pub removed_lines: Vec<String>,
    pub identical: bool,
}

/// Engine for snapshotting router configurations, computing line diffs, and tracking changes.
pub struct ConfigBackupEngine;

impl ConfigBackupEngine {
    /// Hashes the raw content to produce a deterministic fingerprint.
    pub fn compute_fingerprint(data: &str) -> String {
        use std::hash::{Hash, Hasher};
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        data.hash(&mut h1);
        (data.len() as u64).hash(&mut h2);
        format!("{:016x}{:016x}", h1.finish(), h2.finish())
    }

    /// Captures a new configuration snapshot from raw configuration text.
    pub fn create_snapshot(raw_content: &str, provider_name: &str) -> RouterConfigSnapshot {
        let timestamp_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let sha256 = Self::compute_fingerprint(raw_content);
        let id = format!("{}-{}", provider_name.to_lowercase(), sha256);

        RouterConfigSnapshot {
            id,
            timestamp_unix,
            provider_name: provider_name.to_string(),
            raw_content: raw_content.to_string(),
            sha256,
        }
    }

    /// Computes the delta between two configuration snapshots.
    pub fn compute_diff(a: &RouterConfigSnapshot, b: &RouterConfigSnapshot) -> ConfigDiff {
        if a.raw_content == b.raw_content {
            return ConfigDiff {
                added_lines: Vec::new(),
                removed_lines: Vec::new(),
                identical: true,
            };
        }

        let a_lines: Vec<&str> = a.raw_content.lines().collect();
        let b_lines: Vec<&str> = b.raw_content.lines().collect();

        let b_set: HashSet<&str> = b_lines.iter().copied().collect();
        let a_set: HashSet<&str> = a_lines.iter().copied().collect();

        let removed_lines: Vec<String> = a_lines
            .into_iter()
            .filter(|line| !b_set.contains(line))
            .map(|s| s.to_string())
            .collect();

        let added_lines: Vec<String> = b_lines
            .into_iter()
            .filter(|line| !a_set.contains(line))
            .map(|s| s.to_string())
            .collect();

        ConfigDiff {
            identical: removed_lines.is_empty() && added_lines.is_empty(),
            added_lines,
            removed_lines,
        }
    }
}
