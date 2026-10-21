use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use crate::core::scope::ScopeManager;
use crate::types::{Direction, Host, MacAddress};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentBlockedHost {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub name: String,
    pub direction: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistentState {
    pub blocked_hosts: Vec<PersistentBlockedHost>,
    pub scope: Option<ScopeManager>,
}

impl PersistentState {
    fn state_file_path() -> PathBuf {
        crate::platform::get_state_file_path()
    }

    pub fn load() -> Self {
        let path = Self::state_file_path();
        // Check primary location, then fallback to relative current directory if present
        let target_path = if path.exists() {
            path
        } else if std::path::Path::new("rustrict_state.json").exists() {
            PathBuf::from("rustrict_state.json")
        } else {
            path
        };

        if target_path.exists() {
            if let Ok(content) = fs::read_to_string(&target_path) {
                if let Ok(state) = serde_json::from_str::<PersistentState>(&content) {
                    return state;
                }
            }
        }
        PersistentState::default()
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::state_file_path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialization error: {}", e))?;
        fs::write(&path, json)
            .map_err(|e| format!("Failed to write state file {}: {}", path.display(), e))?;
        Ok(())
    }

    pub fn add_blocked(&mut self, host: &Host, dir: Direction) {
        let mac_str = host.mac.to_string();
        self.blocked_hosts.retain(|b| b.ip != host.ip && (host.mac == MacAddress::ZERO || b.mac != mac_str));
        self.blocked_hosts.push(PersistentBlockedHost {
            ip: host.ip,
            mac: mac_str,
            name: host.name.clone(),
            direction: dir.pretty().to_string(),
        });
        let _ = self.save();
    }

    pub fn remove_blocked(&mut self, ip: &Ipv4Addr) {
        self.blocked_hosts.retain(|b| b.ip != *ip);
        let _ = self.save();
    }

    pub fn is_blocked(&self, ip: &Ipv4Addr) -> bool {
        self.blocked_hosts.iter().any(|b| b.ip == *ip)
    }

    pub fn get_direction(&self, ip: &Ipv4Addr) -> Direction {
        if let Some(h) = self.blocked_hosts.iter().find(|b| b.ip == *ip) {
            let dir_lower = h.direction.to_ascii_lowercase();
            if (dir_lower.contains("upload") && dir_lower.contains("download")) || dir_lower.contains("both") {
                Direction::Both
            } else if dir_lower.contains("upload") {
                Direction::Outgoing
            } else if dir_lower.contains("download") {
                Direction::Incoming
            } else {
                Direction::Both
            }
        } else {
            Direction::Both
        }
    }
}
