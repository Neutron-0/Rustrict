use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::types::{Direction, Host};

const STATE_FILE: &str = "rustrict_state.json";

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
}

impl PersistentState {
    pub fn load() -> Self {
        if Path::new(STATE_FILE).exists() {
            if let Ok(content) = fs::read_to_string(STATE_FILE) {
                if let Ok(state) = serde_json::from_str::<PersistentState>(&content) {
                    return state;
                }
            }
        }
        PersistentState::default()
    }

    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialization error: {}", e))?;
        fs::write(STATE_FILE, json)
            .map_err(|e| format!("Failed to write {}: {}", STATE_FILE, e))?;
        Ok(())
    }

    pub fn add_blocked(&mut self, host: &Host, dir: Direction) {
        self.blocked_hosts.retain(|b| b.ip != host.ip);
        self.blocked_hosts.push(PersistentBlockedHost {
            ip: host.ip,
            mac: host.mac.to_string(),
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
            if h.direction.contains("upload") {
                Direction::Outgoing
            } else if h.direction.contains("download") {
                Direction::Incoming
            } else {
                Direction::Both
            }
        } else {
            Direction::Both
        }
    }
}
