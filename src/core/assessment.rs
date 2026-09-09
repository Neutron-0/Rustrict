use std::net::Ipv4Addr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub port: u16,
    pub transport: String, // "tcp" or "udp"
    pub service_name: String,
    pub banner: Option<String>,
    pub status: PortStatus,
}

impl ServiceEntry {
    pub fn new(port: u16, transport: &str, service_name: &str, banner: Option<String>) -> Self {
        Self {
            port,
            transport: transport.to_string(),
            service_name: service_name.to_string(),
            banner,
            status: PortStatus::Open,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl AuditSeverity {
    pub fn badge(&self) -> &'static str {
        match self {
            AuditSeverity::Info => "[INFO]",
            AuditSeverity::Low => "[LOW]",
            AuditSeverity::Medium => "[MED]",
            AuditSeverity::High => "[HIGH]",
            AuditSeverity::Critical => "[CRIT]",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub rule_id: String,
    pub title: String,
    pub target_ip: Ipv4Addr,
    pub port: Option<u16>,
    pub severity: AuditSeverity,
    pub description: String,
    pub remediation: String,
}

impl AuditFinding {
    pub fn new(
        rule_id: &str,
        title: &str,
        target_ip: Ipv4Addr,
        port: Option<u16>,
        severity: AuditSeverity,
        description: &str,
        remediation: &str,
    ) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            title: title.to_string(),
            target_ip,
            port,
            severity,
            description: description.to_string(),
            remediation: remediation.to_string(),
        }
    }
}
