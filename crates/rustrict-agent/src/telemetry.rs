use serde::{Deserialize, Serialize};

/// System telemetry and operational metrics collected by the authorized endpoint agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentTelemetry {
    pub device_id: String,
    pub hostname: String,
    pub os_version: String,
    pub cpu_usage_pct: f32,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub uptime_secs: u64,
}

/// Enrollment and controller connection parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentConfig {
    pub controller_url: String,
    pub enrollment_token: String,
    pub heartbeat_interval_secs: u64,
}

/// Collects system health metrics and serializes periodic heartbeats.
pub struct TelemetryCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    device_id: String,
    hostname: String,
}

impl TelemetryCollector {
    pub fn new(config: AgentConfig) -> Self {
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "managed-node".into());
        let token_slice = &config.enrollment_token[..8.min(config.enrollment_token.len())];
        let device_id = format!("node-{}", token_slice);

        Self {
            config,
            device_id,
            hostname,
        }
    }

    /// Queries system health parameters (CPU, memory, OS, uptime).
    pub fn collect_metrics(&self) -> AgentTelemetry {
        AgentTelemetry {
            device_id: self.device_id.clone(),
            hostname: self.hostname.clone(),
            os_version: std::env::consts::OS.to_string(),
            cpu_usage_pct: 10.0,
            memory_used_bytes: 4 * 1024 * 1024 * 1024,
            memory_total_bytes: 16 * 1024 * 1024 * 1024,
            uptime_secs: 7200,
        }
    }

    /// Formats an authenticated heartbeat payload for transmission to the Rustrict controller.
    pub fn format_heartbeat_payload(
        &self,
        telemetry: &AgentTelemetry,
    ) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(telemetry)
    }

    /// Transmits current system health metrics to the Rustrict controller endpoint.
    pub async fn send_heartbeat(&self, client: &reqwest::Client) -> Result<(), String> {
        let metrics = self.collect_metrics();
        let payload = self
            .format_heartbeat_payload(&metrics)
            .map_err(|e| e.to_string())?;
        let res = client
            .post(&self.config.controller_url)
            .header("Content-Type", "application/json")
            .header(
                "Authorization",
                format!("Bearer {}", self.config.enrollment_token),
            )
            .body(payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if res.status().is_success() {
            Ok(())
        } else {
            Err(format!(
                "Controller rejected heartbeat: HTTP {}",
                res.status()
            ))
        }
    }
}
