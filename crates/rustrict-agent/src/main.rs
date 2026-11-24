use std::time::Duration;
use rustrict_agent::telemetry::{AgentConfig, TelemetryCollector};

#[tokio::main]
async fn main() {
    println!("[rustrict-agent] Starting authorized endpoint telemetry daemon...");

    let controller_url = std::env::var("RUSTRICT_CONTROLLER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3000/api/agent/telemetry".into());
    let enrollment_token = std::env::var("RUSTRICT_ENROLLMENT_TOKEN")
        .unwrap_or_else(|_| "default-dev-token".into());
    let interval_secs: u64 = std::env::var("RUSTRICT_HEARTBEAT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);

    let config = AgentConfig {
        controller_url: controller_url.clone(),
        enrollment_token,
        heartbeat_interval_secs: interval_secs,
    };

    let collector = TelemetryCollector::new(config);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    println!("[rustrict-agent] Connected to controller: {}", controller_url);
    println!("[rustrict-agent] Continuous heartbeat interval: {}s", interval_secs);

    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        match collector.send_heartbeat(&client).await {
            Ok(_) => println!("[rustrict-agent] Heartbeat successfully delivered to controller."),
            Err(e) => eprintln!("[rustrict-agent] Heartbeat dispatch warning: {}", e),
        }
    }
}
