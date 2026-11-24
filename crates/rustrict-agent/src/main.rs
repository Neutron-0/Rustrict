use rustrict_agent::telemetry::{AgentConfig, TelemetryCollector};

#[tokio::main]
async fn main() {
    println!("[rustrict-agent] Starting authorized endpoint telemetry daemon...");

    let config = AgentConfig {
        controller_url: std::env::var("RUSTRICT_CONTROLLER_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080/api/agent/telemetry".into()),
        enrollment_token: std::env::var("RUSTRICT_ENROLLMENT_TOKEN")
            .unwrap_or_else(|_| "default-dev-token".into()),
        heartbeat_interval_secs: 15,
    };

    let collector = TelemetryCollector::new(config);
    let metrics = collector.collect_metrics();

    match collector.format_heartbeat_payload(&metrics) {
        Ok(json) => println!("[rustrict-agent] Initial telemetry snapshot:\n{}", json),
        Err(e) => eprintln!("[rustrict-agent] Failed to serialize telemetry: {}", e),
    }

    println!("[rustrict-agent] Agent active and monitoring.");
}
