use rustrict_agent::telemetry::{AgentConfig, AgentTelemetry, TelemetryCollector};

#[test]
fn test_agent_telemetry_collection_and_heartbeat() {
    let config = AgentConfig {
        controller_url: "https://192.168.1.1:8443/api/agent/heartbeat".into(),
        enrollment_token: "test-enrollment-token-xyz".into(),
        heartbeat_interval_secs: 15,
    };

    let collector = TelemetryCollector::new(config);
    let telemetry = collector.collect_metrics();

    assert!(!telemetry.device_id.is_empty());
    assert!(!telemetry.hostname.is_empty());
    assert!(telemetry.memory_total_bytes > 0);

    // Format heartbeat payload for controller submission
    let payload_json = collector.format_heartbeat_payload(&telemetry).expect("Serialization failed");
    assert!(payload_json.contains("device_id"));
    assert!(payload_json.contains("hostname"));
    assert!(payload_json.contains("memory_total_bytes"));

    // Verify deserialization matches
    let parsed: AgentTelemetry = serde_json::from_str(&payload_json).expect("Deserialization failed");
    assert_eq!(parsed.device_id, telemetry.device_id);
    assert_eq!(parsed.hostname, telemetry.hostname);
}
