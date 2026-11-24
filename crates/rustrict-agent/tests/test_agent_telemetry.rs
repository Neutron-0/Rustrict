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

#[tokio::test]
async fn test_agent_send_heartbeat() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });

    let config = AgentConfig {
        controller_url: format!("http://{}/api/agent/telemetry", addr),
        enrollment_token: "test-token".into(),
        heartbeat_interval_secs: 15,
    };
    let collector = TelemetryCollector::new(config);
    let client = reqwest::Client::new();
    let res = collector.send_heartbeat(&client).await;
    assert!(res.is_ok(), "Heartbeat failed: {:?}", res);
}

