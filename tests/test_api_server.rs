use rustrict::server::{create_app, AppState, EventBus};
use rustrict::types::{Host, MacAddress};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::TcpListener;

fn sample_host() -> Host {
    Host::new(
        1,
        Ipv4Addr::new(192, 168, 1, 50),
        MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        "TestHost".into(),
        "TestVendor".into(),
    )
}

#[tokio::test]
async fn test_rest_status_endpoint_public() {
    let bus = EventBus::new(10);
    let hosts = Arc::new(parking_lot::RwLock::new(vec![sample_host()]));
    let state = Arc::new(AppState {
        event_bus: bus,
        hosts,
        auth_token: Some("secret123".into()),
    });

    let app = create_app(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let url = format!("http://{}/api/status", addr);
    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_rest_hosts_endpoint_requires_auth() {
    let bus = EventBus::new(10);
    let hosts = Arc::new(parking_lot::RwLock::new(vec![sample_host()]));
    let state = Arc::new(AppState {
        event_bus: bus,
        hosts,
        auth_token: Some("secret123".into()),
    });

    let app = create_app(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let url = format!("http://{}/api/hosts", addr);
    let client = reqwest::Client::new();

    // 1. Missing auth header -> 401 Unauthorized
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 401);

    // 2. Correct bearer token -> 200 OK
    let resp = client.get(&url).bearer_auth("secret123").send().await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_agent_telemetry_post_endpoint() {
    let bus = EventBus::new(10);
    let mut rx = bus.subscribe();
    let hosts = Arc::new(parking_lot::RwLock::new(vec![]));
    let state = Arc::new(AppState {
        event_bus: bus,
        hosts,
        auth_token: None,
    });

    let app = create_app(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let url = format!("http://{}/api/agent/telemetry", addr);
    let client = reqwest::Client::new();

    let telemetry_payload = serde_json::json!({
        "device_id": "agent-test-1",
        "hostname": "workstation-node",
        "os_version": "windows",
        "cpu_usage_pct": 15.2,
        "memory_used_bytes": 4294967296u64,
        "memory_total_bytes": 17179869184u64,
        "uptime_secs": 1800
    });

    let resp = client.post(&url).json(&telemetry_payload).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Verify event bus received AgentHeartbeat
    let event = rx.recv().await.unwrap();
    match event {
        rustrict::server::EngineEvent::AgentHeartbeat(val) => {
            assert_eq!(val["device_id"], "agent-test-1");
        }
        other => panic!("Expected AgentHeartbeat event, got {:?}", other),
    }
}

