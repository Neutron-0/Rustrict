use rustrict::server::event_bus::{EngineEvent, EventBus};
use rustrict::types::{Host, MacAddress};
use std::net::Ipv4Addr;

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
async fn test_event_bus_broadcast() {
    let bus = EventBus::new(100);
    let mut rx = bus.subscribe();
    bus.publish(EngineEvent::HostDiscovered(sample_host())).unwrap();
    let received = rx.recv().await.unwrap();
    assert!(matches!(received, EngineEvent::HostDiscovered(_)));
}

#[tokio::test]
async fn test_event_bus_multiple_subscribers() {
    let bus = EventBus::new(50);
    let mut rx1 = bus.subscribe();
    let mut rx2 = bus.subscribe();
    bus.publish(EngineEvent::SystemNotice("Server started".into())).unwrap();
    let msg1 = rx1.recv().await.unwrap();
    let msg2 = rx2.recv().await.unwrap();
    assert!(matches!(msg1, EngineEvent::SystemNotice(_)));
    assert!(matches!(msg2, EngineEvent::SystemNotice(_)));
}
