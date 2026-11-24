use crate::types::Host;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Engine events emitted across Rustrict for real-time streaming and telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum EngineEvent {
    HostDiscovered(Host),
    HostUpdated(Host),
    HostRemoved(std::net::Ipv4Addr),
    SystemNotice(String),
    SystemAlert {
        severity: String,
        title: String,
        details: String,
    },
    BandwidthSample {
        bytes_rx_sec: u64,
        bytes_tx_sec: u64,
    },
    AgentHeartbeat(serde_json::Value),
}

#[derive(Clone)]
pub struct EventBus {
    sender: Arc<broadcast::Sender<EngineEvent>>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(16));
        Self {
            sender: Arc::new(sender),
        }
    }

    pub fn publish(&self, event: EngineEvent) -> Result<usize, broadcast::error::SendError<EngineEvent>> {
        self.sender.send(event)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent> {
        self.sender.subscribe()
    }

    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}
