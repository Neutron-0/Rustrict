use std::net::SocketAddr;
use std::sync::Arc;
use parking_lot::RwLock;

/// Configuration for the resilient overlay tunnel.
#[derive(Debug, Clone)]
pub struct ResilientTunnelConfig {
    pub endpoint: SocketAddr,
    pub psk: [u8; 32],
    pub keepalive_secs: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TunnelError {
    InvalidLength,
    InvalidMagic,
    AuthenticationFailed,
}

const HANDSHAKE_MAGIC: &[u8; 8] = b"RSTUN_HS";
const HEARTBEAT_MAGIC: &[u8; 8] = b"RSTUN_HB";

/// Computes a deterministic 32-byte keyed authentication tag across magic, payload, and PSK.
fn compute_tag(magic: &[u8; 8], value: u64, psk: &[u8; 32]) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    let mut tag = [0u8; 32];
    for chunk_idx in 0..4 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        magic.hash(&mut hasher);
        value.hash(&mut hasher);
        psk.hash(&mut hasher);
        (chunk_idx as u64).hash(&mut hasher);
        let digest = hasher.finish();
        tag[chunk_idx * 8..(chunk_idx + 1) * 8].copy_from_slice(&digest.to_be_bytes());
    }
    tag
}

/// Constant-time tag comparison to prevent timing side channels.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (byte_a, byte_b) in a.iter().zip(b.iter()) {
        diff |= byte_a ^ byte_b;
    }
    diff == 0
}

/// Resilient tunnel connection state manager with dynamic roaming support.
pub struct ResilientTunnel {
    config: Arc<RwLock<ResilientTunnelConfig>>,
}

impl ResilientTunnel {
    pub fn new(config: ResilientTunnelConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Crafts an authenticated handshake frame containing the given nonce.
    pub fn craft_handshake(&self, nonce: u64) -> Vec<u8> {
        let psk = self.config.read().psk;
        let mut packet = Vec::with_capacity(48);
        packet.extend_from_slice(HANDSHAKE_MAGIC);
        packet.extend_from_slice(&nonce.to_be_bytes());
        let tag = compute_tag(HANDSHAKE_MAGIC, nonce, &psk);
        packet.extend_from_slice(&tag);
        packet
    }

    /// Verifies an incoming handshake packet against the PSK and extracts the nonce.
    pub fn verify_handshake(packet: &[u8], psk: &[u8; 32]) -> Result<u64, TunnelError> {
        if packet.len() < 48 {
            return Err(TunnelError::InvalidLength);
        }
        if &packet[..8] != HANDSHAKE_MAGIC {
            return Err(TunnelError::InvalidMagic);
        }
        let nonce_bytes: [u8; 8] = packet[8..16].try_into().map_err(|_| TunnelError::InvalidLength)?;
        let nonce = u64::from_be_bytes(nonce_bytes);

        let mut expected_tag = [0u8; 32];
        expected_tag.copy_from_slice(&packet[16..48]);

        let calculated_tag = compute_tag(HANDSHAKE_MAGIC, nonce, psk);
        if !constant_time_eq(&calculated_tag, &expected_tag) {
            return Err(TunnelError::AuthenticationFailed);
        }

        Ok(nonce)
    }

    /// Crafts an authenticated keepalive heartbeat frame with the given sequence number.
    pub fn craft_heartbeat(&self, seq: u64) -> Vec<u8> {
        let psk = self.config.read().psk;
        let mut packet = Vec::with_capacity(48);
        packet.extend_from_slice(HEARTBEAT_MAGIC);
        packet.extend_from_slice(&seq.to_be_bytes());
        let tag = compute_tag(HEARTBEAT_MAGIC, seq, &psk);
        packet.extend_from_slice(&tag);
        packet
    }

    /// Verifies an incoming heartbeat packet against the PSK and extracts the sequence number.
    pub fn verify_heartbeat(packet: &[u8], psk: &[u8; 32]) -> Result<u64, TunnelError> {
        if packet.len() < 48 {
            return Err(TunnelError::InvalidLength);
        }
        if &packet[..8] != HEARTBEAT_MAGIC {
            return Err(TunnelError::InvalidMagic);
        }
        let seq_bytes: [u8; 8] = packet[8..16].try_into().map_err(|_| TunnelError::InvalidLength)?;
        let seq = u64::from_be_bytes(seq_bytes);

        let mut expected_tag = [0u8; 32];
        expected_tag.copy_from_slice(&packet[16..48]);

        let calculated_tag = compute_tag(HEARTBEAT_MAGIC, seq, psk);
        if !constant_time_eq(&calculated_tag, &expected_tag) {
            return Err(TunnelError::AuthenticationFailed);
        }

        Ok(seq)
    }

    /// Updates the remote endpoint socket address upon roaming or interface migration.
    pub fn update_roaming_endpoint(&self, new_endpoint: SocketAddr) {
        self.config.write().endpoint = new_endpoint;
    }

    /// Returns the active remote endpoint.
    pub fn current_endpoint(&self) -> SocketAddr {
        self.config.read().endpoint
    }
}
