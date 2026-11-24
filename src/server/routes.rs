use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde::Serialize;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use crate::server::event_bus::EventBus;
use crate::server::ws::ws_handler;
use crate::types::Host;

#[derive(Clone)]
pub struct AppState {
    pub event_bus: EventBus,
    pub hosts: Arc<parking_lot::RwLock<Vec<Host>>>,
    pub auth_token: Option<String>,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub host_count: usize,
    pub event_subscribers: usize,
}

pub async fn get_status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let hosts = state.hosts.read();
    Json(StatusResponse {
        status: "online",
        version: env!("CARGO_PKG_VERSION"),
        host_count: hosts.len(),
        event_subscribers: state.event_bus.subscriber_count(),
    })
}

pub async fn get_hosts(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<Host>>, StatusCode> {
    if let Some(ref expected) = state.auth_token {
        let auth = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok());
        match auth {
            Some(h) if h.starts_with("Bearer ") && &h[7..].trim() == expected => (),
            _ => return Err(StatusCode::UNAUTHORIZED),
        }
    }
    let list = state.hosts.read().clone();
    Ok(Json(list))
}

pub fn create_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/status", get(get_status))
        .route("/api/hosts", get(get_hosts))
        .route("/api/ws", get(ws_handler))
        .layer(CorsLayer::permissive())
        .with_state(state)
}
