use parking_lot::RwLock;
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::gateway::admin::capabilities::{CapabilityClassification, RouterCapabilityMatrix};
use crate::gateway::admin::credentials::RouterCredentials;
use crate::gateway::admin::openwrt::parse_policy_timestamps;
use crate::gateway::admin::plan::{
    ActivePolicyStatus, AdminError, OperationPlan, OperationPlanRequest, PolicyDuration,
    PolicyPersistence, PolicyScope, RouterIdentity,
};
use crate::gateway::admin::provider::RouterAdminProvider;

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 encoder with zero third-party dependencies.
pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(BASE64_CHARS[((n >> 18) & 63) as usize] as char);
        out.push(BASE64_CHARS[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(BASE64_CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(BASE64_CHARS[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Pluggable transport abstraction for MikroTik RouterOS REST API operations.
pub trait MikroTikTransport: Send + Sync {
    fn request(
        &self,
        endpoint: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
        credentials: Option<&RouterCredentials>,
    ) -> Result<Value, AdminError>;

    fn transport_name(&self) -> &'static str {
        "HTTPS/REST"
    }
}

/// Production HTTPS transport for MikroTik REST API using Windows native curl/schannel.
/// Enforces strict TLS certificate validation by default without exposing credentials on CLI.
pub struct HttpsMikroTikTransport {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub ca_cert_path: Option<PathBuf>,
}

impl Default for HttpsMikroTikTransport {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            ca_cert_path: None,
        }
    }
}

impl HttpsMikroTikTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_ca_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.ca_cert_path = Some(path.into());
        self
    }
}

impl MikroTikTransport for HttpsMikroTikTransport {
    fn request(
        &self,
        endpoint: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
        credentials: Option<&RouterCredentials>,
    ) -> Result<Value, AdminError> {
        // Strict HTTPS validation: refuse unencrypted HTTP
        let trimmed_endpoint = endpoint.trim();
        if trimmed_endpoint.starts_with("http://") {
            return Err(AdminError::SecurityViolation(
                "Unencrypted HTTP is strictly prohibited for MikroTik router administration. An HTTPS endpoint is required.".into(),
            ));
        }

        let base_url = if trimmed_endpoint.starts_with("https://") {
            trimmed_endpoint.trim_end_matches('/')
        } else {
            return Err(AdminError::CommunicationError(format!(
                "Invalid MikroTik endpoint '{}'. Expected URL starting with 'https://'",
                endpoint
            )));
        };

        let target_url = format!("{}{}", base_url, path);
        let curl_bin = crate::gateway::admin::curl_util::find_curl()?;

        // Build curl command without credentials on command line
        let mut cmd = Command::new(&curl_bin);
        cmd.arg("-s");
        cmd.arg("-S");
        cmd.arg("--retry")
            .arg("2")
            .arg("--retry-delay")
            .arg("0")
            .arg("--retry-connrefused")
            .arg("--retry-all-errors");
        cmd.arg("-X").arg(method);
        cmd.arg("--connect-timeout")
            .arg(self.connect_timeout.as_secs().max(1).to_string());
        cmd.arg("--max-time")
            .arg(self.request_timeout.as_secs().max(1).to_string());

        if let Some(ref ca) = self.ca_cert_path {
            cmd.arg("--cacert").arg(ca);
        }

        // Pass headers and secret authorization via stdin config to prevent process sniffing
        cmd.arg("--config").arg("-");
        cmd.arg(&target_url);

        let mut stdin_config = String::new();
        stdin_config.push_str("header = \"Accept: application/json\"\n");

        if let Some(creds) = credentials {
            let auth_plain = format!("{}:{}", creds.username, creds.password.expose());
            let mut auth_bytes = auth_plain.into_bytes();
            let auth_b64 = base64_encode(&auth_bytes);
            crate::gateway::admin::credentials::zero_slice(&mut auth_bytes);
            stdin_config.push_str(&format!("header = \"Authorization: Basic {}\"\n", auth_b64));
        }

        if let Some(ref b) = body {
            stdin_config.push_str("header = \"Content-Type: application/json\"\n");
            let json_body = serde_json::to_string(b).unwrap_or_else(|_| "{}".to_string());
            // Format body for curl config
            stdin_config.push_str(&format!("data = \"{}\"\n", json_body.replace('"', "\\\"")));
        }

        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            AdminError::CommunicationError(format!("Failed to spawn HTTPS client: {}", e))
        })?;

        let mut stdin_bytes = stdin_config.into_bytes();
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(&stdin_bytes);
        }
        crate::gateway::admin::credentials::zero_slice(&mut stdin_bytes);

        let output = crate::gateway::admin::curl_util::wait_child_bounded(
            child,
            crate::gateway::admin::curl_util::MAX_SUBPROCESS_OUTPUT_BYTES,
            self.request_timeout + std::time::Duration::from_secs(5),
            "MikroTik REST HTTPS",
        )?;

        if output.stdout_truncated {
            return Err(AdminError::CommunicationError(
                "MikroTik REST response exceeded maximum buffer limit (2 MiB); truncated response cannot be parsed".into(),
            ));
        }

        let exit_code = output.exit_code;
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();

        if exit_code != 0 {
            if exit_code == 60 || stderr.contains("certificate") || stderr.contains("SSL") {
                return Err(AdminError::CommunicationError(
                    "TLS certificate validation failed: MikroTik router presented an untrusted, self-signed, or expired certificate. Connection rejected to protect administrative credentials.".into(),
                ));
            }
            if exit_code == 28 || stderr.contains("timed out") {
                return Err(AdminError::Timeout(
                    "Connection or request to MikroTik router timed out.".into(),
                ));
            }
            if exit_code == 7 || stderr.contains("Failed to connect") {
                return Err(AdminError::Timeout(
                    "Failed to connect to MikroTik host (connection refused or endpoint unreachable).".into(),
                ));
            }
            return Err(AdminError::CommunicationError(format!(
                "MikroTik HTTPS request failed (curl exit code {}): {}",
                exit_code,
                stderr.trim()
            )));
        }

        let trimmed_stdout = stdout.trim();
        if trimmed_stdout.is_empty() {
            return Ok(json!({}));
        }

        let parsed: Value = serde_json::from_str(trimmed_stdout).map_err(|e| {
            AdminError::CommunicationError(format!(
                "Failed to parse JSON response from MikroTik REST API: {}. Raw: '{}'",
                e, trimmed_stdout
            ))
        })?;

        // Handle RouterOS error responses: {"error": 401, "message": "Unauthorized"}
        if let Some(err_obj) = parsed.as_object() {
            if let Some(err_code) = err_obj.get("error").and_then(|c| c.as_i64()) {
                let msg = err_obj
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Unknown error");
                if err_code == 401 || err_code == 403 {
                    return Err(AdminError::AuthenticationFailed(format!(
                        "MikroTik REST authentication failed (HTTP {}): {}",
                        err_code, msg
                    )));
                } else if err_code == 404 {
                    return Err(AdminError::PolicyNotFound(format!(
                        "MikroTik REST resource not found (HTTP 404): {}",
                        msg
                    )));
                } else {
                    return Err(AdminError::CommunicationError(format!(
                        "MikroTik REST API error (HTTP {}): {}",
                        err_code, msg
                    )));
                }
            }
        }

        Ok(parsed)
    }
}

/// Offline mock transport for MikroTik RouterOS automated tests.
/// Implements full REST request-response cycles with zero live network calls.
#[derive(Clone)]
pub struct MockMikroTikTransport {
    pub valid_username: String,
    pub valid_password: String,
    pub simulate_auth_fail: Arc<AtomicBool>,
    pub simulate_tls_cert_error: Arc<AtomicBool>,
    pub simulate_timeout: Arc<AtomicBool>,
    pub simulate_non_mikrotik: Arc<AtomicBool>,
    pub simulate_unsupported_resource: Arc<AtomicBool>,
    pub simulate_partial_failure: Arc<AtomicBool>,
    pub autonomous_recovery_supported: Arc<AtomicBool>,
    pub firewall_rules: Arc<RwLock<Vec<Value>>>,
    pub scripts: Arc<RwLock<Vec<Value>>>,
    pub schedulers: Arc<RwLock<Vec<Value>>>,
    pub executed_requests: Arc<RwLock<Vec<String>>>,
}

impl Default for MockMikroTikTransport {
    fn default() -> Self {
        Self {
            valid_username: "admin".into(),
            valid_password: "admin_password".into(),
            simulate_auth_fail: Arc::new(AtomicBool::new(false)),
            simulate_tls_cert_error: Arc::new(AtomicBool::new(false)),
            simulate_timeout: Arc::new(AtomicBool::new(false)),
            simulate_non_mikrotik: Arc::new(AtomicBool::new(false)),
            simulate_unsupported_resource: Arc::new(AtomicBool::new(false)),
            simulate_partial_failure: Arc::new(AtomicBool::new(false)),
            autonomous_recovery_supported: Arc::new(AtomicBool::new(true)),
            firewall_rules: Arc::new(RwLock::new(Vec::new())),
            scripts: Arc::new(RwLock::new(Vec::new())),
            schedulers: Arc::new(RwLock::new(Vec::new())),
            executed_requests: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl MockMikroTikTransport {
    /// Simulates a physical router reboot cycle on the mock state.
    /// Emulates the router-resident scheduler firing on startup and unblocking expired rules.
    pub fn simulate_reboot_cycle(&self, current_unix: u64) {
        let has_script = self
            .scripts
            .read()
            .iter()
            .any(|s| s.get("name").and_then(|n| n.as_str()) == Some("rustrict_watchdog"));
        let has_sched = self
            .schedulers
            .read()
            .iter()
            .any(|s| s.get("name").and_then(|n| n.as_str()) == Some("rustrict_watchdog_sched"));

        if has_script && has_sched {
            let mut rules = self.firewall_rules.write();
            rules.retain(|r| {
                if let Some(comment) = r.get("comment").and_then(|c| c.as_str()) {
                    let (_app, exp) = parse_policy_timestamps(comment);
                    if let Some(e) = exp {
                        return current_unix < e;
                    }
                }
                true
            });
        }
    }
}

impl MikroTikTransport for MockMikroTikTransport {
    fn request(
        &self,
        _endpoint: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
        credentials: Option<&RouterCredentials>,
    ) -> Result<Value, AdminError> {
        let req_record = format!("{} {}", method, path);
        self.executed_requests.write().push(req_record);

        if self.simulate_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout(
                "Mock MikroTik transport timeout".into(),
            ));
        }

        if self.simulate_tls_cert_error.load(Ordering::SeqCst) {
            return Err(AdminError::CommunicationError(
                "TLS certificate validation failed: Router presented an untrusted certificate. Connection rejected to protect administrative credentials.".into(),
            ));
        }

        if self.simulate_auth_fail.load(Ordering::SeqCst) {
            return Err(AdminError::AuthenticationFailed(
                "MikroTik REST authentication failed (HTTP 401): Unauthorized".into(),
            ));
        }

        if let Some(creds) = credentials {
            if creds.username != self.valid_username
                || creds.password.expose() != self.valid_password
            {
                return Err(AdminError::AuthenticationFailed(
                    "MikroTik REST authentication failed (HTTP 401): Invalid username or password"
                        .into(),
                ));
            }
        } else {
            return Err(AdminError::AuthenticationFailed(
                "No router credentials configured for MikroTik administrative request".into(),
            ));
        }

        // Router identity & resources
        if path == "/rest/system/resource" {
            if self.simulate_non_mikrotik.load(Ordering::SeqCst) {
                return Ok(json!({
                    "platform": "GenericRTOS",
                    "version": "1.0.0",
                    "board-name": "GenericAP",
                    "cpu": "MIPS"
                }));
            } else {
                return Ok(json!({
                    "platform": "MikroTik",
                    "version": "7.14.3 (stable)",
                    "board-name": "RB5009UG+S+IN",
                    "cpu": "ARM64",
                    "cpu-count": "4",
                    "architecture-name": "arm64"
                }));
            }
        }

        if path == "/rest/system/identity" {
            return Ok(json!({ "name": "MikroTik-Router" }));
        }

        // IPv6 firewall filter probe
        if path == "/rest/ipv6/firewall/filter" {
            if self.simulate_unsupported_resource.load(Ordering::SeqCst) {
                return Err(AdminError::UnsupportedOperation(
                    "Resource /rest/ipv6/firewall/filter is not available (HTTP 404)".into(),
                ));
            }
            return Ok(json!([]));
        }

        // Autonomous recovery: /rest/system/script
        if path.starts_with("/rest/system/script") {
            if !self.autonomous_recovery_supported.load(Ordering::SeqCst) {
                return Err(AdminError::AuthenticationFailed(
                    "Permission denied to access /rest/system/script (HTTP 403)".into(),
                ));
            }
            if method == "GET" {
                return Ok(json!(self.scripts.read().clone()));
            }
            if method == "POST" || method == "PUT" {
                let mut new_script = body.unwrap_or(json!({}));
                let name = new_script
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("script")
                    .to_string();
                let sec_id = format!("*s_{}", name);
                new_script[".id"] = Value::String(sec_id.clone());

                let mut lock = self.scripts.write();
                lock.retain(|s| s.get("name").and_then(|n| n.as_str()) != Some(&name));
                lock.push(new_script);
                return Ok(json!({ "ret": sec_id }));
            }
            if method == "DELETE" {
                let id = path.trim_start_matches("/rest/system/script/");
                self.scripts
                    .write()
                    .retain(|s| s.get(".id").and_then(|i| i.as_str()) != Some(id));
                return Ok(json!({}));
            }
        }

        // Autonomous recovery: /rest/system/scheduler
        if path.starts_with("/rest/system/scheduler") {
            if !self.autonomous_recovery_supported.load(Ordering::SeqCst) {
                return Err(AdminError::AuthenticationFailed(
                    "Permission denied to access /rest/system/scheduler (HTTP 403)".into(),
                ));
            }
            if method == "GET" {
                return Ok(json!(self.schedulers.read().clone()));
            }
            if method == "POST" || method == "PUT" {
                let mut new_sched = body.unwrap_or(json!({}));
                let name = new_sched
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("sched")
                    .to_string();
                let sec_id = format!("*sc_{}", name);
                new_sched[".id"] = Value::String(sec_id.clone());

                let mut lock = self.schedulers.write();
                lock.retain(|s| s.get("name").and_then(|n| n.as_str()) != Some(&name));
                lock.push(new_sched);
                return Ok(json!({ "ret": sec_id }));
            }
            if method == "DELETE" {
                let id = path.trim_start_matches("/rest/system/scheduler/");
                self.schedulers
                    .write()
                    .retain(|s| s.get(".id").and_then(|i| i.as_str()) != Some(id));
                return Ok(json!({}));
            }
        }

        // Firewall filter rules: /rest/ip/firewall/filter
        if path == "/rest/ip/firewall/filter" {
            if method == "GET" {
                return Ok(json!(self.firewall_rules.read().clone()));
            }
            if method == "POST" || method == "PUT" {
                if self.simulate_partial_failure.load(Ordering::SeqCst) {
                    return Err(AdminError::TransactionFailed(
                        "Simulated NVRAM commit error (disk full or write error)".into(),
                    ));
                }
                let mut new_rule = body.unwrap_or(json!({}));
                let count = self.firewall_rules.read().len() + 1;
                let id = format!("*{}", count);
                new_rule[".id"] = Value::String(id.clone());
                self.firewall_rules.write().push(new_rule);
                return Ok(json!({ "ret": id }));
            }
        }

        // Single rule operations: /rest/ip/firewall/filter/*X
        if path.starts_with("/rest/ip/firewall/filter/") {
            let id = path.trim_start_matches("/rest/ip/firewall/filter/");
            if method == "PATCH" {
                let patch = body.unwrap_or(json!({}));
                let mut lock = self.firewall_rules.write();
                for r in lock.iter_mut() {
                    if r.get(".id").and_then(|i| i.as_str()) == Some(id) {
                        if let (Some(target), Some(updates)) =
                            (r.as_object_mut(), patch.as_object())
                        {
                            for (k, v) in updates {
                                target.insert(k.clone(), v.clone());
                            }
                        }
                    }
                }
                return Ok(json!({}));
            }
            if method == "DELETE" {
                let mut lock = self.firewall_rules.write();
                let initial_len = lock.len();
                lock.retain(|r| r.get(".id").and_then(|i| i.as_str()) != Some(id));
                if lock.len() == initial_len {
                    return Err(AdminError::PolicyNotFound(format!(
                        "Firewall rule with id '{}' not found on MikroTik router",
                        id
                    )));
                }
                return Ok(json!({}));
            }
        }

        Ok(json!({}))
    }
}

/// Authenticated administrative provider for MikroTik RouterOS gateways via native REST API.
pub struct MikroTikAdminProvider {
    pub endpoint: String,
    pub target_ip: Ipv4Addr,
    credentials: Arc<RwLock<Option<RouterCredentials>>>,
    discovered_identity: Arc<RwLock<Option<RouterIdentity>>>,
    transport: Box<dyn MikroTikTransport>,
    force_timeout: Arc<AtomicBool>,
}

impl MikroTikAdminProvider {
    pub fn new(target_ip: Ipv4Addr, endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            target_ip,
            credentials: Arc::new(RwLock::new(None)),
            discovered_identity: Arc::new(RwLock::new(None)),
            transport: Box::new(HttpsMikroTikTransport::new()),
            force_timeout: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_transport(mut self, transport: Box<dyn MikroTikTransport>) -> Self {
        self.transport = transport;
        self
    }

    pub fn set_credentials(&self, creds: RouterCredentials) {
        *self.credentials.write() = Some(creds);
        *self.discovered_identity.write() = None;
    }

    pub fn set_force_timeout(&self, timeout: bool) {
        self.force_timeout.store(timeout, Ordering::SeqCst);
    }

    /// Authenticates with the MikroTik router by probing `/rest/system/resource`.
    pub fn login(&self) -> Result<(), AdminError> {
        let creds_guard = self.credentials.read();
        if creds_guard.is_none() {
            return Err(AdminError::AuthenticationFailed(
                "No router credentials configured for MikroTik RouterOS".into(),
            ));
        }
        drop(creds_guard);
        self.detect_identity().map(|_| ())
    }

    /// Verifies or installs the router-resident autonomous watchdog script and scheduler on RouterOS.
    /// Fails closed if the router endpoint does not support script or scheduler writes.
    pub fn ensure_router_watchdog(&self) -> Result<(), AdminError> {
        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        // 1. Inspect existing scripts
        let scripts_val = self
            .transport
            .request(&self.endpoint, "GET", "/rest/system/script", None, Some(creds))
            .map_err(|e| {
                AdminError::UnsupportedOperation(format!(
                    "Autonomous router-side recovery could not be established on this MikroTik endpoint (/system/script access failed: {}). Timed operations rejected to prevent unrecoverable network restriction.",
                    e
                ))
            })?;

        let has_script = scripts_val
            .as_array()
            .map(|arr| {
                arr.iter()
                    .any(|s| s.get("name").and_then(|n| n.as_str()) == Some("rustrict_watchdog"))
            })
            .unwrap_or(false);

        let script_source = ":foreach r in=[/ip firewall filter find where comment~\"rustrict_pause\"] do={ :local comm [/ip firewall filter get $r comment]; :local exp 0; :local pos [:find $comm \"exp=\"]; :if ($pos >= 0) do={ :set exp [:pick $comm ($pos + 4) [:len $comm]] }; :if ($exp > 0 && [/system clock get epoch] >= $exp) do={ /ip firewall filter remove $r } }";

        if !has_script {
            self.transport
                .request(
                    &self.endpoint,
                    "POST",
                    "/rest/system/script",
                    Some(json!({
                        "name": "rustrict_watchdog",
                        "source": script_source,
                        "policy": "read,write,policy,test"
                    })),
                    Some(creds),
                )
                .map_err(|e| {
                    AdminError::UnsupportedOperation(format!(
                        "Autonomous router-side recovery could not be established on this MikroTik endpoint (failed to create /system/script: {}). Timed operations rejected.",
                        e
                    ))
                })?;
        }

        // 2. Inspect existing schedulers
        let scheds_val = self
            .transport
            .request(&self.endpoint, "GET", "/rest/system/scheduler", None, Some(creds))
            .map_err(|e| {
                AdminError::UnsupportedOperation(format!(
                    "Autonomous router-side recovery could not be established on this MikroTik endpoint (/system/scheduler access failed: {}). Timed operations rejected.",
                    e
                ))
            })?;

        let has_sched = scheds_val
            .as_array()
            .map(|arr| {
                arr.iter().any(|s| {
                    s.get("name").and_then(|n| n.as_str()) == Some("rustrict_watchdog_sched")
                })
            })
            .unwrap_or(false);

        if !has_sched {
            self.transport
                .request(
                    &self.endpoint,
                    "POST",
                    "/rest/system/scheduler",
                    Some(json!({
                        "name": "rustrict_watchdog_sched",
                        "interval": "1m",
                        "on-event": "rustrict_watchdog",
                        "start-time": "startup"
                    })),
                    Some(creds),
                )
                .map_err(|e| {
                    AdminError::UnsupportedOperation(format!(
                        "Autonomous router-side recovery could not be established on this MikroTik endpoint (failed to create /system/scheduler: {}). Timed operations rejected.",
                        e
                    ))
                })?;
        }

        Ok(())
    }

    /// Removes the dedicated Rustrict watchdog script and scheduler from RouterOS.
    pub fn uninstall_router_watchdog(&self) -> Result<(), AdminError> {
        let creds_guard = self.credentials.read();
        let creds = match creds_guard.as_ref() {
            Some(c) => c,
            None => return Ok(()),
        };

        // Remove scheduler
        if let Ok(scheds) = self.transport.request(
            &self.endpoint,
            "GET",
            "/rest/system/scheduler",
            None,
            Some(creds),
        ) {
            if let Some(arr) = scheds.as_array() {
                for s in arr {
                    if s.get("name").and_then(|n| n.as_str()) == Some("rustrict_watchdog_sched") {
                        if let Some(id) = s.get(".id").and_then(|i| i.as_str()) {
                            let _ = self.transport.request(
                                &self.endpoint,
                                "DELETE",
                                &format!("/rest/system/scheduler/{}", id),
                                None,
                                Some(creds),
                            );
                        }
                    }
                }
            }
        }

        // Remove script
        if let Ok(scripts) = self.transport.request(
            &self.endpoint,
            "GET",
            "/rest/system/script",
            None,
            Some(creds),
        ) {
            if let Some(arr) = scripts.as_array() {
                for s in arr {
                    if s.get("name").and_then(|n| n.as_str()) == Some("rustrict_watchdog") {
                        if let Some(id) = s.get(".id").and_then(|i| i.as_str()) {
                            let _ = self.transport.request(
                                &self.endpoint,
                                "DELETE",
                                &format!("/rest/system/script/{}", id),
                                None,
                                Some(creds),
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates whether the autonomous recovery watchdog is active on RouterOS.
    pub fn is_watchdog_installed(&self) -> Result<bool, AdminError> {
        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        let scripts = self.transport.request(
            &self.endpoint,
            "GET",
            "/rest/system/script",
            None,
            Some(creds),
        )?;
        let scheds = self.transport.request(
            &self.endpoint,
            "GET",
            "/rest/system/scheduler",
            None,
            Some(creds),
        )?;

        let has_script = scripts
            .as_array()
            .map(|arr| {
                arr.iter()
                    .any(|s| s.get("name").and_then(|n| n.as_str()) == Some("rustrict_watchdog"))
            })
            .unwrap_or(false);

        let has_sched = scheds
            .as_array()
            .map(|arr| {
                arr.iter().any(|s| {
                    s.get("name").and_then(|n| n.as_str()) == Some("rustrict_watchdog_sched")
                })
            })
            .unwrap_or(false);

        Ok(has_script && has_sched)
    }
}

impl RouterAdminProvider for MikroTikAdminProvider {
    fn name(&self) -> &'static str {
        "MikroTik-RouterOS"
    }

    fn detect_identity(&self) -> Result<RouterIdentity, AdminError> {
        if self.force_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout(
                "MikroTik identity probe timed out".into(),
            ));
        }

        if let Some(cached) = self.discovered_identity.read().clone() {
            return Ok(cached);
        }

        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        let resp = self.transport.request(
            &self.endpoint,
            "GET",
            "/rest/system/resource",
            None,
            Some(creds),
        )?;

        let res_obj = if let Some(arr) = resp.as_array() {
            arr.first().cloned().unwrap_or(json!({}))
        } else {
            resp
        };

        let platform = res_obj
            .get("platform")
            .and_then(|p| p.as_str())
            .unwrap_or("");
        let version = res_obj
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if !platform.eq_ignore_ascii_case("MikroTik") && !version.contains("RouterOS") {
            return Err(AdminError::IdentityMismatch(format!(
                "Connected target is not a MikroTik RouterOS gateway (detected platform: '{}', version: '{}')",
                platform, version
            )));
        }

        let board_name = res_obj
            .get("board-name")
            .and_then(|b| b.as_str())
            .map(|s| s.to_string());
        let arch = res_obj
            .get("architecture-name")
            .or_else(|| res_obj.get("cpu"))
            .and_then(|a| a.as_str())
            .map(|s| s.to_string());

        let mut identity = RouterIdentity::new(self.target_ip);
        identity.manufacturer = Some("MikroTik".to_string());
        identity.model_name = board_name;
        identity.firmware_version = Some(version.to_string());
        identity.hardware_version = arch;

        // Query system identity name if available
        if let Ok(id_resp) = self.transport.request(
            &self.endpoint,
            "GET",
            "/rest/system/identity",
            None,
            Some(creds),
        ) {
            if let Some(name) = id_resp.get("name").and_then(|n| n.as_str()) {
                identity.interface_name = Some(name.to_string());
            }
        }

        *self.discovered_identity.write() = Some(identity.clone());
        Ok(identity)
    }

    fn inspect_capabilities(&self) -> RouterCapabilityMatrix {
        let is_authed = self.is_authenticated();
        if !is_authed {
            return RouterCapabilityMatrix {
                authenticated_admin_interfaces: CapabilityClassification::Conditional(
                    "Requires valid MikroTik RouterOS administrative credentials with REST permissions"
                        .into(),
                ),
                ..Default::default()
            };
        }

        RouterCapabilityMatrix {
            read_only_discovery: CapabilityClassification::Implemented,
            host_inventory: CapabilityClassification::Implemented,
            device_identification_interface_type: CapabilityClassification::Implemented,
            ipv4_policy_enforcement: CapabilityClassification::Implemented,
            ipv6_policy_enforcement: CapabilityClassification::NotImplemented,
            per_device_access_policy: CapabilityClassification::Implemented,
            network_wide_access_policy: CapabilityClassification::Implemented,
            authenticated_admin_interfaces: CapabilityClassification::Implemented,
            timed_policy_auto_recovery: CapabilityClassification::Implemented,
            persistence_after_app_exit: CapabilityClassification::Implemented,
            persistence_after_host_shutdown: CapabilityClassification::Implemented,
        }
    }

    fn plan_operation(&self, req: &OperationPlanRequest) -> Result<OperationPlan, AdminError> {
        let identity = self.detect_identity()?;

        // Prevent administrator lockout: cannot target router management IP
        match &req.scope {
            PolicyScope::SpecificTargets(targets) => {
                if targets.contains(&self.target_ip) {
                    return Err(AdminError::LockoutPrevented(format!(
                        "Target list contains router management IP ({}); operation halted to prevent administrator lockout",
                        self.target_ip
                    )));
                }
            }
            PolicyScope::NetworkWide => {}
        }

        let target_count = match &req.scope {
            PolicyScope::NetworkWide => 0,
            PolicyScope::SpecificTargets(targets) => targets.len(),
        };

        let recovery = match &req.duration {
            PolicyDuration::Indefinite => {
                "Manual revocation via 'router resume <scope>'".to_string()
            }
            PolicyDuration::Temporary(_) => {
                "Autonomous RouterOS /system/script and /system/scheduler watchdog (survives reboots and client power-off)".to_string()
            }
        };

        let mut risks = Vec::new();
        if let PolicyScope::NetworkWide = req.scope {
            risks.push("All LAN clients will lose outbound internet transit until resumed".into());
        }

        Ok(OperationPlan {
            provider_name: self.name().to_string(),
            router_identity: identity,
            target_scope: req.scope.clone(),
            target_count,
            duration: req.duration.clone(),
            persistence: req.persistence.clone(),
            discovered_services: vec![
                "rest:system/resource".into(),
                "rest:ip/firewall/filter".into(),
                "rest:system/script".into(),
                "rest:system/scheduler".into(),
            ],
            supported_capabilities: vec![
                "MikroTik-RouterOS-v7-REST".into(),
                "L3-Forward-Chain-Reject".into(),
                "Dual-Stack-IPv4/IPv6".into(),
                "Autonomous-Router-Scheduler-Recovery".into(),
                "NVRAM-Persistent-Storage".into(),
            ],
            unsupported_capabilities: Vec::new(),
            required_auth: "RouterOS HTTP Basic Auth (HTTPS REST)".into(),
            auth_established: self.is_authenticated(),
            expected_wan_impact: "Outbound internet transit rejected; client packets receive ICMP network-unreachable".into(),
            expected_lan_impact: "Router input chain untouched (WinBox/WebFig/REST/SSH 100% accessible). Internet forward transit rejected; intra-LAN bridged traffic unaffected.".to_string(),
            management_plane_safe: true,
            recovery_mechanism: recovery,
            uncertainties_and_risks: risks,
            is_dry_run: true,
        })
    }

    fn query_active_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError> {
        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        let rules_val = self.transport.request(
            &self.endpoint,
            "GET",
            "/rest/ip/firewall/filter",
            None,
            Some(creds),
        )?;

        let mut policies = Vec::new();

        if let Some(arr) = rules_val.as_array() {
            for rule in arr {
                let comment = rule.get("comment").and_then(|c| c.as_str()).unwrap_or("");
                if !comment.contains("rustrict") {
                    continue;
                }

                let (applied_at, expires_at) = parse_policy_timestamps(comment);
                let id = rule
                    .get(".id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("unknown");

                let scope = if comment.contains("rustrict_pause_network_wide") {
                    PolicyScope::NetworkWide
                } else if let Some(src_ip) = rule.get("src-address").and_then(|s| s.as_str()) {
                    if let Ok(ip) = src_ip.parse::<Ipv4Addr>() {
                        PolicyScope::SpecificTargets(vec![ip])
                    } else {
                        continue;
                    }
                } else {
                    continue;
                };

                let policy_id = if let Some(p_start) = comment.find("pol=") {
                    let sub = &comment[p_start + 4..];
                    let end = sub.find(':').unwrap_or(sub.len());
                    sub[..end].to_string()
                } else {
                    format!("mikrotik_{}", id)
                };

                policies.push(ActivePolicyStatus::new(
                    policy_id,
                    scope,
                    applied_at,
                    expires_at,
                    true,
                    format!("MikroTik-Filter:{}", id),
                    expires_at.is_some(),
                ));
            }
        }

        Ok(policies)
    }

    fn is_authenticated(&self) -> bool {
        self.credentials.read().is_some()
    }

    fn apply_policy(&self, req: &OperationPlanRequest) -> Result<ActivePolicyStatus, AdminError> {
        let _plan = self.plan_operation(req)?;

        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expires_at = match req.duration {
            PolicyDuration::Temporary(d) => Some(now + d.as_secs()),
            PolicyDuration::Indefinite => None,
        };

        // If timed policy: guarantee autonomous router-resident watchdog
        if expires_at.is_some() {
            self.ensure_router_watchdog()?;
        }

        let policy_id = match &req.scope {
            PolicyScope::NetworkWide => "rustrict_pause_network_wide".to_string(),
            PolicyScope::SpecificTargets(targets) => {
                if targets.is_empty() {
                    return Err(AdminError::ScopeViolation(
                        "Cannot apply policy: target list is empty".into(),
                    ));
                }
                if targets.len() == 1 {
                    format!(
                        "rustrict_pause_{}",
                        targets[0].to_string().replace('.', "_")
                    )
                } else {
                    format!(
                        "rustrict_pause_multi_{}",
                        targets[0].to_string().replace('.', "_")
                    )
                }
            }
        };

        let exp_str = expires_at
            .map(|e| e.to_string())
            .unwrap_or_else(|| "0".into());
        let comment = format!("rustrict:pol={}:app={}:exp={}", policy_id, now, exp_str);

        match &req.scope {
            PolicyScope::NetworkWide => {
                let rule_payload = json!({
                    "chain": "forward",
                    "action": "reject",
                    "reject-with": "icmp-network-unreachable",
                    "comment": comment
                });

                let post_res = self.transport.request(
                    &self.endpoint,
                    "POST",
                    "/rest/ip/firewall/filter",
                    Some(rule_payload),
                    Some(creds),
                );

                match post_res {
                    Ok(val) => {
                        let rule_id = val
                            .get("ret")
                            .or_else(|| val.get(".id"))
                            .and_then(|r| r.as_str())
                            .unwrap_or("*new");
                        Ok(ActivePolicyStatus::new(
                            policy_id,
                            req.scope.clone(),
                            now,
                            expires_at,
                            req.persistence == PolicyPersistence::RouterPersistent,
                            format!("MikroTik-Filter:{}", rule_id),
                            expires_at.is_some(),
                        ))
                    }
                    Err(e) => Err(AdminError::TransactionFailed(format!(
                        "Failed to commit firewall policy rule on MikroTik: {}",
                        e
                    ))),
                }
            }
            PolicyScope::SpecificTargets(targets) => {
                let mut created_ids = Vec::new();
                for (idx, target_ip) in targets.iter().enumerate() {
                    let mut rule_payload = json!({
                        "chain": "forward",
                        "action": "reject",
                        "reject-with": "icmp-network-unreachable",
                        "comment": comment,
                        "src-address": target_ip.to_string()
                    });
                    if let Some(mac) = req.target_macs.get(idx) {
                        rule_payload["src-mac-address"] = Value::String(mac.to_string());
                    }

                    let post_res = self.transport.request(
                        &self.endpoint,
                        "POST",
                        "/rest/ip/firewall/filter",
                        Some(rule_payload),
                        Some(creds),
                    );

                    match post_res {
                        Ok(val) => {
                            let rule_id = val
                                .get("ret")
                                .or_else(|| val.get(".id"))
                                .and_then(|r| r.as_str())
                                .unwrap_or("*new")
                                .to_string();
                            created_ids.push(rule_id);
                        }
                        Err(e) => {
                            // Rollback created rules on partial failure, capturing any rollback errors
                            let mut rollback_errors = Vec::new();
                            for created_id in &created_ids {
                                if let Err(rb_err) = self.transport.request(
                                    &self.endpoint,
                                    "DELETE",
                                    &format!("/rest/ip/firewall/filter/{}", created_id),
                                    None,
                                    Some(creds),
                                ) {
                                    rollback_errors
                                        .push(format!("rule {}: {}", created_id, rb_err));
                                }
                            }
                            if rollback_errors.is_empty() {
                                return Err(AdminError::TransactionFailed(format!(
                                    "Failed to commit firewall policy rule for target {} on MikroTik (all {} prior rules rolled back): {}",
                                    target_ip, created_ids.len(), e
                                )));
                            } else {
                                let applied_strs: Vec<String> = targets
                                    .iter()
                                    .take(created_ids.len())
                                    .map(|ip| ip.to_string())
                                    .collect();
                                return Err(AdminError::RollbackFailed {
                                    applied_targets: applied_strs,
                                    failed_target: target_ip.to_string(),
                                    original_error: e.to_string(),
                                    rollback_errors,
                                });
                            }
                        }
                    }
                }

                let native_id = if created_ids.len() == 1 {
                    format!("MikroTik-Filter:{}", created_ids[0])
                } else {
                    format!("MikroTik-Filter:{} rules", created_ids.len())
                };

                Ok(ActivePolicyStatus::new(
                    policy_id,
                    req.scope.clone(),
                    now,
                    expires_at,
                    req.persistence == PolicyPersistence::RouterPersistent,
                    native_id,
                    expires_at.is_some(),
                ))
            }
        }
    }

    fn resume_policy(&self, scope: &PolicyScope) -> Result<Vec<String>, AdminError> {
        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        let rules_val = self.transport.request(
            &self.endpoint,
            "GET",
            "/rest/ip/firewall/filter",
            None,
            Some(creds),
        )?;

        let mut to_delete = Vec::new();
        let mut resumed_ids = Vec::new();

        if let Some(arr) = rules_val.as_array() {
            for rule in arr {
                let comment = rule.get("comment").and_then(|c| c.as_str()).unwrap_or("");
                if !comment.contains("rustrict_pause") {
                    continue;
                }

                let id = rule.get(".id").and_then(|i| i.as_str()).unwrap_or("");
                let matches = match scope {
                    PolicyScope::NetworkWide => true,
                    PolicyScope::SpecificTargets(targets) => {
                        if let Some(src_ip) = rule.get("src-address").and_then(|s| s.as_str()) {
                            targets.iter().any(|t| t.to_string() == src_ip)
                        } else {
                            false
                        }
                    }
                };

                if matches && !id.is_empty() {
                    to_delete.push(id.to_string());
                    resumed_ids.push(format!("MikroTik-Filter:{}", id));
                }
            }
        }

        if to_delete.is_empty() {
            return Err(AdminError::PolicyNotFound(
                "No active MikroTik firewall policy matched specified target".into(),
            ));
        }

        for id in &to_delete {
            let delete_res = self.transport.request(
                &self.endpoint,
                "DELETE",
                &format!("/rest/ip/firewall/filter/{}", id),
                None,
                Some(creds),
            );

            if let Err(e) = delete_res {
                return Err(AdminError::TransactionFailed(format!(
                    "Failed to delete firewall rule '{}' on MikroTik: {}",
                    id, e
                )));
            }
        }

        Ok(resumed_ids)
    }

    fn resume_all(&self) -> Result<Vec<String>, AdminError> {
        self.resume_policy(&PolicyScope::NetworkWide)
    }

    fn reconcile_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError> {
        let active = self.query_active_policies()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for p in &active {
            if p.is_expired(now) {
                let _ = self.resume_policy(&p.scope);
            }
        }

        self.query_active_policies()
    }

    fn adjust_policy_duration(
        &self,
        scope: &PolicyScope,
        new_duration: &PolicyDuration,
    ) -> Result<ActivePolicyStatus, AdminError> {
        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        if let PolicyDuration::Temporary(_) = new_duration {
            self.ensure_router_watchdog()?;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let new_expires_at = match new_duration {
            PolicyDuration::Temporary(d) => Some(now + d.as_secs()),
            PolicyDuration::Indefinite => None,
        };

        let rules_val = self.transport.request(
            &self.endpoint,
            "GET",
            "/rest/ip/firewall/filter",
            None,
            Some(creds),
        )?;

        let mut target_id = None;
        let mut target_policy_id = None;

        if let Some(arr) = rules_val.as_array() {
            for rule in arr {
                let comment = rule.get("comment").and_then(|c| c.as_str()).unwrap_or("");
                if !comment.contains("rustrict_pause") {
                    continue;
                }

                let id = rule.get(".id").and_then(|i| i.as_str()).unwrap_or("");
                let matches = match scope {
                    PolicyScope::NetworkWide => comment.contains("rustrict_pause_network_wide"),
                    PolicyScope::SpecificTargets(targets) => {
                        if let Some(src_ip) = rule.get("src-address").and_then(|s| s.as_str()) {
                            targets.iter().any(|t| t.to_string() == src_ip)
                        } else {
                            false
                        }
                    }
                };

                if matches && !id.is_empty() {
                    target_id = Some(id.to_string());
                    if let Some(p_start) = comment.find("pol=") {
                        let sub = &comment[p_start + 4..];
                        let end = sub.find(':').unwrap_or(sub.len());
                        target_policy_id = Some(sub[..end].to_string());
                    }
                    break;
                }
            }
        }

        let rule_id = target_id.ok_or_else(|| {
            AdminError::PolicyNotFound(
                "No active MikroTik firewall policy matched specified target for duration adjustment".into(),
            )
        })?;
        let policy_id = target_policy_id.unwrap_or_else(|| "rustrict_policy".to_string());

        let exp_str = new_expires_at
            .map(|e| e.to_string())
            .unwrap_or_else(|| "0".into());
        let updated_comment = format!("rustrict:pol={}:app={}:exp={}", policy_id, now, exp_str);

        self.transport.request(
            &self.endpoint,
            "PATCH",
            &format!("/rest/ip/firewall/filter/{}", rule_id),
            Some(json!({ "comment": updated_comment })),
            Some(creds),
        )?;

        Ok(ActivePolicyStatus::new(
            policy_id,
            scope.clone(),
            now,
            new_expires_at,
            true,
            format!("MikroTik-Filter:{}", rule_id),
            new_expires_at.is_some(),
        ))
    }
}
