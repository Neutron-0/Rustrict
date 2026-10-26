use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
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
    PolicyScope, RouterIdentity,
};
use crate::gateway::admin::provider::RouterAdminProvider;
use crate::types::MacAddress;

/// Connected client details returned by the UniFi Network Controller client inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiClientEntry {
    pub id: String,
    pub ip: Option<Ipv4Addr>,
    pub mac: MacAddress,
    pub name: Option<String>,
    pub is_wired: bool,
    pub network: Option<String>,
    pub uptime: u64,
}

/// Pluggable transport abstraction for Ubiquiti UniFi Network API requests.
pub trait UnifiTransport: Send + Sync {
    fn request(
        &self,
        base_url: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
        credentials: Option<&RouterCredentials>,
    ) -> Result<Value, AdminError>;

    fn transport_name(&self) -> &'static str {
        "UniFi-HTTPS-REST"
    }
}

/// Production transport for UniFi Network Controller using Windows native `curl.exe`
/// with Schannel TLS verification, session cookie handling, and piped credentials.
pub struct HttpUnifiTransport {
    pub ca_cert_path: Option<PathBuf>,
    pub connect_timeout: Duration,
    pub session_cookie: Arc<RwLock<Option<String>>>,
}

impl HttpUnifiTransport {
    pub fn new() -> Self {
        Self {
            ca_cert_path: None,
            connect_timeout: Duration::from_secs(8),
            session_cookie: Arc::new(RwLock::new(None)),
        }
    }

    pub fn with_ca_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.ca_cert_path = Some(path.into());
        self
    }
}

impl Default for HttpUnifiTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl UnifiTransport for HttpUnifiTransport {
    fn request(
        &self,
        base_url: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
        credentials: Option<&RouterCredentials>,
    ) -> Result<Value, AdminError> {
        let full_url = if base_url.ends_with('/') && path.starts_with('/') {
            format!("{}{}", base_url.trim_end_matches('/'), path)
        } else if !base_url.ends_with('/') && !path.starts_with('/') {
            format!("{}/{}", base_url, path)
        } else {
            format!("{}{}", base_url, path)
        };

        let mut curl_cfg = format!(
            "url = \"{}\"\n\
             request = \"{}\"\n\
             header = \"Content-Type: application/json\"\n\
             max-time = {}\n\
             silent\n\
             show-error\n",
            full_url,
            method,
            self.connect_timeout.as_secs()
        );

        if let Some(cookie) = self.session_cookie.read().as_ref() {
            curl_cfg.push_str(&format!("cookie = \"{}\"\n", cookie));
        }

        // Support direct API Key header if username is "api-key" or password is provided
        if let Some(creds) = credentials {
            if creds.username.eq_ignore_ascii_case("api-key")
                || creds.username.eq_ignore_ascii_case("apikey")
            {
                curl_cfg.push_str(&format!(
                    "header = \"X-API-KEY: {}\"\n",
                    creds.password.expose().replace('\"', "\\\"")
                ));
            }
        }

        if let Some(ca) = &self.ca_cert_path {
            curl_cfg.push_str(&format!("cacert = \"{}\"\n", ca.display()));
        }

        let curl_bin = crate::gateway::admin::curl_util::find_curl()?;
        let mut cmd = Command::new(&curl_bin);
        cmd.arg("--config").arg("-");

        let body_str = body.map(|b| b.to_string()).unwrap_or_default();
        let _payload_guard = if !body_str.is_empty() {
            let guard = crate::gateway::admin::curl_util::AutoCleanFile::create(
                "rustrict_unifi",
                ".json",
                body_str.as_bytes(),
            )?;
            cmd.arg("--data-binary")
                .arg(format!("@{}", guard.path().display()));
            Some(guard)
        } else {
            None
        };

        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                AdminError::CommunicationError(format!(
                    "Failed to invoke native curl.exe for UniFi Network API: {}",
                    e
                ))
            })?;

        let mut curl_cfg_bytes = curl_cfg.into_bytes();
        if let Some(mut stdin) = child.stdin.take() {
            // Send only configuration on stdin
            let _ = stdin.write_all(&curl_cfg_bytes);
        }
        crate::gateway::admin::credentials::zero_slice(&mut curl_cfg_bytes);

        let output = child.wait_with_output().map_err(|e| {
            AdminError::CommunicationError(format!("Failed to wait for curl.exe output: {}", e))
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            if stderr.contains("SSL")
                || stderr.contains("certificate")
                || stderr.contains("schannel")
            {
                return Err(AdminError::CommunicationError(format!(
                    "TLS certificate validation failed for UniFi Controller at '{}': {}. Connection rejected to protect administrative credentials.",
                    full_url, stderr.trim()
                )));
            }
            if stderr.contains("timed out") || stderr.contains("Operation timed out") {
                return Err(AdminError::Timeout(format!(
                    "UniFi API request timed out: {}",
                    stderr.trim()
                )));
            }
            return Err(AdminError::CommunicationError(format!(
                "UniFi API request failed (curl exit code {:?}): {}",
                output.status.code(),
                stderr.trim()
            )));
        }

        // Parse JSON response
        let parsed: Value = serde_json::from_str(&stdout).map_err(|e| {
            AdminError::CommunicationError(format!(
                "Invalid JSON response from UniFi Controller: {} (Raw: {})",
                e,
                stdout.trim()
            ))
        })?;

        // Inspect UniFi error envelopes: { "meta": { "rc": "error", "msg": "..." } }
        if let Some(meta) = parsed.get("meta") {
            if meta.get("rc").and_then(|r| r.as_str()) == Some("error") {
                let msg = meta
                    .get("msg")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Unknown UniFi API Error");
                if msg.contains("api.err.LoginRequired")
                    || msg.contains("Unauthorized")
                    || msg.contains("Invalid")
                {
                    return Err(AdminError::AuthenticationFailed(format!(
                        "UniFi Authentication Error: {}",
                        msg
                    )));
                }
                return Err(AdminError::TransactionFailed(format!(
                    "UniFi API Error: {}",
                    msg
                )));
            }
        }

        Ok(parsed)
    }
}

/// Offline mock transport for UniFi Network Controller testing.
/// Simulates UniFi OS login, sites, client inventory, sysinfo, and traffic rules.
#[derive(Clone)]
pub struct MockUnifiTransport {
    pub valid_username: String,
    pub valid_password: String,
    pub simulate_auth_fail: Arc<AtomicBool>,
    pub simulate_permission_denied: Arc<AtomicBool>,
    pub simulate_tls_cert_error: Arc<AtomicBool>,
    pub simulate_timeout: Arc<AtomicBool>,
    pub simulate_non_unifi: Arc<AtomicBool>,
    pub simulate_missing_trafficrules: Arc<AtomicBool>,
    pub simulate_partial_failure: Arc<AtomicBool>,
    pub connected_clients: Arc<RwLock<Vec<Value>>>,
    pub traffic_rules: Arc<RwLock<Vec<Value>>>,
    pub executed_requests: Arc<RwLock<Vec<String>>>,
    pub next_rule_id: Arc<RwLock<usize>>,
}

impl Default for MockUnifiTransport {
    fn default() -> Self {
        Self {
            valid_username: "admin".into(),
            valid_password: "admin_password".into(),
            simulate_auth_fail: Arc::new(AtomicBool::new(false)),
            simulate_permission_denied: Arc::new(AtomicBool::new(false)),
            simulate_tls_cert_error: Arc::new(AtomicBool::new(false)),
            simulate_timeout: Arc::new(AtomicBool::new(false)),
            simulate_non_unifi: Arc::new(AtomicBool::new(false)),
            simulate_missing_trafficrules: Arc::new(AtomicBool::new(false)),
            simulate_partial_failure: Arc::new(AtomicBool::new(false)),
            connected_clients: Arc::new(RwLock::new(vec![
                json!({
                    "_id": "client_1",
                    "mac": "00:11:22:33:44:55",
                    "ip": "192.168.1.100",
                    "name": "Workstation-Office",
                    "hostname": "workstation-pc",
                    "is_wired": true,
                    "network": "Default LAN",
                    "uptime": 3600
                }),
                json!({
                    "_id": "client_2",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "ip": "192.168.1.101",
                    "name": "Tablet-WiFi",
                    "hostname": "tablet-ios",
                    "is_wired": false,
                    "network": "Default LAN",
                    "uptime": 1800
                }),
            ])),
            traffic_rules: Arc::new(RwLock::new(Vec::new())),
            executed_requests: Arc::new(RwLock::new(Vec::new())),
            next_rule_id: Arc::new(RwLock::new(1)),
        }
    }
}

impl UnifiTransport for MockUnifiTransport {
    fn request(
        &self,
        _base_url: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
        credentials: Option<&RouterCredentials>,
    ) -> Result<Value, AdminError> {
        self.executed_requests
            .write()
            .push(format!("{} {}", method, path));

        if self.simulate_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout("Mock UniFi transport timeout".into()));
        }

        if self.simulate_tls_cert_error.load(Ordering::SeqCst) {
            return Err(AdminError::CommunicationError(
                "TLS certificate validation failed: UniFi Controller presented an untrusted certificate. Connection rejected to protect administrative credentials.".into(),
            ));
        }

        if self.simulate_auth_fail.load(Ordering::SeqCst) {
            return Err(AdminError::AuthenticationFailed(
                "UniFi Authentication Error: api.err.InvalidCredentials (HTTP 401)".into(),
            ));
        }

        if self.simulate_permission_denied.load(Ordering::SeqCst) {
            return Err(AdminError::AuthenticationFailed(
                "UniFi Permission Denied: User lacks Administrator privileges for site (HTTP 403)"
                    .into(),
            ));
        }

        // Validate credentials if provided
        if let Some(creds) = credentials {
            if creds.username != self.valid_username
                || creds.password.expose() != self.valid_password
            {
                return Err(AdminError::AuthenticationFailed(
                    "UniFi Authentication Error: Invalid username or password".into(),
                ));
            }
        }

        // 1. Authentication login endpoint (/api/auth/login or /api/login)
        if path == "/api/auth/login" || path == "/api/login" {
            return Ok(json!({
                "meta": { "rc": "ok" },
                "data": [{ "unique_id": "user_admin", "username": "admin" }]
            }));
        }

        // 2. Sites discovery endpoint (/api/self/sites or /proxy/network/api/self/sites)
        if path.contains("/api/self/sites") {
            return Ok(json!({
                "meta": { "rc": "ok" },
                "data": [
                    { "_id": "site_default", "name": "default", "desc": "Default" },
                    { "_id": "site_branch", "name": "branch_office", "desc": "Branch Office" }
                ]
            }));
        }

        // 3. Sysinfo endpoint (/stat/sysinfo)
        if path.contains("/stat/sysinfo") {
            if self.simulate_non_unifi.load(Ordering::SeqCst) {
                return Ok(json!({
                    "meta": { "rc": "ok" },
                    "data": [{
                        "version": "1.0.0",
                        "hostname": "generic-gateway",
                        "model": "GenericGateway"
                    }]
                }));
            } else {
                return Ok(json!({
                    "meta": { "rc": "ok" },
                    "data": [{
                        "version": "8.0.28",
                        "hostname": "UniFi-Dream-Machine-Pro",
                        "model": "UniFi Dream Machine Pro",
                        "unifi_version": "8.0.28",
                        "ip_client": "192.168.1.1",
                        "uptime": 1048576
                    }]
                }));
            }
        }

        // 4. Connected clients inventory endpoint (/stat/sta)
        if path.contains("/stat/sta") {
            return Ok(json!({
                "meta": { "rc": "ok" },
                "data": self.connected_clients.read().clone()
            }));
        }

        // 5. Traffic Rules endpoint (/trafficrules or /rest/trafficrule)
        if path.contains("/trafficrules") || path.contains("/rest/trafficrule") {
            if self.simulate_missing_trafficrules.load(Ordering::SeqCst) {
                return Err(AdminError::UnsupportedOperation(
                    "Resource /trafficrules is not supported on this UniFi Controller version (HTTP 404)".into(),
                ));
            }

            if method == "GET" {
                return Ok(json!({
                    "meta": { "rc": "ok" },
                    "data": self.traffic_rules.read().clone()
                }));
            }

            if method == "POST" {
                if self.simulate_partial_failure.load(Ordering::SeqCst) {
                    return Err(AdminError::TransactionFailed(
                        "UniFi Controller database commit error (simulated partial failure)".into(),
                    ));
                }
                let mut new_rule = body.unwrap_or(json!({}));
                let mut next_id = self.next_rule_id.write();
                let rule_id = format!("rule_{}", *next_id);
                *next_id += 1;
                new_rule["_id"] = Value::String(rule_id.clone());

                self.traffic_rules.write().push(new_rule.clone());
                return Ok(json!({
                    "meta": { "rc": "ok" },
                    "data": [new_rule]
                }));
            }

            if method == "PUT" {
                let id = path.split('/').next_back().unwrap_or("");
                let update = body.unwrap_or(json!({}));
                let mut rules = self.traffic_rules.write();
                for r in rules.iter_mut() {
                    if r.get("_id").and_then(|i| i.as_str()) == Some(id) {
                        if let (Some(target), Some(updates)) =
                            (r.as_object_mut(), update.as_object())
                        {
                            for (k, v) in updates {
                                target.insert(k.clone(), v.clone());
                            }
                        }
                        return Ok(json!({ "meta": { "rc": "ok" }, "data": [r.clone()] }));
                    }
                }
                return Err(AdminError::PolicyNotFound(format!(
                    "Traffic rule '{}' not found",
                    id
                )));
            }

            if method == "DELETE" {
                let id = path.split('/').next_back().unwrap_or("");
                let mut rules = self.traffic_rules.write();
                let initial_len = rules.len();
                rules.retain(|r| r.get("_id").and_then(|i| i.as_str()) != Some(id));
                if rules.len() == initial_len {
                    return Err(AdminError::PolicyNotFound(format!(
                        "Traffic rule '{}' not found",
                        id
                    )));
                }
                return Ok(json!({ "meta": { "rc": "ok" } }));
            }
        }

        Ok(json!({ "meta": { "rc": "ok" }, "data": [] }))
    }
}

/// Provider implementing the Ubiquiti UniFi Network API integration.
pub struct UnifiAdminProvider {
    pub target_ip: Ipv4Addr,
    pub endpoint: String,
    pub site: Arc<RwLock<String>>,
    pub transport: Box<dyn UnifiTransport>,
    pub credentials: Arc<RwLock<Option<RouterCredentials>>>,
    pub discovered_identity: Arc<RwLock<Option<RouterIdentity>>>,
    pub active_policies: Arc<RwLock<HashMap<String, ActivePolicyStatus>>>,
    pub is_unifi_os: Arc<AtomicBool>,
    pub force_timeout: Arc<AtomicBool>,
}

impl UnifiAdminProvider {
    pub fn new(target_ip: Ipv4Addr, endpoint: impl Into<String>) -> Self {
        let raw_endpoint = endpoint.into();
        let endpoint = if raw_endpoint.is_empty() {
            format!("https://{}:443", target_ip)
        } else {
            raw_endpoint.trim_end_matches('/').to_string()
        };

        Self {
            target_ip,
            endpoint,
            site: Arc::new(RwLock::new("default".into())),
            transport: Box::new(HttpUnifiTransport::new()),
            credentials: Arc::new(RwLock::new(None)),
            discovered_identity: Arc::new(RwLock::new(None)),
            active_policies: Arc::new(RwLock::new(HashMap::new())),
            is_unifi_os: Arc::new(AtomicBool::new(true)),
            force_timeout: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_transport(mut self, transport: Box<dyn UnifiTransport>) -> Self {
        self.transport = transport;
        self
    }

    pub fn with_site(self, site: impl Into<String>) -> Self {
        *self.site.write() = site.into();
        self
    }

    pub fn set_credentials(&self, creds: RouterCredentials) {
        *self.credentials.write() = Some(creds);
        *self.discovered_identity.write() = None;
    }

    pub fn site(&self) -> String {
        self.site.read().clone()
    }

    pub fn set_site(&self, site: impl Into<String>) {
        *self.site.write() = site.into();
    }

    pub fn set_force_timeout(&self, timeout: bool) {
        self.force_timeout.store(timeout, Ordering::SeqCst);
    }

    /// Normalizes subpaths for UniFi OS consoles (`/proxy/network/...`) vs standalone controllers.
    pub fn build_api_path(&self, subpath: &str) -> String {
        let site = self.site.read();
        let trimmed = subpath.trim_start_matches('/');
        if self.is_unifi_os.load(Ordering::SeqCst) {
            format!("/proxy/network/api/s/{}/{}", *site, trimmed)
        } else {
            format!("/api/s/{}/{}", *site, trimmed)
        }
    }

    /// Normalizes Traffic Rules API path for UniFi Network v7.2+/v8.x/v9.x.
    pub fn build_trafficrule_path(&self, rule_id: Option<&str>) -> String {
        let site = self.site.read();
        let base = if self.is_unifi_os.load(Ordering::SeqCst) {
            format!("/proxy/network/v2/api/site/{}/trafficrules", *site)
        } else {
            format!("/api/s/{}/rest/trafficrule", *site)
        };

        if let Some(id) = rule_id {
            format!("{}/{}", base, id)
        } else {
            base
        }
    }

    /// Authenticates with the UniFi controller by calling the login endpoint.
    pub fn login(&self) -> Result<(), AdminError> {
        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed(
                "No router credentials configured for UniFi Controller".into(),
            )
        })?;

        let login_payload = json!({
            "username": creds.username,
            "password": creds.password.expose()
        });

        // Try UniFi OS login endpoint first, fall back to standalone
        let res = self.transport.request(
            &self.endpoint,
            "POST",
            "/api/auth/login",
            Some(login_payload.clone()),
            Some(creds),
        );
        match res {
            Ok(_) => {
                self.is_unifi_os.store(true, Ordering::SeqCst);
                self.detect_identity().map(|_| ())
            }
            Err(e) => {
                // If 404, attempt classic standalone controller login
                if let AdminError::UnsupportedOperation(_) = e {
                    self.is_unifi_os.store(false, Ordering::SeqCst);
                    self.transport.request(
                        &self.endpoint,
                        "POST",
                        "/api/login",
                        Some(login_payload),
                        Some(creds),
                    )?;
                    self.detect_identity().map(|_| ())
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Discovers all available sites configured on the UniFi Controller.
    pub fn list_sites(&self) -> Result<Vec<String>, AdminError> {
        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        let path = if self.is_unifi_os.load(Ordering::SeqCst) {
            "/proxy/network/api/self/sites"
        } else {
            "/api/self/sites"
        };

        let resp = self
            .transport
            .request(&self.endpoint, "GET", path, None, Some(creds))?;
        let mut sites = Vec::new();

        if let Some(arr) = resp.get("data").and_then(|d| d.as_array()) {
            for site_obj in arr {
                if let Some(name) = site_obj.get("name").and_then(|n| n.as_str()) {
                    sites.push(name.to_string());
                }
            }
        }

        if sites.is_empty() {
            sites.push("default".to_string());
        }

        Ok(sites)
    }

    /// Queries the UniFi connected-client inventory for the active site.
    pub fn list_connected_clients(&self) -> Result<Vec<UnifiClientEntry>, AdminError> {
        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        let path = self.build_api_path("stat/sta");
        let resp = self
            .transport
            .request(&self.endpoint, "GET", &path, None, Some(creds))?;

        let mut clients = Vec::new();
        if let Some(arr) = resp.get("data").and_then(|d| d.as_array()) {
            for item in arr {
                let id = item
                    .get("_id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .to_string();
                let mac_str = item.get("mac").and_then(|m| m.as_str()).unwrap_or("");
                let mac: MacAddress = mac_str.parse().unwrap_or(MacAddress::ZERO);
                let ip = item
                    .get("ip")
                    .and_then(|i| i.as_str())
                    .and_then(|s| s.parse::<Ipv4Addr>().ok());
                let name = item
                    .get("name")
                    .or_else(|| item.get("hostname"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());
                let is_wired = item
                    .get("is_wired")
                    .and_then(|w| w.as_bool())
                    .unwrap_or(false);
                let network = item
                    .get("network")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());
                let uptime = item.get("uptime").and_then(|u| u.as_u64()).unwrap_or(0);

                clients.push(UnifiClientEntry {
                    id,
                    ip,
                    mac,
                    name,
                    is_wired,
                    network,
                    uptime,
                });
            }
        }

        Ok(clients)
    }
}

impl RouterAdminProvider for UnifiAdminProvider {
    fn name(&self) -> &'static str {
        "Ubiquiti-UniFi-Network"
    }

    fn detect_identity(&self) -> Result<RouterIdentity, AdminError> {
        if self.force_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout("UniFi identity probe timed out".into()));
        }

        if let Some(cached) = self.discovered_identity.read().clone() {
            return Ok(cached);
        }

        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        let path = self.build_api_path("stat/sysinfo");
        let resp = self
            .transport
            .request(&self.endpoint, "GET", &path, None, Some(creds))?;

        let info = resp
            .get("data")
            .and_then(|d| d.as_array())
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or(json!({}));

        let model = info.get("model").and_then(|m| m.as_str()).unwrap_or("");
        let hostname = info.get("hostname").and_then(|h| h.as_str()).unwrap_or("");
        let version = info
            .get("version")
            .or_else(|| info.get("unifi_version"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Identity verification: Connected device must be a UniFi console or Network application
        if !model.contains("UniFi")
            && !hostname.contains("UniFi")
            && !info
                .as_object()
                .map(|o| o.contains_key("unifi_version"))
                .unwrap_or(false)
        {
            return Err(AdminError::IdentityMismatch(format!(
                "Connected controller is not an authentic Ubiquiti UniFi gateway (detected model: '{}', hostname: '{}')",
                model, hostname
            )));
        }

        let mut identity = RouterIdentity::new(self.target_ip);
        identity.manufacturer = Some("Ubiquiti Networks".to_string());
        identity.model_name = Some(if !model.is_empty() {
            model.to_string()
        } else {
            "UniFi Network Application".to_string()
        });
        identity.firmware_version = Some(version.to_string());
        identity.interface_name = Some(format!("Site: {}", self.site()));

        *self.discovered_identity.write() = Some(identity.clone());
        Ok(identity)
    }

    fn inspect_capabilities(&self) -> RouterCapabilityMatrix {
        let is_authed = self.is_authenticated();
        if !is_authed {
            return RouterCapabilityMatrix {
                authenticated_admin_interfaces: CapabilityClassification::Conditional(
                    "Requires valid Ubiquiti UniFi credentials with Administrator permissions on target site".into(),
                ),
                ..Default::default()
            };
        }

        RouterCapabilityMatrix {
            read_only_discovery: CapabilityClassification::Implemented,
            host_inventory: CapabilityClassification::Implemented,
            device_identification_interface_type: CapabilityClassification::Implemented,
            ipv4_policy_enforcement: CapabilityClassification::Implemented,
            ipv6_policy_enforcement: CapabilityClassification::Implemented,
            per_device_access_policy: CapabilityClassification::Implemented,
            network_wide_access_policy: CapabilityClassification::Implemented,
            authenticated_admin_interfaces: CapabilityClassification::Implemented,
            timed_policy_auto_recovery: CapabilityClassification::NotImplemented,
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
                        "Target list contains UniFi Controller / Gateway management IP ({}); operation halted to prevent administrator lockout",
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
                "UNSUPPORTED: UniFi Network lacks a controller-resident autonomous scheduler. Temporary policies require external controller-driven reconciliation or explicit resumption.".to_string()
            }
        };

        let mut risks = Vec::new();
        if let PolicyScope::NetworkWide = req.scope {
            risks.push(
                "All client devices on the UniFi network will lose outbound WAN access".into(),
            );
            risks.push("UniFi Console administration (port 443/8443) and intra-LAN routing remain 100% accessible".into());
        }
        if let PolicyDuration::Temporary(_) = req.duration {
            risks.push("Autonomous controller-side expiry is NOT supported on UniFi Network; temporary policies with guaranteed offline recovery must be rejected.".into());
        }

        Ok(OperationPlan {
            provider_name: self.name().to_string(),
            router_identity: identity,
            target_scope: req.scope.clone(),
            target_count,
            duration: req.duration.clone(),
            persistence: req.persistence.clone(),
            discovered_services: vec![
                "unifi:api/auth".into(),
                "unifi:stat/sysinfo".into(),
                "unifi:stat/sta".into(),
                "unifi:trafficrules".into(),
            ],
            supported_capabilities: vec![
                "UniFi-Traffic-Rules-Engine".into(),
                "Per-Device-IP-And-MAC-Blocking".into(),
                "Dual-Stack-IPv4-IPv6-Transit-Rejection".into(),
                "Wired-And-Wireless-Client-Filtering".into(),
                "Preserved-Controller-Management-Plane".into(),
            ],
            unsupported_capabilities: if let PolicyDuration::Temporary(_) = req.duration {
                vec!["Autonomous-Controller-Side-Timed-Recovery".into()]
            } else {
                Vec::new()
            },
            required_auth: "UniFi Session Token / API Key".into(),
            auth_established: self.is_authenticated(),
            expected_wan_impact: "Outbound internet transit rejected by UniFi Traffic Rules engine; targeted devices cannot access WAN".into(),
            expected_lan_impact: "Controller management interface and intra-LAN local traffic remain 100% accessible".into(),
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

        let path = self.build_trafficrule_path(None);
        let resp = self
            .transport
            .request(&self.endpoint, "GET", &path, None, Some(creds))?;

        let mut policies = Vec::new();

        if let Some(arr) = resp.get("data").and_then(|d| d.as_array()) {
            for rule in arr {
                let desc = rule
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("");
                if !desc.contains("Rustrict") && !desc.contains("rustrict") {
                    continue; // Preserve unrelated user-created rules
                }

                let rule_id = rule
                    .get("_id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("unknown");
                let (applied_at, expires_at) = parse_policy_timestamps(desc);

                let scope = if desc.contains("network_wide") {
                    PolicyScope::NetworkWide
                } else if let Some(targets) = rule.get("target_devices").and_then(|t| t.as_array())
                {
                    let mut ips = Vec::new();
                    for t in targets {
                        if t.get("matching_target").and_then(|m| m.as_str()) == Some("IP") {
                            if let Some(ip_str) = t.get("value").and_then(|v| v.as_str()) {
                                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                                    ips.push(ip);
                                }
                            }
                        }
                    }
                    if !ips.is_empty() {
                        PolicyScope::SpecificTargets(ips)
                    } else {
                        continue;
                    }
                } else {
                    continue;
                };

                policies.push(ActivePolicyStatus::new(
                    format!("unifi_{}", rule_id),
                    scope,
                    applied_at,
                    expires_at,
                    true,
                    format!("UniFi-TrafficRule:{}", rule_id),
                    false,
                ));
            }
        }

        Ok(policies)
    }

    fn is_authenticated(&self) -> bool {
        self.credentials.read().is_some()
    }

    fn apply_policy(&self, req: &OperationPlanRequest) -> Result<ActivePolicyStatus, AdminError> {
        // UniFi Network API does not provide a controller-resident autonomous scheduler.
        // Fail closed on temporary durations rather than falsely promising automatic recovery.
        if let PolicyDuration::Temporary(_) = req.duration {
            return Err(AdminError::UnsupportedOperation(
                "UniFi Network API does not provide a controller-resident autonomous scheduler or watchdog. Temporary policies with guaranteed autonomous expiry cannot be enforced independently; operation rejected to prevent unrecoverable restrictions.".into()
            ));
        }

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

        let exp_str = expires_at
            .map(|e| e.to_string())
            .unwrap_or_else(|| "0".into());

        let (policy_id, description, target_devices) = match &req.scope {
            PolicyScope::SpecificTargets(targets) => {
                if targets.is_empty() {
                    return Err(AdminError::ScopeViolation(
                        "Target list cannot be empty".into(),
                    ));
                }
                let mut dev_list = Vec::new();
                for (i, t) in targets.iter().enumerate() {
                    dev_list.push(json!({
                        "matching_target": "IP",
                        "value": t.to_string()
                    }));
                    if let Some(mac) = req.target_macs.get(i) {
                        dev_list.push(json!({
                            "matching_target": "MAC",
                            "value": mac.to_string()
                        }));
                    }
                }
                let pol_id = format!(
                    "rustrict_pause_{}",
                    targets[0].to_string().replace('.', "_")
                );
                let desc = format!("Rustrict:pol={}:app={}:exp={}", pol_id, now, exp_str);
                (pol_id, desc, dev_list)
            }
            PolicyScope::NetworkWide => {
                let pol_id = "rustrict_pause_network_wide".to_string();
                let desc = format!(
                    "Rustrict:pol={}:app={}:exp={}:network_wide",
                    pol_id, now, exp_str
                );
                let dev_list = vec![json!({
                    "matching_target": "ALL_DEVICES"
                })];
                (pol_id, desc, dev_list)
            }
        };

        let rule_payload = json!({
            "action": "BLOCK",
            "target_devices": target_devices,
            "traffic": "INTERNET",
            "description": description,
            "enabled": true,
            "schedule": {
                "mode": "ALWAYS"
            }
        });

        let path = self.build_trafficrule_path(None);
        let resp = self.transport.request(
            &self.endpoint,
            "POST",
            &path,
            Some(rule_payload),
            Some(creds),
        )?;

        let rule_id = resp
            .get("data")
            .and_then(|d| d.as_array())
            .and_then(|a| a.first())
            .and_then(|r| r.get("_id"))
            .and_then(|i| i.as_str())
            .unwrap_or("rule_new");

        let status = ActivePolicyStatus::new(
            policy_id.clone(),
            req.scope.clone(),
            now,
            expires_at,
            true,
            format!("UniFi-TrafficRule:{}", rule_id),
            false,
        );

        self.active_policies
            .write()
            .insert(policy_id, status.clone());
        Ok(status)
    }

    fn resume_policy(&self, scope: &PolicyScope) -> Result<Vec<String>, AdminError> {
        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        let path = self.build_trafficrule_path(None);
        let resp = self
            .transport
            .request(&self.endpoint, "GET", &path, None, Some(creds))?;

        let mut resumed_ids = Vec::new();

        if let Some(arr) = resp.get("data").and_then(|d| d.as_array()) {
            for rule in arr {
                let desc = rule
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("");
                if !desc.contains("Rustrict") && !desc.contains("rustrict") {
                    continue; // Never delete user rules
                }

                let rule_id = rule.get("_id").and_then(|i| i.as_str()).unwrap_or("");
                let matches = match scope {
                    PolicyScope::NetworkWide => true,
                    PolicyScope::SpecificTargets(targets) => targets
                        .iter()
                        .any(|t| desc.contains(&t.to_string().replace('.', "_"))),
                };

                if matches && !rule_id.is_empty() {
                    let del_path = self.build_trafficrule_path(Some(rule_id));
                    self.transport.request(
                        &self.endpoint,
                        "DELETE",
                        &del_path,
                        None,
                        Some(creds),
                    )?;
                    resumed_ids.push(rule_id.to_string());
                }
            }
        }

        if resumed_ids.is_empty() {
            return Err(AdminError::PolicyNotFound(
                "No active UniFi Traffic Rule found matching the specified scope".into(),
            ));
        }

        // Clean local tracking
        let mut active = self.active_policies.write();
        active.retain(|_, pol| match scope {
            PolicyScope::NetworkWide => false,
            PolicyScope::SpecificTargets(targets) => match &pol.scope {
                PolicyScope::SpecificTargets(t) => !t.iter().any(|ip| targets.contains(ip)),
                PolicyScope::NetworkWide => true,
            },
        });

        Ok(resumed_ids)
    }

    fn reconcile_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError> {
        let current_rules = self.query_active_policies()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut valid_policies = Vec::new();
        let creds_guard = self.credentials.read();

        for rule in current_rules {
            if rule.is_expired(now) {
                // Autonomously purge expired rule from UniFi Controller
                if let Some(creds) = creds_guard.as_ref() {
                    let raw_id = rule.policy_id.trim_start_matches("unifi_");
                    let del_path = self.build_trafficrule_path(Some(raw_id));
                    let _ = self.transport.request(
                        &self.endpoint,
                        "DELETE",
                        &del_path,
                        None,
                        Some(creds),
                    );
                }
            } else {
                valid_policies.push(rule);
            }
        }

        Ok(valid_policies)
    }

    fn adjust_policy_duration(
        &self,
        scope: &PolicyScope,
        new_duration: &PolicyDuration,
    ) -> Result<ActivePolicyStatus, AdminError> {
        if let PolicyDuration::Temporary(_) = new_duration {
            return Err(AdminError::UnsupportedOperation(
                "UniFi Network API lacks an autonomous controller-resident scheduler. Cannot adjust policy to a temporary duration with guaranteed autonomous recovery.".into()
            ));
        }

        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let new_expires_at = match new_duration {
            PolicyDuration::Temporary(d) => Some(now + d.as_secs()),
            PolicyDuration::Indefinite => None,
        };

        let path = self.build_trafficrule_path(None);
        let resp = self
            .transport
            .request(&self.endpoint, "GET", &path, None, Some(creds))?;

        let mut target_rule_id = None;
        let mut target_pol_id = None;
        let mut target_rule_obj = None;

        if let Some(arr) = resp.get("data").and_then(|d| d.as_array()) {
            for rule in arr {
                let desc = rule
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("");
                if !desc.contains("Rustrict") && !desc.contains("rustrict") {
                    continue;
                }

                let rule_id = rule.get("_id").and_then(|i| i.as_str()).unwrap_or("");
                let matches = match scope {
                    PolicyScope::NetworkWide => desc.contains("network_wide"),
                    PolicyScope::SpecificTargets(targets) => targets
                        .iter()
                        .any(|t| desc.contains(&t.to_string().replace('.', "_"))),
                };

                if matches && !rule_id.is_empty() {
                    target_rule_id = Some(rule_id.to_string());
                    target_rule_obj = Some(rule.clone());
                    if let Some(p_start) = desc.find("pol=") {
                        let sub = &desc[p_start + 4..];
                        let end = sub.find(':').unwrap_or(sub.len());
                        target_pol_id = Some(sub[..end].to_string());
                    }
                    break;
                }
            }
        }

        let rule_id = target_rule_id.ok_or_else(|| {
            AdminError::PolicyNotFound(
                "No active UniFi Traffic Rule found to adjust duration".into(),
            )
        })?;
        let pol_id = target_pol_id.unwrap_or_else(|| "rustrict_unifi".to_string());

        let exp_str = new_expires_at
            .map(|e| e.to_string())
            .unwrap_or_else(|| "0".into());
        let updated_desc = format!("Rustrict:pol={}:app={}:exp={}", pol_id, now, exp_str);

        let mut update_payload = target_rule_obj.unwrap_or(json!({}));
        update_payload["description"] = Value::String(updated_desc);

        let put_path = self.build_trafficrule_path(Some(&rule_id));
        self.transport.request(
            &self.endpoint,
            "PUT",
            &put_path,
            Some(update_payload),
            Some(creds),
        )?;

        Ok(ActivePolicyStatus::new(
            pol_id,
            scope.clone(),
            now,
            new_expires_at,
            true,
            format!("UniFi-TrafficRule:{}", rule_id),
            false,
        ))
    }

    fn list_devices(
        &self,
    ) -> Result<Vec<crate::gateway::admin::diagnostics::RouterDeviceEntry>, AdminError> {
        let clients = self.list_connected_clients()?;
        let devices = clients
            .into_iter()
            .map(|c| {
                let mut entry = crate::gateway::admin::diagnostics::RouterDeviceEntry::new();
                if let Some(ip) = c.ip {
                    entry = entry.with_ip(ip);
                }
                if !c.mac.is_zero() {
                    entry = entry.with_mac(c.mac);
                }
                if let Some(name) = c.name {
                    entry = entry.with_hostname(name);
                }
                let iface = if c.is_wired {
                    "Wired (Ethernet)"
                } else {
                    "Wireless (Wi-Fi)"
                };
                entry = entry.with_interface(iface);
                entry = entry.with_active(true);
                entry = entry.with_uptime(c.uptime);
                entry
            })
            .collect();
        Ok(devices)
    }
}
