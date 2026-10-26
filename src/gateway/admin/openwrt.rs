use parking_lot::RwLock;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::gateway::admin::capabilities::{CapabilityClassification, RouterCapabilityMatrix};
use crate::gateway::admin::credentials::RouterCredentials;
use crate::gateway::admin::plan::{
    ActivePolicyStatus, AdminError, OperationPlan, OperationPlanRequest, PolicyDuration,
    PolicyPersistence, PolicyScope, RouterIdentity,
};
use crate::gateway::admin::provider::RouterAdminProvider;

/// Pluggable RPC transport abstraction for OpenWrt ubus calls.
/// Enables deterministic offline testing with mock JSON-RPC fixtures.
pub trait OpenWrtTransport: Send + Sync {
    fn call(
        &self,
        endpoint: &str,
        object: &str,
        method: &str,
        params: Value,
        session_id: &str,
    ) -> Result<Value, AdminError>;

    fn transport_name(&self) -> &'static str {
        "HTTP/ubus"
    }

    fn is_ssh(&self) -> bool {
        false
    }
}

/// Standard production HTTP transport using TcpStream for OpenWrt JSON-RPC.
pub struct HttpOpenWrtTransport {
    pub timeout: Duration,
}

impl Default for HttpOpenWrtTransport {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(1500),
        }
    }
}

impl OpenWrtTransport for HttpOpenWrtTransport {
    fn call(
        &self,
        endpoint: &str,
        object: &str,
        method: &str,
        params: Value,
        session_id: &str,
    ) -> Result<Value, AdminError> {
        let parsed_url = parse_endpoint_url(endpoint)?;
        let mut stream = TcpStream::connect_timeout(&parsed_url.socket_addr, self.timeout)
            .map_err(|e| {
                AdminError::Timeout(format!("Connection to OpenWrt router timed out: {}", e))
            })?;

        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));

        let rpc_body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "call",
            "params": [
                session_id,
                object,
                method,
                params
            ]
        });

        let body_str = rpc_body.to_string();
        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            parsed_url.path,
            parsed_url.host_header,
            body_str.len(),
            body_str
        );

        stream.write_all(request.as_bytes()).map_err(|e| {
            AdminError::CommunicationError(format!("Failed to send RPC request: {}", e))
        })?;

        let mut response_buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut read_timed_out = false;
        const MAX_HTTP_RESPONSE_BYTES: usize = 2 * 1024 * 1024; // 2 MiB
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if response_buf.len() + n > MAX_HTTP_RESPONSE_BYTES {
                        return Err(AdminError::CommunicationError(
                            "OpenWrt HTTP response exceeded maximum buffer limit (2 MiB)".into(),
                        ));
                    }
                    response_buf.extend_from_slice(&chunk[..n]);
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock
                    {
                        read_timed_out = true;
                    }
                    break;
                }
            }
        }

        if response_buf.is_empty() && read_timed_out {
            return Err(AdminError::Timeout(
                "Communication with OpenWrt endpoint timed out while reading response".into(),
            ));
        }

        let resp_str = String::from_utf8_lossy(&response_buf);
        let body_start = resp_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
        let header_part = &resp_str[..body_start];

        let status_line = header_part.lines().next().unwrap_or("");
        if status_line.contains(" 301 ")
            || status_line.contains(" 302 ")
            || status_line.contains(" 307 ")
            || status_line.contains(" 308 ")
        {
            return Err(AdminError::SecurityViolation(format!(
                "Unexpected HTTP redirect from router endpoint ({}). Redirection rejected to prevent credential forwarding.",
                status_line.trim()
            )));
        }

        let json_part = &resp_str[body_start..];

        let parsed: Value = serde_json::from_str(json_part).map_err(|e| {
            AdminError::CommunicationError(format!(
                "Invalid JSON-RPC response from OpenWrt endpoint: {}",
                e
            ))
        })?;

        // OpenWrt ubus returns {"result": [status_code, data]}
        if let Some(arr) = parsed.get("result").and_then(|r| r.as_array()) {
            if arr.is_empty() {
                return Err(AdminError::CommunicationError(
                    "Empty result array in ubus response".into(),
                ));
            }
            let code = arr[0].as_i64().unwrap_or(-1);
            if code == 6 {
                return Err(AdminError::AuthenticationFailed(
                    "OpenWrt ubus permission denied or session expired (code 6)".into(),
                ));
            } else if code != 0 {
                return Err(AdminError::CommunicationError(format!(
                    "OpenWrt ubus call failed with status code {}",
                    code
                )));
            }
            return Ok(arr.get(1).cloned().unwrap_or(Value::Null));
        }

        if let Some(err) = parsed.get("error") {
            return Err(AdminError::CommunicationError(format!(
                "OpenWrt JSON-RPC error: {}",
                err
            )));
        }

        Ok(parsed)
    }
}

struct ParsedEndpoint {
    socket_addr: SocketAddr,
    host_header: String,
    path: String,
}

fn parse_endpoint_url(endpoint: &str) -> Result<ParsedEndpoint, AdminError> {
    let clean = endpoint
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let (host_port, path) = if let Some(slash_idx) = clean.find('/') {
        (&clean[..slash_idx], &clean[slash_idx..])
    } else {
        (clean, "/ubus")
    };

    let (ip_str, port) = if let Some(colon_idx) = host_port.find(':') {
        let ip = &host_port[..colon_idx];
        let p = host_port[colon_idx + 1..].parse::<u16>().map_err(|_| {
            AdminError::CommunicationError(format!("Invalid port in endpoint '{}'", endpoint))
        })?;
        (ip, p)
    } else {
        (host_port, 80)
    };

    let ip: Ipv4Addr = ip_str.parse().map_err(|_| {
        AdminError::CommunicationError(format!("Invalid IPv4 address in endpoint '{}'", endpoint))
    })?;

    Ok(ParsedEndpoint {
        socket_addr: SocketAddr::new(std::net::IpAddr::V4(ip), port),
        host_header: host_port.to_string(),
        path: if path.is_empty() {
            "/ubus".to_string()
        } else {
            path.to_string()
        },
    })
}

/// Production and test-ready authenticated OpenWrt router administration provider.
pub struct OpenWrtAdminProvider {
    pub endpoint: String,
    pub target_ip: Ipv4Addr,
    credentials: Arc<RwLock<Option<RouterCredentials>>>,
    session_id: Arc<RwLock<Option<String>>>,
    session_expires_at: Arc<RwLock<Option<u64>>>,
    discovered_identity: Arc<RwLock<Option<RouterIdentity>>>,
    transport: Box<dyn OpenWrtTransport>,
    force_timeout: Arc<AtomicBool>,
}

impl OpenWrtAdminProvider {
    pub fn new(target_ip: Ipv4Addr, endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            target_ip,
            credentials: Arc::new(RwLock::new(None)),
            session_id: Arc::new(RwLock::new(None)),
            session_expires_at: Arc::new(RwLock::new(None)),
            discovered_identity: Arc::new(RwLock::new(None)),
            transport: Box::new(HttpOpenWrtTransport::default()),
            force_timeout: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_transport(mut self, transport: Box<dyn OpenWrtTransport>) -> Self {
        self.transport = transport;
        self
    }

    pub fn set_credentials(&self, creds: RouterCredentials) {
        *self.credentials.write() = Some(creds);
        *self.session_id.write() = None;
        *self.session_expires_at.write() = None;
    }

    pub fn set_force_timeout(&self, timeout: bool) {
        self.force_timeout.store(timeout, Ordering::SeqCst);
    }

    /// Authenticates with the OpenWrt router via ubus session.login
    pub fn login(&self) -> Result<String, AdminError> {
        if self.force_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout(
                "OpenWrt authentication probe timed out".into(),
            ));
        }

        let creds_guard = self.credentials.read();
        let params = if self.transport.is_ssh() {
            json!({
                "username": creds_guard.as_ref().map(|c| c.username.clone()).unwrap_or_else(|| "root".to_string()),
                "auth_method": "ssh_pubkey"
            })
        } else {
            let creds = creds_guard.as_ref().ok_or_else(|| {
                AdminError::AuthenticationFailed("No router credentials configured".into())
            })?;
            json!({
                "username": creds.username,
                "password": creds.password.expose()
            })
        };

        // 00000000000000000000000000000000 represents the null initial session ID
        let resp = self.transport.call(
            &self.endpoint,
            "session",
            "login",
            params,
            "00000000000000000000000000000000",
        )?;

        let token = resp
            .get("ubus_rpc_session")
            .and_then(|t| t.as_str())
            .ok_or_else(|| {
                AdminError::AuthenticationFailed(
                    "Invalid response from OpenWrt login (missing ubus_rpc_session)".into(),
                )
            })?
            .to_string();

        let timeout_secs = resp
            .get("expires")
            .or_else(|| resp.get("timeout"))
            .and_then(|t| t.as_u64())
            .unwrap_or(300);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        *self.session_id.write() = Some(token.clone());
        *self.session_expires_at.write() = Some(now + timeout_secs);

        Ok(token)
    }

    /// Retrieves an active session token, re-authenticating automatically if expired
    fn get_valid_session(&self) -> Result<String, AdminError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        {
            let session_guard = self.session_id.read();
            let expires_guard = self.session_expires_at.read();
            if let (Some(token), Some(exp)) = (session_guard.as_ref(), *expires_guard) {
                if now + 10 < exp {
                    return Ok(token.clone());
                }
            }
        }

        // Re-authenticate
        self.login()
    }

    pub fn transport(&self) -> &dyn OpenWrtTransport {
        self.transport.as_ref()
    }

    /// Verifies or installs the router-resident autonomous cron watchdog for self-healing recovery.
    /// Fails closed if the router endpoint does not support script or crontab writes.
    pub fn ensure_router_watchdog(&self, session: &str) -> Result<(), AdminError> {
        let script_content = r#"#!/bin/sh
# Rustrict Autonomous Recovery Watchdog
# Scans active UCI firewall rules for expired rustrict policies and unblocks them.
changed=0
now=$(date +%s)
for r in $(uci show firewall 2>/dev/null | grep 'name=.rustrict_pause' | cut -d. -f2); do
    exp=$(uci -q get firewall.$r.comment | sed -n 's/.*exp=\([0-9]*\).*/\1/p')
    if [ -n "$exp" ] && [ "$exp" -ne 0 ] && [ "$now" -ge "$exp" ]; then
        uci delete firewall.$r
        changed=1
    fi
done
if [ "$changed" -eq 1 ]; then
    uci commit firewall
    /etc/init.d/firewall reload
fi
"#;

        // Step 1: Install or update dedicated script at /etc/rustrict/watchdog.sh
        let script_res = self.transport.call(
            &self.endpoint,
            "file",
            "write",
            json!({
                "path": "/etc/rustrict/watchdog.sh",
                "data": script_content
            }),
            session,
        );

        if let Err(e) = script_res {
            return Err(AdminError::UnsupportedOperation(format!(
                "Autonomous router-side recovery could not be established on this endpoint (failed to install watchdog script at /etc/rustrict/watchdog.sh: {}). Timed operations rejected to prevent unrecoverable network restriction.",
                e
            )));
        }

        // Step 2: Read crontab
        let read_res = self.transport.call(
            &self.endpoint,
            "file",
            "read",
            json!({ "path": "/etc/crontabs/root" }),
            session,
        );

        let existing_data = match read_res {
            Ok(v) => v
                .get("data")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string(),
            Err(e) => {
                return Err(AdminError::UnsupportedOperation(format!(
                    "Autonomous router-side recovery could not be established on this endpoint (crontab access failed: {}). Timed operations rejected to prevent unrecoverable network restriction. Use persistent/indefinite policy or enable router crontab access.",
                    e
                )));
            }
        };

        let watchdog_block = "# BEGIN RUSTRICT WATCHDOG: rustrict_pause autonomous recovery & /etc/init.d/firewall reload\n* * * * * /bin/sh /etc/rustrict/watchdog.sh\n# END RUSTRICT WATCHDOG\n";

        if !existing_data.contains("/etc/rustrict/watchdog.sh") {
            // Strip any prior older or duplicate rustrict watchdog blocks/lines
            let mut cleaned_lines = Vec::new();
            let mut in_rustrict_block = false;
            for line in existing_data.lines() {
                if line.starts_with("# BEGIN RUSTRICT WATCHDOG") {
                    in_rustrict_block = true;
                    continue;
                }
                if line.starts_with("# END RUSTRICT WATCHDOG") {
                    in_rustrict_block = false;
                    continue;
                }
                if in_rustrict_block || line.contains("rustrict_pause") {
                    continue;
                }
                cleaned_lines.push(line);
            }

            let mut updated_data = cleaned_lines.join("\n");
            if !updated_data.is_empty() && !updated_data.ends_with('\n') {
                updated_data.push('\n');
            }
            updated_data.push_str(watchdog_block);

            let write_res = self.transport.call(
                &self.endpoint,
                "file",
                "write",
                json!({
                    "path": "/etc/crontabs/root",
                    "data": updated_data
                }),
                session,
            );

            if let Err(e) = write_res {
                return Err(AdminError::UnsupportedOperation(format!(
                    "Autonomous router-side recovery could not be established on this endpoint (failed to install crontab watchdog: {}). Timed operations rejected to prevent unrecoverable network restriction.",
                    e
                )));
            }
        }

        Ok(())
    }

    /// Removes the dedicated Rustrict watchdog script and crontab scheduler entry.
    pub fn uninstall_router_watchdog(&self, session: &str) -> Result<(), AdminError> {
        let read_res = self.transport.call(
            &self.endpoint,
            "file",
            "read",
            json!({ "path": "/etc/crontabs/root" }),
            session,
        );

        if let Ok(v) = read_res {
            let data = v.get("data").and_then(|d| d.as_str()).unwrap_or("");
            if data.contains("RUSTRICT WATCHDOG") || data.contains("rustrict_pause") {
                let mut cleaned_lines = Vec::new();
                let mut in_rustrict_block = false;
                for line in data.lines() {
                    if line.starts_with("# BEGIN RUSTRICT WATCHDOG") {
                        in_rustrict_block = true;
                        continue;
                    }
                    if line.starts_with("# END RUSTRICT WATCHDOG") {
                        in_rustrict_block = false;
                        continue;
                    }
                    if in_rustrict_block || line.contains("rustrict_pause") {
                        continue;
                    }
                    cleaned_lines.push(line);
                }

                let cleaned_data = cleaned_lines.join("\n");
                let _ = self.transport.call(
                    &self.endpoint,
                    "file",
                    "write",
                    json!({
                        "path": "/etc/crontabs/root",
                        "data": cleaned_data
                    }),
                    session,
                );
            }
        }

        let _ = self.transport.call(
            &self.endpoint,
            "file",
            "write",
            json!({
                "path": "/etc/rustrict/watchdog.sh",
                "data": ""
            }),
            session,
        );

        Ok(())
    }

    /// Checks if the autonomous recovery watchdog is currently active in router crontab.
    pub fn is_watchdog_installed(&self, session: &str) -> Result<bool, AdminError> {
        let read_res = self.transport.call(
            &self.endpoint,
            "file",
            "read",
            json!({ "path": "/etc/crontabs/root" }),
            session,
        )?;
        let data = read_res.get("data").and_then(|d| d.as_str()).unwrap_or("");
        Ok(data.contains("watchdog.sh") || data.contains("rustrict_pause"))
    }
}

impl RouterAdminProvider for OpenWrtAdminProvider {
    fn name(&self) -> &'static str {
        match self.transport.transport_name() {
            "SSH" => "OpenWrt-SSH",
            _ => "OpenWrt-ubus",
        }
    }

    fn detect_identity(&self) -> Result<RouterIdentity, AdminError> {
        if self.force_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout("Identity probe timed out".into()));
        }

        if let Some(cached) = self.discovered_identity.read().clone() {
            return Ok(cached);
        }

        let session = self.get_valid_session()?;
        let resp = self
            .transport
            .call(&self.endpoint, "system", "board", json!({}), &session)?;

        let release = resp.get("release");
        let dist = release
            .and_then(|r| r.get("distribution"))
            .and_then(|d| d.as_str())
            .unwrap_or("");

        if !dist.eq_ignore_ascii_case("OpenWrt") {
            return Err(AdminError::IdentityMismatch(format!(
                "Connected target is not an OpenWrt gateway (detected distribution: '{}')",
                dist
            )));
        }

        let model = resp
            .get("model")
            .and_then(|m| m.as_str())
            .map(|s| s.to_string());
        let version = release
            .and_then(|r| r.get("version"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let revision = release
            .and_then(|r| r.get("revision"))
            .and_then(|r| r.as_str())
            .map(|s| s.to_string());

        let mut identity = RouterIdentity::new(self.target_ip);
        identity.manufacturer = Some("OpenWrt Community".to_string());
        identity.model_name = model;
        identity.firmware_version = version;
        identity.hardware_version = revision;

        *self.discovered_identity.write() = Some(identity.clone());
        Ok(identity)
    }

    fn inspect_capabilities(&self) -> RouterCapabilityMatrix {
        let is_authed = self.is_authenticated();
        if !is_authed {
            let mut caps = RouterCapabilityMatrix::default();
            let req_desc = if self.transport.is_ssh() {
                "Requires SSH public-key authentication with root privileges"
            } else {
                "Requires valid OpenWrt ubus administrative credentials"
            };
            caps.authenticated_admin_interfaces =
                CapabilityClassification::Conditional(req_desc.into());
            return caps;
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
            timed_policy_auto_recovery: CapabilityClassification::Implemented,
            persistence_after_app_exit: CapabilityClassification::Implemented,
            persistence_after_host_shutdown: CapabilityClassification::Implemented,
        }
    }

    fn plan_operation(&self, req: &OperationPlanRequest) -> Result<OperationPlan, AdminError> {
        let identity = self.detect_identity()?;

        // Prevent target lockout: cannot pause the router's own management IP
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
            PolicyDuration::Temporary(d) => format!(
                "Automatic timed rollback via OpenWrt UCI firewall coordinator (Duration: {:.1} minutes)",
                d.as_secs_f64() / 60.0
            ),
            PolicyDuration::Indefinite => {
                "Manual revocation required via CLI ('router resume <target>')".into()
            }
        };

        let risks = match (&req.scope, &req.persistence) {
            (PolicyScope::NetworkWide, PolicyPersistence::RouterPersistent) => vec![
                "WARNING: Network-wide policy will halt internet access for all devices on LAN.".into(),
                "Router administrative access (port 80/443) and LAN-internal communication remain safe.".into(),
                "Persistent policy will survive OpenWrt router reboots until manually resumed.".into(),
            ],
            (PolicyScope::NetworkWide, PolicyPersistence::VolatileSession) => vec![
                "Network-wide temporary policy will halt transit internet access for all connected clients.".into(),
                "LAN communication between local devices remains active.".into(),
            ],
            (PolicyScope::SpecificTargets(_), _) => vec![
                "Targeted firewall rule rejects client WAN transit at router forward chain.".into(),
                "Dual-stack IPv4 and IPv6 traffic is simultaneously filtered via MAC match.".into(),
            ],
        };

        Ok(OperationPlan {
            provider_name: self.name().to_string(),
            router_identity: identity,
            target_scope: req.scope.clone(),
            target_count,
            duration: req.duration.clone(),
            persistence: req.persistence.clone(),
            discovered_services: vec![
                "ubus:session".into(),
                "ubus:system".into(),
                "ubus:uci".into(),
                "firewall4:nftables".into(),
            ],
            supported_capabilities: vec![
                "OpenWrt ubus JSON-RPC Authentication".into(),
                "UCI Firewall Rule Injection".into(),
                "Dual-Stack IPv4 + IPv6 MAC-Based Transit Drop".into(),
                "Preserved Local Management Plane (HTTP/HTTPS)".into(),
            ],
            unsupported_capabilities: Vec::new(),
            required_auth: "OpenWrt ubus Session Token".into(),
            auth_established: self.is_authenticated(),
            expected_wan_impact:
                "Outbound internet transit rejected; client packets receive ICMP Admin Prohibited"
                    .into(),
            expected_lan_impact:
                "Intra-LAN traffic and router management ports (80, 443, 22) remain 100% accessible"
                    .into(),
            management_plane_safe: true,
            recovery_mechanism: recovery,
            uncertainties_and_risks: risks,
            is_dry_run: true,
        })
    }

    fn query_active_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError> {
        let session = self.get_valid_session()?;
        let resp = self.transport.call(
            &self.endpoint,
            "uci",
            "get",
            json!({ "config": "firewall" }),
            &session,
        )?;

        let mut active = Vec::new();
        if let Some(values) = resp.get("values").and_then(|v| v.as_object()) {
            for (section_name, section_val) in values {
                let name = section_val
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("");

                if !name.starts_with("rustrict_") {
                    continue;
                }

                let comment = section_val
                    .get("comment")
                    .and_then(|c| c.as_str())
                    .unwrap_or("");

                let (applied_at, expires_at) = parse_policy_timestamps(comment);

                let scope = if name == "rustrict_pause_network_wide" {
                    PolicyScope::NetworkWide
                } else if let Some(ip_str) = section_val.get("src_ip").and_then(|i| i.as_str()) {
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        PolicyScope::SpecificTargets(vec![ip])
                    } else {
                        PolicyScope::NetworkWide
                    }
                } else {
                    PolicyScope::NetworkWide
                };

                active.push(ActivePolicyStatus::new(
                    name.to_string(),
                    scope,
                    applied_at,
                    expires_at,
                    true,
                    format!("OpenWrt-UCI:{}", section_name),
                    expires_at.is_some(),
                ));
            }
        }

        Ok(active)
    }

    fn is_authenticated(&self) -> bool {
        let session_guard = self.session_id.read();
        let expires_guard = self.session_expires_at.read();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let (Some(_), Some(exp)) = (session_guard.as_ref(), *expires_guard) {
            now < exp
        } else {
            false
        }
    }

    fn apply_policy(&self, req: &OperationPlanRequest) -> Result<ActivePolicyStatus, AdminError> {
        // Step 1: Pre-validation & dry run check
        let _plan = self.plan_operation(req)?;

        let session = self.get_valid_session()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expires_at = match req.duration {
            PolicyDuration::Temporary(d) => {
                // Ensure autonomous router-resident watchdog is installed before applying timed rule
                self.ensure_router_watchdog(&session)?;
                Some(now + d.as_secs())
            }
            PolicyDuration::Indefinite => None,
        };

        let policy_id = match &req.scope {
            PolicyScope::NetworkWide => "rustrict_pause_network_wide".to_string(),
            PolicyScope::SpecificTargets(targets) => {
                if targets.is_empty() {
                    return Err(AdminError::UnsupportedOperation(
                        "No target devices specified".into(),
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

        // Step 2 & 3: Atomic UCI transaction: add rules for all targets, commit, apply with rollback
        match &req.scope {
            PolicyScope::NetworkWide => {
                let values = json!({
                    "name": policy_id,
                    "src": "lan",
                    "dest": "wan",
                    "target": "REJECT",
                    "comment": comment
                });

                let add_res = self.transport.call(
                    &self.endpoint,
                    "uci",
                    "add",
                    json!({
                        "config": "firewall",
                        "type": "rule",
                        "values": values
                    }),
                    &session,
                );

                if let Err(e) = add_res {
                    return Err(AdminError::TransactionFailed(format!(
                        "Failed to insert firewall rule on OpenWrt: {}",
                        e
                    )));
                }
            }
            PolicyScope::SpecificTargets(targets) => {
                for (idx, target_ip) in targets.iter().enumerate() {
                    let rule_name =
                        format!("rustrict_pause_{}", target_ip.to_string().replace('.', "_"));
                    let mut values = json!({
                        "name": rule_name,
                        "src": "lan",
                        "dest": "wan",
                        "target": "REJECT",
                        "comment": comment,
                        "src_ip": target_ip.to_string()
                    });
                    if let Some(mac) = req.target_macs.get(idx) {
                        values["src_mac"] = json!(mac.to_string());
                    }

                    let add_res = self.transport.call(
                        &self.endpoint,
                        "uci",
                        "add",
                        json!({
                            "config": "firewall",
                            "type": "rule",
                            "values": values
                        }),
                        &session,
                    );

                    if let Err(e) = add_res {
                        // Revert uncommitted changes on partial failure, capturing rollback status
                        let revert_res = self.transport.call(
                            &self.endpoint,
                            "uci",
                            "revert",
                            json!({ "config": "firewall" }),
                            &session,
                        );
                        if let Err(rb_err) = revert_res {
                            let applied_strs: Vec<String> =
                                targets.iter().take(idx).map(|ip| ip.to_string()).collect();
                            return Err(AdminError::RollbackFailed {
                                applied_targets: applied_strs,
                                failed_target: target_ip.to_string(),
                                original_error: e.to_string(),
                                rollback_errors: vec![format!("uci revert failed: {}", rb_err)],
                            });
                        }
                        return Err(AdminError::TransactionFailed(format!(
                            "Failed to insert firewall rule for target {} on OpenWrt (staged rules reverted): {}",
                            target_ip, e
                        )));
                    }
                }
            }
        }

        let commit_res = self.transport.call(
            &self.endpoint,
            "uci",
            "commit",
            json!({ "config": "firewall" }),
            &session,
        );

        if let Err(e) = commit_res {
            // Revert uncommitted changes to maintain transaction atomicity
            let _ = self.transport.call(
                &self.endpoint,
                "uci",
                "revert",
                json!({ "config": "firewall" }),
                &session,
            );
            return Err(AdminError::TransactionFailed(format!(
                "Failed to commit UCI firewall changes (transaction reverted): {}",
                e
            )));
        }

        let apply_res = self.transport.call(
            &self.endpoint,
            "uci",
            "apply",
            json!({ "rollback": true, "timeout": 30 }),
            &session,
        );

        if let Err(e) = apply_res {
            let _ = self.transport.call(
                &self.endpoint,
                "uci",
                "revert",
                json!({ "config": "firewall" }),
                &session,
            );
            return Err(AdminError::TransactionFailed(format!(
                "Failed to apply UCI firewall reload: {}",
                e
            )));
        }

        Ok(ActivePolicyStatus::new(
            policy_id,
            req.scope.clone(),
            now,
            expires_at,
            req.persistence == PolicyPersistence::RouterPersistent,
            "OpenWrt-UCI-Firewall",
            expires_at.is_some(),
        ))
    }

    fn resume_policy(&self, scope: &PolicyScope) -> Result<Vec<String>, AdminError> {
        let session = self.get_valid_session()?;
        let uci_state = self.transport.call(
            &self.endpoint,
            "uci",
            "get",
            json!({ "config": "firewall" }),
            &session,
        )?;

        let mut sections_to_delete = Vec::new();
        let mut resumed_ids = Vec::new();

        if let Some(values) = uci_state.get("values").and_then(|v| v.as_object()) {
            for (section_name, section_val) in values {
                let name = section_val
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("");

                if !name.starts_with("rustrict_") {
                    continue;
                }

                let matches = match scope {
                    PolicyScope::NetworkWide => true, // Network-wide resume removes all rustrict pause rules
                    PolicyScope::SpecificTargets(targets) => {
                        if name == "rustrict_pause_network_wide" {
                            false
                        } else if let Some(ip_str) =
                            section_val.get("src_ip").and_then(|i| i.as_str())
                        {
                            targets.iter().any(|t| t.to_string() == ip_str)
                        } else {
                            false
                        }
                    }
                };

                if matches {
                    sections_to_delete.push(section_name.clone());
                    resumed_ids.push(name.to_string());
                }
            }
        }

        if sections_to_delete.is_empty() {
            return Err(AdminError::PolicyNotFound(
                "No active OpenWrt firewall policy matched specified target".into(),
            ));
        }

        // Delete matching UCI sections
        for section in &sections_to_delete {
            let _ = self.transport.call(
                &self.endpoint,
                "uci",
                "delete",
                json!({
                    "config": "firewall",
                    "section": section
                }),
                &session,
            );
        }

        // Commit and apply with rollback
        let commit_res = self.transport.call(
            &self.endpoint,
            "uci",
            "commit",
            json!({ "config": "firewall" }),
            &session,
        );

        if let Err(e) = commit_res {
            let _ = self.transport.call(
                &self.endpoint,
                "uci",
                "revert",
                json!({ "config": "firewall" }),
                &session,
            );
            return Err(AdminError::TransactionFailed(format!(
                "Failed to commit deletion (rolled back): {}",
                e
            )));
        }

        let _ = self.transport.call(
            &self.endpoint,
            "uci",
            "apply",
            json!({ "rollback": true, "timeout": 30 }),
            &session,
        );

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

        let mut expired_scopes = Vec::new();
        for p in &active {
            if p.is_expired(now) {
                expired_scopes.push(p.scope.clone());
            }
        }

        for exp_scope in expired_scopes {
            let _ = self.resume_policy(&exp_scope);
        }

        self.query_active_policies()
    }

    fn adjust_policy_duration(
        &self,
        scope: &PolicyScope,
        new_duration: &PolicyDuration,
    ) -> Result<ActivePolicyStatus, AdminError> {
        let session = self.get_valid_session()?;

        if let PolicyDuration::Temporary(_) = new_duration {
            self.ensure_router_watchdog(&session)?;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let new_expires_at = match new_duration {
            PolicyDuration::Temporary(d) => Some(now + d.as_secs()),
            PolicyDuration::Indefinite => None,
        };

        let uci_state = self.transport.call(
            &self.endpoint,
            "uci",
            "get",
            json!({ "config": "firewall" }),
            &session,
        )?;

        let mut target_section = None;
        let mut target_policy_id = None;

        if let Some(values) = uci_state.get("values").and_then(|v| v.as_object()) {
            for (section_name, section_val) in values {
                let name = section_val
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("");

                if !name.starts_with("rustrict_") {
                    continue;
                }

                let matches = match scope {
                    PolicyScope::NetworkWide => name == "rustrict_pause_network_wide",
                    PolicyScope::SpecificTargets(targets) => {
                        if let Some(ip_str) = section_val.get("src_ip").and_then(|i| i.as_str()) {
                            targets.iter().any(|t| t.to_string() == ip_str)
                        } else {
                            false
                        }
                    }
                };

                if matches {
                    target_section = Some(section_name.clone());
                    target_policy_id = Some(name.to_string());
                    break;
                }
            }
        }

        let section = target_section.ok_or_else(|| {
            AdminError::PolicyNotFound(
                "No active OpenWrt firewall policy matched specified target for duration adjustment".into(),
            )
        })?;
        let policy_id = target_policy_id.unwrap_or_else(|| "rustrict_policy".to_string());

        let exp_str = new_expires_at
            .map(|e| e.to_string())
            .unwrap_or_else(|| "0".into());
        let comment = format!("rustrict:pol={}:app={}:exp={}", policy_id, now, exp_str);

        let set_res = self.transport.call(
            &self.endpoint,
            "uci",
            "set",
            json!({
                "config": "firewall",
                "section": section,
                "values": {
                    "comment": comment
                }
            }),
            &session,
        );

        if let Err(e) = set_res {
            return Err(AdminError::TransactionFailed(format!(
                "Failed to update policy comment on OpenWrt: {}",
                e
            )));
        }

        let commit_res = self.transport.call(
            &self.endpoint,
            "uci",
            "commit",
            json!({ "config": "firewall" }),
            &session,
        );

        if let Err(e) = commit_res {
            let _ = self.transport.call(
                &self.endpoint,
                "uci",
                "revert",
                json!({ "config": "firewall" }),
                &session,
            );
            return Err(AdminError::TransactionFailed(format!(
                "Failed to commit duration update (transaction rolled back): {}",
                e
            )));
        }

        let _ = self.transport.call(
            &self.endpoint,
            "uci",
            "apply",
            json!({ "rollback": true, "timeout": 30 }),
            &session,
        );

        Ok(ActivePolicyStatus::new(
            policy_id,
            scope.clone(),
            now,
            new_expires_at,
            true,
            format!("OpenWrt-UCI:{}", section),
            new_expires_at.is_some(),
        ))
    }
}

pub fn parse_policy_timestamps(comment: &str) -> (u64, Option<u64>) {
    let mut applied_at = 0;
    let mut expires_at = None;

    for token in comment.split(':') {
        if let Some(val) = token.strip_prefix("app=") {
            applied_at = val.parse::<u64>().unwrap_or(0);
        } else if let Some(val) = token.strip_prefix("exp=") {
            let num = val.parse::<u64>().unwrap_or(0);
            if num > 0 {
                expires_at = Some(num);
            }
        }
    }

    (applied_at, expires_at)
}

/// Deterministic mock transport for offline OpenWrt unit tests.
/// Implements full ubus JSON-RPC request-response cycles with zero network traffic.
#[derive(Clone)]
pub struct MockOpenWrtTransport {
    pub valid_username: String,
    pub valid_password: String,
    pub simulated_session_token: String,
    pub simulate_timeout: Arc<AtomicBool>,
    pub simulate_auth_fail: Arc<AtomicBool>,
    pub simulate_non_openwrt: Arc<AtomicBool>,
    pub autonomous_recovery_supported: Arc<AtomicBool>,
    pub simulate_partial_failure: Arc<AtomicBool>,
    pub crontab_state: Arc<RwLock<Option<String>>>,
    pub watchdog_script_state: Arc<RwLock<Option<String>>>,
    pub uci_firewall_state: Arc<RwLock<serde_json::Map<String, Value>>>,
    pub uncommitted_snapshot: Arc<RwLock<Option<serde_json::Map<String, Value>>>>,
}

impl Default for MockOpenWrtTransport {
    fn default() -> Self {
        Self {
            valid_username: "root".into(),
            valid_password: "admin_password".into(),
            simulated_session_token: "mock_ubus_session_1234567890abcdef".into(),
            simulate_timeout: Arc::new(AtomicBool::new(false)),
            simulate_auth_fail: Arc::new(AtomicBool::new(false)),
            simulate_non_openwrt: Arc::new(AtomicBool::new(false)),
            autonomous_recovery_supported: Arc::new(AtomicBool::new(true)),
            simulate_partial_failure: Arc::new(AtomicBool::new(false)),
            crontab_state: Arc::new(RwLock::new(Some("".to_string()))),
            watchdog_script_state: Arc::new(RwLock::new(None)),
            uci_firewall_state: Arc::new(RwLock::new(serde_json::Map::new())),
            uncommitted_snapshot: Arc::new(RwLock::new(None)),
        }
    }
}

impl MockOpenWrtTransport {
    /// Simulates a physical router reboot cycle.
    /// Emulates the router-resident crontab watchdog firing after system startup,
    /// purging any firewall rules where the expiration timestamp has elapsed.
    pub fn simulate_reboot_cycle(&self, current_unix: u64) {
        let has_watchdog = self
            .crontab_state
            .read()
            .as_ref()
            .map(|c| c.contains("rustrict_pause") || c.contains("watchdog.sh"))
            .unwrap_or(false);

        if has_watchdog {
            let mut uci = self.uci_firewall_state.write();
            let mut to_delete = Vec::new();
            for (sec_name, sec_val) in uci.iter() {
                if let Some(comment) = sec_val.get("comment").and_then(|c| c.as_str()) {
                    let (_applied, expires_at) = parse_policy_timestamps(comment);
                    if let Some(exp) = expires_at {
                        if current_unix >= exp {
                            to_delete.push(sec_name.clone());
                        }
                    }
                }
            }
            for sec in to_delete {
                uci.remove(&sec);
            }
        }
    }
}

impl OpenWrtTransport for MockOpenWrtTransport {
    fn call(
        &self,
        _endpoint: &str,
        object: &str,
        method: &str,
        params: Value,
        session_id: &str,
    ) -> Result<Value, AdminError> {
        if self.simulate_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout("Mock OpenWrt transport timeout".into()));
        }

        match (object, method) {
            ("session", "login") => {
                if self.simulate_auth_fail.load(Ordering::SeqCst) {
                    return Err(AdminError::AuthenticationFailed(
                        "Mock OpenWrt authentication rejected (code 6)".into(),
                    ));
                }

                let user = params
                    .get("username")
                    .and_then(|u| u.as_str())
                    .unwrap_or("");
                let pass = params
                    .get("password")
                    .and_then(|p| p.as_str())
                    .unwrap_or("");

                if user == self.valid_username && pass == self.valid_password {
                    Ok(json!({
                        "ubus_rpc_session": self.simulated_session_token,
                        "expires": 300,
                        "timeout": 300
                    }))
                } else {
                    Err(AdminError::AuthenticationFailed(
                        "Invalid OpenWrt administrative credentials".into(),
                    ))
                }
            }
            ("system", "board") => {
                if session_id != self.simulated_session_token {
                    return Err(AdminError::SessionExpired(
                        "Session expired or invalid".into(),
                    ));
                }

                if self.simulate_non_openwrt.load(Ordering::SeqCst) {
                    Ok(json!({
                        "model": "Generic Consumer Gateway",
                        "release": {
                            "distribution": "ProprietaryRTOS",
                            "version": "1.0.0"
                        }
                    }))
                } else {
                    Ok(json!({
                        "kernel": "5.15.150",
                        "hostname": "OpenWrt",
                        "system": "ARMv8 Processor",
                        "model": "Ubiquiti UniFi / OpenWrt One",
                        "board_name": "openwrt,one",
                        "release": {
                            "distribution": "OpenWrt",
                            "version": "23.05.2",
                            "revision": "r23630-842932a63d"
                        }
                    }))
                }
            }
            ("file", "read") => {
                if session_id != self.simulated_session_token {
                    return Err(AdminError::SessionExpired(
                        "Session expired or invalid".into(),
                    ));
                }
                if !self.autonomous_recovery_supported.load(Ordering::SeqCst) {
                    return Err(AdminError::AuthenticationFailed(
                        "Permission denied to access crontab (code 6)".into(),
                    ));
                }
                let path = params.get("path").and_then(|p| p.as_str()).unwrap_or("");
                let data = if path == "/etc/rustrict/watchdog.sh" {
                    self.watchdog_script_state
                        .read()
                        .clone()
                        .unwrap_or_default()
                } else {
                    self.crontab_state.read().clone().unwrap_or_default()
                };
                Ok(json!({ "data": data }))
            }
            ("file", "write") => {
                if session_id != self.simulated_session_token {
                    return Err(AdminError::SessionExpired(
                        "Session expired or invalid".into(),
                    ));
                }
                if !self.autonomous_recovery_supported.load(Ordering::SeqCst) {
                    return Err(AdminError::AuthenticationFailed(
                        "Permission denied to write crontab (code 6)".into(),
                    ));
                }
                let path = params.get("path").and_then(|p| p.as_str()).unwrap_or("");
                let data = params.get("data").and_then(|d| d.as_str()).unwrap_or("");
                if path == "/etc/rustrict/watchdog.sh" {
                    *self.watchdog_script_state.write() = Some(data.to_string());
                } else {
                    *self.crontab_state.write() = Some(data.to_string());
                }
                Ok(json!({}))
            }
            ("uci", "get") => {
                if session_id != self.simulated_session_token {
                    return Err(AdminError::SessionExpired(
                        "Session expired or invalid".into(),
                    ));
                }
                let lock = self.uci_firewall_state.read();
                Ok(json!({ "values": Value::Object(lock.clone()) }))
            }
            ("uci", "set") => {
                if session_id != self.simulated_session_token {
                    return Err(AdminError::SessionExpired(
                        "Session expired or invalid".into(),
                    ));
                }
                let mut snap = self.uncommitted_snapshot.write();
                if snap.is_none() {
                    *snap = Some(self.uci_firewall_state.read().clone());
                }

                let section = params.get("section").and_then(|s| s.as_str()).unwrap_or("");
                let values = params.get("values").and_then(|v| v.as_object());

                let mut lock = self.uci_firewall_state.write();
                if let (Some(sec_val), Some(new_vals)) = (lock.get_mut(section), values) {
                    if let Some(target_obj) = sec_val.as_object_mut() {
                        for (k, v) in new_vals {
                            target_obj.insert(k.clone(), v.clone());
                        }
                    }
                }
                Ok(json!({}))
            }
            ("uci", "add") => {
                if session_id != self.simulated_session_token {
                    return Err(AdminError::SessionExpired(
                        "Session expired or invalid".into(),
                    ));
                }
                let mut snap = self.uncommitted_snapshot.write();
                if snap.is_none() {
                    *snap = Some(self.uci_firewall_state.read().clone());
                }

                let values = params.get("values").cloned().unwrap_or(json!({}));
                let name = values
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("rule_default");
                let section_id = format!("cfg_{}", name);

                let mut lock = self.uci_firewall_state.write();
                lock.insert(section_id.clone(), values);
                Ok(json!({ "section": section_id }))
            }
            ("uci", "delete") => {
                if session_id != self.simulated_session_token {
                    return Err(AdminError::SessionExpired(
                        "Session expired or invalid".into(),
                    ));
                }
                let mut snap = self.uncommitted_snapshot.write();
                if snap.is_none() {
                    *snap = Some(self.uci_firewall_state.read().clone());
                }

                let section = params.get("section").and_then(|s| s.as_str()).unwrap_or("");
                let mut lock = self.uci_firewall_state.write();
                lock.remove(section);
                Ok(json!({}))
            }
            ("uci", "commit") => {
                if session_id != self.simulated_session_token {
                    return Err(AdminError::SessionExpired(
                        "Session expired or invalid".into(),
                    ));
                }
                if self.simulate_partial_failure.load(Ordering::SeqCst) {
                    return Err(AdminError::TransactionFailed(
                        "Simulated NVRAM commit error (disk full or write error)".into(),
                    ));
                }
                *self.uncommitted_snapshot.write() = None;
                Ok(json!({}))
            }
            ("uci", "revert") => {
                if session_id != self.simulated_session_token {
                    return Err(AdminError::SessionExpired(
                        "Session expired or invalid".into(),
                    ));
                }
                if let Some(prev) = self.uncommitted_snapshot.write().take() {
                    *self.uci_firewall_state.write() = prev;
                }
                Ok(json!({}))
            }
            ("uci", "apply") => {
                if session_id != self.simulated_session_token {
                    return Err(AdminError::SessionExpired(
                        "Session expired or invalid".into(),
                    ));
                }
                Ok(json!({}))
            }
            _ => Err(AdminError::UnsupportedOperation(format!(
                "Mock transport does not handle ubus {}:{}",
                object, method
            ))),
        }
    }

    fn transport_name(&self) -> &'static str {
        "Mock"
    }
}
