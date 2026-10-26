use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustrict::gateway::admin::sanitize_text;
use serde_json::{json, Value};

/// Failure injection modes for simulated router endpoints
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum FailMode {
    HttpError(u16, String),
    SoapFault {
        code: String,
        message: String,
    },
    MalformedJson,
    MalformedXml,
    OversizedResponse(usize),
    Redirect(String),
    Timeout(Duration),
    ConnectionDrop,
    MultiTargetPartialFail {
        succeed_targets: usize,
    },
    /// Mutates router state, but immediately drops TCP connection before sending response
    MutateThenDrop,
    /// Mutates router state, but writes partial response headers before dropping connection
    MutateThenPartialResponse,
    /// Mutates router state, then delays response beyond client deadline
    MutateThenTimeout(Duration),
    /// Mutates router state, but returns an HTTP 500 server error
    MutateThenServerError(u16, String),
    /// Drops connection during read-only queries
    ReadOnlyDrop,
    /// Allows N targets to succeed, fails target N+1, and when rollback is attempted, rollback also fails
    MultiTargetPartialWithRollbackFail {
        succeed_targets: usize,
    },
}

/// Sanitized record of an incoming HTTP request observed by the simulator
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub timestamp_unix: u64,
}

/// Simulated state maintained by the emulator across operations
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct SimulatedRouterState {
    pub authenticated_sessions: HashSet<String>,
    pub openwrt_rules: Vec<Value>,
    pub mikrotik_rules: Vec<Value>,
    pub avm_blocked_ips: HashSet<Ipv4Addr>,
    pub unifi_rules: Vec<Value>,
    pub unifi_cookies: HashSet<String>,
}

/// Loopback-only HTTP router protocol simulator for deterministically testing real router providers
#[allow(dead_code)]
pub struct RouterEmulator {
    addr: SocketAddr,
    shutdown_flag: Arc<AtomicBool>,
    server_handle: Option<JoinHandle<()>>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    state: Arc<Mutex<SimulatedRouterState>>,
    fail_mode: Arc<Mutex<Option<FailMode>>>,
    target_mutation_count: Arc<Mutex<usize>>,
}

#[allow(dead_code)]
impl RouterEmulator {
    /// Spawns a new emulator listener bound strictly to 127.0.0.1 and an ephemeral port
    pub fn start() -> Self {
        // Enforce loopback binding exclusively
        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind loopback socket");
        let addr = listener.local_addr().expect("Read local addr");

        // Hard security assertion: listener must be strictly local loopback
        assert!(
            addr.ip() == Ipv4Addr::LOCALHOST || addr.ip().is_loopback(),
            "Security violation: Emulator must only bind to 127.0.0.1!"
        );

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(Mutex::new(SimulatedRouterState::default()));
        let fail_mode = Arc::new(Mutex::new(None));
        let target_mutation_count = Arc::new(Mutex::new(0));

        let s_flag = shutdown_flag.clone();
        let s_reqs = requests.clone();
        let s_state = state.clone();
        let s_fail = fail_mode.clone();
        let s_mut_count = target_mutation_count.clone();

        let server_handle = thread::spawn(move || {
            let _ = listener.set_nonblocking(true);

            while !s_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _peer)) => {
                        let reqs = s_reqs.clone();
                        let state = s_state.clone();
                        let fail = s_fail.clone();
                        let count = s_mut_count.clone();

                        thread::spawn(move || {
                            Self::handle_connection(stream, reqs, state, fail, count);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr,
            shutdown_flag,
            server_handle: Some(server_handle),
            requests,
            state,
            fail_mode,
            target_mutation_count,
        }
    }

    /// Loopback HTTP base URL for connecting client transports
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Returns the ephemeral port assigned by the OS
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Accesses recorded requests in arrival order
    pub fn recorded_requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// Clears recorded requests
    pub fn clear_recorded_requests(&self) {
        self.requests.lock().unwrap().clear();
    }

    /// Accesses the simulator state snapshot
    pub fn state(&self) -> SimulatedRouterState {
        self.state.lock().unwrap().clone()
    }

    /// Injects an active failure mode into the simulator
    pub fn set_fail_mode(&self, mode: Option<FailMode>) {
        *self.fail_mode.lock().unwrap() = mode;
    }

    /// Resets the multi-target mutation counter
    pub fn reset_mutation_counter(&self) {
        *self.target_mutation_count.lock().unwrap() = 0;
    }

    fn handle_connection(
        stream: TcpStream,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
        state: Arc<Mutex<SimulatedRouterState>>,
        fail_mode: Arc<Mutex<Option<FailMode>>>,
        mutation_count: Arc<Mutex<usize>>,
    ) {
        let _ = stream.set_nodelay(true);
        let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::from_secs(2)));
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

        let mut reader = BufReader::new(stream);

        // Parse HTTP request line
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() || request_line.trim().is_empty() {
            return;
        }

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            return;
        }
        let method = parts[0].to_string();
        let path = parts[1].to_string();

        // Parse HTTP headers
        let mut headers = HashMap::new();
        let mut content_length: usize = 0;
        let mut is_soap = false;
        let mut soap_action = String::new();
        let mut cookie_header = String::new();

        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                let k_trim = k.trim().to_ascii_lowercase();
                let v_trim = v.trim().to_string();

                if k_trim == "content-length" {
                    content_length = v_trim.parse().unwrap_or(0);
                } else if k_trim == "soapaction" {
                    is_soap = true;
                    soap_action = v_trim.clone();
                } else if k_trim == "cookie" {
                    cookie_header = v_trim.clone();
                }

                // Sanitize header value before recording to avoid storing secret passwords/tokens
                let sanitized_v = if k_trim == "authorization" || k_trim == "cookie" {
                    "[REDACTED]".to_string()
                } else {
                    sanitize_text(&v_trim)
                };

                headers.insert(k_trim, sanitized_v);
            }
        }

        if headers
            .get("expect")
            .map(|v| v.to_ascii_lowercase().contains("100-continue"))
            .unwrap_or(false)
        {
            let _ = reader.get_mut().write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
            let _ = reader.get_mut().flush();
        }

        // Parse HTTP body up to bounded limit (max 2 MiB)
        let mut body_bytes = vec![0u8; content_length.min(2 * 1024 * 1024)];
        if content_length > 0 {
            let _ = reader.read_exact(&mut body_bytes);
        }
        let body_raw = String::from_utf8_lossy(&body_bytes).to_string();
        let sanitized_body = sanitize_text(&body_raw);

        let mut stream = reader.into_inner();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        requests.lock().unwrap().push(RecordedRequest {
            method: method.clone(),
            path: path.clone(),
            headers,
            body: sanitized_body,
            timestamp_unix: now,
        });

        // 1. Check for injected failure mode
        let current_fail = fail_mode.lock().unwrap().clone();
        if let Some(fail) = current_fail {
            match fail {
                FailMode::HttpError(status, message) => {
                    let resp = format!(
                        "HTTP/1.1 {} Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status, message.len(), message
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    return;
                }
                FailMode::SoapFault { code, message } => {
                    if !path.contains("tr64desc.xml") {
                        let fault_body = format!(
                            r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <s:Fault>
      <faultcode>{}</faultcode>
      <faultstring>{}</faultstring>
      <detail><UPnPError xmlns="urn:dslforum-org:control-1-0"><errorCode>500</errorCode></UPnPError></detail>
    </s:Fault>
  </s:Body>
</s:Envelope>"#,
                            code, message
                        );
                        let resp = format!(
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            fault_body.len(), fault_body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.flush();
                        let _ = stream.shutdown(std::net::Shutdown::Write);
                        return;
                    }
                }
                FailMode::MalformedJson => {
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{invalid_json:]";
                    let _ = stream.write_all(resp.as_bytes());
                    return;
                }
                FailMode::MalformedXml => {
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: 20\r\nConnection: close\r\n\r\n<unclosed_tag>broken";
                    let _ = stream.write_all(resp.as_bytes());
                    return;
                }
                FailMode::OversizedResponse(size) => {
                    let padding = "A".repeat(size);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        padding.len(), padding
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    return;
                }
                FailMode::Redirect(dest) => {
                    let resp = format!(
                        "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        dest
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    return;
                }
                FailMode::Timeout(dur) => {
                    thread::sleep(dur);
                    return;
                }
                FailMode::ConnectionDrop => {
                    // Close connection abruptly without response
                    return;
                }
                FailMode::MultiTargetPartialFail { succeed_targets } => {
                    let mut count = mutation_count.lock().unwrap();
                    if *count >= succeed_targets {
                        let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: 38\r\nConnection: close\r\n\r\n{\"error\":\"Target rule mutation failed\"}";
                        let _ = stream.write_all(resp.as_bytes());
                        return;
                    }
                    *count += 1;
                }
                FailMode::MutateThenDrop => {
                    if Self::apply_simulated_mutation(
                        &path,
                        &method,
                        &soap_action,
                        &body_raw,
                        &state,
                    ) {
                        return;
                    }
                }
                FailMode::MutateThenPartialResponse => {
                    if Self::apply_simulated_mutation(
                        &path,
                        &method,
                        &soap_action,
                        &body_raw,
                        &state,
                    ) {
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"status\":");
                        let _ = stream.flush();
                        return;
                    }
                }
                FailMode::MutateThenTimeout(dur) => {
                    if Self::apply_simulated_mutation(
                        &path,
                        &method,
                        &soap_action,
                        &body_raw,
                        &state,
                    ) {
                        thread::sleep(dur);
                        return;
                    }
                }
                FailMode::MutateThenServerError(code, ref msg) => {
                    if Self::apply_simulated_mutation(
                        &path,
                        &method,
                        &soap_action,
                        &body_raw,
                        &state,
                    ) {
                        let resp = format!(
                            "HTTP/1.1 {} Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            code, msg.len(), msg
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        return;
                    }
                }
                FailMode::ReadOnlyDrop => {
                    if method == "GET"
                        || (is_soap && !soap_action.contains("DisallowWANAccessByIP"))
                    {
                        return;
                    }
                }
                FailMode::MultiTargetPartialWithRollbackFail { succeed_targets } => {
                    let is_rollback = (is_soap
                        && body_raw.contains("<NewDisallow>0</NewDisallow>"))
                        || (method == "DELETE" && path.contains("firewall"));
                    if is_rollback {
                        let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: 30\r\nConnection: close\r\n\r\n{\"error\":\"Rollback rejected\"}";
                        let _ = stream.write_all(resp.as_bytes());
                        return;
                    }
                    if Self::is_mutation(&path, &method, &soap_action, &body_raw) {
                        let mut count = mutation_count.lock().unwrap();
                        if *count >= succeed_targets {
                            let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: 38\r\nConnection: close\r\n\r\n{\"error\":\"Target rule mutation failed\"}";
                            let _ = stream.write_all(resp.as_bytes());
                            return;
                        }
                        *count += 1;
                    }
                }
            }
        }

        // 2. Dispatch to specific protocol handlers based on URL and Headers
        if path.starts_with("/ubus") {
            Self::handle_openwrt_ubus(&mut stream, &body_raw, state);
        } else if is_soap || path.contains("tr64") || path.contains("upnp") {
            Self::handle_avm_tr064(&mut stream, &path, &soap_action, &body_raw, state);
        } else if path.starts_with("/api/") || path.starts_with("/proxy/") {
            Self::handle_unifi_rest(
                &mut stream,
                &method,
                &path,
                &body_raw,
                &cookie_header,
                state,
            );
        } else if path.starts_with("/rest/") {
            Self::handle_mikrotik_rest(&mut stream, &method, &path, &body_raw, state);
        } else {
            // Default 404 for unknown route
            let _ = stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }

        let _ = stream.flush();
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let mut drain = [0u8; 512];
        while let Ok(n) = stream.read(&mut drain) {
            if n == 0 {
                break;
            }
        }
    }

    fn is_mutation(path: &str, method: &str, soap_action: &str, body_raw: &str) -> bool {
        if soap_action.contains("DisallowWANAccessByIP") {
            return body_raw.contains("<NewIPv4Address>");
        }
        if (path.contains("trafficrule")
            || path.contains("trafficrules")
            || path.contains("firewallrule"))
            && (method == "POST" || method == "PUT" || method == "DELETE")
        {
            return true;
        }
        if path.starts_with("/rest/ip/firewall/filter")
            && (method == "POST" || method == "PUT" || method == "DELETE")
        {
            return true;
        }
        false
    }

    fn apply_simulated_mutation(
        path: &str,
        method: &str,
        soap_action: &str,
        body_raw: &str,
        state: &Arc<Mutex<SimulatedRouterState>>,
    ) -> bool {
        if soap_action.contains("DisallowWANAccessByIP") {
            if body_raw.contains("<NewDisallow>1</NewDisallow>") {
                if let Some(start) = body_raw.find("<NewIPv4Address>") {
                    let s = &body_raw[start + "<NewIPv4Address>".len()..];
                    if let Some(end) = s.find("</NewIPv4Address>") {
                        if let Ok(ip) = s[..end].trim().parse::<Ipv4Addr>() {
                            state.lock().unwrap().avm_blocked_ips.insert(ip);
                            return true;
                        }
                    }
                }
            }
        } else if (path.contains("trafficrule")
            || path.contains("trafficrules")
            || path.contains("firewallrule"))
            && method == "POST"
        {
            if let Ok(val) = serde_json::from_str::<Value>(body_raw) {
                state.lock().unwrap().unifi_rules.push(val);
                return true;
            }
        } else if path.starts_with("/rest/ip/firewall/filter")
            && (method == "POST" || method == "PUT")
        {
            if let Ok(val) = serde_json::from_str::<Value>(body_raw) {
                state.lock().unwrap().mikrotik_rules.push(val);
                return true;
            }
        }
        false
    }

    fn handle_openwrt_ubus(
        stream: &mut TcpStream,
        body_raw: &str,
        state: Arc<Mutex<SimulatedRouterState>>,
    ) {
        let req_json: Value = serde_json::from_str(body_raw).unwrap_or(Value::Null);
        let method = req_json
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        let params = req_json.get("params").cloned().unwrap_or(json!([]));

        let resp_json = match method {
            "call" => {
                let _session = params.get(0).and_then(|s| s.as_str()).unwrap_or("");
                let object = params.get(1).and_then(|o| o.as_str()).unwrap_or("");
                let fn_name = params.get(2).and_then(|f| f.as_str()).unwrap_or("");
                let args = params.get(3).cloned().unwrap_or(json!({}));

                match (object, fn_name) {
                    ("session", "login") => {
                        let user = args.get("username").and_then(|u| u.as_str()).unwrap_or("");
                        let pass = args.get("password").and_then(|p| p.as_str()).unwrap_or("");

                        if user == "root" && pass == "admin_password" {
                            let session_token = "ubus_test_session_token_12345";
                            state
                                .lock()
                                .unwrap()
                                .authenticated_sessions
                                .insert(session_token.into());
                            json!({
                                "jsonrpc": "2.0",
                                "id": 1,
                                "result": [
                                    0,
                                    {
                                        "ubus_rpc_session": session_token,
                                        "timeout": 300,
                                        "expires": 300
                                    }
                                ]
                            })
                        } else {
                            json!({
                                "jsonrpc": "2.0",
                                "id": 1,
                                "result": [5, {}] // 5 = Access denied
                            })
                        }
                    }
                    ("system", "board") => json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": [
                            0,
                            {
                                "release": {
                                    "distribution": "OpenWrt",
                                    "version": "23.05.2"
                                },
                                "board_name": "Ubiquiti UniFi",
                                "model": "OpenWrt One"
                            }
                        ]
                    }),
                    ("uci", "get") => {
                        let rules = state.lock().unwrap().openwrt_rules.clone();
                        let mut values_map = serde_json::Map::new();
                        for r in rules {
                            if let Some(sec) = r.get("section").and_then(|s| s.as_str()) {
                                values_map.insert(sec.to_string(), r);
                            }
                        }
                        json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "result": [0, { "values": values_map }]
                        })
                    }
                    ("uci", "add") => {
                        let sec_id =
                            format!("cfg_{}", state.lock().unwrap().openwrt_rules.len() + 1);
                        let mut r = args.get("values").cloned().unwrap_or(json!({}));
                        if let Some(map) = r.as_object_mut() {
                            map.insert("section".into(), json!(sec_id));
                        }
                        state.lock().unwrap().openwrt_rules.push(r);
                        json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "result": [0, { "section": sec_id }]
                        })
                    }
                    ("uci", "commit") | ("uci", "apply") => json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": [0, {}]
                    }),
                    ("uci", "delete") => {
                        let sec = args.get("section").and_then(|s| s.as_str()).unwrap_or("");
                        state
                            .lock()
                            .unwrap()
                            .openwrt_rules
                            .retain(|r| r.get("section").and_then(|s| s.as_str()) != Some(sec));
                        json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "result": [0, {}]
                        })
                    }
                    ("file", "read") => json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": [0, { "data": "" }]
                    }),
                    ("file", "write") => json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": [0, {}]
                    }),
                    _ => json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": [0, {}]
                    }),
                }
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": { "code": -32601, "message": "Method not found" }
            }),
        };

        let body_str = resp_json.to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body_str.len(), body_str
        );
        let _ = stream.write_all(resp.as_bytes());
    }

    fn handle_avm_tr064(
        stream: &mut TcpStream,
        path: &str,
        soap_action: &str,
        body_raw: &str,
        state: Arc<Mutex<SimulatedRouterState>>,
    ) {
        if path.contains("tr64desc.xml") {
            let desc = r#"<?xml version="1.0"?>
<root xmlns="urn:dslforum-org:device-1-0">
  <device>
    <deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>FRITZ!Box 7590</friendlyName>
    <manufacturer>AVM</manufacturer>
    <modelName>FRITZ!Box 7590</modelName>
    <serviceList>
      <service>
        <serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType>
        <serviceId>urn:DeviceInfo-serviceId:DeviceInfo1</serviceId>
        <controlURL>/upnp/control/deviceinfo</controlURL>
      </service>
      <service>
        <serviceType>urn:dslforum-org:service:X_AVM-DE_HostFilter:1</serviceType>
        <serviceId>urn:X_AVM-DE_HostFilter-serviceId:X_AVM-DE_HostFilter1</serviceId>
        <controlURL>/upnp/control/x_hostfilter</controlURL>
      </service>
      <service>
        <serviceType>urn:dslforum-org:service:Hosts:1</serviceType>
        <serviceId>urn:Hosts-serviceId:Hosts1</serviceId>
        <controlURL>/upnp/control/hosts</controlURL>
      </service>
    </serviceList>
  </device>
</root>"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                desc.len(), desc
            );
            let _ = stream.write_all(resp.as_bytes());
            return;
        }

        let action_clean = soap_action.trim_matches('"');
        let response_envelope = if action_clean.ends_with("GetInfo") {
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetInfoResponse xmlns:u="urn:dslforum-org:service:DeviceInfo:1">
      <NewManufacturerName>AVM</NewManufacturerName>
      <NewModelName>FRITZ!Box 7590</NewModelName>
      <NewSoftwareVersion>7.57</NewSoftwareVersion>
      <NewSerialNumber>A0B1C2D3E4F5</NewSerialNumber>
    </u:GetInfoResponse>
  </s:Body>
</s:Envelope>"#
                .to_string()
        } else if action_clean.ends_with("GetHostNumberOfEntries") {
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetHostNumberOfEntriesResponse xmlns:u="urn:dslforum-org:service:Hosts:1">
      <NewHostNumberOfEntries>1</NewHostNumberOfEntries>
    </u:GetHostNumberOfEntriesResponse>
  </s:Body>
</s:Envelope>"#
                .to_string()
        } else if action_clean.ends_with("GetGenericHostEntry") {
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetGenericHostEntryResponse xmlns:u="urn:dslforum-org:service:Hosts:1">
      <NewIPAddress>192.168.178.20</NewIPAddress>
      <NewMACAddress>AA:BB:CC:DD:EE:01</NewMACAddress>
      <NewHostName>Lab-Test-Client</NewHostName>
      <NewActive>1</NewActive>
      <NewInterfaceType>Ethernet</NewInterfaceType>
    </u:GetGenericHostEntryResponse>
  </s:Body>
</s:Envelope>"#
                .to_string()
        } else if action_clean.ends_with("DisallowWANAccessByIP") {
            // Extract IP from body
            if let Some(start) = body_raw.find("<NewIPv4Address>") {
                let rest = &body_raw[start + 16..];
                if let Some(end) = rest.find("</NewIPv4Address>") {
                    let ip_str = &rest[..end];
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        let is_unblock = body_raw.contains("<NewDisallow>0</NewDisallow>");
                        if is_unblock {
                            state.lock().unwrap().avm_blocked_ips.remove(&ip);
                        } else {
                            state.lock().unwrap().avm_blocked_ips.insert(ip);
                        }
                    }
                }
            }
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:DisallowWANAccessByIPResponse xmlns:u="urn:dslforum-org:service:X_AVM-DE_HostFilter:1" />
  </s:Body>
</s:Envelope>"#
                .to_string()
        } else if action_clean.ends_with("AllowWANAccessByIP") {
            if let Some(start) = body_raw.find("<NewIPv4Address>") {
                let rest = &body_raw[start + 16..];
                if let Some(end) = rest.find("</NewIPv4Address>") {
                    let ip_str = &rest[..end];
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        state.lock().unwrap().avm_blocked_ips.remove(&ip);
                    }
                }
            }
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:AllowWANAccessByIPResponse xmlns:u="urn:dslforum-org:service:X_AVM-DE_HostFilter:1" />
  </s:Body>
</s:Envelope>"#
                .to_string()
        } else if action_clean.ends_with("GetWANAccessByIP") {
            let mut is_disallowed = false;
            if let Some(start) = body_raw.find("<NewIPv4Address>") {
                let rest = &body_raw[start + 16..];
                if let Some(end) = rest.find("</NewIPv4Address>") {
                    let ip_str = &rest[..end];
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        is_disallowed = state.lock().unwrap().avm_blocked_ips.contains(&ip);
                    }
                }
            }
            let disallow_val = if is_disallowed { "1" } else { "0" };
            format!(
                r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetWANAccessByIPResponse xmlns:u="urn:dslforum-org:service:X_AVM-DE_HostFilter:1">
      <NewDisallow>{}</NewDisallow>
    </u:GetWANAccessByIPResponse>
  </s:Body>
</s:Envelope>"#,
                disallow_val
            )
        } else {
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:DefaultResponse xmlns:u="urn:dslforum-org:service:Generic:1" />
  </s:Body>
</s:Envelope>"#
                .to_string()
        };

        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_envelope.len(), response_envelope
        );
        let _ = stream.write_all(resp.as_bytes());
    }

    fn handle_unifi_rest(
        stream: &mut TcpStream,
        method: &str,
        path: &str,
        body_raw: &str,
        _cookie: &str,
        state: Arc<Mutex<SimulatedRouterState>>,
    ) {
        if path.ends_with("/api/login") || path.ends_with("/api/auth/login") {
            let body_json: Value = serde_json::from_str(body_raw).unwrap_or(Value::Null);
            let user = body_json
                .get("username")
                .and_then(|u| u.as_str())
                .unwrap_or("");
            let pass = body_json
                .get("password")
                .and_then(|p| p.as_str())
                .unwrap_or("");

            if user == "admin" && pass == "admin_password" {
                state
                    .lock()
                    .unwrap()
                    .unifi_cookies
                    .insert("unifises=mock_cookie_val_123".into());
                let b = "{\"meta\":{\"rc\":\"ok\"},\"data\":[]}";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nSet-Cookie: unifises=mock_cookie_val_123; Path=/\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    b.len(), b
                );
                let _ = stream.write_all(resp.as_bytes());
                return;
            } else {
                let b = "{\"meta\":{\"rc\":\"error\",\"msg\":\"api.err.Invalid\"}}";
                let resp = format!(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    b.len(), b
                );
                let _ = stream.write_all(resp.as_bytes());
                return;
            }
        }

        if path.contains("/stat/sysinfo") {
            let info = json!({
                "meta": { "rc": "ok" },
                "data": [{
                    "version": "8.0.28",
                    "hostname": "UniFi-Controller",
                    "mac": "00:11:22:33:44:55"
                }]
            });
            let b = info.to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                b.len(), b
            );
            let _ = stream.write_all(resp.as_bytes());
            return;
        }

        if path.contains("/rest/trafficrule") || path.contains("/trafficrules") {
            match method {
                "GET" => {
                    let rules = state.lock().unwrap().unifi_rules.clone();
                    let resp_obj = json!({
                        "meta": { "rc": "ok" },
                        "data": rules
                    });
                    let b = resp_obj.to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        b.len(), b
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
                "POST" => {
                    let mut rule: Value = serde_json::from_str(body_raw).unwrap_or(json!({}));
                    let rule_id =
                        format!("unifi_rule_{}", state.lock().unwrap().unifi_rules.len() + 1);
                    if let Some(map) = rule.as_object_mut() {
                        map.insert("_id".into(), json!(rule_id));
                    }
                    state.lock().unwrap().unifi_rules.push(rule.clone());
                    let resp_obj = json!({
                        "meta": { "rc": "ok" },
                        "data": [rule]
                    });
                    let b = resp_obj.to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        b.len(), b
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
                "DELETE" => {
                    let rule_id = path.split('/').next_back().unwrap_or("");
                    state
                        .lock()
                        .unwrap()
                        .unifi_rules
                        .retain(|r| r.get("_id").and_then(|id| id.as_str()) != Some(rule_id));
                    let resp_obj = json!({ "meta": { "rc": "ok" }, "data": [] });
                    let b = resp_obj.to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        b.len(), b
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
                _ => {}
            }
            return;
        }

        if path.contains("/stat/sta") {
            let sta = json!({
                "meta": { "rc": "ok" },
                "data": [{
                    "mac": "aa:bb:cc:dd:ee:01",
                    "ip": "192.168.1.100",
                    "hostname": "Test-Client",
                    "is_wired": true
                }]
            });
            let b = sta.to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                b.len(), b
            );
            let _ = stream.write_all(resp.as_bytes());
            return;
        }

        let _ =
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }

    fn handle_mikrotik_rest(
        stream: &mut TcpStream,
        method: &str,
        path: &str,
        body_raw: &str,
        state: Arc<Mutex<SimulatedRouterState>>,
    ) {
        if path.contains("/system/resource") {
            let res = json!({
                "platform": "MikroTik",
                "version": "7.14.1",
                "board-name": "hEX S",
                "architecture-name": "mmips"
            });
            let b = res.to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                b.len(), b
            );
            let _ = stream.write_all(resp.as_bytes());
            return;
        }

        if path.contains("/system/identity") {
            let res = json!({ "name": "MikroTik-Test" });
            let b = res.to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                b.len(), b
            );
            let _ = stream.write_all(resp.as_bytes());
            return;
        }

        if path.contains("/ip/firewall/filter") {
            match method {
                "GET" => {
                    let rules = state.lock().unwrap().mikrotik_rules.clone();
                    let b = json!(rules).to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        b.len(), b
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
                "POST" => {
                    let mut rule: Value = serde_json::from_str(body_raw).unwrap_or(json!({}));
                    let rule_id = format!("*{}", state.lock().unwrap().mikrotik_rules.len() + 1);
                    if let Some(map) = rule.as_object_mut() {
                        map.insert(".id".into(), json!(rule_id));
                    }
                    state.lock().unwrap().mikrotik_rules.push(rule.clone());
                    let b = rule.to_string();
                    let resp = format!(
                        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        b.len(), b
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
                "DELETE" => {
                    let id = path.split('/').next_back().unwrap_or("");
                    state
                        .lock()
                        .unwrap()
                        .mikrotik_rules
                        .retain(|r| r.get(".id").and_then(|i| i.as_str()) != Some(id));
                    let resp =
                        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(resp.as_bytes());
                }
                _ => {}
            }
            return;
        }

        if path.contains("/ip/dhcp-server/lease") {
            let leases = json!([{
                "address": "192.168.88.50",
                "mac-address": "AA:BB:CC:DD:EE:88",
                "host-name": "Test-Client-Mikrotik",
                "status": "bound"
            }]);
            let b = leases.to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                b.len(), b
            );
            let _ = stream.write_all(resp.as_bytes());
            return;
        }

        if path.contains("/system/script") || path.contains("/system/scheduler") {
            let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]";
            let _ = stream.write_all(resp.as_bytes());
            return;
        }

        let _ =
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }

    /// Cleanly terminates the background listener thread and resources
    pub fn shutdown(&mut self) {
        if self.shutdown_flag.swap(true, Ordering::SeqCst) {
            return; // Already shut down
        }

        // Connect to local socket to unblock accept() if waiting
        let _ = TcpStream::connect(self.addr);

        if let Some(handle) = self.server_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for RouterEmulator {
    fn drop(&mut self) {
        self.shutdown();
    }
}
