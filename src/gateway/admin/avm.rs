use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::gateway::admin::capabilities::{CapabilityClassification, RouterCapabilityMatrix};
use crate::gateway::admin::credentials::RouterCredentials;
use crate::gateway::admin::plan::{
    ActivePolicyStatus, AdminError, OperationPlan, OperationPlanRequest, PolicyDuration,
    PolicyScope, RouterIdentity,
};
use crate::gateway::admin::provider::RouterAdminProvider;
use crate::gateway::hosts::GatewayHostEntry;
use crate::gateway::soap::SoapClient;
use crate::types::MacAddress;

/// Pure-Rust RFC 1321 MD5 message digest hasher with zero third-party dependencies.
pub fn md5_digest(data: &[u8]) -> String {
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    let s: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    let k: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let orig_len_bits = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&orig_len_bits.to_le_bytes());

    let (chunks, _) = msg.as_chunks::<64>();
    for chunk in chunks {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };

            let temp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(k[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(s[i]));
            a = temp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a0.to_le_bytes());
    result[4..8].copy_from_slice(&b0.to_le_bytes());
    result[8..12].copy_from_slice(&c0.to_le_bytes());
    result[12..16].copy_from_slice(&d0.to_le_bytes());

    let mut hex = String::with_capacity(32);
    for byte in result {
        let _ = write!(hex, "{:02x}", byte);
    }
    hex
}

/// Computes an HTTP Digest response string per RFC 2617.
#[allow(clippy::too_many_arguments)]
pub fn calculate_digest_response(
    username: &str,
    realm: &str,
    password: &str,
    method: &str,
    uri: &str,
    nonce: &str,
    qop: Option<&str>,
    nc: &str,
    cnonce: &str,
) -> String {
    let ha1 = md5_digest(format!("{}:{}:{}", username, realm, password).as_bytes());
    let ha2 = md5_digest(format!("{}:{}", method, uri).as_bytes());

    if let Some(q) = qop {
        md5_digest(format!("{}:{}:{}:{}:{}:{}", ha1, nonce, nc, cnonce, q, ha2).as_bytes())
    } else {
        md5_digest(format!("{}:{}:{}", ha1, nonce, ha2).as_bytes())
    }
}

/// Pluggable transport abstraction for AVM FRITZ!Box TR-064 SOAP communications.
pub trait AvmTransport: Send + Sync {
    /// Executes an authenticated SOAP action against a TR-064 control endpoint.
    fn execute_soap(
        &self,
        _full_control_url: &str,
        service_urn: &str,
        action: &str,
        args_xml: &str,
        credentials: Option<&RouterCredentials>,
    ) -> Result<String, AdminError>;

    /// Fetches the raw XML device description document (e.g. `/tr64desc.xml`).
    fn fetch_description(
        &self,
        description_url: &str,
        credentials: Option<&RouterCredentials>,
    ) -> Result<String, AdminError>;

    fn transport_name(&self) -> &'static str {
        "TR-064/SOAP"
    }
}

/// Production TR-064 transport leveraging Windows native `curl.exe` with Schannel TLS
/// and HTTP Digest Authentication (`--digest`), with credentials piped securely via stdin.
pub struct HttpAvmTransport {
    pub ca_cert_path: Option<PathBuf>,
    pub connect_timeout: Duration,
}

impl HttpAvmTransport {
    pub fn new() -> Self {
        Self {
            ca_cert_path: None,
            connect_timeout: Duration::from_secs(8),
        }
    }

    pub fn with_ca_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.ca_cert_path = Some(path.into());
        self
    }
}

impl Default for HttpAvmTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl AvmTransport for HttpAvmTransport {
    fn execute_soap(
        &self,
        full_control_url: &str,
        service_urn: &str,
        action: &str,
        args_xml: &str,
        credentials: Option<&RouterCredentials>,
    ) -> Result<String, AdminError> {
        let soap_envelope = format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:{} xmlns:u="{}">
      {}
    </u:{}>
  </s:Body>
</s:Envelope>"#,
            action, service_urn, args_xml, action
        );

        let mut curl_cfg = format!(
            "url = \"{}\"\n\
             request = \"POST\"\n\
             header = \"Content-Type: text/xml; charset=\\\"utf-8\\\"\"\n\
             header = \"SOAPAction: \\\"{}#{}\\\"\"\n\
             digest\n\
             max-time = {}\n\
             silent\n\
             show-error\n",
            full_control_url,
            service_urn,
            action,
            self.connect_timeout.as_secs()
        );

        if let Some(creds) = credentials {
            curl_cfg.push_str(&format!(
                "user = \"{}:{}\"\n",
                creds.username.replace('\"', "\\\""),
                creds.password.expose().replace('\"', "\\\"")
            ));
        }

        if let Some(ca) = &self.ca_cert_path {
            curl_cfg.push_str(&format!("cacert = \"{}\"\n", ca.display()));
        }

        let curl_bin = crate::gateway::admin::curl_util::find_curl()?;
        let payload_file = crate::gateway::admin::curl_util::AutoCleanFile::create(
            "rustrict_avm",
            ".xml",
            soap_envelope.as_bytes(),
        )?;

        let mut child = Command::new(&curl_bin)
            .arg("--config")
            .arg("-")
            .arg("--data-binary")
            .arg(format!("@{}", payload_file.path().display()))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                AdminError::CommunicationError(format!(
                    "Failed to invoke native curl.exe for AVM TR-064 SOAP request: {}",
                    e
                ))
            })?;

        let mut curl_cfg_bytes = curl_cfg.into_bytes();
        if let Some(mut stdin) = child.stdin.take() {
            // Send only curl config lines on stdin; payload is delivered via temporary file
            let _ = stdin.write_all(&curl_cfg_bytes);
        }
        crate::gateway::admin::credentials::zero_slice(&mut curl_cfg_bytes);

        let output = crate::gateway::admin::curl_util::wait_child_bounded(
            child,
            crate::gateway::admin::curl_util::MAX_SUBPROCESS_OUTPUT_BYTES,
            self.connect_timeout + std::time::Duration::from_secs(5),
            "AVM TR-064 Challenge",
        )?;

        if output.stdout_truncated {
            return Err(AdminError::CommunicationError(
                "AVM challenge response exceeded maximum buffer limit (2 MiB); truncated response cannot be parsed".into(),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if output.exit_code != 0 {
            if stderr.contains("SSL")
                || stderr.contains("certificate")
                || stderr.contains("schannel")
            {
                return Err(AdminError::CommunicationError(format!(
                    "TLS certificate validation failed for FRITZ!Box at '{}': {}. Connection rejected to protect administrative credentials.",
                    full_control_url, stderr.trim()
                )));
            }
            if stderr.contains("timed out") || stderr.contains("Operation timed out") {
                return Err(AdminError::Timeout(format!(
                    "AVM TR-064 SOAP request timed out: {}",
                    stderr.trim()
                )));
            }
            return Err(AdminError::CommunicationError(format!(
                "AVM TR-064 SOAP request failed (curl exit code {:?}): {}",
                output.exit_code,
                stderr.trim()
            )));
        }

        Ok(stdout)
    }

    fn fetch_description(
        &self,
        description_url: &str,
        credentials: Option<&RouterCredentials>,
    ) -> Result<String, AdminError> {
        let mut curl_cfg = format!(
            "url = \"{}\"\n\
             request = \"GET\"\n\
             digest\n\
             max-time = {}\n\
             silent\n\
             show-error\n",
            description_url,
            self.connect_timeout.as_secs()
        );

        if let Some(creds) = credentials {
            curl_cfg.push_str(&format!(
                "user = \"{}:{}\"\n",
                creds.username.replace('\"', "\\\""),
                creds.password.expose().replace('\"', "\\\"")
            ));
        }

        if let Some(ca) = &self.ca_cert_path {
            curl_cfg.push_str(&format!("cacert = \"{}\"\n", ca.display()));
        }

        let curl_bin = crate::gateway::admin::curl_util::find_curl()?;
        let mut child = Command::new(&curl_bin)
            .arg("--config")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                AdminError::CommunicationError(format!(
                    "Failed to invoke native curl.exe for AVM device description: {}",
                    e
                ))
            })?;

        let mut curl_cfg_bytes = curl_cfg.into_bytes();
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(&curl_cfg_bytes);
        }
        crate::gateway::admin::credentials::zero_slice(&mut curl_cfg_bytes);

        let output = crate::gateway::admin::curl_util::wait_child_bounded(
            child,
            crate::gateway::admin::curl_util::MAX_SUBPROCESS_OUTPUT_BYTES,
            self.connect_timeout + std::time::Duration::from_secs(5),
            "AVM TR-064 Device Description",
        )?;

        if output.stdout_truncated {
            return Err(AdminError::CommunicationError(
                "AVM device description response exceeded maximum buffer limit (2 MiB); truncated response cannot be parsed".into(),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if output.exit_code != 0 {
            if stderr.contains("SSL") || stderr.contains("certificate") {
                return Err(AdminError::CommunicationError(format!(
                    "TLS certificate validation failed for FRITZ!Box: {}",
                    stderr.trim()
                )));
            }
            if stderr.contains("timed out") {
                return Err(AdminError::Timeout(
                    "Device description fetch timed out".into(),
                ));
            }
            return Err(AdminError::CommunicationError(format!(
                "Failed to fetch AVM device description (curl exit code {:?}): {}",
                output.exit_code,
                stderr.trim()
            )));
        }

        Ok(stdout)
    }
}

/// Offline mock transport for AVM FRITZ!Box TR-064 SOAP testing.
/// Simulates full HTTP Digest auth, service descriptions, host inventory, and host filter actions.
#[derive(Clone)]
pub struct MockAvmTransport {
    pub valid_username: String,
    pub valid_password: String,
    pub realm: String,
    pub nonce: String,
    pub simulate_auth_fail: Arc<AtomicBool>,
    pub simulate_timeout: Arc<AtomicBool>,
    pub simulate_non_avm: Arc<AtomicBool>,
    pub simulate_missing_hostfilter: Arc<AtomicBool>,
    pub simulate_soap_fault: Arc<AtomicBool>,
    pub simulate_tls_cert_error: Arc<AtomicBool>,
    /// Number of queries before an asynchronous state change becomes visible
    pub async_delay_cycles: Arc<AtomicUsize>,
    pub async_poll_counter: Arc<AtomicUsize>,
    pub pending_disallow_state: Arc<RwLock<HashMap<Ipv4Addr, bool>>>,
    pub active_disallowed_ips: Arc<RwLock<HashSet<Ipv4Addr>>>,
    pub known_hosts: Arc<RwLock<Vec<GatewayHostEntry>>>,
    pub executed_actions: Arc<RwLock<Vec<String>>>,
}

impl Default for MockAvmTransport {
    fn default() -> Self {
        Self {
            valid_username: "admin".into(),
            valid_password: "admin_password".into(),
            realm: "FRITZ!Box".into(),
            nonce: "mock_tr064_nonce_12345".into(),
            simulate_auth_fail: Arc::new(AtomicBool::new(false)),
            simulate_timeout: Arc::new(AtomicBool::new(false)),
            simulate_non_avm: Arc::new(AtomicBool::new(false)),
            simulate_missing_hostfilter: Arc::new(AtomicBool::new(false)),
            simulate_soap_fault: Arc::new(AtomicBool::new(false)),
            simulate_tls_cert_error: Arc::new(AtomicBool::new(false)),
            async_delay_cycles: Arc::new(AtomicUsize::new(0)),
            async_poll_counter: Arc::new(AtomicUsize::new(0)),
            pending_disallow_state: Arc::new(RwLock::new(HashMap::new())),
            active_disallowed_ips: Arc::new(RwLock::new(HashSet::new())),
            known_hosts: Arc::new(RwLock::new(vec![
                GatewayHostEntry {
                    ip: Ipv4Addr::new(192, 168, 178, 20),
                    mac: "00:11:22:33:44:55".parse().unwrap(),
                    hostname: "Desktop-PC".into(),
                    interface_type: "Ethernet".into(),
                    active: true,
                },
                GatewayHostEntry {
                    ip: Ipv4Addr::new(192, 168, 178, 30),
                    mac: "aa:bb:cc:dd:ee:ff".parse().unwrap(),
                    hostname: "Laptop-WiFi".into(),
                    interface_type: "802.11".into(),
                    active: true,
                },
            ])),
            executed_actions: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl AvmTransport for MockAvmTransport {
    fn execute_soap(
        &self,
        _full_control_url: &str,
        service_urn: &str,
        action: &str,
        args_xml: &str,
        credentials: Option<&RouterCredentials>,
    ) -> Result<String, AdminError> {
        self.executed_actions
            .write()
            .push(format!("{}#{}", service_urn, action));

        if self.simulate_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout(
                "Mock AVM TR-064 transport timeout".into(),
            ));
        }

        if self.simulate_tls_cert_error.load(Ordering::SeqCst) {
            return Err(AdminError::CommunicationError(
                "TLS certificate validation failed: Router presented an untrusted certificate. Connection rejected to protect administrative credentials.".into(),
            ));
        }

        if self.simulate_auth_fail.load(Ordering::SeqCst) {
            return Err(AdminError::AuthenticationFailed(
                "AVM TR-064 Digest authentication failed: 401 Unauthorized".into(),
            ));
        }

        if let Some(creds) = credentials {
            if creds.username != self.valid_username
                || creds.password.expose() != self.valid_password
            {
                return Err(AdminError::AuthenticationFailed(
                    "AVM TR-064 Digest authentication failed: Invalid username or password".into(),
                ));
            }
        } else {
            return Err(AdminError::AuthenticationFailed(
                "No administrative credentials configured for AVM TR-064 request".into(),
            ));
        }

        if self.simulate_soap_fault.load(Ordering::SeqCst) {
            return Ok(r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <s:Fault>
      <faultcode>s:Client</faultcode>
      <faultstring>UPnPError</faultstring>
      <detail>
        <UPnPError xmlns="urn:dslforum-org:control-1-0">
          <errorCode>714</errorCode>
          <errorDescription>NoSuchEntryInArray</errorDescription>
        </UPnPError>
      </detail>
    </s:Fault>
  </s:Body>
</s:Envelope>"#
                .to_string());
        }

        // 1. DeviceInfo:1#GetInfo
        if service_urn.contains("DeviceInfo") && action == "GetInfo" {
            if self.simulate_non_avm.load(Ordering::SeqCst) {
                return Ok(r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetInfoResponse xmlns:u="urn:dslforum-org:service:DeviceInfo:1">
      <NewManufacturerName>GenericCorp</NewManufacturerName>
      <NewModelName>GenericRouter</NewModelName>
      <NewDescription>GenericRouter</NewDescription>
      <NewSoftwareVersion>1.0.0</NewSoftwareVersion>
      <NewHardwareVersion>GenericRouter</NewHardwareVersion>
      <NewSerialNumber>000000000000</NewSerialNumber>
    </u:GetInfoResponse>
  </s:Body>
</s:Envelope>"#
                    .to_string());
            } else {
                return Ok(r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetInfoResponse xmlns:u="urn:dslforum-org:service:DeviceInfo:1">
      <NewManufacturerName>AVM</NewManufacturerName>
      <NewModelName>FRITZ!Box 7590</NewModelName>
      <NewDescription>FRITZ!Box 7590</NewDescription>
      <NewSoftwareVersion>154.07.57</NewSoftwareVersion>
      <NewHardwareVersion>FRITZ!Box 7590</NewHardwareVersion>
      <NewSerialNumber>CCCE1E000001</NewSerialNumber>
    </u:GetInfoResponse>
  </s:Body>
</s:Envelope>"#
                    .to_string());
            }
        }

        // 2. Hosts:1#GetHostNumberOfEntries
        if service_urn.contains("Hosts") && action == "GetHostNumberOfEntries" {
            let count = self.known_hosts.read().len();
            return Ok(format!(
                r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetHostNumberOfEntriesResponse xmlns:u="urn:dslforum-org:service:Hosts:1">
      <NewHostNumberOfEntries>{}</NewHostNumberOfEntries>
    </u:GetHostNumberOfEntriesResponse>
  </s:Body>
</s:Envelope>"#,
                count
            ));
        }

        // 3. Hosts:1#GetGenericHostEntry
        if service_urn.contains("Hosts") && action == "GetGenericHostEntry" {
            let idx = SoapClient::extract_tag_value(args_xml, "NewIndex")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);

            let hosts = self.known_hosts.read();
            if let Some(h) = hosts.get(idx) {
                return Ok(format!(
                    r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetGenericHostEntryResponse xmlns:u="urn:dslforum-org:service:Hosts:1">
      <NewIPAddress>{}</NewIPAddress>
      <NewMACAddress>{}</NewMACAddress>
      <NewHostName>{}</NewHostName>
      <NewInterfaceType>{}</NewInterfaceType>
      <NewActive>{}</NewActive>
    </u:GetGenericHostEntryResponse>
  </s:Body>
</s:Envelope>"#,
                    h.ip,
                    h.mac,
                    h.hostname.as_str(),
                    h.interface_type.as_str(),
                    if h.active { "1" } else { "0" }
                ));
            } else {
                return Ok(r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <s:Fault>
      <faultcode>s:Client</faultcode>
      <faultstring>UPnPError</faultstring>
      <detail>
        <UPnPError xmlns="urn:dslforum-org:control-1-0">
          <errorCode>713</errorCode>
          <errorDescription>SpecifiedArrayIndexInvalid</errorDescription>
        </UPnPError>
      </detail>
    </s:Fault>
  </s:Body>
</s:Envelope>"#
                    .to_string());
            }
        }

        // 4. X_AVM-DE_HostFilter:1#DisallowWANAccessByIP
        if service_urn.contains("X_AVM-DE_HostFilter") && action == "DisallowWANAccessByIP" {
            let ip_str =
                SoapClient::extract_tag_value(args_xml, "NewIPv4Address").unwrap_or_default();
            let disallow_str =
                SoapClient::extract_tag_value(args_xml, "NewDisallow").unwrap_or_default();

            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                let disallow = disallow_str == "1" || disallow_str.eq_ignore_ascii_case("true");
                let delay = self.async_delay_cycles.load(Ordering::SeqCst);
                if delay > 0 {
                    self.pending_disallow_state.write().insert(ip, disallow);
                    self.async_poll_counter.store(0, Ordering::SeqCst);
                } else {
                    if disallow {
                        self.active_disallowed_ips.write().insert(ip);
                    } else {
                        self.active_disallowed_ips.write().remove(&ip);
                    }
                }

                return Ok(r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:DisallowWANAccessByIPResponse xmlns:u="urn:dslforum-org:service:X_AVM-DE_HostFilter:1" />
  </s:Body>
</s:Envelope>"#
                    .to_string());
            } else {
                return Err(AdminError::CommunicationError(
                    "Missing or invalid NewIPv4Address".into(),
                ));
            }
        }

        // 5. X_AVM-DE_HostFilter:1#GetWANAccessByIP
        if service_urn.contains("X_AVM-DE_HostFilter") && action == "GetWANAccessByIP" {
            let ip_str =
                SoapClient::extract_tag_value(args_xml, "NewIPv4Address").unwrap_or_default();
            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                // Check if an asynchronous delay cycle is currently pending
                let delay = self.async_delay_cycles.load(Ordering::SeqCst);
                if delay > 0 {
                    let count = self.async_poll_counter.fetch_add(1, Ordering::SeqCst) + 1;
                    if count >= delay {
                        if let Some(target_state) = self.pending_disallow_state.write().remove(&ip)
                        {
                            if target_state {
                                self.active_disallowed_ips.write().insert(ip);
                            } else {
                                self.active_disallowed_ips.write().remove(&ip);
                            }
                        }
                    }
                }

                let is_disallowed = self.active_disallowed_ips.read().contains(&ip);
                let disallow_val = if is_disallowed { "1" } else { "0" };
                let wan_access = if is_disallowed { "denied" } else { "granted" };

                return Ok(format!(
                    r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetWANAccessByIPResponse xmlns:u="urn:dslforum-org:service:X_AVM-DE_HostFilter:1">
      <NewDisallow>{}</NewDisallow>
      <NewWANAccess>{}</NewWANAccess>
    </u:GetWANAccessByIPResponse>
  </s:Body>
</s:Envelope>"#,
                    disallow_val, wan_access
                ));
            } else {
                return Err(AdminError::CommunicationError(
                    "Invalid NewIPv4Address in query".into(),
                ));
            }
        }

        Err(AdminError::UnsupportedOperation(format!(
            "Unsupported mock TR-064 action '{}' for service '{}'",
            action, service_urn
        )))
    }

    fn fetch_description(
        &self,
        _description_url: &str,
        credentials: Option<&RouterCredentials>,
    ) -> Result<String, AdminError> {
        if self.simulate_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout("Mock fetch description timeout".into()));
        }

        if self.simulate_auth_fail.load(Ordering::SeqCst) {
            return Err(AdminError::AuthenticationFailed(
                "AVM TR-064 Digest authentication failed: 401 Unauthorized".into(),
            ));
        }

        if let Some(creds) = credentials {
            if creds.username != self.valid_username
                || creds.password.expose() != self.valid_password
            {
                return Err(AdminError::AuthenticationFailed(
                    "AVM TR-064 Digest authentication failed: Invalid username or password".into(),
                ));
            }
        }

        let hostfilter_block = if self.simulate_missing_hostfilter.load(Ordering::SeqCst) {
            ""
        } else {
            r#"<service>
        <serviceType>urn:dslforum-org:service:X_AVM-DE_HostFilter:1</serviceType>
        <serviceId>urn:X_AVM-DE_HostFilter-serviceId:X_AVM-DE_HostFilter1</serviceId>
        <controlURL>/upnp/control/x_hostfilter</controlURL>
        <eventSubURL>/upnp/control/x_hostfilter</eventSubURL>
        <SCPDURL>/x_hostfilterSCPD.xml</SCPDURL>
      </service>"#
        };

        Ok(format!(
            r#"<?xml version="1.0"?>
<root xmlns="urn:dslforum-org:device-1-0">
  <device>
    <deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>FRITZ!Box 7590</friendlyName>
    <manufacturer>AVM</manufacturer>
    <manufacturerURL>http://www.avm.de</manufacturerURL>
    <modelDescription>FRITZ!Box 7590</modelDescription>
    <modelName>FRITZ!Box 7590</modelName>
    <modelNumber>7590</modelNumber>
    <serviceList>
      <service>
        <serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType>
        <serviceId>urn:DeviceInfo-serviceId:DeviceInfo1</serviceId>
        <controlURL>/upnp/control/deviceinfo</controlURL>
        <eventSubURL>/upnp/control/deviceinfo</eventSubURL>
        <SCPDURL>/deviceinfoSCPD.xml</SCPDURL>
      </service>
      <service>
        <serviceType>urn:dslforum-org:service:Hosts:1</serviceType>
        <serviceId>urn:Hosts-serviceId:Hosts1</serviceId>
        <controlURL>/upnp/control/hosts</controlURL>
        <eventSubURL>/upnp/control/hosts</eventSubURL>
        <SCPDURL>/hostsSCPD.xml</SCPDURL>
      </service>
      {}
    </serviceList>
  </device>
</root>"#,
            hostfilter_block
        ))
    }
}

/// Router administrative provider for AVM FRITZ!Box devices implementing TR-064 management services.
pub struct AvmAdminProvider {
    pub target_ip: Ipv4Addr,
    pub base_endpoint: String,
    pub transport: Box<dyn AvmTransport>,
    pub credentials: Arc<RwLock<Option<RouterCredentials>>>,
    pub discovered_identity: Arc<RwLock<Option<RouterIdentity>>>,
    pub service_control_urls: Arc<RwLock<HashMap<String, String>>>,
    pub active_policies: Arc<RwLock<HashMap<String, ActivePolicyStatus>>>,
    pub force_timeout: Arc<AtomicBool>,
}

impl AvmAdminProvider {
    pub fn new(target_ip: Ipv4Addr, endpoint: impl Into<String>) -> Self {
        let raw_endpoint = endpoint.into();
        let endpoint = if raw_endpoint.is_empty() {
            format!("https://{}:49443/tr64desc.xml", target_ip)
        } else {
            raw_endpoint
        };

        Self {
            target_ip,
            base_endpoint: endpoint,
            transport: Box::new(HttpAvmTransport::new()),
            credentials: Arc::new(RwLock::new(None)),
            discovered_identity: Arc::new(RwLock::new(None)),
            service_control_urls: Arc::new(RwLock::new(HashMap::new())),
            active_policies: Arc::new(RwLock::new(HashMap::new())),
            force_timeout: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_transport(mut self, transport: Box<dyn AvmTransport>) -> Self {
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

    /// Authenticates with the AVM FRITZ!Box by testing identity retrieval via `DeviceInfo:1#GetInfo`.
    pub fn login(&self) -> Result<(), AdminError> {
        let creds_guard = self.credentials.read();
        if creds_guard.is_none() {
            return Err(AdminError::AuthenticationFailed(
                "No administrative credentials configured for AVM FRITZ!Box".into(),
            ));
        }
        drop(creds_guard);
        self.detect_identity().map(|_| ())
    }

    /// Resolves and validates a service control URL, verifying that it points strictly to
    /// the configured router target host to prevent Server-Side Request Forgery (SSRF).
    pub fn validate_control_url(&self, raw_url: &str) -> Result<String, AdminError> {
        let trimmed = raw_url.trim();

        // If relative path (e.g. "/upnp/control/x_hostfilter")
        if trimmed.starts_with('/') {
            // Parse base endpoint scheme and host
            let fallback_host = self.target_ip.to_string();
            let (scheme, host_port) = if self.base_endpoint.starts_with("https://") {
                let rest = &self.base_endpoint[8..];
                let hp = rest.split('/').next().unwrap_or("");
                ("https", hp)
            } else if self.base_endpoint.starts_with("http://") {
                let rest = &self.base_endpoint[7..];
                let hp = rest.split('/').next().unwrap_or("");
                ("http", hp)
            } else {
                ("https", fallback_host.as_str())
            };

            return Ok(format!("{}://{}{}", scheme, host_port, trimmed));
        }

        // Absolute URL: strictly inspect scheme and host
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            let scheme_end = trimmed.find("://").unwrap();
            let after_scheme = &trimmed[scheme_end + 3..];
            let host_port = after_scheme.split('/').next().unwrap_or("");
            let host = host_port.split(':').next().unwrap_or("");

            // Host must match the configured target IP or router hostname
            if host != self.target_ip.to_string() && host != "fritz.box" {
                return Err(AdminError::SecurityViolation(format!(
                    "Control URL host '{}' does not match configured router target '{}'. Request halted to prevent SSRF.",
                    host, self.target_ip
                )));
            }

            return Ok(trimmed.to_string());
        }

        Err(AdminError::SecurityViolation(format!(
            "Invalid control URL format '{}': must be relative path or verified HTTP(S) URL",
            trimmed
        )))
    }

    /// Parses all `<service>` blocks from the XML device description document.
    pub fn parse_service_list(&self, xml: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        let mut search_idx = 0;

        while let Some(start) = xml[search_idx..].find("<service>") {
            let service_start = search_idx + start;
            if let Some(end) = xml[service_start..].find("</service>") {
                let service_block = &xml[service_start..service_start + end];
                let svc_type = SoapClient::extract_tag_value(service_block, "serviceType");
                let ctrl_url = SoapClient::extract_tag_value(service_block, "controlURL");

                if let (Some(st), Some(cu)) = (svc_type, ctrl_url) {
                    if let Ok(validated_url) = self.validate_control_url(&cu) {
                        map.insert(st, validated_url);
                    }
                }
                search_idx = service_start + end + 10;
            } else {
                break;
            }
        }

        map
    }

    /// Fetches the device description document and caches validated service control URLs.
    pub fn ensure_services_discovered(&self) -> Result<(), AdminError> {
        if !self.service_control_urls.read().is_empty() {
            return Ok(());
        }

        let creds_guard = self.credentials.read();
        let desc_xml = self
            .transport
            .fetch_description(&self.base_endpoint, creds_guard.as_ref())?;

        let services = self.parse_service_list(&desc_xml);
        if services.is_empty() {
            return Err(AdminError::CommunicationError(
                "No valid TR-064 services discovered in device description document".into(),
            ));
        }

        *self.service_control_urls.write() = services;
        Ok(())
    }

    /// Resolves the validated control URL for a given service URN.
    pub fn get_service_control_url(&self, service_urn: &str) -> Result<String, AdminError> {
        self.ensure_services_discovered()?;
        let map = self.service_control_urls.read();
        for (st, cu) in map.iter() {
            if st.contains(service_urn) || service_urn.contains(st) {
                return Ok(cu.clone());
            }
        }
        Err(AdminError::UnsupportedOperation(format!(
            "Required TR-064 service '{}' was not found on this AVM FRITZ!Box",
            service_urn
        )))
    }

    /// Checks if a SOAP response contains an `<s:Fault>` element and converts it to an `AdminError`.
    pub fn check_soap_fault(&self, response_xml: &str) -> Result<(), AdminError> {
        if response_xml.contains("<s:Fault>") || response_xml.contains("<Fault>") {
            let error_code = SoapClient::extract_tag_value(response_xml, "errorCode");
            let error_desc = SoapClient::extract_tag_value(response_xml, "errorDescription")
                .or_else(|| SoapClient::extract_tag_value(response_xml, "faultstring"))
                .unwrap_or_else(|| "Unknown SOAP Fault".into());

            let code_str = error_code.as_deref().unwrap_or("0");
            match code_str {
                "401" => Err(AdminError::UnsupportedOperation(format!(
                    "AVM TR-064 Invalid Action (code 401): {}",
                    error_desc
                ))),
                "402" => Err(AdminError::CommunicationError(format!(
                    "AVM TR-064 Invalid Arguments (code 402): {}",
                    error_desc
                ))),
                "606" => Err(AdminError::AuthenticationFailed(format!(
                    "AVM TR-064 Action Not Authorized (code 606): {}",
                    error_desc
                ))),
                "713" | "714" => Err(AdminError::PolicyNotFound(format!(
                    "AVM TR-064 Entry Not Found (code {}): {}",
                    code_str, error_desc
                ))),
                _ => Err(AdminError::TransactionFailed(format!(
                    "AVM TR-064 SOAP Fault (code {}): {}",
                    code_str, error_desc
                ))),
            }
        } else {
            Ok(())
        }
    }

    /// Polls `GetWANAccessByIP` within a bounded timeout to verify that an asynchronous
    /// host filter policy change has taken effect on the router.
    pub fn poll_verify_wan_access(
        &self,
        ip: Ipv4Addr,
        expected_disallow: bool,
        timeout: Duration,
    ) -> Result<(), AdminError> {
        let creds_guard = self.credentials.read();
        let creds = creds_guard
            .as_ref()
            .ok_or_else(|| AdminError::AuthenticationFailed("No credentials configured".into()))?;

        let ctrl_url = self.get_service_control_url("X_AVM-DE_HostFilter")?;
        let service_urn = "urn:dslforum-org:service:X_AVM-DE_HostFilter:1";
        let args = format!("<NewIPv4Address>{}</NewIPv4Address>", ip);

        let start = Instant::now();
        let expected_val = if expected_disallow { "1" } else { "0" };

        while start.elapsed() < timeout {
            let resp = self.transport.execute_soap(
                &ctrl_url,
                service_urn,
                "GetWANAccessByIP",
                &args,
                Some(creds),
            )?;

            self.check_soap_fault(&resp)?;

            if let Some(val) = SoapClient::extract_tag_value(&resp, "NewDisallow") {
                if val == expected_val {
                    return Ok(());
                }
            }

            std::thread::sleep(Duration::from_millis(50));
        }

        Err(AdminError::Timeout(format!(
            "HostFilter policy verification timed out after {:.1}s: router did not confirm WAN access state (expected NewDisallow={}) for IP {}",
            timeout.as_secs_f64(),
            expected_val,
            ip
        )))
    }

    /// Queries the router's host inventory via `Hosts:1#GetGenericHostEntry`.
    pub fn enumerate_lan_hosts(&self) -> Result<Vec<GatewayHostEntry>, AdminError> {
        let creds_guard = self.credentials.read();
        let creds = creds_guard
            .as_ref()
            .ok_or_else(|| AdminError::AuthenticationFailed("No credentials configured".into()))?;

        let ctrl_url = self.get_service_control_url("Hosts:1")?;
        let service_urn = "urn:dslforum-org:service:Hosts:1";

        // Query total host count if available
        let num_resp = self.transport.execute_soap(
            &ctrl_url,
            service_urn,
            "GetHostNumberOfEntries",
            "",
            Some(creds),
        )?;
        let count = SoapClient::extract_tag_value(&num_resp, "NewHostNumberOfEntries")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(64);

        let mut hosts = Vec::new();
        for idx in 0..count {
            let args = format!("<NewIndex>{}</NewIndex>", idx);
            match self.transport.execute_soap(
                &ctrl_url,
                service_urn,
                "GetGenericHostEntry",
                &args,
                Some(creds),
            ) {
                Ok(resp) => {
                    if self.check_soap_fault(&resp).is_err() {
                        break;
                    }
                    if let Some(ip_str) = SoapClient::extract_tag_value(&resp, "NewIPAddress") {
                        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                            let mac: MacAddress =
                                SoapClient::extract_tag_value(&resp, "NewMACAddress")
                                    .and_then(|m| m.parse().ok())
                                    .unwrap_or(MacAddress::ZERO);
                            let hostname = SoapClient::extract_tag_value(&resp, "NewHostName")
                                .unwrap_or_else(|| "Host".into());
                            let iface_type =
                                SoapClient::extract_tag_value(&resp, "NewInterfaceType")
                                    .unwrap_or_else(|| "Ethernet".into());
                            let active = SoapClient::extract_tag_value(&resp, "NewActive")
                                .map(|a| a == "1")
                                .unwrap_or(false);

                            hosts.push(GatewayHostEntry {
                                ip,
                                mac,
                                hostname,
                                interface_type: iface_type,
                                active,
                            });
                        }
                    }
                }
                Err(_) => break,
            }
        }

        Ok(hosts)
    }
}

impl RouterAdminProvider for AvmAdminProvider {
    fn name(&self) -> &'static str {
        "AVM-FRITZ!Box-TR064"
    }

    fn detect_identity(&self) -> Result<RouterIdentity, AdminError> {
        if self.force_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout("AVM identity probe timed out".into()));
        }

        if let Some(cached) = self.discovered_identity.read().clone() {
            return Ok(cached);
        }

        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        let ctrl_url = self.get_service_control_url("DeviceInfo:1")?;
        let service_urn = "urn:dslforum-org:service:DeviceInfo:1";

        let resp =
            self.transport
                .execute_soap(&ctrl_url, service_urn, "GetInfo", "", Some(creds))?;
        self.check_soap_fault(&resp)?;

        let manufacturer = SoapClient::extract_tag_value(&resp, "NewManufacturerName");
        let model_name = SoapClient::extract_tag_value(&resp, "NewModelName");
        let software_version = SoapClient::extract_tag_value(&resp, "NewSoftwareVersion");
        let hardware_version = SoapClient::extract_tag_value(&resp, "NewHardwareVersion");
        let serial = SoapClient::extract_tag_value(&resp, "NewSerialNumber");

        let mfg_str = manufacturer.as_deref().unwrap_or("");
        let model_str = model_name.as_deref().unwrap_or("");

        // Strict verification: Target must be an authentic AVM FRITZ!Box device
        if !mfg_str.eq_ignore_ascii_case("AVM") && !model_str.contains("FRITZ!Box") {
            return Err(AdminError::IdentityMismatch(format!(
                "Connected target is not an authentic AVM FRITZ!Box gateway (detected manufacturer: '{}', model: '{}')",
                mfg_str, model_str
            )));
        }

        let mut identity = RouterIdentity::new(self.target_ip);
        identity.manufacturer = Some("AVM".to_string());
        identity.model_name = model_name;
        identity.firmware_version = software_version;
        identity.hardware_version = hardware_version;
        identity.serial_number = serial;

        *self.discovered_identity.write() = Some(identity.clone());
        Ok(identity)
    }

    fn inspect_capabilities(&self) -> RouterCapabilityMatrix {
        let is_authed = self.is_authenticated();
        if !is_authed {
            return RouterCapabilityMatrix {
                authenticated_admin_interfaces: CapabilityClassification::Conditional(
                    "Requires valid AVM FRITZ!Box credentials with TR-064 permissions (HTTP Digest)"
                        .into(),
                ),
                ..Default::default()
            };
        }

        // Verify if X_AVM-DE_HostFilter:1 was discovered in service list
        let has_hostfilter = self
            .service_control_urls
            .read()
            .keys()
            .any(|k| k.contains("X_AVM-DE_HostFilter"));

        if !has_hostfilter {
            return RouterCapabilityMatrix {
                read_only_discovery: CapabilityClassification::Implemented,
                host_inventory: CapabilityClassification::Implemented,
                authenticated_admin_interfaces: CapabilityClassification::Implemented,
                ipv4_policy_enforcement: CapabilityClassification::NotImplemented,
                per_device_access_policy: CapabilityClassification::NotImplemented,
                network_wide_access_policy: CapabilityClassification::NotImplemented,
                ..Default::default()
            };
        }

        RouterCapabilityMatrix {
            read_only_discovery: CapabilityClassification::Implemented,
            host_inventory: CapabilityClassification::Implemented,
            device_identification_interface_type: CapabilityClassification::Implemented,
            ipv4_policy_enforcement: CapabilityClassification::Implemented,
            ipv6_policy_enforcement: CapabilityClassification::Conditional(
                "AVM HostFilter service operates strictly on IPv4 addresses; IPv6 WAN traffic cannot be filtered via TR-064".into(),
            ),
            per_device_access_policy: CapabilityClassification::Implemented,
            network_wide_access_policy: CapabilityClassification::Conditional(
                "Enforced by applying individual HostFilter policies across all enumerated LAN hosts; does not disconnect the physical WAN connection".into(),
            ),
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
                "UNSUPPORTED: AVM FRITZ!Box TR-064 lacks a router-resident autonomous scheduler. Temporary policies rejected to avoid unrecoverable restrictions.".to_string()
            }
        };

        let mut risks = Vec::new();
        risks.push(
            "AVM HostFilter applies exclusively to IPv4; IPv6 traffic will continue to route"
                .into(),
        );
        if let PolicyScope::NetworkWide = req.scope {
            risks.push("Network-wide pause applies individual per-device filter rules to all discovered hosts; new hosts connecting afterward will not be automatically blocked.".into());
            risks.push("Physical WAN connection remains active for router services (VoIP, TR-064, firmware updates).".into());
        }
        if let PolicyDuration::Temporary(_) = req.duration {
            risks.push("Autonomous router-side expiry is NOT supported on FRITZ!Box; temporary policies must be rejected.".into());
        }

        Ok(OperationPlan {
            provider_name: self.name().to_string(),
            router_identity: identity,
            target_scope: req.scope.clone(),
            target_count,
            duration: req.duration.clone(),
            persistence: req.persistence.clone(),
            discovered_services: vec![
                "tr64:deviceinfo".into(),
                "tr64:hosts".into(),
                "tr64:x_hostfilter".into(),
            ],
            supported_capabilities: vec![
                "AVM-TR-064-Digest-Auth".into(),
                "X_AVM-DE_HostFilter-DisallowWANAccess".into(),
                "Ethernet-And-WiFi-Client-Filtering".into(),
                "Preserved-Local-Management-Plane".into(),
            ],
            unsupported_capabilities: vec![
                "Autonomous-Router-Scheduler-Recovery".into(),
                "IPv6-Host-Filtering".into(),
                "Global-WAN-Interface-Teardown".into(),
            ],
            required_auth: "TR-064 HTTP Digest Authentication".into(),
            auth_established: self.is_authenticated(),
            expected_wan_impact: "Restricted devices lose outbound IPv4 WAN access via AVM HostFilter profile; dual-stack IPv6 is NOT restricted.".into(),
            expected_lan_impact: "Router administration (HTTP 80/443, TR-064 49000/49443) and local intra-LAN communication remain 100% accessible.".into(),
            management_plane_safe: true,
            recovery_mechanism: recovery,
            uncertainties_and_risks: risks,
            is_dry_run: true,
        })
    }

    fn query_active_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError> {
        let policies = self.active_policies.read().values().cloned().collect();
        Ok(policies)
    }

    fn is_authenticated(&self) -> bool {
        self.credentials.read().is_some()
    }

    fn apply_policy(&self, req: &OperationPlanRequest) -> Result<ActivePolicyStatus, AdminError> {
        let _plan = self.plan_operation(req)?;

        // Autonomous recovery is NOT supported on AVM FRITZ!Box TR-064.
        // Fail closed rather than falsely promising automatic restoration.
        if let PolicyDuration::Temporary(_) = req.duration {
            return Err(AdminError::UnsupportedOperation(
                "AVM FRITZ!Box TR-064 does not provide a router-resident autonomous scheduler. Temporary policies with guaranteed autonomous expiry cannot be enforced by this router; operation rejected to prevent unrecoverable restrictions."
                    .into(),
            ));
        }

        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        let ctrl_url = self.get_service_control_url("X_AVM-DE_HostFilter")?;
        let service_urn = "urn:dslforum-org:service:X_AVM-DE_HostFilter:1";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match &req.scope {
            PolicyScope::SpecificTargets(targets) => {
                if targets.is_empty() {
                    return Err(AdminError::ScopeViolation(
                        "Target list cannot be empty".into(),
                    ));
                }

                let mut applied_targets = Vec::new();
                for target_ip in targets {
                    let args = format!(
                        "<NewIPv4Address>{}</NewIPv4Address><NewDisallow>1</NewDisallow>",
                        target_ip
                    );

                    let res: Result<(), AdminError> = (|| {
                        let resp = self.transport.execute_soap(
                            &ctrl_url,
                            service_urn,
                            "DisallowWANAccessByIP",
                            &args,
                            Some(creds),
                        )?;
                        self.check_soap_fault(&resp)?;
                        self.poll_verify_wan_access(*target_ip, true, Duration::from_secs(5))?;
                        Ok(())
                    })();

                    match res {
                        Ok(()) => applied_targets.push(*target_ip),
                        Err(e) => {
                            // Roll back previously applied targets on partial failure, capturing rollback outcomes
                            let mut rollback_errors = Vec::new();
                            for applied_ip in &applied_targets {
                                let rollback_args = format!(
                                    "<NewIPv4Address>{}</NewIPv4Address><NewDisallow>0</NewDisallow>",
                                    applied_ip
                                );
                                if let Err(rb_err) = self.transport.execute_soap(
                                    &ctrl_url,
                                    service_urn,
                                    "DisallowWANAccessByIP",
                                    &rollback_args,
                                    Some(creds),
                                ) {
                                    rollback_errors
                                        .push(format!("target {}: {}", applied_ip, rb_err));
                                }
                            }
                            if rollback_errors.is_empty() {
                                return Err(AdminError::TransactionFailed(format!(
                                    "Failed to disallow WAN access for target {} on AVM (all {} prior targets rolled back): {}",
                                    target_ip, applied_targets.len(), e
                                )));
                            } else {
                                let applied_strs: Vec<String> =
                                    applied_targets.iter().map(|ip| ip.to_string()).collect();
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

                let policy_id = if targets.len() == 1 {
                    format!("avm_pause_{}", targets[0].to_string().replace('.', "_"))
                } else {
                    format!(
                        "avm_pause_multi_{}",
                        targets[0].to_string().replace('.', "_")
                    )
                };

                let native_id = if targets.len() == 1 {
                    format!("AVM-HostFilter:{}", targets[0])
                } else {
                    format!("AVM-HostFilter:{} targets", targets.len())
                };

                let status = ActivePolicyStatus::new(
                    policy_id.clone(),
                    req.scope.clone(),
                    now,
                    None,
                    true,
                    native_id,
                    false,
                );

                self.active_policies
                    .write()
                    .insert(policy_id, status.clone());
                Ok(status)
            }
            PolicyScope::NetworkWide => {
                let hosts = self.enumerate_lan_hosts()?;
                let mut affected_ips = Vec::new();

                for h in hosts {
                    if h.ip == self.target_ip {
                        continue; // Protect router IP from lockout
                    }
                    let args = format!(
                        "<NewIPv4Address>{}</NewIPv4Address><NewDisallow>1</NewDisallow>",
                        h.ip
                    );

                    let resp = self.transport.execute_soap(
                        &ctrl_url,
                        service_urn,
                        "DisallowWANAccessByIP",
                        &args,
                        Some(creds),
                    )?;
                    self.check_soap_fault(&resp)?;
                    self.poll_verify_wan_access(h.ip, true, Duration::from_secs(5))?;
                    affected_ips.push(h.ip);
                }

                let policy_id = "avm_pause_network_wide".to_string();
                let status = ActivePolicyStatus::new(
                    policy_id.clone(),
                    PolicyScope::NetworkWide,
                    now,
                    None,
                    true,
                    format!("AVM-HostFilter:NetworkWide({} hosts)", affected_ips.len()),
                    false,
                );

                self.active_policies
                    .write()
                    .insert(policy_id, status.clone());
                Ok(status)
            }
        }
    }

    fn resume_policy(&self, scope: &PolicyScope) -> Result<Vec<String>, AdminError> {
        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        let ctrl_url = self.get_service_control_url("X_AVM-DE_HostFilter")?;
        let service_urn = "urn:dslforum-org:service:X_AVM-DE_HostFilter:1";

        let mut resumed = Vec::new();

        match scope {
            PolicyScope::SpecificTargets(targets) => {
                for target_ip in targets {
                    let args = format!(
                        "<NewIPv4Address>{}</NewIPv4Address><NewDisallow>0</NewDisallow>",
                        target_ip
                    );

                    let resp = self.transport.execute_soap(
                        &ctrl_url,
                        service_urn,
                        "DisallowWANAccessByIP",
                        &args,
                        Some(creds),
                    )?;
                    self.check_soap_fault(&resp)?;

                    // Asynchronous verification: poll until router confirms WAN access is restored
                    self.poll_verify_wan_access(*target_ip, false, Duration::from_secs(5))?;
                    resumed.push(target_ip.to_string());
                }

                // Remove matching records from active tracking
                let mut active = self.active_policies.write();
                active.retain(|_, pol| match &pol.scope {
                    PolicyScope::SpecificTargets(t) => !t.iter().any(|ip| targets.contains(ip)),
                    PolicyScope::NetworkWide => true,
                });
            }
            PolicyScope::NetworkWide => {
                let hosts = self.enumerate_lan_hosts()?;
                for h in hosts {
                    let args = format!(
                        "<NewIPv4Address>{}</NewIPv4Address><NewDisallow>0</NewDisallow>",
                        h.ip
                    );

                    let resp = self.transport.execute_soap(
                        &ctrl_url,
                        service_urn,
                        "DisallowWANAccessByIP",
                        &args,
                        Some(creds),
                    )?;
                    self.check_soap_fault(&resp)?;
                    self.poll_verify_wan_access(h.ip, false, Duration::from_secs(5))?;
                    resumed.push(h.ip.to_string());
                }

                self.active_policies.write().clear();
            }
        }

        Ok(resumed)
    }

    fn reconcile_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError> {
        let creds_guard = self.credentials.read();
        let creds = creds_guard.as_ref().ok_or_else(|| {
            AdminError::AuthenticationFailed("No router credentials configured".into())
        })?;

        let ctrl_url = self.get_service_control_url("X_AVM-DE_HostFilter")?;
        let service_urn = "urn:dslforum-org:service:X_AVM-DE_HostFilter:1";

        let mut verified = Vec::new();
        let mut active = self.active_policies.write();

        for pol in active.values_mut() {
            if let PolicyScope::SpecificTargets(targets) = &pol.scope {
                if let Some(ip) = targets.first() {
                    let args = format!("<NewIPv4Address>{}</NewIPv4Address>", ip);
                    if let Ok(resp) = self.transport.execute_soap(
                        &ctrl_url,
                        service_urn,
                        "GetWANAccessByIP",
                        &args,
                        Some(creds),
                    ) {
                        if let Some(disallow) = SoapClient::extract_tag_value(&resp, "NewDisallow")
                        {
                            if disallow == "1" {
                                verified.push(pol.clone());
                            }
                        }
                    }
                }
            } else if let PolicyScope::NetworkWide = pol.scope {
                verified.push(pol.clone());
            }
        }

        Ok(verified)
    }

    fn adjust_policy_duration(
        &self,
        scope: &PolicyScope,
        new_duration: &PolicyDuration,
    ) -> Result<ActivePolicyStatus, AdminError> {
        if let PolicyDuration::Temporary(_) = new_duration {
            return Err(AdminError::UnsupportedOperation(
                "AVM FRITZ!Box TR-064 lacks an autonomous router-resident scheduler. Cannot adjust policy to a temporary duration with guaranteed autonomous recovery."
                    .into(),
            ));
        }

        let mut active = self.active_policies.write();
        for pol in active.values_mut() {
            if &pol.scope == scope {
                pol.expires_at_unix = None;
                return Ok(pol.clone());
            }
        }

        Err(AdminError::PolicyNotFound(
            "No active AVM HostFilter policy found matching the specified scope".into(),
        ))
    }

    fn list_devices(
        &self,
    ) -> Result<Vec<crate::gateway::admin::diagnostics::RouterDeviceEntry>, AdminError> {
        let hosts = self.enumerate_lan_hosts()?;
        let devices = hosts
            .into_iter()
            .map(|h| {
                let mut entry = crate::gateway::admin::diagnostics::RouterDeviceEntry::new();
                entry = entry.with_ip(h.ip);
                if !h.mac.is_zero() {
                    entry = entry.with_mac(h.mac);
                }
                if !h.hostname.is_empty() {
                    entry = entry.with_hostname(h.hostname);
                }
                if !h.interface_type.is_empty() {
                    entry = entry.with_interface(h.interface_type);
                }
                entry = entry.with_active(h.active);
                entry
            })
            .collect();
        Ok(devices)
    }
}
