use parking_lot::RwLock;
use serde_json::{json, Value};
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::gateway::admin::openwrt::{parse_policy_timestamps, OpenWrtTransport};
use crate::gateway::admin::plan::AdminError;
use crate::types::MacAddress;

/// Discovers the local OpenSSH client executable.
/// On Windows, checks System32\OpenSSH\ssh.exe followed by PATH.
/// On non-Windows platforms, checks PATH for 'ssh'.
pub fn find_ssh_client() -> Result<PathBuf, AdminError> {
    #[cfg(windows)]
    {
        // 1. Check SystemRoot / WINDIR System32\OpenSSH\ssh.exe
        if let Ok(sysroot) = std::env::var("SystemRoot") {
            let candidate = PathBuf::from(sysroot).join(r"System32\OpenSSH\ssh.exe");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
        if let Ok(windir) = std::env::var("WINDIR") {
            let candidate = PathBuf::from(windir).join(r"System32\OpenSSH\ssh.exe");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
        let default_sys32 = PathBuf::from(r"C:\Windows\System32\OpenSSH\ssh.exe");
        if default_sys32.exists() {
            return Ok(default_sys32);
        }
    }

    // 2. Search in PATH
    if let Ok(path_var) = std::env::var("PATH") {
        let separator = if cfg!(windows) { ';' } else { ':' };
        for dir in path_var.split(separator) {
            let p = Path::new(dir.trim());
            #[cfg(windows)]
            let candidate = p.join("ssh.exe");
            #[cfg(not(windows))]
            let candidate = p.join("ssh");

            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    Err(AdminError::CommunicationError(
        "OpenSSH client not found. Ensure the Windows Optional Feature 'OpenSSH Client' is installed or 'ssh.exe' is available in System32 / PATH.".into(),
    ))
}

/// Configuration for an SSH-based administrative transport session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshConfig {
    pub host: Ipv4Addr,
    pub port: u16,
    pub username: String,
    pub key_path: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
    pub pinned_host_key: Option<String>,
    pub connect_timeout: Duration,
}

impl SshConfig {
    pub fn new(host: Ipv4Addr) -> Self {
        Self {
            host,
            port: 22,
            username: "root".to_string(),
            key_path: None,
            known_hosts_path: None,
            pinned_host_key: None,
            connect_timeout: Duration::from_secs(5),
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }

    pub fn with_key_path(mut self, key_path: impl Into<PathBuf>) -> Self {
        self.key_path = Some(key_path.into());
        self
    }

    pub fn with_known_hosts_path(mut self, known_hosts_path: impl Into<PathBuf>) -> Self {
        self.known_hosts_path = Some(known_hosts_path.into());
        self
    }

    pub fn with_pinned_host_key(mut self, host_key: impl Into<String>) -> Self {
        self.pinned_host_key = Some(host_key.into());
        self
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }
}

/// Standardized execution result from an SSH remote command invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Abstraction for SSH subprocess execution.
/// Enables deterministic unit testing without spawning real subprocesses or making network calls.
pub trait SshCommandExecutor: Send + Sync {
    fn execute(&self, config: &SshConfig, command: &str) -> Result<SshOutput, AdminError>;
}

/// Production implementation of `SshCommandExecutor` invoking native Windows OpenSSH (`ssh.exe`).
pub struct ProcessSshExecutor {
    ssh_path: Option<PathBuf>,
}

impl ProcessSshExecutor {
    pub fn new() -> Self {
        Self { ssh_path: None }
    }

    pub fn with_custom_client(ssh_path: PathBuf) -> Self {
        Self {
            ssh_path: Some(ssh_path),
        }
    }
}

impl Default for ProcessSshExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl SshCommandExecutor for ProcessSshExecutor {
    fn execute(&self, config: &SshConfig, command: &str) -> Result<SshOutput, AdminError> {
        let ssh_bin = match &self.ssh_path {
            Some(p) => {
                if !p.exists() {
                    return Err(AdminError::CommunicationError(format!(
                        "Configured SSH executable not found at {}",
                        p.display()
                    )));
                }
                p.clone()
            }
            None => find_ssh_client()?,
        };

        // If key_path is configured, verify it exists before invoking
        if let Some(ref key) = config.key_path {
            if !key.exists() {
                return Err(AdminError::AuthenticationFailed(format!(
                    "Configured SSH private key not found at '{}'",
                    key.display()
                )));
            }
        }

        // Pinned host key handling
        let mut temp_kh_file = None;
        let effective_kh_path = if let Some(ref pinned) = config.pinned_host_key {
            let temp_dir = std::env::temp_dir();
            let kh_path = temp_dir.join(format!(
                "rustrict_kh_{}_{}.tmp",
                config.host.to_string().replace('.', "_"),
                config.port
            ));
            let entry = if pinned.contains(' ')
                && (pinned.starts_with('[') || pinned.starts_with(&config.host.to_string()))
            {
                format!("{}\n", pinned)
            } else {
                format!("[{}]:{} {}\n", config.host, config.port, pinned)
            };
            let _ = fs::write(&kh_path, entry);
            temp_kh_file = Some(kh_path.clone());
            Some(kh_path)
        } else {
            config.known_hosts_path.clone()
        };

        let mut cmd = Command::new(&ssh_bin);
        cmd.arg("-p").arg(config.port.to_string());
        cmd.arg("-o").arg(format!(
            "ConnectTimeout={}",
            config.connect_timeout.as_secs().max(1)
        ));
        cmd.arg("-o").arg("BatchMode=yes");
        cmd.arg("-o").arg("PasswordAuthentication=no");
        cmd.arg("-o").arg("NumberOfPasswordPrompts=0");
        cmd.arg("-o").arg("StrictHostKeyChecking=yes");

        if let Some(ref kh) = effective_kh_path {
            cmd.arg("-o")
                .arg(format!("UserKnownHostsFile={}", kh.display()));
        }

        if let Some(ref key) = config.key_path {
            cmd.arg("-i").arg(key);
        }

        cmd.arg("-T"); // Disable pseudo-terminal allocation
        cmd.arg(format!("{}@{}", config.username, config.host));
        cmd.arg(command);

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            AdminError::CommunicationError(format!("Failed to spawn SSH subprocess: {}", e))
        })?;

        // Drain stdout and stderr in background threads to prevent pipe buffer deadlocks
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();

        let stdout_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut s) = stdout_pipe {
                use std::io::Read;
                let _ = s.read_to_end(&mut buf);
            }
            buf
        });

        let stderr_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut s) = stderr_pipe {
                use std::io::Read;
                let _ = s.read_to_end(&mut buf);
            }
            buf
        });

        // Bounded request timeout: connect timeout + execution headroom with child termination
        let timeout = config.connect_timeout + Duration::from_secs(10);
        let start = std::time::Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        if let Some(kh) = temp_kh_file {
                            let _ = fs::remove_file(kh);
                        }
                        return Err(AdminError::Timeout(
                            "SSH remote command execution timed out on router endpoint".into(),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(kh) = temp_kh_file {
                        let _ = fs::remove_file(kh);
                    }
                    return Err(AdminError::CommunicationError(format!(
                        "Error monitoring SSH subprocess: {}",
                        e
                    )));
                }
            }
        };

        let stdout_bytes = stdout_handle.join().unwrap_or_default();
        let stderr_bytes = stderr_handle.join().unwrap_or_default();

        // Cleanup temporary known_hosts file if created
        if let Some(kh) = temp_kh_file {
            let _ = fs::remove_file(kh);
        }

        let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
        let stderr = String::from_utf8_lossy(&stderr_bytes).to_string();
        let exit_code = status.code().unwrap_or(-1);

        if exit_code == 255 {
            if stderr.contains("Host key verification failed")
                || stderr.contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
            {
                return Err(AdminError::AuthenticationFailed(
                    "SSH host-key verification failed: Host key mismatch or untrusted host. Connection aborted to prevent MITM attacks.".into(),
                ));
            }
            if stderr.contains("Permission denied") || stderr.contains("Authentication failed") {
                return Err(AdminError::AuthenticationFailed(format!(
                    "SSH authentication failed: {}",
                    stderr.trim()
                )));
            }
            if stderr.contains("timed out") || stderr.contains("Connection timed out") {
                return Err(AdminError::Timeout(format!(
                    "SSH connection timed out: {}",
                    stderr.trim()
                )));
            }
            return Err(AdminError::CommunicationError(format!(
                "SSH connection terminated unexpectedly (code 255): {}",
                stderr.trim()
            )));
        }

        Ok(SshOutput {
            stdout,
            stderr,
            exit_code,
        })
    }
}

/// Offline mock SSH executor for hermetic regression tests with zero network traffic.
#[derive(Clone)]
pub struct MockSshExecutor {
    pub simulate_missing_client: Arc<AtomicBool>,
    pub simulate_host_key_mismatch: Arc<AtomicBool>,
    pub simulate_auth_failure: Arc<AtomicBool>,
    pub simulate_non_root: Arc<AtomicBool>,
    pub simulate_non_openwrt: Arc<AtomicBool>,
    pub simulate_timeout: Arc<AtomicBool>,
    pub simulate_command_error: Arc<AtomicBool>,
    pub crontab_content: Arc<RwLock<String>>,
    pub watchdog_script_content: Arc<RwLock<Option<String>>>,
    pub firewall_rules: Arc<RwLock<serde_json::Map<String, Value>>>,
    pub uncommitted_rules: Arc<RwLock<Option<serde_json::Map<String, Value>>>>,
    pub executed_commands: Arc<RwLock<Vec<String>>>,
}

impl Default for MockSshExecutor {
    fn default() -> Self {
        Self {
            simulate_missing_client: Arc::new(AtomicBool::new(false)),
            simulate_host_key_mismatch: Arc::new(AtomicBool::new(false)),
            simulate_auth_failure: Arc::new(AtomicBool::new(false)),
            simulate_non_root: Arc::new(AtomicBool::new(false)),
            simulate_non_openwrt: Arc::new(AtomicBool::new(false)),
            simulate_timeout: Arc::new(AtomicBool::new(false)),
            simulate_command_error: Arc::new(AtomicBool::new(false)),
            crontab_content: Arc::new(RwLock::new(String::new())),
            watchdog_script_content: Arc::new(RwLock::new(None)),
            firewall_rules: Arc::new(RwLock::new(serde_json::Map::new())),
            uncommitted_rules: Arc::new(RwLock::new(None)),
            executed_commands: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl MockSshExecutor {
    /// Simulates a router reboot cycle on the mock state.
    /// Evaluates router-resident watchdog and removes expired firewall rules.
    pub fn simulate_reboot_cycle(&self, current_unix: u64) {
        let has_watchdog = self.crontab_content.read().contains("watchdog.sh")
            || self.crontab_content.read().contains("rustrict_pause");

        if has_watchdog && self.watchdog_script_content.read().is_some() {
            let mut uci = self.firewall_rules.write();
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

impl SshCommandExecutor for MockSshExecutor {
    fn execute(&self, _config: &SshConfig, command: &str) -> Result<SshOutput, AdminError> {
        self.executed_commands.write().push(command.to_string());

        if self.simulate_missing_client.load(Ordering::SeqCst) {
            return Err(AdminError::CommunicationError(
                "OpenSSH client not found. Ensure the Windows Optional Feature 'OpenSSH Client' is installed or 'ssh.exe' is available in System32 / PATH.".into(),
            ));
        }

        if self.simulate_host_key_mismatch.load(Ordering::SeqCst) {
            return Err(AdminError::AuthenticationFailed(
                "SSH host-key verification failed: Host key mismatch or untrusted host. Connection aborted to prevent MITM attacks.".into(),
            ));
        }

        if self.simulate_auth_failure.load(Ordering::SeqCst) {
            return Err(AdminError::AuthenticationFailed(
                "SSH authentication failed: Permission denied (publickey)".into(),
            ));
        }

        if self.simulate_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout(
                "SSH connection timed out after 5 seconds".into(),
            ));
        }

        // Command dispatch
        if command.trim() == "id -u" {
            if self.simulate_non_root.load(Ordering::SeqCst) {
                return Ok(SshOutput {
                    stdout: "1000\n".into(),
                    stderr: "".into(),
                    exit_code: 0,
                });
            } else {
                return Ok(SshOutput {
                    stdout: "0\n".into(),
                    stderr: "".into(),
                    exit_code: 0,
                });
            }
        }

        // Crontab read
        if command.contains("cat '/etc/crontabs/root'")
            || command.contains("cat /etc/crontabs/root")
        {
            if self.simulate_command_error.load(Ordering::SeqCst) {
                return Ok(SshOutput {
                    stdout: "".into(),
                    stderr: "cat: /etc/crontabs/root: Permission denied".into(),
                    exit_code: 1,
                });
            }
            return Ok(SshOutput {
                stdout: self.crontab_content.read().clone(),
                stderr: "".into(),
                exit_code: 0,
            });
        }

        // Watchdog script read
        if command.contains("cat '/etc/rustrict/watchdog.sh'")
            || command.contains("cat /etc/rustrict/watchdog.sh")
        {
            return Ok(SshOutput {
                stdout: self
                    .watchdog_script_content
                    .read()
                    .clone()
                    .unwrap_or_default(),
                stderr: "".into(),
                exit_code: 0,
            });
        }

        // Watchdog script write
        if (command.contains("> '/etc/rustrict/watchdog.sh'")
            || command.contains("> /etc/rustrict/watchdog.sh"))
            && command.contains("printf")
        {
            if self.simulate_command_error.load(Ordering::SeqCst) {
                return Ok(SshOutput {
                    stdout: "".into(),
                    stderr: "mkdir: cannot create directory '/etc/rustrict': Read-only file system"
                        .into(),
                    exit_code: 1,
                });
            }
            if let Some(start) = command.find("printf '%s' '") {
                let rest = &command[start + 13..];
                if let Some(end) = rest.rfind("' > '") {
                    *self.watchdog_script_content.write() =
                        Some(rest[..end].replace("'\\''", "'").to_string());
                } else if let Some(end2) = rest.rfind("' > ") {
                    *self.watchdog_script_content.write() =
                        Some(rest[..end2].replace("'\\''", "'").to_string());
                }
            }
            return Ok(SshOutput {
                stdout: "".into(),
                stderr: "".into(),
                exit_code: 0,
            });
        }

        // Crontab write
        if (command.contains("> '/etc/crontabs/root'") || command.contains("> /etc/crontabs/root"))
            && command.contains("printf")
        {
            if self.simulate_command_error.load(Ordering::SeqCst) {
                return Ok(SshOutput {
                    stdout: "".into(),
                    stderr: "cannot create /etc/crontabs/root: Permission denied".into(),
                    exit_code: 1,
                });
            }
            if let Some(start) = command.find("printf '%s' '") {
                let rest = &command[start + 13..];
                if let Some(end) = rest.rfind("' > '") {
                    *self.crontab_content.write() = rest[..end].replace("'\\''", "'").to_string();
                } else if let Some(end2) = rest.rfind("' > ") {
                    *self.crontab_content.write() = rest[..end2].replace("'\\''", "'").to_string();
                }
            }
            return Ok(SshOutput {
                stdout: "".into(),
                stderr: "".into(),
                exit_code: 0,
            });
        }

        // Remote ubus call
        if let Some(pos) = command.find("ubus call ") {
            let sub = &command[pos + 10..];
            let parts: Vec<&str> = sub.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                let object = parts[0];
                let method = parts[1];
                let params: Value = if parts.len() == 3 {
                    let raw = parts[2].trim();
                    let trimmed = if raw.starts_with('\'') && raw.ends_with('\'') && raw.len() >= 2
                    {
                        &raw[1..raw.len() - 1]
                    } else {
                        raw
                    };
                    let unescaped = trimmed.replace("'\\''", "'");
                    serde_json::from_str(&unescaped).unwrap_or(Value::Null)
                } else {
                    Value::Null
                };

                match (object, method) {
                    ("system", "board") => {
                        if self.simulate_non_openwrt.load(Ordering::SeqCst) {
                            return Ok(SshOutput {
                                stdout: json!({
                                    "model": "Generic Consumer Router",
                                    "release": {
                                        "distribution": "ProprietaryRTOS",
                                        "version": "1.0.0"
                                    }
                                })
                                .to_string(),
                                stderr: "".into(),
                                exit_code: 0,
                            });
                        } else {
                            return Ok(SshOutput {
                                stdout: json!({
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
                                })
                                .to_string(),
                                stderr: "".into(),
                                exit_code: 0,
                            });
                        }
                    }
                    ("uci", "get") => {
                        let rules = self.firewall_rules.read().clone();
                        return Ok(SshOutput {
                            stdout: json!({ "values": Value::Object(rules) }).to_string(),
                            stderr: "".into(),
                            exit_code: 0,
                        });
                    }
                    ("uci", "add") => {
                        let mut snap = self.uncommitted_rules.write();
                        if snap.is_none() {
                            *snap = Some(self.firewall_rules.read().clone());
                        }
                        let values = params.get("values").cloned().unwrap_or(json!({}));
                        let name = values
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("rule");
                        let sec_id = format!("cfg_{}", name);
                        self.firewall_rules.write().insert(sec_id.clone(), values);
                        return Ok(SshOutput {
                            stdout: json!({ "section": sec_id }).to_string(),
                            stderr: "".into(),
                            exit_code: 0,
                        });
                    }
                    ("uci", "set") => {
                        let mut snap = self.uncommitted_rules.write();
                        if snap.is_none() {
                            *snap = Some(self.firewall_rules.read().clone());
                        }
                        let section = params.get("section").and_then(|s| s.as_str()).unwrap_or("");
                        let new_vals = params.get("values").and_then(|v| v.as_object());
                        if let Some(target) = self
                            .firewall_rules
                            .write()
                            .get_mut(section)
                            .and_then(|v| v.as_object_mut())
                        {
                            if let Some(nv) = new_vals {
                                for (k, v) in nv {
                                    target.insert(k.clone(), v.clone());
                                }
                            }
                        }
                        return Ok(SshOutput {
                            stdout: json!({}).to_string(),
                            stderr: "".into(),
                            exit_code: 0,
                        });
                    }
                    ("uci", "delete") => {
                        let mut snap = self.uncommitted_rules.write();
                        if snap.is_none() {
                            *snap = Some(self.firewall_rules.read().clone());
                        }
                        let section = params.get("section").and_then(|s| s.as_str()).unwrap_or("");
                        self.firewall_rules.write().remove(section);
                        return Ok(SshOutput {
                            stdout: json!({}).to_string(),
                            stderr: "".into(),
                            exit_code: 0,
                        });
                    }
                    ("uci", "commit") => {
                        if self.simulate_command_error.load(Ordering::SeqCst) {
                            return Ok(SshOutput {
                                stdout: "".into(),
                                stderr: "uci: I/O error: disk full".into(),
                                exit_code: 1,
                            });
                        }
                        *self.uncommitted_rules.write() = None;
                        return Ok(SshOutput {
                            stdout: json!({}).to_string(),
                            stderr: "".into(),
                            exit_code: 0,
                        });
                    }
                    ("uci", "revert") => {
                        if let Some(prev) = self.uncommitted_rules.write().take() {
                            *self.firewall_rules.write() = prev;
                        }
                        return Ok(SshOutput {
                            stdout: json!({}).to_string(),
                            stderr: "".into(),
                            exit_code: 0,
                        });
                    }
                    ("uci", "apply") => {
                        return Ok(SshOutput {
                            stdout: json!({}).to_string(),
                            stderr: "".into(),
                            exit_code: 0,
                        });
                    }
                    _ => {}
                }
            }
        }

        // Generic fallback
        Ok(SshOutput {
            stdout: "".into(),
            stderr: "".into(),
            exit_code: 0,
        })
    }
}

/// Validates that an input argument does not contain shell metacharacters.
/// Rejects characters that could lead to command injection or subshell execution:
/// ';', '&', '|', '$', '`', '\n', '\r', '\0', '<', '>', '(', ')', '{', '}'
pub fn validate_shell_arg(arg: &str) -> Result<(), AdminError> {
    for c in arg.chars() {
        match c {
            ';' | '&' | '|' | '$' | '`' | '\n' | '\r' | '\0' | '<' | '>' | '(' | ')' | '{'
            | '}' => {
                return Err(AdminError::SecurityViolation(format!(
                    "Prohibited character '{}' detected in argument '{}'. Potential command injection attempt halted.",
                    c, arg
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Strictly parses and validates an IPv4 address string to prevent shell injection.
pub fn validate_ip_str(ip_str: &str) -> Result<Ipv4Addr, AdminError> {
    validate_shell_arg(ip_str)?;
    ip_str.trim().parse::<Ipv4Addr>().map_err(|e| {
        AdminError::SecurityViolation(format!("Invalid IPv4 address format '{}': {}", ip_str, e))
    })
}

/// Strictly parses and validates a MAC address string to prevent shell injection.
pub fn validate_mac_str(mac_str: &str) -> Result<MacAddress, AdminError> {
    validate_shell_arg(mac_str)?;
    mac_str.trim().parse::<MacAddress>().map_err(|e| {
        AdminError::SecurityViolation(format!("Invalid MAC address format '{}': {}", mac_str, e))
    })
}

/// Strictly validates a policy identifier (must contain only [a-zA-Z0-9_-]).
pub fn validate_policy_id(id: &str) -> Result<(), AdminError> {
    validate_shell_arg(id)?;
    if id.is_empty() || id.len() > 64 {
        return Err(AdminError::SecurityViolation(
            "Policy identifier must be between 1 and 64 characters".into(),
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AdminError::SecurityViolation(format!(
            "Policy identifier '{}' contains invalid characters. Only alphanumeric, '_' and '-' are permitted.",
            id
        )));
    }
    Ok(())
}

/// Safely escapes a string for inclusion in a single-quoted POSIX shell argument.
/// In POSIX shell, inside '...', every character is literal except '.
/// Single quotes are escaped by ending the quote, inserting a backslash-escaped quote, and restarting: '\''
pub fn escape_posix_single_quotes(s: &str) -> String {
    s.replace('\'', "'\\''")
}

/// Isolated SSH administrative transport for OpenWrt routers.
/// Implements `OpenWrtTransport` by executing remote `ubus` and file management operations over SSH.
pub struct SshOpenWrtTransport {
    pub config: SshConfig,
    pub executor: Arc<dyn SshCommandExecutor>,
    pub is_root_verified: Arc<AtomicBool>,
}

impl SshOpenWrtTransport {
    pub fn new(config: SshConfig) -> Self {
        Self {
            config,
            executor: Arc::new(ProcessSshExecutor::new()),
            is_root_verified: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_executor(config: SshConfig, executor: Arc<dyn SshCommandExecutor>) -> Self {
        Self {
            config,
            executor,
            is_root_verified: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Explicitly verifies that the connected SSH session has root privileges (UID 0).
    pub fn verify_root_privileges(&self) -> Result<(), AdminError> {
        let out = self.executor.execute(&self.config, "id -u")?;
        if out.exit_code != 0 {
            return Err(AdminError::AuthenticationFailed(format!(
                "Failed to probe user privileges over SSH: {}",
                out.stderr.trim()
            )));
        }
        let uid_str = out.stdout.trim();
        if uid_str != "0" {
            return Err(AdminError::AuthenticationFailed(format!(
                "Connected as SSH user '{}' (UID {}). OpenWrt firewall administration requires root privileges (UID 0).",
                self.config.username, uid_str
            )));
        }
        self.is_root_verified.store(true, Ordering::SeqCst);
        Ok(())
    }
}

impl OpenWrtTransport for SshOpenWrtTransport {
    fn transport_name(&self) -> &'static str {
        "SSH"
    }

    fn is_ssh(&self) -> bool {
        true
    }

    fn call(
        &self,
        _endpoint: &str,
        object: &str,
        method: &str,
        params: Value,
        _session_id: &str,
    ) -> Result<Value, AdminError> {
        validate_shell_arg(object)?;
        validate_shell_arg(method)?;

        match (object, method) {
            ("session", "login") => {
                self.verify_root_privileges()?;
                Ok(json!({
                    "ubus_rpc_session": "ssh_authenticated_root_session",
                    "expires": 86400,
                    "timeout": 86400
                }))
            }
            ("file", "read") => {
                let path = params.get("path").and_then(|p| p.as_str()).unwrap_or("");
                validate_shell_arg(path)?;
                let cmd = format!("cat '{}' 2>/dev/null", escape_posix_single_quotes(path));
                let out = self.executor.execute(&self.config, &cmd)?;
                if out.exit_code != 0 && !out.stderr.is_empty() {
                    return Err(AdminError::CommunicationError(format!(
                        "Failed to read file '{}' over SSH: {}",
                        path,
                        out.stderr.trim()
                    )));
                }
                Ok(json!({ "data": out.stdout }))
            }
            ("file", "write") => {
                let path = params.get("path").and_then(|p| p.as_str()).unwrap_or("");
                let data = params.get("data").and_then(|d| d.as_str()).unwrap_or("");
                validate_shell_arg(path)?;

                let escaped_path = escape_posix_single_quotes(path);
                let escaped_data = escape_posix_single_quotes(data);

                let cmd = if path.ends_with(".sh") {
                    format!(
                        "mkdir -p $(dirname '{}') && printf '%s' '{}' > '{}' && chmod 755 '{}'",
                        escaped_path, escaped_data, escaped_path, escaped_path
                    )
                } else {
                    format!(
                        "mkdir -p $(dirname '{}') && printf '%s' '{}' > '{}'",
                        escaped_path, escaped_data, escaped_path
                    )
                };

                let out = self.executor.execute(&self.config, &cmd)?;
                if out.exit_code != 0 {
                    return Err(AdminError::CommunicationError(format!(
                        "Failed to write file '{}' over SSH (exit code {}): {}",
                        path,
                        out.exit_code,
                        out.stderr.trim()
                    )));
                }
                Ok(json!({}))
            }
            _ => {
                let params_str =
                    serde_json::to_string(&params).unwrap_or_else(|_| "{}".to_string());
                let escaped_params = escape_posix_single_quotes(&params_str);
                let cmd = format!("ubus call {} {} '{}'", object, method, escaped_params);

                let out = self.executor.execute(&self.config, &cmd)?;
                if out.exit_code != 0 {
                    return Err(AdminError::CommunicationError(format!(
                        "SSH remote ubus call {} {} failed (exit code {}): {}",
                        object,
                        method,
                        out.exit_code,
                        out.stderr.trim()
                    )));
                }

                let trimmed = out.stdout.trim();
                if trimmed.is_empty() {
                    return Ok(json!({}));
                }

                let parsed: Value = serde_json::from_str(trimmed).map_err(|e| {
                    AdminError::CommunicationError(format!(
                        "Failed to parse JSON output from remote ubus call: {}. Raw output: '{}'",
                        e, trimmed
                    ))
                })?;

                Ok(parsed)
            }
        }
    }
}
