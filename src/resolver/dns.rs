use std::net::Ipv4Addr;
use std::process::Command;

/// Attempts reverse DNS lookup using nslookup with short timeout
pub fn query_reverse_dns(ip: Ipv4Addr) -> Option<String> {
    let output = Command::new("nslookup")
        .arg(ip.to_string())
        .output()
        .ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("Name:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let name = parts[1].trim_end_matches('.').to_string();
                    if !name.is_empty() {
                        return Some(name);
                    }
                }
            }
        }
    }
    None
}
