use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;
use rayon::prelude::*;

use crate::core::assessment::{PortStatus, ServiceEntry};

pub const TOP_PORTS: &[(u16, &str)] = &[
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (80, "http"),
    (110, "pop3"),
    (135, "msrpc"),
    (139, "netbios-ssn"),
    (143, "imap"),
    (443, "https"),
    (445, "microsoft-ds"),
    (554, "rtsp"),
    (1433, "ms-sql"),
    (1883, "mqtt"),
    (3306, "mysql"),
    (3389, "ms-wbt-server"),
    (5000, "upnp"),
    (5432, "postgresql"),
    (5900, "vnc"),
    (8000, "http-alt"),
    (8080, "http-proxy"),
    (8443, "https-alt"),
    (8883, "secure-mqtt"),
    (9000, "management"),
];

pub fn get_top_port_numbers() -> Vec<u16> {
    TOP_PORTS.iter().map(|&(p, _)| p).collect()
}

pub fn get_service_name_for_port(port: u16) -> &'static str {

    for &(p, name) in TOP_PORTS {
        if p == port {
            return name;
        }
    }
    match port {
        20 => "ftp-data",
        69 => "tftp",
        88 => "kerberos",
        123 => "ntp",
        161 => "snmp",
        389 => "ldap",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        5985 => "wsman-http",
        5986 => "wsman-https",
        _ => "unknown",
    }
}

pub fn parse_ports_arg(arg: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    let parts = arg.split(',');

    for part in parts {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((start_s, end_s)) = trimmed.split_once('-') {
            let start: u16 = start_s.trim().parse().map_err(|e| format!("Invalid port number: {}", e))?;
            let end: u16 = end_s.trim().parse().map_err(|e| format!("Invalid port number: {}", e))?;
            if start > end {
                return Err(format!("Invalid port range: {}-{}", start, end));
            }
            // Limit range expansion to at most 1024 ports per range chunk to prevent thread exhaustion
            let count = (end as u32) - (start as u32) + 1;
            if count > 2048 {
                return Err(format!("Port range {}-{} exceeds 2048 ports limit", start, end));
            }
            for p in start..=end {
                if !ports.contains(&p) {
                    ports.push(p);
                }
            }
        } else {
            let port: u16 = trimmed.parse().map_err(|e| format!("Invalid port: {}", e))?;
            if !ports.contains(&port) {
                ports.push(port);
            }
        }
    }

    if ports.is_empty() {
        return Err("No valid ports specified".into());
    }

    Ok(ports)
}

pub fn probe_tcp_port(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<ServiceEntry> {
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;

    let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(400)));

    let service_name = get_service_name_for_port(port);
    let mut banner: Option<String> = None;

    // Banner grab heuristics
    if port == 80 || port == 8080 || port == 8000 || port == 5000 {
        // Send fast HTTP HEAD
        let req = b"HEAD / HTTP/1.0\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n";
        if stream.write_all(req).is_ok() {
            let mut buf = [0u8; 1024];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    let resp = String::from_utf8_lossy(&buf[..n]);
                    for line in resp.lines() {
                        if line.to_ascii_lowercase().starts_with("server:") {
                            banner = Some(line.trim().to_string());
                            break;
                        }
                    }
                }
            }
        }
    } else if port == 21 || port == 22 || port == 25 || port == 110 {
        // Protocols that speak first with a greeting banner
        let mut buf = [0u8; 512];
        if let Ok(n) = stream.read(&mut buf) {
            if n > 0 {
                let greeting = String::from_utf8_lossy(&buf[..n]);
                if let Some(first_line) = greeting.lines().next() {
                    banner = Some(first_line.trim().to_string());
                }
            }
        }
    }

    Some(ServiceEntry {
        port,
        transport: "tcp".to_string(),
        service_name: service_name.to_string(),
        banner,
        status: PortStatus::Open,
    })
}

pub fn scan_host_ports<F>(
    ip: Ipv4Addr,
    ports: &[u16],
    timeout: Duration,
    on_progress: F,
) -> Vec<ServiceEntry>
where
    F: Fn(usize, usize) + Sync + Send,
{
    let total = ports.len();
    let scanned = std::sync::atomic::AtomicUsize::new(0);

    let mut open_services: Vec<ServiceEntry> = ports
        .par_iter()
        .filter_map(|&port| {
            let res = probe_tcp_port(ip, port, timeout);
            let done = scanned.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if done.is_multiple_of(5) || done == total {
                on_progress(done, total);
            }

            res
        })
        .collect();

    open_services.sort_by_key(|s| s.port);
    open_services
}
