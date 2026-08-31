pub mod dns;
pub mod llmnr;
pub mod mdns;
pub mod netbios;
pub mod oui;
pub mod passive;
pub mod smb;
pub mod tls;

use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::time::Duration;
use crate::types::{MacAddress, NameSource};

pub struct HostIdentity {
    pub hostname: String,
    pub source: NameSource,
    pub vendor: String,
}

/// Attempts a fast HTTP title probe (port 80 / 8080) for routers, web consoles, and printers
fn probe_http_title(ip: Ipv4Addr) -> Option<String> {
    for port in [80, 8080] {
        let addr = SocketAddrV4::new(ip, port);
        if let Ok(mut stream) = TcpStream::connect_timeout(&std::net::SocketAddr::V4(addr), Duration::from_millis(60)) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(60)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(60)));
            use std::io::{Read, Write};
            let req = format!("GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Rustrict\r\nConnection: close\r\n\r\n", ip);
            if stream.write_all(req.as_bytes()).is_ok() {
                let mut buf = [0u8; 1024];
                if let Ok(n) = stream.read(&mut buf) {
                    let resp = String::from_utf8_lossy(&buf[..n]);
                    if let Some(start) = resp.to_lowercase().find("<title>") {
                        if let Some(end) = resp.to_lowercase().find("</title>") {
                            if start + 7 < end {
                                let title = resp[start + 7..end].trim().to_string();
                                if !title.is_empty() && title.len() < 50 {
                                    return Some(title);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Verified Multi-Protocol Host Identity Aggregator
/// Never synthesizes or guesses hostnames if protocols return no authoritative name.
pub fn resolve_identity(
    ip: Ipv4Addr,
    mac: &MacAddress,
    local_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
) -> HostIdentity {
    resolve_identity_with_gateway(ip, mac, local_ip, gateway_ip, None)
}

pub fn resolve_identity_with_gateway(
    ip: Ipv4Addr,
    mac: &MacAddress,
    local_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    gateway_client: Option<&crate::gateway::GatewayClient>,
) -> HostIdentity {
    // 1. Identify Gateway
    if ip == gateway_ip {
        let vendor = oui::lookup_vendor(mac);
        return HostIdentity {
            hostname: "Default Gateway (Router)".to_string(),
            source: NameSource::Gateway,
            vendor: if vendor != "Generic Network Device" { vendor.to_string() } else { "Router".to_string() },
        };
    }

    // 2. Identify Local Machine
    if ip == local_ip {
        let name = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "This PC".to_string());
        return HostIdentity {
            hostname: format!("{} (This PC)", name),
            source: NameSource::Local,
            vendor: "Local Host".to_string(),
        };
    }

    let vendor = oui::lookup_vendor(mac).to_string();

    // 3. Try Router Gateway UPnP / TR-064 DHCP Client Table (Authoritative router lease name)
    if let Some(gc) = gateway_client {
        if let Some(entry) = gc.get_host_by_ip(&ip) {
            if !entry.hostname.is_empty() {
                return HostIdentity {
                    hostname: entry.hostname,
                    source: NameSource::RouterUpnp,
                    vendor,
                };
            }
        }
    }

    // 3. Try SMB NTLMSSP Challenge Leak (Windows Laptops, PCs, Samba NAS)
    if let Some(name) = smb::probe_smb_ntlm(ip) {
        return HostIdentity {
            hostname: name,
            source: NameSource::Smb,
            vendor,
        };
    }

    // 4. Try TLS Certificate Common Name (Windows RDP, HTTPS servers)
    if let Some(name) = tls::probe_tls_certificate(ip) {
        return HostIdentity {
            hostname: name,
            source: NameSource::Tls,
            vendor,
        };
    }

    // 5. Try NetBIOS Name Service (Windows, Samba, NAS, Printers)
    if let Some(name) = netbios::query_netbios(ip) {
        return HostIdentity {
            hostname: name,
            source: NameSource::NetBios,
            vendor,
        };
    }

    // 6. Try mDNS (Apple MacBooks, iPhones, Linux workstations, IoT)
    if let Some(name) = mdns::query_mdns(ip) {
        return HostIdentity {
            hostname: name,
            source: NameSource::Mdns,
            vendor,
        };
    }

    // 7. Try LLMNR (Windows Link-Local)
    if let Some(name) = llmnr::query_llmnr(ip) {
        return HostIdentity {
            hostname: name,
            source: NameSource::NetBios,
            vendor,
        };
    }

    // 8. Try HTTP banner / title probe (Routers, IP cams, Web consoles)
    if let Some(title) = probe_http_title(ip) {
        return HostIdentity {
            hostname: title,
            source: NameSource::Mdns,
            vendor,
        };
    }

    // 9. Try Reverse DNS
    if let Some(name) = dns::query_reverse_dns(ip) {
        return HostIdentity {
            hostname: name,
            source: NameSource::Mdns,
            vendor,
        };
    }

    // 10. No authentic hostname resolved - do NOT guess or fake a device name.
    HostIdentity {
        hostname: String::new(),
        source: NameSource::Unresolved,
        vendor,
    }
}
