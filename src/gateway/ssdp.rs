use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct GatewayServiceInfo {
    pub addr: SocketAddr,
    pub control_url: String,
    pub service_urn: String,
}

pub struct SsdpScanner;

impl SsdpScanner {
    /// Discovers router UPnP/TR-064 LANHostConfigManagement service
    pub fn discover(gateway_ip: Ipv4Addr) -> Option<GatewayServiceInfo> {
        // 1. Try SSDP multicast discovery
        if let Some(info) = Self::multicast_discovery(gateway_ip) {
            return Some(info);
        }

        // 2. Unicast fallback probe on common router UPnP ports
        Self::unicast_probe(gateway_ip)
    }

    fn multicast_discovery(gateway_ip: Ipv4Addr) -> Option<GatewayServiceInfo> {
        let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
        let _ = socket.set_read_timeout(Some(Duration::from_millis(800)));
        let _ = socket.set_broadcast(true);

        let query = "M-SEARCH * HTTP/1.1\r\n\
                     HOST: 239.255.255.250:1900\r\n\
                     MAN: \"ssdp:discover\"\r\n\
                     MX: 1\r\n\
                     ST: ssdp:all\r\n\r\n";

        let dest: SocketAddr = "239.255.255.250:1900".parse().ok()?;
        let _ = socket.send_to(query.as_bytes(), dest);

        let mut buf = [0u8; 2048];
        let start = std::time::Instant::now();

        while start.elapsed() < Duration::from_millis(1000) {
            if let Ok((len, src)) = socket.recv_from(&mut buf) {
                // If response comes from gateway IP or on same subnet
                if src.ip() == gateway_ip {
                    let text = String::from_utf8_lossy(&buf[..len]);
                    if let Some(loc) = Self::parse_header_value(&text, "LOCATION") {
                        if let Some(info) = Self::parse_description_url(&loc) {
                            return Some(info);
                        }
                    }
                }
            }
        }
        None
    }

    fn unicast_probe(gateway_ip: Ipv4Addr) -> Option<GatewayServiceInfo> {
        let candidate_ports = [1900, 49152, 49153, 5000, 80, 8080];
        let candidate_paths = [
            "/rootDesc.xml",
            "/desc.xml",
            "/igd.xml",
            "/upnp/IGD.xml",
            "/gatedesc.xml",
        ];

        for &port in &candidate_ports {
            let addr = SocketAddr::new(gateway_ip.into(), port);
            for &path in &candidate_paths {
                if let Some(desc_xml) = Self::fetch_http(addr, path) {
                    if let Some((control_path, service_urn)) = Self::find_host_service(&desc_xml) {
                        return Some(GatewayServiceInfo {
                            addr,
                            control_url: control_path,
                            service_urn,
                        });
                    }
                }
            }
        }
        None
    }

    pub fn parse_header_value(headers: &str, key: &str) -> Option<String> {
        let key_lower = key.to_ascii_lowercase();
        for line in headers.lines() {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().to_ascii_lowercase() == key_lower {
                    return Some(v.trim().to_string());
                }
            }
        }
        None
    }

    fn parse_description_url(url_str: &str) -> Option<GatewayServiceInfo> {
        let stripped = url_str.strip_prefix("http://")?;
        let (host_port, path) = match stripped.split_once('/') {
            Some((hp, p)) => (hp, format!("/{}", p)),
            None => (stripped, "/".to_string()),
        };

        let addr: SocketAddr = host_port.parse().ok()?;
        let desc_xml = Self::fetch_http(addr, &path)?;
        let (control_path, service_urn) = Self::find_host_service(&desc_xml)?;

        Some(GatewayServiceInfo {
            addr,
            control_url: control_path,
            service_urn,
        })
    }

    fn fetch_http(addr: SocketAddr, path: &str) -> Option<String> {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(200)).ok()?;
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));

        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Rustrict\r\nConnection: close\r\n\r\n",
            path, addr
        );

        stream.write_all(req.as_bytes()).ok()?;

        let mut buf = Vec::new();
        let mut temp = [0u8; 2048];
        while let Ok(n) = stream.read(&mut temp) {
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&temp[..n]);
            if buf.len() > 65536 {
                break;
            }
        }

        Some(String::from_utf8_lossy(&buf).to_string())
    }

    fn find_host_service(xml: &str) -> Option<(String, String)> {
        let known_services = [
            "urn:schemas-upnp-org:service:LANHostConfigManagement:1",
            "urn:dslforum-org:service:LANHostConfigManagement:1",
            "urn:schemas-upnp-org:service:Hosts:1",
        ];

        for &svc in &known_services {
            if let Some(svc_pos) = xml.find(svc) {
                // Find <controlURL> within the service block
                let window = &xml[svc_pos..std::cmp::min(svc_pos + 1000, xml.len())];
                if let Some(ctrl) = crate::gateway::soap::SoapClient::extract_tag_value(window, "controlURL") {
                    let path = if ctrl.starts_with('/') {
                        ctrl
                    } else {
                        format!("/{}", ctrl)
                    };
                    return Some((path, svc.to_string()));
                }
            }
        }

        // Fallback default control URLs used by common router chipsets
        if xml.contains("InternetGatewayDevice") {
            return Some((
                "/upnp/control/LANHostConfigManagement1".to_string(),
                "urn:schemas-upnp-org:service:LANHostConfigManagement:1".to_string(),
            ));
        }

        None
    }
}
