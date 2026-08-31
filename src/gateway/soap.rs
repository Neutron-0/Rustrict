use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::time::Duration;

use crate::gateway::hosts::GatewayHostEntry;
use crate::types::MacAddress;

/// Constructs and executes UPnP / TR-064 SOAP queries against the router gateway
pub struct SoapClient;

impl SoapClient {
    /// Extracts text between `<tag>` and `</tag>` (ignoring namespaces or case)
    pub fn extract_tag_value(xml: &str, tag_name: &str) -> Option<String> {
        let tag_lower = tag_name.to_ascii_lowercase();
        let xml_lower = xml.to_ascii_lowercase();

        // Search for opening tag variations like `<tag>` or `<u:tag>` or `<tag `
        let mut search_idx = 0;
        while let Some(open_rel) = xml_lower[search_idx..].find('<') {
            let open_pos = search_idx + open_rel;
            if let Some(close_bracket) = xml[open_pos..].find('>') {
                let bracket_pos = open_pos + close_bracket;
                let full_tag = &xml[open_pos + 1..bracket_pos].trim();
                let local_name = full_tag
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .split(':')
                    .last()
                    .unwrap_or("")
                    .to_ascii_lowercase();

                if local_name == tag_lower {
                    // Found opening tag, now locate corresponding closing tag
                    let content_start = bracket_pos + 1;
                    if let Some(close_rel) = xml_lower[content_start..].find(&format!("</{}", local_name)) {
                        let content_end = content_start + close_rel;
                        let val = xml[content_start..content_end].trim();
                        return Some(val.to_string());
                    }
                }
                search_idx = bracket_pos + 1;
            } else {
                break;
            }
        }
        None
    }

    /// Queries a single host entry by numeric index (0..N) using GetGenericHostEntry
    pub fn get_generic_host_entry(
        gateway_addr: SocketAddr,
        control_path: &str,
        service_urn: &str,
        entry_index: u32,
    ) -> Result<Option<GatewayHostEntry>, String> {
        let soap_body = format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetGenericHostEntry xmlns:u="{service_urn}">
      <NewHostNumberOfEntries>{entry_index}</NewHostNumberOfEntries>
    </u:GetGenericHostEntry>
  </s:Body>
</s:Envelope>"#
        );

        let action = format!("\"{}#GetGenericHostEntry\"", service_urn);
        let resp = Self::send_soap_request(gateway_addr, control_path, &action, &soap_body)?;

        // If router returns 714 (NoSuchEntryInArray) or fault, return Ok(None) to indicate end of list
        if resp.contains("714") || resp.contains("NoSuchEntryInArray") || resp.contains("<s:Fault>") {
            return Ok(None);
        }

        let ip_str = Self::extract_tag_value(&resp, "NewIPAddress")
            .or_else(|| Self::extract_tag_value(&resp, "IPAddress"));
        let mac_str = Self::extract_tag_value(&resp, "NewMACAddress")
            .or_else(|| Self::extract_tag_value(&resp, "MACAddress"));
        let hostname_str = Self::extract_tag_value(&resp, "NewHostName")
            .or_else(|| Self::extract_tag_value(&resp, "HostName"))
            .unwrap_or_default();
        let iface_type = Self::extract_tag_value(&resp, "NewInterfaceType")
            .or_else(|| Self::extract_tag_value(&resp, "InterfaceType"))
            .unwrap_or_else(|| "Unknown".to_string());
        let active_str = Self::extract_tag_value(&resp, "NewActive")
            .or_else(|| Self::extract_tag_value(&resp, "Active"))
            .unwrap_or_else(|| "1".to_string());

        let active = active_str == "1" || active_str.eq_ignore_ascii_case("true");

        if let (Some(ip_s), Some(mac_s)) = (ip_str, mac_str) {
            if let Ok(ip) = Ipv4Addr::from_str(&ip_s) {
                let mac = MacAddress::from_str(&mac_s).unwrap_or(MacAddress::ZERO);
                return Ok(Some(GatewayHostEntry::new(
                    ip,
                    mac,
                    hostname_str,
                    iface_type,
                    active,
                )));
            }
        }

        Ok(None)
    }

    /// Sends a low-level HTTP POST request with SOAP headers
    fn send_soap_request(
        addr: SocketAddr,
        path: &str,
        soap_action: &str,
        body: &str,
    ) -> Result<String, String> {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500))
            .map_err(|e| format!("Could not connect to gateway SOAP endpoint: {}", e))?;

        let _ = stream.set_read_timeout(Some(Duration::from_millis(750)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));

        let req = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: text/xml; charset=\"utf-8\"\r\n\
             Content-Length: {}\r\n\
             SOAPAction: {}\r\n\
             Connection: close\r\n\r\n{}",
            path,
            addr,
            body.len(),
            soap_action,
            body
        );

        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("Failed to write SOAP request: {}", e))?;

        let mut buf = Vec::new();
        let mut temp = [0u8; 4096];
        loop {
            match stream.read(&mut temp) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&temp[..n]),
                Err(_) => break,
            }
        }

        Ok(String::from_utf8_lossy(&buf).to_string())
    }
}
