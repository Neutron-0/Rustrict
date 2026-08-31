use std::net::Ipv4Addr;
use std::process::Command;
use crate::types::{MacAddress, NetworkInterface};

pub fn is_privileged() -> bool {
    unsafe {
        windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0
    }
}

pub fn enable_ip_forwarding() -> Result<(), String> {
    let status = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Set-NetIPInterface -Forwarding Enabled"])
        .status()
        .map_err(|e| format!("Failed to execute PowerShell: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err("Failed to enable IP forwarding via Set-NetIPInterface".into())
    }
}

pub fn disable_ip_forwarding() -> Result<(), String> {
    let status = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Set-NetIPInterface -Forwarding Disabled"])
        .status()
        .map_err(|e| format!("Failed to execute PowerShell: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err("Failed to disable IP forwarding via Set-NetIPInterface".into())
    }
}

/// SendARP sends an ARP request directly through the Windows kernel network stack
pub fn send_arp(ip: Ipv4Addr) -> Option<MacAddress> {
    let ip_octets = ip.octets();
    let dest_ip = u32::from_ne_bytes(ip_octets);
    let mut mac_bytes = [0u8; 6];
    let mut mac_len: u32 = 6;

    let res = unsafe {
        windows_sys::Win32::NetworkManagement::IpHelper::SendARP(
            dest_ip,
            0,
            mac_bytes.as_mut_ptr() as *mut _,
            &mut mac_len as *mut _,
        )
    };

    if res == 0 && mac_len == 6 {
        let mac = MacAddress(mac_bytes);
        if mac != MacAddress::ZERO && mac != MacAddress::BROADCAST {
            return Some(mac);
        }
    }
    None
}

/// Reads existing active dynamic entries from Windows kernel ARP table
pub fn get_arp_cache() -> Vec<(Ipv4Addr, MacAddress)> {
    let mut entries = Vec::new();
    if let Ok(output) = Command::new("arp").arg("-a").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[2].eq_ignore_ascii_case("dynamic") {
                if let (Ok(ip), Ok(mac)) = (parts[0].parse::<Ipv4Addr>(), parts[1].parse::<MacAddress>()) {
                    if mac != MacAddress::ZERO && mac != MacAddress::BROADCAST {
                        entries.push((ip, mac));
                    }
                }
            }
        }
    }
    entries
}

/// Discovers the active default IPv4 interface using Windows routing and netsh
pub fn get_default_interface() -> Result<NetworkInterface, String> {
    // Query route print to find active default gateway and interface IP
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            r#"Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1 -Property InterfaceAlias, NextHop, InterfaceMetric | ForEach-Object { "$($_.InterfaceAlias)|$($_.NextHop)" }"#,
        ])
        .output()
        .map_err(|e| format!("Failed to query route: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.trim();
    if line.is_empty() || !line.contains('|') {
        return Err("No default route (gateway) found on this machine.".into());
    }

    let parts: Vec<&str> = line.split('|').collect();
    let iface_name = parts[0].trim().to_string();
    let gateway_ip: Ipv4Addr = parts[1].trim().parse()
        .map_err(|_| format!("Invalid gateway IP: {}", parts[1]))?;

    // Now query IP address and netmask for this interface
    let ip_cmd = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                r#"Get-NetIPAddress -InterfaceAlias '{}' -AddressFamily IPv4 | Select-Object -First 1 | ForEach-Object {{"$($_.IPAddress)|$($_.PrefixLength)"}}"#,
                iface_name
            ),
        ])
        .output()
        .map_err(|e| format!("Failed to query IP address: {}", e))?;

    let ip_stdout = String::from_utf8_lossy(&ip_cmd.stdout);
    let ip_line = ip_stdout.trim();
    let ip_parts: Vec<&str> = ip_line.split('|').collect();
    if ip_parts.len() < 2 {
        return Err(format!("Could not query IP address for interface {}", iface_name));
    }

    let local_ip: Ipv4Addr = ip_parts[0].trim().parse()
        .map_err(|_| format!("Invalid local IP: {}", ip_parts[0]))?;
    let prefix_len: u8 = ip_parts[1].trim().parse().unwrap_or(24);
    let mask_u32 = if prefix_len == 0 {
        0
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };
    let netmask = Ipv4Addr::from(mask_u32);

    // Resolve gateway MAC
    let gateway_mac = send_arp(gateway_ip).unwrap_or(MacAddress::ZERO);

    // Query MAC address and GUID of local adapter
    let adapter_cmd = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                r#"Get-NetAdapter -Name '{}' | Select-Object -First 1 | ForEach-Object {{ "$($_.MacAddress)|$($_.InterfaceGuid)" }}"#,
                iface_name
            ),
        ])
        .output()
        .map_err(|e| format!("Failed to query adapter info: {}", e))?;

    let adapter_str = String::from_utf8_lossy(&adapter_cmd.stdout);
    let parts: Vec<&str> = adapter_str.trim().split('|').collect();
    let mac_str = parts.get(0).unwrap_or(&"").replace('-', ":");
    let local_mac = mac_str.parse::<MacAddress>().unwrap_or(MacAddress::ZERO);

    let guid_str = parts.get(1).unwrap_or(&"").trim();
    let device_path = if !guid_str.is_empty() {
        format!(r"\Device\NPF_{}", guid_str)
    } else {
        iface_name.clone()
    };

    Ok(NetworkInterface {
        name: iface_name.clone(),
        description: iface_name,
        ip: local_ip,
        netmask,
        gateway: gateway_ip,
        gateway_mac,
        mac: local_mac,
        device_path,
    })
}
