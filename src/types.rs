use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const BROADCAST: MacAddress = MacAddress([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    pub const ZERO: MacAddress = MacAddress([0, 0, 0, 0, 0, 0]);

    pub fn oui_prefix(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }
}

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub description: String,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub gateway_mac: MacAddress,
    pub mac: MacAddress,
    pub device_path: String,
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let clean = s.trim();
        let parts: Vec<&str> = clean.split(|c| c == ':' || c == '-').collect();

        if parts.len() != 6 {
            return Err("MAC address must contain 6 octets".into());
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part.trim(), 16)
                .map_err(|e| format!("Invalid hex byte in MAC: {}", e))?;
        }

        Ok(MacAddress(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Outgoing,
    Incoming,
    Both,
}

impl Direction {
    pub fn pretty(&self) -> &'static str {
        match self {
            Direction::Outgoing => "upload",
            Direction::Incoming => "download",
            Direction::Both => "upload / download",
        }
    }

    pub fn includes_outgoing(&self) -> bool {
        matches!(self, Direction::Outgoing | Direction::Both)
    }

    pub fn includes_incoming(&self) -> bool {
        matches!(self, Direction::Incoming | Direction::Both)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStatus {
    Free,
    Limited(BitRate, Direction),
    Blocked(Direction),
}

impl HostStatus {
    pub fn pretty(&self) -> String {
        match self {
            HostStatus::Free => "Free".to_string(),
            HostStatus::Limited(rate, dir) => format!("Limited ({}, {})", rate, dir.pretty()),
            HostStatus::Blocked(dir) => format!("Blocked ({})", dir.pretty()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSource {
    Local,       // This machine
    Gateway,     // Default gateway / router
    RouterUpnp,  // Retrieved from Router Gateway UPnP / TR-064 client list
    Dhcp,        // Sniffed via DHCP Option 12
    Smb,         // Extracted via SMB NTLMSSP challenge
    Tls,         // Extracted from X.509 certificate CN
    Mdns,        // Resolved via mDNS service/PTR
    NetBios,     // Resolved via NBNS query
    Manual,      // Assigned by user via add command
    Unresolved,  // No authoritative hostname resolved
}

#[derive(Debug, Clone)]
pub struct Host {
    pub id: usize,
    pub ip: Ipv4Addr,
    pub mac: MacAddress,
    pub name: String,
    pub name_source: NameSource,
    pub vendor: String,
    pub status: HostStatus,
    pub online: bool,
    pub spoofed: bool,
    pub watched: bool,
    pub persistent_block: bool,
}

impl Host {
    pub fn new(id: usize, ip: Ipv4Addr, mac: MacAddress, name: String, vendor: String) -> Self {
        let name_source = if name.is_empty() {
            NameSource::Unresolved
        } else {
            NameSource::Manual
        };
        Self {
            id,
            ip,
            mac,
            name,
            name_source,
            vendor,
            status: HostStatus::Free,
            online: true,
            spoofed: false,
            watched: false,
            persistent_block: false,
        }
    }

    pub fn with_source(
        id: usize,
        ip: Ipv4Addr,
        mac: MacAddress,
        name: String,
        name_source: NameSource,
        vendor: String,
    ) -> Self {
        Self {
            id,
            ip,
            mac,
            name,
            name_source,
            vendor,
            status: HostStatus::Free,
            online: true,
            spoofed: false,
            watched: false,
            persistent_block: false,
        }
    }

    pub fn display_name(&self) -> String {
        if !self.name.is_empty() {
            if !self.vendor.is_empty() && self.vendor != "Unknown" {
                format!("{} ({})", self.name, self.vendor)
            } else {
                self.name.clone()
            }
        } else if !self.vendor.is_empty() && self.vendor != "Unknown" {
            format!("[{}]", self.vendor)
        } else {
            "-".to_string()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BitRate(pub u64); // bits per second

impl BitRate {
    pub fn from_str_custom(s: &str) -> Result<Self, String> {
        let s = s.trim().to_lowercase();
        let num_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let num: u64 = s[..num_end]
            .parse()
            .map_err(|_| "Invalid number in bitrate".to_string())?;
        let unit = &s[num_end..];

        let multiplier = match unit {
            "bit" | "b" | "bps" | "" => 1,
            "kbit" | "kb" | "kbps" | "k" => 1_000,
            "mbit" | "mb" | "mbps" | "m" => 1_000_000,
            "gbit" | "gb" | "gbps" | "g" => 1_000_000_000,
            _ => return Err(format!("Unknown bitrate unit: {}", unit)),
        };

        Ok(BitRate(num * multiplier))
    }
}

impl fmt::Display for BitRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bps = self.0;
        if bps >= 1_000_000_000 {
            write!(f, "{:.1}gbit", bps as f64 / 1_000_000_000.0)
        } else if bps >= 1_000_000 {
            write!(f, "{:.1}mbit", bps as f64 / 1_000_000.0)
        } else if bps >= 1_000 {
            write!(f, "{:.1}kbit", bps as f64 / 1_000.0)
        } else {
            write!(f, "{}bit", bps)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ByteValue(pub u64); // bytes

impl fmt::Display for ByteValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        if bytes >= 1024 * 1024 * 1024 {
            write!(f, "{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        } else if bytes >= 1024 * 1024 {
            write!(f, "{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        } else if bytes >= 1024 {
            write!(f, "{:.1} KB", bytes as f64 / 1024.0)
        } else {
            write!(f, "{} B", bytes)
        }
    }
}
