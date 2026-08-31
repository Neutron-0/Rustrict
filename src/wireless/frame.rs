use crate::types::MacAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Management,
    Control,
    Data,
    Unknown(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementSubtype {
    AssociationRequest,
    AssociationResponse,
    ProbeRequest,
    ProbeResponse,
    Beacon,
    Disassociation,
    Authentication,
    Deauthentication,
    Other(u8),
}

#[derive(Debug, Clone)]
pub struct Dot11Frame<'a> {
    pub frame_type: FrameType,
    pub subtype: u8,
    pub to_ds: bool,
    pub from_ds: bool,
    pub receiver: MacAddress,
    pub transmitter: MacAddress,
    pub bssid: MacAddress,
    pub body: &'a [u8],
}

impl<'a> Dot11Frame<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 24 {
            return None;
        }

        let fc = u16::from_le_bytes([buf[0], buf[1]]);
        let type_val = ((fc >> 2) & 0x03) as u8;
        let subtype_val = ((fc >> 4) & 0x0f) as u8;

        let frame_type = match type_val {
            0 => FrameType::Management,
            1 => FrameType::Control,
            2 => FrameType::Data,
            other => FrameType::Unknown(other),
        };

        let to_ds = (fc & (1 << 8)) != 0;
        let from_ds = (fc & (1 << 9)) != 0;

        let addr1 = MacAddress([buf[4], buf[5], buf[6], buf[7], buf[8], buf[9]]);
        let addr2 = MacAddress([buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]);
        let addr3 = MacAddress([buf[16], buf[17], buf[18], buf[19], buf[20], buf[21]]);

        let body = &buf[24..];

        Some(Self {
            frame_type,
            subtype: subtype_val,
            to_ds,
            from_ds,
            receiver: addr1,
            transmitter: addr2,
            bssid: addr3,
            body,
        })
    }

    pub fn management_subtype(&self) -> Option<ManagementSubtype> {
        if self.frame_type != FrameType::Management {
            return None;
        }

        Some(match self.subtype {
            0 => ManagementSubtype::AssociationRequest,
            1 => ManagementSubtype::AssociationResponse,
            4 => ManagementSubtype::ProbeRequest,
            5 => ManagementSubtype::ProbeResponse,
            8 => ManagementSubtype::Beacon,
            10 => ManagementSubtype::Disassociation,
            11 => ManagementSubtype::Authentication,
            12 => ManagementSubtype::Deauthentication,
            other => ManagementSubtype::Other(other),
        })
    }

    pub fn extract_ssid(&self) -> Option<String> {
        // In Beacon or Probe Response: body starts after 12 fixed bytes (timestamp 8, beacon interval 2, cap info 2)
        if self.body.len() < 14 {
            return None;
        }

        let mut offset = 12;
        while offset + 2 <= self.body.len() {
            let tag_num = self.body[offset];
            let tag_len = self.body[offset + 1] as usize;
            offset += 2;

            if offset + tag_len > self.body.len() {
                break;
            }

            if tag_num == 0 {
                // Tag 0 = SSID
                let ssid_bytes = &self.body[offset..offset + tag_len];
                let ssid = String::from_utf8_lossy(ssid_bytes).to_string();
                return Some(if ssid.is_empty() { "<Hidden SSID>".into() } else { ssid });
            }

            offset += tag_len;
        }

        None
    }
}
