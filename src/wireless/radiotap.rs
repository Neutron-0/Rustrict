/// Zero-copy Radiotap Header Parser (IEEE 802.11 Radiotap)
#[derive(Debug, Clone, Copy)]
pub struct RadiotapHeader {
    pub version: u8,
    pub length: u16,
    pub present_flags: u32,
    pub channel_freq: Option<u16>, // e.g. 2412 MHz (Ch 1), 5180 MHz (Ch 36)
    pub dbm_signal: Option<i8>,     // e.g. -45 dBm
}

impl RadiotapHeader {
    pub fn parse(buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < 8 {
            return None;
        }

        let version = buf[0];
        let length = u16::from_le_bytes([buf[2], buf[3]]) as usize;
        let present = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);

        if buf.len() < length {
            return None;
        }

        let mut channel_freq = None;
        let mut dbm_signal = None;

        // Iterate fields according to present bitmask
        let mut offset = 8;
        // Bit 0: TSFT (8 bytes)
        if (present & (1 << 0)) != 0 {
            offset = (offset + 7) & !7; // 8-byte aligned
            offset += 8;
        }
        // Bit 1: Flags (1 byte)
        if (present & (1 << 1)) != 0 {
            offset += 1;
        }
        // Bit 2: Rate (1 byte)
        if (present & (1 << 2)) != 0 {
            offset += 1;
        }
        // Bit 3: Channel (4 bytes: 2 bytes frequency, 2 bytes flags)
        if (present & (1 << 3)) != 0 {
            offset = (offset + 1) & !1; // 2-byte aligned
            if offset + 4 <= length {
                channel_freq = Some(u16::from_le_bytes([buf[offset], buf[offset + 1]]));
                offset += 4;
            }
        }
        // Bit 5: dBm Antenna Signal (1 byte signed)
        if (present & (1 << 5)) != 0 {
            if offset < length {
                dbm_signal = Some(buf[offset] as i8);
            }
        }

        let payload = &buf[length..];
        Some((
            Self {
                version,
                length: length as u16,
                present_flags: present,
                channel_freq,
                dbm_signal,
            },
            payload,
        ))
    }
}
