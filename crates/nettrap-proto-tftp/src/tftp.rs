pub const TFTP_OPCODE_RRQ: u16 = 1;
pub const TFTP_OPCODE_WRQ: u16 = 2;
pub const TFTP_OPCODE_DATA: u16 = 3;
pub const TFTP_OPCODE_ACK: u16 = 4;
pub const TFTP_OPCODE_ERROR: u16 = 5;

pub const TFTP_BLOCK_SIZE: usize = 512;

#[derive(Debug, Clone)]
pub enum TftpPacket {
    ReadRequest {
        filename: String,
        mode: String,
        options: Vec<(String, String)>,
    },
    WriteRequest {
        filename: String,
        mode: String,
        options: Vec<(String, String)>,
    },
    Data {
        block: u16,
        data: Vec<u8>,
    },
    Ack {
        block: u16,
    },
    Error {
        code: u16,
        message: String,
    },
}

impl TftpPacket {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let opcode = u16::from_be_bytes([data[0], data[1]]);
        match opcode {
            TFTP_OPCODE_RRQ | TFTP_OPCODE_WRQ => {
                let payload = &data[2..];
                if !payload.ends_with(&[0]) {
                    return None;
                }
                let mut parts: Vec<&[u8]> = payload.split(|&b| b == 0).collect();
                if matches!(parts.last(), Some(part) if part.is_empty()) {
                    parts.pop();
                }
                if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
                    return None;
                }
                let filename = String::from_utf8_lossy(parts[0]).to_string();
                // Reject path traversal attempts
                if filename.contains("..") || filename.contains('\\') || filename.starts_with('/') {
                    return None;
                }
                let mode = String::from_utf8_lossy(parts[1]).to_string();
                if !matches!(
                    mode.to_ascii_lowercase().as_str(),
                    "netascii" | "octet" | "mail"
                ) {
                    return None;
                }
                let options = parse_options(&parts[2..])?;
                if opcode == TFTP_OPCODE_RRQ {
                    Some(TftpPacket::ReadRequest {
                        filename,
                        mode,
                        options,
                    })
                } else {
                    Some(TftpPacket::WriteRequest {
                        filename,
                        mode,
                        options,
                    })
                }
            }
            TFTP_OPCODE_DATA => {
                if data.len() < 4 {
                    return None;
                }
                let block = u16::from_be_bytes([data[2], data[3]]);
                let payload = data[4..].to_vec();
                Some(TftpPacket::Data {
                    block,
                    data: payload,
                })
            }
            TFTP_OPCODE_ACK => {
                if data.len() < 4 {
                    return None;
                }
                let block = u16::from_be_bytes([data[2], data[3]]);
                Some(TftpPacket::Ack { block })
            }
            TFTP_OPCODE_ERROR => {
                if data.len() < 4 {
                    return None;
                }
                let code = u16::from_be_bytes([data[2], data[3]]);
                let msg_bytes = &data[4..];
                let end = msg_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(msg_bytes.len());
                let message = String::from_utf8_lossy(&msg_bytes[..end]).to_string();
                Some(TftpPacket::Error { code, message })
            }
            _ => None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TftpPacket::Data { block, data } => {
                let mut buf = Vec::with_capacity(4 + data.len());
                buf.extend_from_slice(&TFTP_OPCODE_DATA.to_be_bytes());
                buf.extend_from_slice(&block.to_be_bytes());
                buf.extend_from_slice(data);
                buf
            }
            TftpPacket::Ack { block } => {
                let mut buf = Vec::with_capacity(4);
                buf.extend_from_slice(&TFTP_OPCODE_ACK.to_be_bytes());
                buf.extend_from_slice(&block.to_be_bytes());
                buf
            }
            TftpPacket::Error { code, message } => {
                let mut buf = Vec::with_capacity(5 + message.len());
                buf.extend_from_slice(&TFTP_OPCODE_ERROR.to_be_bytes());
                buf.extend_from_slice(&code.to_be_bytes());
                buf.extend_from_slice(message.as_bytes());
                buf.push(0);
                buf
            }
            _ => Vec::new(),
        }
    }
}

fn parse_options(parts: &[&[u8]]) -> Option<Vec<(String, String)>> {
    if parts.len() % 2 != 0 {
        return None;
    }

    let mut options = Vec::new();
    for pair in parts.chunks_exact(2) {
        if pair[0].is_empty() || pair[1].is_empty() {
            return None;
        }
        let name = String::from_utf8_lossy(pair[0]).to_ascii_lowercase();
        let value = String::from_utf8_lossy(pair[1]).to_string();
        options.push((name, value));
    }
    Some(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rrq(filename: &[u8], mode: &[u8], final_nul: bool) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&TFTP_OPCODE_RRQ.to_be_bytes());
        packet.extend_from_slice(filename);
        packet.push(0);
        packet.extend_from_slice(mode);
        if final_nul {
            packet.push(0);
        }
        packet
    }

    #[test]
    fn rrq_requires_final_nul_and_non_empty_mode() {
        assert!(TftpPacket::parse(&rrq(b"firmware.bin", b"octet", false)).is_none());
        assert!(TftpPacket::parse(&rrq(b"firmware.bin", b"", true)).is_none());
    }

    #[test]
    fn rrq_rejects_unknown_modes() {
        assert!(TftpPacket::parse(&rrq(b"firmware.bin", b"binary", true)).is_none());
    }

    #[test]
    fn rrq_accepts_valid_request() {
        let parsed = TftpPacket::parse(&rrq(b"firmware.bin", b"octet", true));

        match parsed {
            Some(TftpPacket::ReadRequest {
                filename,
                mode,
                options,
            }) => {
                assert_eq!(filename, "firmware.bin");
                assert_eq!(mode, "octet");
                assert!(options.is_empty());
            }
            _ => panic!("expected RRQ"),
        }
    }

    #[test]
    fn rrq_preserves_options_for_listener_rejection() {
        let mut packet = rrq(b"firmware.bin", b"octet", true);
        packet.extend_from_slice(b"blksize\0");
        packet.extend_from_slice(b"1428\0");
        packet.extend_from_slice(b"timeout\0");
        packet.extend_from_slice(b"1\0");

        match TftpPacket::parse(&packet) {
            Some(TftpPacket::ReadRequest { options, .. }) => {
                assert_eq!(
                    options,
                    vec![
                        ("blksize".to_string(), "1428".to_string()),
                        ("timeout".to_string(), "1".to_string())
                    ]
                );
            }
            _ => panic!("expected RRQ with options"),
        }
    }

    #[test]
    fn rrq_rejects_malformed_option_pairs() {
        let mut packet = rrq(b"firmware.bin", b"octet", true);
        packet.extend_from_slice(b"blksize\0");

        assert!(TftpPacket::parse(&packet).is_none());
    }
}
