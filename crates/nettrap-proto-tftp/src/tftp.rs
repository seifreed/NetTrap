pub const TFTP_OPCODE_RRQ: u16 = 1;
pub const TFTP_OPCODE_WRQ: u16 = 2;
pub const TFTP_OPCODE_DATA: u16 = 3;
pub const TFTP_OPCODE_ACK: u16 = 4;
pub const TFTP_OPCODE_ERROR: u16 = 5;

pub const TFTP_BLOCK_SIZE: usize = 512;

#[derive(Debug, Clone)]
pub enum TftpPacket {
    ReadRequest { filename: String, mode: String },
    WriteRequest { filename: String, mode: String },
    Data { block: u16, data: Vec<u8> },
    Ack { block: u16 },
    Error { code: u16, message: String },
}

impl TftpPacket {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let opcode = u16::from_be_bytes([data[0], data[1]]);
        match opcode {
            TFTP_OPCODE_RRQ | TFTP_OPCODE_WRQ => {
                let payload = &data[2..];
                let parts: Vec<&[u8]> = payload.split(|&b| b == 0).collect();
                if parts.len() >= 2 {
                    let filename = String::from_utf8_lossy(parts[0]).to_string();
                    let mode = String::from_utf8_lossy(parts[1]).to_string();
                    if opcode == TFTP_OPCODE_RRQ {
                        Some(TftpPacket::ReadRequest { filename, mode })
                    } else {
                        Some(TftpPacket::WriteRequest { filename, mode })
                    }
                } else {
                    None
                }
            }
            TFTP_OPCODE_DATA => {
                if data.len() < 4 { return None; }
                let block = u16::from_be_bytes([data[2], data[3]]);
                let payload = data[4..].to_vec();
                Some(TftpPacket::Data { block, data: payload })
            }
            TFTP_OPCODE_ACK => {
                if data.len() < 4 { return None; }
                let block = u16::from_be_bytes([data[2], data[3]]);
                Some(TftpPacket::Ack { block })
            }
            TFTP_OPCODE_ERROR => {
                if data.len() < 4 { return None; }
                let code = u16::from_be_bytes([data[2], data[3]]);
                let msg_bytes = &data[4..];
                let end = msg_bytes.iter().position(|&b| b == 0).unwrap_or(msg_bytes.len());
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
