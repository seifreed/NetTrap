use crate::prelude::*;

pub const TFTP_OPCODE_RRQ: u16 = 1;
pub const TFTP_OPCODE_WRQ: u16 = 2;
pub const TFTP_OPCODE_DATA: u16 = 3;
pub const TFTP_OPCODE_ACK: u16 = 4;
pub const TFTP_OPCODE_ERROR: u16 = 5;

#[inline]
fn u16_at(data: &[u8], index: usize) -> Option<u16> {
    let end = index.checked_add(2)?;
    let bytes = data.get(index..end)?;
    let bytes: [u8; 2] = bytes.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

pub const TFTP_BLOCK_SIZE: usize = 512;
const TFTP_MAX_PACKET_BYTES: usize = 4 + TFTP_BLOCK_SIZE;
const TFTP_MAX_CONTROL_PACKET_BYTES: usize = u16::MAX as usize - 8;

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
        let opcode = u16_at(data, 0)?;
        match opcode {
            TFTP_OPCODE_RRQ | TFTP_OPCODE_WRQ => {
                if data.len() > TFTP_MAX_CONTROL_PACKET_BYTES {
                    return None;
                }
                let payload = data.get(2..)?;
                if !payload.ends_with(&[0]) {
                    return None;
                }
                let mut parts: Vec<&[u8]> = payload.split(|&b| b == 0).collect();
                if matches!(parts.last(), Some(part) if part.is_empty()) {
                    parts.pop();
                }
                let filename_bytes = parts.first().copied()?;
                let mode_bytes = parts.get(1).copied()?;
                if filename_bytes.is_empty() || mode_bytes.is_empty() {
                    return None;
                }
                if !tftp_text_field_is_safe(filename_bytes) {
                    return None;
                }
                let filename = String::from_utf8_lossy(filename_bytes).to_string();
                if !tftp_filename_is_safe(&filename) {
                    return None;
                }
                if !tftp_text_field_is_safe(mode_bytes) {
                    return None;
                }
                let mode = String::from_utf8_lossy(mode_bytes).to_string();
                if !matches!(
                    mode.to_ascii_lowercase().as_str(),
                    "netascii" | "octet" | "mail"
                ) {
                    return None;
                }
                let options = parse_options(parts.get(2..).unwrap_or_default())?;
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
                if data.len() < 4 || data.len() > TFTP_MAX_PACKET_BYTES {
                    return None;
                }
                let block = u16_at(data, 2)?;
                if block == 0 {
                    return None;
                }
                let payload = data.get(4..)?.to_vec();
                Some(TftpPacket::Data {
                    block,
                    data: payload,
                })
            }
            TFTP_OPCODE_ACK => {
                if data.len() != 4 {
                    return None;
                }
                let block = u16_at(data, 2)?;
                Some(TftpPacket::Ack { block })
            }
            TFTP_OPCODE_ERROR => {
                if data.len() > TFTP_MAX_CONTROL_PACKET_BYTES {
                    return None;
                }
                if data.len() < 5 || !data.ends_with(&[0]) {
                    return None;
                }
                let code = u16_at(data, 2)?;
                let msg_bytes = data.get(4..(data.len() - 1))?;
                if msg_bytes.contains(&0) || !tftp_text_field_is_safe(msg_bytes) {
                    return None;
                }
                let message = String::from_utf8_lossy(msg_bytes).to_string();
                Some(TftpPacket::Error { code, message })
            }
            _ => None,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            TftpPacket::ReadRequest {
                filename,
                mode,
                options,
            } => serialize_request(TFTP_OPCODE_RRQ, filename, mode, options),
            TftpPacket::WriteRequest {
                filename,
                mode,
                options,
            } => serialize_request(TFTP_OPCODE_WRQ, filename, mode, options),
            TftpPacket::Data { block, data } => {
                if *block == 0 || data.len() > TFTP_BLOCK_SIZE {
                    return Err(Error::Protocol("Invalid TFTP DATA packet".to_string()));
                }
                let mut buf = Vec::with_capacity(4 + data.len());
                buf.extend_from_slice(&TFTP_OPCODE_DATA.to_be_bytes());
                buf.extend_from_slice(&block.to_be_bytes());
                buf.extend_from_slice(data);
                Ok(buf)
            }
            TftpPacket::Ack { block } => {
                let mut buf = Vec::with_capacity(4);
                buf.extend_from_slice(&TFTP_OPCODE_ACK.to_be_bytes());
                buf.extend_from_slice(&block.to_be_bytes());
                Ok(buf)
            }
            TftpPacket::Error { code, message } => {
                if !tftp_text_field_is_safe(message.as_bytes()) {
                    return Err(Error::Protocol(
                        "TFTP packet contains unsafe text".to_string(),
                    ));
                }
                let packet_len = 5usize.checked_add(message.len()).ok_or_else(|| {
                    Error::Protocol("TFTP packet exceeds maximum size".to_string())
                })?;
                ensure_control_packet_size(packet_len)?;

                let mut buf = Vec::with_capacity(packet_len);
                buf.extend_from_slice(&TFTP_OPCODE_ERROR.to_be_bytes());
                buf.extend_from_slice(&code.to_be_bytes());
                buf.extend_from_slice(message.as_bytes());
                buf.push(0);
                Ok(buf)
            }
        }
    }
}

fn serialize_request(
    opcode: u16,
    filename: &str,
    mode: &str,
    options: &[(String, String)],
) -> Result<Vec<u8>> {
    let mut names = std::collections::HashSet::new();
    if filename.is_empty()
        || mode.is_empty()
        || !tftp_text_field_is_safe(filename.as_bytes())
        || !tftp_text_field_is_safe(mode.as_bytes())
        || !matches!(
            mode.to_ascii_lowercase().as_str(),
            "netascii" | "octet" | "mail"
        )
    {
        return Err(Error::Protocol(
            "TFTP packet contains unsafe text".to_string(),
        ));
    }

    let mut packet_len = 2usize
        .checked_add(filename.len())
        .and_then(|len| len.checked_add(1))
        .and_then(|len| len.checked_add(mode.len()))
        .and_then(|len| len.checked_add(1))
        .ok_or_else(|| Error::Protocol("TFTP packet exceeds maximum size".to_string()))?;
    if !tftp_filename_is_safe(filename) {
        return Err(Error::Protocol(
            "TFTP packet contains unsafe text".to_string(),
        ));
    }
    for (name, value) in options {
        if name.is_empty()
            || value.is_empty()
            || !tftp_text_field_is_safe(name.as_bytes())
            || !tftp_text_field_is_safe(value.as_bytes())
            || !names.insert(name.to_ascii_lowercase())
        {
            return Err(Error::Protocol(
                "TFTP packet contains invalid options".to_string(),
            ));
        }
        packet_len = packet_len
            .checked_add(name.len())
            .and_then(|len| len.checked_add(1))
            .and_then(|len| len.checked_add(value.len()))
            .and_then(|len| len.checked_add(1))
            .ok_or_else(|| Error::Protocol("TFTP packet exceeds maximum size".to_string()))?;
    }
    ensure_control_packet_size(packet_len)?;

    let mut buf = Vec::with_capacity(packet_len);
    buf.extend_from_slice(&opcode.to_be_bytes());
    buf.extend_from_slice(filename.as_bytes());
    buf.push(0);
    buf.extend_from_slice(mode.as_bytes());
    buf.push(0);

    for (name, value) in options {
        buf.extend_from_slice(name.as_bytes());
        buf.push(0);
        buf.extend_from_slice(value.as_bytes());
        buf.push(0);
    }

    Ok(buf)
}

fn ensure_control_packet_size(len: usize) -> Result<()> {
    if len > TFTP_MAX_CONTROL_PACKET_BYTES {
        Err(Error::Protocol(
            "TFTP packet exceeds maximum size".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn parse_options(parts: &[&[u8]]) -> Option<Vec<(String, String)>> {
    if !parts.len().is_multiple_of(2) {
        return None;
    }

    let mut options = Vec::new();
    let mut names = std::collections::HashSet::new();
    for pair in parts.chunks_exact(2) {
        let (name, rest) = pair.split_first()?;
        let value = rest.first()?;
        if name.is_empty() || value.is_empty() {
            return None;
        }
        if !tftp_text_field_is_safe(name) || !tftp_text_field_is_safe(value) {
            return None;
        }
        let name = String::from_utf8_lossy(name).to_ascii_lowercase();
        let value = String::from_utf8_lossy(value).to_string();
        if !names.insert(name.clone()) {
            return None;
        }
        options.push((name, value));
    }
    Some(options)
}

fn tftp_text_field_is_safe(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| !byte.is_ascii_control() && byte.is_ascii())
}

pub(crate) fn tftp_filename_is_safe(value: &str) -> bool {
    if !tftp_text_field_is_safe(value.as_bytes()) {
        return false;
    }
    if value.starts_with(['/', '\\']) {
        return false;
    }
    if nettrap_core::parse::looks_like_windows_drive_path(value) {
        return false;
    }
    if value.contains(':') {
        return false;
    }
    !value
        .split(['/', '\\'])
        .any(|segment| matches!(segment, "." | ".."))
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
    fn rrq_rejects_control_characters_in_text_fields() {
        assert!(TftpPacket::parse(&rrq(b"firmware\n.bin", b"octet", true)).is_none());
        assert!(TftpPacket::parse(&rrq(b"firmware.bin", b"octet\x1b", true)).is_none());

        let mut packet = rrq(b"firmware.bin", b"octet", true);
        packet.extend_from_slice(b"blksize\0");
        packet.extend_from_slice(b"1428\n\0");
        assert!(TftpPacket::parse(&packet).is_none());
    }

    #[test]
    fn rrq_accepts_benign_dotted_filename() {
        let parsed = TftpPacket::parse(&rrq(b"firmware..bin", b"octet", true));

        match parsed {
            Some(TftpPacket::ReadRequest { filename, .. }) => {
                assert_eq!(filename, "firmware..bin");
            }
            _ => panic!("expected RRQ with dotted filename"),
        }
    }

    #[test]
    fn rrq_rejects_path_traversal_and_absolute_filenames() {
        assert!(TftpPacket::parse(&rrq(b"../firmware.bin", b"octet", true)).is_none());
        assert!(TftpPacket::parse(&rrq(b"/firmware.bin", b"octet", true)).is_none());
        assert!(TftpPacket::parse(&rrq(b"firmware/../payload.bin", b"octet", true)).is_none());
        assert!(TftpPacket::parse(&rrq(b".", b"octet", true)).is_none());
        assert!(TftpPacket::parse(&rrq(b"firmware/.", b"octet", true)).is_none());
    }

    #[test]
    fn rrq_rejects_windows_drive_prefixed_filenames() {
        assert!(TftpPacket::parse(&rrq(b"C:/firmware.bin", b"octet", true)).is_none());
        assert!(TftpPacket::parse(&rrq(b"C:\\firmware.bin", b"octet", true)).is_none());
    }

    #[test]
    fn rrq_rejects_colon_separated_filenames() {
        assert!(TftpPacket::parse(&rrq(b"firmware:stream", b"octet", true)).is_none());
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
    fn request_to_bytes_round_trips_rrq_with_options() {
        let packet = TftpPacket::ReadRequest {
            filename: "firmware.bin".to_string(),
            mode: "octet".to_string(),
            options: vec![
                ("blksize".to_string(), "1428".to_string()),
                ("timeout".to_string(), "1".to_string()),
            ],
        };

        let encoded = packet.to_bytes().expect("RRQ should serialize");

        match TftpPacket::parse(&encoded) {
            Some(TftpPacket::ReadRequest {
                filename,
                mode,
                options,
            }) => {
                assert_eq!(filename, "firmware.bin");
                assert_eq!(mode, "octet");
                assert_eq!(
                    options,
                    vec![
                        ("blksize".to_string(), "1428".to_string()),
                        ("timeout".to_string(), "1".to_string())
                    ]
                );
            }
            _ => panic!("expected RRQ round-trip"),
        }
    }

    #[test]
    fn request_to_bytes_round_trips_wrq_without_options() {
        let packet = TftpPacket::WriteRequest {
            filename: "upload.bin".to_string(),
            mode: "octet".to_string(),
            options: Vec::new(),
        };

        let encoded = packet.to_bytes().expect("WRQ should serialize");

        match TftpPacket::parse(&encoded) {
            Some(TftpPacket::WriteRequest {
                filename,
                mode,
                options,
            }) => {
                assert_eq!(filename, "upload.bin");
                assert_eq!(mode, "octet");
                assert!(options.is_empty());
            }
            _ => panic!("expected WRQ round-trip"),
        }
    }

    #[test]
    fn request_serializer_rejects_mutated_text_fields() {
        let mut packet = TftpPacket::ReadRequest {
            filename: "firmware.bin".to_string(),
            mode: "octet".to_string(),
            options: vec![("blksize".to_string(), "1428".to_string())],
        };
        if let TftpPacket::ReadRequest { filename, .. } = &mut packet {
            filename.push('\n');
        }

        assert!(packet.to_bytes().is_err());
    }

    #[test]
    fn request_serializer_rejects_path_traversal_and_absolute_filenames() {
        let traversal = TftpPacket::ReadRequest {
            filename: "../firmware.bin".to_string(),
            mode: "octet".to_string(),
            options: Vec::new(),
        };
        let absolute = TftpPacket::WriteRequest {
            filename: "/firmware.bin".to_string(),
            mode: "octet".to_string(),
            options: Vec::new(),
        };

        assert!(traversal.to_bytes().is_err());
        assert!(absolute.to_bytes().is_err());

        let colon = TftpPacket::ReadRequest {
            filename: "firmware:stream".to_string(),
            mode: "octet".to_string(),
            options: Vec::new(),
        };
        let current_dir = TftpPacket::ReadRequest {
            filename: ".".to_string(),
            mode: "octet".to_string(),
            options: Vec::new(),
        };

        assert!(colon.to_bytes().is_err());
        assert!(current_dir.to_bytes().is_err());
    }

    #[test]
    fn request_serializer_rejects_empty_filename_or_mode() {
        let empty_filename = TftpPacket::ReadRequest {
            filename: String::new(),
            mode: "octet".to_string(),
            options: Vec::new(),
        };
        let empty_mode = TftpPacket::ReadRequest {
            filename: "firmware.bin".to_string(),
            mode: String::new(),
            options: Vec::new(),
        };

        assert!(empty_filename.to_bytes().is_err());
        assert!(empty_mode.to_bytes().is_err());
    }

    #[test]
    fn request_serializer_rejects_unknown_modes() {
        let packet = TftpPacket::ReadRequest {
            filename: "firmware.bin".to_string(),
            mode: "binary".to_string(),
            options: Vec::new(),
        };

        assert!(packet.to_bytes().is_err());
    }

    #[test]
    fn request_serializer_rejects_duplicate_options() {
        let packet = TftpPacket::ReadRequest {
            filename: "firmware.bin".to_string(),
            mode: "octet".to_string(),
            options: vec![
                ("blksize".to_string(), "1428".to_string()),
                ("blksize".to_string(), "1024".to_string()),
            ],
        };

        assert!(packet.to_bytes().is_err());
    }

    #[test]
    fn request_serializer_rejects_empty_option_fields() {
        let empty_name = TftpPacket::ReadRequest {
            filename: "firmware.bin".to_string(),
            mode: "octet".to_string(),
            options: vec![("".to_string(), "1428".to_string())],
        };
        let empty_value = TftpPacket::ReadRequest {
            filename: "firmware.bin".to_string(),
            mode: "octet".to_string(),
            options: vec![("blksize".to_string(), "".to_string())],
        };

        assert!(empty_name.to_bytes().is_err());
        assert!(empty_value.to_bytes().is_err());
    }

    #[test]
    fn rrq_rejects_malformed_option_pairs() {
        let mut packet = rrq(b"firmware.bin", b"octet", true);
        packet.extend_from_slice(b"blksize\0");

        assert!(TftpPacket::parse(&packet).is_none());
    }

    #[test]
    fn u16_at_rejects_overflowing_offset() {
        assert_eq!(u16_at(&[0, 1], usize::MAX), None);
    }

    #[test]
    fn rrq_rejects_oversized_requests_before_splitting_options() {
        let mut packet = rrq(b"firmware.bin", b"octet", true);
        packet.resize(TFTP_MAX_CONTROL_PACKET_BYTES + 1, b'a');
        let Some(last) = packet.len().checked_sub(1) else {
            return;
        };
        if let Some(byte) = packet.get_mut(last) {
            *byte = 0;
        }

        assert!(TftpPacket::parse(&packet).is_none());
    }

    #[test]
    fn rrq_accepts_requests_larger_than_default_data_packet_limit() {
        let filename = vec![b'a'; TFTP_BLOCK_SIZE + 128];
        let packet = rrq(&filename, b"octet", true);

        assert!(packet.len() > TFTP_MAX_PACKET_BYTES);
        assert!(packet.len() <= TFTP_MAX_CONTROL_PACKET_BYTES);

        match TftpPacket::parse(&packet) {
            Some(TftpPacket::ReadRequest {
                filename,
                mode,
                options,
            }) => {
                assert_eq!(filename.len(), TFTP_BLOCK_SIZE + 128);
                assert_eq!(mode, "octet");
                assert!(options.is_empty());
            }
            _ => panic!("expected oversized RRQ to parse"),
        }
    }

    #[test]
    fn rrq_rejects_duplicate_options() {
        let packet = rrq(b"firmware.bin", b"octet", true)
            .into_iter()
            .chain([
                b'b', b'l', b'k', b's', b'i', b'z', b'e', 0, b'5', b'1', b'2', 0, b'b', b'l', b'k',
                b's', b'i', b'z', b'e', 0, b'1', b'0', b'2', b'4', 0,
            ])
            .collect::<Vec<_>>();

        assert!(TftpPacket::parse(&packet).is_none());
    }

    #[test]
    fn ack_rejects_trailing_bytes() {
        let packet = [
            TFTP_OPCODE_ACK.to_be_bytes()[0],
            TFTP_OPCODE_ACK.to_be_bytes()[1],
            0,
            1,
            b'x',
        ];

        assert!(TftpPacket::parse(&packet).is_none());
    }

    #[test]
    fn data_rejects_blocks_larger_than_default_block_size() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&TFTP_OPCODE_DATA.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend(std::iter::repeat_n(0, TFTP_BLOCK_SIZE + 1));

        assert!(TftpPacket::parse(&packet).is_none());
    }

    #[test]
    fn data_rejects_block_zero() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&TFTP_OPCODE_DATA.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(b"hello");

        assert!(TftpPacket::parse(&packet).is_none());
    }

    #[test]
    fn data_serializer_rejects_invalid_data_packets() {
        assert!(
            TftpPacket::Data {
                block: 0,
                data: b"hello".to_vec(),
            }
            .to_bytes()
            .is_err()
        );
        assert!(
            TftpPacket::Data {
                block: 1,
                data: vec![0; TFTP_BLOCK_SIZE + 1],
            }
            .to_bytes()
            .is_err()
        );
    }

    #[test]
    fn error_requires_single_final_nul() {
        let mut missing_nul = Vec::new();
        missing_nul.extend_from_slice(&TFTP_OPCODE_ERROR.to_be_bytes());
        missing_nul.extend_from_slice(&1u16.to_be_bytes());
        missing_nul.extend_from_slice(b"error");

        let mut trailing_after_nul = Vec::new();
        trailing_after_nul.extend_from_slice(&TFTP_OPCODE_ERROR.to_be_bytes());
        trailing_after_nul.extend_from_slice(&1u16.to_be_bytes());
        trailing_after_nul.extend_from_slice(b"error\0x");

        assert!(TftpPacket::parse(&missing_nul).is_none());
        assert!(TftpPacket::parse(&trailing_after_nul).is_none());
    }

    #[test]
    fn error_rejects_control_characters_in_message() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&TFTP_OPCODE_ERROR.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(b"bad\nmessage\0");

        assert!(TftpPacket::parse(&packet).is_none());
    }

    #[test]
    fn error_rejects_oversized_messages_before_allocating_string() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&TFTP_OPCODE_ERROR.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.resize(TFTP_MAX_CONTROL_PACKET_BYTES + 1, b'a');
        let Some(last) = packet.len().checked_sub(1) else {
            return;
        };
        if let Some(byte) = packet.get_mut(last) {
            *byte = 0;
        }

        assert!(TftpPacket::parse(&packet).is_none());
    }

    #[test]
    fn error_serializer_rejects_mutated_message_lines() {
        let mut packet = TftpPacket::Error {
            code: 1,
            message: "File not found".to_string(),
        };
        if let TftpPacket::Error { message, .. } = &mut packet {
            message.push_str("\r\nowned");
        }

        assert!(packet.to_bytes().is_err());
    }

    #[test]
    fn request_serializer_rejects_oversized_packets_before_emitting_bytes() {
        let packet = TftpPacket::ReadRequest {
            filename: "a".repeat(TFTP_MAX_CONTROL_PACKET_BYTES),
            mode: "octet".to_string(),
            options: Vec::new(),
        };

        assert!(packet.to_bytes().is_err());
    }

    #[test]
    fn error_serializer_rejects_oversized_packets_before_emitting_bytes() {
        let packet = TftpPacket::Error {
            code: 1,
            message: "a".repeat(TFTP_MAX_CONTROL_PACKET_BYTES),
        };

        assert!(packet.to_bytes().is_err());
    }
}
