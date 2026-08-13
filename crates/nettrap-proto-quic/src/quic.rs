use memchr::memchr;

use nettrap_proto_tls::fingerprint;

const MAX_QUIC_PACKET_BYTES: usize = 65_535;
const MAX_QUIC_CONNECTION_ID_BYTES: usize = 20;

pub struct QuicHandler {
    version: u32,
}

impl QuicHandler {
    pub fn new() -> Self {
        Self { version: 1 }
    }

    pub fn detect_quic(&self, data: &[u8]) -> bool {
        if data.len() < 5 || data.len() > MAX_QUIC_PACKET_BYTES {
            return false;
        }

        let first_byte = match data.first() {
            Some(byte) => *byte,
            None => return false,
        };
        let is_long_header = (first_byte & 0x80) != 0;
        let has_fixed_bit = (first_byte & 0x40) != 0;
        if !is_long_header || !has_fixed_bit || data.len() < 9 {
            return false;
        }

        let Some(version_bytes) = data.get(1..5) else {
            return false;
        };
        let Ok(version_bytes) = version_bytes.try_into() else {
            return false;
        };
        let packet_version = u32::from_be_bytes(version_bytes);
        packet_version == self.version && quic_long_header_is_well_formed(data)
    }

    pub fn extract_sni(&self, data: &[u8]) -> Option<String> {
        if !self.detect_quic(data) {
            return None;
        }

        if let Some(sni) = fingerprint::extract_sni(data) {
            return Some(sni);
        }

        self.extract_embedded_tls_sni(data)
    }

    fn extract_embedded_tls_sni(&self, data: &[u8]) -> Option<String> {
        let mut offset = 0usize;
        while let Some(remaining) = data.get(offset..) {
            let Some(candidate) = memchr(0x16, remaining) else {
                break;
            };
            let candidate = offset + candidate;
            let suffix = data.get(candidate..)?;
            if let Some(sni) = fingerprint::extract_sni(suffix) {
                return Some(sni);
            }
            offset = candidate.saturating_add(1);
        }
        None
    }
}

impl Default for QuicHandler {
    fn default() -> Self {
        Self::new()
    }
}

pub fn detect_quic(data: &[u8]) -> bool {
    QuicHandler::new().detect_quic(data)
}

fn quic_long_header_is_well_formed(data: &[u8]) -> bool {
    let packet_type = (data[0] & 0x30) >> 4;
    let packet_number_len = usize::from(data[0] & 0x03) + 1;
    let mut offset = 5;

    let Some(dcid_len) = read_len_byte(data, &mut offset) else {
        return false;
    };
    if dcid_len > MAX_QUIC_CONNECTION_ID_BYTES || !skip_bytes(data, &mut offset, dcid_len) {
        return false;
    }

    let Some(scid_len) = read_len_byte(data, &mut offset) else {
        return false;
    };
    if scid_len > MAX_QUIC_CONNECTION_ID_BYTES || !skip_bytes(data, &mut offset, scid_len) {
        return false;
    }

    if packet_type == 3 {
        return data.len().saturating_sub(offset) >= 17;
    }

    if packet_type == 0 {
        let Some(token_len) = read_quic_varint(data, &mut offset) else {
            return false;
        };
        let Ok(token_len) = usize::try_from(token_len) else {
            return false;
        };
        if !skip_bytes(data, &mut offset, token_len) {
            return false;
        }
    }

    let Some(payload_len) = read_quic_varint(data, &mut offset) else {
        return false;
    };
    let Ok(payload_len) = usize::try_from(payload_len) else {
        return false;
    };
    payload_len >= packet_number_len && payload_len <= data.len().saturating_sub(offset)
}

fn read_len_byte(data: &[u8], offset: &mut usize) -> Option<usize> {
    let len = usize::from(*data.get(*offset)?);
    *offset += 1;
    Some(len)
}

fn skip_bytes(data: &[u8], offset: &mut usize, count: usize) -> bool {
    let Some(next) = offset.checked_add(count) else {
        return false;
    };
    if next > data.len() {
        return false;
    }
    *offset = next;
    true
}

fn read_quic_varint(data: &[u8], offset: &mut usize) -> Option<u64> {
    let first = *data.get(*offset)?;
    let len = 1usize << usize::from(first >> 6);
    let bytes = data.get(*offset..(*offset).checked_add(len)?)?;
    *offset += len;

    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_sni_does_not_guess_from_quic_initial_payload() {
        let handler = QuicHandler::new();
        let packet = quic_initial_packet(b"\x00\x00\x00\x11\x00\x0f\x00\x0cexample.com");

        assert!(handler.detect_quic(&packet));
        assert_eq!(handler.extract_sni(&packet), None);
    }

    #[test]
    fn extract_sni_finds_cleartext_tls_client_hello_inside_quic_payload() {
        let handler = QuicHandler::new();
        let packet = quic_initial_packet(&tls_client_hello_with_sni(b"example.com"));

        assert_eq!(handler.extract_sni(&packet).as_deref(), Some("example.com"));
    }

    #[test]
    fn detect_quic_requires_long_header_shape() {
        let handler = QuicHandler::new();

        assert!(!handler.detect_quic(&[0x43, 0, 0, 0, 1, 0, 0, 0, 0]));
        assert!(!handler.detect_quic(&[0x83, 0, 0, 0, 1, 0, 0, 0, 0]));
        assert!(!handler.detect_quic(&[0xc3, 0, 0, 0, 1, 0, 0, 0, 0]));
        assert!(handler.detect_quic(&quic_initial_packet(b"")));
    }

    #[test]
    fn configured_version_must_match_packet_version() {
        let handler = QuicHandler {
            version: 0xff00_0001,
        };

        assert!(!handler.detect_quic(&quic_initial_packet(b"")));
        assert!(handler.detect_quic(&quic_initial_packet_with_version(0xff00_0001, b"")));
    }

    #[test]
    fn free_detector_rejects_unsupported_versions() {
        assert!(detect_quic(&quic_initial_packet(b"")));
        assert!(!detect_quic(&quic_initial_packet_with_version(
            0xff00_0001,
            b""
        )));
    }

    #[test]
    fn oversized_quic_packets_are_rejected_before_sni_scan() {
        let handler = QuicHandler::new();
        let mut packet = quic_initial_packet(b"");
        packet.extend(std::iter::repeat_n(
            b'a',
            MAX_QUIC_PACKET_BYTES + 1 - packet.len(),
        ));

        assert!(!handler.detect_quic(&packet));
        assert_eq!(handler.extract_sni(&packet), None);
    }

    #[test]
    fn detect_quic_rejects_truncated_initial_lengths() {
        let handler = QuicHandler::new();

        assert!(!handler.detect_quic(&[0xc3, 0, 0, 0, 1, 0]));
        assert!(!handler.detect_quic(&[0xc3, 0, 0, 0, 1, 0, 0]));
        assert!(!handler.detect_quic(&[0xc3, 0, 0, 0, 1, 0, 0, 0]));
        assert!(!handler.detect_quic(&[0xc3, 0, 0, 0, 1, 21, 0, 0, 0, 0]));
    }

    fn quic_initial_packet(payload: &[u8]) -> Vec<u8> {
        quic_initial_packet_with_version(1, payload)
    }

    fn quic_initial_packet_with_version(version: u32, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0xc3];
        packet.extend_from_slice(&version.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0]);
        write_quic_varint(4 + payload.len(), &mut packet);
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(payload);
        packet
    }

    fn write_quic_varint(value: usize, out: &mut Vec<u8>) {
        if value < 64 {
            out.push(value as u8);
            return;
        }
        out.push(0x40 | ((value >> 8) as u8));
        out.push(value as u8);
    }

    fn tls_client_hello_with_sni(hostname: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&0x0002u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);

        let mut sni_extension = Vec::new();
        let list_len = 1 + 2 + hostname.len();
        let ext_len = 2 + list_len;
        sni_extension.extend_from_slice(&0x0000u16.to_be_bytes());
        sni_extension.extend_from_slice(&(ext_len as u16).to_be_bytes());
        sni_extension.extend_from_slice(&(list_len as u16).to_be_bytes());
        sni_extension.push(0);
        sni_extension.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        sni_extension.extend_from_slice(hostname);

        body.extend_from_slice(&(sni_extension.len() as u16).to_be_bytes());
        body.extend_from_slice(&sni_extension);

        let handshake_len = body.len();
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&((handshake_len + 4) as u16).to_be_bytes());
        record.push(0x01);
        record.extend_from_slice(&[
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ]);
        record.extend_from_slice(&body);
        record
    }
}
