pub struct CoapHandler;

impl CoapHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 4 {
            return Vec::new();
        }
        let version = (data[0] >> 6) & 0x03;
        let msg_type = (data[0] >> 4) & 0x03;
        let code = data[1];
        let msg_id = u16::from_be_bytes([data[2], data[3]]);
        tracing::info!(
            "CoAP: version={}, type={}, code={}.{:02}, id={}",
            version,
            msg_type,
            code >> 5,
            code & 0x1F,
            msg_id
        );

        // Build ACK response
        let mut resp = vec![0u8; 4];
        resp[0] = (1 << 6) | (2 << 4); // Version 1, ACK
        resp[1] = 0x45; // 2.05 Content
        resp[2] = data[2];
        resp[3] = data[3]; // Same message ID
        // Add payload marker + content
        resp.push(0xFF); // Payload marker
        resp.extend_from_slice(b"{\"status\":\"ok\"}");
        resp
    }
}

impl Default for CoapHandler {
    fn default() -> Self {
        Self::new()
    }
}
