pub struct NknHandler;

impl NknHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        // NKN uses a JSON-RPC like protocol over WebSocket/TCP
        let text = String::from_utf8_lossy(data);

        if text.contains("\"jsonrpc\"") || text.contains("\"method\"") {
            tracing::warn!(
                "NKN JSON-RPC request detected: {}",
                text.chars().take(200).collect::<String>()
            );

            // Extract method if present
            if let Some(method_start) = text.find("\"method\"") {
                let rest = &text[method_start..];
                if let Some(colon) = rest.find(':') {
                    let value = rest[colon + 1..].trim().trim_matches('"').trim_matches(',');
                    let method_end = value.find('"').unwrap_or(value.len());
                    tracing::warn!("NKN method: {}", &value[..method_end]);
                }
            }

            // Return a valid JSON-RPC response
            let response = r#"{"jsonrpc":"2.0","result":{"id":"nettrap-node-id","version":"2.2.0","height":1000000},"id":1}"#;
            return response.as_bytes().to_vec();
        }

        // NKN also uses a binary protocol for P2P
        if data.len() >= 4 {
            let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            tracing::info!(
                "NKN binary packet: magic=0x{:08x}, len={}",
                magic,
                data.len()
            );
        }

        Vec::new()
    }

    /// Detect NKN/NKAbuse traffic patterns
    pub fn is_nkn_traffic(data: &[u8]) -> bool {
        let text = String::from_utf8_lossy(data);
        text.contains("\"jsonrpc\"")
            && (text.contains("getlatestblockheight")
                || text.contains("getnodestate")
                || text.contains("getwsaddr"))
    }
}

impl Default for NknHandler {
    fn default() -> Self {
        Self::new()
    }
}
