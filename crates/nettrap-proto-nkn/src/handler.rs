pub struct NknHandler;

#[derive(Debug)]
struct NknJsonRpcRequest {
    method: String,
    id: Option<serde_json::Value>,
}

impl NknHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        // NKN uses a JSON-RPC like protocol over WebSocket/TCP
        if let Some(request) = Self::parse_json_rpc(data) {
            let text = String::from_utf8_lossy(data);
            tracing::warn!(
                "NKN JSON-RPC request detected: {}",
                text.chars().take(200).collect::<String>()
            );
            tracing::warn!("NKN method: {}", request.method);

            let Some(id) = request.id else {
                return Vec::new();
            };
            let response = if Self::is_known_nkn_method(&request.method) {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": {
                        "id": "nettrap-node-id",
                        "version": "2.2.0",
                        "height": 1000000,
                    },
                    "id": id,
                })
            } else {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32601,
                        "message": "Method not found",
                    },
                    "id": id,
                })
            };
            return response.to_string().into_bytes();
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
        let Some(request) = Self::parse_json_rpc(data) else {
            return false;
        };
        Self::is_known_nkn_method(&request.method)
    }

    fn is_known_nkn_method(method: &str) -> bool {
        matches!(
            method,
            "getlatestblockheight" | "getnodestate" | "getwsaddr"
        )
    }

    fn parse_json_rpc(data: &[u8]) -> Option<NknJsonRpcRequest> {
        let value: serde_json::Value = serde_json::from_slice(data).ok()?;
        let object = value.as_object()?;
        if object.get("jsonrpc")?.as_str()? != "2.0" {
            return None;
        }
        let method = object.get("method")?.as_str()?;
        if method.is_empty() {
            return None;
        }
        let id = object.get("id").cloned();
        if id
            .as_ref()
            .is_some_and(|id| !Self::is_valid_json_rpc_id(id))
        {
            return None;
        }

        Some(NknJsonRpcRequest {
            method: method.to_string(),
            id,
        })
    }

    fn is_valid_json_rpc_id(id: &serde_json::Value) -> bool {
        id.is_null() || id.is_string() || id.is_number()
    }
}

impl Default for NknHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_rpc_request_gets_response() {
        let response =
            NknHandler::new().handle(br#"{"jsonrpc":"2.0","method":"getnodestate","id":7}"#);

        assert!(!response.is_empty());
        let response: serde_json::Value =
            serde_json::from_slice(&response).expect("response should be JSON");
        assert_eq!(response["id"], 7);
        assert_eq!(response["jsonrpc"], "2.0");
    }

    #[test]
    fn text_with_method_substring_is_not_json_rpc() {
        let response = NknHandler::new().handle(br#"prefix "method": "getnodestate""#);

        assert!(response.is_empty());
    }

    #[test]
    fn traffic_detection_requires_valid_json_rpc_method() {
        assert!(NknHandler::is_nkn_traffic(
            br#"{"jsonrpc":"2.0","method":"getlatestblockheight","id":1}"#
        ));
        assert!(!NknHandler::is_nkn_traffic(
            br#"{"jsonrpc":"2.0","method":"unknown","id":1}"#
        ));
        assert!(!NknHandler::is_nkn_traffic(br#""jsonrpc" "getnodestate""#));
        assert!(!NknHandler::is_nkn_traffic(
            br#"{"jsonrpc":"2.0","method":" getnodestate ","id":1}"#
        ));
    }

    #[test]
    fn unknown_json_rpc_method_returns_method_not_found() {
        let response = NknHandler::new().handle(br#"{"jsonrpc":"2.0","method":"unknown","id":9}"#);

        let response: serde_json::Value =
            serde_json::from_slice(&response).expect("response should be JSON");
        assert_eq!(response["id"], 9);
        assert_eq!(response["error"]["code"], -32601);
        assert!(response.get("result").is_none());
    }

    #[test]
    fn json_rpc_notifications_do_not_get_responses() {
        let known = NknHandler::new().handle(br#"{"jsonrpc":"2.0","method":"getnodestate"}"#);
        assert!(known.is_empty());

        let unknown = NknHandler::new().handle(br#"{"jsonrpc":"2.0","method":"unknown"}"#);
        assert!(unknown.is_empty());
    }

    #[test]
    fn json_rpc_rejects_invalid_id_shapes() {
        let object_id =
            NknHandler::new().handle(br#"{"jsonrpc":"2.0","method":"getnodestate","id":{}}"#);
        let array_id =
            NknHandler::new().handle(br#"{"jsonrpc":"2.0","method":"getnodestate","id":[]}"#);

        assert!(object_id.is_empty());
        assert!(array_id.is_empty());
    }

    #[test]
    fn json_rpc_method_names_are_exact() {
        let response =
            NknHandler::new().handle(br#"{"jsonrpc":"2.0","method":" getnodestate ","id":7}"#);

        let response: serde_json::Value =
            serde_json::from_slice(&response).expect("response should be JSON");
        assert_eq!(response["id"], 7);
        assert_eq!(response["error"]["code"], -32601);
    }
}
