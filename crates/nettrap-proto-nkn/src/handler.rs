use serde::de::Deserializer as _;
use serde::de::{self, IgnoredAny, MapAccess, Visitor};

pub struct NknHandler;

const MAX_JSON_RPC_METHOD_BYTES: usize = 128;
const MAX_JSON_RPC_ID_STRING_BYTES: usize = 256;
const MAX_JSON_RPC_REQUEST_BYTES: usize = 4096;
const REDACTED_JSON_RPC_FIELD: &str = "***REDACTED***";

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
            tracing::debug!(
                "NKN JSON-RPC request detected: {}",
                nettrap_core::sanitize::single_line_bytes(data)
            );
            tracing::debug!(
                "NKN method: {}",
                nettrap_core::sanitize::single_line(&request.method)
            );
            tracing::warn!(
                "NKN JSON-RPC request detected: method={}",
                REDACTED_JSON_RPC_FIELD
            );

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
        if data.len() > MAX_JSON_RPC_REQUEST_BYTES {
            return None;
        }

        let mut deserializer = serde_json::Deserializer::from_slice(data);
        let request = deserializer.deserialize_any(JsonRpcVisitor).ok()?;
        deserializer.end().ok()?;
        if request.method.is_empty() || request.method.len() > MAX_JSON_RPC_METHOD_BYTES {
            return None;
        }
        if request
            .id
            .as_ref()
            .is_some_and(|id| !Self::is_valid_json_rpc_id(id))
        {
            return None;
        }

        Some(request)
    }

    fn is_valid_json_rpc_id(id: &serde_json::Value) -> bool {
        id.is_null()
            || id.is_number()
            || id
                .as_str()
                .is_some_and(|value| value.len() <= MAX_JSON_RPC_ID_STRING_BYTES)
    }
}

struct JsonRpcVisitor;

impl<'de> Visitor<'de> for JsonRpcVisitor {
    type Value = NknJsonRpcRequest;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON-RPC object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut jsonrpc = None;
        let mut method = None;
        let mut id = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "jsonrpc" => {
                    if jsonrpc.replace(map.next_value::<String>()?).is_some() {
                        return Err(de::Error::custom("duplicate jsonrpc field"));
                    }
                }
                "method" => {
                    if method.replace(map.next_value::<String>()?).is_some() {
                        return Err(de::Error::custom("duplicate method field"));
                    }
                }
                "id" => {
                    if id.replace(map.next_value::<serde_json::Value>()?).is_some() {
                        return Err(de::Error::custom("duplicate id field"));
                    }
                }
                _ => {
                    let _: IgnoredAny = map.next_value()?;
                }
            }
        }

        if jsonrpc.as_deref() != Some("2.0") {
            return Err(de::Error::custom("unsupported jsonrpc version"));
        }
        let method = method.ok_or_else(|| de::Error::custom("missing method"))?;

        Ok(NknJsonRpcRequest { method, id })
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

    const LOG_FIELD_PREVIEW_CHARS: usize = 240;

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
    fn json_rpc_rejects_oversized_reflected_fields() {
        let oversized_method = format!(
            r#"{{"jsonrpc":"2.0","method":"{}","id":1}}"#,
            "a".repeat(MAX_JSON_RPC_METHOD_BYTES + 1)
        );
        let oversized_id = format!(
            r#"{{"jsonrpc":"2.0","method":"getnodestate","id":"{}"}}"#,
            "a".repeat(MAX_JSON_RPC_ID_STRING_BYTES + 1)
        );

        assert!(
            NknHandler::new()
                .handle(oversized_method.as_bytes())
                .is_empty()
        );
        assert!(NknHandler::new().handle(oversized_id.as_bytes()).is_empty());
    }

    #[test]
    fn json_rpc_rejects_oversized_request_before_parsing_unknown_fields() {
        let oversized = format!(
            r#"{{"jsonrpc":"2.0","method":"getnodestate","id":1,"padding":"{}"}}"#,
            "a".repeat(MAX_JSON_RPC_REQUEST_BYTES)
        );

        assert!(NknHandler::new().handle(oversized.as_bytes()).is_empty());
        assert!(!NknHandler::is_nkn_traffic(oversized.as_bytes()));
    }

    #[test]
    fn json_rpc_ignores_unknown_fields_without_changing_response() {
        let response = NknHandler::new().handle(
            br#"{"jsonrpc":"2.0","method":"getnodestate","id":7,"unknown":{"nested":["ignored"]}}"#,
        );

        let response: serde_json::Value =
            serde_json::from_slice(&response).expect("response should be JSON");
        assert_eq!(response["id"], 7);
        assert!(response.get("result").is_some());
    }

    #[test]
    fn logged_json_rpc_fields_are_single_line() {
        let raw = nettrap_core::sanitize::single_line("{\n\"method\":\"bad\\nmethod\"\x1b}");
        let method = nettrap_core::sanitize::single_line("bad\nmethod\x1b");

        assert_eq!(raw, "{ \"method\":\"bad\\nmethod\" }");
        assert_eq!(method, "bad method ");
        assert!(!raw.chars().any(char::is_control));
        assert!(!method.chars().any(char::is_control));

        let long = "a".repeat(LOG_FIELD_PREVIEW_CHARS + 1);
        assert_eq!(
            nettrap_core::sanitize::single_line(&long).len(),
            LOG_FIELD_PREVIEW_CHARS
        );
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

    #[test]
    fn json_rpc_rejects_duplicate_top_level_keys() {
        let duplicate_method = NknHandler::new()
            .handle(br#"{"jsonrpc":"2.0","method":"getnodestate","method":"unknown","id":7}"#);
        let duplicate_id =
            NknHandler::new().handle(br#"{"jsonrpc":"2.0","method":"getnodestate","id":7,"id":8}"#);

        assert!(duplicate_method.is_empty());
        assert!(duplicate_id.is_empty());
    }

    #[test]
    fn json_rpc_rejects_trailing_bytes_after_request() {
        let trailing_text = NknHandler::new()
            .handle(br#"{"jsonrpc":"2.0","method":"getnodestate","id":7} trailing"#);
        let trailing_object =
            NknHandler::new().handle(br#"{"jsonrpc":"2.0","method":"getnodestate","id":7}{}"#);

        assert!(trailing_text.is_empty());
        assert!(trailing_object.is_empty());
    }
}
