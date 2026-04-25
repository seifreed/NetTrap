pub struct PostgresHandler {
    version: String,
}

const POSTGRES_SSL_REQUEST: u32 = 80877103;
const POSTGRES_GSSENC_REQUEST: u32 = 80877104;

impl PostgresHandler {
    pub fn new() -> Self {
        Self {
            version: "16.2".to_string(),
        }
    }

    pub fn get_handshake_response(&self) -> Vec<u8> {
        // PostgreSQL sends 'R' authentication request
        let mut resp = Vec::new();
        resp.push(b'R'); // Auth request
        resp.extend_from_slice(&8u32.to_be_bytes()); // Length
        resp.extend_from_slice(&0u32.to_be_bytes()); // AuthenticationOk
        // Ready for query
        resp.push(b'Z');
        resp.extend_from_slice(&5u32.to_be_bytes());
        resp.push(b'I'); // Idle
        resp
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        match data[0] {
            b'Q' => {
                // Simple query: 'Q'(1) + length(4) + query_string
                if data.len() < 5 {
                    return Vec::new();
                }
                let msg_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
                if msg_len < 4 || data.len() < 1 + msg_len {
                    tracing::debug!(
                        "POSTGRES malformed Query length: declared={}, available={}",
                        msg_len,
                        data.len().saturating_sub(1)
                    );
                    return Vec::new();
                }
                let query_end = 1 + msg_len;
                let raw_query = String::from_utf8_lossy(&data[5..query_end]);
                let query = raw_query.trim_end_matches('\0');
                tracing::warn!("POSTGRES QUERY (v{}): {}", self.version, query);
                // CommandComplete + ReadyForQuery
                let mut resp = Vec::new();
                let tag = b"SELECT 0";
                resp.push(b'C');
                resp.extend_from_slice(&((4 + tag.len() + 1) as u32).to_be_bytes());
                resp.extend_from_slice(tag);
                resp.push(0);
                resp.push(b'Z');
                resp.extend_from_slice(&5u32.to_be_bytes());
                resp.push(b'I');
                resp
            }
            b'X' => Vec::new(), // Terminate
            // Post-auth commands: Parse, Bind, Describe, Execute, Close, Flush, Sync, FunctionCall
            b'P' | b'B' | b'D' | b'E' | b'C' | b'H' | b'S' | b'F' => {
                tracing::info!("POSTGRES command: 0x{:02x}", data[0]);
                // Respond with ReadyForQuery (idle)
                let mut resp = Vec::new();
                resp.push(b'Z');
                resp.extend_from_slice(&5u32.to_be_bytes());
                resp.push(b'I'); // Idle
                resp
            }
            _ if data.len() >= 8 => {
                // Startup message (no type byte, starts with length + version)
                let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let pg_version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                if pg_version == POSTGRES_SSL_REQUEST {
                    // SSLRequest → respond 'N' (no SSL), client will retry with normal startup
                    tracing::info!("POSTGRES SSLRequest from client, declining");
                    vec![b'N']
                } else if pg_version == POSTGRES_GSSENC_REQUEST {
                    // GSSENCRequest → respond 'N' (no GSS encryption), client will retry startup.
                    tracing::info!("POSTGRES GSSENCRequest from client, declining");
                    vec![b'N']
                } else if pg_version == 196608 {
                    // Normal 3.0 startup
                    tracing::info!(
                        "POSTGRES startup (server v{}): client version=0x{:08x}",
                        self.version,
                        pg_version
                    );
                    if len > 8 {
                        let msg_end = (len as usize).min(data.len());
                        let params = String::from_utf8_lossy(&data[8..msg_end]);
                        tracing::info!("POSTGRES params: {}", params.replace('\0', " "));
                    }
                    self.get_handshake_response()
                } else {
                    tracing::info!("POSTGRES unknown message: first_byte=0x{:02x}", data[0]);
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    }
}

impl Default for PostgresHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gssenc_request_is_declined_like_ssl_request() {
        let mut request = Vec::new();
        request.extend_from_slice(&8u32.to_be_bytes());
        request.extend_from_slice(&POSTGRES_GSSENC_REQUEST.to_be_bytes());

        assert_eq!(PostgresHandler::new().handle(&request), b"N");
    }

    #[test]
    fn malformed_query_length_does_not_panic() {
        let response = PostgresHandler::new().handle(&[b'Q', 0, 0, 0, 1]);

        assert!(response.is_empty());
    }

    #[test]
    fn truncated_query_length_is_rejected() {
        let response = PostgresHandler::new().handle(&[b'Q', 0, 0, 0, 8, b'S', b'E']);

        assert!(response.is_empty());
    }
}
