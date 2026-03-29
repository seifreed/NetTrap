/// Ident protocol handler (TCP/113, RFC 1413)
///
/// Accepts a port-pair query and returns a fake USERID response.
pub struct IdentHandler {
    os_type: String,
    default_user: String,
}

impl IdentHandler {
    pub fn new() -> Self {
        Self {
            os_type: "UNIX".to_string(),
            default_user: "root".to_string(),
        }
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.default_user = user.into();
        self
    }

    /// Handle an ident query line, e.g. "6191, 23\r\n".
    /// Returns the RFC 1413 response string.
    pub fn handle(&self, query: &str) -> String {
        let query = query.trim();
        tracing::info!("Ident query: '{}'", query);

        // Parse "server-port , client-port"
        let ports: Vec<&str> = query.splitn(2, ',').map(|s| s.trim()).collect();
        if ports.len() == 2 {
            format!(
                "{} , {} : USERID : {} : {}\r\n",
                ports[0], ports[1], self.os_type, self.default_user
            )
        } else {
            format!("{} : ERROR : INVALID-PORT\r\n", query)
        }
    }
}

impl Default for IdentHandler {
    fn default() -> Self {
        Self::new()
    }
}
