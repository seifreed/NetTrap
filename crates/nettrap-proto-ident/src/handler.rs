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
        self.default_user = sanitize_identity_field(&user.into(), "root");
        self
    }

    /// Handle an ident query line, e.g. "6191, 23\r\n".
    /// Returns the RFC 1413 response string.
    pub fn handle(&self, query: &str) -> String {
        let query = query.trim();
        tracing::info!("Ident query: '{}'", query);

        if let Some((server_port, client_port)) = parse_port_pair(query) {
            format!(
                "{} , {} : USERID : {} : {}\r\n",
                server_port, client_port, self.os_type, self.default_user
            )
        } else {
            format!("{} : ERROR : INVALID-PORT\r\n", sanitize_error_query(query))
        }
    }
}

fn parse_port_pair(query: &str) -> Option<(u16, u16)> {
    let mut parts = query.split(',');
    let server_port = parse_port(parts.next()?)?;
    let client_port = parse_port(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some((server_port, client_port))
}

fn parse_port(value: &str) -> Option<u16> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u16>().ok()
}

fn sanitize_error_query(query: &str) -> String {
    query
        .chars()
        .filter(|ch| !ch.is_control())
        .take(128)
        .collect()
}

fn sanitize_identity_field(value: &str, fallback: &str) -> String {
    let safe: String = value
        .lines()
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|ch| !ch.is_control())
        .take(64)
        .collect::<String>()
        .trim()
        .to_string();
    if safe.is_empty() {
        fallback.to_string()
    } else {
        safe
    }
}

impl Default for IdentHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::IdentHandler;

    #[test]
    fn accepts_valid_port_pair() {
        let response = IdentHandler::new().handle(" 6191 , 23\r\n");

        assert_eq!(response, "6191 , 23 : USERID : UNIX : root\r\n");
    }

    #[test]
    fn rejects_non_numeric_ports() {
        let response = IdentHandler::new().handle("abc, 23");

        assert_eq!(response, "abc, 23 : ERROR : INVALID-PORT\r\n");
    }

    #[test]
    fn rejects_overflow_ports() {
        let response = IdentHandler::new().handle("65536, 23");

        assert_eq!(response, "65536, 23 : ERROR : INVALID-PORT\r\n");
    }

    #[test]
    fn rejects_empty_port_fields() {
        let response = IdentHandler::new().handle("6191, ");

        assert_eq!(response, "6191, : ERROR : INVALID-PORT\r\n");
    }

    #[test]
    fn rejects_extra_fields() {
        let response = IdentHandler::new().handle("6191, 23, 80");

        assert_eq!(response, "6191, 23, 80 : ERROR : INVALID-PORT\r\n");
    }

    #[test]
    fn configured_user_cannot_inject_response_lines() {
        let response = IdentHandler::new()
            .with_user("root\r\n6191 , 23 : USERID : UNIX : injected")
            .handle("6191, 23");

        assert_eq!(response, "6191 , 23 : USERID : UNIX : root\r\n");
        assert_eq!(response.matches("\r\n").count(), 1);
    }
}
