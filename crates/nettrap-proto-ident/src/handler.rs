/// Ident protocol handler (TCP/113, RFC 1413)
///
/// Accepts a port-pair query and returns a fake USERID response.
pub struct IdentHandler {
    os_type: String,
    default_user: String,
}

const IDENT_MAX_QUERY_LINE_BYTES: usize = 512;
const REDACTED_IDENT_QUERY_FIELD: &str = "***REDACTED***";

impl IdentHandler {
    pub fn new() -> Self {
        Self {
            os_type: "UNIX".to_string(),
            default_user: "root".to_string(),
        }
    }

    /// Handle an ident query line, e.g. "6191, 23\r\n".
    /// Returns the RFC 1413 response string.
    pub fn handle(&self, query: &str) -> String {
        let Some(query) = ident_query_line(query) else {
            return " : ERROR : INVALID-PORT\r\n".to_string();
        };
        let query = query.trim_end_matches(' ');
        if query.is_empty() || query.chars().next().is_some_and(char::is_whitespace) {
            return format!("{} : ERROR : INVALID-PORT\r\n", sanitize_error_query(query));
        }
        tracing::debug!("Ident query: '{}'", query);
        tracing::info!("Ident query: '{}'", REDACTED_IDENT_QUERY_FIELD);

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

fn ident_query_line(query: &str) -> Option<&str> {
    if let Some(line) = query.strip_suffix("\r\n") {
        if line.chars().any(|ch| matches!(ch, '\r' | '\n')) {
            return None;
        }
        return bounded_ident_query_line(line);
    }
    if query.ends_with(['\r', '\n']) {
        return None;
    }
    if query.chars().any(|ch| matches!(ch, '\r' | '\n')) {
        return None;
    }
    bounded_ident_query_line(query)
}

fn bounded_ident_query_line(line: &str) -> Option<&str> {
    (line.len() <= IDENT_MAX_QUERY_LINE_BYTES).then_some(line)
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
    let value = value.trim_matches(' ');
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u16>().ok().filter(|port| *port != 0)
}

fn sanitize_error_query(query: &str) -> String {
    let strip_all_whitespace = query
        .chars()
        .any(|ch| ch.is_whitespace() && !ch.is_ascii_whitespace());

    query
        .chars()
        .filter(|ch| {
            !ch.is_control()
                && if strip_all_whitespace {
                    !ch.is_whitespace()
                } else {
                    !ch.is_whitespace() || *ch == ' '
                }
        })
        .take(128)
        .collect()
}

impl Default for IdentHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{IDENT_MAX_QUERY_LINE_BYTES, IdentHandler};

    #[test]
    fn accepts_valid_port_pair() {
        let response = IdentHandler::new().handle("6191 , 23\r\n");

        assert_eq!(response, "6191 , 23 : USERID : UNIX : root\r\n");
    }

    #[test]
    fn rejects_leading_whitespace_query() {
        let response = IdentHandler::new().handle(" 6191 , 23\r\n");

        assert_eq!(response, " 6191 , 23 : ERROR : INVALID-PORT\r\n");
    }

    #[test]
    fn rejects_non_numeric_ports() {
        let response = IdentHandler::new().handle("abc, 23");

        assert_eq!(response, "abc, 23 : ERROR : INVALID-PORT\r\n");

        let response = IdentHandler::new().handle("+6191, 23");

        assert_eq!(response, "+6191, 23 : ERROR : INVALID-PORT\r\n");
    }

    #[test]
    fn rejects_overflow_ports() {
        let response = IdentHandler::new().handle("65536, 23");

        assert_eq!(response, "65536, 23 : ERROR : INVALID-PORT\r\n");
    }

    #[test]
    fn rejects_zero_ports() {
        let response = IdentHandler::new().handle("0, 23");

        assert_eq!(response, "0, 23 : ERROR : INVALID-PORT\r\n");

        let response = IdentHandler::new().handle("6191, 0");

        assert_eq!(response, "6191, 0 : ERROR : INVALID-PORT\r\n");
    }

    #[test]
    fn rejects_partial_line_terminators() {
        for query in ["6191, 23\n", "6191, 23\r"] {
            let response = IdentHandler::new().handle(query);

            assert_eq!(response, " : ERROR : INVALID-PORT\r\n", "{query:?}");
        }
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
    fn rejects_oversized_query_line_without_echo() {
        let query = "1".repeat(IDENT_MAX_QUERY_LINE_BYTES + 1);
        let response = IdentHandler::new().handle(&query);

        assert_eq!(response, " : ERROR : INVALID-PORT\r\n");
        assert!(!response.contains(&query));
    }

    #[test]
    fn accepts_maximum_query_line_length() {
        let padding = " ".repeat(IDENT_MAX_QUERY_LINE_BYTES - "6191,23".len());
        let query = format!("6191,23{padding}");
        let response = IdentHandler::new().handle(&query);

        assert_eq!(response, "6191 , 23 : USERID : UNIX : root\r\n");
    }

    #[test]
    fn rejects_tab_padded_port_fields() {
        let response = IdentHandler::new().handle("6191, 23\t\r\n");

        assert_eq!(response, "6191, 23 : ERROR : INVALID-PORT\r\n");
    }

    #[test]
    fn rejects_embedded_crlf_in_query_line() {
        let response = IdentHandler::new().handle("6191,23\r\nUSER test");

        assert_eq!(response, " : ERROR : INVALID-PORT\r\n");
        assert!(!response.contains("USER test"));
    }

    #[test]
    fn rejects_unicode_whitespace_padded_query() {
        let response = IdentHandler::new().handle("6191, 23\u{00a0}\r\n");

        assert_eq!(response, "6191,23 : ERROR : INVALID-PORT\r\n");
    }

    #[test]
    fn invalid_query_error_strips_unicode_whitespace_from_echo() {
        let response = IdentHandler::new().handle("6191, 23\u{00a0}\r\n");

        assert_eq!(response, "6191,23 : ERROR : INVALID-PORT\r\n");
    }
}
