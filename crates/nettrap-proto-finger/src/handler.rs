/// Finger protocol handler (TCP/79, RFC 1288)
///
/// Returns fake user information for any queried username.
pub struct FingerHandler {
    hostname: String,
}

const FINGER_MAX_USER_CHARS: usize = 64;
const FINGER_MAX_QUERY_LINE_BYTES: usize = 512;
const REDACTED_FINGER_QUERY_FIELD: &str = "***REDACTED***";
const INVALID_FINGER_QUERY_RESPONSE: &str = "No such user.\r\n";

impl FingerHandler {
    pub fn new() -> Self {
        Self {
            hostname: "nettrap.local".to_string(),
        }
    }

    /// Handle a finger query line (e.g. "root\r\n" or "\r\n" for listing).
    /// Returns a human-readable response string.
    pub fn handle(&self, query: &str) -> String {
        let query = parse_query(query);
        let user = match &query {
            FingerQuery::User(user) => user.as_str(),
            FingerQuery::Listing => "",
            FingerQuery::Invalid => REDACTED_FINGER_QUERY_FIELD,
        };
        tracing::debug!("Finger query: '{}'", user);
        tracing::info!("Finger query: '{}'", REDACTED_FINGER_QUERY_FIELD);

        match query {
            FingerQuery::Listing => format!(
                "Login    Name                 TTY  Idle  When    Where\r\n\
                 root     System Administrator  *1         Mon 08:00  console\r\n\
                 admin    Admin User            *2   3d    Mon 08:00  {}\r\n",
                self.hostname
            ),
            FingerQuery::User(user) => format!(
                "Login: {user}\r\n\
                 Name: {user}\r\n\
                 Directory: /home/{user}\r\n\
                 Shell: /bin/bash\r\n\
                 On since Mon Jan  1 08:00 (UTC) on tty1\r\n\
                 No mail.\r\n\
                 No Plan.\r\n"
            ),
            FingerQuery::Invalid => INVALID_FINGER_QUERY_RESPONSE.to_string(),
        }
    }
}

impl Default for FingerHandler {
    fn default() -> Self {
        Self::new()
    }
}

enum FingerQuery {
    Listing,
    User(String),
    Invalid,
}

fn parse_query(query: &str) -> FingerQuery {
    if query.contains('\0') {
        return FingerQuery::Invalid;
    }
    let Some(first_line) = finger_query_line(query) else {
        return FingerQuery::Invalid;
    };
    if first_line.is_empty() {
        return FingerQuery::Listing;
    }
    if first_line.chars().next().is_some_and(char::is_whitespace) {
        return FingerQuery::Invalid;
    }
    if first_line
        .chars()
        .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return FingerQuery::Invalid;
    }

    let parts: Vec<&str> = first_line.split(' ').collect();
    if parts.iter().skip(1).any(|part| part.is_empty()) {
        return FingerQuery::Invalid;
    }
    let mut parts = parts.into_iter();
    let Some(first) = parts.next() else {
        return FingerQuery::Listing;
    };
    let token = if first.eq_ignore_ascii_case("/W") {
        let Some(user) = parts.next() else {
            return FingerQuery::Listing;
        };
        if parts.next().is_some() {
            return FingerQuery::Invalid;
        }
        user
    } else {
        if parts.next().is_some() {
            return FingerQuery::Invalid;
        }
        first
    };
    if token.is_empty()
        || token.chars().count() > FINGER_MAX_USER_CHARS
        || !token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '@'))
    {
        FingerQuery::Invalid
    } else {
        FingerQuery::User(token.to_string())
    }
}

fn finger_query_line(query: &str) -> Option<&str> {
    if let Some(line) = query.strip_suffix("\r\n") {
        if line
            .as_bytes()
            .iter()
            .any(|&byte| matches!(byte, b'\r' | b'\n'))
        {
            return None;
        }
        return bounded_finger_query_line(line);
    }
    if query
        .as_bytes()
        .iter()
        .any(|&byte| matches!(byte, b'\r' | b'\n'))
    {
        return None;
    }
    bounded_finger_query_line(query)
}

fn bounded_finger_query_line(line: &str) -> Option<&str> {
    (line.len() <= FINGER_MAX_QUERY_LINE_BYTES).then_some(line)
}

#[cfg(test)]
mod tests {
    use super::{FINGER_MAX_QUERY_LINE_BYTES, FingerHandler};

    #[test]
    fn preserves_normal_user_query() {
        let response = FingerHandler::new().handle("root\r\n");

        assert!(response.contains("Login: root\r\n"));
        assert!(response.contains("Directory: /home/root\r\n"));
    }

    #[test]
    fn sanitizes_control_characters_from_user_query() {
        let response = FingerHandler::new().handle("ro\x1bInjected: yes");

        assert_eq!(response, "No such user.\r\n");
        assert!(!response.contains("Injected: yes"));
    }

    #[test]
    fn rejects_oversized_user_query() {
        let long_user = "a".repeat(80);
        let response = FingerHandler::new().handle(&long_user);

        assert_eq!(response, "No such user.\r\n");
        assert!(!response.contains(&"a".repeat(80)));
    }

    #[test]
    fn rejects_oversized_query_line() {
        let long_query = "a".repeat(FINGER_MAX_QUERY_LINE_BYTES + 1);
        let response = FingerHandler::new().handle(&long_query);

        assert_eq!(response, "No such user.\r\n");
        assert!(!response.contains(&long_query));
    }

    #[test]
    fn long_format_switch_preserves_user_query() {
        let response = FingerHandler::new().handle("/W root\r\n");

        assert!(response.contains("Login: root\r\n"));
        assert!(response.contains("Directory: /home/root\r\n"));
        assert!(!response.contains("Login: W\r\n"));
    }

    #[test]
    fn long_format_switch_without_user_keeps_listing_mode() {
        let response = FingerHandler::new().handle("/W\r\n");

        assert!(response.contains("Login    Name"));
        assert!(!response.contains("Login: W\r\n"));
    }

    #[test]
    fn compressed_spaces_in_user_queries_are_rejected() {
        let response = FingerHandler::new().handle("root  admin\r\n");

        assert_eq!(response, "No such user.\r\n");
        assert!(!response.contains("Login: root\r\n"));

        let response = FingerHandler::new().handle("/W  root\r\n");

        assert_eq!(response, "No such user.\r\n");
        assert!(!response.contains("Login: root\r\n"));
    }

    #[test]
    fn extra_user_query_tokens_are_rejected() {
        let response = FingerHandler::new().handle("root admin\r\n");

        assert_eq!(response, "No such user.\r\n");
        assert!(!response.contains("Login: root\r\n"));

        let response = FingerHandler::new().handle("/W root extra\r\n");

        assert_eq!(response, "No such user.\r\n");
        assert!(!response.contains("Login: root\r\n"));
    }

    #[test]
    fn invalid_user_tokens_are_rejected_without_listing_users() {
        let response = FingerHandler::new().handle("root!admin\r\n");

        assert_eq!(response, "No such user.\r\n");
        assert!(!response.contains("Login: rootadmin\r\n"));
    }

    #[test]
    fn partial_line_terminators_are_rejected_without_listing_users() {
        for query in ["root\n", "root\r"] {
            let response = FingerHandler::new().handle(query);

            assert_eq!(response, "No such user.\r\n", "{query:?}");
            assert!(!response.contains("Login: root\r\n"), "{query:?}");
        }
    }

    #[test]
    fn embedded_newline_in_user_queries_is_rejected_without_listing_users() {
        let response = FingerHandler::new().handle("root\njunk");

        assert_eq!(response, "No such user.\r\n");
        assert!(!response.contains("Login: root\r\n"));
    }

    #[test]
    fn embedded_nul_in_user_queries_is_rejected_without_listing_users() {
        let response = FingerHandler::new().handle("root\0admin");

        assert_eq!(response, "No such user.\r\n");
        assert!(!response.contains("INVALID-PORT"));
        assert!(!response.contains("Login: root\r\n"));
    }

    #[test]
    fn leading_whitespace_user_queries_are_rejected_without_listing_users() {
        let response = FingerHandler::new().handle(" root\r\n");

        assert_eq!(response, "No such user.\r\n");
        assert!(!response.contains("Login: root\r\n"));
    }

    #[test]
    fn multi_word_user_queries_are_rejected() {
        let response = FingerHandler::new().handle("root admin\r\n");

        assert_eq!(response, "No such user.\r\n");
        assert!(!response.contains("Login: root\r\n"));
    }

    #[test]
    fn unicode_whitespace_in_user_queries_is_rejected_without_listing_users() {
        let response = FingerHandler::new().handle("root\u{00a0}admin\r\n");

        assert_eq!(response, "No such user.\r\n");
        assert!(!response.contains("Login: rootadmin\r\n"));
    }

    #[test]
    fn embedded_carriage_returns_are_rejected_without_listing_users() {
        let response = FingerHandler::new().handle("root\rjunk");

        assert_eq!(response, "No such user.\r\n");
        assert!(!response.contains("Login: root\r\n"));
    }

    #[test]
    fn empty_query_keeps_listing_mode() {
        let response = FingerHandler::new().handle("\r\n");

        assert!(response.contains("Login    Name"));
        assert!(response.contains("System Administrator"));
    }
}
