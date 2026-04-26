/// Finger protocol handler (TCP/79, RFC 1288)
///
/// Returns fake user information for any queried username.
pub struct FingerHandler {
    hostname: String,
}

impl FingerHandler {
    pub fn new() -> Self {
        Self {
            hostname: "nettrap.local".to_string(),
        }
    }

    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = hostname.into();
        self
    }

    /// Handle a finger query line (e.g. "root\r\n" or "\r\n" for listing).
    /// Returns a human-readable response string.
    pub fn handle(&self, query: &str) -> String {
        let user = sanitize_user(query);
        tracing::info!("Finger query: '{}'", user);

        if user.is_empty() {
            // Listing mode
            format!(
                "Login    Name                 TTY  Idle  When    Where\r\n\
                 root     System Administrator  *1         Mon 08:00  console\r\n\
                 admin    Admin User            *2   3d    Mon 08:00  {}\r\n",
                self.hostname
            )
        } else {
            format!(
                "Login: {user}\r\n\
                 Name: {user}\r\n\
                 Directory: /home/{user}\r\n\
                 Shell: /bin/bash\r\n\
                 On since Mon Jan  1 08:00 (UTC) on tty1\r\n\
                 No mail.\r\n\
                 No Plan.\r\n"
            )
        }
    }
}

impl Default for FingerHandler {
    fn default() -> Self {
        Self::new()
    }
}

fn sanitize_user(query: &str) -> String {
    query
        .trim()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '@'))
        .take(64)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::FingerHandler;

    #[test]
    fn preserves_normal_user_query() {
        let response = FingerHandler::new().handle("root\r\n");

        assert!(response.contains("Login: root\r\n"));
        assert!(response.contains("Directory: /home/root\r\n"));
    }

    #[test]
    fn sanitizes_control_characters_from_user_query() {
        let response = FingerHandler::new().handle("ro\r\nInjected: yes");

        assert!(response.contains("Login: roInjectedyes\r\n"));
        assert!(!response.contains("Injected: yes"));
    }

    #[test]
    fn caps_user_query_length() {
        let long_user = "a".repeat(80);
        let response = FingerHandler::new().handle(&long_user);
        let expected = "a".repeat(64);

        assert!(response.contains(&format!("Login: {expected}\r\n")));
        assert!(!response.contains(&"a".repeat(80)));
    }

    #[test]
    fn empty_query_keeps_listing_mode() {
        let response = FingerHandler::new().handle("\r\n");

        assert!(response.contains("Login    Name"));
        assert!(response.contains("System Administrator"));
    }
}
