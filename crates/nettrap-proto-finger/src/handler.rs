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
        let user = query.trim();
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
