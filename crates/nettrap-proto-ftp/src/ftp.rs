pub struct FtpHandler {
    banner: String,
}

impl FtpHandler {
    pub fn new() -> Self {
        Self {
            banner: "220 NetTrap FTP Ready".to_string(),
        }
    }

    pub fn with_banner(mut self, banner: impl Into<String>) -> Self {
        self.banner = banner.into();
        self
    }
}

impl Default for FtpHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl FtpHandler {
    pub fn handle(&self, command: &str) -> FtpResponse {
        let upper = command.to_uppercase();

        if upper.starts_with("USER") {
            FtpResponse::new(331, "Username OK, need password")
        } else if upper.starts_with("PASS") {
            FtpResponse::new(230, "User logged in")
        } else if upper.starts_with("PWD") {
            FtpResponse::new(257, "/")
        } else if upper.starts_with("TYPE") {
            FtpResponse::new(200, "Type set to I")
        } else if upper.starts_with("PASV") {
            FtpResponse::new(227, "Entering Passive Mode")
        } else if upper.starts_with("LIST") || upper.starts_with("RETR") {
            FtpResponse::new(150, "Opening data connection")
        } else if upper.starts_with("QUIT") {
            FtpResponse::new(221, "Goodbye")
        } else {
            FtpResponse::new(200, "OK")
        }
    }

    pub fn get_banner(&self) -> &[u8] {
        self.banner.as_bytes()
    }
}

pub struct FtpResponse {
    pub code: u16,
    pub message: String,
}

impl FtpResponse {
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        format!("{} {}\r\n", self.code, self.message).into_bytes()
    }
}
