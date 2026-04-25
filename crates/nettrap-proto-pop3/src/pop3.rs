pub struct Pop3Response {
    pub positive: bool,
    pub message: String,
}

impl Pop3Response {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            positive: true,
            message: message.into(),
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            positive: false,
            message: message.into(),
        }
    }

    pub fn raw(message: impl Into<String>) -> Self {
        Self {
            positive: true,
            message: message.into(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        if is_complete_pop3_response(&self.message) {
            return self.message.as_bytes().to_vec();
        }

        let prefix = if self.positive { "+OK" } else { "-ERR" };
        format!("{} {}\r\n", prefix, self.message).into_bytes()
    }
}

fn is_complete_pop3_response(message: &str) -> bool {
    message == "+\r\n"
        || message.starts_with("+OK ")
        || message.starts_with("+OK\r\n")
        || message.starts_with("-ERR ")
        || message.starts_with("-ERR\r\n")
}
