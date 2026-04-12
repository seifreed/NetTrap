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

    pub fn to_bytes(&self) -> Vec<u8> {
        let prefix = if self.positive { "+OK" } else { "-ERR" };
        format!("{} {}\r\n", prefix, self.message).into_bytes()
    }
}
