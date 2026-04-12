use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IrcBanner {
    Generic,
    DebianIrcd,
    Custom(String),
}

impl IrcBanner {
    pub fn get_banner(&self, server_name: &str) -> String {
        match self {
            IrcBanner::Generic => format!(
                ":{}  NOTICE AUTH :*** Looking up your hostname...\r\n:{}  NOTICE AUTH :*** Found your hostname\r\n",
                server_name, server_name
            ),
            IrcBanner::DebianIrcd => format!(
                ":{}  NOTICE AUTH :*** Looking up your hostname...\r\n:{}  NOTICE AUTH :*** Checking Ident\r\n:{}  NOTICE AUTH :*** Found your hostname\r\n:{}  NOTICE AUTH :*** No Ident response\r\n",
                server_name, server_name, server_name, server_name
            ),
            IrcBanner::Custom(banner) => format!("{}\r\n", banner),
        }
    }
}

impl Default for IrcBanner {
    fn default() -> Self {
        IrcBanner::Generic
    }
}

pub struct IrcResponse {
    pub messages: Vec<String>,
}

impl IrcResponse {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    pub fn single(msg: impl Into<String>) -> Self {
        Self {
            messages: vec![msg.into()],
        }
    }

    pub fn add(&mut self, msg: impl Into<String>) {
        self.messages.push(msg.into());
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.messages.join("").into_bytes()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}
