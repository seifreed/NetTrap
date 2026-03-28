use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub port: u16,
    pub bind_address: String,
    pub enabled: bool,
    pub emulate_response: bool,
    pub response_delay_ms: u64,
    pub custom_response: Option<String>,
    pub protocol: nettrap_core::prelude::Protocol,
}

impl ListenerConfig {
    pub fn new(name: impl Into<String>, port: u16) -> Self {
        Self {
            name: name.into(),
            port,
            bind_address: "0.0.0.0".to_string(),
            enabled: true,
            emulate_response: true,
            response_delay_ms: 0,
            custom_response: None,
            protocol: if port == 53 {
                nettrap_core::prelude::Protocol::Udp
            } else {
                nettrap_core::prelude::Protocol::Tcp
            },
        }
    }

    pub fn dns() -> Self {
        let mut config = Self::new("dns", 53);
        config.protocol = nettrap_core::prelude::Protocol::Udp;
        config
    }

    pub fn http() -> Self {
        let mut config = Self::new("http", 80);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config
    }

    pub fn https() -> Self {
        let mut config = Self::new("https", 443);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config
    }

    pub fn with_bind_address(mut self, addr: impl Into<String>) -> Self {
        self.bind_address = addr.into();
        self
    }

    pub fn with_response_delay(mut self, delay_ms: u64) -> Self {
        self.response_delay_ms = delay_ms;
        self
    }

    pub fn with_custom_response(mut self, response: impl Into<String>) -> Self {
        self.custom_response = Some(response.into());
        self
    }

    pub fn with_protocol(mut self, protocol: nettrap_core::prelude::Protocol) -> Self {
        self.protocol = protocol;
        self
    }
}
