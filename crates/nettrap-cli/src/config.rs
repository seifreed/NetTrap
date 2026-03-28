
pub mod engine;
pub mod listener;

pub use engine::*;
pub use listener::*;

pub fn default_dns_config() -> ListenerConfig {
    ListenerConfig {
        name: "dns".to_string(),
        port: 53,
        bind_address: "0.0.0.0".to_string(),
        enabled: true,
        emulate_response: true,
        response_delay_ms: 0,
        custom_response: None,
        protocol: nettrap_core::prelude::Protocol::Udp,
    }
}

pub fn default_http_config() -> ListenerConfig {
    ListenerConfig {
        name: "http".to_string(),
        port: 80,
        bind_address: "0.0.0.0".to_string(),
        enabled: true,
        emulate_response: true,
        response_delay_ms: 0,
        custom_response: None,
        protocol: nettrap_core::prelude::Protocol::Tcp,
    }
}

pub fn default_https_config() -> ListenerConfig {
    ListenerConfig {
        name: "https".to_string(),
        port: 443,
        bind_address: "0.0.0.0".to_string(),
        enabled: true,
        emulate_response: true,
        response_delay_ms: 0,
        custom_response: None,
        protocol: nettrap_core::prelude::Protocol::Tcp,
    }
}
