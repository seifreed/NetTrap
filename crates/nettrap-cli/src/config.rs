
pub mod engine;
pub mod listener;

pub use engine::*;
pub use listener::*;

pub fn default_dns_config() -> ListenerConfig {
    ListenerConfig::dns()
}

pub fn default_http_config() -> ListenerConfig {
    ListenerConfig::http()
}

pub fn default_https_config() -> ListenerConfig {
    ListenerConfig::https()
}

pub fn default_smtp_config() -> ListenerConfig {
    ListenerConfig::smtp()
}

pub fn default_ftp_config() -> ListenerConfig {
    ListenerConfig::ftp()
}

pub fn default_pop3_config() -> ListenerConfig {
    ListenerConfig::pop3()
}

pub fn default_irc_config() -> ListenerConfig {
    ListenerConfig::irc()
}

pub fn default_tftp_config() -> ListenerConfig {
    ListenerConfig::tftp()
}
