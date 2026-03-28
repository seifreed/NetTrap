pub mod listener;
pub mod registry;

pub use listener::*;
pub use registry::*;

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use nettrap_core::prelude::*;
    pub use nettrap_core::error::{Error, Result};
    pub use async_trait::async_trait;
    pub use crate::listener::{ListenerTrait, ListenerConfig, TcpListenerWrapper, UdpListenerWrapper};
    pub use crate::registry::ListenerRegistry;
}