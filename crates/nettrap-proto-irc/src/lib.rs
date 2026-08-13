pub mod handler;
pub mod irc;

pub use handler::*;
pub use irc::*;

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use crate::handler::*;
    pub use crate::irc::*;
    pub use async_trait::async_trait;
    pub use nettrap_core::error::{Error, Result};
    pub use nettrap_core::prelude::*;
}
