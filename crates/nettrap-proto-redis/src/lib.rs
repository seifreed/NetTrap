pub mod handler;
pub mod redis;

pub use handler::*;
pub use redis::*;

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use crate::handler::*;
    pub use crate::redis::*;
    pub use async_trait::async_trait;
    pub use nettrap_core::error::{Error, Result};
    pub use nettrap_core::prelude::*;
}
