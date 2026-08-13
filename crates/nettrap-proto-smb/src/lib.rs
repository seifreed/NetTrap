pub mod handler;

pub use handler::*;

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use crate::handler::*;
    pub use async_trait::async_trait;
    pub use nettrap_core::error::{Error, Result};
    pub use nettrap_core::prelude::*;
}
