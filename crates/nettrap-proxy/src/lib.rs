pub mod taste;
pub mod proxy;
pub mod router;

pub use taste::*;
pub use proxy::*;
pub use router::*;

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use crate::taste::*;
    pub use crate::proxy::*;
    pub use crate::router::*;
    pub use nettrap_core::prelude::*;
    pub use nettrap_core::error::{Error, Result};
    pub use async_trait::async_trait;
}
