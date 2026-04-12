pub mod proxy;
pub mod router;
pub mod taste;

pub use proxy::*;
pub use router::*;
pub use taste::*;

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use crate::proxy::*;
    pub use crate::router::*;
    pub use crate::taste::*;
    pub use async_trait::async_trait;
    pub use nettrap_core::error::{Error, Result};
    pub use nettrap_core::prelude::*;
}
