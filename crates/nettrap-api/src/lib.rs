pub mod handlers;
pub mod server;

pub mod health {
    pub use nettrap_engine::health::*;
}

pub use handlers::*;
pub use health::*;
pub use server::*;

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use crate::handlers::*;
    pub use crate::health::*;
    pub use crate::server::*;
    pub use nettrap_core::prelude::*;
}

pub type Result<T> = std::result::Result<T, nettrap_core::Error>;
