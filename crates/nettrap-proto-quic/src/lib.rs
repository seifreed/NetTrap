pub mod quic;

pub use quic::*;

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use crate::quic::*;
    pub use nettrap_core::error::{Error, Result};
    pub use nettrap_core::prelude::*;
}
