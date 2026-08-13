pub mod ftp;

pub use ftp::*;

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use crate::ftp::*;
    pub use nettrap_core::error::{Error, Result};
    pub use nettrap_core::prelude::*;
}
