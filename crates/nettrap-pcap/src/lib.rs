pub mod pcap;
pub mod writer;

pub use pcap::*;
pub use writer::*;

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use crate::pcap::*;
    pub use crate::writer::*;
    pub use nettrap_core::error::{Error, Result};
    pub use nettrap_core::prelude::*;
}
