pub mod tui;

pub use tui::*;

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use crate::tui::*;
    pub use nettrap_core::prelude::*;
}
