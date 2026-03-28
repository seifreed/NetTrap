pub use crate::cli::*;
pub use crate::config::*;
pub use crate::engine::*;
pub use crate::Error;
pub use clap::Parser;
pub use nettrap_core::prelude::*;

#[macro_export]
macro_rules! prelude {
    () => {
        pub use crate::cli::*;
        pub use crate::config::*;
        pub use crate::engine::*;
        pub use crate::Error;
        pub use clap::Parser;
        pub use nettrap_core::prelude::*;
    };
}
