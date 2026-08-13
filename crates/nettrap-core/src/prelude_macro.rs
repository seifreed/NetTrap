export macro_rules! prelude {
    () => {
        pub use nettrap_core::prelude::*;
        pub use nettrap_core::error::{Error, Result};
    };
}