//! WinDivert-based packet interception for NetTrap on Windows.
//!
//! This crate provides a WinDivert interceptor for capturing and modifying
//! network packets on Windows systems.

#[cfg(windows)]
mod bindings;
#[cfg(windows)]
mod dll;
#[cfg(windows)]
mod interceptor;

#[cfg(windows)]
pub use interceptor::WinDivertInterceptor;
#[cfg(windows)]
pub use dll::windivert_dll::{find_windivert_dll, get_driver_name};

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use nettrap_core::prelude::*;
    pub use async_trait::async_trait;
}