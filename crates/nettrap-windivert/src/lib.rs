//! WinDivert-based packet interception for NetTrap on Windows.
//!
//! This crate provides a WinDivert interceptor for capturing and modifying
//! network packets on Windows systems.

#[cfg(windows)]
mod bindings;
#[cfg(windows)]
mod dll;

#[cfg(windows)]
pub use bindings::HANDLE;
#[cfg(windows)]
pub use bindings::WinDivert;
#[cfg(windows)]
pub use bindings::{
    IPPROTO_TCP, IPPROTO_UDP, WINDIVERT_DIRECTION_IN, WINDIVERT_DIRECTION_OUT,
    WINDIVERT_LAYER_NETWORK, WindivertAddress, WindivertIpHdr, WindivertIpv6Hdr, WindivertTcpHdr,
    WindivertUdpHdr, close_handle,
};
#[cfg(windows)]
pub use dll::windivert_dll::{find_windivert_dll, get_driver_name};

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use async_trait::async_trait;
    pub use nettrap_core::prelude::*;
}
