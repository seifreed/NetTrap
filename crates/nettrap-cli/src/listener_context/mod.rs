//! Listener context module with composition-based architecture.
//!
//! This module provides:
//! - `ListenerContext`: Primary configuration and state container
//! - `ListenerContextBuilder`: Fluent builder for constructing contexts
//!
//! # Example
//!
//! ```ignore
//! let ctx = ListenerContext::builder()
//!     .name("dns")
//!     .port(53)
//!     .build(security, runtime);
//! ```

mod builder;
mod context;

pub use builder::ListenerContextBuilder;
pub use context::ListenerContext;
