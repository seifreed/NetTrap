pub mod request;
pub mod response;
pub mod server;

/// Standalone HTTP request parser (uses Vec headers, `path` field).
/// For the trait-based handler system, use `HttpRequest` from `server` module instead.
pub use request::HttpRequest as HttpRequestParsed;
pub use response::{StaticResponse, not_found_response, ok_response};
pub use server::{HttpHandlerTrait, HttpRequest, HttpResponse, HttpServer};

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use crate::server::{HttpHandlerTrait, HttpRequest, HttpResponse, HttpServer};
    pub use async_trait::async_trait;
    pub use nettrap_core::error::{Error, Result};
    pub use nettrap_core::prelude::*;
}
