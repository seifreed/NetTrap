pub mod server;
pub mod request;
pub mod response;

pub use server::{HttpServer, HttpRequest, HttpResponse, HttpHandlerTrait};
pub use request::HttpRequest as HttpRequest2;
pub use response::{ok_response, not_found_response, StaticResponse};

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use crate::server::{HttpServer, HttpRequest, HttpResponse, HttpHandlerTrait};
    pub use nettrap_core::prelude::*;
    pub use nettrap_core::error::{Error, Result};
    pub use async_trait::async_trait;
}