//! NetTrap Core Engine
//!
//! This crate contains the business logic for NetTrap, following Clean Architecture
//! principles. It defines:
//!
//! - **Traits** (interfaces) for dependency injection
//! - **Use Cases** (Engine) orchestration
//! - **Entities** (StartupContext, ShutdownContext)
//!
//! ## Architecture
//!
//! The Engine sits at the center, depending on abstractions (traits):
//!
//! ```text
//! CLI (nettrap-cli)
//!     |
//!     v
//! Engine (Use Case Layer)
//!     |-- ConfigRepo (trait)
//!     |-- ListenerSpawner (trait)
//!     |-- InterceptorSpawner (trait)
//!     |
//!     v
//! Infrastructure (nettrap-*)
//!     |-- nettrap-proxy
//!     |-- nettrap-pcap
//!     |-- nettrap-tls-mitm
//! ```
//!
//! ## Testing
//!
//! The Engine can be tested with mock implementations:
//!
//! ```ignore
//! struct MockListenerSpawner;
//! impl ListenerSpawner for MockListenerSpawner {
//!     fn spawn(&self, _: &ListenerConfig) -> JoinHandle<()> { ... }
//! }
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;

pub mod engine;
pub mod shutdown;
pub mod startup;

pub use engine::*;
pub use shutdown::ShutdownContext;
pub use startup::StartupContext;

// ═══════════════════════════════════════════════════════════════════════
// TRAITS FOR DEPENDENCY INJECTION (Clean Architecture Interfaces)
// ═══════════════════════════════════════════════════════════════════════

/// Listener configuration trait.
///
/// Abstracts listener configuration for testing.
pub trait ListenerConfigTrait: Send + Sync {
    fn name(&self) -> &str;
    fn port(&self) -> u16;
    fn protocol(&self) -> nettrap_core::prelude::Protocol;
    fn is_enabled(&self) -> bool;
    fn is_hidden(&self) -> bool;
    fn use_ssl(&self) -> bool;
}

/// Trait for spawning listener tasks.
///
/// Allows mocking listeners in tests.
#[async_trait]
pub trait ListenerSpawner: Send + Sync {
    /// Spawn a TCP listener task.
    async fn spawn_tcp(
        &self,
        config: Arc<dyn ListenerConfigTrait>,
        bind_addr: std::net::IpAddr,
        output_path: Option<PathBuf>,
    ) -> tokio::task::JoinHandle<()>;

    /// Spawn a UDP listener task.
    async fn spawn_udp(
        &self,
        config: Arc<dyn ListenerConfigTrait>,
        bind_addr: std::net::IpAddr,
        output_path: Option<PathBuf>,
    ) -> tokio::task::JoinHandle<()>;
}

/// Trait for spawning interceptors.
///
/// Allows mocking interceptors in tests.
pub trait InterceptorSpawner: Send + Sync {
    /// Spawn an interceptor task if enabled.
    fn spawn(
        &self,
        interface: Option<String>,
        output_path: Option<PathBuf>,
    ) -> Option<tokio::task::JoinHandle<()>>;
}

/// Trait for engine configuration.
///
/// Abstracts configuration access for testing.
pub trait EngineConfigTrait: Send + Sync {
    fn has_attribution(&self) -> bool;
    fn pcap_enabled(&self) -> bool;
    fn output_path(&self) -> Option<&str>;
}

/// Trait for shutdown handlers.
///
/// Allows customizing shutdown behavior.
#[async_trait]
pub trait ShutdownHandler: Send + Sync {
    /// Execute shutdown logic.
    async fn shutdown(&self, ctx: &ShutdownContext);
}

/// Trait for startup handlers.
///
/// Allows customizing startup behavior.
pub trait StartupHandler: Send + Sync {
    /// Called after startup context is created.
    fn on_startup(&self, ctx: &StartupContext);
}

// ═══════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ═══════════════════════════════════════════════════════════════════════

/// Engine error type.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Startup error: {0}")]
    Startup(String),

    #[error("Shutdown error: {0}")]
    Shutdown(String),

    #[error("Listener error: {0}")]
    Listener(String),

    #[error("Interceptor error: {0}")]
    Interceptor(String),
}

pub type Result<T> = std::result::Result<T, EngineError>;
