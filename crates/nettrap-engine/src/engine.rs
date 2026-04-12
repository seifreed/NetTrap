//! Core Engine trait and implementation.
//!
//! The Engine is the main orchestrator for NetTrap, following the Use Case
//! pattern from Clean Architecture. It:
//!
//! 1. Creates startup context (TLS CA, router, PCAP, etc.)
//! 2. Spawns listeners (TCP/UDP)
//! 3. Optionally spawns interceptors
//! 4. Waits for shutdown signal
//! 5. Executes cleanup (reports, close resources)

use std::path::PathBuf;

use async_trait::async_trait;

use crate::Result;

/// Core Engine trait following Clean Architecture.
///
/// This trait defines the interface for the main orchestrator,
/// allowing different implementations:
///
/// - `FullEngine`: Production implementation with all features
/// - `MockEngine`: Testing implementation with mock resources
/// - `MinimalEngine`: Lightweight implementation for testing
#[async_trait]
pub trait Engine: Send + Sync {
    /// Start the engine and run until shutdown signal.
    ///
    /// This method:
    /// 1. Initializes resources (TLS CA, router, etc.)
    /// 2. Spawns listener tasks
    /// 3. Optionally spawns packet interceptor
    /// 4. Waits for Ctrl+C or stop flag
    /// 5. Cleans up resources
    async fn run(&self, stop_flag: Option<PathBuf>) -> Result<()>;

    /// Get the engine configuration.
    fn config(&self) -> &dyn crate::EngineConfigTrait;

    /// Check if interception is enabled.
    fn is_intercept_enabled(&self) -> bool;

    /// Get the network interface name.
    fn interface(&self) -> Option<&str>;

    /// Get the output path override.
    fn output_override(&self) -> Option<&PathBuf>;
}

/// Engine state enum for lifecycle management.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    /// Engine created but not started
    Created,
    /// Engine is initializing resources
    Initializing,
    /// Engine is running listeners
    Running,
    /// Engine is shutting down
    ShuttingDown,
    /// Engine has stopped
    Stopped,
    /// Engine encountered an error
    Error,
}

impl Default for EngineState {
    fn default() -> Self {
        Self::Created
    }
}

/// Configuration for engine behavior.
#[derive(Debug, Clone)]
pub struct EngineOptions {
    /// Enable packet interception
    pub intercept_enabled: bool,
    /// Network interface to use
    pub interface: Option<String>,
    /// Output file path override
    pub output_override: Option<PathBuf>,
    /// Attribution enabled
    pub attribution_enabled: bool,
    /// PCAP capture enabled
    pub pcap_enabled: bool,
    /// Verbose logging
    pub verbose: bool,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            intercept_enabled: false,
            interface: None,
            output_override: None,
            attribution_enabled: false,
            pcap_enabled: false,
            verbose: false,
        }
    }
}
