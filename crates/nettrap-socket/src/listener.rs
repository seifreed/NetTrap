use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::net::{TcpListener, UdpSocket};

use crate::prelude::*;

#[async_trait]
pub trait ListenerTrait: Send + Sync {
    fn name(&self) -> &'static str;
    fn port(&self) -> u16;
    fn protocol(&self) -> Protocol;
    fn binds_to(&self) -> std::net::IpAddr;
    
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    fn is_running(&self) -> bool;
}

pub struct TcpListenerWrapper {
    config: ListenerConfig,
    listener: RwLock<Option<TcpListener>>,
    running: RwLock<bool>,
}

impl TcpListenerWrapper {
    pub fn new(config: ListenerConfig) -> Self {
        Self {
            config,
            listener: RwLock::new(None),
            running: RwLock::new(false),
        }
    }
}

#[async_trait]
impl ListenerTrait for TcpListenerWrapper {
    fn name(&self) -> &'static str {
        Box::leak(self.config.name.clone().into_boxed_str())
    }
    
    fn port(&self) -> u16 {
        self.config.port
    }
    
    fn protocol(&self) -> Protocol {
        self.config.protocol.clone()
    }
    
    fn binds_to(&self) -> std::net::IpAddr {
        self.config.bind_address
    }
    
    async fn start(&self) -> Result<()> {
        let addr = std::net::SocketAddr::new(self.config.bind_address, self.config.port);
        let listener = TcpListener::bind(addr).await?;
        *self.listener.write() = Some(listener);
        *self.running.write() = true;
        tracing::info!("TCP listener {} started on port {}", self.config.name, self.config.port);
        Ok(())
    }
    
    async fn stop(&self) -> Result<()> {
        *self.listener.write() = None;
        *self.running.write() = false;
        tracing::info!("TCP listener {} stopped", self.config.name);
        Ok(())
    }
    
    fn is_running(&self) -> bool {
        *self.running.read()
    }
}

pub struct UdpListenerWrapper {
    config: ListenerConfig,
    socket: RwLock<Option<UdpSocket>>,
    running: RwLock<bool>,
}

impl UdpListenerWrapper {
    pub fn new(config: ListenerConfig) -> Self {
        Self {
            config,
            socket: RwLock::new(None),
            running: RwLock::new(false),
        }
    }
}

#[async_trait]
impl ListenerTrait for UdpListenerWrapper {
    fn name(&self) -> &'static str {
        Box::leak(self.config.name.clone().into_boxed_str())
    }
    
    fn port(&self) -> u16 {
        self.config.port
    }
    
    fn protocol(&self) -> Protocol {
        self.config.protocol.clone()
    }
    
    fn binds_to(&self) -> std::net::IpAddr {
        self.config.bind_address
    }
    
    async fn start(&self) -> Result<()> {
        let addr = std::net::SocketAddr::new(self.config.bind_address, self.config.port);
        let socket = UdpSocket::bind(addr).await?;
        *self.socket.write() = Some(socket);
        *self.running.write() = true;
        tracing::info!("UDP listener {} started on port {}", self.config.name, self.config.port);
        Ok(())
    }
    
    async fn stop(&self) -> Result<()> {
        *self.socket.write() = None;
        *self.running.write() = false;
        tracing::info!("UDP listener {} stopped", self.config.name);
        Ok(())
    }
    
    fn is_running(&self) -> bool {
        *self.running.read()
    }
}

#[derive(Debug, Clone)]
pub struct ListenerConfig {
    pub name: String,
    pub port: u16,
    pub protocol: Protocol,
    pub bind_address: std::net::IpAddr,
    pub enabled: bool,
}

impl ListenerConfig {
    pub fn new(name: impl Into<String>, port: u16, protocol: Protocol) -> Self {
        Self {
            name: name.into(),
            port,
            protocol,
            bind_address: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            enabled: true,
        }
    }
    
    pub fn dns() -> Self {
        Self::new("dns", 53, Protocol::Udp)
    }
    
    pub fn http() -> Self {
        Self::new("http", 80, Protocol::Tcp)
    }
    
    pub fn https() -> Self {
        Self::new("https", 443, Protocol::Tcp)
    }
    
    pub fn with_bind_address(mut self, addr: impl Into<String>) -> Self {
        if let Ok(ip) = addr.into().parse() {
            self.bind_address = ip;
        }
        self
    }
    
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}