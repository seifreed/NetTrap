use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::router::ProtocolRouter;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UdpForwardKey {
    src: std::net::SocketAddr,
    protocol_name: String,
    target_port: u16,
}

impl UdpForwardKey {
    fn new(src: std::net::SocketAddr, protocol_name: impl Into<String>, target_port: u16) -> Self {
        Self {
            src,
            protocol_name: protocol_name.into(),
            target_port,
        }
    }
}

fn resolve_listener_port(
    listener_ports: &std::collections::HashMap<String, u16>,
    protocol_name: &str,
    peer: std::net::SocketAddr,
    transport: &str,
) -> std::io::Result<u16> {
    listener_ports.get(protocol_name).copied().ok_or_else(|| {
        std::io::Error::other(format!(
            "Proxy {} routing misconfiguration: handler '{}' has no listener port for {}",
            transport, protocol_name, peer
        ))
    })
}

/// ProxyListener intercepts connections on unbound ports and routes them
/// to the best matching handler based on content analysis.
pub struct ProxyListener {
    router: Arc<ProtocolRouter>,
    bind_address: String,
}

impl ProxyListener {
    pub fn new(router: Arc<ProtocolRouter>) -> Self {
        Self {
            router,
            bind_address: "0.0.0.0".to_string(),
        }
    }

    pub fn with_bind_address(mut self, addr: impl Into<String>) -> Self {
        self.bind_address = addr.into();
        self
    }

    /// Sample data from a TCP connection to determine protocol
    pub fn detect_protocol(&self, data: &[u8], dst_port: u16) -> Option<(String, u8)> {
        self.router.route_tcp(data, dst_port)
    }

    /// Start a TCP proxy on the given port that routes to internal listeners
    pub async fn start_tcp_proxy(
        &self,
        port: u16,
        listener_ports: std::collections::HashMap<String, u16>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = format!("{}:{}", self.bind_address, port);
        let listener = TcpListener::bind(&addr).await?;
        let router = Arc::clone(&self.router);

        tracing::info!("TCP proxy listening on {}", addr);

        loop {
            let (client_stream, peer) = listener.accept().await?;
            let router = Arc::clone(&router);
            let ports = listener_ports.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_proxy_connection(client_stream, peer, router, ports).await {
                    tracing::debug!("Proxy connection error from {}: {}", peer, e);
                }
            });
        }
    }

    /// Start a UDP proxy on the given port
    pub async fn start_udp_proxy(
        &self,
        port: u16,
        listener_ports: std::collections::HashMap<String, u16>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = format!("{}:{}", self.bind_address, port);
        let socket = Arc::new(UdpSocket::bind(&addr).await?);
        let router = Arc::clone(&self.router);

        tracing::info!("UDP proxy listening on {}", addr);

        let mut buf = vec![0u8; 65535];
        // Track UDP forwarding sockets per source and detected destination.
        let forward_table: Arc<
            parking_lot::RwLock<
                std::collections::HashMap<UdpForwardKey, (Arc<UdpSocket>, std::time::Instant)>,
            >,
        > = Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));

        // Spawn periodic cleanup of stale UDP sessions (every 60s, expire after 120s)
        {
            let cleanup_table = Arc::clone(&forward_table);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    let mut table = cleanup_table.write();
                    let before = table.len();
                    table.retain(|_, (_, last)| last.elapsed().as_secs() < 120);
                    let evicted = before - table.len();
                    if evicted > 0 {
                        tracing::debug!("UDP proxy: evicted {} stale sessions", evicted);
                    }
                }
            });
        }

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let data = buf[..len].to_vec();
                    let detected = router.route_udp(&data, port);

                    if let Some((proto_name, _score)) = detected {
                        let target_port =
                            match resolve_listener_port(&listener_ports, &proto_name, src, "UDP") {
                                Ok(port) => port,
                                Err(err) => {
                                    tracing::warn!("{}", err);
                                    continue;
                                }
                            };
                        let key = UdpForwardKey::new(src, proto_name.clone(), target_port);
                        let fwd_table = Arc::clone(&forward_table);
                        let client_socket = Arc::clone(&socket);

                        // Get or create forwarding socket
                        let fwd_socket = {
                            let mut table = fwd_table.write();
                            if let Some((sock, last)) = table.get_mut(&key) {
                                *last = std::time::Instant::now();
                                Some(Arc::clone(sock))
                            } else {
                                None
                            }
                        };

                        let fwd_socket = match fwd_socket {
                            Some(s) => s,
                            None => {
                                let s = match UdpSocket::bind("0.0.0.0:0").await {
                                    Ok(s) => Arc::new(s),
                                    Err(e) => {
                                        tracing::warn!("Failed to bind UDP forward socket: {}", e);
                                        continue;
                                    }
                                };
                                if let Err(e) =
                                    s.connect(format!("127.0.0.1:{}", target_port)).await
                                {
                                    tracing::warn!("Failed to connect UDP forward socket: {}", e);
                                    continue;
                                }
                                fwd_table.write().insert(
                                    key.clone(),
                                    (Arc::clone(&s), std::time::Instant::now()),
                                );

                                // Spawn reverse forwarder
                                let s_clone = Arc::clone(&s);
                                let client_clone = Arc::clone(&client_socket);
                                tokio::spawn(async move {
                                    let mut rbuf = vec![0u8; 65535];
                                    while let Ok(n) = s_clone.recv(&mut rbuf).await {
                                        if let Err(e) = client_clone.send_to(&rbuf[..n], src).await
                                        {
                                            tracing::debug!(
                                                "UDP proxy forward error to {}: {}",
                                                src,
                                                e
                                            );
                                        }
                                    }
                                });

                                s
                            }
                        };

                        if let Err(e) = fwd_socket.send(&data).await {
                            tracing::debug!("UDP proxy send error: {}", e);
                        }
                    }
                }
                Err(e) => tracing::warn!("UDP proxy recv error: {}", e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_forward_key_distinguishes_protocol_for_same_source() {
        let src = "127.0.0.1:53000".parse().expect("valid socket address");
        let dns = UdpForwardKey::new(src, "dns", 53);
        let snmp = UdpForwardKey::new(src, "snmp", 161);

        assert_ne!(dns, snmp);
    }

    #[test]
    fn udp_forward_key_distinguishes_target_port_for_same_source_and_protocol() {
        let src = "127.0.0.1:53000".parse().expect("valid socket address");
        let first = UdpForwardKey::new(src, "dns", 53);
        let second = UdpForwardKey::new(src, "dns", 5353);

        assert_ne!(first, second);
    }

    #[test]
    fn resolve_listener_port_errors_when_handler_has_no_port_mapping() {
        let peer = "127.0.0.1:53000".parse().expect("valid socket address");
        let listener_ports = std::collections::HashMap::new();

        let err = resolve_listener_port(&listener_ports, "http", peer, "TCP")
            .expect_err("missing mapping should fail");

        assert!(err.to_string().contains("http"));
    }
}

/// Handle a single proxied TCP connection with full-duplex forwarding
async fn handle_proxy_connection(
    client: TcpStream,
    peer: std::net::SocketAddr,
    router: Arc<ProtocolRouter>,
    listener_ports: std::collections::HashMap<String, u16>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read first bytes to detect protocol
    let mut sample = vec![0u8; 4096];
    let n = client.peek(&mut sample).await?;

    if n == 0 {
        return Ok(());
    }

    let dst_port = client.local_addr()?.port();
    let detected = router.route_tcp(&sample[..n], dst_port);

    let (proto_name, score) = match detected {
        Some(d) => d,
        None => {
            tracing::debug!("Proxy: no protocol detected from {}", peer);
            return Ok(());
        }
    };

    let target_port = resolve_listener_port(&listener_ports, &proto_name, peer, "TCP")?;

    tracing::debug!(
        "Proxy: routing {} -> {} (score={}) to 127.0.0.1:{}",
        peer,
        proto_name,
        score,
        target_port
    );

    // Connect to internal listener
    let server = TcpStream::connect(format!("127.0.0.1:{}", target_port)).await?;

    // Split both streams and forward bidirectionally
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();

    let client_to_server = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if server_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        if let Err(e) = server_write.shutdown().await {
            tracing::trace!("TCP proxy server shutdown error: {}", e);
        }
    });

    let server_to_client = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match server_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if client_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        if let Err(e) = client_write.shutdown().await {
            tracing::trace!("TCP proxy client shutdown error: {}", e);
        }
    });

    // Wait for both directions to complete
    let _ = tokio::join!(client_to_server, server_to_client);

    Ok(())
}
