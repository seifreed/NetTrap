use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::router::ProtocolRouter;

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
        self.router.route(data, dst_port)
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
        // Track UDP "sessions": (src_addr) -> forwarded_socket
        let forward_table: Arc<parking_lot::RwLock<std::collections::HashMap<String, Arc<UdpSocket>>>> =
            Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let data = buf[..len].to_vec();
                    let detected = router.route(&data, port);

                    if let Some((proto_name, _score)) = detected {
                        if let Some(&target_port) = listener_ports.get(&proto_name) {
                            let key = format!("{}:{}", src.ip(), src.port());
                            let fwd_table = Arc::clone(&forward_table);
                            let client_socket = Arc::clone(&socket);

                            // Get or create forwarding socket
                            let fwd_socket = {
                                let table = fwd_table.read();
                                table.get(&key).cloned()
                            };

                            let fwd_socket = match fwd_socket {
                                Some(s) => s,
                                None => {
                                    let s = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
                                    s.connect(format!("127.0.0.1:{}", target_port)).await.unwrap();
                                    fwd_table.write().insert(key.clone(), Arc::clone(&s));

                                    // Spawn reverse forwarder
                                    let s_clone = Arc::clone(&s);
                                    let client_clone = Arc::clone(&client_socket);
                                    tokio::spawn(async move {
                                        let mut rbuf = vec![0u8; 65535];
                                        loop {
                                            match s_clone.recv(&mut rbuf).await {
                                                Ok(n) => {
                                                    let _ = client_clone.send_to(&rbuf[..n], src).await;
                                                }
                                                Err(_) => break,
                                            }
                                        }
                                    });

                                    s
                                }
                            };

                            let _ = fwd_socket.send(&data).await;
                        }
                    }
                }
                Err(e) => tracing::warn!("UDP proxy recv error: {}", e),
            }
        }
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
    let detected = router.route(&sample[..n], dst_port);

    let (proto_name, score) = match detected {
        Some(d) => d,
        None => {
            tracing::debug!("Proxy: no protocol detected from {}", peer);
            return Ok(());
        }
    };

    let target_port = match listener_ports.get(&proto_name) {
        Some(&p) => p,
        None => {
            tracing::debug!("Proxy: no listener port for {} from {}", proto_name, peer);
            return Ok(());
        }
    };

    tracing::debug!(
        "Proxy: routing {} -> {} (score={}) to 127.0.0.1:{}",
        peer, proto_name, score, target_port
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
        let _ = server_write.shutdown().await;
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
        let _ = client_write.shutdown().await;
    });

    // Wait for both directions to complete
    let _ = tokio::join!(client_to_server, server_to_client);

    Ok(())
}
