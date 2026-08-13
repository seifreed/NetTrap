use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::{AbortHandle, JoinSet};

use crate::router::ProtocolRouter;

const UDP_FORWARD_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const UDP_FORWARD_SESSION_TTL: Duration = Duration::from_secs(120);
const MAX_UDP_FORWARD_SESSIONS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UdpForwardKey {
    src: std::net::SocketAddr,
    protocol_name: String,
    target_port: u16,
}

type UdpForwardTable =
    Arc<parking_lot::RwLock<std::collections::HashMap<UdpForwardKey, UdpForwardEntry>>>;

struct UdpForwardCleanup(UdpForwardTable);

impl Drop for UdpForwardCleanup {
    fn drop(&mut self) {
        let mut table = self.0.write();
        for entry in table.drain().map(|(_, entry)| entry) {
            entry.reverse_task.abort();
        }
    }
}

struct UdpForwardEntry {
    socket: Arc<UdpSocket>,
    last_activity: Instant,
    reverse_task: AbortHandle,
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

fn evict_stale_udp_forward_entries(
    table: &mut std::collections::HashMap<UdpForwardKey, UdpForwardEntry>,
    max_age: Duration,
) -> usize {
    let stale_keys: Vec<UdpForwardKey> = table
        .iter()
        .filter(|(_, entry)| entry.last_activity.elapsed() >= max_age)
        .map(|(key, _)| key.clone())
        .collect();

    let removed = stale_keys.len();
    for key in stale_keys {
        if let Some(entry) = table.remove(&key) {
            entry.reverse_task.abort();
        }
    }
    removed
}

fn enforce_udp_forward_capacity(
    table: &mut std::collections::HashMap<UdpForwardKey, UdpForwardEntry>,
    max_sessions: usize,
) -> usize {
    if max_sessions == 0 {
        return 0;
    }

    let mut evicted = 0;
    while table.len() >= max_sessions {
        let Some(oldest_key) = table
            .iter()
            .min_by_key(|(_, entry)| entry.last_activity)
            .map(|(key, _)| key.clone())
        else {
            break;
        };

        if let Some(entry) = table.remove(&oldest_key) {
            entry.reverse_task.abort();
            evicted += 1;
        }
    }
    evicted
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
        let mut connection_tasks = JoinSet::new();

        tracing::info!("TCP proxy listening on {}", addr);

        loop {
            while let Some(result) = connection_tasks.try_join_next() {
                if let Err(err) = result
                    && !err.is_cancelled()
                {
                    tracing::warn!("TCP proxy connection task failed: {}", err);
                }
            }

            let (client_stream, peer) = listener.accept().await?;
            let router = Arc::clone(&router);
            let ports = listener_ports.clone();

            connection_tasks.spawn(async move {
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
        let forward_table: UdpForwardTable =
            Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));
        let _forward_cleanup = UdpForwardCleanup(Arc::clone(&forward_table));
        let mut cleanup_interval = tokio::time::interval(UDP_FORWARD_CLEANUP_INTERVAL);

        loop {
            tokio::select! {
                _ = cleanup_interval.tick() => {
                    let mut table = forward_table.write();
                    let evicted = evict_stale_udp_forward_entries(&mut table, UDP_FORWARD_SESSION_TTL);
                    if evicted > 0 {
                        tracing::debug!("UDP proxy: evicted {} stale sessions", evicted);
                    }
                }
                result = socket.recv_from(&mut buf) => match result {
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
                            if let Some(entry) = table.get_mut(&key) {
                                entry.last_activity = Instant::now();
                                Some(Arc::clone(&entry.socket))
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

                                let s_clone = Arc::clone(&s);
                                let client_clone = Arc::clone(&client_socket);
                                let reverse_task = tokio::spawn(async move {
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
                                let reverse_task = reverse_task.abort_handle();

                                let mut table = fwd_table.write();
                                let evicted = enforce_udp_forward_capacity(
                                    &mut table,
                                    MAX_UDP_FORWARD_SESSIONS,
                                );
                                if evicted > 0 {
                                    tracing::warn!(
                                        "UDP proxy: evicted {} oldest sessions at capacity {}",
                                        evicted,
                                        MAX_UDP_FORWARD_SESSIONS
                                    );
                                }
                                table.insert(
                                    key.clone(),
                                    UdpForwardEntry {
                                        socket: Arc::clone(&s),
                                        last_activity: Instant::now(),
                                        reverse_task,
                                    },
                                );

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
}

/// Handle a single proxied TCP connection with full-duplex forwarding
async fn handle_proxy_connection(
    client: TcpStream,
    peer: std::net::SocketAddr,
    router: Arc<ProtocolRouter>,
    listener_ports: std::collections::HashMap<String, u16>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    let server = TcpStream::connect(format!("127.0.0.1:{}", target_port)).await?;

    let (client_read, client_write) = client.into_split();
    let (server_read, server_write) = server.into_split();

    let client_to_server =
        tokio::spawn(
            async move { forward_tcp_direction(client_read, server_write, "server").await },
        );

    let server_to_client =
        tokio::spawn(
            async move { forward_tcp_direction(server_read, client_write, "client").await },
        );

    await_proxy_tasks(client_to_server, server_to_client).await
}

async fn forward_tcp_direction<R, W>(
    mut reader: R,
    mut writer: W,
    writer_label: &'static str,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8192];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).await?;
    }
    writer.shutdown().await.map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("TCP proxy {writer_label} shutdown error: {err}"),
        )
    })
}

async fn await_proxy_tasks(
    mut client_to_server: tokio::task::JoinHandle<io::Result<()>>,
    mut server_to_client: tokio::task::JoinHandle<io::Result<()>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::select! {
        client_result = &mut client_to_server => {
            let client_result = surface_proxy_task_result("client-to-server", client_result);
            if let Err(err) = client_result {
                server_to_client.abort();
                let _ = server_to_client.await;
                return Err(err);
            }

            let server_result = server_to_client.await;
            surface_proxy_task_result("server-to-client", server_result)
        }
        server_result = &mut server_to_client => {
            let server_result = surface_proxy_task_result("server-to-client", server_result);
            if let Err(err) = server_result {
                client_to_server.abort();
                let _ = client_to_server.await;
                return Err(err);
            }

            let client_result = client_to_server.await;
            surface_proxy_task_result("client-to-server", client_result)
        }
    }
}

fn surface_proxy_task_result(
    direction: &str,
    result: std::result::Result<io::Result<()>, tokio::task::JoinError>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(Box::new(io::Error::new(
            err.kind(),
            format!("TCP proxy {direction} copy failed: {err}"),
        ))),
        Err(err) => Err(Box::new(io::Error::other(format!(
            "TCP proxy {direction} task failed: {err}"
        )))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pending_udp_forward_entry(
        last_activity: Instant,
    ) -> (UdpForwardEntry, tokio::task::JoinHandle<()>) {
        let socket = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind test UDP socket"),
        );
        let reverse_task = tokio::spawn(std::future::pending::<()>());
        let reverse_abort = reverse_task.abort_handle();

        (
            UdpForwardEntry {
                socket,
                last_activity,
                reverse_task: reverse_abort,
            },
            reverse_task,
        )
    }

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

    #[tokio::test]
    async fn await_proxy_tasks_surfaces_panics_from_worker_tasks() {
        let ok_task = tokio::spawn(async { Ok::<(), io::Error>(()) });
        let panic_task: tokio::task::JoinHandle<io::Result<()>> = tokio::spawn(async {
            panic!("proxy worker panic");
        });

        let err = await_proxy_tasks(panic_task, ok_task)
            .await
            .expect_err("task panic should be surfaced");

        assert!(err.to_string().contains("proxy worker panic"));
    }

    #[tokio::test]
    async fn await_proxy_tasks_surfaces_copy_errors_from_worker_tasks() {
        let ok_task = tokio::spawn(async { Ok::<(), io::Error>(()) });
        let error_task = tokio::spawn(async {
            Err::<(), io::Error>(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "relay write failed",
            ))
        });

        let err = await_proxy_tasks(error_task, ok_task)
            .await
            .expect_err("copy error should be surfaced");

        assert!(err.to_string().contains("client-to-server"));
        assert!(err.to_string().contains("relay write failed"));
    }

    #[tokio::test]
    async fn await_proxy_tasks_aborts_pending_peer_when_other_direction_errors() {
        let pending_task = tokio::spawn(std::future::pending::<io::Result<()>>());
        let error_task = tokio::spawn(async {
            Err::<(), io::Error>(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "peer connection reset",
            ))
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            await_proxy_tasks(error_task, pending_task),
        )
        .await
        .expect("proxy task aggregation should not hang");

        let err = result.expect_err("copy error should be surfaced");
        assert!(err.to_string().contains("peer connection reset"));
    }

    #[test]
    fn resolve_listener_port_errors_when_handler_has_no_port_mapping() {
        let peer = "127.0.0.1:53000".parse().expect("valid socket address");
        let listener_ports = std::collections::HashMap::new();

        let err = resolve_listener_port(&listener_ports, "http", peer, "TCP")
            .expect_err("missing mapping should fail");

        assert!(err.to_string().contains("http"));
    }

    #[tokio::test]
    async fn stale_udp_forward_cleanup_aborts_reverse_task() {
        let key = UdpForwardKey::new(
            "127.0.0.1:53000".parse().expect("valid socket address"),
            "dns",
            53,
        );
        let stale_at = Instant::now() - (UDP_FORWARD_SESSION_TTL + Duration::from_secs(1));
        let (entry, reverse_task) = pending_udp_forward_entry(stale_at).await;
        let mut table = std::collections::HashMap::new();
        table.insert(key, entry);

        assert_eq!(
            evict_stale_udp_forward_entries(&mut table, UDP_FORWARD_SESSION_TTL),
            1
        );
        assert!(table.is_empty());

        let err = reverse_task
            .await
            .expect_err("cleanup should abort reverse task");
        assert!(err.is_cancelled());
    }

    #[tokio::test]
    async fn udp_forward_capacity_aborts_oldest_reverse_task() {
        let old_key = UdpForwardKey::new(
            "127.0.0.1:53000".parse().expect("valid socket address"),
            "dns",
            53,
        );
        let fresh_key = UdpForwardKey::new(
            "127.0.0.1:53001".parse().expect("valid socket address"),
            "dns",
            53,
        );
        let (old_entry, old_reverse_task) =
            pending_udp_forward_entry(Instant::now() - Duration::from_secs(10)).await;
        let (fresh_entry, fresh_reverse_task) = pending_udp_forward_entry(Instant::now()).await;
        let mut table = std::collections::HashMap::new();
        table.insert(old_key.clone(), old_entry);
        table.insert(fresh_key.clone(), fresh_entry);

        assert_eq!(enforce_udp_forward_capacity(&mut table, 2), 1);
        assert!(!table.contains_key(&old_key));
        assert!(table.contains_key(&fresh_key));

        let err = old_reverse_task
            .await
            .expect_err("capacity eviction should abort oldest reverse task");
        assert!(err.is_cancelled());

        fresh_reverse_task.abort();
        let _ = fresh_reverse_task.await;
    }
}
