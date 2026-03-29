//! Distributed deployment support for NetTrap.
//! All features are optional — standalone mode requires zero distributed config.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use parking_lot::RwLock;
use tokio::io::AsyncWriteExt;

use crate::config::DistributedConfig;

// ─── Node Identity ───────────────────────────────────────────────────────────

/// Unique identity for this NetTrap node in a distributed fleet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub node_id: String,
    pub hostname: String,
    pub region: String,
    pub tags: Vec<String>,
    pub started_at: String,
}

impl NodeIdentity {
    pub fn generate(region: Option<String>, tags: Vec<String>) -> Self {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        Self {
            node_id: uuid::Uuid::new_v4().to_string(),
            hostname,
            region: region.unwrap_or_else(|| "default".to_string()),
            tags,
            started_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// ─── Event Sink Trait ────────────────────────────────────────────────────────

/// Trait for shipping events to external systems
#[async_trait::async_trait]
pub trait EventSink: Send + Sync {
    async fn send(&self, event: &crate::nbi::NetworkBehaviorIndicator) -> Result<(), String>;
    async fn flush(&self) -> Result<(), String>;
    fn name(&self) -> &'static str;
}

// ─── Webhook/HTTP Sink ───────────────────────────────────────────────────────

/// Ships events to an HTTP endpoint (webhooks, Elasticsearch, Splunk HEC, etc.)
pub struct HttpSink {
    url: String,
    auth_header: Option<String>,
    batch: RwLock<Vec<String>>,
    batch_size: usize,
}

impl HttpSink {
    pub fn new(url: impl Into<String>, auth: Option<String>, batch_size: usize) -> Self {
        Self {
            url: url.into(),
            auth_header: auth,
            batch: RwLock::new(Vec::new()),
            batch_size: if batch_size == 0 { 100 } else { batch_size },
        }
    }

    async fn send_batch(&self, events: Vec<String>) -> Result<(), String> {
        let client = reqwest::Client::new();
        // Send each event individually for maximum compatibility
        // (ES _doc, Splunk HEC, generic webhooks all expect single objects)
        for event_json in &events {
            let mut req = client.post(&self.url)
                .header("Content-Type", "application/json")
                .body(event_json.clone());
            if let Some(ref auth) = self.auth_header {
                req = req.header("Authorization", auth.clone());
            }
            match req.send().await {
                Ok(resp) if !resp.status().is_success() => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    tracing::warn!("HTTP sink {} response: {} — {}", self.url, status, body.chars().take(200).collect::<String>());
                }
                Err(e) => {
                    tracing::warn!("HTTP sink send error: {}", e);
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl EventSink for HttpSink {
    async fn send(&self, event: &crate::nbi::NetworkBehaviorIndicator) -> Result<(), String> {
        let json = serde_json::to_string(event).map_err(|e| e.to_string())?;
        let should_flush = {
            let mut batch = self.batch.write();
            batch.push(json);
            batch.len() >= self.batch_size
        };
        if should_flush {
            self.flush().await?;
        }
        Ok(())
    }

    async fn flush(&self) -> Result<(), String> {
        let events: Vec<String> = {
            let mut batch = self.batch.write();
            std::mem::take(&mut *batch)
        };
        if !events.is_empty() {
            self.send_batch(events).await?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str { "http" }
}

// ─── TCP Socket Sink (for NATS/Kafka/Logstash/Fluentd) ──────────────────────

/// Ships events as newline-delimited JSON over a TCP socket.
/// Compatible with: Logstash tcp input, Fluentd, NATS, custom collectors.
pub struct TcpSink {
    addr: String,
    connection: tokio::sync::Mutex<Option<tokio::net::TcpStream>>,
}

impl TcpSink {
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            connection: tokio::sync::Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl EventSink for TcpSink {
    async fn send(&self, event: &crate::nbi::NetworkBehaviorIndicator) -> Result<(), String> {
        let json = serde_json::to_string(event).map_err(|e| e.to_string())?;
        let line = format!("{}\n", json);

        let mut conn = self.connection.lock().await;
        // Ensure connected
        if conn.is_none() {
            let stream = tokio::net::TcpStream::connect(&self.addr)
                .await
                .map_err(|e| format!("TCP sink connect error: {}", e))?;
            *conn = Some(stream);
        }
        if let Some(ref mut stream) = *conn {
            if stream.write_all(line.as_bytes()).await.is_err() {
                // Connection lost, drop it so next send reconnects
                *conn = None;
                return Err("TCP sink write failed, will reconnect".to_string());
            }
        }
        Ok(())
    }

    async fn flush(&self) -> Result<(), String> {
        let mut conn = self.connection.lock().await;
        if let Some(ref mut stream) = *conn {
            let _ = stream.flush().await;
        }
        Ok(())
    }

    fn name(&self) -> &'static str { "tcp" }
}

// ─── Syslog UDP Sink ─────────────────────────────────────────────────────────

/// Ships events as syslog-formatted UDP datagrams (RFC 5424)
pub struct SyslogUdpSink {
    addr: String,
    socket: tokio::sync::Mutex<Option<tokio::net::UdpSocket>>,
    facility: u8, // LOG_LOCAL0 = 16
}

impl SyslogUdpSink {
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            socket: tokio::sync::Mutex::new(None),
            facility: 16, // LOCAL0
        }
    }
}

#[async_trait::async_trait]
impl EventSink for SyslogUdpSink {
    async fn send(&self, event: &crate::nbi::NetworkBehaviorIndicator) -> Result<(), String> {
        let severity = 6u8; // INFO
        let priority = (self.facility * 8) + severity;
        let timestamp = &event.timestamp;
        let hostname = hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_default();
        let msg = serde_json::to_string(event).map_err(|e| e.to_string())?;
        let syslog_msg = format!("<{}>1 {} {} NetTrap - - - {}", priority, timestamp, hostname, msg);

        let mut sock = self.socket.lock().await;
        if sock.is_none() {
            let s = tokio::net::UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("Syslog UDP bind error: {}", e))?;
            s.connect(&self.addr)
                .await
                .map_err(|e| format!("Syslog UDP connect error: {}", e))?;
            *sock = Some(s);
        }
        if let Some(ref socket) = *sock {
            socket.send(syslog_msg.as_bytes()).await.map_err(|e| format!("Syslog send error: {}", e))?;
        }
        Ok(())
    }

    async fn flush(&self) -> Result<(), String> { Ok(()) }
    fn name(&self) -> &'static str { "syslog" }
}

// ─── Multi-Sink Fanout ───────────────────────────────────────────────────────

/// Sends events to multiple sinks simultaneously
pub struct EventFanout {
    sinks: Vec<Box<dyn EventSink>>,
}

impl EventFanout {
    pub fn new() -> Self {
        Self { sinks: Vec::new() }
    }

    pub fn add_sink(&mut self, sink: Box<dyn EventSink>) {
        tracing::info!("Event sink registered: {}", sink.name());
        self.sinks.push(sink);
    }

    pub fn has_sinks(&self) -> bool {
        !self.sinks.is_empty()
    }

    pub async fn send(&self, event: &crate::nbi::NetworkBehaviorIndicator) {
        for sink in &self.sinks {
            if let Err(e) = sink.send(event).await {
                tracing::warn!("Event sink '{}' error: {}", sink.name(), e);
            }
        }
    }

    pub async fn flush_all(&self) {
        for sink in &self.sinks {
            if let Err(e) = sink.flush().await {
                tracing::warn!("Event sink '{}' flush error: {}", sink.name(), e);
            }
        }
    }
}

// ─── Build Fanout from Config ────────────────────────────────────────────────

/// Build event fanout from config
pub fn build_event_fanout(config: &DistributedConfig) -> EventFanout {
    let mut fanout = EventFanout::new();

    for sink_cfg in &config.event_sinks {
        match sink_cfg.sink_type.as_str() {
            "http" | "webhook" | "elasticsearch" | "splunk" => {
                fanout.add_sink(Box::new(HttpSink::new(
                    &sink_cfg.target,
                    sink_cfg.auth.clone(),
                    sink_cfg.batch_size,
                )));
            }
            "tcp" | "nats" | "logstash" | "fluentd" => {
                fanout.add_sink(Box::new(TcpSink::new(&sink_cfg.target)));
            }
            "syslog" | "syslog_udp" => {
                fanout.add_sink(Box::new(SyslogUdpSink::new(&sink_cfg.target)));
            }
            other => {
                tracing::warn!("Unknown event sink type: {}", other);
            }
        }
    }

    fanout
}

// ─── Health Check Server ─────────────────────────────────────────────────────

/// Simple HTTP health check + metrics endpoint
pub async fn run_health_server(bind: String, node: Arc<NodeIdentity>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("Failed to bind health server on {}: {}", bind, e);
            return;
        }
    };

    tracing::info!("Health/metrics server on {}", bind);

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let node = Arc::clone(&node);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let request = String::from_utf8_lossy(&buf);

                let (status, body) = if request.contains("GET /health") {
                    ("200 OK", serde_json::json!({
                        "status": "healthy",
                        "node_id": node.node_id,
                        "hostname": node.hostname,
                        "region": node.region,
                        "uptime_since": node.started_at,
                    }).to_string())
                } else if request.contains("GET /metrics") {
                    // Prometheus-compatible metrics
                    let metrics = format!(
                        "# HELP nettrap_up Whether NetTrap is running\n\
                         # TYPE nettrap_up gauge\n\
                         nettrap_up 1\n\
                         # HELP nettrap_info Node information\n\
                         # TYPE nettrap_info gauge\n\
                         nettrap_info{{node_id=\"{}\",hostname=\"{}\",region=\"{}\"}} 1\n",
                        node.node_id, node.hostname, node.region
                    );
                    ("200 OK", metrics)
                } else if request.contains("GET /ready") {
                    ("200 OK", r#"{"ready": true}"#.to_string())
                } else {
                    ("404 Not Found", "Not Found".to_string())
                };

                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    status, body.len(), body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    }
}

// ─── Heartbeat ───────────────────────────────────────────────────────────────

/// Periodically sends heartbeat to control plane
pub async fn run_heartbeat(control_url: String, token: Option<String>, node: Arc<NodeIdentity>, interval_secs: u64) {
    if interval_secs == 0 { return; }

    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/heartbeat", control_url);

    loop {
        let payload = serde_json::json!({
            "node_id": node.node_id,
            "hostname": node.hostname,
            "region": node.region,
            "tags": node.tags,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let mut req = client.post(&url).json(&payload);
        if let Some(ref t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }

        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!("Heartbeat sent to control plane");
            }
            Ok(resp) => {
                tracing::warn!("Heartbeat rejected: {}", resp.status());
            }
            Err(e) => {
                tracing::warn!("Heartbeat failed: {}", e);
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
    }
}
