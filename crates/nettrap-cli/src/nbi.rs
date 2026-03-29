use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Network Behavior Indicator - structured per-protocol telemetry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBehaviorIndicator {
    pub timestamp: String,
    pub listener: String,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub indicators: HashMap<String, String>,
}

impl NetworkBehaviorIndicator {
    pub fn new(listener: &str, protocol: &str, src_ip: &str, src_port: u16, dst_port: u16) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            listener: listener.to_string(),
            protocol: protocol.to_string(),
            src_ip: src_ip.to_string(),
            src_port,
            dst_port,
            process_name: None,
            process_pid: None,
            indicators: HashMap::new(),
        }
    }

    pub fn with_process(mut self, name: Option<String>, pid: Option<u32>) -> Self {
        self.process_name = name;
        self.process_pid = pid;
        self
    }

    pub fn add(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.indicators.insert(key.into(), value.into());
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Build NBI for DNS query
pub fn dns_nbi(listener: &str, src_ip: &str, src_port: u16, dst_port: u16, domain: &str, query_type: &str) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "DNS", src_ip, src_port, dst_port);
    nbi.add("query_type", query_type);
    nbi.add("domain", domain);
    nbi
}

/// Build NBI for HTTP request
pub fn http_nbi(listener: &str, src_ip: &str, src_port: u16, dst_port: u16, method: &str, uri: &str, host: &str, user_agent: &str, body_len: usize) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "HTTP", src_ip, src_port, dst_port);
    nbi.add("method", method);
    nbi.add("uri", uri);
    nbi.add("host", host);
    nbi.add("user_agent", user_agent);
    if body_len > 0 {
        nbi.add("body_length", body_len.to_string());
    }
    nbi
}

/// Build NBI for SMTP command
pub fn smtp_nbi(listener: &str, src_ip: &str, src_port: u16, dst_port: u16, command: &str, args: &str) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "SMTP", src_ip, src_port, dst_port);
    nbi.add("command", command);
    if !args.is_empty() {
        nbi.add("args", args);
    }
    nbi
}

/// Build NBI for FTP command
pub fn ftp_nbi(listener: &str, src_ip: &str, src_port: u16, dst_port: u16, command: &str, args: &str) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "FTP", src_ip, src_port, dst_port);
    nbi.add("command", command);
    if !args.is_empty() {
        nbi.add("args", args);
    }
    nbi
}

/// Build NBI for POP3 command
pub fn pop3_nbi(listener: &str, src_ip: &str, src_port: u16, dst_port: u16, command: &str, args: &str) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "POP3", src_ip, src_port, dst_port);
    nbi.add("command", command);
    if !args.is_empty() {
        nbi.add("args", args);
    }
    nbi
}

/// Build NBI for IRC command
pub fn irc_nbi(listener: &str, src_ip: &str, src_port: u16, dst_port: u16, nick: &str, command: &str, args: &str) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "IRC", src_ip, src_port, dst_port);
    nbi.add("nick", nick);
    nbi.add("command", command);
    if !args.is_empty() {
        nbi.add("args", args);
    }
    nbi
}

/// Build NBI for TFTP request
pub fn tftp_nbi(listener: &str, src_ip: &str, src_port: u16, dst_port: u16, operation: &str, filename: &str) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "TFTP", src_ip, src_port, dst_port);
    nbi.add("operation", operation);
    if !filename.is_empty() {
        nbi.add("filename", filename);
    }
    nbi
}

/// Build NBI for raw/unknown data
pub fn raw_nbi(listener: &str, src_ip: &str, src_port: u16, dst_port: u16, data_len: usize, hexdump_preview: &str) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "RAW", src_ip, src_port, dst_port);
    nbi.add("data_length", data_len.to_string());
    if !hexdump_preview.is_empty() {
        nbi.add("hexdump", hexdump_preview);
    }
    nbi
}

/// Build NBI for TLS connection
pub fn tls_nbi(listener: &str, src_ip: &str, src_port: u16, dst_port: u16, sni: &str) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "TLS", src_ip, src_port, dst_port);
    if !sni.is_empty() {
        nbi.add("sni", sni);
    }
    nbi
}

/// Print NBI summary to console
pub fn print_summary(nbi_jsonl_path: &std::path::Path) {
    let content = match std::fs::read_to_string(nbi_jsonl_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut protocol_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut unique_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut total = 0usize;

    for line in content.lines() {
        if let Ok(nbi) = serde_json::from_str::<NetworkBehaviorIndicator>(line) {
            *protocol_counts.entry(nbi.protocol.clone()).or_insert(0) += 1;
            unique_ips.insert(nbi.src_ip.clone());
            total += 1;
        }
    }

    if total == 0 { return; }

    println!("\n=== NetTrap NBI Summary ===");
    println!("Total events:    {}", total);
    println!("Unique sources:  {}", unique_ips.len());
    println!("Protocols:");
    let mut sorted: Vec<_> = protocol_counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (proto, count) in sorted {
        println!("  {:<10} {}", proto, count);
    }
    println!("===========================\n");
}

/// NBI collector that writes to JSONL file and optionally fans out to distributed sinks
pub struct NbiCollector {
    path: Option<std::path::PathBuf>,
    fanout: Option<std::sync::Arc<crate::distributed::EventFanout>>,
    database: Option<std::sync::Arc<crate::database::DatabaseBackend>>,
}

impl NbiCollector {
    pub fn new(path: Option<std::path::PathBuf>) -> Self {
        Self { path, fanout: None, database: None }
    }

    /// Attach a distributed event fanout (only stored if it has active sinks)
    pub fn with_fanout(mut self, fanout: std::sync::Arc<crate::distributed::EventFanout>) -> Self {
        if fanout.has_sinks() {
            self.fanout = Some(fanout);
        }
        self
    }

    /// Attach a database backend for persistent storage
    pub fn with_database(mut self, db: std::sync::Arc<crate::database::DatabaseBackend>) -> Self {
        self.database = Some(db);
        self
    }

    /// Generate an HTML report from the NBI JSONL file
    pub fn generate_html_report(nbi_jsonl_path: &std::path::Path, output_path: &std::path::Path) -> std::io::Result<()> {
        let content = std::fs::read_to_string(nbi_jsonl_path)?;
        let mut nbis: Vec<NetworkBehaviorIndicator> = Vec::new();

        for line in content.lines() {
            if let Ok(nbi) = serde_json::from_str::<NetworkBehaviorIndicator>(line) {
                nbis.push(nbi);
            }
        }

        let mut html = String::from(r#"<!DOCTYPE html>
<html><head>
<title>NetTrap - Network Behavior Indicators Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #f5f5f5; }
h1 { color: #d35400; border-bottom: 2px solid #d35400; padding-bottom: 10px; }
h2 { color: #2c3e50; margin-top: 30px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 20px; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }
th { background: #2c3e50; color: white; padding: 10px 15px; text-align: left; }
td { padding: 8px 15px; border-bottom: 1px solid #ecf0f1; }
tr:hover { background: #f8f9fa; }
.summary { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 20px; }
.card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); min-width: 150px; }
.card h3 { margin: 0 0 10px 0; color: #7f8c8d; font-size: 14px; }
.card .value { font-size: 28px; font-weight: bold; color: #2c3e50; }
.protocol-dns { color: #2980b9; } .protocol-http { color: #27ae60; }
.protocol-smtp { color: #8e44ad; } .protocol-ftp { color: #d35400; }
.protocol-pop3 { color: #c0392b; } .protocol-irc { color: #16a085; }
.protocol-tls { color: #f39c12; } .protocol-raw { color: #7f8c8d; }
.protocol-tftp { color: #2c3e50; }
.indicators { font-family: monospace; font-size: 12px; }
</style>
</head><body>
<h1>NetTrap - Network Behavior Indicators</h1>
"#);

        // Summary cards
        let total = nbis.len();
        let mut protocol_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut unique_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
        for nbi in &nbis {
            *protocol_counts.entry(nbi.protocol.clone()).or_insert(0) += 1;
            unique_ips.insert(nbi.src_ip.clone());
        }

        html.push_str("<div class=\"summary\">");
        html.push_str(&format!("<div class=\"card\"><h3>Total Events</h3><div class=\"value\">{}</div></div>", total));
        html.push_str(&format!("<div class=\"card\"><h3>Unique Sources</h3><div class=\"value\">{}</div></div>", unique_ips.len()));
        html.push_str(&format!("<div class=\"card\"><h3>Protocols</h3><div class=\"value\">{}</div></div>", protocol_counts.len()));
        html.push_str("</div>");

        // Protocol breakdown
        html.push_str("<h2>Protocol Summary</h2><table><tr><th>Protocol</th><th>Events</th></tr>");
        let mut sorted_protos: Vec<_> = protocol_counts.iter().collect();
        sorted_protos.sort_by(|a, b| b.1.cmp(a.1));
        for (proto, count) in &sorted_protos {
            html.push_str(&format!("<tr><td class=\"protocol-{}\">{}</td><td>{}</td></tr>",
                proto.to_lowercase(), proto, count));
        }
        html.push_str("</table>");

        // Full event table
        html.push_str("<h2>All Events</h2><table><tr><th>Time</th><th>Protocol</th><th>Listener</th><th>Source</th><th>Port</th><th>Indicators</th><th>Process</th></tr>");
        for nbi in &nbis {
            let indicators_str: String = nbi.indicators.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(", ");
            let process_str = match (&nbi.process_name, &nbi.process_pid) {
                (Some(name), Some(pid)) => format!("{} ({})", name, pid),
                (Some(name), None) => name.clone(),
                _ => String::new(),
            };
            html.push_str(&format!(
                "<tr><td>{}</td><td class=\"protocol-{}\">{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"indicators\">{}</td><td>{}</td></tr>",
                &nbi.timestamp[..19], nbi.protocol.to_lowercase(), nbi.protocol, nbi.listener,
                nbi.src_ip, nbi.dst_port, indicators_str, process_str
            ));
        }
        html.push_str("</table>");

        html.push_str(&format!("<p><em>Report generated by NetTrap at {}</em></p>", chrono::Utc::now().to_rfc3339()));
        html.push_str("</body></html>");

        std::fs::write(output_path, html)?;
        Ok(())
    }

    pub async fn record(&self, nbi: &NetworkBehaviorIndicator) {
        // Always log to tracing
        tracing::info!(
            target: "nbi",
            "[NBI] {} {} {}:{} -> :{} {:?}",
            nbi.protocol, nbi.listener, nbi.src_ip, nbi.src_port, nbi.dst_port, nbi.indicators
        );

        // Write to file if configured
        if let Some(ref path) = self.path {
            if let Ok(mut file) = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
            {
                use tokio::io::AsyncWriteExt;
                let _ = file.write_all(nbi.to_json().as_bytes()).await;
                let _ = file.write_all(b"\n").await;
            }
        }

        // Database storage
        if let Some(ref db) = self.database {
            if let Err(e) = db.insert_event(nbi).await {
                tracing::warn!("Database insert error: {}", e);
            }
        }

        // Fan out to distributed sinks if configured
        if let Some(ref fanout) = self.fanout {
            fanout.send(nbi).await;
        }
    }
}
