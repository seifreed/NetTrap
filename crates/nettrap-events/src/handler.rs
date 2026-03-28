use std::sync::Arc;

use crate::prelude::*;

pub struct LogEventHandler {
    name: &'static str,
    filter: Option<Vec<String>>,
}

impl LogEventHandler {
    pub fn new() -> Self {
        Self {
            name: "log",
            filter: None,
        }
    }

    pub fn with_filter(filter: Vec<String>) -> Self {
        Self {
            name: "log",
            filter: Some(filter),
        }
    }
}

impl EventHandlerTrait for LogEventHandler {
    fn handle(&self, event: &Event) -> Result<()> {
        if let Some(ref filter) = self.filter {
            if !filter.iter().any(|f| event.event_type().contains(f)) {
                return Ok(());
            }
        }

        match event {
            Event::FlowCreated(e) => {
                tracing::info!(
                    "[FLOW] Created {} -> {}:{} -> {}:{} ({:?})",
                    e.flow_id,
                    e.five_tuple.src_ip,
                    e.five_tuple.src_port,
                    e.five_tuple.dst_ip,
                    e.five_tuple.dst_port,
                    e.five_tuple.protocol
                );
            }
            Event::DnsQuery(e) => {
                tracing::info!("[DNS] Query {} ({})", e.query, e.query_type);
            }
            Event::HttpRequest(e) => {
                if let (Some(method), Some(uri), Some(host)) = (&e.method, &e.uri, &e.host) {
                    tracing::info!("[HTTP] {} {}://{}", method, host, uri);
                }
            }
            Event::Warning(e) => {
                tracing::warn!("[WARN] {}", e.message);
            }
            Event::Error(e) => {
                tracing::error!("[ERROR] {}", e.message);
            }
            _ => {}
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn handles_event_type(&self, _event_type: &str) -> bool {
        true
    }
}

impl Default for LogEventHandler {
    fn default() -> Self {
        Self::new()
    }
}

pub struct JsonFileHandler {
    path: String,
}

impl JsonFileHandler {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

impl EventHandlerTrait for JsonFileHandler {
    fn handle(&self, event: &Event) -> Result<()> {
        let json = serde_json::to_string(event).map_err(|e| Error::Storage(e.to_string()))?;

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| Error::Storage(e.to_string()))?;

        writeln!(file, "{}", json).map_err(|e| Error::Storage(e.to_string()))?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "json_file"
    }

    fn handles_event_type(&self, _event_type: &str) -> bool {
        true
    }
}

pub struct CallbackEventHandler<F>
where
    F: Fn(&Event) -> Result<()> + Send + Sync,
{
    name: &'static str,
    callback: F,
    filter: Option<Vec<String>>,
}

impl<F> CallbackEventHandler<F>
where
    F: Fn(&Event) -> Result<()> + Send + Sync,
{
    pub fn new(name: &'static str, callback: F) -> Self {
        Self {
            name,
            callback,
            filter: None,
        }
    }

    pub fn with_filter(name: &'static str, callback: F, filter: Vec<String>) -> Self {
        Self {
            name,
            callback,
            filter: Some(filter),
        }
    }
}

impl<F> EventHandlerTrait for CallbackEventHandler<F>
where
    F: Fn(&Event) -> Result<()> + Send + Sync,
{
    fn handle(&self, event: &Event) -> Result<()> {
        if let Some(ref filter) = self.filter {
            if !filter.iter().any(|f| event.event_type().contains(f)) {
                return Ok(());
            }
        }
        (self.callback)(event)
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn handles_event_type(&self, event_type: &str) -> bool {
        if let Some(ref filter) = self.filter {
            filter.iter().any(|f| event_type.contains(f))
        } else {
            true
        }
    }
}

pub fn make_log_handler() -> Arc<dyn EventHandlerTrait + Send + Sync> {
    Arc::new(LogEventHandler::new())
}

pub fn make_json_file_handler(path: impl Into<String>) -> Arc<dyn EventHandlerTrait + Send + Sync> {
    Arc::new(JsonFileHandler::new(path))
}

pub fn make_callback_handler<F>(
    name: &'static str,
    callback: F,
) -> Arc<dyn EventHandlerTrait + Send + Sync>
where
    F: Fn(&Event) -> Result<()> + Send + Sync + 'static,
{
    Arc::new(CallbackEventHandler::new(name, callback))
}
