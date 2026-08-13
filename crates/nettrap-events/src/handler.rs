use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::prelude::*;
use nettrap_fsutil::append_regular_file;

const LOG_EVENT_PREVIEW_CHARS: usize = 240;

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
}

impl EventHandlerTrait for LogEventHandler {
    fn handle(&self, event: &Event) -> Result<()> {
        if let Some(ref filter) = self.filter
            && !filter.iter().any(|f| event.event_type() == f)
        {
            return Ok(());
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
                tracing::info!(
                    "[DNS] Query {} ({})",
                    safe_event_log_text(&e.query),
                    e.query_type
                );
            }
            Event::HttpRequest(e) => {
                if let Some(method) = &e.method {
                    match (&e.uri, &e.host) {
                        (Some(uri), Some(host)) => {
                            tracing::info!(
                                "[HTTP] {} {} {}",
                                safe_event_log_text(method),
                                safe_event_log_text(host),
                                safe_event_log_text(uri)
                            );
                        }
                        (Some(uri), None) => {
                            tracing::info!(
                                "[HTTP] {} {}",
                                safe_event_log_text(method),
                                safe_event_log_text(uri)
                            );
                        }
                        (None, Some(host)) => {
                            tracing::info!(
                                "[HTTP] {} {}",
                                safe_event_log_text(method),
                                safe_event_log_text(host)
                            );
                        }
                        (None, None) => {
                            tracing::info!("[HTTP] {}", safe_event_log_text(method));
                        }
                    }
                }
            }
            Event::Warning(e) => {
                tracing::warn!("[WARN] {}", safe_event_log_text(&e.message));
            }
            Event::Error(e) => {
                tracing::error!("[ERROR] {}", safe_event_log_text(&e.message));
            }
            _ => {}
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn handles_event_type(&self, event_type: &str) -> bool {
        if let Some(ref filter) = self.filter {
            filter.iter().any(|f| event_type == f)
        } else {
            true
        }
    }
}

fn safe_event_log_text(value: &str) -> String {
    nettrap_core::sanitize::single_line(value)
        .chars()
        .take(LOG_EVENT_PREVIEW_CHARS)
        .collect()
}

impl Default for LogEventHandler {
    fn default() -> Self {
        Self::new()
    }
}

pub struct JsonFileHandler {
    path: PathBuf,
}

impl JsonFileHandler {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl EventHandlerTrait for JsonFileHandler {
    fn handle(&self, event: &Event) -> Result<()> {
        let json = serde_json::to_string(event).map_err(|e| Error::Storage(e.to_string()))?;
        let path = self.path.as_path();

        use std::io::Write;
        let mut file = append_regular_file(path).map_err(|e| Error::Storage(e.to_string()))?;

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
}

impl<F> EventHandlerTrait for CallbackEventHandler<F>
where
    F: Fn(&Event) -> Result<()> + Send + Sync,
{
    fn handle(&self, event: &Event) -> Result<()> {
        if let Some(ref filter) = self.filter
            && !filter.iter().any(|f| event.event_type() == f)
        {
            return Ok(());
        }
        (self.callback)(event)
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn handles_event_type(&self, event_type: &str) -> bool {
        if let Some(ref filter) = self.filter {
            filter.iter().any(|f| event_type == f)
        } else {
            true
        }
    }
}

pub fn make_log_handler() -> Arc<dyn EventHandlerTrait + Send + Sync> {
    Arc::new(LogEventHandler::new())
}

pub fn make_json_file_handler(path: impl AsRef<Path>) -> Arc<dyn EventHandlerTrait + Send + Sync> {
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

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::{
        CallbackEventHandler, EventHandlerTrait, JsonFileHandler, LOG_EVENT_PREVIEW_CHARS,
        LogEventHandler, safe_event_log_text,
    };
    use crate::event::{Event, HttpEvent, WarningEvent};
    #[cfg(unix)]
    use crate::prelude::Error;
    use nettrap_core::FlowId;
    use tracing::Level;

    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut buffer = self.0.lock().expect("buffer lock");
            buffer.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn callback_handler_filter_rejects_partial_event_type_matches() {
        let hits = AtomicUsize::new(0);
        let handler = CallbackEventHandler {
            name: "callback",
            callback: |_: &Event| {
                hits.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            filter: Some(vec!["warn".to_string()]),
        };

        handler
            .handle(&warning_event())
            .expect("filtered handle should succeed");
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        assert!(!handler.handles_event_type("warning"));
        assert!(handler.handles_event_type("warn"));
    }

    #[test]
    fn callback_handler_filter_allows_exact_event_type_matches() {
        let hits = AtomicUsize::new(0);
        let handler = CallbackEventHandler {
            name: "callback",
            callback: |_: &Event| {
                hits.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            filter: Some(vec!["warning".to_string()]),
        };

        handler
            .handle(&warning_event())
            .expect("exact filter should match");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(handler.handles_event_type("warning"));
    }

    #[test]
    fn log_handler_filter_uses_exact_event_type_matching() {
        let handler = LogEventHandler {
            name: "log",
            filter: Some(vec!["warning".to_string()]),
        };

        assert!(handler.handles_event_type("warning"));
        assert!(!handler.handles_event_type("warn"));
    }

    #[test]
    fn event_log_fields_are_single_line() {
        let text = safe_event_log_text("GET\u{2028}/owned\x1b");

        assert_eq!(text, "GET /owned ");
        assert!(!text.chars().any(char::is_control));

        let long = "a".repeat(LOG_EVENT_PREVIEW_CHARS + 1);
        assert_eq!(safe_event_log_text(&long).len(), LOG_EVENT_PREVIEW_CHARS);
    }

    #[test]
    fn log_handler_emits_http_requests_without_host() {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::INFO)
            .without_time()
            .with_ansi(false)
            .with_writer({
                let buffer = Arc::clone(&buffer);
                move || BufferWriter(Arc::clone(&buffer))
            })
            .finish();

        let handler = LogEventHandler::new();
        let event = Event::HttpRequest(HttpEvent {
            timestamp: chrono::Utc::now(),
            flow_id: FlowId::nil(),
            method: Some("GET".to_string()),
            uri: Some("/status".to_string()),
            host: None,
            user_agent: None,
            status_code: None,
            content_type: None,
            content_length: None,
            headers: std::collections::HashMap::new(),
            is_request: true,
        });

        let dispatch = tracing::Dispatch::new(subscriber);
        tracing::dispatcher::with_default(&dispatch, || {
            handler.handle(&event).expect("logging should succeed");
        });

        let output = String::from_utf8(buffer.lock().expect("buffer lock").clone())
            .expect("log output should be utf-8");

        assert!(output.contains("[HTTP] GET /status"));
    }

    #[test]
    fn log_handler_emits_http_requests_with_host_without_fake_scheme() {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::INFO)
            .without_time()
            .with_ansi(false)
            .with_writer({
                let buffer = Arc::clone(&buffer);
                move || BufferWriter(Arc::clone(&buffer))
            })
            .finish();

        let handler = LogEventHandler::new();
        let event = Event::HttpRequest(HttpEvent {
            timestamp: chrono::Utc::now(),
            flow_id: FlowId::nil(),
            method: Some("GET".to_string()),
            uri: Some("/status".to_string()),
            host: Some("example.test".to_string()),
            user_agent: None,
            status_code: None,
            content_type: None,
            content_length: None,
            headers: std::collections::HashMap::new(),
            is_request: true,
        });

        let dispatch = tracing::Dispatch::new(subscriber);
        tracing::dispatcher::with_default(&dispatch, || {
            handler.handle(&event).expect("logging should succeed");
        });

        let output = String::from_utf8(buffer.lock().expect("buffer lock").clone())
            .expect("log output should be utf-8");

        assert!(output.contains("[HTTP] GET example.test /status"));
        assert!(!output.contains("example.test:///status"));
    }

    #[test]
    fn json_file_handler_creates_parent_directories() {
        let dir = std::env::temp_dir().join(format!(
            "nettrap-events-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let path = dir.join("nested").join("events.jsonl");
        let handler = JsonFileHandler::new(&path);

        handler
            .handle(&warning_event())
            .expect("json file handler should create parent directories");

        let contents = std::fs::read_to_string(&path).expect("event log should be readable");
        assert!(contents.contains("\"message\":\"warn\""));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn json_file_handler_rejects_symlinked_parent_directory() {
        let dir = std::env::temp_dir().join(format!(
            "nettrap-events-symlink-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let real_parent = dir.join("real");
        let link_parent = dir.join("linked");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        std::os::unix::fs::symlink(&real_parent, &link_parent).expect("create symlink parent");

        let path = link_parent.join("events.jsonl");
        let handler = JsonFileHandler::new(&path);

        let err = handler
            .handle(&warning_event())
            .expect_err("symlink path should be rejected");
        assert!(matches!(err, Error::Storage(_)));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn json_file_handler_rejects_symlinked_final_path() {
        let dir = std::env::temp_dir().join(format!(
            "nettrap-events-final-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let real_parent = dir.join("real");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        let target = real_parent.join("events.jsonl");
        std::fs::write(&target, "existing").expect("write target");
        let link = dir.join("linked.jsonl");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let handler = JsonFileHandler::new(&link);

        let err = handler
            .handle(&warning_event())
            .expect_err("symlink final path should be rejected");
        assert!(matches!(err, Error::Storage(_)));

        let contents = std::fs::read_to_string(&target).expect("read original target");
        assert_eq!(contents, "existing");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn json_file_handler_accepts_non_utf8_output_path() {
        use std::os::unix::ffi::OsStringExt;

        let dir = std::env::temp_dir().join(format!(
            "nettrap-events-nonutf8-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join(std::ffi::OsString::from_vec(b"events-\xff.jsonl".to_vec()));

        let handler = JsonFileHandler::new(&path);
        handler
            .handle(&warning_event())
            .expect("non-UTF8 event path should be preserved");

        assert!(path.is_file());
        let _ = std::fs::remove_dir_all(dir);
    }

    fn warning_event() -> Event {
        Event::Warning(WarningEvent {
            timestamp: chrono::Utc::now(),
            message: "warn".to_string(),
            flow_id: None,
        })
    }
}
