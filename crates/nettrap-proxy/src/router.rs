use parking_lot::RwLock;
use crate::taste::{ProtocolTaste, TasteScore};

/// A registered protocol handler with its taste detector
pub struct RegisteredHandler {
    pub name: String,
    pub taster: Box<dyn ProtocolTaste>,
    pub hidden: bool,
}

/// Routes connections to the best-matching protocol handler based on content
pub struct ProtocolRouter {
    handlers: RwLock<Vec<RegisteredHandler>>,
    default_tcp: Option<String>,
    default_udp: Option<String>,
}

impl ProtocolRouter {
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(Vec::new()),
            default_tcp: None,
            default_udp: None,
        }
    }

    pub fn with_default_tcp(mut self, name: impl Into<String>) -> Self {
        self.default_tcp = Some(name.into());
        self
    }

    pub fn with_default_udp(mut self, name: impl Into<String>) -> Self {
        self.default_udp = Some(name.into());
        self
    }

    pub fn register(&self, name: impl Into<String>, taster: Box<dyn ProtocolTaste>, hidden: bool) {
        self.handlers.write().push(RegisteredHandler {
            name: name.into(),
            taster,
            hidden,
        });
    }

    /// Determine the best handler for given data and port.
    /// Returns (handler_name, confidence_score).
    pub fn route(&self, data: &[u8], dst_port: u16) -> Option<(String, TasteScore)> {
        let handlers = self.handlers.read();
        let mut best_name: Option<String> = None;
        let mut best_score: TasteScore = 0;

        for handler in handlers.iter() {
            let score = handler.taster.taste(data, dst_port);
            if score > best_score {
                best_score = score;
                best_name = Some(handler.name.clone());
            }
        }

        best_name.map(|name| (name, best_score))
    }

    /// Get default handler name for TCP if no content match
    pub fn default_tcp_handler(&self) -> Option<&str> {
        self.default_tcp.as_deref()
    }

    /// Get default handler name for UDP if no content match
    pub fn default_udp_handler(&self) -> Option<&str> {
        self.default_udp.as_deref()
    }

    pub fn handler_count(&self) -> usize {
        self.handlers.read().len()
    }
}

impl Default for ProtocolRouter {
    fn default() -> Self { Self::new() }
}
