use crate::taste::{ProtocolTaste, TasteScore};
use parking_lot::RwLock;

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
        self.default_tcp = normalize_default_name(name.into());
        self
    }

    pub fn with_default_udp(mut self, name: impl Into<String>) -> Self {
        self.default_udp = normalize_default_name(name.into());
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
        self.route_filtered(data, dst_port, |_| true)
    }

    fn route_filtered<F>(
        &self,
        data: &[u8],
        dst_port: u16,
        mut include: F,
    ) -> Option<(String, TasteScore)>
    where
        F: FnMut(&str) -> bool,
    {
        let handlers = self.handlers.read();
        let mut best_name: Option<String> = None;
        let mut best_score: TasteScore = 0;

        for handler in handlers.iter() {
            if !include(&handler.name) {
                continue;
            }
            let score = handler.taster.taste(data, dst_port);
            if score > best_score {
                best_score = score;
                best_name = Some(handler.name.clone());
            }
        }

        best_name.map(|name| (name, best_score))
    }

    /// Determine the best TCP handler, falling back to the configured default
    /// when no detector yields a positive score.
    pub fn route_tcp(&self, data: &[u8], dst_port: u16) -> Option<(String, TasteScore)> {
        self.route_with_default(data, dst_port, self.default_tcp.as_deref(), |_| true)
    }

    /// Determine the best UDP handler, falling back to the configured default
    /// when no detector yields a positive score.
    pub fn route_udp(&self, data: &[u8], dst_port: u16) -> Option<(String, TasteScore)> {
        self.route_with_default(
            data,
            dst_port,
            self.default_udp.as_deref(),
            is_udp_supported_handler,
        )
    }

    fn route_with_default<F>(
        &self,
        data: &[u8],
        dst_port: u16,
        default_handler: Option<&str>,
        mut include: F,
    ) -> Option<(String, TasteScore)>
    where
        F: FnMut(&str) -> bool + Copy,
    {
        match self.route_filtered(data, dst_port, include) {
            Some((name, score)) if score > 1 => Some((name, score)),
            Some((name, score)) if score == 1 && default_handler.is_none() => Some((name, score)),
            _ => default_handler
                .filter(|name| {
                    let trimmed = name.trim_matches([' ', '\t']);
                    !trimmed.is_empty()
                        && !trimmed
                            .chars()
                            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
                        && include(name)
                })
                .map(|name| (name.to_string(), 0)),
        }
    }

    /// Get default handler name for TCP if no content match
    pub fn default_tcp_handler(&self) -> Option<&str> {
        self.default_tcp.as_deref().filter(|name| {
            let trimmed = name.trim_matches([' ', '\t']);
            !trimmed.is_empty()
                && !trimmed
                    .chars()
                    .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
        })
    }

    /// Get default handler name for UDP if no content match
    pub fn default_udp_handler(&self) -> Option<&str> {
        self.default_udp.as_deref().filter(|name| {
            let trimmed = name.trim_matches([' ', '\t']);
            !trimmed.is_empty()
                && !trimmed
                    .chars()
                    .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
        })
    }

    pub fn handler_count(&self) -> usize {
        self.handlers.read().len()
    }

    /// Build a configured protocol router pre-loaded with all supported
    /// protocol detectors, applying the optional default TCP/UDP handlers.
    pub fn with_default_tastes(
        default_tcp: Option<String>,
        default_udp: Option<String>,
    ) -> std::sync::Arc<ProtocolRouter> {
        use crate::taste::{
            ChargenTaste, CoapTaste, DaytimeTaste, DnsTaste, DummyTaste, FingerTaste, FtpTaste,
            HttpTaste, IdentTaste, IrcTaste, LdapTaste, MemcachedTaste, MqttTaste, MysqlTaste,
            NknTaste, NtpTaste, Pop3Taste, PostgresTaste, QuicTaste, QuotdTaste, RawTaste,
            RdpTaste, RedisTaste, SipTaste, SmbTaste, SmtpTaste, SnmpTaste, SocksTaste, SshTaste,
            SyslogRecvTaste, TelnetTaste, TftpTaste, TimeTaste, TlsTaste, UpnpTaste,
        };

        let mut router = ProtocolRouter::new();
        if let Some(default_tcp) = default_tcp {
            router = router.with_default_tcp(default_tcp);
        }
        if let Some(default_udp) = default_udp {
            router = router.with_default_udp(default_udp);
        }
        let router = std::sync::Arc::new(router);

        let tastes: Vec<(&'static str, Box<dyn ProtocolTaste>)> = vec![
            ("dns", Box::new(DnsTaste)),
            ("http", Box::new(HttpTaste)),
            ("tls", Box::new(TlsTaste)),
            ("smtp", Box::new(SmtpTaste)),
            ("ftp", Box::new(FtpTaste)),
            ("pop3", Box::new(Pop3Taste)),
            ("irc", Box::new(IrcTaste)),
            ("tftp", Box::new(TftpTaste)),
            ("quic", Box::new(QuicTaste)),
            ("telnet", Box::new(TelnetTaste)),
            ("ssh", Box::new(SshTaste)),
            ("smb", Box::new(SmbTaste)),
            ("rdp", Box::new(RdpTaste)),
            ("redis", Box::new(RedisTaste)),
            ("mysql", Box::new(MysqlTaste)),
            ("ldap", Box::new(LdapTaste)),
            ("mqtt", Box::new(MqttTaste)),
            ("snmp", Box::new(SnmpTaste)),
            ("socks", Box::new(SocksTaste)),
            ("memcached", Box::new(MemcachedTaste)),
            ("nkn", Box::new(NknTaste)),
            ("postgres", Box::new(PostgresTaste)),
            ("sip", Box::new(SipTaste)),
            ("upnp", Box::new(UpnpTaste)),
            ("ntp", Box::new(NtpTaste)),
            ("coap", Box::new(CoapTaste)),
            ("finger", Box::new(FingerTaste)),
            ("ident", Box::new(IdentTaste)),
            ("daytime", Box::new(DaytimeTaste)),
            ("time", Box::new(TimeTaste)),
            ("chargen", Box::new(ChargenTaste)),
            ("quotd", Box::new(QuotdTaste)),
            ("syslogrecv", Box::new(SyslogRecvTaste)),
            ("dummy", Box::new(DummyTaste)),
            ("raw", Box::new(RawTaste)),
        ];

        for (name, taste) in tastes {
            router.register(name, taste, false);
        }

        tracing::debug!(
            "Protocol router initialised with {} handlers",
            router.handler_count()
        );
        router
    }
}

impl Default for ProtocolRouter {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize_default_name(name: String) -> Option<String> {
    let name = name.trim_matches([' ', '\t']);
    if name.is_empty()
        || name
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        None
    } else {
        Some(name.to_string())
    }
}

fn is_udp_supported_handler(name: &str) -> bool {
    matches!(
        name,
        "dns"
            | "tftp"
            | "snmp"
            | "sip"
            | "upnp"
            | "ntp"
            | "coap"
            | "quic"
            | "daytime"
            | "time"
            | "chargen"
            | "quotd"
            | "syslogrecv"
            | "raw"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NeverMatchTaste;

    impl ProtocolTaste for NeverMatchTaste {
        fn taste(&self, _data: &[u8], _dst_port: u16) -> TasteScore {
            0
        }

        fn protocol_name(&self) -> &'static str {
            "never"
        }
    }

    #[test]
    fn build_keeps_defaults_unset_when_none_are_provided() {
        let router = ProtocolRouter::with_default_tastes(None, None);

        assert_eq!(router.default_tcp_handler(), None);
        assert_eq!(router.default_udp_handler(), None);
    }

    #[test]
    fn build_applies_only_the_defaults_that_exist() {
        let router = ProtocolRouter::with_default_tastes(Some("http".to_string()), None);

        assert_eq!(router.default_tcp_handler(), Some("http"));
        assert_eq!(router.default_udp_handler(), None);
    }

    #[test]
    fn route_tcp_falls_back_to_default_handler() {
        let router = ProtocolRouter::new().with_default_tcp("http");
        router.register("never", Box::new(NeverMatchTaste), false);

        let routed = router.route_tcp(b"??", 31337);

        assert_eq!(routed, Some(("http".to_string(), 0)));
    }

    #[test]
    fn route_udp_falls_back_to_default_handler() {
        let router = ProtocolRouter::new().with_default_udp("dns");
        router.register("never", Box::new(NeverMatchTaste), false);

        let routed = router.route_udp(b"??", 53530);

        assert_eq!(routed, Some(("dns".to_string(), 0)));
    }

    #[test]
    fn route_tcp_prefers_default_over_raw_fallback_score() {
        let router = ProtocolRouter::new().with_default_tcp("http");
        router.register("raw", Box::new(crate::taste::RawTaste), false);

        let routed = router.route_tcp(b"\x00\x01", 31337);

        assert_eq!(routed, Some(("http".to_string(), 0)));
    }

    #[test]
    fn route_tcp_prefers_default_over_dummy_catch_all() {
        let router = ProtocolRouter::new().with_default_tcp("http");
        router.register("dummy", Box::new(crate::taste::DummyTaste), true);
        router.register("raw", Box::new(crate::taste::RawTaste), false);

        let routed = router.route_tcp(b"\x00\x01", 31337);

        assert_eq!(routed, Some(("http".to_string(), 0)));
    }

    #[test]
    fn route_tcp_uses_tls_fallback_on_alternate_https_ports() {
        let router = ProtocolRouter::with_default_tastes(None, None);

        assert_eq!(
            router.route_tcp(b"INVALID", 8443),
            Some(("tls".to_string(), 40))
        );
        assert_eq!(
            router.route_tcp(b"INVALID", 9443),
            Some(("tls".to_string(), 40))
        );
        assert_eq!(
            router.route_tcp(b"GET / HTTP/1.1", 8443),
            Some(("http".to_string(), 95))
        );
    }

    #[test]
    fn empty_default_handler_is_ignored() {
        let router = ProtocolRouter::new().with_default_udp("");
        router.register("never", Box::new(NeverMatchTaste), false);

        assert_eq!(router.default_udp_handler(), None);
        assert_eq!(router.route_udp(b"??", 53530), None);
    }

    #[test]
    fn default_handler_names_are_trimmed() {
        let router = ProtocolRouter::new()
            .with_default_tcp(" http ")
            .with_default_udp("\t dns \t");

        assert_eq!(router.default_tcp_handler(), Some("http"));
        assert_eq!(router.default_udp_handler(), Some("dns"));
        assert_eq!(
            router.route_tcp(b"??", 31337),
            Some(("http".to_string(), 0))
        );
        assert_eq!(router.route_udp(b"??", 53530), Some(("dns".to_string(), 0)));
    }

    #[test]
    fn default_handler_names_reject_unicode_whitespace_padding() {
        let router = ProtocolRouter::new()
            .with_default_tcp("http\u{00a0}")
            .with_default_udp("\u{2028}dns");

        assert_eq!(router.default_tcp_handler(), None);
        assert_eq!(router.default_udp_handler(), None);
        assert_eq!(router.route_tcp(b"??", 31337), None);
        assert_eq!(router.route_udp(b"??", 53530), None);
    }

    #[test]
    fn route_tcp_uses_raw_fallback_when_no_default_is_configured() {
        let router = ProtocolRouter::new();
        router.register("raw", Box::new(crate::taste::RawTaste), false);

        let routed = router.route_tcp(b"\x00\x01", 31337);

        assert_eq!(routed, Some(("raw".to_string(), 1)));
    }

    #[test]
    fn route_udp_uses_raw_fallback_when_no_default_is_configured() {
        let router = ProtocolRouter::new();
        router.register("raw", Box::new(crate::taste::RawTaste), false);

        let routed = router.route_udp(b"\x00\x01", 53530);

        assert_eq!(routed, Some(("raw".to_string(), 1)));
    }

    #[test]
    fn route_udp_ignores_tcp_only_mqtt_taster() {
        let router = ProtocolRouter::new();
        router.register("mqtt", Box::new(crate::taste::MqttTaste), false);

        let routed = router.route_udp(b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00", 1883);

        assert_eq!(routed, None);
    }

    #[test]
    fn route_udp_ignores_tcp_only_default_handler() {
        let router = ProtocolRouter::new().with_default_udp("mqtt");

        let routed = router.route_udp(b"??", 1883);

        assert_eq!(routed, None);
    }

    #[test]
    fn route_udp_allows_quic_taster() {
        let router = ProtocolRouter::new();
        router.register("quic", Box::new(crate::taste::QuicTaste), false);

        let routed = router.route_udp(&[0xc3, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 4, 0, 0, 0, 0], 443);

        assert_eq!(routed, Some(("quic".to_string(), 85)));
    }

    #[test]
    fn route_udp_allows_registered_datagram_utility_handlers() {
        for (name, taster, port) in [
            (
                "daytime",
                Box::new(crate::taste::DaytimeTaste) as Box<dyn ProtocolTaste>,
                13,
            ),
            ("time", Box::new(crate::taste::TimeTaste), 37),
            ("chargen", Box::new(crate::taste::ChargenTaste), 19),
            ("quotd", Box::new(crate::taste::QuotdTaste), 17),
            ("syslogrecv", Box::new(crate::taste::SyslogRecvTaste), 514),
        ] {
            let router = ProtocolRouter::new();
            router.register(name, taster, false);

            assert_eq!(
                router.route_udp(b"<13> test", port),
                Some((name.to_string(), 90))
            );
        }
    }
}
