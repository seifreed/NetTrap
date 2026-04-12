use std::sync::Arc;

use nettrap_proxy::{
    ChargenTaste, CoapTaste, DaytimeTaste, DnsTaste, DummyTaste, FingerTaste, FtpTaste, HttpTaste,
    IdentTaste, IrcTaste, LdapTaste, MemcachedTaste, MqttTaste, MysqlTaste, NknTaste, NtpTaste,
    Pop3Taste, PostgresTaste, ProtocolRouter, ProtocolTaste, QuicTaste, QuotdTaste, RawTaste,
    RdpTaste, RedisTaste, SipTaste, SmbTaste, SmtpTaste, SnmpTaste, SocksTaste, SshTaste,
    SyslogRecvTaste, TelnetTaste, TftpTaste, TimeTaste, TlsTaste, UpnpTaste,
};

/// Protocol router configuration.
///
/// Creates a ProtocolRouter with all registered protocol detectors.
pub struct RouterSetup;

impl RouterSetup {
    /// Build a configured protocol router with all supported protocols.
    pub fn build(default_tcp: Option<String>, default_udp: Option<String>) -> Arc<ProtocolRouter> {
        let mut router = ProtocolRouter::new();
        if let Some(default_tcp) = default_tcp {
            router = router.with_default_tcp(default_tcp);
        }
        if let Some(default_udp) = default_udp {
            router = router.with_default_udp(default_udp);
        }
        let router = Arc::new(router);
        register_protocol_tastes(&router);

        tracing::debug!(
            "Protocol router initialised with {} handlers",
            router.handler_count()
        );
        router
    }
}

fn register_protocol_tastes(router: &Arc<ProtocolRouter>) {
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
}

#[cfg(test)]
mod tests {
    use super::RouterSetup;

    #[test]
    fn build_keeps_defaults_unset_when_none_are_provided() {
        let router = RouterSetup::build(None, None);

        assert_eq!(router.default_tcp_handler(), None);
        assert_eq!(router.default_udp_handler(), None);
    }

    #[test]
    fn build_applies_only_the_defaults_that_exist() {
        let router = RouterSetup::build(Some("http".to_string()), None);

        assert_eq!(router.default_tcp_handler(), Some("http"));
        assert_eq!(router.default_udp_handler(), None);
    }
}
