//! Facade crate that aggregates all protocol handlers.
//!
//! This crate provides a single dependency point for all protocol handlers,
//! following the Clean Architecture principle of reducing coupling between
//! the entry point (nettrap-cli) and the protocol implementations.

pub mod handlers {
    pub use nettrap_proto_chargen;
    pub use nettrap_proto_coap;
    pub use nettrap_proto_daytime;
    pub use nettrap_proto_dns;
    pub use nettrap_proto_dummy;
    pub use nettrap_proto_finger;
    pub use nettrap_proto_ftp;
    pub use nettrap_proto_http;
    pub use nettrap_proto_ident;
    pub use nettrap_proto_irc;
    pub use nettrap_proto_ldap;
    pub use nettrap_proto_memcached;
    pub use nettrap_proto_mqtt;
    pub use nettrap_proto_mysql;
    pub use nettrap_proto_nkn;
    pub use nettrap_proto_ntp;
    pub use nettrap_proto_pop3;
    pub use nettrap_proto_postgres;
    pub use nettrap_proto_quic;
    pub use nettrap_proto_quotd;
    pub use nettrap_proto_raw;
    pub use nettrap_proto_rdp;
    pub use nettrap_proto_redis;
    pub use nettrap_proto_sip;
    pub use nettrap_proto_smb;
    pub use nettrap_proto_smtp;
    pub use nettrap_proto_snmp;
    pub use nettrap_proto_socks;
    pub use nettrap_proto_ssh;
    pub use nettrap_proto_syslogrecv;
    pub use nettrap_proto_telnet;
    pub use nettrap_proto_tftp;
    pub use nettrap_proto_time;
    pub use nettrap_proto_tls;
    pub use nettrap_proto_upnp;
}

pub mod traits {
    pub use nettrap_proto_dns::handler::DnsHandlerTrait;
    pub use nettrap_proto_irc::IrcHandlerTrait;
    pub use nettrap_proto_pop3::Pop3HandlerTrait;
    pub use nettrap_proto_smtp::SmtpHandlerTrait;
    pub use nettrap_proto_tftp::TftpHandlerTrait;
}

pub mod tcp {
    pub use nettrap_proto_ftp::FtpHandler;
    pub use nettrap_proto_irc::IrcHandler;
    pub use nettrap_proto_ldap::LdapHandler;
    pub use nettrap_proto_memcached::MemcachedHandler;
    pub use nettrap_proto_mqtt::MqttHandler;
    pub use nettrap_proto_mysql::MysqlHandler;
    pub use nettrap_proto_nkn::NknHandler;
    pub use nettrap_proto_pop3::Pop3Handler;
    pub use nettrap_proto_postgres::PostgresHandler;
    pub use nettrap_proto_rdp::RdpHandler;
    pub use nettrap_proto_redis::RedisHandler;
    pub use nettrap_proto_smb::SmbHandler;
    pub use nettrap_proto_smtp::SmtpHandler;
    pub use nettrap_proto_socks::SocksHandler;
    pub use nettrap_proto_ssh::SshHandler;
    pub use nettrap_proto_telnet::TelnetHandler;
}

pub mod udp {
    pub use nettrap_proto_coap::CoapHandler;
    pub use nettrap_proto_dns::handler::DnsHandler;
    pub use nettrap_proto_mqtt::MqttHandler;
    pub use nettrap_proto_ntp::NtpHandler;
    pub use nettrap_proto_sip::SipHandler;
    pub use nettrap_proto_snmp::SnmpHandler;
    pub use nettrap_proto_tftp::TftpHandler;
    pub use nettrap_proto_upnp::UpnpHandler;
}

pub mod taste {
    pub use nettrap_proxy::{
        ChargenTaste, CoapTaste, DaytimeTaste, DnsTaste, DummyTaste, FingerTaste, FtpTaste,
        HttpTaste, IdentTaste, IrcTaste, LdapTaste, MemcachedTaste, MqttTaste, MysqlTaste,
        NknTaste, NtpTaste, Pop3Taste, PostgresTaste, ProtocolRouter, QuicTaste, QuotdTaste,
        RawTaste, RdpTaste, RedisTaste, SipTaste, SmbTaste, SmtpTaste, SnmpTaste, SocksTaste,
        SshTaste, SyslogRecvTaste, TelnetTaste, TftpTaste, TimeTaste, TlsTaste, UpnpTaste,
    };
}

pub mod prelude {
    pub use crate::handlers::*;
    pub use crate::traits::*;
}
