//! Property-style fuzz harness: throw malformed/truncated/oversized/random
//! bytes at every protocol handler and assert none of them panic.
//!
//! This is a regression contract: a handler that receives untrusted bytes
//! must never panic, regardless of how malformed the input is.

use std::panic::{AssertUnwindSafe, catch_unwind};

fn fuzz(name: &str, mut f: impl FnMut(&[u8])) {
    let mut inputs: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0u8],
        vec![0xffu8],
        vec![0x30u8],
        vec![0x16u8],
        vec![0xfeu8],
        vec![b'\n'],
        vec![b'\r'],
        vec![0x00, 0x00, 0x00, 0x01],
        vec![0x00, 0x00, 0x00, 0x04, 0xfe, b'S'],
        vec![0xfe, b'S', b'M', b'B'],
        vec![0xff, b'S', b'M', b'B'],
        vec![0x03, 0x00, 0x00, 0x0b],
        vec![0x30, 0x82, 0x00, 0x05],
        vec![0x30, 0x05, 0x02, 0x01, 0x01, 0x60, 0x00],
        vec![0u8; 4],
        vec![0u8; 8],
        vec![0u8; 16],
        vec![0u8; 48],
        vec![0u8; 64],
        vec![0u8; 65],
        vec![0u8; 128],
        vec![0u8; 256],
        vec![0u8; 512],
        vec![0u8; 1024],
        vec![0xffu8; 8],
        vec![0xffu8; 48],
        vec![0xffu8; 64],
        vec![0xffu8; 128],
        vec![0xffu8; 256],
        vec![0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x02, 0x01, 0x01],
        vec![0x00, 0x00, 0x10, 0x00, 0xfe, b'S', b'M', b'B', 0x00],
        (0u8..=255).rev().collect::<Vec<u8>>(),
        (0u8..=255).collect::<Vec<u8>>(),
        (0u8..=200).step_by(7).collect::<Vec<u8>>(),
        (0..512).map(|i| (i % 7) as u8).collect::<Vec<u8>>(),
        (0..1024).map(|i| (i % 13) as u8).collect::<Vec<u8>>(),
    ];

    let mut seed: u64 = 0x1234_5678_9abc_def0;
    for _ in 0..400 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let len = (seed % 300) as usize;
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            v.push((seed >> 33) as u8);
        }
        inputs.push(v);
    }

    for input in &inputs {
        let res = catch_unwind(AssertUnwindSafe(|| f(input)));
        if let Err(e) = res {
            panic!(
                "handler {name} panicked on input len={} first={:?}: {e:?}\n--- hex ---\n{}",
                input.len(),
                input.first(),
                hex::encode(input),
            );
        }
    }
}

fn fuzz_str(name: &str, mut f: impl FnMut(&str)) {
    let inputs: Vec<String> = vec![
        String::new(),
        " ".into(),
        "\t".into(),
        "\r\n".into(),
        "\n".into(),
        "\r".into(),
        "a".into(),
        "root".into(),
        "root\r\n".into(),
        "root\n".into(),
        "root\r".into(),
        "Cookie: mstshash=alice\r\n".into(),
        "a\u{00a0}b".into(),
        "\u{1f600}".into(),
        (0..256)
            .map(|i| (i as u8) as char)
            .filter(|c| !c.is_control() || *c == ' ' || *c == '\r' || *c == '\n')
            .collect(),
        "GET / HTTP/1.1\r\nHost: a\r\n\r\n".into(),
        "EHLO test\r\n".into(),
        "6191, 23\r\n".into(),
        "a".repeat(600),
        "a".repeat(10_000),
    ];
    for input in &inputs {
        let res = catch_unwind(AssertUnwindSafe(|| f(input)));
        if let Err(e) = res {
            panic!("str handler {name} panicked on {input:?}: {e:?}");
        }
    }
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[test]
fn fuzz_smb_handler() {
    let h = nettrap_proto_smb::SmbHandler::new();
    fuzz("smb", |d| {
        let _ = h.handle(d);
    });
}
#[test]
fn fuzz_rdp_handler() {
    let h = nettrap_proto_rdp::RdpHandler::new();
    fuzz("rdp", |d| {
        let _ = h.handle(d);
    });
}
#[test]
fn fuzz_mysql_handler() {
    let h = nettrap_proto_mysql::MysqlHandler::new();
    fuzz("mysql", |d| {
        let _ = h.handle(d);
    });
}
#[test]
fn fuzz_ldap_handler() {
    let h = nettrap_proto_ldap::LdapHandler::new();
    fuzz("ldap", |d| {
        let _ = h.handle(d);
    });
}
#[test]
fn fuzz_snmp_handler() {
    let h = nettrap_proto_snmp::SnmpHandler::new();
    fuzz("snmp", |d| {
        let _ = h.handle(d);
    });
}
#[test]
fn fuzz_socks_handler() {
    let h = nettrap_proto_socks::SocksHandler::new();
    fuzz("socks", |d| {
        let _ = h.handle(d);
    });
}
#[test]
fn fuzz_memcached_handler() {
    let h = nettrap_proto_memcached::MemcachedHandler::new();
    fuzz("memcached", |d| {
        let _ = h.handle(d);
    });
}
#[test]
fn fuzz_nkn_handler() {
    let h = nettrap_proto_nkn::NknHandler::new();
    fuzz("nkn", |d| {
        let _ = h.handle(d);
    });
}
#[test]
fn fuzz_postgres_handler() {
    let h = nettrap_proto_postgres::PostgresHandler::new();
    fuzz("postgres", |d| {
        let _ = h.handle(d);
    });
}
#[test]
fn fuzz_sip_handler() {
    let h = nettrap_proto_sip::SipHandler::new();
    fuzz("sip", |d| {
        let _ = h.handle(d);
    });
}
#[test]
fn fuzz_upnp_handler() {
    let h = nettrap_proto_upnp::UpnpHandler::new();
    fuzz("upnp", |d| {
        let _ = h.handle(d);
    });
    fuzz("upnp_ssdp", |d| {
        let _ = h.handle_ssdp(d);
    });
    fuzz("upnp_http", |d| {
        let _ = h.handle_http(d);
    });
}
#[test]
fn fuzz_ntp_handler() {
    let h = nettrap_proto_ntp::NtpHandler::new();
    fuzz("ntp", |d| {
        let _ = h.handle(d);
    });
}
#[test]
fn fuzz_coap_handler() {
    let h = nettrap_proto_coap::CoapHandler::new();
    fuzz("coap", |d| {
        let _ = h.handle(d);
    });
}
#[test]
fn fuzz_mqtt_handler() {
    let h = nettrap_proto_mqtt::MqttHandler::new();
    fuzz("mqtt", |d| {
        let _ = h.handle_packet(d);
    });
}
#[test]
fn fuzz_redis_handler() {
    let h = nettrap_proto_redis::RedisHandler::new();
    fuzz("redis", |d| {
        let _ = h.handle_command(d);
    });
    let mut auth = false;
    fuzz("redis_auth", |d| {
        let _ = h.handle_command_with_auth_state(d, &mut auth);
    });
}
#[test]
fn fuzz_raw_handler() {
    let h = nettrap_proto_raw::RawHandler::new();
    fuzz("raw", |d| {
        let _ = h.handle(d);
    });
}
#[test]
fn fuzz_quic_detect() {
    let h = nettrap_proto_quic::QuicHandler::new();
    fuzz("quic_detect", |d| {
        let _ = h.detect_quic(d);
        let _ = h.extract_sni(d);
    });
}
#[test]
fn fuzz_finger_handler() {
    let h = nettrap_proto_finger::FingerHandler::new();
    fuzz_str("finger", |s| {
        let _ = h.handle(s);
    });
}
#[test]
fn fuzz_ident_handler() {
    let h = nettrap_proto_ident::IdentHandler::new();
    fuzz_str("ident", |s| {
        let _ = h.handle(s);
    });
}
#[test]
fn fuzz_telnet_handler() {
    let h = nettrap_proto_telnet::TelnetHandler::new();
    fuzz_str("telnet", |s| {
        let _ = h.handle_command(s);
    });
}
#[test]
fn fuzz_ftp_handler() {
    let h = nettrap_proto_ftp::FtpHandler::new();
    fuzz_str("ftp", |s| {
        let _ = h.handle(s);
    });
}
