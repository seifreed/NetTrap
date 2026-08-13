use super::*;

fn minimal_tls_client_hello() -> Vec<u8> {
    let mut tls = vec![0x16, 0x03, 0x03, 0x00, 0x2f];
    tls.extend_from_slice(&[0x01, 0x00, 0x00, 0x2b]);
    tls.extend_from_slice(&[0x03, 0x03]);
    tls.extend(std::iter::repeat_n(0, 32));
    tls.extend_from_slice(&[0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x00]);
    tls
}

fn minimal_quic_initial(version: u32) -> Vec<u8> {
    let mut packet = vec![0xc3];
    packet.extend_from_slice(&version.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0]);
    packet
}

fn memcached_binary_request(
    opcode: u8,
    extras_len: usize,
    key_len: usize,
    value_len: usize,
) -> Vec<u8> {
    let body_len = extras_len + key_len + value_len;
    let mut request = vec![
        0x80,
        opcode,
        ((key_len >> 8) & 0xff) as u8,
        (key_len & 0xff) as u8,
        extras_len as u8,
        0x00,
        0x00,
        0x00,
    ];
    request.extend_from_slice(&(body_len as u32).to_be_bytes());
    request.extend_from_slice(&0u32.to_be_bytes());
    request.extend_from_slice(&0u64.to_be_bytes());
    request.extend(std::iter::repeat_n(0, extras_len));
    request.extend(std::iter::repeat_n(b'k', key_len));
    request.extend(std::iter::repeat_n(b'v', value_len));
    request
}

#[test]
fn test_dns_taste_port() {
    let taste = DnsTaste;
    assert_eq!(taste.taste(&[], 53), 0);
    assert_eq!(taste.taste(b"not dns", 53), 0);
    assert_eq!(taste.taste(&[], 80), 0);
}

#[test]
fn test_dns_taste_data() {
    let taste = DnsTaste;
    let dns_query = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p',
        b'l', b'e', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1,
    ];
    let dns_two_questions = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p',
        b'l', b'e', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1, 3, b'f', b'o', b'o', 0, 0, 1, 0, 1,
    ];
    let dns_query_with_opt = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 7, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1, 0x00, 0x00, 0x29,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let dns_query_with_zero_opt_payload = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 7, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1, 0x00, 0x00, 0x29,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let dns_query_with_trailing_bytes = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p',
        b'l', b'e', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1, b'j', b'u', b'n', b'k',
    ];
    let dns_query_with_compressed_question = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1,
    ];
    let dns_status_query = [
        0x12, 0x34, 0x09, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p',
        b'l', b'e', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1,
    ];
    assert_eq!(taste.taste(&dns_query, 0), 70);
    assert_eq!(taste.taste(&dns_query, 53), 90);
    assert_eq!(taste.taste(&dns_two_questions, 53), 0);
    assert_eq!(taste.taste(&dns_query_with_opt, 53), 90);
    assert_eq!(taste.taste(&dns_query_with_zero_opt_payload, 53), 0);
    assert_eq!(taste.taste(&dns_query_with_trailing_bytes, 53), 0);
    assert_eq!(taste.taste(&dns_query_with_compressed_question, 53), 0);
    assert_eq!(taste.taste(&dns_status_query, 53), 0);

    let truncated = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7, b'e',
    ];
    assert_eq!(taste.taste(&truncated, 53), 0);
}

#[test]
fn test_dns_taste_allows_ascii_transaction_id() {
    let taste = DnsTaste;
    let dns_query = [
        0x41, 0x42, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p',
        b'l', b'e', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1,
    ];

    assert_eq!(taste.taste(&dns_query, 53), 90);
}

#[test]
fn test_http_taste_methods() {
    let taste = HttpTaste;
    assert_eq!(taste.taste(b"GET / HTTP/1.1", 80), 95);
    assert_eq!(taste.taste(b"POST /api HTTP/1.1", 8080), 95);
    assert_eq!(taste.taste(b"TRACE /debug HTTP/1.1", 80), 95);
    assert_eq!(taste.taste(b"GET http://example.com.../ HTTP/1.1", 80), 0);
    assert_eq!(taste.taste(b"GET http://12345/ HTTP/1.1", 80), 0);
    assert_eq!(taste.taste(b"GET http://192.0.2.10/ HTTP/1.1", 80), 95);
    assert_eq!(taste.taste(b"GET http://2001:db8::1/ HTTP/1.1", 80), 0);
    assert_eq!(taste.taste(b"GET ftp://example.com HTTP/1.1", 80), 0);
    assert_eq!(taste.taste(b"CONNECT / HTTP/1.1", 80), 0);
    assert_eq!(taste.taste(b"CONNECT [2001:db8::1]:443:80 HTTP/1.1", 80), 0);
    assert_eq!(taste.taste(b"HTTP/1.1 200 OK", 0), 0);
    assert_eq!(taste.taste(b"garbage HTTP inside", 0), 0);
    assert_eq!(taste.taste(b"INVALID", 80), 30);
    assert_eq!(taste.taste(b"INVALID", 8080), 30);
    assert_eq!(taste.taste(b"INVALID", 8443), 0);
    assert_eq!(taste.taste(b"GET / HTTP/1.1", 8443), 95);
}

#[test]
fn test_tls_taste() {
    let taste = TlsTaste;
    let mut tls = minimal_tls_client_hello();
    tls[2] = 0x01;
    assert_eq!(taste.taste(&tls, 443), 95);
    let mut tls_with_trailing_junk = tls.clone();
    tls_with_trailing_junk.extend_from_slice(b"junk");
    assert_eq!(taste.taste(&tls_with_trailing_junk, 0), 0);
    let mut tls_with_trailing_bytes = tls.clone();
    tls_with_trailing_bytes.extend_from_slice(b"junk");
    tls_with_trailing_bytes[3] = 0x00;
    tls_with_trailing_bytes[4] = 0x33;
    assert_eq!(taste.taste(&tls_with_trailing_bytes, 0), 0);
    let mut tls_with_trailing_handshake_bytes = tls.clone();
    tls_with_trailing_handshake_bytes.push(0);
    tls_with_trailing_handshake_bytes[4] += 1;
    tls_with_trailing_handshake_bytes[8] += 1;
    assert_eq!(taste.taste(&tls_with_trailing_handshake_bytes, 0), 0);
    let mut invalid_tls = vec![0x16, 0x03, 0x03, 0x00, 0x27];
    invalid_tls.extend_from_slice(&[0x01, 0x00, 0x00, 0x23]);
    invalid_tls.extend(std::iter::repeat_n(0, 35));
    assert_eq!(taste.taste(&invalid_tls, 0), 0);
    let mut tls = minimal_tls_client_hello();
    tls[2] = 0x03;
    assert_eq!(taste.taste(&tls, 0), 95);
    let mut sslv2 = vec![
        0x80, 0x1c, 0x01, 0x03, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10,
    ];
    sslv2.extend_from_slice(&[0x01, 0x02, 0x03]);
    sslv2.extend_from_slice(&[0; 16]);
    assert_eq!(taste.taste(&sslv2, 0), 80);
    assert_eq!(taste.taste(&sslv2.repeat(4096), 0), 80);
    let mut sslv2_with_tls = sslv2.clone();
    sslv2_with_tls.extend_from_slice(&tls);
    assert_eq!(taste.taste(&sslv2_with_tls, 0), 80);
    let mut sslv2_with_trailing_bytes = sslv2.clone();
    sslv2_with_trailing_bytes.extend_from_slice(b"junk");
    sslv2_with_trailing_bytes[0] = 0x80;
    sslv2_with_trailing_bytes[1] = 0x20;
    assert_eq!(taste.taste(&sslv2_with_trailing_bytes, 0), 0);
    assert_eq!(taste.taste(&[0x80, 0x00, 0x01], 0), 0);
    assert_eq!(
        taste.taste(
            &[0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00],
            0
        ),
        0
    );
    assert_eq!(taste.taste(&[0x16, 0x03, 0x03, 0x00, 0x20], 0), 0);
    assert_eq!(taste.taste(&[0x16, 0x03, 0x03, 0x00, 0x20], 443), 40);
    assert_eq!(taste.taste(&[], 8443), 40);
    assert_eq!(taste.taste(&[], 9443), 40);
    assert_eq!(taste.taste(&[0x16, 0x03, 0x00, 0x00, 0x20], 0), 0);
    let mut short_client_hello = vec![0x16, 0x03, 0x03, 0x00, 0x26];
    short_client_hello.extend_from_slice(&[0x01, 0x00, 0x00, 0x22]);
    short_client_hello.extend(std::iter::repeat_n(0, 34));
    assert_eq!(taste.taste(&short_client_hello, 0), 0);
    assert_eq!(taste.taste(&[], 443), 40);
}

#[test]
fn test_irc_taste_recognizes_handler_commands() {
    let taste = IrcTaste;

    assert_eq!(taste.taste(b"", 994), 85);
    assert_eq!(taste.taste(b"PONG :server\r\n", 0), 80);
    assert_eq!(taste.taste(b"PART #channel\r\n", 0), 80);
    assert_eq!(taste.taste(b"PRIVMSG #channel :hello\r\n", 0), 80);
    assert_eq!(taste.taste(b"MODE #channel +o nick\r\n", 0), 80);
    assert_eq!(taste.taste(b"LIST\r\n", 0), 80);
    assert_eq!(taste.taste(b"QUIT :bye\r\n", 0), 80);
    assert_eq!(taste.taste(b"NOTICE #channel :hello\r\n", 0), 80);
    assert_eq!(taste.taste(b"WHO #channel\r\n", 0), 80);
    assert_eq!(taste.taste(b"WHOIS nick\r\n", 0), 80);
    assert_eq!(taste.taste(b"PRIVMSGX #channel :hello\r\n", 0), 80);
    assert_eq!(taste.taste(b"PRIVMSGX #channel :hello", 0), 0);
    assert_eq!(taste.taste(b"PRIVMSGX\0 #channel :hello\r\n", 0), 0);
}

#[test]
fn test_tftp_taste_requires_new_request_shape() {
    let taste = TftpTaste;
    let rrq = b"\x00\x01firmware.bin\x00octet\x00";
    let ack = b"\x00\x04\x00\x01";
    let data = b"\x00\x03\x00\x01payload";

    assert_eq!(taste.taste(rrq, 69), 90);
    assert_eq!(taste.taste(rrq, 1069), 75);
    assert_eq!(taste.taste(ack, 69), 0);
    assert_eq!(taste.taste(data, 69), 0);
    assert_eq!(taste.taste(b"\x00\x01file\x00badmode\x00", 69), 0);
    assert_eq!(taste.taste(b"\x00\x01file\n\x00octet\x00", 69), 0);
    assert_eq!(taste.taste(b"\x00\x01file\x00octet\x1b\x00", 69), 0);
    assert_eq!(
        taste.taste(b"\x00\x01file\x00octet\x00blksize\x001428\n\x00", 69),
        0
    );
    assert_eq!(
        taste.taste(b"\x00\x01file\x00octet\x00blksize\x00\x00", 69),
        0
    );
    assert_eq!(
        taste.taste(
            b"\x00\x01file\x00octet\x00blksize\x001428\x00BLKSIZE\x00512\x00",
            69
        ),
        0
    );
    assert_eq!(taste.taste(b"\x00\x01../secret\x00octet\x00", 69), 0);
    assert_eq!(taste.taste(b"\x00\x01file..bin\x00octet\x00", 69), 90);
    assert_eq!(taste.taste(b"\x00\x01/secret\x00octet\x00", 69), 0);
    assert_eq!(taste.taste(b"\x00\x01dir\\secret\x00octet\x00", 69), 90);
    let mut oversized = b"\x00\x01file\x00octet\x00".to_vec();
    oversized.resize(u16::MAX as usize, b'a');
    oversized.push(0);
    assert_eq!(taste.taste(&oversized, 69), 0);
}

#[test]
fn test_ldap_taste_rejects_incomplete_long_form_lengths() {
    let taste = LdapTaste;
    let bind = [0x30, 0x05, 0x02, 0x01, 0x01, 0x60, 0x00];
    let modify = [0x30, 0x05, 0x02, 0x01, 0x01, 0x66, 0x00];
    let incomplete_long_form = [0x30, 0x82, 0x00];
    let zero_message_id = [0x30, 0x05, 0x02, 0x01, 0x00, 0x60, 0x00];
    let negative_message_id = [0x30, 0x05, 0x02, 0x01, 0x80, 0x60, 0x00];
    let non_minimal_message_id = [0x30, 0x06, 0x02, 0x02, 0x00, 0x7f, 0x60, 0x00];
    let valid_bind = {
        let dn = b"cn";
        let mut bind = vec![0x02, 0x01, 0x03, 0x04, dn.len() as u8];
        bind.extend_from_slice(dn);
        bind.extend_from_slice(&[0x80, 0x00]);
        let mut operation = vec![0x60, bind.len() as u8];
        operation.extend_from_slice(&bind);
        let mut request = vec![0x30, (3 + operation.len()) as u8, 0x02, 0x01, 0x01];
        request.extend_from_slice(&operation);
        request
    };
    let valid_sasl_bind = {
        let mut sasl = vec![0x04, 0x05];
        sasl.extend_from_slice(b"PLAIN");
        sasl.extend_from_slice(&[0x04, 0x00]);
        let mut bind = vec![0x02, 0x01, 0x03, 0x04, 0x00, 0xa3, sasl.len() as u8];
        bind.extend_from_slice(&sasl);
        let mut operation = vec![0x60, bind.len() as u8];
        operation.extend_from_slice(&bind);
        let mut request = vec![0x30, (3 + operation.len()) as u8, 0x02, 0x01, 0x01];
        request.extend_from_slice(&operation);
        request
    };
    let malformed_sasl_bind = {
        let mut bind = vec![0x02, 0x01, 0x03, 0x04, 0x00, 0xa3, 0x05];
        bind.extend_from_slice(b"PLAIN");
        let mut operation = vec![0x60, bind.len() as u8];
        operation.extend_from_slice(&bind);
        let mut request = vec![0x30, (3 + operation.len()) as u8, 0x02, 0x01, 0x01];
        request.extend_from_slice(&operation);
        request
    };
    let search_with_junk_tail = [0x30, 0x08, 0x02, 0x01, 0x01, 0x63, 0x01, 0x00, 0x00];
    let bind_with_bad_controls = {
        let mut request = valid_bind.clone();
        request[1] += 3;
        request.extend_from_slice(&[0xa0, 0x01, 0x00]);
        request
    };

    assert_eq!(taste.taste(&bind, 1389), 0);
    assert_eq!(taste.taste(&valid_bind, 1389), 55);
    assert_eq!(taste.taste(&valid_sasl_bind, 1389), 55);
    assert_eq!(taste.taste(&malformed_sasl_bind, 1389), 0);
    assert_eq!(taste.taste(&search_with_junk_tail, 1389), 0);
    assert_eq!(taste.taste(&bind_with_bad_controls, 1389), 0);
    assert_eq!(taste.taste(&modify, 1389), 0);
    assert_eq!(taste.taste(&incomplete_long_form, 1389), 0);
    assert_eq!(taste.taste(&zero_message_id, 1389), 0);
    assert_eq!(taste.taste(&negative_message_id, 1389), 0);
    assert_eq!(taste.taste(&non_minimal_message_id, 1389), 0);

    let mut trailing_junk = valid_bind;
    trailing_junk.push(0);
    assert_eq!(taste.taste(&trailing_junk, 1389), 0);
}

#[test]
fn test_quic_taste_requires_known_version() {
    let taste = QuicTaste;

    assert_eq!(taste.taste(&minimal_quic_initial(1), 443), 85);
    assert_eq!(
        taste.taste(&[0xc3, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0], 443),
        0
    );
    assert_eq!(
        taste.taste(&[0xc3, 0xff, 0x00, 0x00, 0x10, 0, 0, 0, 0], 443),
        0
    );
    assert_eq!(
        taste.taste(&[0x83, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0], 443),
        0
    );
    assert_eq!(taste.taste(&[0xc3, 0x00, 0x00, 0x00, 0x01], 443), 0);
    assert_eq!(
        taste.taste(&[0xc3, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0], 443),
        0
    );
    let mut oversized = minimal_quic_initial(1);
    oversized.resize(MAX_QUIC_TASTE_PACKET_BYTES + 1, 0);
    assert_eq!(taste.taste(&oversized, 443), 0);
}

#[test]
fn test_ntp_taste_requires_client_mode_even_on_standard_port() {
    let taste = NtpTaste;
    let mut client = vec![0u8; 48];
    client[0] = 0x23;
    let mut server = vec![0u8; 48];
    server[0] = 0x24;

    assert_eq!(taste.taste(&client, 123), 90);
    assert_eq!(taste.taste(&client, 12345), 60);
    assert_eq!(taste.taste(&server, 123), 0);
    assert_eq!(taste.taste(&server, 12345), 0);
    assert_eq!(taste.taste(b"garbage", 123), 0);
    assert_eq!(taste.taste(&[0u8; 48], 12345), 0);
}

#[test]
fn test_coap_taste_requires_plain_request_even_on_standard_ports() {
    let taste = CoapTaste;

    assert_eq!(taste.taste(&[0x40, 0x00, 0x12, 0x34], 5683), 90);
    assert_eq!(taste.taste(&[0x40, 0x00, 0x12, 0x34], 12345), 50);
    assert_eq!(taste.taste(&[0x40, 0x01, 0x12, 0x34], 5683), 90);
    assert_eq!(taste.taste(&[0x40, 0x01, 0x12, 0x34], 5684), 50);
    assert_eq!(taste.taste(&[0x40, 0x01, 0x12, 0x34], 12345), 50);
    assert_eq!(taste.taste(b"garbage", 5683), 0);
    assert_eq!(taste.taste(b"garbage", 5684), 0);
    assert_eq!(taste.taste(&[0x60, 0x41, 0x12, 0x34], 12345), 0);
    assert_eq!(taste.taste(&[0x49, 0x01, 0x12, 0x34], 12345), 0);
    assert_eq!(taste.taste(&[0x40, 0x05, 0x12, 0x34], 5683), 90);
    assert_eq!(taste.taste(&[0x40, 0x01, 0x12, 0x34, 0x0d], 5683), 0);
    assert_eq!(taste.taste(&[0x40, 0x01, 0x12, 0x34, 0xff], 5683), 0);
}

#[test]
fn test_upnp_taste_requires_well_formed_ssdp() {
    let taste = UpnpTaste;
    let m_search = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";
    let notify_alive = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\nUSN: uuid:device-1::upnp:rootdevice\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.1:49152/desc.xml\r\n\r\n";
    let notify_alive_trailing = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\nUSN: uuid:device-1::upnp:rootdevice\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.1:49152/desc.xml\r\n\r\njunk";

    assert_eq!(taste.taste(m_search, 1900), 90);
    assert_eq!(taste.taste(m_search, 9999), 75);
    assert_eq!(taste.taste(notify_alive, 1900), 0);
    assert_eq!(taste.taste(notify_alive_trailing, 1900), 0);
    assert_eq!(taste.taste(b"garbage", 1900), 0);
    assert_eq!(
            taste.taste(
                b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\njunk",
                1900
            ),
            0
        );
    assert_eq!(
        taste.taste(
            b"M-SEARCH * HTTP/1.1\r\nHOST: x\r\nST: upnp:rootdevice\r\n\r\n",
            1900
        ),
        0
    );
}

#[test]
fn test_upnp_taste_rejects_unicode_whitespace_in_ssdp_headers() {
    let taste = UpnpTaste;
    let m_search = "M-SEARCH * HTTP/1.1\r\nHOST: \u{00a0}239.255.255.250:1900\r\nMAN: \u{00a0}\"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";

    assert_eq!(taste.taste(m_search.as_bytes(), 1900), 0);
}

#[test]
fn test_upnp_taste_rejects_conflicting_duplicate_headers() {
    let taste = UpnpTaste;
    let conflicting = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMAN: \"other\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";
    let identical = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";
    let zero_mx = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 0\r\nST: upnp:rootdevice\r\n\r\n";
    let wrong_host = b"M-SEARCH * HTTP/1.1\r\nHOST: example.com:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";

    assert_eq!(taste.taste(conflicting, 1900), 0);
    assert_eq!(taste.taste(identical, 1900), 0);
    assert_eq!(taste.taste(zero_mx, 1900), 0);
    assert_eq!(taste.taste(wrong_host, 1900), 0);
}

#[test]
fn test_postgres_taste_recognizes_startup_messages() {
    let taste = PostgresTaste;
    let ssl_request = [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
    let gssenc_request = [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x30];
    let cancel_request = [
        0x00, 0x00, 0x00, 0x10, 0x04, 0xd2, 0x16, 0x2e, 0x00, 0x00, 0x04, 0xd2, 0x00, 0x00, 0x16,
        0x2e,
    ];
    let query = [
        b'Q', 0, 0, 0, 13, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'1', 0,
    ];
    let bad_query = [
        b'Q', 0, 0, 0, 13, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'1', b'X',
    ];
    let mut query_with_sync = query.to_vec();
    query_with_sync.extend_from_slice(&[b'S', 0, 0, 0, 4]);
    let mut query_with_trailing_junk = query.to_vec();
    query_with_trailing_junk.extend_from_slice(b"junk");
    let parse = [
        b'P', 0, 0, 0, 16, 0, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'1', 0, 0, 0,
    ];
    let bad_parse = [b'P', 0, 0, 0, 11, 0, b'S', b'E', b'L', b'E', b'C', b'T'];
    let bind = [b'B', 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0];
    let bad_bind = [b'B', 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 1];
    let bad_describe = [b'D', 0, 0, 0, 6, b'X', 0];
    let execute = [b'E', 0, 0, 0, 9, 0, 0, 0, 0, 0];
    let bad_execute = [b'E', 0, 0, 0, 9, b'p', b'o', b'r', b't', 0];
    let function_call = [b'F', 0, 0, 0, 14, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    let bad_function_call = [b'F', 0, 0, 0, 14, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];
    let terminate = [b'X', 0, 0, 0, 4];
    let bad_terminate = [b'X', 0, 0, 0, 3];
    let startup = [
        0x00, 0x00, 0x00, 0x20, 0x00, 0x03, 0x00, 0x00, b'u', b's', b'e', b'r', 0x00, b'a', b'l',
        b'i', b'c', b'e', 0x00, b'd', b'b', b'n', b'a', b'm', b'e', 0x00, b't', b'e', b's', b't',
        0x00, 0x00,
    ];
    let tls_client_hello = minimal_tls_client_hello();
    let mut ssl_request_with_tls = ssl_request.to_vec();
    ssl_request_with_tls.extend_from_slice(&tls_client_hello);

    assert_eq!(taste.taste(&ssl_request, 15432), 85);
    assert_eq!(taste.taste(&ssl_request_with_tls, 15432), 85);
    assert_eq!(taste.taste(&gssenc_request, 15432), 85);
    assert_eq!(taste.taste(&cancel_request, 15432), 85);
    assert_eq!(taste.taste(&query, 15432), 80);
    assert_eq!(taste.taste(&query_with_sync, 15432), 0);
    assert_eq!(taste.taste(&query.repeat(4096), 15432), 0);
    assert_eq!(taste.taste(&query_with_trailing_junk, 15432), 0);
    assert_eq!(taste.taste(&bad_query, 15432), 0);
    assert_eq!(taste.taste(&parse, 15432), 80);
    assert_eq!(taste.taste(&bad_parse, 15432), 0);
    assert_eq!(taste.taste(&bind, 15432), 80);
    assert_eq!(taste.taste(&bad_bind, 15432), 0);
    assert_eq!(taste.taste(&bad_describe, 15432), 0);
    assert_eq!(taste.taste(&execute, 15432), 80);
    assert_eq!(taste.taste(&bad_execute, 15432), 0);
    assert_eq!(taste.taste(&function_call, 15432), 80);
    assert_eq!(taste.taste(&bad_function_call, 15432), 0);
    assert_eq!(taste.taste(&terminate, 15432), 80);
    assert_eq!(taste.taste(&bad_terminate, 15432), 0);
    assert_eq!(taste.taste(&startup, 15432), 85);
    assert_eq!(taste.taste(&startup[..startup.len() - 1], 15432), 0);
}

#[test]
fn test_coap_taste_recognizes_empty_messages() {
    let taste = CoapTaste;
    let empty_con = [0x40, 0x00, 0x12, 0x34];
    let empty_ack = [0x60, 0x00, 0x12, 0x34];
    let empty_rst = [0x70, 0x00, 0x12, 0x34];

    assert_eq!(taste.taste(&empty_con, 5683), 90);
    assert_eq!(taste.taste(&empty_ack, 5683), 90);
    assert_eq!(taste.taste(&empty_rst, 5683), 90);
    assert_eq!(taste.taste(&empty_ack, 5684), 50);
}

#[test]
fn test_redis_taste_rejects_trailing_junk_but_accepts_pipelined_requests() {
    let taste = RedisTaste;
    let valid = b"*1\r\n$4\r\nPING\r\n";
    let mut with_trailing = valid.to_vec();
    with_trailing.extend_from_slice(b"junk");
    let mut inline_with_trailing = b"PING\r\n".to_vec();
    inline_with_trailing.extend_from_slice(b"junk");
    let mut pipelined_resp = valid.to_vec();
    pipelined_resp.extend_from_slice(valid);
    let mut pipelined_resp_with_trailing = pipelined_resp.clone();
    pipelined_resp_with_trailing.extend_from_slice(b"junk");
    let pipelined_inline = b"PING\r\nINFO\r\n";
    let pipelined_inline_with_blank_line = b"PING\r\n\r\nINFO\r\n";
    let resp_with_blank_tail = b"*1\r\n$4\r\nPING\r\n\r\n";
    let inline_blank_then_junk = b"PING\r\n\r\njunk";

    assert_eq!(taste.taste(valid, 0), 80);
    assert_eq!(taste.taste(&with_trailing, 0), 0);
    assert_eq!(taste.taste(&inline_with_trailing, 0), 0);
    assert_eq!(taste.taste(&pipelined_resp, 0), 80);
    assert_eq!(taste.taste(&pipelined_resp_with_trailing, 0), 0);
    assert_eq!(taste.taste(pipelined_inline, 0), 80);
    assert_eq!(taste.taste(pipelined_inline_with_blank_line, 0), 80);
    assert_eq!(taste.taste(resp_with_blank_tail, 0), 80);
    assert_eq!(taste.taste(inline_blank_then_junk, 0), 0);
}

#[test]
fn test_ident_taste_rejects_lone_newline_suffixes() {
    let taste = IdentTaste;

    assert_eq!(taste.taste(b"6191, 23\r\n", 0), 75);
    assert_eq!(taste.taste(b"6191, 23\n", 0), 0);
    assert_eq!(taste.taste(b"6191, 23\r", 0), 0);
}

#[test]
fn test_ident_taste_rejects_embedded_crlf_injection() {
    let taste = IdentTaste;

    assert_eq!(taste.taste(b"6191, 23\r\nNICK test", 0), 0);
    assert_eq!(taste.taste(b"6191, 23\r\n", 0), 75);
}

#[test]
fn test_mysql_taste_recognizes_client_packets() {
    let taste = MysqlTaste;
    const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
    const CLIENT_SSL: u32 = 0x0000_0800;
    const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
    const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
    const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;
    const CLIENT_CONNECT_ATTRS: u32 = 0x0010_0000;
    let mut login = Vec::new();
    login.extend_from_slice(&0x0000_8200u32.to_le_bytes());
    login.extend_from_slice(&0u32.to_le_bytes());
    login.push(0x21);
    login.extend_from_slice(&[0; 23]);
    login.extend_from_slice(b"root\0");
    login.push(3);
    login.extend_from_slice(b"abc");

    let mut login_packet = Vec::from([
        (login.len() & 0xff) as u8,
        ((login.len() >> 8) & 0xff) as u8,
        ((login.len() >> 16) & 0xff) as u8,
        1,
    ]);
    login_packet.extend_from_slice(&login);

    let mut non_minimal_lenenc_login = Vec::new();
    non_minimal_lenenc_login.extend_from_slice(
        &(CLIENT_PROTOCOL_41 | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA).to_le_bytes(),
    );
    non_minimal_lenenc_login.extend_from_slice(&0u32.to_le_bytes());
    non_minimal_lenenc_login.push(0x21);
    non_minimal_lenenc_login.extend_from_slice(&[0; 23]);
    non_minimal_lenenc_login.extend_from_slice(b"root\0");
    non_minimal_lenenc_login.extend_from_slice(&[0xfc, 3, 0]);
    non_minimal_lenenc_login.extend_from_slice(b"abc");
    let mut non_minimal_lenenc_login_packet = Vec::from([
        (non_minimal_lenenc_login.len() & 0xff) as u8,
        ((non_minimal_lenenc_login.len() >> 8) & 0xff) as u8,
        ((non_minimal_lenenc_login.len() >> 16) & 0xff) as u8,
        1,
    ]);
    non_minimal_lenenc_login_packet.extend_from_slice(&non_minimal_lenenc_login);

    let mut malformed_login = login_packet.clone();
    malformed_login.extend_from_slice(b"junk");
    let len = malformed_login.len() - 4;
    malformed_login[0] = (len & 0xff) as u8;
    malformed_login[1] = ((len >> 8) & 0xff) as u8;
    malformed_login[2] = ((len >> 16) & 0xff) as u8;

    let legacy_login = [0x85, 0xa6, 0x00, 0x00, 0x00, b'r', b'o', b'o', b't', 0x00];
    let mut legacy_login_packet = Vec::from([
        (legacy_login.len() & 0xff) as u8,
        ((legacy_login.len() >> 8) & 0xff) as u8,
        ((legacy_login.len() >> 16) & 0xff) as u8,
        1,
    ]);
    legacy_login_packet.extend_from_slice(&legacy_login);
    let mut malformed_legacy_login_packet = legacy_login_packet.clone();
    malformed_legacy_login_packet.extend_from_slice(b"junk");
    let len = malformed_legacy_login_packet.len() - 4;
    malformed_legacy_login_packet[0] = (len & 0xff) as u8;
    malformed_legacy_login_packet[1] = ((len >> 8) & 0xff) as u8;
    malformed_legacy_login_packet[2] = ((len >> 16) & 0xff) as u8;

    let query = [0x03, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'1'];
    let mut query_packet = Vec::from([
        (query.len() & 0xff) as u8,
        ((query.len() >> 8) & 0xff) as u8,
        ((query.len() >> 16) & 0xff) as u8,
        2,
    ]);
    query_packet.extend_from_slice(&query);

    let ping = [0x0e];
    let mut ping_packet = Vec::from([1, 0, 0, 3]);
    ping_packet.extend_from_slice(&ping);
    let mut coalesced_query = query_packet.clone();
    coalesced_query.extend_from_slice(&ping_packet);
    let mut query_with_trailing_junk = query_packet.clone();
    query_with_trailing_junk.extend_from_slice(b"junk");

    let quit = [0x01];
    let mut quit_packet = Vec::from([1, 0, 0, 4]);
    quit_packet.extend_from_slice(&quit);

    let init_db = [0x02, b't', b'e', b's', b't'];
    let mut init_db_packet = Vec::from([
        (init_db.len() & 0xff) as u8,
        ((init_db.len() >> 8) & 0xff) as u8,
        ((init_db.len() >> 16) & 0xff) as u8,
        5,
    ]);
    init_db_packet.extend_from_slice(&init_db);

    let field_list = [0x04, b'u', b's', b'e', b'r', b's', 0x00, b'%'];
    let mut field_list_packet = Vec::from([
        (field_list.len() & 0xff) as u8,
        ((field_list.len() >> 8) & 0xff) as u8,
        ((field_list.len() >> 16) & 0xff) as u8,
        6,
    ]);
    field_list_packet.extend_from_slice(&field_list);
    let non_utf8_field_list = [0x04, b'u', 0xff, 0x00, b'%'];
    let mut non_utf8_field_list_packet = Vec::from([
        (non_utf8_field_list.len() & 0xff) as u8,
        ((non_utf8_field_list.len() >> 8) & 0xff) as u8,
        ((non_utf8_field_list.len() >> 16) & 0xff) as u8,
        6,
    ]);
    non_utf8_field_list_packet.extend_from_slice(&non_utf8_field_list);
    let unicode_space_field_list = [0x04, b'u', 0xc2, 0xa0, 0x00, b'%'];
    let mut unicode_space_field_list_packet = Vec::from([
        (unicode_space_field_list.len() & 0xff) as u8,
        ((unicode_space_field_list.len() >> 8) & 0xff) as u8,
        ((unicode_space_field_list.len() >> 16) & 0xff) as u8,
        6,
    ]);
    unicode_space_field_list_packet.extend_from_slice(&unicode_space_field_list);

    let attr_capabilities =
        CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_ATTRS;
    let mut bad_attrs_login = Vec::new();
    bad_attrs_login.extend_from_slice(&attr_capabilities.to_le_bytes());
    bad_attrs_login.extend_from_slice(&0u32.to_le_bytes());
    bad_attrs_login.push(0x21);
    bad_attrs_login.extend_from_slice(&[0; 23]);
    bad_attrs_login.extend_from_slice(b"root\0");
    bad_attrs_login.push(0);
    bad_attrs_login.extend_from_slice(b"mysql_native_password\0");
    bad_attrs_login.push(23);
    bad_attrs_login.push(12);
    bad_attrs_login.extend_from_slice(b"_client_name");
    bad_attrs_login.push(9);
    bad_attrs_login.extend_from_slice("net\u{00a0}trap".as_bytes());
    let mut bad_attrs_login_packet = Vec::from([
        (bad_attrs_login.len() & 0xff) as u8,
        ((bad_attrs_login.len() >> 8) & 0xff) as u8,
        ((bad_attrs_login.len() >> 16) & 0xff) as u8,
        1,
    ]);
    bad_attrs_login_packet.extend_from_slice(&bad_attrs_login);

    let bad_query = [0x03, b'S', b'E', b'L', b'\0'];
    let mut bad_query_packet = Vec::from([
        (bad_query.len() & 0xff) as u8,
        ((bad_query.len() >> 8) & 0xff) as u8,
        ((bad_query.len() >> 16) & 0xff) as u8,
        7,
    ]);
    bad_query_packet.extend_from_slice(&bad_query);

    assert_eq!(taste.taste(&login_packet, 15432), 75);
    assert_eq!(taste.taste(&non_minimal_lenenc_login_packet, 15432), 0);
    assert_eq!(taste.taste(&malformed_login, 15432), 0);
    assert_eq!(taste.taste(&legacy_login_packet, 15432), 75);
    assert_eq!(taste.taste(&malformed_legacy_login_packet, 15432), 0);
    assert_eq!(taste.taste(&query_packet, 15432), 80);
    assert_eq!(taste.taste(&coalesced_query, 15432), 0);
    assert_eq!(taste.taste(&query_packet.repeat(4096), 15432), 0);
    assert_eq!(taste.taste(&query_with_trailing_junk, 15432), 0);
    assert_eq!(taste.taste(&ping_packet, 15432), 80);
    assert_eq!(taste.taste(&quit_packet, 15432), 80);
    assert_eq!(taste.taste(&init_db_packet, 15432), 80);
    assert_eq!(taste.taste(&field_list_packet, 15432), 80);
    assert_eq!(taste.taste(&non_utf8_field_list_packet, 15432), 80);
    assert_eq!(taste.taste(&unicode_space_field_list_packet, 15432), 0);
    assert_eq!(taste.taste(&bad_attrs_login_packet, 15432), 0);
    assert_eq!(taste.taste(&bad_query_packet, 15432), 0);
    assert_eq!(
        taste.taste(&[0x04, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00], 15432),
        75
    );
    let malformed_ssl_request_short = Vec::from([
        0x10,
        0x00,
        0x00,
        0x01,
        (CLIENT_PROTOCOL_41 | CLIENT_SSL) as u8,
        ((CLIENT_PROTOCOL_41 | CLIENT_SSL) >> 8) as u8,
        ((CLIENT_PROTOCOL_41 | CLIENT_SSL) >> 16) as u8,
        ((CLIENT_PROTOCOL_41 | CLIENT_SSL) >> 24) as u8,
        0x00,
        0x00,
        0x00,
        0x00,
        0x21,
        0x00,
        0x00,
        0x00,
    ]);
    assert_eq!(taste.taste(&malformed_ssl_request_short, 15432), 0);
    let mut malformed_ssl_request = Vec::from([
        0x20,
        0x00,
        0x00,
        0x01,
        (CLIENT_PROTOCOL_41 | CLIENT_SSL) as u8,
        ((CLIENT_PROTOCOL_41 | CLIENT_SSL) >> 8) as u8,
        ((CLIENT_PROTOCOL_41 | CLIENT_SSL) >> 16) as u8,
        ((CLIENT_PROTOCOL_41 | CLIENT_SSL) >> 24) as u8,
        0x00,
        0x00,
        0x00,
        0x00,
        0x21,
        0x00,
        0x00,
        0x00,
    ]);
    malformed_ssl_request.resize(36, 0);
    malformed_ssl_request[13] = 0x01;
    assert_eq!(taste.taste(&malformed_ssl_request, 15432), 0);
    let mut ssl_request = malformed_ssl_request.clone();
    ssl_request[13] = 0x00;
    let tls_client_hello = minimal_tls_client_hello();
    let mut ssl_request_with_tls = ssl_request.clone();
    ssl_request_with_tls.extend_from_slice(&tls_client_hello);
    assert_eq!(taste.taste(&ssl_request, 15432), 75);
    assert_eq!(taste.taste(&ssl_request_with_tls, 15432), 75);
    assert_eq!(taste.taste(b"SELECT 1", 15432), 0);
}

#[test]
fn test_smtp_taste() {
    let taste = SmtpTaste;
    assert_eq!(taste.taste(&[], 25), 85);
    assert_eq!(taste.taste(&[], 587), 85);
    assert_eq!(taste.taste(b"HELO example.com", 8080), 90);
    assert_eq!(taste.taste(b"EHLO test", 0), 90);
    assert_eq!(taste.taste(b"MAIL FROM:<a@example.test> SIZE=1000", 0), 90);
    assert_eq!(
        taste.taste(b"RCPT TO:<b@example.test> NOTIFY=SUCCESS", 0),
        90
    );
    assert_eq!(taste.taste(b"VRFY root", 0), 90);
    assert_eq!(taste.taste(b"AUTH PLAIN dXNlcgBzZWNyZXQ=", 0), 90);
    assert_eq!(taste.taste(b"AUTH CRAM-MD5", 0), 90);
    assert_eq!(taste.taste(b"AUTH FOO initial", 0), 90);
    assert_eq!(taste.taste(b"NOOP", 0), 90);
    assert_eq!(taste.taste(b"RSET", 0), 90);
    assert_eq!(taste.taste(b"HELP", 0), 90);
    assert_eq!(taste.taste(b"STARTTLS", 0), 90);
    assert_eq!(taste.taste(b"X-EXPS", 0), 90);
    assert_eq!(taste.taste(b"X-EXCH50", 0), 90);
    assert_eq!(taste.taste(b"X-LINK2STATE", 0), 90);
    assert_eq!(taste.taste(b"NOOP ", 0), 0);
    assert_eq!(taste.taste(b"EHLO  example.com", 0), 0);
    assert_eq!(taste.taste(b"EHLO", 0), 0);
    assert_eq!(taste.taste(b"EHLO example.com extra", 0), 0);
    assert_eq!(taste.taste(b"DATA now", 0), 0);
    assert_eq!(taste.taste(b"MAIL FROM", 0), 0);
    assert_eq!(taste.taste(b"MAIL FROM:<a@example.test> extra", 0), 0);
    assert_eq!(taste.taste(b"RCPT TO:<>", 0), 0);
    assert_eq!(taste.taste(b"VRFY root extra", 0), 0);
    assert_eq!(taste.taste(b"AUTH CRAM-MD5 ignored", 0), 0);
    assert_eq!(taste.taste(b"AUTH FOO initial extra", 0), 0);
    assert_eq!(taste.taste(b"EHLO\texample.com", 0), 0);
    assert_eq!(taste.taste("EHLO\u{00a0}example.com".as_bytes(), 0), 0);
    assert_eq!(taste.taste(b"NOOP\n", 0), 0);
    assert_eq!(taste.taste(b"NOOP\r", 0), 0);
    assert_eq!(taste.taste(b"NOOP\r\n", 0), 90);
    assert_eq!(taste.taste(b"EXPN root", 0), 0);
    assert_eq!(taste.taste(b"EHLOXYZ example.com", 0), 0);
}

#[test]
fn test_command_tastes_reject_prefixed_verbs() {
    assert_eq!(FtpTaste.taste(b"LISTEN\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"RETRIEVE file\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"LIST\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"FEAT\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"OPTS UTF8 ON\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"PORT 127,0,0,1,7,138\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"EPRT |1|127.0.0.1|1930|\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"HOST example.test\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"REIN\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"SIZE payload.bin\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"MDTM payload.bin\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"MKD newdir\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"XMKD newdir\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"RMD olddir\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"XRMD olddir\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"DELE payload.bin\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"RNFR oldname\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"RNTO newname\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"STAT\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"ABOR\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"CDUP\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"NOOP\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"HELP\r\n", 0), 80);
    assert_eq!(FtpTaste.taste(b"LIST \r\n", 0), 0);
    assert_eq!(FtpTaste.taste(b"LIST\t\r\n", 0), 0);
    assert_eq!(FtpTaste.taste(b"USER\tname\r\n", 0), 0);
    assert_eq!(FtpTaste.taste(b"USER  name\r\n", 0), 0);
    assert_eq!(FtpTaste.taste(b"USER name\0extra\r\n", 0), 0);
    assert_eq!(FtpTaste.taste(b"LIST\n", 0), 0);
    assert_eq!(FtpTaste.taste(b"LIST\r", 0), 0);

    assert_eq!(Pop3Taste.taste(b"RETRIEVE 1\r\n", 0), 0);
    assert_eq!(Pop3Taste.taste(b"RETR 1\r\n", 0), 80);
    assert_eq!(Pop3Taste.taste(b"DELE 1\r\n", 0), 80);
    assert_eq!(Pop3Taste.taste(b"TOP 1 10\r\n", 0), 80);
    assert_eq!(Pop3Taste.taste(b"UIDL 1\r\n", 0), 80);
    assert_eq!(Pop3Taste.taste(b"APOP user digest\r\n", 0), 80);
    assert_eq!(Pop3Taste.taste(b"NOOP\r\n", 0), 80);
    assert_eq!(Pop3Taste.taste(b"RSET\r\n", 0), 80);
    assert_eq!(Pop3Taste.taste(b"USER alice\r\n", 0), 65);
    assert_eq!(Pop3Taste.taste(b"LIST\r\n", 0), 65);
    assert_eq!(Pop3Taste.taste(b"STAT \r\n", 0), 0);
    assert_eq!(Pop3Taste.taste(b"STAT extra\r\n", 0), 0);
    assert_eq!(Pop3Taste.taste(b"RETR\r\n", 0), 0);
    assert_eq!(Pop3Taste.taste(b"RETR nope\r\n", 0), 0);
    assert_eq!(Pop3Taste.taste(b"TOP 1\r\n", 0), 0);
    assert_eq!(Pop3Taste.taste(b"CAPA extra\r\n", 0), 0);
    assert_eq!(Pop3Taste.taste(b"USER\r\n", 0), 0);
    assert_eq!(Pop3Taste.taste(b"RETR  1\r\n", 0), 0);
    assert_eq!(Pop3Taste.taste("USER\u{00a0}alice\r\n".as_bytes(), 0), 0);
    assert_eq!(Pop3Taste.taste(b"STAT\n", 0), 0);
    assert_eq!(Pop3Taste.taste(b"STAT\r", 0), 0);
    assert_eq!(IrcTaste.taste(b"PING\tserver\r\n", 0), 0);

    assert_eq!(MemcachedTaste.taste(b"statsfoo\r\n", 0), 0);
    assert_eq!(MemcachedTaste.taste(b"stats\r\n", 0), 85);
    assert_eq!(MemcachedTaste.taste(b"STATS\r\n", 0), 85);
    assert_eq!(MemcachedTaste.taste(b"stats detail dump\r\n", 0), 85);
    assert_eq!(MemcachedTaste.taste(b"stats items\r\n", 0), 0);
    assert_eq!(MemcachedTaste.taste(b"stats slabs\r\n", 0), 0);
    assert_eq!(MemcachedTaste.taste(b"stats settings\r\n", 0), 0);
    assert_eq!(MemcachedTaste.taste(b"stats sizes\r\n", 0), 0);
    assert_eq!(MemcachedTaste.taste(b"stats\r\njunk", 0), 0);
    assert_eq!(MemcachedTaste.taste(b"stats\r\nversion\r\n", 0), 0);
    assert_eq!(MemcachedTaste.taste(b"stats", 0), 0);
    assert_eq!(MemcachedTaste.taste(b"stats\n", 0), 0);
    assert_eq!(MemcachedTaste.taste(b"gets cache-key\r\n", 0), 85);
    assert_eq!(MemcachedTaste.taste(b"gat 10 cache-key\r\n", 0), 85);
    assert_eq!(MemcachedTaste.taste(b"gats 10 cache-key\r\n", 0), 85);
    assert_eq!(MemcachedTaste.taste(b"get\tcache-key\r\n", 0), 0);
    assert_eq!(MemcachedTaste.taste(b"get cache-key\tother\r\n", 0), 0);
    assert_eq!(MemcachedTaste.taste(b"delete cache-key\r\n", 0), 85);
    assert_eq!(MemcachedTaste.taste(b"touch cache-key 10\r\n", 0), 85);
    assert_eq!(MemcachedTaste.taste(b"incr cache-key 1\r\n", 0), 85);
    assert_eq!(MemcachedTaste.taste(b"decr cache-key 1\r\n", 0), 85);
    assert_eq!(MemcachedTaste.taste(b"verbosity 1\r\n", 0), 85);
    assert_eq!(MemcachedTaste.taste(b"set cache-key\r\n", 0), 0);
    assert_eq!(
        MemcachedTaste.taste(b"SET cache-key 0 0 5\r\nhello\r\n", 0),
        85
    );
    assert_eq!(
        MemcachedTaste.taste(b"set cache-key 0 0 5\r\nhello\r\n", 0),
        85
    );
    assert_eq!(
        MemcachedTaste.taste(b"set cache-key 0 0 5\r\nhello\r\nget cache-key\r\n", 0),
        0
    );
    assert_eq!(MemcachedTaste.taste(b"deletex cache-key\r\n", 0), 0);
}

#[test]
fn test_syslog_taste_accepts_valid_pri_messages() {
    let taste = SyslogRecvTaste;

    assert_eq!(
        taste.taste(b"<13> Jan  1 00:00:00 host app: message", 514),
        90
    );
    assert_eq!(taste.taste(b"Jan  1 00:00:00 host app: message", 1514), 75);
    assert_eq!(
        taste.taste(b"<192> Jan  1 00:00:00 host app: message", 514),
        90
    );
    assert_eq!(taste.taste(b"<13> Jan  1 host app: message\r\n", 514), 90);
    assert_eq!(taste.taste(b"<13>message", 514), 90);
    assert_eq!(taste.taste(b"<13>message\xfftail", 514), 90);
    assert_eq!(taste.taste(b"<13>\tmessage", 514), 90);
    assert_eq!(taste.taste(b"<13>", 514), 0);
    assert_eq!(taste.taste(b"Jan xx 00:00:00 host app: message", 514), 0);
    assert_eq!(taste.taste(b"<13>message\n", 514), 0);
    assert_eq!(taste.taste(b"<13>message\r", 514), 0);
    assert_eq!(taste.taste(b"<13>line 1\r\nline 2", 514), 0);
    assert_eq!(taste.taste(b"<13>message\0", 514), 0);

    let mut oversized = b"<13> ".to_vec();
    oversized.extend(std::iter::repeat_n(b'a', 1024));
    assert_eq!(taste.taste(&oversized, 514), 0);
}

#[test]
fn test_memcached_taste_recognizes_binary_quiet_opcodes() {
    let taste = MemcachedTaste;

    assert_eq!(taste.taste(&memcached_binary_request(0x18, 0, 0, 0), 0), 75);
    assert_eq!(taste.taste(&memcached_binary_request(0x19, 0, 1, 1), 0), 75);
    assert_eq!(taste.taste(&memcached_binary_request(0x1a, 0, 1, 1), 0), 75);
    assert_eq!(taste.taste(&memcached_binary_request(0x1e, 4, 1, 0), 0), 75);
}

#[test]
fn test_memcached_taste_recognizes_late_binary_opcodes() {
    let taste = MemcachedTaste;

    assert_eq!(taste.taste(&memcached_binary_request(0x1b, 4, 0, 0), 0), 75);
    assert_eq!(taste.taste(&memcached_binary_request(0x1c, 4, 1, 0), 0), 75);
    assert_eq!(taste.taste(&memcached_binary_request(0x1d, 4, 1, 0), 0), 75);
    assert_eq!(taste.taste(&memcached_binary_request(0x1e, 4, 1, 0), 0), 75);
}

#[test]
fn test_memcached_text_taste_matches_ascii_separator_policy() {
    let taste = MemcachedTaste;

    assert_eq!(taste.taste(b"get\tkey\r\n", 0), 0);
    assert_eq!(taste.taste(b"set key 0 0  1\r\na\r\n", 0), 0);
    assert_eq!(taste.taste(b"get key\r\nget other\r\n", 0), 0);
    assert_eq!(taste.taste("get cache\u{009f}key\r\n".as_bytes(), 0), 0);
    assert_eq!(taste.taste("get\u{00a0}key\r\n".as_bytes(), 0), 0);
    assert_eq!(taste.taste(b"get key\tother\r\n", 0), 0);
}

#[test]
fn test_memcached_binary_taste_requires_complete_declared_body() {
    let taste = MemcachedTaste;
    let mut valid = vec![0u8; 25];
    valid[0] = 0x80;
    valid[1] = 0x00;
    valid[3] = 0x01;
    valid[11] = 0x01;
    valid[24] = b'k';

    let mut missing_body = valid[..24].to_vec();
    missing_body[11] = 0x01;
    let mut with_trailing_junk = valid.clone();
    with_trailing_junk.extend_from_slice(b"junk");
    let mut coalesced = valid.clone();
    coalesced.extend_from_slice(&valid);
    let mut coalesced_many = valid.clone();
    coalesced_many.extend_from_slice(&valid);
    coalesced_many.extend_from_slice(&valid);

    let mut inconsistent_metadata = vec![0u8; 25];
    inconsistent_metadata[0] = 0x80;
    inconsistent_metadata[1] = 0x00;
    inconsistent_metadata[3] = 0x02;
    inconsistent_metadata[11] = 0x01;

    assert_eq!(taste.taste(&valid, 0), 75);
    assert_eq!(taste.taste(&missing_body, 0), 0);
    assert_eq!(taste.taste(&with_trailing_junk, 0), 0);
    assert_eq!(taste.taste(&coalesced, 0), 0);
    assert_eq!(taste.taste(&coalesced_many, 0), 0);
    assert_eq!(taste.taste(&inconsistent_metadata, 0), 0);
}

#[test]
fn test_memcached_binary_taste_requires_opcode_shape() {
    let taste = MemcachedTaste;

    assert_eq!(taste.taste(&memcached_binary_request(0x00, 0, 1, 0), 0), 75);
    assert_eq!(taste.taste(&memcached_binary_request(0xff, 0, 0, 0), 0), 75);
    assert_eq!(taste.taste(&memcached_binary_request(0x00, 0, 0, 0), 0), 0);
    assert_eq!(taste.taste(&memcached_binary_request(0x00, 4, 1, 0), 0), 0);
    assert_eq!(taste.taste(&memcached_binary_request(0x1b, 0, 0, 0), 0), 0);
    assert_eq!(taste.taste(&memcached_binary_request(0x1c, 4, 0, 0), 0), 0);
}

#[test]
fn test_memcached_binary_taste_rejects_noncanonical_header_fields() {
    let taste = MemcachedTaste;
    let mut valid = vec![0u8; 25];
    valid[0] = 0x80;
    valid[1] = 0x00;
    valid[3] = 0x01;
    valid[11] = 0x01;
    valid[24] = b'k';

    let mut nonzero_data_type = valid.clone();
    nonzero_data_type[5] = 0x01;

    let mut nonzero_reserved = valid.clone();
    nonzero_reserved[7] = 0x01;

    assert_eq!(taste.taste(&valid, 0), 75);
    assert_eq!(taste.taste(&nonzero_data_type, 0), 0);
    assert_eq!(taste.taste(&nonzero_reserved, 0), 0);
}

#[test]
fn test_rdp_taste_requires_valid_tpkt_and_x224() {
    let taste = RdpTaste;
    let valid = [
        0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut invalid_class = valid;
    invalid_class[10] = 0x01;
    let truncated_x224 = [
        0x03, 0x00, 0x00, 0x0b, 0x07, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let garbage = b"not rdp";

    assert_eq!(taste.taste(&valid, 3389), 95);
    assert_eq!(taste.taste(&valid, 12345), 70);
    assert_eq!(taste.taste(&invalid_class, 12345), 0);
    assert_eq!(taste.taste(&truncated_x224, 3389), 40);
    assert_eq!(taste.taste(garbage, 3389), 40);
    assert_eq!(taste.taste(garbage, 12345), 0);
}

#[test]
fn test_smb_taste_requires_complete_smb_header() {
    let taste = SmbTaste;
    let mut smb2 = vec![0xfe, b'S', b'M', b'B'];
    smb2.extend_from_slice(&64u16.to_le_bytes());
    smb2.extend_from_slice(&[0; 62]);

    let mut netbios = vec![0x00, 0x00, 0x00, smb2.len() as u8];
    netbios.extend_from_slice(&smb2);
    let mut coalesced_netbios = netbios.clone();
    coalesced_netbios.extend_from_slice(&netbios);
    let mut coalesced_many_netbios = coalesced_netbios.clone();
    coalesced_many_netbios.extend_from_slice(&netbios);
    let mut netbios_with_junk = netbios.clone();
    netbios_with_junk.extend_from_slice(b"junk");
    let mut smb2_response = smb2.clone();
    smb2_response[16] = 0x01;

    assert_eq!(taste.taste(&smb2, 0), 95);
    assert_eq!(taste.taste(&netbios, 0), 95);
    assert_eq!(taste.taste(&coalesced_netbios, 0), 0);
    assert_eq!(taste.taste(&coalesced_many_netbios, 0), 0);
    assert_eq!(taste.taste(&netbios_with_junk, 0), 0);
    assert_eq!(taste.taste(&smb2_response, 0), 0);
    assert_eq!(taste.taste(b"\xfeSMB", 0), 0);
    assert_eq!(taste.taste(b"\xffSMB", 0), 0);
    assert_eq!(taste.taste(&[0xfe, b'S', b'M', b'B', 0, 0], 0), 0);
    assert_eq!(
        taste.taste(&[0x00, 0x02, 0x00, 0x04, 0xfe, b'S', b'M', b'B'], 0),
        0
    );
}

#[test]
fn test_redis_taste_requires_structured_command() {
    let taste = RedisTaste;

    assert_eq!(taste.taste(b"PING\r\n", 0), 80);
    assert_eq!(taste.taste(b"ECHO hello\r\n", 0), 80);
    assert_eq!(taste.taste(b"HELLO\r\n", 0), 80);
    assert_eq!(
        taste.taste(b"HELLO 3 AUTH alice secret SETNAME bob\r\n", 0),
        80
    );
    assert_eq!(taste.taste(b"TIME\r\n", 0), 80);
    assert_eq!(taste.taste(b"ROLE\r\n", 0), 80);
    assert_eq!(taste.taste(b"AUTH password\r\n", 0), 80);
    assert_eq!(taste.taste(b"DEL key other\r\n", 0), 80);
    assert_eq!(taste.taste(b"EXISTS key other\r\n", 0), 80);
    assert_eq!(taste.taste(b"MGET key other\r\n", 0), 80);
    assert_eq!(taste.taste(b"GETDEL key\r\n", 0), 80);
    assert_eq!(taste.taste(b"GETSET key value\r\n", 0), 80);
    assert_eq!(taste.taste(b"SETEX key 10 value\r\n", 0), 80);
    assert_eq!(taste.taste(b"PSETEX key 10 value\r\n", 0), 80);
    assert_eq!(taste.taste(b"SETNX key value\r\n", 0), 80);
    assert_eq!(taste.taste(b"MSET key value other value\r\n", 0), 80);
    assert_eq!(taste.taste(b"MSETNX key value other value\r\n", 0), 80);
    assert_eq!(taste.taste(b"INCR key\r\n", 0), 80);
    assert_eq!(taste.taste(b"DECR key\r\n", 0), 80);
    assert_eq!(taste.taste(b"INCRBY key -5\r\n", 0), 80);
    assert_eq!(taste.taste(b"DECRBY key +5\r\n", 0), 80);
    assert_eq!(taste.taste(b"EXPIRE key 10 NX\r\n", 0), 80);
    assert_eq!(taste.taste(b"PEXPIRE key 10\r\n", 0), 80);
    assert_eq!(taste.taste(b"EXPIREAT key 10 GT\r\n", 0), 80);
    assert_eq!(taste.taste(b"PEXPIREAT key 10 LT\r\n", 0), 80);
    assert_eq!(taste.taste(b"TTL key\r\n", 0), 80);
    assert_eq!(taste.taste(b"PTTL key\r\n", 0), 80);
    assert_eq!(taste.taste(b"EXPIRETIME key\r\n", 0), 80);
    assert_eq!(taste.taste(b"PEXPIRETIME key\r\n", 0), 80);
    assert_eq!(taste.taste(b"TYPE key\r\n", 0), 80);
    assert_eq!(taste.taste(b"STRLEN key\r\n", 0), 80);
    assert_eq!(taste.taste(b"CONFIG SET dir /tmp/\r\n", 0), 80);
    assert_eq!(taste.taste(b"SELECT 1\r\n", 0), 80);
    assert_eq!(taste.taste(b"CLIENT LIST\r\n", 0), 80);
    assert_eq!(taste.taste(b"EVAL return 1 0\r\n", 0), 80);
    assert_eq!(taste.taste(b"FLUSHDB\r\n", 0), 80);
    assert_eq!(taste.taste(b"DBSIZE\r\n", 0), 80);
    assert_eq!(taste.taste(b"COMMAND\r\n", 0), 80);
    assert_eq!(taste.taste(b"CLUSTER INFO\r\n", 0), 80);
    assert_eq!(taste.taste(b"SAVE\r\n", 0), 80);
    assert_eq!(taste.taste(b"SET key\r\n", 0), 0);
    assert_eq!(taste.taste(b"SET key value UNKNOWN\r\n", 0), 0);
    assert_eq!(taste.taste(b"CONFIG REWRITE\r\n", 0), 0);
    assert_eq!(taste.taste(b"CLIENT\r\n", 0), 80);
    assert_eq!(taste.taste(b"CLUSTER\r\n", 0), 80);
    assert_eq!(taste.taste(b"MODULE\r\n", 0), 80);
    assert_eq!(taste.taste(b"PING", 0), 0);
    assert_eq!(taste.taste(b"PING\n", 0), 0);
    assert_eq!(taste.taste(b"GET  key\r\n", 0), 0);
    assert_eq!(taste.taste("GET key\u{00a0}extra\r\n".as_bytes(), 0), 0);
    assert_eq!(taste.taste(b"*1\r\n$-1\r\n", 0), 0);
    assert_eq!(
        taste.taste(b"*2\r\n$4\r\nAUTH\r\n$8\r\npassword\r\n", 0),
        80
    );
    assert_eq!(taste.taste(b"*1\r\n$4\r\nPING\r\n", 0), 80);

    assert_eq!(taste.taste(b"PINGX\r\n", 0), 0);
    assert_eq!(taste.taste(b"ECHO\r\n", 0), 0);
    assert_eq!(taste.taste(b"HELLO 4\r\n", 0), 0);
    assert_eq!(taste.taste(b"TIME extra\r\n", 0), 0);
    assert_eq!(taste.taste(b"ROLE extra\r\n", 0), 0);
    assert_eq!(taste.taste(b"DEL\r\n", 0), 0);
    assert_eq!(taste.taste(b"SETEX key 0 value\r\n", 0), 0);
    assert_eq!(taste.taste(b"MSET key value other\r\n", 0), 0);
    assert_eq!(taste.taste(b"INCRBY key nope\r\n", 0), 0);
    assert_eq!(taste.taste(b"EXPIRE key nope\r\n", 0), 0);
    assert_eq!(taste.taste(b"EXPIRE key 10 BAD\r\n", 0), 0);
    assert_eq!(taste.taste(b"TTL\r\n", 0), 0);
    assert_eq!(taste.taste(b"INFOO\r\n", 0), 0);
    assert_eq!(taste.taste(b"AUTHZ password\r\n", 0), 0);
    assert_eq!(taste.taste(b"CONFIGX SET dir /tmp/\r\n", 0), 0);
    assert_eq!(taste.taste(b"SELECTED 1\r\n", 0), 0);
    assert_eq!(taste.taste(b"CLIENTS LIST\r\n", 0), 0);
    assert_eq!(taste.taste(b"EVALSHA1 123\r\n", 0), 0);
    assert_eq!(taste.taste(b"FLUSHDBX\r\n", 0), 0);
    assert_eq!(taste.taste(b"CLUSTERED INFO\r\n", 0), 0);
    assert_eq!(taste.taste(b"*garbage\r\n", 0), 0);
    assert_eq!(taste.taste(b"*+1\r\n$4\r\nPING\r\n", 0), 0);
    assert_eq!(taste.taste(b"*0\r\n", 0), 0);
    assert_eq!(taste.taste(b"*2", 0), 0);
    assert_eq!(taste.taste(b"*1\r\n", 0), 0);
    assert_eq!(taste.taste(b"*1\r\n$4\r\nPING", 0), 0);
    assert_eq!(taste.taste(b"*1\r\n$+4\r\nPING\r\n", 0), 0);
    assert_eq!(taste.taste(b"*1\r\n$65537\r\nPING\r\n", 0), 0);
}

#[test]
fn test_ident_taste_requires_unsigned_decimal_ports() {
    let taste = IdentTaste;

    assert_eq!(taste.taste(b"6191, 23\r\n", 0), 75);
    assert_eq!(taste.taste(b"+6191, 23\r\n", 0), 0);
    assert_eq!(taste.taste(b"6191, +23\r\n", 0), 0);
    assert_eq!(taste.taste(b"0, 23\r\n", 0), 0);
    assert_eq!(taste.taste(b"6191, 0\r\n", 0), 0);
    assert_eq!(taste.taste(b"6191, 23\t\r\n", 0), 0);
    let oversized = format!("6191,23{}\r\n", " ".repeat(IDENT_MAX_QUERY_LINE_BYTES));
    assert_eq!(taste.taste(oversized.as_bytes(), 0), 0);
}

#[test]
fn test_ident_taste_rejects_unicode_whitespace_padding() {
    let taste = IdentTaste;

    assert_eq!(taste.taste("6191,\u{00a0}23\r\n".as_bytes(), 0), 0);
    assert_eq!(taste.taste("\u{00a0}6191, 23\r\n".as_bytes(), 0), 0);
}

#[test]
fn test_sip_taste_requires_request_line() {
    let taste = SipTaste;
    let invite_no_body = b"INVITE sip:user@example.test SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1\r\nFrom: <sip:alice@example.test>\r\nTo: <sip:user@example.test>\r\nCall-ID: abc\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";
    let invite_with_body = b"INVITE sip:user@example.test SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1\r\nFrom: <sip:alice@example.test>\r\nTo: <sip:user@example.test>\r\nCall-ID: abc\r\nCSeq: 1 INVITE\r\nContent-Length: 4\r\n\r\ntest";
    let invite_with_bad_length = b"INVITE sip:user@example.test SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1\r\nFrom: <sip:alice@example.test>\r\nTo: <sip:user@example.test>\r\nCall-ID: abc\r\nCSeq: 1 INVITE\r\nContent-Length: 4\r\n\r\n";
    let invite_with_signed_length = b"INVITE sip:user@example.test SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1\r\nFrom: <sip:alice@example.test>\r\nTo: <sip:user@example.test>\r\nCall-ID: abc\r\nCSeq: 1 INVITE\r\nContent-Length: +0\r\n\r\n";
    let invite_with_mismatched_cseq = b"INVITE sip:user@example.test SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1\r\nFrom: <sip:alice@example.test>\r\nTo: <sip:user@example.test>\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
    let invite_with_tab_target = b"INVITE sip:user\talias@example.test SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1\r\nFrom: <sip:alice@example.test>\r\nTo: <sip:user@example.test>\r\nCall-ID: abc\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";
    let invite_with_space_prefixed_header = b"INVITE sip:user@example.test SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1\r\n From: <sip:alice@example.test>\r\nTo: <sip:user@example.test>\r\nCall-ID: abc\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";
    let message_request = b"MESSAGE sip:user@example.test SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1\r\nFrom: <sip:alice@example.test>\r\nTo: <sip:user@example.test>\r\nCall-ID: abc\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n";
    let mut valid_with_trailing = invite_no_body.to_vec();
    valid_with_trailing.extend_from_slice(b"junk");

    assert_eq!(taste.taste(b"SIP/2.0 200 OK\r\n", 5060), 0);
    assert_eq!(
        taste.taste(b"INVITE sip:user@example.test SIP/2.0\r\n", 5060),
        0
    );
    assert_eq!(taste.taste(invite_no_body, 5060), 90);
    assert_eq!(taste.taste(invite_with_body, 5060), 90);
    assert_eq!(taste.taste(invite_with_bad_length, 5060), 0);
    assert_eq!(taste.taste(invite_with_signed_length, 5060), 0);
    assert_eq!(taste.taste(invite_with_mismatched_cseq, 5060), 0);
    assert_eq!(taste.taste(invite_with_tab_target, 5060), 0);
    assert_eq!(taste.taste(invite_with_space_prefixed_header, 5060), 0);
    assert_eq!(taste.taste(&valid_with_trailing, 5060), 0);
    assert_eq!(taste.taste(message_request, 5060), 90);
    assert_eq!(
        taste.taste(b"INVITEX sip:user@example.test SIP/2.0\r\n", 5060),
        0
    );
}

#[test]
fn test_socks_taste_requires_structured_handshake_or_request() {
    let taste = SocksTaste;
    let connect_v4 = [0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x00, 0x50];
    let loopback_connect_v4 = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];
    let multicast_connect_v4 = [0x05, 0x01, 0x00, 0x01, 224, 0, 0, 1, 0x00, 0x50];
    let mapped_loopback_connect_v6 = [
        0x05, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1, 0x00, 0x50,
    ];
    let usable_connect_v6 = [
        0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00,
        0x50,
    ];
    let socks4_unspecified_ip = [0x04, 0x01, 0x00, 0x50, 0, 0, 0, 0, b'u', 0];
    let socks4_loopback_ip = [0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, b'u', 0];
    let socks4_multicast_ip = [0x04, 0x01, 0x00, 0x50, 224, 0, 0, 1, b'u', 0];
    let mut connect_v4_trailing = connect_v4.to_vec();
    connect_v4_trailing.push(0x00);

    assert_eq!(taste.taste(&[0x05, 0x01, 0x00], 0), 70);
    assert_eq!(taste.taste(&connect_v4, 0), 70);
    assert_eq!(
        taste.taste(
            &[
                0x05, 0x02, 0x02, 0x00, 0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x00, 0x50
            ],
            0
        ),
        0
    );
    assert_eq!(taste.taste(&[0x05, 0x01, 0x00].repeat(4096), 0), 0);
    assert_eq!(taste.taste(&loopback_connect_v4, 0), 0);
    assert_eq!(taste.taste(&multicast_connect_v4, 0), 0);
    assert_eq!(taste.taste(&mapped_loopback_connect_v6, 0), 0);
    assert_eq!(taste.taste(&usable_connect_v6, 0), 70);
    assert_eq!(taste.taste(&socks4_unspecified_ip, 0), 0);
    assert_eq!(taste.taste(&socks4_loopback_ip, 0), 0);
    assert_eq!(taste.taste(&socks4_multicast_ip, 0), 0);
    assert_eq!(taste.taste(&connect_v4_trailing, 0), 0);
    assert_eq!(taste.taste(&[0x05, 0x00], 0), 0);
    assert_eq!(taste.taste(&[0x05, 0x01, 0x02], 0), 70);
    assert_eq!(
        taste.taste(
            &[
                0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80
            ],
            0
        ),
        0
    );
    assert_eq!(
        taste.taste(&[0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, b'u', 0], 0),
        0
    );
    assert_eq!(
        taste.taste(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00], 0),
        0
    );
    assert_eq!(
        taste.taste(
            &[
                0x05, 0x01, 0x00, 0x03, 0x0c, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b't',
                b'e', b's', b't', 0x00, 0x00
            ],
            0
        ),
        70
    );
    assert_eq!(
        taste.taste(
            &[
                0x05, 0x01, 0x00, 0x03, 0x05, b'!', b'b', b'a', b'd', b'!', 0x04, 0x38,
            ],
            0
        ),
        0
    );
    assert_eq!(
        taste.taste(&[0x04, 0x01, 0x00, 0x00, 127, 0, 0, 1, b'u', 0], 0),
        0
    );

    assert_eq!(taste.taste(&[0x05, 0x00, 0x00], 0), 0);
    assert_eq!(taste.taste(&[0x05, 0x01], 0), 0);
    assert_eq!(
        taste.taste(&[0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, b'u'], 0),
        0
    );
}

#[test]
fn test_mqtt_taste_requires_complete_valid_connect_header() {
    let taste = MqttTaste;
    let valid_connect = [
        0x10, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x00, 0x00, 0x00,
    ];
    let mqtt_v5_connect = [
        0x10, 0x0d, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mqtt_v5_connect_non_minimal_properties = [
        0x10, 0x0e, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x05, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
        0x00,
    ];
    let mqtt_v5_connect_unknown_property = [
        0x10, 0x0e, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x05, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00,
        0x00,
    ];
    let mqtt_v5_connect_duplicate_property = [
        0x10, 0x13, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x05, 0x00, 0x00, 0x00, 0x06, 0x21, 0x00,
        0x01, 0x21, 0x00, 0x01, 0x00, 0x00,
    ];
    let mqtt_v5_connect_unknown_will_property = [
        0x10, 0x13, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x05, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0xff, 0x00, 0x00, 0x00, 0x00,
    ];
    let mqtt_v31_connect = [
        0x10, 0x0e, 0x00, 0x06, b'M', b'Q', b'I', b's', b'd', b'p', 0x03, 0x02, 0x00, 0x00, 0x00,
        0x00,
    ];
    let mut mqtt_v31_no_clean_empty_client_id = mqtt_v31_connect;
    mqtt_v31_no_clean_empty_client_id[11] = 0x00;
    let mut invalid_flags = valid_connect;
    invalid_flags[9] = 0x01;
    let mut trailing_bytes = valid_connect.to_vec();
    trailing_bytes.push(0x00);

    assert_eq!(taste.taste(&valid_connect, 0), 95);
    assert_eq!(taste.taste(&mqtt_v5_connect, 0), 95);
    assert_eq!(taste.taste(&mqtt_v5_connect_non_minimal_properties, 0), 0);
    assert_eq!(taste.taste(&mqtt_v5_connect_unknown_property, 0), 0);
    assert_eq!(taste.taste(&mqtt_v5_connect_duplicate_property, 0), 0);
    assert_eq!(taste.taste(&mqtt_v5_connect_unknown_will_property, 0), 0);
    assert_eq!(taste.taste(&mqtt_v31_connect, 0), 95);
    assert_eq!(taste.taste(&mqtt_v31_no_clean_empty_client_id, 0), 0);
    assert_eq!(taste.taste(&invalid_flags, 0), 0);
    assert_eq!(taste.taste(&trailing_bytes, 0), 0);
    assert_eq!(
        taste.taste(&[0x10, 0xff, 0xff, 0xff, 0xff, 0x00, 0x04], 0),
        0
    );
    assert_eq!(
        taste.taste(&[0x10, 0x8c, 0x00, 0x00, 0x04, b'M', b'Q', b'T', b'T'], 0),
        0
    );
    assert_eq!(
        taste.taste(&[0x10, 0x7f, 0x00, 0x04, b'M', b'Q', b'T', b'T'], 0),
        0
    );
    assert_eq!(
        taste.taste(&[0x11, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T'], 0),
        0
    );
}

#[test]
fn test_mqtt_taste_recognizes_common_client_packets() {
    let taste = MqttTaste;
    let publish = [0x30, 0x08, 0x00, 0x04, b't', b'e', b's', b't', b'h', b'i'];
    let subscribe = [
        0x82, 0x0e, 0x00, 0x01, 0x00, 0x09, b's', b'e', b'n', b's', b'o', b'r', b's', b'/', b'#',
        0x00,
    ];
    let pubrel = [0x62, 0x02, 0x00, 0x01];
    let unsubscribe = [0xa2, 0x05, 0x00, 0x01, 0x00, 0x01, b'a'];
    let pingreq = [0xC0, 0x00];
    let disconnect = [0xE0, 0x00];
    let disconnect_with_reason = [0xE0, 0x01, 0x00];

    assert_eq!(taste.taste(&publish, 0), 95);
    assert_eq!(taste.taste(&subscribe, 0), 95);
    assert_eq!(taste.taste(&pubrel, 0), 95);
    assert_eq!(taste.taste(&unsubscribe, 0), 95);
    assert_eq!(taste.taste(&pingreq, 0), 95);
    assert_eq!(taste.taste(&disconnect, 0), 95);
    assert_eq!(taste.taste(&disconnect_with_reason, 0), 95);
    assert_eq!(taste.taste(b"\x30\x08\x00\x04bad#hi", 0), 0);
    assert_eq!(taste.taste(b"\x82\x0e\x00\x01\x00\x09sensors/#\x03", 0), 0);
    assert_eq!(
        taste.taste(&[0xa2, 0x05, 0x00, 0x00, 0x00, 0x01, b'a'], 0),
        0
    );
    assert_eq!(taste.taste(&[0x62, 0x02, 0x00, 0x00], 0), 0);
    assert_eq!(taste.taste(&[0xe0, 0x01, 0xff], 0), 0);
}

#[test]
fn test_snmp_taste_requires_structured_request() {
    let taste = SnmpTaste;
    let valid_get_request = [
        0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x19,
        0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08,
        0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
    ];
    let mut noncanonical_request_id = valid_get_request.to_vec();
    noncanonical_request_id[1] = 0x27;
    noncanonical_request_id[14] = 0x1a;
    noncanonical_request_id[16] = 0x02;
    noncanonical_request_id.insert(17, 0x00);
    let mut negative_request_id = valid_get_request.to_vec();
    negative_request_id[17] = 0x80;
    let mut getbulk_v1 = valid_get_request.to_vec();
    getbulk_v1[4] = 0x00;
    getbulk_v1[13] = 0xa5;
    getbulk_v1[20] = 0x01;
    getbulk_v1[23] = 0x02;
    let mut response_pdu = valid_get_request;
    response_pdu[13] = 0xa2;

    assert_eq!(taste.taste(&valid_get_request, 0), 60);
    assert_eq!(taste.taste(&valid_get_request, 161), 90);
    assert_eq!(taste.taste(&noncanonical_request_id, 0), 0);
    assert_eq!(taste.taste(&negative_request_id, 0), 0);
    assert_eq!(taste.taste(&getbulk_v1, 0), 0);
    assert_eq!(taste.taste(&[0x30, 0x00, 0x02, 0x01, 0x01], 0), 0);
    assert_eq!(taste.taste(&[0x30, 0x26, 0x02, 0x01, 0x01], 0), 0);
    assert_eq!(taste.taste(&response_pdu, 0), 0);
}

#[test]
fn test_nkn_taste_requires_json_rpc() {
    let taste = NknTaste;
    let valid = br#"{"jsonrpc":"2.0","method":"getlatestblockheight","params":[],"id":1}"#;
    let unknown_method = br#"{"jsonrpc":"2.0","method":"unknown","params":[],"id":9}"#;
    let notification = br#"{"jsonrpc":"2.0","method":"unknown","params":[]}"#;
    let mut trailing = valid.to_vec();
    trailing.extend_from_slice(b"junk");

    assert_eq!(taste.taste(valid, 0), 90);
    assert_eq!(taste.taste(valid, 30001), 95);
    assert_eq!(taste.taste(unknown_method, 0), 0);
    assert_eq!(taste.taste(unknown_method, 30002), 95);
    assert_eq!(taste.taste(notification, 0), 0);
    assert_eq!(taste.taste(notification, 30002), 95);
    assert_eq!(taste.taste(&trailing, 0), 0);
    assert_eq!(taste.taste(b"garbage", 30001), 0);
    assert_eq!(taste.taste(b"noise \"jsonrpc\" getlatestblockheight", 0), 0);
}

#[test]
fn test_telnet_taste_rejects_ssh_banner_on_telnet_port() {
    let taste = TelnetTaste;

    assert_eq!(taste.taste(b"SSH-2.0-OpenSSH_9.6\r\n", 23), 0);
    assert_eq!(taste.taste(b"SSH-2.0-OpenSSH_9.6\r\n", 22), 0);
    assert!(taste.taste(&[0xFF, 0xFD, 0x01], 12345) > 0);
    assert_eq!(taste.taste(b"id\r\n", 23), 90);
}

#[test]
fn test_ssh_taste_requires_valid_client_version_banner() {
    let taste = SshTaste;

    assert_eq!(taste.taste(b"SSH-2.0-OpenSSH_9.6\r\n", 0), 95);
    assert_eq!(taste.taste(b"SSH-1.99-CompatClient\n", 0), 95);
    assert_eq!(taste.taste(b"", 22), 85);
    assert_eq!(taste.taste(b"SSH-\r\n", 22), 0);
    assert_eq!(taste.taste(b"SSH-2.0-\r\n", 22), 0);
    assert_eq!(taste.taste(b"SSH-2.0- bad\r\n", 22), 0);
    assert_eq!(taste.taste(b"SSH-1.5-OldClient\r\n", 22), 0);
    assert_eq!(taste.taste(b"SSH-2.0-OpenSSH_9.6", 22), 0);
    assert_eq!(taste.taste(b"SSH-2.0-OpenSSH_9.6\nignored", 22), 0);
    let max_lf_only = format!("SSH-2.0-{}\n", "a".repeat(246));
    assert_eq!(taste.taste(max_lf_only.as_bytes(), 0), 95);
}

#[test]
fn test_syslog_taste_validates_pri() {
    let taste = SyslogRecvTaste;

    assert_eq!(taste.taste(b"<13> message", 514), 90);
    assert_eq!(taste.taste(b"<13> message", 1514), 75);
    assert_eq!(taste.taste(b"<013>message", 514), 90);
    assert_eq!(taste.taste(b"<192>message", 514), 90);
    assert_eq!(taste.taste(b"<192>", 514), 0);
    assert_eq!(taste.taste(b"<abc>message", 514), 90);
    assert_eq!(taste.taste(b"garbage", 514), 0);
}

#[test]
fn test_raw_taste_fallback() {
    let taste = RawTaste;
    assert_eq!(taste.taste(&[], 0), 1);
    assert_eq!(taste.taste(b"any data", 12345), 1);
}
