use super::{
    MAX_UPNP_BODY_BYTES, MAX_UPNP_HEADER_BYTES, UpnpHandler, bounded_upnp_request_text,
    content_length_matches_body, headers_are_well_formed, request_log_preview, strict_header_value,
};

fn fixed_now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant")
}

#[test]
fn ssdp_m_search_gets_discovery_response() {
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";

    let response = UpnpHandler::new().with_now(fixed_now).handle_ssdp(request);

    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(String::from_utf8_lossy(&response).contains("DATE: Mon, 01 Jan 2024 00:00:00 GMT"));
    assert!(String::from_utf8_lossy(&response).contains("EXT:\r\n"));
    assert!(
        String::from_utf8_lossy(&response).contains("LOCATION: http://192.168.1.1:49152/desc.xml")
    );
}

#[test]
fn ssdp_m_search_rejects_unicode_whitespace_in_headers() {
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN:\xC2\xA0\"ssdp:discover\"\r\nMX: 1\r\nST:\xC2\xA0upnp:rootdevice\r\n\r\n";

    let response = UpnpHandler::new().handle_ssdp(request);

    assert!(response.is_empty());
}

#[test]
fn ssdp_m_search_requires_mandatory_discovery_headers() {
    let missing_host =
        b"M-SEARCH * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";
    let missing_mx = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: upnp:rootdevice\r\n\r\n";
    let malformed_mx = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: +1\r\nST: upnp:rootdevice\r\n\r\n";
    let zero_mx = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 0\r\nST: upnp:rootdevice\r\n\r\n";
    let large_mx = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 70000\r\nST: upnp:rootdevice\r\n\r\n";
    let duplicate_host = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";
    let wrong_host = b"M-SEARCH * HTTP/1.1\r\nHOST: example.com:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";
    let wrong_st = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:service:WANPPPConnection:1\r\n\r\n";

    assert!(UpnpHandler::new().handle_ssdp(missing_host).is_empty());
    assert!(UpnpHandler::new().handle_ssdp(missing_mx).is_empty());
    assert!(UpnpHandler::new().handle_ssdp(malformed_mx).is_empty());
    assert!(UpnpHandler::new().handle_ssdp(zero_mx).is_empty());
    assert!(!UpnpHandler::new().handle_ssdp(large_mx).is_empty());
    assert!(UpnpHandler::new().handle_ssdp(duplicate_host).is_empty());
    assert!(UpnpHandler::new().handle_ssdp(wrong_host).is_empty());
    assert!(UpnpHandler::new().handle_ssdp(wrong_st).is_empty());
}

#[test]
fn ssdp_m_search_accepts_ssdp_all_search_target() {
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";

    assert!(!UpnpHandler::new().handle_ssdp(request).is_empty());
}

#[test]
fn ssdp_m_search_echoes_service_search_target_in_response() {
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\r\n";

    let response = UpnpHandler::new().handle_ssdp(request);
    let response_text = String::from_utf8_lossy(&response);

    assert!(response_text.contains("ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n"));
    assert!(
        response_text
            .contains("USN: uuid:nettrap::urn:schemas-upnp-org:service:WANIPConnection:1\r\n")
    );
}

#[test]
fn ssdp_m_search_echoes_uuid_search_target_in_response() {
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: uuid:nettrap\r\n\r\n";

    let response = UpnpHandler::new().handle_ssdp(request);
    let response_text = String::from_utf8_lossy(&response);

    assert!(response_text.contains("ST: uuid:nettrap\r\n"));
    assert!(response_text.contains("USN: uuid:nettrap\r\n"));
}

#[test]
fn configured_listen_ip_cannot_inject_ssdp_headers() {
    let handler = UpnpHandler::new().with_listen_ip("10.0.0.1\r\nX-Injected: yes");

    assert!(handler.is_err());
}

#[test]
fn configured_listen_ip_cannot_inject_device_description_xml() {
    let handler = UpnpHandler::new().with_listen_ip("10.0.0.1</URLBase><Injected>yes");

    assert!(handler.is_err());
}

#[test]
fn configured_ipv6_listen_ip_is_bracketed_in_urls() {
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";

    let response = UpnpHandler::new()
        .with_listen_ip("2001:db8::1")
        .expect("valid listen ip")
        .handle_ssdp(request);
    let response_text = String::from_utf8_lossy(&response);

    assert!(response_text.contains("LOCATION: http://[2001:db8::1]:49152/desc.xml\r\n"));
}

#[test]
fn configured_ipv4_mapped_listen_ip_is_canonicalized_in_urls() {
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";

    let response = UpnpHandler::new()
        .with_listen_ip("[::ffff:203.0.113.10]")
        .expect("valid listen ip")
        .handle_ssdp(request);
    let response_text = String::from_utf8_lossy(&response);

    assert!(response_text.contains("LOCATION: http://203.0.113.10:49152/desc.xml\r\n"));

    let desc = UpnpHandler::new()
        .with_listen_ip("[::ffff:203.0.113.10]")
        .expect("valid listen ip")
        .handle_http(b"GET /desc.xml HTTP/1.1\r\nHost: 203.0.113.10:49152\r\n\r\n");
    let desc_text = String::from_utf8_lossy(&desc);

    assert!(desc_text.contains("<URLBase>http://203.0.113.10:49152/</URLBase>"));
}

#[test]
fn ssdp_does_not_handle_soap_actions() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\n\r\nAddPortMapping";

    let response = UpnpHandler::new().handle_ssdp(request);

    assert!(response.is_empty());
}

#[test]
fn ssdp_rejects_trailing_body_after_headers() {
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\nGARBAGE";

    let response = UpnpHandler::new().handle_ssdp(request);

    assert!(response.is_empty());
}

#[test]
fn ssdp_rejects_truncated_headers_without_blank_line() {
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: upnp:rootdevice";

    let response = UpnpHandler::new().handle_ssdp(request);

    assert!(response.is_empty());
}

#[test]
fn ssdp_rejects_oversized_headers() {
    let mut request = b"M-SEARCH * HTTP/1.1\r\nHOST: ".to_vec();
    request.extend(std::iter::repeat_n(b'a', MAX_UPNP_HEADER_BYTES));
    request.extend_from_slice(b"\r\n\r\n");

    let response = UpnpHandler::new().handle_ssdp(&request);

    assert!(response.is_empty());
}

#[test]
fn ssdp_rejects_empty_search_target() {
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST:   \r\n\r\n";

    let response = UpnpHandler::new().handle_ssdp(request);

    assert!(response.is_empty());
}

#[test]
fn http_get_desc_xml_returns_device_description() {
    let response = UpnpHandler::new()
        .with_listen_ip("10.0.0.1")
        .expect("valid listen ip")
        .handle_http(b"GET /desc.xml HTTP/1.1\r\nHost: 10.0.0.1:49152\r\n\r\n");
    let response_text = String::from_utf8_lossy(&response);

    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(response_text.contains("<friendlyName>NetTrap UPnP Gateway</friendlyName>"));
    assert!(response_text.contains("http://10.0.0.1:49152/"));
    assert!(!response_text.contains("eventSubURL"));
}

#[test]
fn http_11_rejects_missing_host_header() {
    let get = b"GET /desc.xml HTTP/1.1\r\n\r\n";
    let post = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nContent-Length: 14\r\n\r\nAddPortMapping";

    assert!(UpnpHandler::new().handle_http(get).is_empty());
    assert!(UpnpHandler::new().handle_http(post).is_empty());
}

#[test]
fn http_get_wanipconn_scpd_returns_action_list() {
    let response =
        UpnpHandler::new().handle_http(b"GET /wanipconnSCPD.xml HTTP/1.1\r\nHost: router\r\n\r\n");
    let response_text = String::from_utf8_lossy(&response);

    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(response_text.contains("<name>GetExternalIPAddress</name>"));
    assert!(response_text.contains("<name>AddPortMapping</name>"));
    assert!(response_text.contains("<name>DeletePortMapping</name>"));
}

#[test]
fn configured_listen_ip_rejects_invalid_input() {
    let handler = UpnpHandler::new().with_listen_ip("10.0.0.1\r\nX-Injected: yes");

    assert!(handler.is_err());
}

#[test]
fn configured_listen_ip_rejects_host_port_suffix() {
    let handler = UpnpHandler::new().with_listen_ip("example.com:1900");

    assert!(handler.is_err());
}

#[test]
fn configured_listen_ip_rejects_numeric_hostname() {
    let handler = UpnpHandler::new().with_listen_ip("12345");

    assert!(handler.is_err());
}

#[test]
fn configured_listen_ip_rejects_leading_whitespace() {
    let handler = UpnpHandler::new().with_listen_ip(" 10.0.0.1");

    assert!(handler.is_err());
}

#[test]
fn configured_listen_ip_rejects_unspecified_addresses() {
    assert!(UpnpHandler::new().with_listen_ip("0.0.0.0").is_err());
    assert!(UpnpHandler::new().with_listen_ip("::").is_err());
    assert!(UpnpHandler::new().with_listen_ip("::ffff:0.0.0.0").is_err());
}

#[test]
fn configured_listen_ip_rejects_loopback_addresses() {
    assert!(UpnpHandler::new().with_listen_ip("127.0.0.1").is_err());
    assert!(UpnpHandler::new().with_listen_ip("::1").is_err());
    assert!(
        UpnpHandler::new()
            .with_listen_ip("::ffff:127.0.0.1")
            .is_err()
    );
}

#[test]
fn configured_listen_ip_rejects_multicast_and_broadcast_addresses() {
    for ip in [
        "224.0.0.1",
        "239.255.255.250",
        "255.255.255.255",
        "224,0,0,1",
        "239,255,255,250",
        "255,255,255,255",
        "::ffff:224.0.0.1",
        "::ffff:255.255.255.255",
    ] {
        assert!(UpnpHandler::new().with_listen_ip(ip).is_err(), "{ip}");
    }
}

#[test]
fn http_post_add_port_mapping_returns_soap_response() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nContent-Length: 14\r\n\r\nAddPortMapping";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(String::from_utf8_lossy(&response).contains("AddPortMappingResponse"));
}

#[test]
fn http_post_get_external_ip_address_returns_soap_response() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"\r\nContent-Length: 0\r\n\r\n";

    let response = UpnpHandler::new().handle_http(request);
    let response_text = String::from_utf8_lossy(&response);

    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(response_text.contains("<NewExternalIPAddress>"));
}

#[test]
fn http_post_get_external_ip_address_falls_back_to_literal_ip_for_hostnames() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"\r\nContent-Length: 0\r\n\r\n";

    let response = UpnpHandler::new()
        .with_listen_ip("example.com")
        .expect("valid listen ip")
        .handle_http(request);
    let response_text = String::from_utf8_lossy(&response);

    assert!(response_text.contains("<NewExternalIPAddress>192.168.1.1</NewExternalIPAddress>"));
}

#[test]
fn http_post_get_external_ip_address_canonicalizes_ipv4_mapped_listen_ip() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"\r\nContent-Length: 0\r\n\r\n";

    let response = UpnpHandler::new()
        .with_listen_ip("[::ffff:203.0.113.10]")
        .expect("valid listen ip")
        .handle_http(request);
    let response_text = String::from_utf8_lossy(&response);

    assert!(response_text.contains("<NewExternalIPAddress>203.0.113.10</NewExternalIPAddress>"));
}

#[test]
fn http_post_accepts_body_with_bare_lf_line_endings() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nContent-Length: 8\r\n\r\n<a>\n</a>";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
}

#[test]
fn http_post_requires_matching_content_length_for_body() {
    let missing_length = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\n\r\nAddPortMapping";
    assert!(UpnpHandler::new().handle_http(missing_length).is_empty());

    let mismatched_length = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nContent-Length: 13\r\n\r\nAddPortMapping";
    assert!(UpnpHandler::new().handle_http(mismatched_length).is_empty());

    let signed_length = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nContent-Length: +14\r\n\r\nAddPortMapping";
    assert!(UpnpHandler::new().handle_http(signed_length).is_empty());

    let invalid_duplicate_length = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nContent-Length: abc\r\nContent-Length: 14\r\n\r\nAddPortMapping";
    assert!(
        UpnpHandler::new()
            .handle_http(invalid_duplicate_length)
            .is_empty()
    );

    let duplicate_length = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nContent-Length: 14\r\nContent-Length: 14\r\n\r\nAddPortMapping";
    assert!(UpnpHandler::new().handle_http(duplicate_length).is_empty());
}

#[test]
fn http_post_rejects_transfer_encoding_even_with_matching_content_length() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nTransfer-Encoding: chunked\r\nContent-Length: 14\r\n\r\nAddPortMapping";

    assert!(UpnpHandler::new().handle_http(request).is_empty());
}

#[test]
fn bounded_upnp_request_text_decodes_headers_only() {
    let request =
        b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nContent-Length: 4\r\n\r\nBODY";

    let (text, body_start, body_len) =
        bounded_upnp_request_text(request, MAX_UPNP_BODY_BYTES).expect("valid request");

    assert!(text.ends_with("\r\n\r\n"));
    assert!(!text.contains("BODY"));
    assert_eq!(body_start, request.len() - 4);
    assert_eq!(body_len, 4);
}

#[test]
fn http_post_rejects_oversized_body_before_text_parsing() {
    let mut request = format!(
            "POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nContent-Length: {}\r\n\r\n",
            MAX_UPNP_BODY_BYTES + 1
        )
        .into_bytes();
    request.extend(std::iter::repeat_n(b'a', MAX_UPNP_BODY_BYTES + 1));

    let response = UpnpHandler::new().handle_http(&request);

    assert!(response.is_empty());
}

#[test]
fn http_post_accepts_chunked_body_at_max_size() {
    let body = "a".repeat(MAX_UPNP_BODY_BYTES);
    let request = format!(
        "POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{}\r\n0\r\n\r\n",
        body.len(),
        body
    );

    let response = UpnpHandler::new().handle_http(request.as_bytes());

    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
}

#[test]
fn http_post_accepts_chunked_body_with_valid_extensions() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nTransfer-Encoding: chunked\r\n\r\n4 ; foo = bar\r\ntest\r\n0\r\n\r\n";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
}

#[test]
fn http_post_chunked_body_uses_original_byte_offset_after_obs_text_headers() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nX-Trace: \xff\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
}

#[test]
fn http_post_accepts_quoted_pair_escaped_space_and_quote_in_chunk_extension() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=\"bar\\\"baz\\ space\"\r\ntest\r\n0\r\n\r\n";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
}

#[test]
fn http_post_rejects_invalid_chunk_extensions() {
    let invalid_token =
            b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nTransfer-Encoding: chunked\r\n\r\n4;foo@=bar\r\ntest\r\n0\r\n\r\n";
    let invalid_value =
            b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=bar@\r\ntest\r\n0\r\n\r\n";
    let invalid_escaped =
            b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=\"bar\\\0baz\"\r\ntest\r\n0\r\n\r\n";

    assert!(UpnpHandler::new().handle_http(invalid_token).is_empty());
    assert!(UpnpHandler::new().handle_http(invalid_value).is_empty());
    assert!(UpnpHandler::new().handle_http(invalid_escaped).is_empty());
}

#[test]
fn http_post_rejects_oversized_chunked_body_before_buffering() {
    let body = "a".repeat(MAX_UPNP_BODY_BYTES + 1);
    let request = format!(
        "POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{}\r\n0\r\n\r\n",
        body.len(),
        body
    );

    let response = UpnpHandler::new().handle_http(request.as_bytes());

    assert!(response.is_empty());
}

#[test]
fn http_post_rejects_oversized_chunk_metadata() {
    let extension = "a".repeat(MAX_UPNP_HEADER_BYTES + 1);
    let request = format!(
        "POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nTransfer-Encoding: chunked\r\n\r\n1;{}\r\na\r\n0\r\n\r\n",
        extension
    );

    let response = UpnpHandler::new().handle_http(request.as_bytes());

    assert!(response.is_empty());
}

#[test]
fn http_post_rejects_duplicate_soap_action_headers() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping\"\r\nContent-Length: 14\r\n\r\nAddPortMapping";

    assert!(UpnpHandler::new().handle_http(request).is_empty());
}

#[test]
fn http_post_rejects_duplicate_soap_action_when_one_is_padded() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping\"   \r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nContent-Length: 14\r\n\r\nAddPortMapping";

    assert!(UpnpHandler::new().handle_http(request).is_empty());
}

#[test]
fn logged_http_request_preview_is_single_line() {
    let preview = request_log_preview(
        "POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\x1b\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\x08\r\n\r\n",
    );

    assert!(preview.contains("POST /upnp/control/WANIPConn1 HTTP/1.1 | Host: router "));
    assert!(!preview.chars().any(char::is_control));
}

#[test]
fn http_post_rejects_action_prefix_match() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#NotAddPortMapping\"\r\nContent-Length: 17\r\n\r\nNotAddPortMapping";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.is_empty());
}

#[test]
fn http_post_rejects_malformed_double_quoted_action() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\"\r\nContent-Length: 14\r\n\r\nAddPortMapping";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.is_empty());
}

#[test]
fn http_post_rejects_leading_unicode_whitespace_in_soap_action() {
    let request = "POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \u{00a0}\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nContent-Length: 14\r\n\r\nAddPortMapping";

    let response = UpnpHandler::new().handle_http(request.as_bytes());

    assert!(response.is_empty());
}

#[test]
fn http_post_rejects_whitespace_padded_soap_action() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"   \r\nContent-Length: 14\r\n\r\nAddPortMapping";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.is_empty());
}

#[test]
fn http_rejects_unsupported_http_version() {
    let response =
        UpnpHandler::new().handle_http(b"GET /desc.xml HTTP/2.0\r\nHost: 10.0.0.1:49152\r\n\r\n");

    assert!(response.is_empty());
}

#[test]
fn http_rejects_malformed_headers() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nBroken-Header\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\n\r\n";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.is_empty());
}

#[test]
fn http_rejects_header_names_with_internal_whitespace() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nBad Header: value\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\n\r\n";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.is_empty());
}

#[test]
fn http_rejects_headers_with_leading_whitespace() {
    let request = b"GET /desc.xml HTTP/1.1\r\n Host: 10.0.0.1:49152\r\n\r\n";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.is_empty());
}

#[test]
fn http_rejects_truncated_headers_without_blank_line() {
    let request = b"GET /desc.xml HTTP/1.1\r\nHost: 10.0.0.1:49152";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.is_empty());
}

#[test]
fn http_accepts_obs_text_in_header_values() {
    let request = b"GET /desc.xml HTTP/1.1\r\nHost: router\xff\r\n\r\n";

    let response = UpnpHandler::new().handle_http(request);

    assert!(!response.is_empty());
}

#[test]
fn http_rejects_control_bytes_in_header_values() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\x1b\r\nContent-Length: 14\r\n\r\nAddPortMapping";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.is_empty());
}

#[test]
fn http_rejects_bare_lf_line_endings() {
    let request = b"GET /desc.xml HTTP/1.1\nHost: 10.0.0.1:49152\n\n";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.is_empty());
}

#[test]
fn http_accepts_unicode_line_separators_in_headers() {
    let request = "GET /desc.xml HTTP/1.1\r\nHost: 10.0.0.1:49152\u{2028}X: injected\r\n\r\n";

    let response = UpnpHandler::new().handle_http(request.as_bytes());

    assert!(!response.is_empty());
}

#[test]
fn http_rejects_bare_cr_line_endings_in_headers() {
    let request = b"GET /desc.xml HTTP/1.1\r\r\nHost: 10.0.0.1:49152\r\r\n\r\n";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.is_empty());
}

#[test]
fn http_rejects_unicode_line_separators_in_request_line() {
    let request = "GET /desc.xml HTTP/1.1\u{2028}Host: 10.0.0.1:49152\r\n\r\n";

    let response = UpnpHandler::new().handle_http(request.as_bytes());

    assert!(response.is_empty());
}

#[test]
fn http_rejects_embedded_nul_bytes_in_request_line() {
    let request = b"GET /desc.xml HTTP/1.1\0Host: 10.0.0.1:49152\r\n\r\n";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.is_empty());
}

#[test]
fn ssdp_accepts_obs_text_in_header_values() {
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nX-Test: hi\x85\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";

    let response = UpnpHandler::new().handle_ssdp(request);

    assert!(!response.is_empty());
}

#[test]
fn ssdp_rejects_unicode_line_separators_in_headers() {
    let request = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\u{2028}X: injected\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";

    let response = UpnpHandler::new().handle_ssdp(request.as_bytes());

    assert!(response.is_empty());
}

#[test]
fn ssdp_rejects_bare_cr_line_endings_in_headers() {
    let request = b"M-SEARCH * HTTP/1.1\r\r\nHOST: 239.255.255.250:1900\r\r\nMAN: \"ssdp:discover\"\r\r\nMX: 1\r\r\nST: upnp:rootdevice\r\r\n\r\n";

    let response = UpnpHandler::new().handle_ssdp(request);

    assert!(response.is_empty());
}

#[test]
fn ssdp_rejects_unicode_line_separators_in_request_line() {
    let request = "M-SEARCH * HTTP/1.1\u{2028}HOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";

    let response = UpnpHandler::new().handle_ssdp(request.as_bytes());

    assert!(response.is_empty());
}

#[test]
fn http_post_without_soap_action_is_not_upnp() {
    let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\n\r\nAddPortMapping";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.is_empty());
}

#[test]
fn http_post_with_multiline_soap_body_is_accepted() {
    let body = concat!(
        "<s:Envelope>\r\n",
        "<s:Body>\r\n",
        "alpha\u{2028}beta\r\n",
        "</s:Body>\r\n",
        "</s:Envelope>\r\n",
    );
    let request = format!(
        "POST /upnp/control/WANIPConn1 HTTP/1.1\r\n\
Host: router\r\n\
SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\n\
Content-Length: {}\r\n\
\r\n\
{}",
        body.len(),
        body
    );

    assert!(headers_are_well_formed(&request));
    assert!(content_length_matches_body(&request, body.len()));
    assert_eq!(
        strict_header_value(&request, "SOAPAction"),
        Some(" \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"")
    );

    let response = UpnpHandler::new().handle_http(request.as_bytes());

    assert!(!response.is_empty());
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK"));
}

#[test]
fn http_post_on_wrong_path_is_not_upnp() {
    let request = b"POST /submit HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nContent-Length: 14\r\n\r\nAddPortMapping";

    let response = UpnpHandler::new().handle_http(request);

    assert!(response.is_empty());
}

#[test]
fn configured_listen_ip_rejects_unicode_whitespace() {
    let handler = UpnpHandler::new().with_listen_ip("192.168.1.1\u{00a0}");

    assert!(handler.is_err());
}

#[test]
fn configured_listen_ip_accepts_absolute_hostnames_with_trailing_dots() {
    let hostname = format!(
        "{}.{}.{}.{}.",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let normalized = hostname
        .strip_suffix('.')
        .expect("hostname should end with dot");

    let handler = UpnpHandler::new()
        .with_listen_ip(&hostname)
        .expect("absolute hostname should be accepted");
    let response = String::from_utf8(handler.handle_ssdp(
            b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n",
        ))
        .expect("response should be utf8");

    assert!(response.contains(&format!(
        "LOCATION: http://{}:49152/desc.xml\r\n",
        normalized
    )));
}

#[test]
fn configured_listen_ip_canonicalizes_hostname_case() {
    let upper = UpnpHandler::new()
        .with_listen_ip("UPNP.EXAMPLE.")
        .expect("absolute hostname should be accepted");
    let lower = UpnpHandler::new()
        .with_listen_ip("upnp.example")
        .expect("absolute hostname should be accepted");

    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";
    assert_eq!(upper.handle_ssdp(request), lower.handle_ssdp(request));
}
