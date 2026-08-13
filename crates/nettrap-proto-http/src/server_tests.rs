use super::{
    HttpRequest, HttpResponse, HttpServer, MAX_CUSTOM_RESPONSE_PATH_BYTES, MAX_CUSTOM_RESPONSES,
    MAX_RESPONSE_BODY_BYTES,
};
use crate::prelude::Error;

#[test]
fn parse_rejects_truncated_post_body() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhel";

    let Ok(parsed) = HttpRequest::parse(request) else {
        panic!("parser should not error");
    };
    assert!(parsed.is_none(), "truncated body should remain incomplete");
}

#[test]
fn parse_accepts_complete_post_body() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello";

    let Ok(parsed) = HttpRequest::parse(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("complete request should parse");
    };

    assert_eq!(parsed.uri, "/upload");
    assert_eq!(parsed.body, b"hello");
    assert!(parsed.has_body);
    assert_eq!(parsed.host.as_deref(), Some("example.test"));
    assert_eq!(
        parsed.headers.get("content-length").map(String::as_str),
        Some("5")
    );
}

#[test]
fn parse_preserves_original_request_target_as_uri() {
    let request =
        b"GET http://example.test/alpha/../gate?id=1 HTTP/1.1\r\nHost: example.test\r\n\r\n";

    let Ok(Some(parsed)) = HttpRequest::parse(request) else {
        panic!("absolute-form request should parse");
    };

    assert_eq!(parsed.uri, "http://example.test/alpha/../gate?id=1");
    assert_eq!(parsed.host.as_deref(), Some("example.test"));
}

#[test]
fn parse_preserves_explicit_empty_body_framing() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n";

    let Ok(Some(parsed)) = HttpRequest::parse(request) else {
        panic!("request should parse");
    };

    assert!(parsed.has_body);
    assert!(parsed.body.is_empty());
}

#[test]
fn parse_normalizes_host_header_case_and_absolute_form() {
    let request = b"GET / HTTP/1.1\r\nHost: EXAMPLE.TEST.:8080\r\n\r\n";

    let Ok(Some(parsed)) = HttpRequest::parse(request) else {
        panic!("request should parse");
    };

    assert_eq!(parsed.host.as_deref(), Some("example.test:8080"));
    assert_eq!(
        parsed.headers.get("host").map(String::as_str),
        Some("example.test:8080")
    );
}

#[test]
fn parse_rejects_fallback_to_absolute_form_authority_when_host_header_is_invalid() {
    let request = b"GET http://example.test/index.html HTTP/1.0\r\nHost: bad name\r\n\r\n";

    let Ok(Some(parsed)) = HttpRequest::parse(request) else {
        panic!("request should parse");
    };

    assert_eq!(parsed.host, None);
    assert_eq!(
        parsed.headers.get("host").map(String::as_str),
        Some("bad name")
    );
}

#[test]
fn parse_rejects_absolute_form_authority_with_backslash() {
    let request = b"GET http://example.test\\evil/index.html HTTP/1.0\r\nX-Test: 1\r\n\r\n";

    assert!(HttpRequest::parse(request).is_err());
}

#[test]
fn parse_rejects_duplicate_host_headers_even_with_absolute_form_target() {
    let request = b"GET http://example.test/index.html HTTP/1.0\r\nHost: example.test\r\nHost: example.net\r\n\r\n";

    assert!(HttpRequest::parse(request).unwrap().is_none());
}

#[test]
fn parse_uses_absolute_form_authority_without_host_header() {
    let request = b"GET http://example.test:8080/index.html HTTP/1.0\r\nX-Test: 1\r\n\r\n";

    let Ok(Some(parsed)) = HttpRequest::parse(request) else {
        panic!("request should parse");
    };

    assert_eq!(parsed.host.as_deref(), Some("example.test:8080"));
}

#[test]
fn parse_rejects_loopback_absolute_form_authorities() {
    for request in [
        b"GET http://127.0.0.1/index.html HTTP/1.0\r\nX-Test: 1\r\n\r\n".as_slice(),
        b"GET http://127.0.0.1:8080/index.html HTTP/1.0\r\nX-Test: 1\r\n\r\n".as_slice(),
    ] {
        assert!(
            HttpRequest::parse(request).is_err(),
            "loopback authority should fail"
        );
    }
}

#[test]
fn parse_uses_connect_authority_without_host_header() {
    let request = b"CONNECT example.test:443 HTTP/1.0\r\nX-Test: 1\r\n\r\n";

    let Ok(Some(parsed)) = HttpRequest::parse(request) else {
        panic!("request should parse");
    };

    assert_eq!(parsed.host.as_deref(), Some("example.test:443"));
}

#[test]
fn parse_rejects_connect_authority_without_explicit_port() {
    let request = b"CONNECT example.test HTTP/1.0\r\nX-Test: 1\r\n\r\n";

    assert!(HttpRequest::parse(request).is_err());
}

#[test]
fn parse_rejects_zero_port_host_header_for_canonicalization() {
    let request = b"GET / HTTP/1.0\r\nHost: example.test:0\r\nX-Test: 1\r\n\r\n";

    let Ok(Some(parsed)) = HttpRequest::parse(request) else {
        panic!("request should parse");
    };

    assert_eq!(parsed.host, None);
    assert_eq!(
        parsed.headers.get("host").map(String::as_str),
        Some("example.test:0")
    );
}

#[test]
fn parse_canonicalizes_zero_padded_host_port() {
    let request = b"GET / HTTP/1.0\r\nHost: example.test:080\r\nX-Test: 1\r\n\r\n";

    let Ok(Some(parsed)) = HttpRequest::parse(request) else {
        panic!("request should parse");
    };

    assert_eq!(parsed.host.as_deref(), Some("example.test:80"));
    assert_eq!(
        parsed.headers.get("host").map(String::as_str),
        Some("example.test:80")
    );
}

#[test]
fn parse_omits_empty_user_agent_header() {
    let request = b"GET / HTTP/1.1\r\nHost: example.test\r\nUser-Agent:\r\n\r\n";

    let Ok(Some(parsed)) = HttpRequest::parse(request) else {
        panic!("request should parse");
    };

    assert_eq!(parsed.user_agent, None);
}

#[test]
fn parse_rejects_unbracketed_ipv6_host_header_for_canonicalization() {
    let request = b"GET / HTTP/1.0\r\nHost: 2001:db8::1\r\nX-Test: 1\r\n\r\n";

    let Ok(Some(parsed)) = HttpRequest::parse(request) else {
        panic!("request should parse");
    };

    assert_eq!(parsed.host, None);
    assert_eq!(
        parsed.headers.get("host").map(String::as_str),
        Some("2001:db8::1")
    );
}

#[test]
fn response_serializer_omits_body_for_reset_content_status() {
    let response = HttpResponse {
        status_code: 205,
        status_text: "Reset Content".to_string(),
        headers: std::collections::BTreeMap::from([(
            "Content-Type".to_string(),
            "text/plain".to_string(),
        )]),
        body: b"payload".to_vec(),
        suppress_body: false,
    };

    let bytes = response.to_bytes();
    let Ok(text) = std::str::from_utf8(&bytes) else {
        panic!("response is utf-8");
    };

    assert!(text.starts_with("HTTP/1.1 205 Reset Content\r\n"));
    assert!(text.contains("Content-Length: 0\r\n"));
    assert!(!text.ends_with("payload"));
}

#[test]
fn parse_rejects_invalid_content_length() {
    let request =
        b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: abc\r\n\r\nhello";

    assert!(HttpRequest::parse(request).is_err());

    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: +5\r\n\r\nhello";

    assert!(HttpRequest::parse(request).is_err());
}

#[test]
fn parse_rejects_truncated_chunked_body() {
    let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntes";

    let Ok(parsed) = HttpRequest::parse(request) else {
        panic!("parser should not error");
    };
    assert!(
        parsed.is_none(),
        "truncated chunked body should remain incomplete"
    );
}

#[test]
fn parse_accepts_complete_chunked_body() {
    let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

    let Ok(parsed) = HttpRequest::parse(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("complete chunked request should parse");
    };

    assert_eq!(parsed.uri, "/upload");
    assert_eq!(parsed.body, b"test");
}

#[test]
fn parse_rejects_transfer_encoding_with_content_length() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 14\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

    assert!(HttpRequest::parse(request).is_err());
}

#[test]
fn parse_rejects_chunked_when_not_final_transfer_coding() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked, gzip\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

    assert!(HttpRequest::parse(request).is_err());
}

#[test]
fn parse_rejects_unsupported_transfer_coding_before_chunked() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

    assert!(HttpRequest::parse(request).is_err());
}

#[test]
fn parse_does_not_absorb_coalesced_request_as_body_without_framing() {
    let request =
            b"GET /a HTTP/1.1\r\nHost: example.test\r\n\r\nGET /b HTTP/1.1\r\nHost: example.test\r\n\r\n";

    assert!(matches!(HttpRequest::parse(request), Ok(None)));
}

#[test]
fn custom_responses_match_normalized_paths_with_query() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/index.html", "custom")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "GET".to_string(),
        uri: "/index.html?v=1".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"custom");
}

#[test]
fn default_response_rejects_oversized_body() {
    let err = super::bounded_response_body("a".repeat(MAX_RESPONSE_BODY_BYTES + 1))
        .expect_err("oversized default response should fail");

    assert!(matches!(err, Error::Config(message) if message.contains("exceeds size limit")));
}

#[test]
fn custom_response_rejects_oversized_body() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));

    let err = server
        .add_custom_response("/large", "a".repeat(MAX_RESPONSE_BODY_BYTES + 1))
        .expect_err("oversized custom response should fail");

    assert!(matches!(err, Error::Config(message) if message.contains("exceeds size limit")));
}

#[test]
fn custom_response_rejects_oversized_path() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    let path = format!("/{}", "a".repeat(MAX_CUSTOM_RESPONSE_PATH_BYTES + 1));

    let err = server
        .add_custom_response(path, "ok")
        .expect_err("oversized custom response path should fail");

    assert!(matches!(err, Error::Config(message) if message.contains("path exceeds size limit")));
}

#[test]
fn custom_response_rejects_empty_path() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));

    let add_err = server
        .add_custom_response("", "ok")
        .expect_err("empty custom response path should fail");
    assert!(
        matches!(add_err, Error::Config(message) if message == "Invalid HTTP custom response path")
    );

    let remove_err = server
        .remove_custom_response("")
        .expect_err("empty custom response path should fail");
    assert!(
        matches!(remove_err, Error::Config(message) if message == "Invalid HTTP custom response path")
    );
}

#[test]
fn custom_response_count_is_bounded_but_existing_paths_can_update() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    for index in 0..MAX_CUSTOM_RESPONSES {
        server
            .add_custom_response(format!("/r{index}"), "ok")
            .expect("custom response below limit should be accepted");
    }

    server
        .add_custom_response("/r0", "updated")
        .expect("existing custom response should update at limit");
    let err = server
        .add_custom_response("/overflow", "nope")
        .expect_err("new custom response beyond limit should fail");

    assert!(
        matches!(err, Error::Config(message) if message.contains("Too many HTTP custom responses"))
    );
}

#[test]
fn custom_responses_match_normalized_paths_with_absolute_form() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/index.html", "custom")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "GET".to_string(),
        uri: "http://example.test/index.html".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"custom");

    let trailing_dot_request = HttpRequest {
        method: "GET".to_string(),
        uri: "http://example.test./index.html".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test.".to_string()),
        user_agent: None,
        has_body: false,
    };

    let trailing_dot_response = server.build_response(&trailing_dot_request);
    assert_eq!(trailing_dot_response.body, b"custom");
}

#[test]
fn custom_responses_reject_invalid_absolute_form_hosts() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/index.html", "custom")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "GET".to_string(),
        uri: "http://12345/index.html".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("12345".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"<html></html>");

    let malformed_ipv6_request = HttpRequest {
        method: "GET".to_string(),
        uri: "http://[2001:db8::1]:443:80/index.html".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("[2001:db8::1]:443".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&malformed_ipv6_request);
    assert_eq!(response.body, b"<html></html>");
}

#[test]
fn custom_responses_reject_trailing_dot_ipv4_absolute_form_hosts() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/index.html", "custom")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "GET".to_string(),
        uri: "http://192.0.2.10./index.html".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("192.0.2.10.".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"<html></html>");
}

#[test]
fn custom_responses_reject_trailing_dot_numeric_absolute_form_hosts() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/index.html", "custom")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "GET".to_string(),
        uri: "http://12345./index.html".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("12345.".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"<html></html>");
}

#[test]
fn custom_responses_match_ipv4_absolute_form_targets() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/index.html", "custom")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "GET".to_string(),
        uri: "http://192.0.2.10/index.html".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("192.0.2.10".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"custom");
}

#[test]
fn custom_responses_reject_unbracketed_ipv6_absolute_form_targets() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/index.html", "custom")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "GET".to_string(),
        uri: "http://2001:db8::1/index.html".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("2001:db8::1".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"<html></html>");
}

#[test]
fn custom_responses_match_uppercase_absolute_form_with_dot_segments() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/beta/gamma", "custom")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "GET".to_string(),
        uri: "HTTP://example.test/alpha/../beta/./gamma?x=1#frag".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"custom");
}

#[test]
fn custom_responses_ignore_path_parameters_during_lookup() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/payload.exe", "custom")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "GET".to_string(),
        uri: "/payload.exe;download=1".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"custom");
}

#[test]
fn custom_responses_match_backslash_separated_paths() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/beta/gamma", "custom")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "GET".to_string(),
        uri: "/alpha\\..\\beta\\gamma".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"custom");
}

#[test]
fn custom_responses_match_backslash_separated_absolute_form() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/beta/gamma", "custom")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "GET".to_string(),
        uri: "http://example.test\\beta\\gamma?x=1".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"custom");
}

#[test]
fn custom_responses_preserve_asterisk_and_authority_targets() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("*", "asterisk")
        .expect("valid custom response path");
    server
        .add_custom_response("example.test:443", "authority")
        .expect("valid custom response path");
    server
        .add_custom_response("example.test.:443", "authority-dot")
        .expect("valid custom response path");

    let asterisk = HttpRequest {
        method: "OPTIONS".to_string(),
        uri: "*".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test".to_string()),
        user_agent: None,
        has_body: false,
    };
    let authority = HttpRequest {
        method: "CONNECT".to_string(),
        uri: "example.test:443".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test".to_string()),
        user_agent: None,
        has_body: false,
    };

    assert_eq!(server.build_response(&asterisk).body, b"asterisk");
    assert_eq!(server.build_response(&authority).body, b"authority");

    let trailing_dot_authority = HttpRequest {
        method: "CONNECT".to_string(),
        uri: "example.test.:443".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test.".to_string()),
        user_agent: None,
        has_body: false,
    };

    assert_eq!(
        server.build_response(&trailing_dot_authority).body,
        b"authority-dot"
    );
}

#[test]
fn custom_responses_match_bracketed_ipv6_authority_targets() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("[2001:db8::1]:443", "ipv6-authority")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "CONNECT".to_string(),
        uri: "[2001:db8::1]:443".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("[2001:db8::1]".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"ipv6-authority");
}

#[test]
fn custom_responses_match_case_normalized_authority_targets() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("example.test:443", "authority")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "CONNECT".to_string(),
        uri: "EXAMPLE.TEST:443".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"authority");
}

#[test]
fn custom_responses_canonicalize_bracketed_ipv6_authority_targets() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("[2001:db8:0:0::1]:443", "ipv6-authority")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "CONNECT".to_string(),
        uri: "[2001:db8::1]:443".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("[2001:db8::1]".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"ipv6-authority");
}

#[test]
fn custom_responses_canonicalize_bracketed_ipv4_mapped_authority_targets() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("[::ffff:192.0.2.10]:443", "mapped-authority")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "CONNECT".to_string(),
        uri: "[::ffff:192.0.2.10]:443".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("192.0.2.10:443".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"mapped-authority");
}

#[test]
fn custom_responses_reject_unspecified_authority_targets() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/index.html", "custom")
        .expect("valid custom response path");

    assert!(server.add_custom_response("0.0.0.0:443", "bad").is_err());
    assert!(server.add_custom_response("[::]:443", "bad").is_err());
    assert!(
        server
            .add_custom_response("[::ffff:0.0.0.0]:443", "bad")
            .is_err()
    );
}

#[test]
fn custom_responses_reject_loopback_authority_targets() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/index.html", "custom")
        .expect("valid custom response path");

    assert!(server.add_custom_response("127.0.0.1:443", "bad").is_err());
    assert!(server.add_custom_response("[::1]:443", "bad").is_err());
    assert!(
        server
            .add_custom_response("http://127.0.0.1/index.html", "bad")
            .is_err()
    );
}

#[test]
fn custom_responses_reject_multicast_authority_targets() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/index.html", "custom")
        .expect("valid custom response path");

    assert!(server.add_custom_response("224.0.0.1:443", "bad").is_err());
    assert!(
        server
            .add_custom_response("255.255.255.255:443", "bad")
            .is_err()
    );
    assert!(server.add_custom_response("[ff02::1]:443", "bad").is_err());
    assert!(
        server
            .add_custom_response("[::ffff:224.0.0.1]:443", "bad")
            .is_err()
    );
}

#[test]
fn custom_responses_reject_overlong_authority_labels() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    let target = format!("{}.example.test:443", "a".repeat(64));

    assert!(server.add_custom_response(&target, "bad").is_err());
}

#[test]
fn custom_responses_reject_overlong_authority_hostnames() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    let target = format!(
        "{}.{}.{}.{}.example.test:443",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );

    assert!(server.add_custom_response(&target, "bad").is_err());
}

#[test]
fn custom_responses_reject_windows_drive_targets() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/index.html", "custom")
        .expect("valid custom response path");
    let err = server
        .add_custom_response("C:/index.html", "drive")
        .expect_err("Windows drive paths should be rejected");
    assert!(
        matches!(err, Error::Config(message) if message == "Invalid HTTP custom response path")
    );

    let request = HttpRequest {
        method: "GET".to_string(),
        uri: "C:/index.html".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"<html></html>");

    let normal = HttpRequest {
        uri: "/index.html".to_string(),
        ..request
    };
    let response = server.build_response(&normal);
    assert_eq!(response.body, b"custom");
}

#[test]
fn custom_responses_do_not_match_loopback_authority_requests() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/index.html", "custom")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "CONNECT".to_string(),
        uri: "127.0.0.1:443".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("127.0.0.1".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"<html></html>");

    let request = HttpRequest {
        uri: "[::1]:443".to_string(),
        host: Some("[::1]".to_string()),
        ..request
    };
    let response = server.build_response(&request);
    assert_eq!(response.body, b"<html></html>");
}

#[test]
fn add_custom_response_normalizes_registered_paths() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("http://example.test/index.html?v=1", "custom")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "GET".to_string(),
        uri: "/index.html".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"custom");
}

#[test]
fn add_custom_response_rejects_unicode_line_separators_in_path() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    let err = server
        .add_custom_response("/alpha\u{2028}beta", "custom")
        .expect_err("path with unicode separators should fail");

    assert!(
        matches!(err, Error::Config(message) if message.contains("Invalid HTTP custom response path"))
    );
}

#[test]
fn remove_custom_response_normalizes_registered_paths() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("http://example.test/index.html?v=1", "custom")
        .expect("valid custom response path");
    server
        .remove_custom_response("/index.html")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "GET".to_string(),
        uri: "/index.html".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"<html></html>");
}

#[test]
fn remove_custom_response_ignores_path_parameters_for_canonical_routes() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    server
        .add_custom_response("/index.html", "custom")
        .expect("valid custom response path");
    server
        .remove_custom_response("/index.html;download=1")
        .expect("valid custom response path");

    let request = HttpRequest {
        method: "GET".to_string(),
        uri: "/index.html;download=1".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = server.build_response(&request);
    assert_eq!(response.body, b"<html></html>");
}

#[test]
fn response_serializer_rejects_injected_headers() {
    let mut response = HttpResponse::ok("hello");
    response.status_text = "OK\r\nX-Injected: yes".to_string();
    response
        .headers
        .insert("X-Test".to_string(), "ok".to_string());

    let bytes = response.to_bytes();
    let Ok(text) = std::str::from_utf8(&bytes) else {
        panic!("response is utf-8");
    };

    assert!(text.starts_with("HTTP/1.1 500 Internal Server Error\r\n"));
    assert!(text.contains("Invalid HTTP header"));
}

#[test]
fn response_serializer_rewrites_content_length_for_mutated_body() {
    let mut response = HttpResponse::ok("hello");
    response.body = b"goodbye".to_vec();

    let bytes = response.to_bytes();
    let Ok(text) = std::str::from_utf8(&bytes) else {
        panic!("response is utf-8");
    };

    assert!(text.contains("Content-Length: 7\r\n"));
    assert!(!text.contains("Content-Length: 5\r\n"));
}

#[test]
fn response_serializer_removes_transfer_encoding_for_materialized_body() {
    let mut response = HttpResponse::ok("hello");
    response
        .headers
        .insert("Transfer-Encoding".to_string(), "chunked".to_string());

    let bytes = response.to_bytes();
    let Ok(text) = std::str::from_utf8(&bytes) else {
        panic!("response is utf-8");
    };

    assert!(text.contains("Content-Length: 5\r\n"));
    assert!(!text.contains("Transfer-Encoding:"));
}

#[test]
fn response_serializer_preserves_latin1_header_values_as_single_bytes() {
    let mut response = HttpResponse::ok("hello");
    response
        .headers
        .insert("X-Test".to_string(), "\u{00ff}".to_string());

    let bytes = response.to_bytes();

    assert!(
        bytes
            .windows(b"X-Test: \xff\r\n".len())
            .any(|window| window == b"X-Test: \xff\r\n")
    );
    assert!(
        !bytes
            .windows(b"X-Test: \xc3\xbf\r\n".len())
            .any(|window| window == b"X-Test: \xc3\xbf\r\n")
    );
}

#[test]
fn response_serializer_omits_body_for_no_content_status() {
    let response = HttpResponse {
        status_code: 204,
        status_text: "No Content".to_string(),
        headers: std::collections::BTreeMap::from([(
            "Content-Type".to_string(),
            "text/plain".to_string(),
        )]),
        body: b"payload".to_vec(),
        suppress_body: false,
    };

    let bytes = response.to_bytes();
    let Ok(text) = std::str::from_utf8(&bytes) else {
        panic!("response is utf-8");
    };

    assert!(text.starts_with("HTTP/1.1 204 No Content\r\n"));
    assert!(text.contains("Content-Length: 0\r\n"));
    assert!(!text.ends_with("payload"));
}

#[test]
fn handle_request_suppresses_body_for_head() {
    let server = HttpServer::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    let request = HttpRequest {
        method: "HEAD".to_string(),
        uri: "/".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: Vec::new(),
        host: Some("example.test".to_string()),
        user_agent: None,
        has_body: false,
    };

    let response = super::block_on_ready(<HttpServer as super::HttpHandlerTrait>::handle_request(
        &server, request,
    ))
    .expect("HEAD response");
    let bytes = response.to_bytes();
    let Ok(text) = std::str::from_utf8(&bytes) else {
        panic!("response is utf-8");
    };

    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(text.contains("Content-Length: 13\r\n"));
    assert!(!text.ends_with("<html></html>"));
}
