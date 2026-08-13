use crate::parser::{MAX_HEADER_SIZE, MAX_TOTAL_SIZE, is_valid_http_host_name};

use super::parse_http_request_bytes;

#[test]
fn chunked_decoder_rejects_size_that_would_overflow_terminator_check() {
    let max_hex_digits = format!("{:x}", usize::MAX).len();
    let chunk_size = usize::MAX - (max_hex_digits + 2);
    let request = format!(
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n{chunk_size:x}\r\nx"
    );

    let Ok(parsed) = parse_http_request_bytes(request.as_bytes()) else {
        panic!("parser should not error");
    };

    assert!(parsed.is_none());
}

#[test]
fn parse_normalizes_uppercase_absolute_form_and_dot_segments() {
    let request = b"GET HTTP://example.test/alpha/../beta/./gamma?x=1#frag HTTP/1.1\r\nHost: example.test\r\n\r\n";

    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("request should parse");
    };

    assert_eq!(parsed.path, "/beta/gamma");
    assert_eq!(
        parsed.target,
        "HTTP://example.test/alpha/../beta/./gamma?x=1#frag"
    );
}

#[test]
fn parse_accepts_http_1_0_request_without_headers() {
    let request = b"GET / HTTP/1.0\r\n\r\n";

    let parsed = parse_http_request_bytes(request)
        .expect("headerless HTTP/1.0 request should not error")
        .expect("headerless HTTP/1.0 request should parse");

    assert_eq!(parsed.method, "GET");
    assert_eq!(parsed.path, "/");
    assert!(parsed.headers.is_empty());
}

#[test]
fn parse_accepts_body_bytes_with_embedded_carriage_return() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\nA\rB!";

    let Ok(Some(parsed)) = parse_http_request_bytes(request) else {
        panic!("request with binary body should parse");
    };

    assert_eq!(parsed.body, b"A\rB!");
}

#[test]
fn parse_rejects_http_1_1_request_without_headers() {
    let request = b"GET / HTTP/1.1\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_http_1_1_request_without_host_header() {
    let request = b"GET / HTTP/1.1\r\nX-Test: 1\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_absolute_form_without_authority() {
    let request = b"GET http:///path HTTP/1.1\r\nHost: example.test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_carriage_return_only_line_endings() {
    let request = b"GET / HTTP/1.1\rHost: example.test\r\r";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_carriage_return_only_chunk_headers() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\rtest\r\n0\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_line_feed_only_chunk_headers() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\ntest\r\n0\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_invalid_chunk_data_terminator() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntestxx0\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_carriage_return_only_chunk_trailers() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\rTrailer: bad\r\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_line_feed_only_chunk_trailers() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nTrailer: bad\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_absolute_form_with_unsupported_scheme() {
    let request = b"GET ftp://example.test/path HTTP/1.1\r\nHost: example.test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_absolute_form_with_invalid_authority_labels() {
    for target in [
        "http://example..test/path",
        "http://.example.test/path",
        "http://bad-.example.test/path",
        "http://-bad.example.test/path",
        "http://12345/path",
    ] {
        let request = format!("GET {target} HTTP/1.1\r\nHost: example.test\r\n\r\n");

        assert!(
            parse_http_request_bytes(request.as_bytes()).is_err(),
            "{target}"
        );
    }
}

#[test]
fn parse_accepts_absolute_form_authorities_with_trailing_dots() {
    let request = b"GET http://example.test./path HTTP/1.1\r\nHost: example.test\r\n\r\n";

    let Ok(Some(parsed)) = parse_http_request_bytes(request) else {
        panic!("request should parse");
    };
    assert_eq!(parsed.path, "/path");
}

#[test]
fn parse_rejects_invalid_host_header_labels() {
    for host in [
        "example..test",
        ".example.test",
        "bad-.example.test",
        "-bad.example.test",
    ] {
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");

        assert!(
            parse_http_request_bytes(request.as_bytes()).is_err(),
            "{host}"
        );
    }
}

#[test]
fn parse_rejects_overlong_host_header_labels() {
    let host = format!("{}.example.test", "a".repeat(64));
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");

    assert!(parse_http_request_bytes(request.as_bytes()).is_err());
}

#[test]
fn parse_rejects_overlong_host_header_names() {
    let host = ["a"; 128].join(".");
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");

    assert!(host.len() > 253);
    assert!(parse_http_request_bytes(request.as_bytes()).is_err());
}

#[test]
fn parse_accepts_absolute_hostnames_with_trailing_dots() {
    for host in ["example.test.", "example.test.:8080"] {
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");

        let Ok(Some(parsed)) = parse_http_request_bytes(request.as_bytes()) else {
            panic!("{host}");
        };
        assert_eq!(parsed.path, "/");
    }
}

#[test]
fn parse_rejects_multiple_trailing_dots_in_host_header() {
    let request = b"GET / HTTP/1.1\r\nHost: example.test...\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_numeric_host_header() {
    let request = b"GET / HTTP/1.1\r\nHost: 12345\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn http_host_name_helper_rejects_numeric_hostnames() {
    assert!(!is_valid_http_host_name("12345"));
    assert!(!is_valid_http_host_name("192.0.2.10"));
}

#[test]
fn parse_normalizes_backslash_separated_paths() {
    let request = b"GET /alpha\\..\\beta\\gamma HTTP/1.1\r\nHost: example.test\r\n\r\n";

    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("request should parse");
    };

    assert_eq!(parsed.path, "/beta/gamma");
}

#[test]
fn parse_normalizes_backslash_separated_absolute_form_paths() {
    let request = b"GET http://example.test\\alpha\\..\\beta\\gamma?x=1 HTTP/1.1\r\nHost: example.test\r\n\r\n";

    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("request should parse");
    };

    assert_eq!(parsed.path, "/beta/gamma");
}

#[test]
fn parse_preserves_asterisk_and_authority_targets() {
    let request = b"OPTIONS * HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("request should parse");
    };
    assert_eq!(parsed.path, "*");

    let request = b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("request should parse");
    };
    assert_eq!(parsed.path, "example.test:443");

    let request = b"CONNECT foo:bar HTTP/1.1\r\nHost: example.test\r\n\r\n";
    assert!(parse_http_request_bytes(request).is_err());

    let request = b"GET * HTTP/1.1\r\nHost: example.test\r\n\r\n";
    assert!(parse_http_request_bytes(request).is_err());

    let request = b"GET example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n";
    assert!(parse_http_request_bytes(request).is_err());

    let request = b"CONNECT /path HTTP/1.1\r\nHost: example.test\r\n\r\n";
    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_unicode_line_separators_in_request_target() {
    let request = b"GET /submit\xe2\x80\xa8X:1 HTTP/1.1\r\nHost: example.test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn connect_authority_targets_reject_invalid_labels() {
    for target in [
        "example..test:443",
        ".example.test:443",
        "bad-.example.test:443",
        "12345:443",
    ] {
        let request = format!("CONNECT {target} HTTP/1.1\r\nHost: example.test\r\n\r\n");

        assert!(
            parse_http_request_bytes(request.as_bytes()).is_err(),
            "{target}"
        );
    }
}

#[test]
fn connect_authority_targets_reject_overlong_labels() {
    let target = format!("{}.example.test:443", "a".repeat(64));
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: example.test\r\n\r\n");

    assert!(parse_http_request_bytes(request.as_bytes()).is_err());
}

#[test]
fn connect_authority_targets_accept_ipv4_literals() {
    let request = b"CONNECT 192.0.2.10:443 HTTP/1.1\r\nHost: example.test\r\n\r\n";

    let Ok(Some(parsed)) = parse_http_request_bytes(request) else {
        panic!("ipv4 authority should parse");
    };

    assert_eq!(parsed.path, "192.0.2.10:443");
}

#[test]
fn connect_authority_targets_accept_valid_hostnames() {
    let request = b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n";

    let Ok(Some(parsed)) = parse_http_request_bytes(request) else {
        panic!("authority-form CONNECT should parse");
    };

    assert_eq!(parsed.method, "CONNECT");
    assert_eq!(parsed.target, "example.test:443");
}

#[test]
fn connect_authority_targets_reject_unspecified_ip_literals() {
    for request in [
        b"CONNECT 0.0.0.0:443 HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        b"CONNECT [::]:443 HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        b"CONNECT [::ffff:0.0.0.0]:443 HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
    ] {
        assert!(parse_http_request_bytes(request).is_err());
    }
}

#[test]
fn connect_authority_targets_reject_special_ip_literals() {
    for request in [
        b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        b"CONNECT 224.0.0.1:443 HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        b"CONNECT 255.255.255.255:443 HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        b"CONNECT [::1]:443 HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        b"CONNECT [::ffff:127.0.0.1]:443 HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
    ] {
        assert!(parse_http_request_bytes(request).is_err());
    }
}

#[test]
fn connect_authority_targets_reject_unbracketed_ipv6_literals() {
    let request = b"CONNECT 2001:db8::1:443 HTTP/1.1\r\nHost: example.test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());

    let request = b"CONNECT ::1:443 HTTP/1.1\r\nHost: example.test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn connect_authority_targets_accept_trailing_dot_hostnames() {
    let request = b"CONNECT example.test.:443 HTTP/1.1\r\nHost: example.test\r\n\r\n";

    let Ok(Some(parsed)) = parse_http_request_bytes(request) else {
        panic!("request should parse");
    };
    assert_eq!(parsed.path, "example.test.:443");
}

#[test]
fn absolute_form_targets_reject_unspecified_ip_literals() {
    for request in [
        b"GET http://0.0.0.0/path HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        b"GET http://[::]/path HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        b"GET http://[::ffff:0.0.0.0]/path HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
    ] {
        assert!(parse_http_request_bytes(request).is_err());
    }
}

#[test]
fn absolute_form_targets_reject_special_ip_literals() {
    for request in [
        b"GET http://127.0.0.1/path HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        b"GET http://224.0.0.1/path HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        b"GET http://255.255.255.255/path HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        b"GET http://[::1]/path HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        b"GET http://[::ffff:127.0.0.1]/path HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
    ] {
        assert!(parse_http_request_bytes(request).is_err());
    }
}

#[test]
fn parse_rejects_special_ip_host_headers() {
    for host in [
        "127.0.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "[ff02::1]",
        "[::ffff:127.0.0.1]",
    ] {
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");

        assert!(
            parse_http_request_bytes(request.as_bytes()).is_err(),
            "{host}"
        );
    }
}

#[test]
fn parse_rejects_relative_form_targets_without_leading_slash() {
    let request = b"GET /path HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("request should parse");
    };
    assert_eq!(parsed.path, "/path");

    let request = b"GET foo HTTP/1.1\r\nHost: example.test\r\n\r\n";
    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_header_lines_without_colons() {
    let request = b"GET / HTTP/1.1\r\nHost: example.test\r\nBroken-Header\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_nul_in_header_value() {
    let request = b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Test: hello\0world\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_control_bytes_in_header_value() {
    let request = b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Test: hello\x0bworld\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_crlf_in_header_value() {
    let request = b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Test: hello\r\nworld\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_accepts_unicode_separators_in_header_value() {
    let request = "GET / HTTP/1.1\r\nHost: example.test\r\nX-Test: hello\u{2028}world\r\n\r\n";

    let Ok(parsed) = parse_http_request_bytes(request.as_bytes()) else {
        panic!("parser should not error");
    };
    assert!(parsed.is_some());
}

#[test]
fn parse_rejects_unicode_line_separators_in_header_block() {
    let request = "GET / HTTP/1.1\r\nHost: example.test\u{2028}X-Injected: yes\r\n\r\n";

    assert!(parse_http_request_bytes(request.as_bytes()).is_err());
}

#[test]
fn parse_rejects_unicode_whitespace_in_header_name() {
    let request =
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length\u{00a0}: 5\r\n\r\nhello";

    assert!(parse_http_request_bytes(request.as_bytes()).is_err());
}

#[test]
fn parse_accepts_obs_text_in_header_values() {
    let request = b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Test: hi\x80\xff\r\n\r\n";

    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("request should parse");
    };
    assert_eq!(parsed.headers[1].1, "hi\u{80}\u{ff}");
}

#[test]
fn chunked_trailers_reject_whitespace_in_field_names() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n Bad-Trailer: value\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn chunked_trailers_accept_unicode_whitespace_in_field_values() {
    let request = "POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nBad-Trailer: \u{00a0}value\r\n\r\n";

    let Ok(parsed) = parse_http_request_bytes(request.as_bytes()) else {
        panic!("parser should not error");
    };
    assert!(parsed.is_some());
}

#[test]
fn chunked_trailers_accept_unicode_line_separators_in_field_values() {
    let request = "POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nBad-Trailer: value\u{2028}Injected: yes\r\n\r\n";

    let Ok(parsed) = parse_http_request_bytes(request.as_bytes()) else {
        panic!("parser should not error");
    };
    assert!(parsed.is_some());
}

#[test]
fn chunked_trailers_accept_obs_text_in_field_values() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nBad-Trailer: hi\x80\r\n\r\n";

    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    assert!(parsed.is_some());
}

#[test]
fn http_11_host_header_rejects_internal_whitespace() {
    let request = b"GET / HTTP/1.1\r\nHost: example test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn http_11_host_header_rejects_unicode_whitespace() {
    let request = "GET / HTTP/1.1\r\nHost: example\u{00a0}test\r\n\r\n";

    assert!(parse_http_request_bytes(request.as_bytes()).is_err());
}

#[test]
fn http_11_host_header_rejects_unicode_whitespace_around_value() {
    let request = "GET / HTTP/1.1\r\nHost: \u{00a0}example.test\u{00a0}\r\n\r\n";

    assert!(parse_http_request_bytes(request.as_bytes()).is_err());
}

#[test]
fn http_11_host_header_rejects_trailing_dot_ipv4_literal() {
    let request = b"GET / HTTP/1.1\r\nHost: 192.0.2.10.\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn http_11_host_header_rejects_unbracketed_ipv6_literal() {
    let request = b"GET / HTTP/1.1\r\nHost: ::1\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn http_11_host_header_rejects_numeric_host_with_port() {
    let request = b"GET / HTTP/1.1\r\nHost: 12345:80\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn http_11_host_header_accepts_ipv4_literal_with_port() {
    let request = b"GET / HTTP/1.1\r\nHost: 192.0.2.10:8080\r\n\r\n";
    let Ok(Some(parsed)) = parse_http_request_bytes(request) else {
        panic!("usable IPv4 Host authority with a port should parse");
    };

    assert_eq!(parsed.headers[0].1, "192.0.2.10:8080");
}

#[test]
fn http_11_host_header_rejects_trailing_dot_numeric_host_with_port() {
    let request = b"GET / HTTP/1.1\r\nHost: 12345.:80\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn http_11_host_header_accepts_usable_bracketed_ipv6_literal() {
    let request = b"GET / HTTP/1.1\r\nHost: [2001:db8::1]\r\n\r\n";

    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("request should parse");
    };
    assert_eq!(parsed.headers[0].1, "[2001:db8::1]");
}

#[test]
fn http_11_host_header_rejects_loopback_bracketed_ipv6_literal() {
    let request = b"GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn http_11_host_header_rejects_unspecified_ip_literals() {
    let request = b"GET / HTTP/1.1\r\nHost: 0.0.0.0\r\n\r\n";
    assert!(parse_http_request_bytes(request).is_err());

    let request = b"GET / HTTP/1.1\r\nHost: [::]\r\n\r\n";
    assert!(parse_http_request_bytes(request).is_err());

    let request = b"GET / HTTP/1.1\r\nHost: [::ffff:0.0.0.0]\r\n\r\n";
    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn http_11_host_header_rejects_invalid_bracketed_literal() {
    let request = b"GET / HTTP/1.1\r\nHost: [not-an-ip]\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn http_11_host_header_rejects_duplicate_values() {
    let request = b"GET / HTTP/1.1\r\nHost: example.test\r\nHost: attacker.test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn http_11_host_header_rejects_userinfo_values() {
    let request = b"GET / HTTP/1.1\r\nHost: user@example.test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn parse_rejects_absolute_form_with_userinfo_authority() {
    let request = b"GET http://user@example.test/path HTTP/1.1\r\nHost: example.test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn http_11_host_header_rejects_out_of_range_bracketed_ipv6_port() {
    let request = b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:65536\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn http_11_host_header_rejects_out_of_range_port() {
    let request = b"GET / HTTP/1.1\r\nHost: example.test:65536\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn http_11_host_header_rejects_signed_ports() {
    let request = b"GET / HTTP/1.1\r\nHost: example.test:+80\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());

    let request = b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:+80\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn connect_authority_targets_reject_invalid_bracketed_literal() {
    let request = b"CONNECT [not-an-ip]:443 HTTP/1.1\r\nHost: example.test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn connect_authority_targets_reject_out_of_range_port() {
    let request = b"CONNECT example.test:65536 HTTP/1.1\r\nHost: example.test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn connect_authority_targets_reject_signed_ports() {
    let request = b"CONNECT example.test:+443 HTTP/1.1\r\nHost: example.test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());

    let request = b"CONNECT [2001:db8::1]:+443 HTTP/1.1\r\nHost: example.test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn absolute_form_targets_reject_out_of_range_authority_port() {
    let request = b"GET http://example.test:65536/path HTTP/1.1\r\nHost: example.test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn absolute_form_targets_reject_overlong_labels() {
    let target = format!("http://{}.example.test/path", "a".repeat(64));
    let request = format!("GET {target} HTTP/1.1\r\nHost: example.test\r\n\r\n");

    assert!(parse_http_request_bytes(request.as_bytes()).is_err());
}

#[test]
fn absolute_form_targets_reject_overlong_hostnames() {
    let target = format!(
        "http://{}.{}.{}.{}.example.test/path",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );
    let request = format!("GET {target} HTTP/1.1\r\nHost: example.test\r\n\r\n");

    assert!(parse_http_request_bytes(request.as_bytes()).is_err());
}

#[test]
fn absolute_form_targets_reject_signed_authority_ports() {
    let request = b"GET http://example.test:+80/path HTTP/1.1\r\nHost: example.test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());

    let request = b"GET http://[2001:db8::1]:+80/path HTTP/1.1\r\nHost: example.test\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn duplicate_content_length_accepts_equivalent_numeric_values() {
    let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 05\r\nContent-Length: 5\r\n\r\nhello";

    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("request should parse");
    };
    assert_eq!(parsed.body, b"hello".to_vec());
}

#[test]
fn duplicate_transfer_encoding_rejects_chunked_values() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn transfer_encoding_with_content_length_is_rejected() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 14\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn transfer_encoding_with_unsupported_coding_is_rejected() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn transfer_encoding_rejects_mixed_values_with_chunked() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());

    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked, gzip\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn chunked_decoder_rejects_whitespace_around_chunk_size() {
    let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n 4\r\ntest\r\n0\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn chunked_decoder_rejects_unicode_whitespace_around_chunk_size() {
    let request = "POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n\u{00a0}4\u{00a0}\r\ntest\r\n0\r\n\r\n";

    assert!(parse_http_request_bytes(request.as_bytes()).is_err());
}

#[test]
fn chunked_decoder_accepts_chunk_extensions_after_chunk_size() {
    let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=bar\r\ntest\r\n0\r\n\r\n";

    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("request should parse");
    };

    assert_eq!(parsed.body, b"test".to_vec());
}

#[test]
fn chunked_decoder_accepts_bws_around_chunk_extensions() {
    let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4 ; foo = bar\r\ntest\r\n0\r\n\r\n";

    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("request should parse");
    };

    assert_eq!(parsed.body, b"test".to_vec());
}

#[test]
fn chunked_decoder_accepts_quoted_pair_escaped_space_and_quote() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=\"bar\\\"baz\\ space\"\r\ntest\r\n0\r\n\r\n";

    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("request should parse");
    };

    assert_eq!(parsed.body, b"test".to_vec());
}

#[test]
fn chunked_decoder_rejects_invalid_escaped_chunk_extension_byte() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=\"bar\\\0baz\"\r\ntest\r\n0\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn chunked_decoder_accepts_quoted_chunk_extension_values() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=\"bar baz\"\r\ntest\r\n0\r\n\r\n";

    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("request should parse");
    };

    assert_eq!(parsed.body, b"test".to_vec());
}

#[test]
fn chunked_decoder_rejects_invalid_chunk_extension_token() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4;foo@=bar\r\ntest\r\n0\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn chunked_decoder_rejects_invalid_chunk_extension_value() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=bar@\r\ntest\r\n0\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn chunked_decoder_accepts_trailers_with_ascii_ows_values() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nDigest: sha-256=abc123\r\nX-Note:\tchunk complete\r\n\r\n";

    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    let Some(parsed) = parsed else {
        panic!("request should parse");
    };

    assert_eq!(parsed.body, b"test".to_vec());
}

#[test]
fn chunked_decoder_rejects_control_bytes_in_chunk_extensions() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=\0bar\r\ntest\r\n0\r\n\r\n";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn chunked_decoder_rejects_empty_or_whitespace_chunk_extensions() {
    let empty_extension = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4;\r\ntest\r\n0\r\n\r\n";
    let whitespace_only_extension =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4; \t \r\ntest\r\n0\r\n\r\n";

    assert!(parse_http_request_bytes(empty_extension).is_err());
    assert!(parse_http_request_bytes(whitespace_only_extension).is_err());
}

#[test]
fn chunked_decoder_rejects_unicode_whitespace_in_transfer_encoding() {
    let request = "POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\u{00a0}\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

    assert!(parse_http_request_bytes(request.as_bytes()).is_err());
}

#[test]
fn chunked_decoder_rejects_trailing_bytes_after_terminator() {
    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\nGARBAGE";

    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    assert!(parsed.is_none());
}

#[test]
fn content_length_rejects_trailing_bytes_after_declared_body() {
    let request =
        b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhelloGARBAGE";

    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    assert!(parsed.is_none());
}

#[test]
fn request_without_body_framing_rejects_trailing_bytes() {
    let request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\nGARBAGE";

    let Ok(parsed) = parse_http_request_bytes(request) else {
        panic!("parser should not error");
    };
    assert!(parsed.is_none());
}

#[test]
fn duplicate_content_length_rejects_invalid_first_value() {
    let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: abc\r\nContent-Length: 5\r\n\r\nhello";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn content_length_rejects_invalid_values() {
    let request =
        b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: abc\r\n\r\nhello";

    assert!(parse_http_request_bytes(request).is_err());

    let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: +5\r\n\r\nhello";

    assert!(parse_http_request_bytes(request).is_err());
}

#[test]
fn content_length_rejects_oversized_bodies() {
    let oversized = MAX_TOTAL_SIZE + 1;
    let request = format!(
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
        oversized
    );

    assert!(parse_http_request_bytes(request.as_bytes()).is_err());
}

#[test]
fn oversized_request_without_framing_is_rejected() {
    let mut request = Vec::with_capacity(MAX_TOTAL_SIZE + 1);
    request.extend_from_slice(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n");
    request.resize(MAX_TOTAL_SIZE + 1, b'a');

    assert!(parse_http_request_bytes(&request).is_err());
}

#[test]
fn oversized_headers_with_terminator_are_rejected() {
    let mut request = Vec::with_capacity(MAX_HEADER_SIZE + 64);
    request.extend_from_slice(b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Big: ");
    request.extend(std::iter::repeat_n(b'a', MAX_HEADER_SIZE + 1));
    request.extend_from_slice(b"\r\n\r\n");

    assert!(parse_http_request_bytes(&request).is_err());
}

#[test]
fn oversized_headers_without_terminator_are_rejected() {
    let mut request = Vec::with_capacity(MAX_HEADER_SIZE + 1);
    request.extend_from_slice(b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Big: ");
    request.extend(std::iter::repeat_n(b'a', MAX_HEADER_SIZE));

    assert!(parse_http_request_bytes(&request).is_err());
}

#[test]
fn parse_rejects_unicode_whitespace_around_content_length() {
    let request = "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: \u{00a0}5\u{00a0}\r\n\r\nhello";

    assert!(parse_http_request_bytes(request.as_bytes()).is_err());
}
