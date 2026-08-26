//! Utility functions for the engine module

mod http_dump;
mod http_files;
#[cfg(test)]
mod http_test_support;
pub mod service_name;

#[cfg(test)]
use std::borrow::Cow;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use crate::session::normalize_session_ip;
use nettrap_fsutil::append_regular_file_line;

pub use http_dump::dump_http_post;
#[cfg(test)]
pub(crate) use http_dump::http_post_dump_path;
pub use http_files::build_http_response_with_fakefile;
#[cfg(test)]
pub(crate) use http_files::{
    MAX_DEFAULT_FILE_RESPONSE_BYTES, build_http_response_with_body, safe_server_header_value,
};
#[cfg(test)]
pub(crate) use http_test_support::{
    extract_http_body, extract_http_host, extract_http_method, extract_http_path,
    extract_http_target,
};

pub(crate) fn normalize_request_path(path: &str) -> &str {
    path.split(['?', '#']).next().unwrap_or(path)
}

pub(crate) fn normalize_request_path_for_lookup(path: &str) -> String {
    let path = normalize_request_path(path);
    let preserve_trailing_slash = path.ends_with('/')
        || path
            .rsplit('/')
            .next()
            .is_some_and(|segment| segment.starts_with(';'));

    let mut normalized = String::with_capacity(path.len());
    for segment in path.split('/') {
        let segment = segment.split_once(';').map_or(segment, |(head, _)| head);
        if !segment.is_empty() {
            if !normalized.is_empty() {
                normalized.push('/');
            }
            normalized.push_str(segment);
        }
    }

    if path.starts_with('/') {
        normalized.insert(0, '/');
    }
    if preserve_trailing_slash && !normalized.ends_with('/') {
        normalized.push('/');
    }
    if normalized.is_empty() {
        "/".to_string()
    } else {
        normalized
    }
}

/// Log an event to the output file in JSONL format.
///
/// # Arguments
///
/// * `output_path` - Optional path to the log file
/// * `listener` - Name of the listener that received the connection
/// * `peer` - Socket address of the peer
/// * `event` - Event type (e.g., "connect", "dns_query")
/// * `detail` - Additional event details
///
/// # Example
///
/// ```ignore
/// log_event(Some(Path::new("/var/log/nettrap/events.jsonl")), "dns", &addr, "dns_query", "query=example.com").await;
/// ```
pub async fn log_event(
    output_path: Option<&Path>,
    listener: &str,
    peer: &std::net::SocketAddr,
    event: &str,
    detail: &str,
) {
    if let Some(path) = output_path {
        let detail = nettrap_core::sanitize::single_line(detail);
        let line = serde_json::json!({
            "timestamp": crate::faketime::fake_now().to_rfc3339(),
            "listener": listener,
            "src_ip": canonical_socket_ip_string(peer),
            "src_port": peer.port(),
            "event": event,
            "detail": detail,
        });
        let line = format!("{}\n", line);
        match append_regular_file_line(path, line.as_bytes()) {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!("Failed to write event log entry to {:?}: {}", path, e);
            }
        }
    }
}

pub(crate) fn canonical_socket_ip_string(peer: &std::net::SocketAddr) -> String {
    normalize_session_ip(peer.ip()).to_string()
}

fn request_path_is_unsafe(path: &str) -> bool {
    if path.contains('\\') || path.contains(':') {
        return true;
    }

    if crate::webroot::percent_encoded_path_is_unsafe(path) {
        return true;
    }

    let normalized = path.trim_start_matches('/');
    Path::new(normalized)
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
}

fn candidate_is_unsafe(candidate: &Path) -> bool {
    candidate.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::RootDir
        ) || matches!(component, std::path::Component::Prefix(_))
    })
}

/// Generate fake file content for common file extensions.
///
/// # Arguments
///
/// * `ext` - File extension (without dot)
///
/// # Returns
///
/// Fake content appropriate for the extension.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_post_dump_path_uses_relative_file_names_without_prefix() {
        let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("socket address");
        let path = http_post_dump_path(&None, &peer).expect("default dump path should build");

        assert!(!path.is_absolute());
        let name = path.file_name().and_then(|name| name.to_str()).unwrap();
        assert!(name.starts_with("http_post_"));
        assert!(name.ends_with("_8080.bin"));
    }

    #[test]
    fn http_post_dump_path_is_unique_without_clock_dependency() {
        let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("socket address");
        let first = http_post_dump_path(&None, &peer).expect("default dump path should build");
        let second = http_post_dump_path(&None, &peer).expect("default dump path should build");

        assert_ne!(first, second);
        assert!(first.file_name().and_then(|name| name.to_str()).is_some());
        assert!(second.file_name().and_then(|name| name.to_str()).is_some());
    }

    #[test]
    fn http_post_dump_path_rejects_control_characters_in_prefix() {
        let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("socket address");
        let prefix = Some("dump\nnext".to_string());

        let err = http_post_dump_path(&prefix, &peer)
            .expect_err("control characters in dump prefix should fail");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("control characters"));
    }

    #[test]
    fn test_extract_http_host() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_http_host(data).as_deref(), Some("example.com"));

        let trailing_dot_host = b"GET / HTTP/1.1\r\nHost: example.com.\r\n\r\n";
        assert_eq!(
            extract_http_host(trailing_dot_host).as_deref(),
            Some("example.com")
        );

        let trailing_dot_host_with_port = b"GET / HTTP/1.1\r\nHost: example.com.:443\r\n\r\n";
        assert_eq!(
            extract_http_host(trailing_dot_host_with_port).as_deref(),
            Some("example.com:443")
        );

        let zero_padded_port_host = b"GET / HTTP/1.1\r\nHost: example.com:080\r\n\r\n";
        assert_eq!(
            extract_http_host(zero_padded_port_host).as_deref(),
            Some("example.com:80")
        );

        let numeric_host_header = b"GET / HTTP/1.1\r\nHost: 12345\r\n\r\n";
        assert_eq!(extract_http_host(numeric_host_header), None);

        let invalid_host_absolute_form =
            b"GET http://example.com/index.html HTTP/1.0\r\nHost: example.com:0\r\n\r\n";
        assert_eq!(extract_http_host(invalid_host_absolute_form), None);

        let invalid_host_connect =
            b"CONNECT example.com:443 HTTP/1.0\r\nHost: example.com:0\r\n\r\n";
        assert_eq!(extract_http_host(invalid_host_connect), None);

        let data2 = b"GET / HTTP/1.1\r\nhost: example.org\r\n\r\n";
        assert_eq!(extract_http_host(data2).as_deref(), Some("example.org"));

        let bracketed_ipv6 = b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n";
        assert_eq!(
            extract_http_host(bracketed_ipv6).as_deref(),
            Some("[2001:db8::1]:443")
        );

        let bracketed_ipv6_noncanonical = b"GET / HTTP/1.1\r\nHost: [2001:db8:0:0::1]:443\r\n\r\n";
        assert_eq!(
            extract_http_host(bracketed_ipv6_noncanonical).as_deref(),
            Some("[2001:db8::1]:443")
        );

        let mapped_ipv4_host = b"GET / HTTP/1.1\r\nHost: [::ffff:203.0.113.10]:443\r\n\r\n";
        assert_eq!(
            extract_http_host(mapped_ipv4_host).as_deref(),
            Some("203.0.113.10:443")
        );

        let mapped_ipv4_connect =
            b"CONNECT [::ffff:203.0.113.10]:443 HTTP/1.0\r\nX-Test: 1\r\n\r\n";
        assert_eq!(
            extract_http_host(mapped_ipv4_connect).as_deref(),
            Some("203.0.113.10:443")
        );

        let unspecified_ipv4 = b"GET / HTTP/1.1\r\nHost: 0.0.0.0\r\n\r\n";
        assert_eq!(extract_http_host(unspecified_ipv4), None);

        let unspecified_ipv6 = b"GET / HTTP/1.1\r\nHost: [::]\r\n\r\n";
        assert_eq!(extract_http_host(unspecified_ipv6), None);

        let loopback_ipv4 = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        assert_eq!(extract_http_host(loopback_ipv4), None);

        let multicast_ipv4 = b"GET / HTTP/1.1\r\nHost: 224.0.0.1\r\n\r\n";
        assert_eq!(extract_http_host(multicast_ipv4), None);

        let loopback_ipv6 = b"GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n";
        assert_eq!(extract_http_host(loopback_ipv6), None);

        let mapped_loopback_ipv6 = b"GET / HTTP/1.1\r\nHost: [::ffff:127.0.0.1]\r\n\r\n";
        assert_eq!(extract_http_host(mapped_loopback_ipv6), None);

        let malformed = b"GET\t/ HTTP/1.1\r\nHost: example.net\r\n\r\n";
        assert_eq!(extract_http_host(malformed), None);

        let data3 = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_host(data3), None);

        let nul_host = b"GET / HTTP/1.1\r\nHost: example\0.com\r\n\r\n";
        assert_eq!(extract_http_host(nul_host), None);

        let mixed_line_endings = b"GET / HTTP/1.1\r\nHost: example.test\n\r\n";
        assert_eq!(extract_http_host(mixed_line_endings), None);

        let bare_lf_request_line = b"GET / HTTP/1.1\nHost: example.org\r\n\r\n";
        assert_eq!(extract_http_host(bare_lf_request_line), None);

        let body_with_lf = b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\nhello\nworld";
        assert_eq!(
            extract_http_host(body_with_lf).as_deref(),
            Some("example.org")
        );

        let host_in_body = b"GET / HTTP/1.1\r\nUser-Agent: nettrap\r\n\r\nHost: body.example\r\n";
        assert_eq!(extract_http_host(host_in_body), None);

        let numeric_host = b"GET / HTTP/1.1\r\nHost: 12345:80\r\n\r\n";
        assert_eq!(extract_http_host(numeric_host), None);

        let trailing_dot_numeric_host = b"GET / HTTP/1.1\r\nHost: 12345.:80\r\n\r\n";
        assert_eq!(extract_http_host(trailing_dot_numeric_host), None);

        let ipv6_host = b"GET / HTTP/1.1\r\nHost: ::1\r\n\r\n";
        assert_eq!(extract_http_host(ipv6_host), None);

        let duplicate_host = b"GET / HTTP/1.1\r\nHost: example.org\r\nHost: example.net\r\n\r\n";
        assert_eq!(extract_http_host(duplicate_host), None);

        let overlong_label = format!("{}.example.test", "a".repeat(64));
        let overlong_host = format!("GET / HTTP/1.1\r\nHost: {overlong_label}\r\n\r\n");
        assert_eq!(extract_http_host(overlong_host.as_bytes()), None);
    }

    #[test]
    fn test_extract_http_host_rejects_unicode_whitespace_padding() {
        let data = "GET / HTTP/1.1\r\nHost: \u{00a0}example.com\u{00a0}\r\n\r\n";
        assert_eq!(extract_http_host(data.as_bytes()), None);
    }

    #[test]
    fn http_server_header_rejects_ascii_padding() {
        assert_eq!(
            safe_server_header_value(" Apache/2.4.99 "),
            Cow::Borrowed("NetTrap")
        );
    }

    #[test]
    fn test_extract_http_host_preserves_obs_text_in_other_headers() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Test: hi\xff\r\n\r\n";

        assert_eq!(extract_http_host(data).as_deref(), Some("example.com"));
    }

    #[test]
    fn test_extract_http_host_accepts_absolute_form_request_line() {
        let data = b"GET http://example.com/index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";

        assert_eq!(extract_http_host(data).as_deref(), Some("example.com"));

        let special_absolute_form =
            b"GET http://127.0.0.1/index.html HTTP/1.0\r\nX-Test: 1\r\n\r\n";
        assert_eq!(extract_http_host(special_absolute_form), None);

        let special_ipv6_absolute_form =
            b"GET http://[::1]/index.html HTTP/1.0\r\nX-Test: 1\r\n\r\n";
        assert_eq!(extract_http_host(special_ipv6_absolute_form), None);
    }

    #[test]
    fn test_extract_http_host_uses_absolute_form_target_without_host_header() {
        let data = b"GET http://example.com:8080/index.html HTTP/1.0\r\nX-Test: 1\r\n\r\n";

        assert_eq!(extract_http_host(data).as_deref(), Some("example.com:8080"));
    }

    #[test]
    fn test_extract_http_host_canonicalizes_case_and_absolute_form() {
        let data = b"GET / HTTP/1.1\r\nHost: EXAMPLE.COM.:8080\r\n\r\n";

        assert_eq!(extract_http_host(data).as_deref(), Some("example.com:8080"));
    }

    #[test]
    fn test_extract_http_host_rejects_malformed_host_header_even_with_absolute_target() {
        let data = b"GET http://example.com/index.html HTTP/1.1\r\nHost: bad host\r\n\r\n";

        assert_eq!(extract_http_host(data), None);
    }

    #[test]
    fn test_extract_http_host_uses_connect_authority_without_host_header() {
        let data = b"CONNECT example.com:443 HTTP/1.0\r\nX-Test: 1\r\n\r\n";

        assert_eq!(extract_http_host(data).as_deref(), Some("example.com:443"));
    }

    #[test]
    fn test_extract_http_host_canonicalizes_bracketed_ipv6_connect_authority() {
        let data = b"CONNECT [2001:db8:0:0::1]:443 HTTP/1.0\r\nX-Test: 1\r\n\r\n";

        assert_eq!(
            extract_http_host(data).as_deref(),
            Some("[2001:db8::1]:443")
        );
    }

    #[test]
    fn test_extract_http_host_rejects_unicode_whitespace_in_header_name() {
        let data = "GET / HTTP/1.1\r\nHo\u{00a0}st: example.com\r\n\r\n";
        assert_eq!(extract_http_host(data.as_bytes()), None);
    }

    #[test]
    fn test_extract_http_host_rejects_overlong_hostnames() {
        let hostname = format!("{}.example.test", "a".repeat(64));
        let data = format!("GET / HTTP/1.1\r\nHost: {hostname}\r\n\r\n");

        assert_eq!(extract_http_host(data.as_bytes()), None);
    }

    #[test]
    fn test_extract_http_host_rejects_injected_request_line_separators() {
        let data = b"GET / HTTP/1.1\nHost: example.org\r\n\r\n";

        assert_eq!(extract_http_host(data), None);
        assert_eq!(extract_http_method(data), None);
        assert_eq!(extract_http_target(data), None);
    }

    #[test]
    fn test_extract_http_host_rejects_unicode_line_separators_in_headers() {
        let data = "GET / HTTP/1.1\r\nHost: example.org\u{2028}Injected: yes\r\n\r\n";

        assert_eq!(extract_http_host(data.as_bytes()), None);
    }

    #[test]
    fn test_extract_http_method() {
        let data = b"POST /login HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_method(data).as_deref(), Some("POST"));

        let data2 = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_method(data2).as_deref(), Some("GET"));

        let data3 = b"";
        assert_eq!(extract_http_method(data3), None);

        let nul_method = b"GE\0T / HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_method(nul_method), None);
    }

    #[test]
    fn test_extract_http_path() {
        let data = b"GET /path/to/resource?q=1 HTTP/1.1\r\n\r\n";
        assert_eq!(
            extract_http_target(data).as_deref(),
            Some("/path/to/resource?q=1")
        );
        assert_eq!(
            extract_http_path(data).as_deref(),
            Some("/path/to/resource")
        );

        let data2 = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2).as_deref(), Some("/"));

        let data2b = b"GET /wpad.dat?x=1 HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2b).as_deref(), Some("/wpad.dat"));

        let data2c = b"GET http://example.test/index.html?v=1#frag HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2c).as_deref(), Some("/index.html"));

        let data2d = b"GET HTTP://example.test/Upper?q=1 HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2d).as_deref(), Some("/Upper"));

        let invalid_absolute_form = b"GET http://bad_example.test/index.html HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(invalid_absolute_form), None);

        let numeric_absolute_form = b"GET http://12345/index.html HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(numeric_absolute_form), None);

        let trailing_dot_numeric_absolute_form = b"GET http://12345./index.html HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(trailing_dot_numeric_absolute_form), None);

        let ipv4_absolute_form = b"GET http://192.0.2.10/index.html HTTP/1.1\r\n\r\n";
        assert_eq!(
            extract_http_path(ipv4_absolute_form).as_deref(),
            Some("/index.html")
        );

        let loopback_absolute_form = b"GET http://127.0.0.1/index.html HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(loopback_absolute_form), None);

        let multicast_absolute_form = b"GET http://224.0.0.1/index.html HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(multicast_absolute_form), None);

        let ipv6_loopback_absolute_form = b"GET http://[::1]/index.html HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(ipv6_loopback_absolute_form), None);

        let ipv6_multicast_absolute_form = b"GET http://[ff02::1]/index.html HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(ipv6_multicast_absolute_form), None);

        let trailing_dot_absolute_form = b"GET http://example.test./index.html HTTP/1.1\r\n\r\n";
        assert_eq!(
            extract_http_path(trailing_dot_absolute_form).as_deref(),
            Some("/index.html")
        );

        let ipv6_absolute_form = b"GET http://::1/index.html HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(ipv6_absolute_form), None);

        let data2e = b"GET /alpha/../beta/./gamma HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2e).as_deref(), Some("/beta/gamma"));

        let data2f = b"GET /alpha\\..\\beta\\gamma HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2f).as_deref(), Some("/beta/gamma"));

        let data2f2 = b"GET http://example.test\\alpha\\..\\beta\\gamma?x=1 HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2f2).as_deref(), Some("/beta/gamma"));

        let data2g = b"OPTIONS * HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2g).as_deref(), Some("*"));

        let data2h = b"CONNECT example.test:443 HTTP/1.1\r\n\r\n";
        assert_eq!(
            extract_http_path(data2h).as_deref(),
            Some("example.test:443")
        );

        let data2h_trailing_dot = b"CONNECT example.test.:443 HTTP/1.1\r\n\r\n";
        assert_eq!(
            extract_http_path(data2h_trailing_dot).as_deref(),
            Some("example.test.:443")
        );

        let data2h_ipv4 = b"CONNECT 192.0.2.10:443 HTTP/1.1\r\n\r\n";
        assert_eq!(
            extract_http_path(data2h_ipv4).as_deref(),
            Some("192.0.2.10:443")
        );

        let unspecified_authority = b"CONNECT 0.0.0.0:443 HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(unspecified_authority), None);

        let unspecified_ipv6_authority = b"CONNECT [::]:443 HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(unspecified_ipv6_authority), None);

        let data2h_ipv6 = b"CONNECT 2001:db8::1:443 HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2h_ipv6), None);

        let data2h2 = b"CONNECT bad_example.test:443 HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2h2), None);

        let data2i = b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2i), None);

        let data2j = b"CONNECT [::1]:0 HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2j), None);

        let invalid_bracketed_literal = b"CONNECT [not-an-ip]:443 HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(invalid_bracketed_literal), None);

        let userinfo_authority = b"CONNECT user@example.test:443 HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(userinfo_authority), None);

        let data2k = b"GET foo:bar HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2k), None);

        let data2l = b"GET foo HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2l), None);

        let data2m = b"GET * HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2m), None);

        let data2n = b"CONNECT /path HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2n), None);

        let data2o = b"GET\t/path HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2o), None);

        let data3 = b"GET\r\n\r\n";
        assert_eq!(extract_http_path(data3), None);
    }

    #[test]
    fn test_extract_http_body() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(extract_http_body(request), Some(b"hello".to_vec()));

        let absolute_form_request =
            b"POST http://example.test/upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(
            extract_http_body(absolute_form_request),
            Some(b"hello".to_vec())
        );

        let obs_text_header = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nX-Test: hi\xff\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(extract_http_body(obs_text_header), Some(b"hello".to_vec()));

        let injected_request_line = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nGET /evil HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        assert!(extract_http_body(injected_request_line).is_none());

        let chunked =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        assert_eq!(extract_http_body(chunked), Some(b"test".to_vec()));

        let truncated =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhel";
        assert!(extract_http_body(truncated).is_none());

        let invalid_length =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: abc\r\n\r\nhello";
        assert!(extract_http_body(invalid_length).is_none());

        let signed_length =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: +5\r\n\r\nhello";
        assert!(extract_http_body(signed_length).is_none());

        let conflicting_duplicate_length =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\nContent-Length: 4\r\n\r\nhello";
        assert!(extract_http_body(conflicting_duplicate_length).is_none());

        let invalid_duplicate_length =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: abc\r\nContent-Length: 5\r\n\r\nhello";
        assert!(extract_http_body(invalid_duplicate_length).is_none());

        let matching_duplicate_length =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 05\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(
            extract_http_body(matching_duplicate_length),
            Some(b"hello".to_vec())
        );

        let content_length_with_trailing_bytes =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhelloGET /b HTTP/1.1\r\nHost: example.test\r\n\r\n";
        assert!(extract_http_body(content_length_with_trailing_bytes).is_none());

        let unsupported_encoding =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip\r\n\r\nhello";
        assert!(extract_http_body(unsupported_encoding).is_none());

        let transfer_encoding_with_content_length = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 14\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        assert!(extract_http_body(transfer_encoding_with_content_length).is_none());

        let mixed_transfer_encoding =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        assert!(extract_http_body(mixed_transfer_encoding).is_none());

        let chunked_not_final =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked, gzip\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        assert!(extract_http_body(chunked_not_final).is_none());

        let chunked_with_trailing_bytes = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\nGET /b HTTP/1.1\r\nHost: example.test\r\n\r\n";
        assert!(extract_http_body(chunked_with_trailing_bytes).is_none());

        let leading_whitespace_headers =
            b"POST /upload HTTP/1.1\r\n Host: example.test\r\n Content-Length: 5\r\n\r\nhello";
        assert!(extract_http_body(leading_whitespace_headers).is_none());

        let leading_whitespace_transfer_encoding =
            b"POST /upload HTTP/1.1\r\n Host: example.test\r\n Transfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        assert!(extract_http_body(leading_whitespace_transfer_encoding).is_none());

        let unicode_whitespace_headers = "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: \u{00a0}5\u{00a0}\r\n\r\nhello";
        assert!(extract_http_body(unicode_whitespace_headers.as_bytes()).is_none());

        let unicode_whitespace_transfer_encoding = "POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\u{00a0}\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        assert!(extract_http_body(unicode_whitespace_transfer_encoding.as_bytes()).is_none());

        let colonless_header =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nBroken-Header\r\n\r\nhello";
        assert!(extract_http_body(colonless_header).is_none());

        let control_value =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nX-Test: hello\x0bworld\r\n\r\nhello";
        assert!(extract_http_body(control_value).is_none());

        let unicode_separator_value = "POST /upload HTTP/1.1\r\nHost: example.test\r\nX-Test: hello\u{2028}world\r\n\r\nhello";
        assert!(extract_http_body(unicode_separator_value.as_bytes()).is_none());

        let signed_chunk_size =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n+4\r\ntest\r\n0\r\n\r\n";
        assert!(extract_http_body(signed_chunk_size).is_none());

        let whitespace_chunk_size =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n 4\r\ntest\r\n0\r\n\r\n";
        assert!(extract_http_body(whitespace_chunk_size).is_none());

        let chunk_extension_with_empty_suffix =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4;\r\ntest\r\n0\r\n\r\n";
        assert!(extract_http_body(chunk_extension_with_empty_suffix).is_none());

        let chunk_extension_with_whitespace =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4; foo=bar\r\ntest\r\n0\r\n\r\n";
        assert!(extract_http_body(chunk_extension_with_whitespace).is_none());

        let duplicate_chunked =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        assert!(extract_http_body(duplicate_chunked).is_none());

        let invalid_trailers = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nBad-Trailer\r\n\r\n";
        assert!(extract_http_body(invalid_trailers).is_none());

        let max_hex_digits = format!("{:x}", usize::MAX).len();
        let chunk_size = usize::MAX - (max_hex_digits + 2);
        let oversized_chunk = format!(
            "POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n{chunk_size:x}\r\nx"
        );
        assert!(extract_http_body(oversized_chunk.as_bytes()).is_none());

        let coalesced =
            b"GET /a HTTP/1.1\r\nHost: example.test\r\n\r\nGET /b HTTP/1.1\r\nHost: example.test\r\n\r\n";
        assert!(extract_http_body(coalesced).is_none());

        let mixed_line_endings =
            b"POST /upload HTTP/1.1\r\nHost: example.test\nContent-Length: 5\r\n\r\nhello";
        assert!(extract_http_body(mixed_line_endings).is_none());
    }

    #[test]
    fn fakefile_response_serves_real_bodies_for_known_extensions() {
        let _cwd_lock = crate::test_util::lock_current_dir();

        // A `.exe` request without a webroot must return a non-empty PE stub,
        let exe = build_http_response_with_fakefile("/payload.exe", "NetTrap");
        let text = String::from_utf8_lossy(&exe);
        assert!(text.contains("Content-Type: application/octet-stream"));
        assert!(!text.contains("Content-Length: 0\r\n"));
        let body_start = exe
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("headers")
            + 4;
        assert_eq!(&exe[body_start..body_start + 2], b"MZ");

        let root = build_http_response_with_fakefile("/", "NetTrap");
        let root_text = String::from_utf8_lossy(&root);
        assert!(root_text.contains("Content-Type: text/html"));
        assert!(root_text.contains("<html>"));
    }

    #[test]
    fn fakefile_response_ignores_query_and_fragment_suffixes() {
        let _cwd_lock = crate::test_util::lock_current_dir();

        let response = build_http_response_with_fakefile("/payload.exe?dl=1#frag", "NetTrap");
        let body_start = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("headers")
            + 4;

        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(
            String::from_utf8_lossy(&response).contains("Content-Type: application/octet-stream")
        );
        assert_eq!(&response[body_start..body_start + 2], b"MZ");
    }

    #[test]
    fn fakefile_response_ignores_path_parameters_for_extension_lookup() {
        let _cwd_lock = crate::test_util::lock_current_dir();

        let response = build_http_response_with_fakefile("/payload.exe;download=1", "NetTrap");
        let body_start = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("headers")
            + 4;

        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(
            String::from_utf8_lossy(&response).contains("Content-Type: application/octet-stream")
        );
        assert_eq!(&response[body_start..body_start + 2], b"MZ");
    }

    #[test]
    fn fakefile_response_prefers_default_files_assets_when_present() {
        let workspace = unique_temp_dir("nettrap-utils-default-files");
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(workspace.join("defaultFiles")).expect("create defaultFiles dir");
        std::fs::write(
            workspace.join("defaultFiles").join("NetTrap.html"),
            b"<html><body><h1>utils-default-files-hit</h1></body></html>",
        )
        .expect("write default file");

        let _guard = current_dir_guard(&workspace);
        let response = build_http_response_with_fakefile("/missing.html", "NetTrap");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("utils-default-files-hit"), "got: {text:?}");
        assert!(!text.contains("Welcome to the server."), "got: {text:?}");
        drop(_guard);
        std::fs::remove_dir_all(workspace).expect("cleanup temp workspace");
    }

    #[test]
    fn fakefile_response_rejects_large_default_files_asset() {
        let workspace = unique_temp_dir("nettrap-utils-default-files-large");
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(workspace.join("defaultFiles")).expect("create defaultFiles dir");
        let file = std::fs::File::create(workspace.join("defaultFiles").join("NetTrap.html"))
            .expect("create sparse file");
        file.set_len(MAX_DEFAULT_FILE_RESPONSE_BYTES + 1)
            .expect("extend sparse file");
        drop(file);

        let _guard = current_dir_guard(&workspace);
        let response = build_http_response_with_fakefile("/missing.html", "NetTrap");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 413 Payload Too Large"));
        assert!(!text.contains("Welcome to the server."));
        drop(_guard);
        std::fs::remove_dir_all(workspace).expect("cleanup temp workspace");
    }

    #[test]
    fn fakefile_response_serves_exact_default_files_name_when_present() {
        let workspace = unique_temp_dir("nettrap-utils-ncsi");
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(workspace.join("defaultFiles")).expect("create defaultFiles dir");
        std::fs::write(
            workspace.join("defaultFiles").join("NCSI.txt"),
            b"stock-ncsi-response",
        )
        .expect("write default file");

        let _guard = current_dir_guard(&workspace);
        let response = build_http_response_with_fakefile("/NCSI.txt", "NetTrap");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("stock-ncsi-response"), "got: {text:?}");
        assert!(text.contains("Content-Type: text/plain"));
        drop(_guard);
        std::fs::remove_dir_all(workspace).expect("cleanup temp workspace");
    }

    #[test]
    fn fakefile_response_prefers_default_files_assets_with_query_suffix() {
        let workspace = unique_temp_dir("nettrap-utils-default-files-query");
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(workspace.join("defaultFiles")).expect("create defaultFiles dir");
        std::fs::write(
            workspace.join("defaultFiles").join("NetTrap.html"),
            b"<html><body><h1>query-hit</h1></body></html>",
        )
        .expect("write default file");

        let _guard = current_dir_guard(&workspace);
        let response = build_http_response_with_fakefile("/missing.html?x=1#frag", "NetTrap");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("query-hit"), "got: {text:?}");
        assert!(!text.contains("Welcome to the server."), "got: {text:?}");
        drop(_guard);
        std::fs::remove_dir_all(workspace).expect("cleanup temp workspace");
    }

    #[test]
    fn fakefile_response_prefers_default_files_assets_with_path_parameters() {
        let workspace = unique_temp_dir("nettrap-utils-default-files-params");
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(workspace.join("defaultFiles")).expect("create defaultFiles dir");
        std::fs::write(
            workspace.join("defaultFiles").join("NetTrap.html"),
            b"<html><body><h1>params-hit</h1></body></html>",
        )
        .expect("write default file");

        let _guard = current_dir_guard(&workspace);
        let response = build_http_response_with_fakefile("/missing.html;download=1", "NetTrap");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("params-hit"), "got: {text:?}");
        assert!(!text.contains("Welcome to the server."), "got: {text:?}");
        drop(_guard);
        std::fs::remove_dir_all(workspace).expect("cleanup temp workspace");
    }

    #[test]
    fn fakefile_response_serves_literal_semicolon_filename_when_present() {
        let workspace = unique_temp_dir("nettrap-utils-semicolon-file");
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(workspace.join("defaultFiles")).expect("create defaultFiles dir");
        std::fs::write(
            workspace
                .join("defaultFiles")
                .join("payload.exe;download=1"),
            b"literal-semicolon",
        )
        .expect("write default file");

        let _guard = current_dir_guard(&workspace);
        let response = build_http_response_with_fakefile("/payload.exe;download=1", "NetTrap");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("literal-semicolon"), "got: {text:?}");
        assert!(!text.contains("MZ"));
        drop(_guard);
        std::fs::remove_dir_all(workspace).expect("cleanup temp workspace");
    }

    #[test]
    fn fakefile_response_rejects_unsafe_stripped_lookup_path() {
        let _cwd_lock = crate::test_util::lock_current_dir();

        let response = build_http_response_with_fakefile("/safe/..;x/payload.exe", "NetTrap");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 404 Not Found"), "got: {text:?}");
        assert!(!text.contains("MZ"));
    }

    #[test]
    fn fakefile_response_rejects_default_files_path_traversal() {
        let workspace = unique_temp_dir("nettrap-utils-default-files-traversal");
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(workspace.join("defaultFiles")).expect("create defaultFiles dir");
        std::fs::write(workspace.join("secret.exe"), b"outside-secret").expect("write outside");

        let _guard = current_dir_guard(&workspace);
        for path in [
            "/../../secret.exe",
            "/%2e%2e/secret.exe",
            "/..%2fsecret.exe",
        ] {
            let response = build_http_response_with_fakefile(path, "NetTrap");
            let text = String::from_utf8_lossy(&response);

            assert!(text.starts_with("HTTP/1.1 404 Not Found"), "{path}: {text}");
            assert!(!text.contains("outside-secret"), "{path}: {text}");
            assert!(!text.contains("MZ"), "{path}: {text}");
        }
        drop(_guard);
        std::fs::remove_dir_all(workspace).expect("cleanup temp workspace");
    }

    #[test]
    fn fakefile_response_serves_directory_index_from_default_files() {
        let workspace = unique_temp_dir("nettrap-utils-default-files-index");
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(workspace.join("defaultFiles").join("dir"))
            .expect("create defaultFiles dir");
        std::fs::write(
            workspace
                .join("defaultFiles")
                .join("dir")
                .join("index.html"),
            b"<html><body><h1>dir-index-hit</h1></body></html>",
        )
        .expect("write default file");

        let _guard = current_dir_guard(&workspace);
        let response = build_http_response_with_fakefile("/dir/", "NetTrap");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("dir-index-hit"), "got: {text:?}");
        assert!(!text.contains("Welcome to the server."), "got: {text:?}");
        drop(_guard);
        std::fs::remove_dir_all(workspace).expect("cleanup temp workspace");
    }

    #[test]
    fn fakefile_response_skips_directory_without_index_when_searching_default_files() {
        let workspace = unique_temp_dir("nettrap-utils-default-files-empty-dir");
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(workspace.join("defaultFiles").join("dir"))
            .expect("create defaultFiles dir");

        let _guard = current_dir_guard(&workspace);
        let response = build_http_response_with_fakefile("/dir/", "NetTrap");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("<html>"));
        assert!(!text.contains("Internal Server Error"));
        drop(_guard);
        std::fs::remove_dir_all(workspace).expect("cleanup temp workspace");
    }

    #[test]
    fn fakefile_response_rejects_misconfigured_default_files_entry() {
        let workspace = unique_temp_dir("nettrap-utils-default-files-dir");
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(workspace.join("defaultFiles").join("NetTrap.html"))
            .expect("create directory at default file path");

        let _guard = current_dir_guard(&workspace);
        let response = build_http_response_with_fakefile("/missing.html", "NetTrap");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 500 Internal Server Error"));
        assert!(!text.contains("Welcome to the server."));
        drop(_guard);
        std::fs::remove_dir_all(workspace).expect("cleanup temp workspace");
    }

    #[cfg(unix)]
    #[test]
    fn fakefile_response_rejects_symlinked_default_files_entry() {
        use std::os::unix::fs::symlink;

        let workspace = unique_temp_dir("nettrap-utils-default-files-symlink");
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(workspace.join("defaultFiles")).expect("create defaultFiles dir");
        std::fs::write(workspace.join("outside.html"), b"<html>outside</html>")
            .expect("write outside file");
        symlink(
            workspace.join("outside.html"),
            workspace.join("defaultFiles").join("NetTrap.html"),
        )
        .expect("create defaultFiles symlink");

        let _guard = current_dir_guard(&workspace);
        let response = build_http_response_with_fakefile("/missing.html", "NetTrap");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 500 Internal Server Error"));
        assert!(!text.contains("outside"));
        drop(_guard);
        std::fs::remove_dir_all(workspace).expect("cleanup temp workspace");
    }

    #[test]
    fn test_build_http_response() {
        let response = build_http_response_with_body(
            b"<html><body><h1>It works!</h1></body></html>".to_vec(),
            "text/html",
            "TestServer/1.0",
        );
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(response.windows(4).any(|w| w == b"html"));
    }

    #[test]
    fn http_response_server_header_cannot_inject_headers() {
        let _cwd_lock = crate::test_util::lock_current_dir();

        let response = build_http_response_with_fakefile(
            "/index.html",
            "NetTrap\r\nX-Injected: yes\r\nContent-Length: 0",
        );
        let text = std::str::from_utf8(&response).expect("response is utf-8");

        assert!(text.contains("\r\nServer: NetTrap\r\n"));
        assert!(!text.contains("X-Injected"));
        assert!(!text.contains("Server: NetTrap\r\nX-Injected"));
    }

    #[test]
    fn http_response_server_header_rejects_unicode_whitespace() {
        let _cwd_lock = crate::test_util::lock_current_dir();

        let response =
            build_http_response_with_fakefile("/index.html", "NetTrap\u{00a0}X-Injected: yes");
        let text = std::str::from_utf8(&response).expect("response is utf-8");

        assert!(text.contains("\r\nServer: NetTrap\r\n"));
        assert!(!text.contains("X-Injected"));
    }

    #[test]
    fn http_response_server_header_rejects_unicode_line_separators() {
        let _cwd_lock = crate::test_util::lock_current_dir();

        let response =
            build_http_response_with_fakefile("/index.html", "NetTrap\u{2028}X-Injected: yes");
        let text = std::str::from_utf8(&response).expect("response is utf-8");

        assert!(text.contains("\r\nServer: NetTrap\r\n"));
        assert!(!text.contains("X-Injected"));
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        static TEMP_COUNTER: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);
        let seq = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("{prefix}-{}-{seq}", std::process::id()))
    }

    fn current_dir_guard(new_dir: &Path) -> CurrentDirGuard {
        let lock = crate::test_util::lock_current_dir();
        let previous = std::env::current_dir().expect("capture current dir");
        std::env::set_current_dir(new_dir).expect("set current dir");
        CurrentDirGuard {
            previous,
            _lock: lock,
        }
    }

    struct CurrentDirGuard {
        previous: PathBuf,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for CurrentDirGuard {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.previous).expect("restore current dir");
        }
    }

    #[test]
    fn http_post_dump_path_joins_prefix_as_filesystem_path() {
        let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("socket address");
        let path =
            http_post_dump_path(&Some("spool/".to_string()), &peer).expect("path should build");

        assert!(path.starts_with("spool"));
        assert_eq!(path.extension().and_then(|ext| ext.to_str()), Some("bin"));
    }

    #[test]
    fn http_post_dump_path_preserves_unicode_whitespace_prefix() {
        let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("socket address");
        let path = http_post_dump_path(&Some("\u{00a0}spool\u{2003}".to_string()), &peer)
            .expect("path should build");

        assert!(path.starts_with("\u{00a0}spool\u{2003}"));
        assert_eq!(path.extension().and_then(|ext| ext.to_str()), Some("bin"));
    }

    #[test]
    fn http_post_dump_path_rejects_blank_prefix() {
        let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("socket address");
        let err = http_post_dump_path(&Some(" \t ".to_string()), &peer)
            .expect_err("blank prefix should fail");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("must not be blank"));
    }

    #[test]
    fn http_post_dump_path_rejects_control_character_prefix() {
        let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("socket address");
        let err = http_post_dump_path(&Some("spool\n".to_string()), &peer)
            .expect_err("control character prefix should fail");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string()
                .contains("control characters or unicode separators")
        );
    }

    #[test]
    fn http_post_dump_path_rejects_unicode_line_separator_prefix() {
        let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("socket address");
        let err = http_post_dump_path(&Some("spool\u{2028}".to_string()), &peer)
            .expect_err("unicode separator prefix should fail");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string()
                .contains("control characters or unicode separators")
        );
    }

    #[test]
    fn extract_http_request_line_ignores_body_unicode_separators() {
        let request = concat!(
            "POST /submit HTTP/1.1\r\n",
            "Host: example.test\r\n",
            "Content-Length: 18\r\n",
            "\r\n",
            "alpha\u{2028}beta payload",
        );

        assert_eq!(
            extract_http_method(request.as_bytes()).as_deref(),
            Some("POST")
        );
        assert_eq!(
            extract_http_target(request.as_bytes()).as_deref(),
            Some("/submit")
        );
        assert_eq!(
            extract_http_host(request.as_bytes()).as_deref(),
            Some("example.test")
        );
    }

    #[test]
    fn extract_http_target_rejects_unicode_line_separators() {
        let request = concat!(
            "GET /submit\u{2028}X:1 HTTP/1.1\r\n",
            "Host: example.test\r\n",
            "\r\n",
        );

        assert_eq!(extract_http_target(request.as_bytes()), None);
        assert_eq!(extract_http_path(request.as_bytes()), None);
    }

    #[test]
    fn http_post_dump_path_preserves_ascii_spaced_prefix() {
        let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("socket address");
        let path = http_post_dump_path(&Some("  spool dir  ".to_string()), &peer)
            .expect("path should build");

        assert!(path.starts_with("  spool dir  "));
        assert_eq!(path.extension().and_then(|ext| ext.to_str()), Some("bin"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn log_event_rejects_symlinked_parent_directory() {
        let root =
            std::env::temp_dir().join(format!("nettrap-log-event-symlink-{}", std::process::id()));
        let real_parent = root.join("real");
        let linked_parent = root.join("linked");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");

        let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("socket address");
        let output_path = linked_parent.join("events.jsonl");

        log_event(Some(&output_path), "listener", &peer, "connect", "detail").await;

        assert!(!real_parent.join("events.jsonl").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn log_event_bounds_and_sanitizes_detail() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-log-event-detail-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create temp root");
        let output_path = root.join("events.jsonl");
        let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("socket address");
        let detail = format!("{}{}\nsecret", "a".repeat(300), "\u{2028}");

        log_event(Some(&output_path), "listener", &peer, "connect", &detail).await;

        let content = std::fs::read_to_string(&output_path).expect("read event log");
        let value: serde_json::Value =
            serde_json::from_str(content.trim_end()).expect("event log should be JSON");
        let detail = value
            .get("detail")
            .and_then(serde_json::Value::as_str)
            .expect("detail field should be string");

        assert_eq!(detail.chars().count(), 240);
        assert!(!detail.chars().any(char::is_control));
        assert!(!detail.contains('\u{2028}'));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_log_events_remain_valid_jsonl() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-log-event-concurrent-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create temp root");
        let output_path = std::sync::Arc::new(root.join("events.jsonl"));
        let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("socket address");

        let mut tasks = Vec::new();
        for index in 0..128 {
            let output_path = std::sync::Arc::clone(&output_path);
            tasks.push(tokio::spawn(async move {
                log_event(
                    Some(output_path.as_path()),
                    "listener",
                    &peer,
                    "connect",
                    &format!("event-{index}"),
                )
                .await;
            }));
        }
        for task in tasks {
            task.await.expect("log task should finish");
        }

        let content = std::fs::read_to_string(&*output_path).expect("read event log");
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 128);
        for line in lines {
            serde_json::from_str::<serde_json::Value>(line).expect("each JSONL line is valid");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn log_event_canonicalizes_ipv4_mapped_source_ips() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-log-event-ip-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create temp root");
        let output_path = root.join("events.jsonl");
        let peer: std::net::SocketAddr = "[::ffff:198.51.100.7]:8080".parse().unwrap();

        log_event(Some(&output_path), "listener", &peer, "connect", "detail").await;

        let content = std::fs::read_to_string(&output_path).expect("read event log");
        let value: serde_json::Value =
            serde_json::from_str(content.trim_end()).expect("event log should be JSON");
        assert_eq!(
            value.get("src_ip").and_then(serde_json::Value::as_str),
            Some("198.51.100.7")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn log_event_uses_faketime_offset_for_timestamp() {
        let baseline = crate::faketime::get_delta();
        crate::faketime::set_delta(86_400);

        let root = std::env::temp_dir().join(format!(
            "nettrap-log-event-time-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create temp root");
        let output_path = root.join("events.jsonl");
        let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("socket address");

        log_event(Some(&output_path), "listener", &peer, "connect", "detail").await;

        let content = std::fs::read_to_string(&output_path).expect("read event log");
        let value: serde_json::Value =
            serde_json::from_str(content.trim_end()).expect("event log should be JSON");
        let expected_date = crate::faketime::fake_now().date_naive();
        let timestamp = value
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .expect("timestamp field should be string");
        let parsed_timestamp =
            chrono::DateTime::parse_from_rfc3339(timestamp).expect("timestamp should parse");
        assert_eq!(
            parsed_timestamp.date_naive(),
            expected_date,
            "event log timestamp should follow faketime offset"
        );

        crate::faketime::set_delta(baseline);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dump_http_post_rejects_symlinked_parent_directory() {
        let root =
            std::env::temp_dir().join(format!("nettrap-http-post-symlink-{}", std::process::id()));
        let real_parent = root.join("real");
        let linked_parent = root.join("linked");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");

        let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("socket address");
        let prefix = Some(linked_parent.to_string_lossy().into_owned());

        dump_http_post(b"payload", &prefix, &peer).await;

        let entries = std::fs::read_dir(&real_parent).expect("read real parent");
        assert_eq!(entries.count(), 0);

        let _ = std::fs::remove_dir_all(&root);
    }
}
