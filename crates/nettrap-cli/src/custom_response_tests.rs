#[cfg(unix)]
use super::read_limited_file;
use super::{
    CustomResponseConfig, CustomResponseType, MAX_CUSTOM_RESPONSE_BASE64_CONFIG_BYTES,
    MAX_CUSTOM_RESPONSE_BYTES, MAX_CUSTOM_RESPONSE_FILE_BYTES,
    MAX_CUSTOM_RESPONSE_MATCHERS_PER_FIELD, MAX_CUSTOM_RESPONSE_RULES, host_matches_pattern,
    uri_matches_pattern,
};

#[test]
fn host_matches_are_exact_or_subdomain_only() {
    assert!(host_matches_pattern("evil.com", "evil.com"));
    assert!(host_matches_pattern("api.evil.com", "evil.com"));
    assert!(host_matches_pattern("evil.com:8080", "evil.com"));
    assert!(host_matches_pattern("evil.com.:8080", "evil.com"));
    assert!(!host_matches_pattern("evil.com:8080.", "evil.com"));
    assert!(!host_matches_pattern("evil.com...:8080", "evil.com"));
    assert!(!host_matches_pattern("notevil.com", "evil.com"));
    assert!(!host_matches_pattern("evil.com.attacker.test", "evil.com"));
}

#[test]
fn host_matches_validate_bracketed_ipv6_hosts() {
    assert!(host_matches_pattern("[::1]", "::1"));
    assert!(host_matches_pattern("[::1]:8080", "[::1]"));
    assert!(!host_matches_pattern("[::1]evil", "::1"));
    assert!(!host_matches_pattern("[::1", "[::1"));
    assert!(!host_matches_pattern("[::1]:0", "::1"));
    assert!(!host_matches_pattern("[not-ipv6]", "not-ipv6"));
}

#[test]
fn host_matches_accepts_ipv4_mapped_ipv6_literals() {
    assert!(host_matches_pattern("::ffff:192.0.2.10", "192.0.2.10"));
    assert!(host_matches_pattern("192.0.2.10", "::ffff:192.0.2.10"));
    assert!(host_matches_pattern(
        "[::ffff:192.0.2.10]:8080",
        "192.0.2.10:8080"
    ));
    assert!(host_matches_pattern(
        "[::ffff:192.0.2.10]",
        "[::ffff:192.0.2.10]"
    ));
}

#[test]
fn wildcard_host_matchers_reject_unsafe_host_authorities() {
    assert!(host_matches_pattern("", "*"));
    assert!(host_matches_pattern("example.test", "*"));
    assert!(!host_matches_pattern("127.0.0.1", "*"));
    assert!(!host_matches_pattern("0.0.0.0", "*"));
    assert!(!host_matches_pattern("[::1]", "*"));
    assert!(!host_matches_pattern("example.test\r\nInjected: yes", "*"));
    assert!(!host_matches_pattern("example.test\u{2028}evil.test", "*"));
}

#[test]
fn host_matches_rejects_trailing_dot_numeric_hosts() {
    assert!(!host_matches_pattern("192.0.2.10.", "192.0.2.10"));
    assert!(host_matches_pattern("example.test.", "example.test"));
}

#[test]
fn host_matches_ignore_ports_for_ipv4_literals() {
    assert!(host_matches_pattern("192.0.2.10:8080", "192.0.2.10"));
    assert!(!host_matches_pattern("192.0.2.10.:8080", "192.0.2.10"));
}

#[test]
fn custom_response_rejects_unbracketed_ipv6_host_matchers() {
    let err = CustomResponseConfig::parse("host=::1;uri=/gate;type=static;body=OK")
        .expect_err("bare ipv6 host matcher should fail");

    assert!(
        err.to_string()
            .contains("Invalid custom response rule field 'host'"),
        "unexpected error: {err}"
    );

    let err = CustomResponseConfig::parse("host=2001:db8::1;uri=/gate;type=static;body=OK")
        .expect_err("bare ipv6 host matcher should fail");

    assert!(
        err.to_string()
            .contains("Invalid custom response rule field 'host'"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_host_matcher_ports_require_matching_host_port() {
    let config = CustomResponseConfig::parse("host=example.test:443;uri=/gate;type=static;body=OK")
        .expect("host matcher with port should parse");

    assert!(config.find_match("example.test", "/gate").is_none());
    assert!(config.find_match("example.test:443", "/gate").is_some());
    assert!(config.find_match("example.test:80", "/gate").is_none());
}

#[test]
fn custom_response_rejects_mismatched_host_matcher_ports() {
    let config = CustomResponseConfig::parse("host=example.test:443;uri=/gate;type=static;body=OK")
        .expect("host matcher with port should parse");

    assert!(config.find_match("example.test:80", "/gate").is_none());
}

#[test]
fn custom_response_rejects_wildcard_label_host_matchers() {
    let err = CustomResponseConfig::parse("host=*.example.test;uri=/gate;type=static;body=OK")
        .expect_err("wildcard label host matcher should fail");

    assert!(
        err.to_string()
            .contains("Invalid custom response rule field 'host'")
    );
}

#[test]
fn uri_matches_use_exact_paths_or_suffix_patterns() {
    assert!(uri_matches_pattern("/gate", "/gate"));
    assert!(!uri_matches_pattern("/delegate", "/gate"));
    assert!(uri_matches_pattern("/dropper.exe", ".exe"));
    assert!(!uri_matches_pattern("/dropper.dll", ".exe"));
}

#[test]
fn custom_response_matching_uses_safe_host_and_uri_semantics() {
    let config = CustomResponseConfig::parse(
        "host=evil.com;uri=/gate;type=static;body=OK||host=*;uri=.exe;type=static;body=BIN",
    )
    .expect("custom response config should parse");

    let exact = config.find_match("evil.com", "/gate");
    assert!(exact.is_some());

    let subdomain = config.find_match("api.evil.com", "/gate");
    assert!(subdomain.is_some());

    assert!(config.find_match("notevil.com", "/gate").is_none());
    assert!(config.find_match("evil.com", "/delegate").is_none());
    assert!(config.find_match("evil.com", "/payload.exe").is_some());
}

#[test]
fn custom_response_matching_ignores_path_parameters_for_lookup() {
    let config = CustomResponseConfig::parse(
        "host=*;uri=/payload.exe;type=static;body=BIN||host=*;uri=.exe;type=static;body=EXE",
    )
    .expect("custom response config should parse");

    let exact = config
        .find_match("example.test", "/payload.exe;download=1")
        .expect("canonical path should match");
    assert!(matches!(
        exact.response,
        CustomResponseType::HttpStaticString(ref body) if body == "BIN"
    ));

    let suffix = config
        .find_match("example.test", "/nested/payload.exe;download=1")
        .expect("suffix pattern should match stripped path");
    assert!(matches!(
        suffix.response,
        CustomResponseType::HttpStaticString(ref body) if body == "EXE"
    ));
}

#[test]
fn custom_response_rejects_invalid_host_matchers() {
    let err = CustomResponseConfig::parse("host=mail_example.com;uri=/gate;type=static;body=OK")
        .expect_err("invalid host matcher should fail");

    assert!(
        err.to_string()
            .contains("Invalid custom response rule field 'host'"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_rejects_multiple_trailing_dots_in_host_matchers() {
    let err = CustomResponseConfig::parse("host=evil.com...;uri=/gate;type=static;body=OK")
        .expect_err("invalid host matcher should fail");

    assert!(
        err.to_string()
            .contains("Invalid custom response rule field 'host'"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_rejects_numeric_host_matchers() {
    let err = CustomResponseConfig::parse("host=12345;uri=/gate;type=static;body=OK")
        .expect_err("numeric host matcher should fail");

    assert!(
        err.to_string()
            .contains("Invalid custom response rule field 'host'"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_rejects_overlong_host_labels() {
    let hostname = format!("{}.example.test", "a".repeat(64));
    let err =
        CustomResponseConfig::parse(&format!("host={hostname};uri=/gate;type=static;body=OK"))
            .expect_err("overlong host label should fail");

    assert!(
        err.to_string()
            .contains("Invalid custom response rule field 'host'"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_rejects_overlong_absolute_hostnames() {
    let hostname = format!(
        "{}.{}.{}.{}.",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );
    assert_eq!(hostname.len(), 255);

    let err =
        CustomResponseConfig::parse(&format!("host={hostname};uri=/gate;type=static;body=OK"))
            .expect_err("overlong hostname should fail");

    assert!(
        err.to_string()
            .contains("Invalid custom response rule field 'host'"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_rejects_unspecified_host_matchers() {
    for config_str in [
        "host=0.0.0.0;uri=/gate;type=static;body=OK",
        "host=[::];uri=/gate;type=static;body=OK",
        "host=[::ffff:0.0.0.0];uri=/gate;type=static;body=OK",
    ] {
        let err = CustomResponseConfig::parse(config_str)
            .expect_err("unspecified host matcher should fail");

        assert!(
            err.to_string()
                .contains("Invalid custom response rule field 'host'"),
            "unexpected error: {err}"
        );
    }
}

#[test]
fn custom_response_rejects_special_host_matchers() {
    for config_str in [
        "host=127.0.0.1;uri=/gate;type=static;body=OK",
        "host=255.255.255.255;uri=/gate;type=static;body=OK",
        "host=[::1];uri=/gate;type=static;body=OK",
        "host=[ff02::1];uri=/gate;type=static;body=OK",
        "host=[::ffff:127.0.0.1];uri=/gate;type=static;body=OK",
    ] {
        let err =
            CustomResponseConfig::parse(config_str).expect_err("special host matcher should fail");

        assert!(
            err.to_string()
                .contains("Invalid custom response rule field 'host'"),
            "unexpected error: {err}"
        );
    }
}

#[test]
fn documented_comma_key_syntax_preserves_uri_restriction() {
    let config = CustomResponseConfig::parse("host=evil.com,uri=/gate;type=static;body=OK")
        .expect("custom response config should parse");

    assert!(config.find_match("evil.com", "/gate").is_some());
    assert!(config.find_match("evil.com", "/other").is_none());
    assert!(config.find_match("uri=/gate", "/other").is_none());
}

#[test]
fn custom_response_rejects_unknown_embedded_host_fields() {
    let err = CustomResponseConfig::parse("host=*,typ=file;path=/tmp/payload")
        .expect_err("unknown embedded host field should fail");

    assert!(
        err.to_string()
            .contains("Unknown custom response rule field 'typ=file'"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_rejects_unknown_embedded_uri_fields() {
    let err = CustomResponseConfig::parse("host=*;uri=/gate,typ=file;body=OK")
        .expect_err("unknown embedded uri field should fail");

    assert!(
        err.to_string()
            .contains("Unknown custom response rule field 'typ=file'"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_allows_equals_in_uri_matchers() {
    let config = CustomResponseConfig::parse("host=*;uri=/gate?id=1;type=static;body=OK")
        .expect("URI query matcher should parse");

    assert!(config.find_match("example.test", "/gate?id=1").is_some());
}

#[test]
fn custom_response_matches_original_target_when_rule_contains_query() {
    let config = CustomResponseConfig::parse("host=*;uri=/gate?id=1;type=static;body=OK")
        .expect("URI query matcher should parse");

    let response = config
        .build_response_for_request("example.test", "/gate", "/gate?id=1")
        .expect("query-specific rule should match original target");
    let response = String::from_utf8(response).expect("static response should be utf8");

    assert!(response.ends_with("\r\n\r\nOK"));
}

#[test]
fn custom_response_static_body_preserves_semicolons() {
    let config =
        CustomResponseConfig::parse("host=*;uri=*;type=static;body=line one;line two;line three")
            .expect("static body with semicolons should parse");

    let response = config
        .build_response_for_request("example.test", "/", "/")
        .expect("matching rule should respond");
    let response = String::from_utf8(response).expect("static response should be utf8");

    assert!(response.ends_with("\r\n\r\nline one;line two;line three"));
}

#[test]
fn custom_response_prefers_original_target_over_broader_route_uri_match() {
    let config = CustomResponseConfig::parse(
            "host=*;uri=/gate;type=static;body=GENERIC||host=*;uri=/gate?id=1;type=static;body=SPECIFIC",
        )
        .expect("custom response config should parse");

    let response = config
        .build_response_for_request("example.test", "/gate", "/gate?id=1")
        .expect("specific target rule should win");
    let response = String::from_utf8(response).expect("static response should be utf8");

    assert!(response.ends_with("\r\n\r\nSPECIFIC"));
}

#[test]
fn custom_response_content_type_cannot_inject_headers() {
    let err = CustomResponseConfig::parse(
        "host=*;uri=*;type=static;body=OK;content_type=text/plain\r\nX-Injected: yes",
    )
    .expect_err("unsafe content_type should be rejected");

    assert!(err.to_string().contains("invalid whitespace"));
}

#[test]
fn custom_response_content_type_preserves_semicolon_parameters() {
    let config = CustomResponseConfig::parse(
        "host=*;uri=*;type=static;body=OK;content_type=text/plain; charset=utf-8",
    )
    .expect("content_type with parameters should parse");

    let response = config
        .build_response_for_request("example.test", "/", "/")
        .expect("matching rule should respond");
    let text = String::from_utf8(response).expect("response should be utf-8");

    assert!(text.contains("\r\nContent-Type: text/plain; charset=utf-8\r\n"));
}

#[test]
fn custom_response_content_type_preserves_quoted_semicolons_in_parameters() {
    let config = CustomResponseConfig::parse(
        "host=*;uri=*;type=static;body=OK;content_type=multipart/form-data; boundary=\"abc;def\"",
    )
    .expect("quoted content_type parameter should parse");

    let response = config
        .build_response_for_request("example.test", "/", "/")
        .expect("matching rule should respond");
    let text = String::from_utf8(response).expect("response should be utf-8");

    assert!(text.contains("\r\nContent-Type: multipart/form-data; boundary=\"abc;def\"\r\n"));
}

#[test]
fn custom_response_content_type_rejects_trailing_rule_fields() {
    let err = CustomResponseConfig::parse(
        "host=*;uri=*;type=static;body=OK;content_type=text/plain; body=NEXT",
    )
    .expect_err("content_type should not swallow later rule fields");

    assert!(
        err.to_string()
            .contains("Unknown custom response rule field")
    );
}

#[test]
fn custom_response_mutated_content_type_rejects_injected_headers() {
    let mut config = CustomResponseConfig::parse("host=*;uri=*;type=static;body=OK")
        .expect("custom response config should parse");
    config.rules[0].content_type = Some("text/plain\r\nX-Injected: yes".to_string());

    let response = config
        .build_response_for_request("example.test", "/", "/")
        .expect("mutated content type should fail closed");
    let text = String::from_utf8(response).expect("static response should be utf8");

    assert!(text.starts_with("HTTP/1.1 500 Internal Server Error\r\n"));
    assert!(text.contains("Internal Server Error"));
}

#[test]
fn synthesized_responses_honor_server_version() {
    let config = CustomResponseConfig::parse(
        "host=*;uri=.txt;type=static;body={{server}}||host=*;uri=*;type=base64;data=aGk=",
    )
    .expect("custom response config should parse")
    .with_server_version(Some("Apache/2.4.99 (Unix)"))
    .expect("valid server version should be accepted");

    let static_resp = String::from_utf8(
        config
            .build_response_for_request("h", "/a.txt", "/a.txt")
            .expect("static rule responds"),
    )
    .unwrap();
    assert!(static_resp.contains("\r\nServer: Apache/2.4.99 (Unix)\r\n"));
    assert!(!static_resp.contains("Server: NetTrap"));
    assert!(static_resp.ends_with("\r\n\r\nApache/2.4.99 (Unix)"));

    let b64_resp = String::from_utf8(
        config
            .build_response_for_request("h", "/x", "/x")
            .expect("base64 rule responds"),
    )
    .unwrap();
    assert!(b64_resp.contains("\r\nServer: Apache/2.4.99 (Unix)\r\n"));

    let default_cfg = CustomResponseConfig::parse("host=*;uri=*;type=static;body=hi")
        .expect("custom response config should parse");
    let default_resp = String::from_utf8(
        default_cfg
            .build_response_for_request("h", "/", "/")
            .expect("responds"),
    )
    .unwrap();
    assert!(default_resp.contains("\r\nServer: NetTrap\r\n"));
}

#[test]
fn custom_response_rejects_invalid_base64_payloads() {
    let err = CustomResponseConfig::parse("host=*;uri=*;type=base64;data=%%%")
        .expect_err("invalid base64 should fail");

    assert!(
        err.to_string()
            .contains("Invalid base64 in custom response rule"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_requires_payload_for_file_and_base64_rules() {
    let missing_path = CustomResponseConfig::parse("host=*;uri=*;type=file")
        .expect_err("file response without path should fail");
    assert!(
        missing_path
            .to_string()
            .contains("type 'file' requires non-empty path="),
        "unexpected error: {missing_path}"
    );

    let empty_path = CustomResponseConfig::parse("host=*;uri=*;type=file;path=")
        .expect_err("file response with empty path should fail");
    assert!(
        empty_path
            .to_string()
            .contains("type 'file' requires non-empty path="),
        "unexpected error: {empty_path}"
    );

    let body_for_file = CustomResponseConfig::parse("host=*;uri=*;type=file;body=/tmp/x")
        .expect_err("file response must use path field");
    assert!(
        body_for_file
            .to_string()
            .contains("type 'file' requires non-empty path="),
        "unexpected error: {body_for_file}"
    );

    let data_for_file = CustomResponseConfig::parse("host=*;uri=*;type=file;data=/tmp/x")
        .expect_err("file response must use path field");
    assert!(
        data_for_file
            .to_string()
            .contains("type 'file' requires non-empty path="),
        "unexpected error: {data_for_file}"
    );

    let missing_data = CustomResponseConfig::parse("host=*;uri=*;type=base64")
        .expect_err("base64 response without data should fail");
    assert!(
        missing_data
            .to_string()
            .contains("type 'base64' requires non-empty data="),
        "unexpected error: {missing_data}"
    );

    let body_for_base64 = CustomResponseConfig::parse("host=*;uri=*;type=base64;body=aGk=")
        .expect_err("base64 response must use data field");
    assert!(
        body_for_base64
            .to_string()
            .contains("type 'base64' requires non-empty data="),
        "unexpected error: {body_for_base64}"
    );

    let path_for_base64 = CustomResponseConfig::parse("host=*;uri=*;type=base64;path=aGk=")
        .expect_err("base64 response must use data field");
    assert!(
        path_for_base64
            .to_string()
            .contains("type 'base64' requires non-empty data="),
        "unexpected error: {path_for_base64}"
    );

    let path_without_type = CustomResponseConfig::parse("host=*;uri=*;path=/tmp/payload")
        .expect_err("path= without type=file should fail");
    assert!(
        path_without_type
            .to_string()
            .contains("type 'file' or 'base64' is required for path= or data="),
        "unexpected error: {path_without_type}"
    );

    let data_without_type = CustomResponseConfig::parse("host=*;uri=*;data=aGk=")
        .expect_err("data= without type=base64 should fail");
    assert!(
        data_without_type
            .to_string()
            .contains("type 'file' or 'base64' is required for path= or data="),
        "unexpected error: {data_without_type}"
    );

    let empty_static = CustomResponseConfig::parse("host=*;uri=*;type=static;body=")
        .expect("empty static response body remains valid");
    assert!(empty_static.find_match("example.test", "/").is_some());
}

#[test]
fn custom_response_file_rejects_control_characters_in_path() {
    let err = CustomResponseConfig::parse("host=*;uri=*;type=file;path=/tmp/payload\nnext")
        .expect_err("file path with control characters should fail");

    assert!(
            err.to_string()
                .contains("Invalid custom response rule field 'path': contains control characters or unicode whitespace")
        );
}

#[test]
fn custom_response_file_rejects_unicode_line_separators_in_path() {
    let err = CustomResponseConfig::parse("host=*;uri=*;type=file;path=/tmp/payload\u{2028}next")
        .expect_err("file path with unicode separators should fail");

    assert!(
            err.to_string()
                .contains("Invalid custom response rule field 'path': contains control characters or unicode whitespace")
        );
}

#[test]
fn custom_response_file_rejects_ascii_padding_in_path() {
    let err = CustomResponseConfig::parse("host=*;uri=*;type=file;path= /tmp/payload ")
        .expect_err("file path with ASCII padding should fail");

    assert!(
        err.to_string()
            .contains("Invalid custom response rule field 'path': invalid whitespace")
    );
}

#[cfg(unix)]
#[test]
fn custom_response_file_rejects_fifo_without_blocking() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-custom-response-fifo-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    let path = root.join("payload.bin");
    let status = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("run mkfifo");
    assert!(status.success(), "mkfifo should succeed");

    assert!(matches!(
        read_limited_file(&path, MAX_CUSTOM_RESPONSE_FILE_BYTES),
        Ok(super::LimitedFileRead::NotFile)
    ));
    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

#[test]
fn custom_response_base64_rejects_oversized_encoded_data() {
    let encoded = "A".repeat(MAX_CUSTOM_RESPONSE_BASE64_CONFIG_BYTES + 1);
    let err = CustomResponseConfig::parse(&format!("host=*;uri=*;type=base64;data={encoded}"))
        .expect_err("oversized encoded base64 data should fail before decode");

    assert!(
        err.to_string().contains("encoded size limit"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_base64_rejects_oversized_decoded_data() {
    use base64::Engine as _;

    let payload = vec![b'x'; MAX_CUSTOM_RESPONSE_BYTES + 1];
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
    let err = CustomResponseConfig::parse(&format!("host=*;uri=*;type=base64;data={encoded}"))
        .expect_err("oversized decoded base64 data should fail");

    assert!(
        err.to_string().contains("decoded size limit"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_returns_500_when_template_recursion_exceeds_limit() {
    let nested = format!("{}x{}", "{{#if host}}".repeat(17), "{{/if}}".repeat(17));
    let config = CustomResponseConfig::parse(&format!("host=*;uri=*;type=static;body={}", nested))
        .expect("custom response config should parse");

    let response = String::from_utf8(
        config
            .build_response_for_request("example.com", "/", "/")
            .expect("matching rule should respond"),
    )
    .expect("response should be utf-8");

    assert!(
        response.starts_with("HTTP/1.1 500 Internal Server Error"),
        "unexpected response: {response:?}"
    );
}

#[test]
fn custom_response_rejects_unknown_rule_fields() {
    let err = CustomResponseConfig::parse("host=*;uri=*;boddy=OK")
        .expect_err("unknown fields should fail");

    assert!(
        err.to_string()
            .contains("Unknown custom response rule field"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_rejects_unknown_rule_types() {
    let err = CustomResponseConfig::parse("host=*;uri=*;type=statik;body=OK")
        .expect_err("unknown type should fail");

    assert!(
        err.to_string()
            .contains("Unknown custom response rule type 'statik'"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_rejects_unicode_whitespace_in_rule_tokens() {
    let err = CustomResponseConfig::parse("host=evil\u{00a0}.com;uri=/gate;type=static;body=OK")
        .expect_err("unicode whitespace in host should fail");
    assert!(err.to_string().contains("invalid whitespace"));

    let err = CustomResponseConfig::parse("host=evil.com;uri=/ga\u{00a0}te;type=static;body=OK")
        .expect_err("unicode whitespace in uri should fail");
    assert!(err.to_string().contains("invalid whitespace"));
}

#[test]
fn custom_response_rejects_ascii_padding_in_rule_tokens() {
    for config_str in [
        "host= evil.com;uri=/gate;type=static;body=OK",
        "host=evil.com;uri= /gate;type=static;body=OK",
        "host=evil.com;uri=/gate;type= static;body=OK",
        "host=evil.com;uri=/gate;type=static;body=OK;content_type= text/plain",
    ] {
        let err = CustomResponseConfig::parse(config_str)
            .expect_err("ascii whitespace in rule token should fail");

        assert!(err.to_string().contains("invalid whitespace"), "{err}");
    }
}

#[test]
fn custom_response_rejects_c1_controls_in_rule_tokens() {
    let err = CustomResponseConfig::parse("host=evil\u{009f}.com;uri=/gate;type=static;body=OK")
        .expect_err("C1 control in host should fail");
    assert!(err.to_string().contains("invalid whitespace"));

    let err = CustomResponseConfig::parse("host=evil.com;uri=/ga\u{009f}te;type=static;body=OK")
        .expect_err("C1 control in uri should fail");
    assert!(err.to_string().contains("invalid whitespace"));
}

#[test]
fn custom_response_rejects_empty_list_items() {
    let trailing_host = CustomResponseConfig::parse("host=evil.com,;uri=/gate;type=static;body=OK")
        .expect_err("trailing empty host item should fail");
    assert!(trailing_host.to_string().contains("invalid whitespace"));

    let empty_uri =
        CustomResponseConfig::parse("host=evil.com;uri=/gate,,/next;type=static;body=OK")
            .expect_err("empty uri list item should fail");
    assert!(empty_uri.to_string().contains("invalid whitespace"));
}

#[test]
fn custom_response_rejects_empty_rule_segments() {
    let err = CustomResponseConfig::parse("host=evil.com;;uri=/gate;type=static;body=OK")
        .expect_err("empty rule segment should fail");

    assert!(
        err.to_string()
            .contains("Custom response rule segment must not be blank"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_rejects_blank_config_string() {
    let err = CustomResponseConfig::parse("").expect_err("blank config should fail");

    assert!(
        err.to_string()
            .contains("Custom response config must not be blank"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_rejects_empty_top_level_rule_segments() {
    let err = CustomResponseConfig::parse("host=evil.com||||uri=/gate;type=static;body=OK")
        .expect_err("empty top-level rule segment should fail");

    assert!(
        err.to_string()
            .contains("Custom response rule segment must not be blank"),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_response_rejects_duplicate_rule_fields() {
    let duplicate_host =
        CustomResponseConfig::parse("host=*;host=evil.com;uri=*;type=static;body=hi")
            .expect_err("duplicate host field should fail");
    assert!(
        duplicate_host
            .to_string()
            .contains("Duplicate custom response rule field 'host'")
    );

    let duplicate_type =
        CustomResponseConfig::parse("host=*;uri=*;type=static;type=file;path=/tmp/x")
            .expect_err("duplicate type field should fail");
    assert!(
        duplicate_type
            .to_string()
            .contains("Duplicate custom response rule field 'type'")
    );
}

#[test]
fn custom_response_server_version_cannot_inject_headers() {
    let err = CustomResponseConfig::parse("host=*;uri=*;type=static;body=hi")
        .expect("custom response config should parse")
        .with_server_version(Some("Apache\r\nX-Injected: yes"))
        .expect_err("invalid server version should fail");

    assert!(
        err.to_string()
            .contains("Custom response server_version header value contains unsafe characters")
    );
}

#[test]
fn custom_response_server_version_rejects_unicode_line_separators() {
    let err = CustomResponseConfig::parse("host=*;uri=*;type=static;body=hi")
        .expect("custom response config should parse")
        .with_server_version(Some("Apache\u{2028}X-Injected: yes"))
        .expect_err("unicode line separator should fail");

    assert!(
        err.to_string()
            .contains("Custom response server_version header value contains unsafe characters")
    );
}

#[test]
fn custom_response_server_version_rejects_ascii_padding() {
    let err = CustomResponseConfig::parse("host=*;uri=*;type=static;body=hi")
        .expect("custom response config should parse")
        .with_server_version(Some(" Apache/2.4.99 "))
        .expect_err("ascii padding should fail");

    assert!(
        err.to_string()
            .contains("Custom response server_version header value cannot be padded")
    );
}

#[test]
fn custom_response_static_rejects_oversized_config_body() {
    let body = "a".repeat(MAX_CUSTOM_RESPONSE_BYTES + 1);
    let err = CustomResponseConfig::parse(&format!("host=*;uri=*;type=static;body={body}"))
        .expect_err("oversized static body should fail");

    assert!(err.to_string().contains("static body exceeds size limit"));
}

#[test]
fn custom_response_rejects_too_many_rules() {
    let rule = "host=*;uri=*;type=static;body=OK";
    let config = std::iter::repeat_n(rule, MAX_CUSTOM_RESPONSE_RULES + 1)
        .collect::<Vec<_>>()
        .join("||");

    let err =
        CustomResponseConfig::parse(&config).expect_err("oversized rule set should be rejected");

    assert!(err.to_string().contains("Too many custom response rules"));
}

#[test]
fn custom_response_rejects_too_many_host_matchers() {
    let hosts = (0..=MAX_CUSTOM_RESPONSE_MATCHERS_PER_FIELD)
        .map(|idx| format!("host{idx}.example"))
        .collect::<Vec<_>>()
        .join(",");
    let config = format!("host={hosts};uri=*;type=static;body=OK");

    let err = CustomResponseConfig::parse(&config)
        .expect_err("oversized host matcher list should be rejected");

    assert!(
        err.to_string()
            .contains("Too many custom response host matchers")
    );
}

#[test]
fn custom_response_rejects_too_many_uri_matchers() {
    let uris = (0..=MAX_CUSTOM_RESPONSE_MATCHERS_PER_FIELD)
        .map(|idx| format!("/path{idx}"))
        .collect::<Vec<_>>()
        .join(",");
    let config = format!("host=*;uri={uris};type=static;body=OK");

    let err = CustomResponseConfig::parse(&config)
        .expect_err("oversized URI matcher list should be rejected");

    assert!(
        err.to_string()
            .contains("Too many custom response uri matchers")
    );
}

#[test]
fn custom_response_static_rejects_oversized_template_expansion() {
    let config = CustomResponseConfig::parse("host=*;uri=*;type=static;body={{uri}}{{uri}}")
        .expect("custom response config should parse");
    let target = format!("/{}", "a".repeat(MAX_CUSTOM_RESPONSE_BYTES / 2));

    let response = config
        .build_response_for_request("example.com", "/", &target)
        .expect("matching static rule should respond");
    let text = String::from_utf8(response).expect("response should be utf-8");

    assert!(text.starts_with("HTTP/1.1 413 Payload Too Large"));
}

#[test]
fn custom_response_file_rejects_oversized_file() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-custom-response-limit-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    let path = root.join("large.http");
    let file = std::fs::File::create(&path).expect("create sparse file");
    file.set_len(MAX_CUSTOM_RESPONSE_FILE_BYTES + 1)
        .expect("extend sparse file");
    let config =
        CustomResponseConfig::parse(&format!("host=*;uri=*;type=file;path={}", path.display()))
            .expect("custom response config should parse");

    let response = config
        .build_response_for_request("example.com", "/", "/")
        .expect("matching file rule should respond");

    assert!(response.starts_with(b"HTTP/1.1 413 Payload Too Large"));
    let text = String::from_utf8(response).expect("response should be utf-8");
    assert!(text.contains("\r\nServer: NetTrap\r\n"));
    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

#[test]
fn custom_response_file_rejects_oversized_file_with_custom_server_version() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-custom-response-limit-server-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    let path = root.join("large.http");
    let file = std::fs::File::create(&path).expect("create sparse file");
    file.set_len(MAX_CUSTOM_RESPONSE_FILE_BYTES + 1)
        .expect("extend sparse file");
    let config =
        CustomResponseConfig::parse(&format!("host=*;uri=*;type=file;path={}", path.display()))
            .expect("custom response config should parse")
            .with_server_version(Some("Apache/2.4.99 (Unix)"))
            .expect("valid server version should be accepted");

    let response = config
        .build_response_for_request("example.com", "/", "/")
        .expect("matching file rule should respond");
    let text = String::from_utf8(response).expect("response should be utf-8");

    assert!(text.starts_with("HTTP/1.1 413 Payload Too Large"));
    assert!(text.contains("\r\nServer: Apache/2.4.99 (Unix)\r\n"));
    assert!(!text.contains("\r\nServer: NetTrap\r\n"));
    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

#[test]
fn custom_response_file_preserves_raw_bytes() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-custom-response-raw-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    let path = root.join("raw.http");
    let content = b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n\xff<RAW-DATE>{{host}}";
    std::fs::write(&path, content).expect("write raw response");
    let config =
        CustomResponseConfig::parse(&format!("host=*;uri=*;type=file;path={}", path.display()))
            .expect("custom response config should parse");

    let response = config
        .build_response_for_request("example.com", "/", "/")
        .expect("matching file rule should respond");

    assert_eq!(response, content);
    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

#[test]
fn custom_response_file_accepts_trailing_current_dir_component() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-custom-response-curdir-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    let path = root.join("raw.http");
    let content = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    std::fs::write(&path, content).expect("write raw response");
    let config = CustomResponseConfig::parse(&format!(
        "host=*;uri=*;type=file;path={}",
        path.join(".").display()
    ))
    .expect("custom response config should parse");

    let response = config
        .build_response_for_request("example.com", "/", "/")
        .expect("matching file rule should respond");

    assert_eq!(response, content);
    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

#[cfg(unix)]
#[test]
fn custom_response_file_rejects_final_symlink() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-custom-response-symlink-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    let target = root.join("target.http");
    let link = root.join("linked.http");
    std::fs::write(&target, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        .expect("write target response");
    std::os::unix::fs::symlink(&target, &link).expect("create symlink");
    let config =
        CustomResponseConfig::parse(&format!("host=*;uri=*;type=file;path={}", link.display()))
            .expect("custom response config should parse");

    let response = config
        .build_response_for_request("example.com", "/", "/")
        .expect("matching file rule should respond");
    let text = String::from_utf8(response).expect("response should be utf-8");

    assert!(text.starts_with("HTTP/1.1 500 Internal Server Error"));
    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

#[cfg(unix)]
#[test]
fn custom_response_file_rejects_symlinked_parent_directory() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-custom-response-parent-symlink-{}",
        std::process::id()
    ));
    let real_parent = root.join("real");
    let link_parent = root.join("linked");
    std::fs::create_dir_all(&real_parent).expect("create real parent");
    std::fs::write(
        real_parent.join("target.http"),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
    )
    .expect("write target response");
    std::os::unix::fs::symlink(&real_parent, &link_parent).expect("create symlink parent");

    let config = CustomResponseConfig::parse(&format!(
        "host=*;uri=*;type=file;path={}",
        link_parent.join("target.http").display()
    ))
    .expect("custom response config should parse");

    let response = config
        .build_response_for_request("example.com", "/", "/")
        .expect("matching file rule should respond");
    let text = String::from_utf8(response).expect("response should be utf-8");

    assert!(text.starts_with("HTTP/1.1 500 Internal Server Error"));
    std::fs::remove_dir_all(root).expect("cleanup temp root");
}
