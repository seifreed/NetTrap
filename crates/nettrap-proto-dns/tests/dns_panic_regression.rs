use nettrap_proto_dns::parse_query_summary;

/// Regression: malformed TSIG additional records must be rejected before the
/// third-party parser can reach its integer-overflow error path.
#[test]
fn dns_parse_rejects_malformed_tsig_additional() {
    let data = [
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x01, 0x00, 0xfa, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let result = std::panic::catch_unwind(|| parse_query_summary(&data));
    assert!(
        result.is_ok(),
        "parse_query_summary must not panic on malformed TSIG additional data"
    );
    assert!(
        result.unwrap().is_none(),
        "non-EDNS additional records should not parse to a valid query"
    );
}
