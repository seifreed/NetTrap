use nettrap_proto_dns::parse_query_summary;

/// Regression: the hickory-proto library panics ("attempt to subtract with
/// overflow") when parsing a malformed TSIG record whose error-formatting
/// arithmetic underflows. NetTrap's DNS handler must catch this panic so a
/// crafted DNS packet cannot crash the honeypot process.
#[test]
fn dns_parse_does_not_panic_on_malformed_tsig() {
    let data: [u8; 44] = [
        0x81, 0x29, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfa,
        0x00, 0xe8, 0x00, 0x00, 0x21, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0d, 0x01, 0x00, 0x02,
        0x00, 0x41, 0x00, 0x00, 0x09, 0x00, 0x40, 0x02, 0x83, 0x0a, 0x0b, 0xb6, 0x41, 0x0a,
    ];
    let result = std::panic::catch_unwind(|| parse_query_summary(&data));
    assert!(
        result.is_ok(),
        "parse_query_summary must not panic on malformed TSIG data"
    );
    assert!(
        result.unwrap().is_none(),
        "malformed TSIG packet should not parse to a valid query"
    );
}
