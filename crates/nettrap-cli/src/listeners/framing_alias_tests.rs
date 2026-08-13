use super::*;

#[test]
fn qotd_is_an_alias_for_quotd() {
    assert!(listener_name_matches_protocol("qotd", "quotd"));
    assert!(listener_name_matches_protocol("QOTD", "quotd"));
    assert!(listener_name_matches_protocol("qotd_17", "quotd"));
    assert!(listener_name_matches_protocol("qotd-banner", "quotd"));
    assert!(listener_name_matches_protocol("quotd", "quotd"));
    assert_eq!(explicit_tcp_one_shot_protocol("qotd"), Some("quotd"));
    assert_eq!(explicit_tcp_one_shot_protocol("quotd"), Some("quotd"));
    assert!(!build_tcp_one_shot_response("quotd").is_empty());
}

#[test]
fn time_one_shot_response_uses_the_fake_clock() {
    let previous = crate::faketime::get_delta();
    crate::faketime::set_delta(-1);

    let response = build_tcp_one_shot_response("time");
    let expected = nettrap_proto_time::TimeHandler::new()
        .handle_at(crate::faketime::fake_now())
        .to_vec();

    crate::faketime::set_delta(previous);
    assert_eq!(response, expected);
}

#[test]
fn alias_does_not_capture_unrelated_names() {
    assert_eq!(canonical_protocol_alias("quic"), "quic");
    assert_eq!(canonical_protocol_alias("queue"), "queue");
    assert!(!listener_name_matches_protocol("quic", "quotd"));
}

#[test]
fn explicit_tcp_one_shot_protocol_handles_unicode_case_folding() {
    assert_eq!(explicit_tcp_one_shot_protocol("QOTD"), Some("quotd"));
    assert_eq!(explicit_tcp_one_shot_protocol("QoTd"), Some("quotd"));
    assert!(listener_name_matches_protocol("MÜLLER", "müller"));
    assert_eq!(explicit_tcp_one_shot_protocol("MÜLLER"), None);
    assert_eq!(canonical_protocol_alias("MÜLLER"), "müller");
}
