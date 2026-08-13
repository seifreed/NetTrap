#[cfg(test)]
mod tests {
    use nettrap_proto_dns::handler::{DnsHandler, DnsHandlerTrait};

    #[tokio::test]
    async fn test_dns_a_record() {
        let handler = DnsHandler::new();
        let query = build_dns_query("example.com", 1); // A record

        let result = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await;
        assert!(result.is_ok(), "DNS A query should succeed");

        let response = result.unwrap();
        assert!(response.len() > 12, "DNS response should have header");
    }

    #[tokio::test]
    async fn test_dns_aaaa_record() {
        let handler = DnsHandler::new();
        let query = build_dns_query("example.com", 28); // AAAA record

        let result = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await;
        assert!(result.is_ok(), "DNS AAAA query should succeed");
    }

    #[tokio::test]
    async fn test_dns_custom_response() {
        let handler = DnsHandler::new();
        handler
            .add_custom_response("test.example.com", vec!["10.0.0.1".to_string()])
            .expect("custom response should validate");

        let query = build_dns_query("test.example.com", 1);
        let result = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dns_custom_response_normalizes_case_and_trailing_dot() {
        let handler = DnsHandler::new();
        handler
            .add_custom_response("Example.COM.", vec!["10.0.0.1".to_string()])
            .expect("custom response should validate");

        let query = build_dns_query("example.com", 1);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_a_record(&response, "10.0.0.1"));
    }

    #[tokio::test]
    async fn test_dns_custom_response_matches_wildcard_label() {
        let handler = DnsHandler::new();
        handler
            .add_custom_response("*.example.com", vec!["10.0.0.9".to_string()])
            .expect("wildcard custom response should validate");

        let query = build_dns_query("www.example.com", 1);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_a_record(&response, "10.0.0.9"));
    }

    #[tokio::test]
    async fn test_dns_ncsi_response_ip_is_configurable() {
        let handler = DnsHandler::new()
            .with_ncsi_response_ip("10.1.2.3".parse().expect("valid IPv4"))
            .expect("valid NCSI IP");
        let query = build_dns_query("dns.msftncsi.com", 1);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_a_record(&response, "10.1.2.3"));
    }

    #[tokio::test]
    async fn test_dns_ncsi_only_special_cases_a_queries() {
        let handler = DnsHandler::new()
            .with_ncsi_response_ip("10.1.2.3".parse().expect("valid IPv4"))
            .expect("valid NCSI IP");
        let query = build_dns_query("dns.msftncsi.com", 28);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_no_answers(&response));
    }

    #[tokio::test]
    async fn test_dns_default_response_ip_supports_aaaa_ipv6() {
        let handler = DnsHandler::new()
            .with_default_response_ip("2001:db8::10")
            .expect("valid default response IP");
        let query = build_dns_query("example.com", 28);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_aaaa_record(&response, "2001:db8::10"));
    }

    #[tokio::test]
    async fn test_dns_default_response_ip_canonicalizes_ipv4_mapped_literal() {
        let handler = DnsHandler::new()
            .with_default_response_ip("::ffff:192.0.2.10")
            .expect("valid default response IP");
        let query = build_dns_query("example.com", 1);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_a_record(&response, "192.0.2.10"));
    }

    #[test]
    fn test_dns_default_response_ip_rejects_unspecified_values() {
        for ip in ["0.0.0.0", "::", "::ffff:0.0.0.0"] {
            let err = match DnsHandler::new().with_default_response_ip(ip) {
                Ok(_) => panic!("unspecified default response IP should fail"),
                Err(err) => err,
            };

            assert!(
                err.to_string().contains("Invalid default DNS response IP"),
                "unexpected error for {ip}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn test_dns_default_response_ip_does_not_synthesize_aaaa_from_ipv4() {
        let handler = DnsHandler::new()
            .with_default_response_ip("192.0.2.10")
            .expect("valid default response IP");
        let query = build_dns_query("example.com", 28);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_no_answers(&response));
    }

    #[test]
    fn test_dns_custom_response_rejects_invalid_ip_strings() {
        let handler = DnsHandler::new();

        let err = match handler.add_custom_response(
            "example.com",
            vec!["10.0.0.1".to_string(), "not-an-ip".to_string()],
        ) {
            Ok(_) => panic!("invalid custom response IP should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("invalid IP 'not-an-ip'"));
    }

    #[tokio::test]
    async fn test_dns_custom_response_canonicalizes_ipv4_mapped_addresses() {
        let handler = DnsHandler::new();
        handler
            .add_custom_response("example.com", vec!["::ffff:192.0.2.10".to_string()])
            .expect("custom response should accept mapped IPv4");
        let query = build_dns_query("example.com", 1);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_a_record(&response, "192.0.2.10"));
    }

    #[test]
    fn test_dns_custom_response_rejects_unspecified_ip_strings() {
        let handler = DnsHandler::new();

        for ip in ["0.0.0.0", "::", "::ffff:0.0.0.0"] {
            let err = match handler.add_custom_response("example.com", vec![ip.to_string()]) {
                Ok(_) => panic!("unspecified custom response IP should fail"),
                Err(err) => err,
            };

            assert!(
                err.to_string().contains("invalid IP"),
                "unexpected error for {ip}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn test_dns_explicit_mx_response_works_without_wildcard() {
        let handler = DnsHandler::new()
            .with_wildcard(false)
            .with_default_response_mx("mail.example.net.")
            .expect("valid default MX response");
        let query = build_dns_query("example.com", 15);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_mx_record(&response, "mail.example.net."));
    }

    #[tokio::test]
    async fn test_dns_explicit_txt_response_works_without_wildcard() {
        let handler = DnsHandler::new()
            .with_wildcard(false)
            .with_default_response_txt("nettrap-test")
            .expect("valid default TXT response");
        let query = build_dns_query("example.com", 16);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_txt_record(&response, "nettrap-test"));
    }

    #[tokio::test]
    async fn test_dns_long_txt_response_is_split_into_character_strings() {
        let txt_value = "a".repeat(300);
        let handler = DnsHandler::new()
            .with_wildcard(false)
            .with_default_response_txt(txt_value.clone())
            .expect("valid default TXT response");
        let query = build_dns_query("example.com", 16);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_concatenated_txt_record(&response, &txt_value));
    }

    #[tokio::test]
    async fn test_dns_mx_txt_fallbacks_stay_disabled_without_wildcard() {
        let handler = DnsHandler::new().with_wildcard(false);

        let mx_response = handler
            .handle_query(
                &build_dns_query("example.com", 15),
                "127.0.0.1:53".parse().unwrap(),
            )
            .await
            .unwrap();
        let txt_response = handler
            .handle_query(
                &build_dns_query("example.com", 16),
                "127.0.0.1:53".parse().unwrap(),
            )
            .await
            .unwrap();

        assert!(response_has_no_answers(&mx_response));
        assert!(response_has_no_answers(&txt_response));
    }

    fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};

        let mut message = Message::new(0, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;

        let name = Name::from_ascii(domain).unwrap();
        let query_type = match qtype {
            1 => RecordType::A,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            _ => RecordType::A,
        };
        let query = Query::query(name, query_type);
        message.add_query(query);

        message.to_vec().unwrap()
    }

    fn response_has_a_record(response: &[u8], ip: &str) -> bool {
        use hickory_proto::op::Message;
        use hickory_proto::rr::RData;

        let expected: std::net::Ipv4Addr = ip.parse().unwrap();
        let message = Message::from_vec(response).unwrap();
        message.answers.iter().any(|record| match &record.data {
            RData::A(a) => a.0 == expected,
            _ => false,
        })
    }

    fn response_has_aaaa_record(response: &[u8], ip: &str) -> bool {
        use hickory_proto::op::Message;
        use hickory_proto::rr::RData;

        let expected: std::net::Ipv6Addr = ip.parse().unwrap();
        let message = Message::from_vec(response).unwrap();
        message.answers.iter().any(|record| match &record.data {
            RData::AAAA(aaaa) => aaaa.0 == expected,
            _ => false,
        })
    }

    fn response_has_mx_record(response: &[u8], exchange: &str) -> bool {
        use hickory_proto::op::Message;
        use hickory_proto::rr::RData;

        let message = Message::from_vec(response).unwrap();
        message.answers.iter().any(|record| match &record.data {
            RData::MX(mx) => mx.exchange.to_utf8() == exchange,
            _ => false,
        })
    }

    fn response_has_txt_record(response: &[u8], value: &str) -> bool {
        use hickory_proto::op::Message;
        use hickory_proto::rr::RData;

        let message = Message::from_vec(response).unwrap();
        message.answers.iter().any(|record| match &record.data {
            RData::TXT(txt) => txt
                .txt_data
                .iter()
                .any(|chunk| chunk.as_ref() == value.as_bytes()),
            _ => false,
        })
    }

    fn response_has_concatenated_txt_record(response: &[u8], value: &str) -> bool {
        use hickory_proto::op::Message;
        use hickory_proto::rr::RData;

        let message = Message::from_vec(response).unwrap();
        message.answers.iter().any(|record| match &record.data {
            RData::TXT(txt) => {
                txt.txt_data.iter().all(|chunk| chunk.len() <= 255)
                    && txt
                        .txt_data
                        .iter()
                        .flat_map(|chunk| chunk.as_ref())
                        .copied()
                        .collect::<Vec<_>>()
                        == value.as_bytes()
            }
            _ => false,
        })
    }

    fn response_has_no_answers(response: &[u8]) -> bool {
        use hickory_proto::op::Message;

        Message::from_vec(response).unwrap().answers.is_empty()
    }

    fn is_nxdomain(response: &[u8]) -> bool {
        use hickory_proto::op::{Message, ResponseCode};

        Message::from_vec(response).unwrap().metadata.response_code == ResponseCode::NXDomain
    }

    #[tokio::test]
    async fn nxdomains_counts_down_once_and_never_cycles() {
        let handler = DnsHandler::new()
            .with_default_response_ip("1.1.1.1")
            .expect("valid default response IP")
            .with_nxdomains(2);
        let src = "127.0.0.1:53".parse().unwrap();
        let query = build_dns_query("c2.evil.test", 1); // A

        for _ in 0..2 {
            let resp = handler.handle_query(&query, src).await.unwrap();
            assert!(is_nxdomain(&resp), "first N A queries must be NXDOMAIN");
        }
        for _ in 0..4 {
            let resp = handler.handle_query(&query, src).await.unwrap();
            assert!(
                !is_nxdomain(&resp),
                "later queries must not cycle back to NXDOMAIN"
            );
            assert!(response_has_a_record(&resp, "1.1.1.1"));
        }
    }

    #[tokio::test]
    async fn nxdomains_only_consumes_a_queries() {
        let handler = DnsHandler::new()
            .with_default_response_ip("1.1.1.1")
            .expect("valid default response IP")
            .with_nxdomains(3);
        let src = "127.0.0.1:53".parse().unwrap();

        let mx = handler
            .handle_query(&build_dns_query("c2.evil.test", 15), src)
            .await
            .unwrap();
        assert!(!is_nxdomain(&mx));

        let a = handler
            .handle_query(&build_dns_query("c2.evil.test", 1), src)
            .await
            .unwrap();
        assert!(is_nxdomain(&a));
    }
}
