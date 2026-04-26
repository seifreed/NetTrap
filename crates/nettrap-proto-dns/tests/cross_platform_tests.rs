// DNS Protocol tests - cross-platform

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
        handler.add_custom_response("test.example.com", vec!["10.0.0.1".to_string()]);

        let query = build_dns_query("test.example.com", 1);
        let result = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dns_custom_response_normalizes_case_and_trailing_dot() {
        let handler = DnsHandler::new();
        handler.add_custom_response("Example.COM.", vec!["10.0.0.1".to_string()]);

        let query = build_dns_query("example.com", 1);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_a_record(&response, "10.0.0.1"));
    }

    #[tokio::test]
    async fn test_dns_ncsi_response_ip_is_configurable() {
        let handler =
            DnsHandler::new().with_ncsi_response_ip("10.1.2.3".parse().expect("valid IPv4"));
        let query = build_dns_query("dns.msftncsi.com", 1);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_a_record(&response, "10.1.2.3"));
    }

    #[tokio::test]
    async fn test_dns_ncsi_only_special_cases_a_queries() {
        let handler =
            DnsHandler::new().with_ncsi_response_ip("10.1.2.3".parse().expect("valid IPv4"));
        let query = build_dns_query("dns.msftncsi.com", 28);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_no_answers(&response));
    }

    #[tokio::test]
    async fn test_dns_default_response_ip_supports_aaaa_ipv6() {
        let handler = DnsHandler::new().with_default_response_ip("2001:db8::10");
        let query = build_dns_query("example.com", 28);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_aaaa_record(&response, "2001:db8::10"));
    }

    #[tokio::test]
    async fn test_dns_default_response_ip_does_not_synthesize_aaaa_from_ipv4() {
        let handler = DnsHandler::new().with_default_response_ip("192.0.2.10");
        let query = build_dns_query("example.com", 28);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_no_answers(&response));
    }

    #[tokio::test]
    async fn test_dns_explicit_mx_response_works_without_wildcard() {
        let handler = DnsHandler::new()
            .with_wildcard(false)
            .with_default_response_mx("mail.example.net.");
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
            .with_default_response_txt("nettrap-test");
        let query = build_dns_query("example.com", 16);
        let response = handler
            .handle_query(&query, "127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();

        assert!(response_has_txt_record(&response, "nettrap-test"));
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

        let mut message = Message::new();
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

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
        message.answers().iter().any(|record| match record.data() {
            RData::A(a) => a.0 == expected,
            _ => false,
        })
    }

    fn response_has_aaaa_record(response: &[u8], ip: &str) -> bool {
        use hickory_proto::op::Message;
        use hickory_proto::rr::RData;

        let expected: std::net::Ipv6Addr = ip.parse().unwrap();
        let message = Message::from_vec(response).unwrap();
        message.answers().iter().any(|record| match record.data() {
            RData::AAAA(aaaa) => aaaa.0 == expected,
            _ => false,
        })
    }

    fn response_has_mx_record(response: &[u8], exchange: &str) -> bool {
        use hickory_proto::op::Message;
        use hickory_proto::rr::RData;

        let message = Message::from_vec(response).unwrap();
        message.answers().iter().any(|record| match record.data() {
            RData::MX(mx) => mx.exchange().to_utf8() == exchange,
            _ => false,
        })
    }

    fn response_has_txt_record(response: &[u8], value: &str) -> bool {
        use hickory_proto::op::Message;
        use hickory_proto::rr::RData;

        let message = Message::from_vec(response).unwrap();
        message.answers().iter().any(|record| match record.data() {
            RData::TXT(txt) => txt
                .txt_data()
                .iter()
                .any(|chunk| chunk.as_ref() == value.as_bytes()),
            _ => false,
        })
    }

    fn response_has_no_answers(response: &[u8]) -> bool {
        use hickory_proto::op::Message;

        Message::from_vec(response).unwrap().answers().is_empty()
    }
}
