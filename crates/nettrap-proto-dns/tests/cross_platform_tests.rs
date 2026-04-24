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
}
