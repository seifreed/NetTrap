pub struct UpnpHandler {
    listen_ip: String,
}

impl UpnpHandler {
    pub fn new() -> Self {
        Self {
            listen_ip: "192.168.1.1".to_string(),
        }
    }

    pub fn with_listen_ip(mut self, ip: impl Into<String>) -> Self {
        self.listen_ip = ip.into();
        self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        self.handle_ssdp(data)
    }

    pub fn handle_ssdp(&self, data: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(data);

        if headers_are_well_formed(&text) && is_ssdp_m_search(&text) {
            tracing::warn!("SSDP M-SEARCH discovery attempt");
            self.ssdp_discovery_response()
        } else {
            Vec::new()
        }
    }

    pub fn handle_http(&self, data: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(data);
        if !headers_are_well_formed(&text) {
            return Vec::new();
        }
        let Some((method, path)) = request_line(&text) else {
            return Vec::new();
        };

        if method.eq_ignore_ascii_case("GET") && path == "/desc.xml" {
            tracing::warn!("UPnP device description request");
            return http_xml_response(&self.device_description());
        }

        if !method.eq_ignore_ascii_case("POST") {
            return Vec::new();
        }

        if path != "/upnp/control/WANIPConn1" {
            return Vec::new();
        }

        let Some(action) = header_value(&text, "SOAPAction") else {
            return Vec::new();
        };

        if action_matches(action, "DeletePortMapping") {
            tracing::warn!(
                "UPnP delete port mapping attempt: {}",
                text.lines().take(3).collect::<Vec<_>>().join(" | ")
            );
            http_xml_response(delete_port_mapping_response())
        } else if action_matches(action, "AddPortMapping") {
            tracing::warn!(
                "UPnP add port mapping attempt: {}",
                text.lines().take(3).collect::<Vec<_>>().join(" | ")
            );
            http_xml_response(add_port_mapping_response())
        } else {
            Vec::new()
        }
    }

    fn ssdp_discovery_response(&self) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nST: upnp:rootdevice\r\nUSN: uuid:nettrap::upnp:rootdevice\r\nLOCATION: http://{}:49152/desc.xml\r\nSERVER: Linux/3.14 UPnP/1.1 NetTrap/1.0\r\n\r\n",
            self.listen_ip
        )
        .into_bytes()
    }

    fn device_description(&self) -> String {
        format!(
            "<?xml version=\"1.0\"?><root xmlns=\"urn:schemas-upnp-org:device-1-0\"><specVersion><major>1</major><minor>0</minor></specVersion><URLBase>http://{}:49152/</URLBase><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>NetTrap UPnP Gateway</friendlyName><manufacturer>NetTrap</manufacturer><modelName>NetTrap</modelName><UDN>uuid:nettrap</UDN><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>/upnp/control/WANIPConn1</controlURL><eventSubURL>/upnp/event/WANIPConn1</eventSubURL><SCPDURL>/wanipconnSCPD.xml</SCPDURL></service></serviceList></device></root>",
            self.listen_ip
        )
    }
}

impl Default for UpnpHandler {
    fn default() -> Self {
        Self::new()
    }
}

fn request_line(text: &str) -> Option<(&str, &str)> {
    let line = text.lines().next()?.trim_end_matches('\r');
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let path = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some()
        || method.is_empty()
        || path.is_empty()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return None;
    }
    Some((method, path))
}

fn is_ssdp_m_search(text: &str) -> bool {
    let Some((method, path)) = request_line(text) else {
        return false;
    };
    method.eq_ignore_ascii_case("M-SEARCH")
        && path == "*"
        && header_value(text, "MAN")
            .is_some_and(|value| value.eq_ignore_ascii_case("\"ssdp:discover\""))
        && header_value(text, "ST").is_some()
}

fn header_value<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    for line in text.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim());
        }
    }
    None
}

fn headers_are_well_formed(text: &str) -> bool {
    for line in text.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            return true;
        }
        let Some((key, _)) = line.split_once(':') else {
            return false;
        };
        if key.trim().is_empty() {
            return false;
        }
    }
    true
}

fn action_matches(action: &str, operation: &str) -> bool {
    let action = action.trim().trim_matches('"');
    let Some((service, action_name)) = action.rsplit_once('#') else {
        return false;
    };
    service == "urn:schemas-upnp-org:service:WANIPConnection:1" && action_name == operation
}

fn http_xml_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nServer: Linux/3.14 UPnP/1.1 NetTrap/1.0\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

fn add_port_mapping_response() -> &'static str {
    "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:AddPortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"></u:AddPortMappingResponse></s:Body></s:Envelope>"
}

fn delete_port_mapping_response() -> &'static str {
    "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:DeletePortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"></u:DeletePortMappingResponse></s:Body></s:Envelope>"
}

#[cfg(test)]
mod tests {
    use super::UpnpHandler;

    #[test]
    fn ssdp_m_search_gets_discovery_response() {
        let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: upnp:rootdevice\r\n\r\n";

        let response = UpnpHandler::new().handle_ssdp(request);

        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(
            String::from_utf8_lossy(&response)
                .contains("LOCATION: http://192.168.1.1:49152/desc.xml")
        );
    }

    #[test]
    fn ssdp_does_not_handle_soap_actions() {
        let request =
            b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\n\r\nAddPortMapping";

        let response = UpnpHandler::new().handle_ssdp(request);

        assert!(response.is_empty());
    }

    #[test]
    fn http_get_desc_xml_returns_device_description() {
        let response = UpnpHandler::new()
            .with_listen_ip("10.0.0.1")
            .handle_http(b"GET /desc.xml HTTP/1.1\r\nHost: 10.0.0.1:49152\r\n\r\n");
        let response_text = String::from_utf8_lossy(&response);

        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(response_text.contains("<friendlyName>NetTrap UPnP Gateway</friendlyName>"));
        assert!(response_text.contains("http://10.0.0.1:49152/"));
    }

    #[test]
    fn http_post_add_port_mapping_returns_soap_response() {
        let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nContent-Length: 14\r\n\r\nAddPortMapping";

        let response = UpnpHandler::new().handle_http(request);

        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(String::from_utf8_lossy(&response).contains("AddPortMappingResponse"));
    }

    #[test]
    fn http_post_rejects_action_prefix_match() {
        let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#NotAddPortMapping\"\r\nContent-Length: 17\r\n\r\nNotAddPortMapping";

        let response = UpnpHandler::new().handle_http(request);

        assert!(response.is_empty());
    }

    #[test]
    fn http_rejects_unsupported_http_version() {
        let response = UpnpHandler::new()
            .handle_http(b"GET /desc.xml HTTP/2.0\r\nHost: 10.0.0.1:49152\r\n\r\n");

        assert!(response.is_empty());
    }

    #[test]
    fn http_rejects_malformed_headers() {
        let request = b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\nBroken-Header\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\n\r\n";

        let response = UpnpHandler::new().handle_http(request);

        assert!(response.is_empty());
    }

    #[test]
    fn http_post_without_soap_action_is_not_upnp() {
        let request =
            b"POST /upnp/control/WANIPConn1 HTTP/1.1\r\nHost: router\r\n\r\nAddPortMapping";

        let response = UpnpHandler::new().handle_http(request);

        assert!(response.is_empty());
    }

    #[test]
    fn http_post_on_wrong_path_is_not_upnp() {
        let request = b"POST /submit HTTP/1.1\r\nHost: router\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nContent-Length: 14\r\n\r\nAddPortMapping";

        let response = UpnpHandler::new().handle_http(request);

        assert!(response.is_empty());
    }
}
