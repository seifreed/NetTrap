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
        let text = String::from_utf8_lossy(data);

        if text.contains("M-SEARCH") {
            tracing::warn!("SSDP M-SEARCH discovery attempt");
            let resp = format!(
                "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nST: upnp:rootdevice\r\nUSN: uuid:nettrap::upnp:rootdevice\r\nLOCATION: http://{}:49152/desc.xml\r\nSERVER: Linux/3.14 UPnP/1.1 NetTrap/1.0\r\n\r\n",
                self.listen_ip
            );
            resp.into_bytes()
        } else if text.contains("DeletePortMapping") {
            tracing::warn!(
                "UPnP delete port mapping attempt: {}",
                text.lines().take(3).collect::<Vec<_>>().join(" | ")
            );
            b"<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:DeletePortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"></u:DeletePortMappingResponse></s:Body></s:Envelope>".to_vec()
        } else if text.contains("AddPortMapping") {
            tracing::warn!(
                "UPnP add port mapping attempt: {}",
                text.lines().take(3).collect::<Vec<_>>().join(" | ")
            );
            b"<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:AddPortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"></u:AddPortMappingResponse></s:Body></s:Envelope>".to_vec()
        } else {
            Vec::new()
        }
    }
}

impl Default for UpnpHandler {
    fn default() -> Self {
        Self::new()
    }
}
