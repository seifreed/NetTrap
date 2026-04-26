use crate::mqtt::{
    MQTT_CONNACK, MQTT_CONNECT, MQTT_DISCONNECT, MQTT_PINGREQ, MQTT_PINGRESP, MQTT_PUBACK,
    MQTT_PUBLISH, MQTT_PUBREC, MQTT_SUBACK, MQTT_SUBSCRIBE,
};

pub struct MqttHandler {
    broker_name: String,
}

impl MqttHandler {
    pub fn new() -> Self {
        Self {
            broker_name: "nettrap-mqtt".to_string(),
        }
    }

    pub fn with_broker_name(mut self, name: impl Into<String>) -> Self {
        self.broker_name = name.into();
        self
    }

    pub fn handle_packet(&self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }

        let packet_type = (data[0] >> 4) & 0x0F;
        let Some((remaining_len, start)) = Self::parse_remaining_length(data) else {
            return Vec::new();
        };
        if start.checked_add(remaining_len) != Some(data.len())
            || !Self::valid_fixed_header(data[0], packet_type, remaining_len)
        {
            return Vec::new();
        }

        match packet_type {
            MQTT_CONNECT => {
                // Parse CONNECT: extract client_id, username, password
                let Some(info) = Self::parse_connect(data) else {
                    tracing::debug!("Malformed MQTT CONNECT packet");
                    return Vec::new();
                };
                tracing::info!(
                    "MQTT CONNECT: client_id={}, username={:?}, password={:?}",
                    info.client_id,
                    info.username,
                    info.password
                );
                // Send CONNACK (accepted)
                vec![
                    (MQTT_CONNACK << 4), // Fixed header
                    2,                   // Remaining length
                    0,                   // Session present = false
                    0,                   // Return code 0 = accepted
                ]
            }
            MQTT_PUBLISH => {
                // Parse topic and payload
                if let Some((topic, payload)) = Self::parse_publish(data) {
                    tracing::info!(
                        "MQTT PUBLISH: topic={}, payload_len={}",
                        topic,
                        payload.len()
                    );
                    tracing::debug!("MQTT payload: {:?}", String::from_utf8_lossy(&payload));
                }
                // QoS 0 = no ack, QoS 1 = PUBACK, QoS 2 = PUBREC
                let qos = (data[0] >> 1) & 0x03;
                if matches!(qos, 1 | 2) {
                    // Packet ID follows topic_length(2) + topic(var) in the variable header
                    let remaining_start = start;
                    if remaining_start + 2 <= data.len() {
                        let topic_len =
                            u16::from_be_bytes([data[remaining_start], data[remaining_start + 1]])
                                as usize;
                        let packet_id_pos = remaining_start + 2 + topic_len;
                        if packet_id_pos + 2 <= data.len() {
                            let packet_id =
                                u16::from_be_bytes([data[packet_id_pos], data[packet_id_pos + 1]]);
                            let ack_type = if qos == 2 { MQTT_PUBREC } else { MQTT_PUBACK };
                            return vec![
                                (ack_type << 4),
                                2,
                                (packet_id >> 8) as u8,
                                (packet_id & 0xFF) as u8,
                            ];
                        }
                    }
                }
                Vec::new()
            }
            MQTT_SUBSCRIBE => {
                // Parse topics
                let remaining_start = start;
                if let Some(packet_id) = Self::parse_subscribe_packet_id(&data[remaining_start..]) {
                    tracing::info!("MQTT SUBSCRIBE: packet_id={}", packet_id);
                    // SUBACK with granted QoS 0
                    return vec![
                        (MQTT_SUBACK << 4),
                        3,
                        (packet_id >> 8) as u8,
                        (packet_id & 0xFF) as u8,
                        0, // Granted QoS 0
                    ];
                }
                Vec::new()
            }
            MQTT_PINGREQ => {
                if remaining_len == 0 {
                    vec![(MQTT_PINGRESP << 4), 0]
                } else {
                    Vec::new()
                }
            }
            MQTT_DISCONNECT => {
                tracing::debug!("MQTT DISCONNECT");
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn valid_fixed_header(first: u8, packet_type: u8, remaining_len: usize) -> bool {
        let flags = first & 0x0F;
        match packet_type {
            MQTT_CONNECT => flags == 0,
            MQTT_PINGREQ | MQTT_DISCONNECT => flags == 0 && remaining_len == 0,
            MQTT_PUBLISH => ((flags >> 1) & 0x03) != 0x03,
            MQTT_SUBSCRIBE => flags == 0x02,
            _ => flags == 0,
        }
    }

    /// Parse the remaining length field in MQTT fixed header.
    /// Returns (remaining_length_value, start_of_payload) or None if invalid.
    /// MQTT spec limits remaining length to 268,435,455 bytes (max 4 bytes encoding).
    fn parse_remaining_length(data: &[u8]) -> Option<(usize, usize)> {
        if data.len() < 2 {
            return None;
        }

        let mut multiplier = 1usize;
        let mut value = 0usize;
        let mut i = 1;

        loop {
            if i >= data.len() || i > 4 {
                // Exceeded max bytes or ran out of data
                return None;
            }

            let byte = data[i];
            value += ((byte & 0x7F) as usize) * multiplier;
            multiplier *= 128;

            if byte & 0x80 == 0 {
                // Continuation bit not set, we're done
                break;
            }

            i += 1;
        }

        // Validate that value doesn't exceed MQTT max (268,435,455)
        if value > 268_435_455 {
            return None;
        }

        Some((value, i + 1))
    }

    fn parse_connect(data: &[u8]) -> Option<MqttConnectInfo> {
        if data.first().copied()? != (MQTT_CONNECT << 4) {
            return None;
        }
        let (remaining_len, start) = Self::parse_remaining_length(data)?;
        if start.checked_add(remaining_len)? != data.len() {
            return None;
        }
        let payload = &data[start..];

        let mut proto_pos = 0usize;
        let proto_name = Self::read_mqtt_string(payload, &mut proto_pos)?;
        let proto_level_pos = proto_pos;
        if proto_level_pos + 4 > payload.len() {
            return None;
        }
        let proto_level = payload[proto_level_pos];
        if !matches!(
            (proto_name.as_slice(), proto_level),
            (b"MQTT", 4 | 5) | (b"MQIsdp", 3)
        ) {
            return None;
        }

        let flags = payload[proto_level_pos + 1];
        if flags & 0x01 != 0 {
            return None;
        }
        let will_flag = flags & 0x04 != 0;
        let will_qos = (flags >> 3) & 0x03;
        let will_retain = flags & 0x20 != 0;
        if will_qos == 0x03 || (!will_flag && (will_qos != 0 || will_retain)) {
            return None;
        }

        let mut pos = proto_level_pos + 4; // protocol level + flags + keepalive
        if proto_level == 5 {
            let properties_len = Self::read_variable_int(payload, &mut pos)?;
            pos = pos.checked_add(properties_len)?;
            if pos > payload.len() {
                return None;
            }
        }

        let client_id =
            String::from_utf8_lossy(&Self::read_mqtt_string(payload, &mut pos)?).to_string();

        let mut username = None;
        let mut password = None;

        // MQTT 5 includes Will Properties before Will Topic and Will Message.
        if will_flag {
            if proto_level == 5 {
                let will_properties_len = Self::read_variable_int(payload, &mut pos)?;
                pos = pos.checked_add(will_properties_len)?;
                if pos > payload.len() {
                    return None;
                }
            }
            Self::read_mqtt_string(payload, &mut pos)?;
            Self::read_mqtt_string(payload, &mut pos)?;
        }

        if flags & 0x80 != 0 {
            username = Some(
                String::from_utf8_lossy(&Self::read_mqtt_string(payload, &mut pos)?).to_string(),
            );
        }

        if flags & 0x40 != 0 {
            password = Some(
                String::from_utf8_lossy(&Self::read_mqtt_string(payload, &mut pos)?).to_string(),
            );
        }

        if pos != payload.len() {
            return None;
        }

        Some(MqttConnectInfo {
            client_id,
            username,
            password,
        })
    }

    fn read_mqtt_string(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
        if *pos + 2 > data.len() {
            return None;
        }
        let len = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
        *pos += 2;
        let end = (*pos).checked_add(len)?;
        if end > data.len() {
            return None;
        }
        let value = data[*pos..end].to_vec();
        *pos = end;
        Some(value)
    }

    fn read_variable_int(data: &[u8], pos: &mut usize) -> Option<usize> {
        let mut multiplier = 1usize;
        let mut value = 0usize;
        for _ in 0..4 {
            if *pos >= data.len() {
                return None;
            }
            let byte = data[*pos];
            *pos += 1;
            value = value.checked_add(((byte & 0x7F) as usize).checked_mul(multiplier)?)?;
            if byte & 0x80 == 0 {
                return Some(value);
            }
            multiplier = multiplier.checked_mul(128)?;
        }
        None
    }

    fn parse_publish(data: &[u8]) -> Option<(String, Vec<u8>)> {
        let (remaining_len, start) = Self::parse_remaining_length(data)?;
        if start.checked_add(remaining_len)? != data.len() {
            return None;
        }
        if start >= data.len() {
            return None;
        }
        let payload = &data[start..];
        if payload.len() < 2 {
            return None;
        }

        let topic_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        if 2 + topic_len > payload.len() {
            return None; // topic_len exceeds available data
        }
        let mut pos = 2 + topic_len;
        let topic = String::from_utf8_lossy(&payload[2..2 + topic_len]).to_string();

        // Skip packet ID for QoS 1/2
        let qos = (data[0] >> 1) & 0x03;
        if qos >= 1 {
            if pos + 2 > payload.len() {
                return None;
            }
            pos += 2;
        }

        let msg_payload = if pos < payload.len() {
            payload[pos..].to_vec()
        } else {
            Vec::new()
        };
        Some((topic, msg_payload))
    }

    fn parse_subscribe_packet_id(payload: &[u8]) -> Option<u16> {
        if payload.len() < 5 {
            return None;
        }
        let packet_id = u16::from_be_bytes([payload[0], payload[1]]);
        let mut pos = 2usize;
        let mut topic_count = 0usize;

        while pos < payload.len() {
            if pos + 2 > payload.len() {
                return None;
            }
            let topic_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
            pos += 2;
            if topic_len == 0 {
                return None;
            }
            let topic_end = pos.checked_add(topic_len)?;
            if topic_end >= payload.len() {
                return None;
            }
            pos = topic_end;
            let requested_qos = payload[pos];
            if requested_qos > 2 {
                return None;
            }
            pos += 1;
            topic_count += 1;
        }

        if topic_count == 0 {
            return None;
        }
        Some(packet_id)
    }
}

pub struct MqttConnectInfo {
    pub client_id: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for MqttHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_returns_connack_when_well_formed() {
        let packet = vec![
            0x10, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
        ];

        assert_eq!(
            MqttHandler::new().handle_packet(&packet),
            vec![0x20, 0x02, 0x00, 0x00]
        );
    }

    #[test]
    fn connect_returns_empty_when_truncated() {
        let packet = vec![0x10, 0x0c, 0x00, 0x04, b'M', b'Q'];

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    #[test]
    fn connect_returns_empty_when_protocol_name_is_invalid() {
        let packet = vec![
            0x10, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'X', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
        ];

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    #[test]
    fn connect_returns_empty_when_fixed_header_flags_are_invalid() {
        let packet = vec![
            0x11, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
        ];

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    #[test]
    fn pingreq_returns_empty_when_remaining_length_is_nonzero() {
        assert!(
            MqttHandler::new()
                .handle_packet(&[0xc0, 0x01, 0x00])
                .is_empty()
        );
    }

    #[test]
    fn publish_qos1_returns_puback() {
        let packet = vec![0x32, 0x06, 0x00, 0x01, b'a', 0x12, 0x34, b'x'];

        assert_eq!(
            MqttHandler::new().handle_packet(&packet),
            vec![0x40, 0x02, 0x12, 0x34]
        );
    }

    #[test]
    fn publish_qos2_returns_pubrec() {
        let packet = vec![0x34, 0x06, 0x00, 0x01, b'a', 0x12, 0x34, b'x'];

        assert_eq!(
            MqttHandler::new().handle_packet(&packet),
            vec![0x50, 0x02, 0x12, 0x34]
        );
    }

    #[test]
    fn publish_qos3_is_rejected() {
        let packet = vec![0x36, 0x06, 0x00, 0x01, b'a', 0x12, 0x34, b'x'];

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    #[test]
    fn subscribe_requires_complete_topic_filter() {
        let handler = MqttHandler::new();

        assert!(handler.handle_packet(&[0x82, 0x02, 0x12, 0x34]).is_empty());
        assert!(
            handler
                .handle_packet(&[0x82, 0x05, 0x12, 0x34, 0x00, 0x01, b'a'])
                .is_empty()
        );
        assert!(
            handler
                .handle_packet(&[0x82, 0x04, 0x12, 0x34, 0x00, 0x00])
                .is_empty()
        );
        assert!(
            handler
                .handle_packet(&[0x82, 0x06, 0x12, 0x34, 0x00, 0x01, b'a', 0x03])
                .is_empty()
        );
    }

    #[test]
    fn subscribe_with_valid_topic_gets_suback() {
        let packet = [0x82, 0x06, 0x12, 0x34, 0x00, 0x01, b'a', 0x00];

        assert_eq!(
            MqttHandler::new().handle_packet(&packet),
            vec![0x90, 0x03, 0x12, 0x34, 0x00]
        );
    }

    #[test]
    fn mqtt5_connect_with_will_properties_is_accepted() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&mqtt_string(b"MQTT"));
        payload.push(5);
        payload.push(0x04);
        payload.extend_from_slice(&[0x00, 0x3c]);
        payload.push(0);
        payload.extend_from_slice(&mqtt_string(b"client"));
        payload.push(0);
        payload.extend_from_slice(&mqtt_string(b"topic"));
        payload.extend_from_slice(&mqtt_string(b"payload"));

        let mut packet = vec![0x10, payload.len() as u8];
        packet.extend_from_slice(&payload);

        assert_eq!(
            MqttHandler::new().handle_packet(&packet),
            vec![0x20, 0x02, 0x00, 0x00]
        );
    }

    fn mqtt_string(value: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(value.len() + 2);
        encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
        encoded.extend_from_slice(value);
        encoded
    }
}
