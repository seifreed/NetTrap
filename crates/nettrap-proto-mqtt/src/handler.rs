use crate::mqtt::{
    MQTT_CONNACK, MQTT_CONNECT, MQTT_DISCONNECT, MQTT_PINGREQ, MQTT_PINGRESP, MQTT_PUBACK,
    MQTT_PUBLISH, MQTT_SUBACK, MQTT_SUBSCRIBE,
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
                // QoS 0 = no ack needed, QoS 1 = PUBACK
                let qos = (data[0] >> 1) & 0x03;
                if qos >= 1 {
                    // Packet ID follows topic_length(2) + topic(var) in the variable header
                    let remaining_start = Self::remaining_length_end(data);
                    if remaining_start + 2 <= data.len() {
                        let topic_len =
                            u16::from_be_bytes([data[remaining_start], data[remaining_start + 1]])
                                as usize;
                        let packet_id_pos = remaining_start + 2 + topic_len;
                        if packet_id_pos + 2 <= data.len() {
                            let packet_id =
                                u16::from_be_bytes([data[packet_id_pos], data[packet_id_pos + 1]]);
                            return vec![
                                (MQTT_PUBACK << 4),
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
                let remaining_start = Self::remaining_length_end(data);
                if remaining_start + 2 <= data.len() {
                    let packet_id =
                        u16::from_be_bytes([data[remaining_start], data[remaining_start + 1]]);
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
                vec![(MQTT_PINGRESP << 4), 0]
            }
            MQTT_DISCONNECT => {
                tracing::debug!("MQTT DISCONNECT");
                Vec::new()
            }
            _ => Vec::new(),
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

    /// Get the start position after the remaining length field.
    /// Returns the byte index where payload starts, or data.len() if invalid.
    fn remaining_length_end(data: &[u8]) -> usize {
        Self::parse_remaining_length(data)
            .map(|(_, start)| start)
            .unwrap_or(data.len())
    }

    fn parse_connect(data: &[u8]) -> Option<MqttConnectInfo> {
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

        // Skip Will Topic and Will Message if Will Flag (bit 2) is set
        if will_flag {
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
        let start = Self::remaining_length_end(data);
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
            pos += 2;
        }

        let msg_payload = if pos < payload.len() {
            payload[pos..].to_vec()
        } else {
            Vec::new()
        };
        Some((topic, msg_payload))
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
}
