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
                if let Some(info) = Self::parse_connect(data) {
                    tracing::info!(
                        "MQTT CONNECT: client_id={}, username={:?}, password={:?}",
                        info.client_id,
                        info.username,
                        info.password
                    );
                }
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
                        let topic_len = u16::from_be_bytes([data[remaining_start], data[remaining_start + 1]]) as usize;
                        let packet_id_pos = remaining_start + 2 + topic_len;
                        if packet_id_pos + 2 <= data.len() {
                            let packet_id = u16::from_be_bytes([data[packet_id_pos], data[packet_id_pos + 1]]);
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
        let start = Self::remaining_length_end(data);
        if start >= data.len() {
            return None;
        }
        let payload = &data[start..];
        if payload.len() < 10 {
            return None;
        }

        // Skip protocol name + level + flags + keepalive
        let proto_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        // Validate proto_len doesn't exceed payload
        let flags_offset = 2 + proto_len + 1; // offset to connect flags byte
        if flags_offset >= payload.len() {
            return None;
        }
        let flags = payload[flags_offset]; // connect flags
        let mut pos = flags_offset + 1 + 2; // flags + keepalive

        // Client ID
        if pos + 2 > payload.len() {
            return None;
        }
        let id_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;
        let safe_id_len = id_len.min(payload.len().saturating_sub(pos));
        let client_id = String::from_utf8_lossy(&payload[pos..pos + safe_id_len]).to_string();
        pos += safe_id_len; // Clamp to prevent pos from exceeding payload.len()

        let mut username = None;
        let mut password = None;

        // Skip Will Topic and Will Message if Will Flag (bit 2) is set
        if flags & 0x04 != 0 {
            // Will Topic (length-prefixed string)
            if pos + 2 > payload.len() {
                return Some(MqttConnectInfo { client_id, username, password });
            }
            let will_topic_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
            pos += 2;
            if pos + will_topic_len > payload.len() {
                return Some(MqttConnectInfo { client_id, username, password });
            }
            pos += will_topic_len;
            // Will Message (length-prefixed bytes)
            if pos + 2 > payload.len() {
                return Some(MqttConnectInfo { client_id, username, password });
            }
            let will_msg_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
            pos += 2;
            if pos + will_msg_len > payload.len() {
                return Some(MqttConnectInfo { client_id, username, password });
            }
            pos += will_msg_len;
        }

        // Username (if flag set)
        if flags & 0x80 != 0 && pos + 2 <= payload.len() {
            let len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
            pos += 2;
            if pos + len <= payload.len() {
                username = Some(String::from_utf8_lossy(&payload[pos..pos + len]).to_string());
                pos += len;
            }
        }

        // Password (if flag set)
        if flags & 0x40 != 0 && pos + 2 <= payload.len() {
            let len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
            pos += 2;
            if pos + len <= payload.len() {
                password = Some(String::from_utf8_lossy(&payload[pos..pos + len]).to_string());
            }
        }

        Some(MqttConnectInfo {
            client_id,
            username,
            password,
        })
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
