use crate::mqtt::{MQTT_CONNACK, MQTT_CONNECT, MQTT_DISCONNECT, MQTT_PINGREQ, MQTT_PINGRESP,
    MQTT_PUBACK, MQTT_PUBLISH, MQTT_SUBACK, MQTT_SUBSCRIBE};

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
                if qos >= 1 && data.len() >= 4 {
                    // Extract packet ID and send PUBACK
                    let remaining_start = Self::remaining_length_end(data);
                    if remaining_start + 2 <= data.len() {
                        let packet_id = u16::from_be_bytes([
                            data[remaining_start],
                            data[remaining_start + 1],
                        ]);
                        return vec![
                            (MQTT_PUBACK << 4),
                            2,
                            (packet_id >> 8) as u8,
                            (packet_id & 0xFF) as u8,
                        ];
                    }
                }
                Vec::new()
            }
            MQTT_SUBSCRIBE => {
                // Parse topics
                let remaining_start = Self::remaining_length_end(data);
                if remaining_start + 2 <= data.len() {
                    let packet_id = u16::from_be_bytes([
                        data[remaining_start],
                        data[remaining_start + 1],
                    ]);
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

    fn remaining_length_end(data: &[u8]) -> usize {
        let mut i = 1;
        while i < data.len() && i < 5 {
            if data[i] & 0x80 == 0 {
                return i + 1;
            }
            i += 1;
        }
        i + 1
    }

    fn parse_connect(data: &[u8]) -> Option<MqttConnectInfo> {
        let start = Self::remaining_length_end(data);
        let payload = &data[start..];
        if payload.len() < 10 {
            return None;
        }

        // Skip protocol name + level + flags + keepalive
        let proto_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        let mut pos = 2 + proto_len + 1 + 1 + 2; // name + level + flags + keepalive
        let flags = payload[2 + proto_len + 1]; // connect flags

        // Client ID
        if pos + 2 > payload.len() {
            return None;
        }
        let id_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;
        let end = (pos + id_len).min(payload.len());
        let client_id = String::from_utf8_lossy(&payload[pos..end]).to_string();
        pos += id_len;

        let mut username = None;
        let mut password = None;

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
        let payload = &data[start..];
        if payload.len() < 2 {
            return None;
        }

        let topic_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        let mut pos = 2 + topic_len;
        let topic_end = (2 + topic_len).min(payload.len());
        let topic = String::from_utf8_lossy(&payload[2..topic_end]).to_string();

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
