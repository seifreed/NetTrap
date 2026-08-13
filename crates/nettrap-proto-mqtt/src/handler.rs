use std::sync::Mutex;

use crate::mqtt::{
    MQTT_CONNACK, MQTT_CONNECT, MQTT_DISCONNECT, MQTT_PINGREQ, MQTT_PINGRESP, MQTT_PUBACK,
    MQTT_PUBCOMP, MQTT_PUBLISH, MQTT_PUBREC, MQTT_PUBREL, MQTT_SUBACK, MQTT_SUBSCRIBE,
    MQTT_UNSUBACK, MQTT_UNSUBSCRIBE, MqttState,
};
mod parsing;

pub use parsing::MqttConnectInfo;
use parsing::*;

const REDACTED_MQTT_FIELD: &str = "***REDACTED***";

/// Returns true when `data` is a complete MQTT DISCONNECT packet accepted by the parser.
pub fn is_valid_disconnect_frame(data: &[u8]) -> bool {
    if data.is_empty() || data.len() > MQTT_MAX_PACKET_BYTES {
        return false;
    }

    let packet_type = (data[0] >> 4) & 0x0F;
    if packet_type != MQTT_DISCONNECT {
        return false;
    }
    let Some((remaining_len, start)) = parse_remaining_length(data) else {
        return false;
    };
    start.checked_add(remaining_len) == Some(data.len())
        && valid_fixed_header(data[0], packet_type, remaining_len)
        && parse_disconnect_packet(&data[start..]).is_some()
}

pub struct MqttHandler {
    broker_name: String,
    state: Mutex<MqttState>,
    protocol_level: Mutex<Option<u8>>,
}

impl MqttHandler {
    pub fn new() -> Self {
        Self {
            broker_name: "nettrap-mqtt".to_string(),
            state: Mutex::new(MqttState::WaitingConnect),
            protocol_level: Mutex::new(None),
        }
    }

    pub fn handle_packet(&self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        if data.len() > MQTT_MAX_PACKET_BYTES {
            return Vec::new();
        }

        let packet_type = (data[0] >> 4) & 0x0F;
        let Some((remaining_len, start)) = parse_remaining_length(data) else {
            return Vec::new();
        };
        if start.checked_add(remaining_len) != Some(data.len())
            || !valid_fixed_header(data[0], packet_type, remaining_len)
        {
            return Vec::new();
        }

        match self.current_state() {
            MqttState::WaitingConnect if packet_type != MQTT_CONNECT => return Vec::new(),
            MqttState::Connected if packet_type == MQTT_CONNECT => return Vec::new(),
            MqttState::Disconnected => return Vec::new(),
            _ => {}
        }

        match packet_type {
            MQTT_CONNECT => {
                // Parse CONNECT: extract client_id, username, password
                let Some(info) = parse_connect(data) else {
                    tracing::debug!(
                        broker = %self.broker_name,
                        "Malformed MQTT CONNECT packet"
                    );
                    return Vec::new();
                };
                tracing::debug!(
                    broker = %self.broker_name,
                    "MQTT CONNECT: client_id={}, username={:?}, password={:?}",
                    nettrap_core::sanitize::single_line(&info.client_id),
                    info
                        .username
                        .as_deref()
                        .map(nettrap_core::sanitize::single_line),
                    info
                        .password
                        .as_deref()
                        .map(nettrap_core::sanitize::single_line_bytes)
                );
                tracing::info!(
                    broker = %self.broker_name,
                    "MQTT CONNECT: client_id={}, username={}, password={}",
                    REDACTED_MQTT_FIELD,
                    REDACTED_MQTT_FIELD,
                    REDACTED_MQTT_FIELD
                );
                if info.client_id_rejected {
                    self.set_state(MqttState::Disconnected);
                    return vec![MQTT_CONNACK << 4, 2, 0, 2];
                }
                self.set_protocol_level(info.protocol_level);
                self.set_state(MqttState::Connected);
                if info.protocol_level == 5 {
                    // MQTT 5 CONNACK: ack flags + reason code + properties length.
                    vec![(MQTT_CONNACK << 4), 3, 0, 0, 0]
                } else {
                    // MQTT 3.1.1 CONNACK: session-present + return code.
                    vec![
                        (MQTT_CONNACK << 4), // Fixed header
                        2,                   // Remaining length
                        0,                   // Session present = false
                        0,                   // Return code 0 = accepted
                    ]
                }
            }
            MQTT_PUBLISH => {
                if let Some(info) = parse_publish(data) {
                    tracing::debug!(
                        broker = %self.broker_name,
                        "MQTT PUBLISH: topic={}, payload_len={}",
                        nettrap_core::sanitize::single_line(&info.topic),
                        info.payload_len
                    );
                    tracing::debug!(
                        broker = %self.broker_name,
                        "MQTT payload preview: {}",
                        nettrap_core::sanitize::single_line_bytes(&info.payload_preview)
                    );
                    tracing::info!(
                        broker = %self.broker_name,
                        "MQTT PUBLISH: topic={}, payload_len={}",
                        REDACTED_MQTT_FIELD,
                        info.payload_len
                    );
                    let qos = (data[0] >> 1) & 0x03;
                    if let Some(packet_id) = info.packet_id {
                        let ack_type = if qos == 2 { MQTT_PUBREC } else { MQTT_PUBACK };
                        return vec![
                            (ack_type << 4),
                            2,
                            (packet_id >> 8) as u8,
                            (packet_id & 0xFF) as u8,
                        ];
                    }
                }
                Vec::new()
            }
            MQTT_SUBSCRIBE => {
                let remaining_start = start;
                if let Some(info) = parse_subscribe_packet_for_level(
                    &data[remaining_start..],
                    self.current_protocol_level(),
                ) {
                    tracing::info!(
                        broker = %self.broker_name,
                        "MQTT SUBSCRIBE: packet_id={}",
                        info.packet_id
                    );
                    let properties_len = usize::from(info.has_properties);
                    let Some(remaining_len) = 2usize
                        .checked_add(properties_len)
                        .and_then(|len| len.checked_add(info.topic_count))
                    else {
                        return Vec::new();
                    };
                    let mut response = Vec::with_capacity(2 + remaining_len);
                    response.push(MQTT_SUBACK << 4);
                    push_remaining_length(&mut response, remaining_len);
                    response.extend_from_slice(&info.packet_id.to_be_bytes());
                    if info.has_properties {
                        response.push(0);
                    }
                    response.extend(info.granted_qos);
                    return response;
                }
                Vec::new()
            }
            MQTT_UNSUBSCRIBE => {
                let remaining_start = start;
                if let Some(info) = parse_unsubscribe_packet_for_level(
                    &data[remaining_start..],
                    self.current_protocol_level(),
                ) {
                    tracing::info!(
                        broker = %self.broker_name,
                        "MQTT UNSUBSCRIBE: packet_id={}, topics={}",
                        info.packet_id,
                        info.topic_count
                    );
                    let remaining_len = if info.has_properties {
                        let Some(len) = 2usize
                            .checked_add(1)
                            .and_then(|len| len.checked_add(info.topic_count))
                        else {
                            return Vec::new();
                        };
                        len
                    } else {
                        2
                    };
                    let mut response = Vec::with_capacity(2 + remaining_len);
                    response.push(MQTT_UNSUBACK << 4);
                    push_remaining_length(&mut response, remaining_len);
                    response.extend_from_slice(&info.packet_id.to_be_bytes());
                    if info.has_properties {
                        response.push(0);
                        response.extend(std::iter::repeat_n(0, info.topic_count));
                    }
                    return response;
                }
                Vec::new()
            }
            MQTT_PUBREL => {
                let remaining_start = start;
                if let Some(info) = parse_pubrel_packet(&data[remaining_start..]) {
                    tracing::info!(
                        broker = %self.broker_name,
                        "MQTT PUBREL: packet_id={}",
                        info.packet_id
                    );
                    return vec![
                        (MQTT_PUBCOMP << 4),
                        2,
                        (info.packet_id >> 8) as u8,
                        (info.packet_id & 0xFF) as u8,
                    ];
                }
                Vec::new()
            }
            MQTT_PINGREQ => {
                if remaining_len == 0 {
                    tracing::debug!(broker = %self.broker_name, "MQTT PINGREQ");
                    vec![(MQTT_PINGRESP << 4), 0]
                } else {
                    Vec::new()
                }
            }
            MQTT_DISCONNECT => {
                if parse_disconnect_packet_for_level(&data[start..], self.current_protocol_level())
                    .is_none()
                {
                    return Vec::new();
                }
                self.set_state(MqttState::Disconnected);
                tracing::debug!(broker = %self.broker_name, "MQTT DISCONNECT");
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn set_protocol_level(&self, level: u8) {
        let mut guard = self
            .protocol_level
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(level);
    }

    fn set_state(&self, state: MqttState) {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = state;
    }

    fn current_state(&self) -> MqttState {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn current_protocol_level(&self) -> Option<u8> {
        *self
            .protocol_level
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn push_remaining_length(output: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = value.to_le_bytes()[0] & 0x7f;
        value /= 128;
        if value > 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

impl Default for MqttHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG_FIELD_PREVIEW_CHARS: usize = 240;

    fn connected_handler(protocol_level: u8) -> MqttHandler {
        let handler = MqttHandler::new();
        handler.set_protocol_level(protocol_level);
        handler.set_state(MqttState::Connected);
        handler
    }

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
    fn mqtt3_connect_rejects_empty_client_id_without_clean_session() {
        let handler = MqttHandler::new();
        let packet = mqtt_connect_packet(4, 0x00, &[mqtt_string(b"")]);

        assert_eq!(handler.handle_packet(&packet), vec![0x20, 0x02, 0x00, 0x02]);
        assert!(handler.handle_packet(&[0xc0, 0x00]).is_empty());
    }

    #[test]
    fn connect_v5_returns_mqtt5_connack_with_properties_length() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&mqtt_string(b"MQTT"));
        payload.push(5);
        payload.push(0x02);
        payload.extend_from_slice(&[0x00, 0x3c]);
        payload.push(0);
        payload.extend_from_slice(&mqtt_string(b"client"));

        let mut packet = vec![0x10, payload.len() as u8];
        packet.extend_from_slice(&payload);

        assert_eq!(
            MqttHandler::new().handle_packet(&packet),
            vec![0x20, 0x03, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn packets_before_connect_are_rejected() {
        assert!(
            MqttHandler::new()
                .handle_packet(&[0x32, 0x06, 0x00, 0x01, b'a', 0x12, 0x34, b'x'])
                .is_empty()
        );
    }

    #[test]
    fn second_connect_is_rejected() {
        let handler = MqttHandler::new();
        let packet = mqtt_connect_packet(4, 0x02, &[mqtt_string(b"client")]);

        assert_eq!(handler.handle_packet(&packet), vec![0x20, 0x02, 0x00, 0x00]);
        assert!(handler.handle_packet(&packet).is_empty());
    }

    #[test]
    fn packets_after_disconnect_are_rejected() {
        let handler = connected_handler(4);

        assert!(handler.handle_packet(&[0xe0, 0x00]).is_empty());
        assert!(
            handler
                .handle_packet(&[0x32, 0x06, 0x00, 0x01, b'a', 0x12, 0x34, b'x'])
                .is_empty()
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
    fn connect_rejects_password_flag_without_username_flag() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&mqtt_string(b"MQTT"));
        payload.push(4);
        payload.push(0x42);
        payload.extend_from_slice(&[0x00, 0x3c]);
        payload.extend_from_slice(&mqtt_string(b"client"));
        payload.extend_from_slice(&mqtt_string(b"secret"));

        let mut packet = vec![0x10, payload.len() as u8];
        packet.extend_from_slice(&payload);

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    #[test]
    fn connect_rejects_invalid_utf8_client_id() {
        let packet = mqtt_connect_packet(4, 0x02, &[mqtt_string(&[0xff])]);

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    #[test]
    fn connect_rejects_nul_in_utf8_client_id() {
        let packet = mqtt_connect_packet(4, 0x02, &[mqtt_string(b"bad\0client")]);

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    #[test]
    fn connect_rejects_invalid_utf8_username() {
        let packet = mqtt_connect_packet(4, 0x82, &[mqtt_string(b"client"), mqtt_string(&[0xff])]);

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    #[test]
    fn connect_accepts_binary_password() {
        let packet = mqtt_connect_packet(
            4,
            0xc2,
            &[
                mqtt_string(b"client"),
                mqtt_string(b"user"),
                mqtt_string(&[0x00, 0xff, b'p']),
            ],
        );

        assert_eq!(
            MqttHandler::new().handle_packet(&packet),
            vec![0x20, 0x02, 0x00, 0x00]
        );

        let info = parse_connect(&packet).expect("binary password connect should parse");
        assert_eq!(info.client_id, "client");
        assert_eq!(info.username.as_deref(), Some("user"));
        assert_eq!(info.password.as_deref(), Some(&[0x00, 0xff, b'p'][..]));
    }

    #[test]
    fn logged_mqtt_fields_are_single_line() {
        assert_eq!(
            nettrap_core::sanitize::single_line("client\nid\x1b"),
            "client id "
        );
        assert_eq!(
            Some(nettrap_core::sanitize::single_line("user\r\nname\x08")),
            Some("user  name ".to_string())
        );
        assert_eq!(
            Some(nettrap_core::sanitize::single_line_bytes(b"user")),
            Some("user".to_string())
        );
        assert_eq!(
            Some(nettrap_core::sanitize::single_line_bytes(&[0xff, b'x'])),
            Some("hex:ff78".to_string())
        );
        assert_eq!(
            nettrap_core::sanitize::single_line_bytes(&[0xff, 0x00, b'a']),
            "hex:ff0061"
        );

        let long = "a".repeat(LOG_FIELD_PREVIEW_CHARS + 1);
        assert_eq!(
            nettrap_core::sanitize::single_line(&long).len(),
            LOG_FIELD_PREVIEW_CHARS
        );
    }

    #[test]
    fn publish_payload_preview_preserves_non_utf8_bytes() {
        let preview =
            nettrap_core::sanitize::single_line_bytes(&[b't', b'o', b'p', 0xff, 0x00, b'a']);

        assert_eq!(preview, "hex:746f70ff0061");
    }

    #[test]
    fn publish_payload_preview_bounds_non_utf8_bytes() {
        let mut value = vec![0xff; nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS];
        value.push(b'a');

        let rendered = nettrap_core::sanitize::single_line_bytes(&value);

        assert!(rendered.starts_with("hex:"));
        assert!(rendered.len() <= nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS);
    }

    #[test]
    fn connect_rejects_invalid_utf8_will_topic() {
        let packet = mqtt_connect_packet(
            5,
            0x06,
            &[
                mqtt_string(b"client"),
                mqtt_string(&[0xff]),
                mqtt_string(b"payload"),
            ],
        );

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
    fn pingresp_rejects_nonzero_remaining_length() {
        assert!(
            MqttHandler::new()
                .handle_packet(&[0xd0, 0x01, 0x00])
                .is_empty()
        );
    }

    #[test]
    fn connack_rejects_server_to_client_packet_type() {
        assert!(!valid_fixed_header(0x20, MQTT_CONNACK, 2));
        assert!(
            MqttHandler::new()
                .handle_packet(&[0x20, 0x02, 0x00, 0x00])
                .is_empty()
        );
    }

    #[test]
    fn disconnect_accepts_mqtt5_reason_code_and_empty_properties() {
        assert!(valid_fixed_header(0xe0, MQTT_DISCONNECT, 2));
        assert!(
            MqttHandler::new()
                .handle_packet(&[0xe0, 0x02, 0x00, 0x00])
                .is_empty()
        );
    }

    #[test]
    fn disconnect_accepts_single_byte_remaining_length() {
        assert!(valid_fixed_header(0xe0, MQTT_DISCONNECT, 1));
        assert!(
            MqttHandler::new()
                .handle_packet(&[0xe0, 0x01, 0x00])
                .is_empty()
        );
    }

    #[test]
    fn mqtt3_disconnect_payload_is_rejected_without_closing_session() {
        let handler = connected_handler(4);

        assert!(handler.handle_packet(&[0xe0, 0x01, 0x00]).is_empty());
        assert_eq!(handler.handle_packet(&[0xc0, 0x00]), vec![0xd0, 0x00]);
    }

    #[test]
    fn disconnect_rejects_invalid_reason_code() {
        assert!(parse_disconnect_packet(&[0xff]).is_none());
        assert!(
            MqttHandler::new()
                .handle_packet(&[0xe0, 0x01, 0xff])
                .is_empty()
        );
    }

    #[test]
    fn disconnect_rejects_trailing_bytes_after_properties() {
        assert!(parse_disconnect_packet(&[0x00, 0x00, 0x00]).is_none());
        assert!(
            MqttHandler::new()
                .handle_packet(&[0xe0, 0x03, 0x00, 0x00, 0x00])
                .is_empty()
        );
    }

    #[test]
    fn remaining_length_must_use_minimal_encoding() {
        assert!(
            MqttHandler::new()
                .handle_packet(&[0xc0, 0x80, 0x00])
                .is_empty()
        );
    }

    #[test]
    fn remaining_length_rejects_overlong_encoding() {
        assert!(
            MqttHandler::new()
                .handle_packet(&[0xc0, 0x80, 0x80, 0x80, 0x80, 0x00])
                .is_empty()
        );
    }

    #[test]
    fn parse_remaining_length_rejects_overlong_encoding() {
        assert_eq!(
            parse_remaining_length(&[0x10, 0x80, 0x80, 0x80, 0x80, 0x00]),
            None
        );
    }

    #[test]
    fn mqtt_string_reader_rejects_overflowing_offset() {
        let mut pos = usize::MAX;

        assert_eq!(read_mqtt_string(&[0x00, 0x00], &mut pos), None);
        assert_eq!(pos, usize::MAX);
    }

    #[test]
    fn mqtt5_variable_byte_integers_must_use_minimal_encoding() {
        let mut connect_properties = Vec::new();
        connect_properties.extend_from_slice(&mqtt_string(b"MQTT"));
        connect_properties.push(5);
        connect_properties.push(0);
        connect_properties.extend_from_slice(&[0x00, 0x3c]);
        connect_properties.extend_from_slice(&[0x80, 0x00]);
        connect_properties.extend_from_slice(&mqtt_string(b"client"));

        let mut connect_packet = vec![0x10, connect_properties.len() as u8];
        connect_packet.extend_from_slice(&connect_properties);

        let mut will_properties = Vec::new();
        will_properties.extend_from_slice(&mqtt_string(b"MQTT"));
        will_properties.push(5);
        will_properties.push(0x04);
        will_properties.extend_from_slice(&[0x00, 0x3c]);
        will_properties.push(0);
        will_properties.extend_from_slice(&mqtt_string(b"client"));
        will_properties.extend_from_slice(&[0x80, 0x00]);
        will_properties.extend_from_slice(&mqtt_string(b"topic"));
        will_properties.extend_from_slice(&mqtt_string(b"payload"));

        let mut will_packet = vec![0x10, will_properties.len() as u8];
        will_packet.extend_from_slice(&will_properties);

        assert!(MqttHandler::new().handle_packet(&connect_packet).is_empty());
        assert!(MqttHandler::new().handle_packet(&will_packet).is_empty());
    }

    #[test]
    fn publish_qos1_returns_puback() {
        let packet = vec![0x32, 0x06, 0x00, 0x01, b'a', 0x12, 0x34, b'x'];

        assert_eq!(
            connected_handler(4).handle_packet(&packet),
            vec![0x40, 0x02, 0x12, 0x34]
        );
    }

    #[test]
    fn publish_payload_preview_is_bounded_while_preserving_length() {
        let payload = vec![b'x'; 2048];
        let mut variable_header = Vec::new();
        variable_header.extend_from_slice(&mqtt_string(b"a"));
        variable_header.extend_from_slice(&[0x12, 0x34]);
        let remaining_len = variable_header.len() + payload.len();

        let mut packet = vec![0x32];
        push_remaining_length(&mut packet, remaining_len);
        packet.extend_from_slice(&variable_header);
        packet.extend_from_slice(&payload);

        let info = parse_publish(&packet).expect("valid publish packet");

        assert_eq!(info.payload_len, payload.len());
        assert_eq!(info.payload_preview.len(), 1024);
        assert_eq!(info.packet_id, Some(0x1234));
        assert_eq!(
            connected_handler(4).handle_packet(&packet),
            vec![0x40, 0x02, 0x12, 0x34]
        );
    }

    #[test]
    fn publish_qos2_returns_pubrec() {
        let packet = vec![0x34, 0x06, 0x00, 0x01, b'a', 0x12, 0x34, b'x'];

        assert_eq!(
            connected_handler(4).handle_packet(&packet),
            vec![0x50, 0x02, 0x12, 0x34]
        );
    }

    #[test]
    fn pubrel_returns_pubcomp() {
        let packet = [0x62, 0x02, 0x12, 0x34];

        assert_eq!(
            connected_handler(4).handle_packet(&packet),
            vec![0x70, 0x02, 0x12, 0x34]
        );
    }

    #[test]
    fn mqtt5_pubrel_with_reason_string_returns_pubcomp() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1234u16.to_be_bytes());
        payload.push(0x00);
        let mut properties = Vec::new();
        properties.push(0x1f);
        properties.extend_from_slice(&mqtt_string(b"released"));
        payload.extend_from_slice(&[properties.len() as u8]);
        payload.extend_from_slice(&properties);

        let mut packet = vec![0x62];
        push_remaining_length(&mut packet, payload.len());
        packet.extend_from_slice(&payload);

        assert_eq!(
            connected_handler(5).handle_packet(&packet),
            vec![0x70, 0x02, 0x12, 0x34]
        );
    }

    #[test]
    fn mqtt5_pubrel_rejects_unknown_properties() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1234u16.to_be_bytes());
        payload.push(0x00);
        payload.push(0x01);
        payload.push(0x99);

        let mut packet = vec![0x62];
        push_remaining_length(&mut packet, payload.len());
        packet.extend_from_slice(&payload);

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    #[test]
    fn publish_qos3_is_rejected() {
        let packet = vec![0x36, 0x06, 0x00, 0x01, b'a', 0x12, 0x34, b'x'];

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    #[test]
    fn publish_qos1_does_not_ack_malformed_topic() {
        let empty_topic = [0x32, 0x05, 0x00, 0x00, 0x12, 0x34, b'x'];
        let invalid_utf8_topic = [0x32, 0x06, 0x00, 0x01, 0xff, 0x12, 0x34, b'x'];
        let nul_topic = [0x32, 0x08, 0x00, 0x03, b'a', 0x00, b'b', 0x12, 0x34, b'x'];
        let wildcard_topic = [0x32, 0x06, 0x00, 0x01, b'#', 0x12, 0x34, b'x'];

        assert!(MqttHandler::new().handle_packet(&empty_topic).is_empty());
        assert!(
            MqttHandler::new()
                .handle_packet(&invalid_utf8_topic)
                .is_empty()
        );
        assert!(MqttHandler::new().handle_packet(&nul_topic).is_empty());
        assert!(MqttHandler::new().handle_packet(&wildcard_topic).is_empty());
    }

    #[test]
    fn publish_qos1_does_not_ack_zero_packet_id() {
        let packet = vec![0x32, 0x06, 0x00, 0x01, b'a', 0x00, 0x00, b'x'];

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    #[test]
    fn subscribe_requires_complete_topic_filter() {
        let handler = MqttHandler::new();

        assert!(handler.handle_packet(&[0x82, 0x02, 0x12, 0x34]).is_empty());
        assert!(
            handler
                .handle_packet(&[0x82, 0x06, 0x00, 0x00, 0x00, 0x01, b'a', 0x00])
                .is_empty()
        );
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
        assert!(
            handler
                .handle_packet(&[0x82, 0x06, 0x12, 0x34, 0x00, 0x01, 0xff, 0x00])
                .is_empty()
        );
        assert!(
            handler
                .handle_packet(&[0x82, 0x06, 0x12, 0x34, 0x00, 0x01, 0x00, 0x00])
                .is_empty()
        );
        assert!(
            handler
                .handle_packet(&[0x82, 0x07, 0x12, 0x34, 0x00, 0x02, b'a', b'#', 0x00])
                .is_empty()
        );
    }

    #[test]
    fn subscribe_with_valid_topic_gets_suback() {
        let packet = [0x82, 0x07, 0x12, 0x34, 0x00, 0x00, 0x01, b'a', 0x00];

        assert_eq!(
            connected_handler(5).handle_packet(&packet),
            vec![0x90, 0x04, 0x12, 0x34, 0x00, 0x00]
        );
    }

    #[test]
    fn mqtt4_session_uses_mqtt4_suback_and_unsuback_shapes() {
        let handler = MqttHandler::new();
        let connect = mqtt_connect_packet(4, 0x02, &[mqtt_string(b"client")]);

        assert_eq!(
            handler.handle_packet(&connect),
            vec![0x20, 0x02, 0x00, 0x00]
        );
        assert_eq!(
            handler.handle_packet(&[0x82, 0x06, 0x12, 0x34, 0x00, 0x01, b'a', 0x00]),
            vec![0x90, 0x03, 0x12, 0x34, 0x00]
        );
        assert_eq!(
            handler.handle_packet(&[0xa2, 0x05, 0x12, 0x34, 0x00, 0x01, b'a']),
            vec![0xb0, 0x02, 0x12, 0x34]
        );
    }

    #[test]
    fn subscribe_with_multiple_topics_gets_one_grant_per_topic() {
        let packet = [
            0x82, 0x0b, 0x12, 0x34, 0x00, 0x00, 0x01, b'a', 0x00, 0x00, 0x01, b'b', 0x01,
        ];

        assert_eq!(
            connected_handler(5).handle_packet(&packet),
            vec![0x90, 0x05, 0x12, 0x34, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn subscribe_grants_requested_qos_two() {
        let packet = [0x82, 0x07, 0x12, 0x34, 0x00, 0x00, 0x01, b'a', 0x02];

        assert_eq!(
            connected_handler(5).handle_packet(&packet),
            vec![0x90, 0x04, 0x12, 0x34, 0x00, 0x02]
        );
    }

    #[test]
    fn unsubscribe_with_valid_topic_gets_unsuback() {
        let packet = [0xa2, 0x06, 0x12, 0x34, 0x00, 0x00, 0x01, b'a'];

        assert_eq!(
            connected_handler(5).handle_packet(&packet),
            vec![0xb0, 0x04, 0x12, 0x34, 0x00, 0x00]
        );
    }

    #[test]
    fn mqtt5_unsubscribe_with_user_properties_gets_unsuback() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1234u16.to_be_bytes());
        let mut properties = Vec::new();
        properties.push(0x26);
        properties.extend_from_slice(&mqtt_string(b"trace-id"));
        properties.extend_from_slice(&mqtt_string(b"abc123"));
        payload.extend_from_slice(&[properties.len() as u8]);
        payload.extend_from_slice(&properties);
        payload.extend_from_slice(&mqtt_string(b"a"));

        let mut packet = vec![0xa2];
        push_remaining_length(&mut packet, payload.len());
        packet.extend_from_slice(&payload);

        assert_eq!(
            connected_handler(5).handle_packet(&packet),
            vec![0xb0, 0x04, 0x12, 0x34, 0x00, 0x00]
        );
    }

    #[test]
    fn mqtt5_unsubscribe_without_properties_still_includes_reason_codes() {
        let packet = [
            0xa2, 0x09, 0x12, 0x34, 0x00, 0x00, 0x01, b'a', 0x00, 0x01, b'b',
        ];

        assert_eq!(
            connected_handler(5).handle_packet(&packet),
            vec![0xb0, 0x05, 0x12, 0x34, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn mqtt5_unsubscribe_rejects_unknown_properties() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1234u16.to_be_bytes());
        payload.extend_from_slice(&[0x01, 0x99]);
        payload.extend_from_slice(&mqtt_string(b"a"));

        let mut packet = vec![0xa2];
        push_remaining_length(&mut packet, payload.len());
        packet.extend_from_slice(&payload);

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    #[test]
    fn mqtt5_subscribe_with_zero_properties_gets_mqtt5_suback() {
        let packet = [0x82, 0x07, 0x12, 0x34, 0x00, 0x00, 0x01, b'a', 0x00];

        assert_eq!(
            connected_handler(5).handle_packet(&packet),
            vec![0x90, 0x04, 0x12, 0x34, 0x00, 0x00]
        );
    }

    #[test]
    fn mqtt5_subscribe_accepts_user_properties() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1234u16.to_be_bytes());
        let mut properties = Vec::new();
        properties.push(0x26);
        properties.extend_from_slice(&mqtt_string(b"trace-id"));
        properties.extend_from_slice(&mqtt_string(b"abc123"));
        payload.extend_from_slice(&[properties.len() as u8]);
        payload.extend_from_slice(&properties);
        payload.extend_from_slice(&mqtt_string(b"a"));
        payload.push(0x00);

        let mut packet = vec![0x82];
        push_remaining_length(&mut packet, payload.len());
        packet.extend_from_slice(&payload);

        assert_eq!(
            connected_handler(5).handle_packet(&packet),
            vec![0x90, 0x04, 0x12, 0x34, 0x00, 0x00]
        );
    }

    #[test]
    fn mqtt_packet_over_local_size_limit_is_rejected() {
        let packet = vec![MQTT_CONNECT << 4; MQTT_MAX_PACKET_BYTES + 1];

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    #[test]
    fn mqtt5_subscribe_prefers_explicit_properties_when_implicit_form_is_invalid() {
        let packet = ambiguous_subscribe_packet();

        assert_eq!(
            connected_handler(5).handle_packet(&packet),
            vec![0x90, 0x05, 0x12, 0x34, 0x00, 0x01, 0x01]
        );
    }

    #[test]
    fn mqtt5_subscribe_rejects_unknown_properties() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1234u16.to_be_bytes());
        payload.extend_from_slice(&[0x01, 0x99]);
        payload.extend_from_slice(&mqtt_string(b"a"));
        payload.push(0x00);

        let mut packet = vec![0x82];
        push_remaining_length(&mut packet, payload.len());
        packet.extend_from_slice(&payload);

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    #[test]
    fn mqtt5_subscribe_accepts_subscription_options_with_rap_bit_set() {
        let packet = [0x82, 0x07, 0x12, 0x34, 0x00, 0x00, 0x01, b'a', 0x09];

        assert_eq!(
            connected_handler(5).handle_packet(&packet),
            vec![0x90, 0x04, 0x12, 0x34, 0x00, 0x01]
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
            vec![0x20, 0x03, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn mqtt5_connect_accepts_user_properties() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&mqtt_string(b"MQTT"));
        payload.push(5);
        payload.push(0x02);
        payload.extend_from_slice(&[0x00, 0x3c]);
        let mut properties = Vec::new();
        properties.push(0x26);
        properties.extend_from_slice(&mqtt_string(b"session"));
        properties.extend_from_slice(&mqtt_string(b"alpha"));
        payload.extend_from_slice(&[properties.len() as u8]);
        payload.extend_from_slice(&properties);
        payload.extend_from_slice(&mqtt_string(b"client"));

        let mut packet = vec![0x10, payload.len() as u8];
        packet.extend_from_slice(&payload);

        assert_eq!(
            MqttHandler::new().handle_packet(&packet),
            vec![0x20, 0x03, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn mqtt5_connect_rejects_duplicate_authentication_method_properties() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&mqtt_string(b"MQTT"));
        payload.push(5);
        payload.push(0x02);
        payload.extend_from_slice(&[0x00, 0x3c]);
        let mut properties = Vec::new();
        properties.push(0x15);
        properties.extend_from_slice(&mqtt_string(b"SCRAM-SHA-1"));
        properties.push(0x15);
        properties.extend_from_slice(&mqtt_string(b"SCRAM-SHA-256"));
        payload.extend_from_slice(&[properties.len() as u8]);
        payload.extend_from_slice(&properties);
        payload.extend_from_slice(&mqtt_string(b"client"));

        let mut packet = vec![0x10, payload.len() as u8];
        packet.extend_from_slice(&payload);

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    #[test]
    fn mqtt5_connect_rejects_unknown_properties() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&mqtt_string(b"MQTT"));
        payload.push(5);
        payload.push(0x02);
        payload.extend_from_slice(&[0x00, 0x3c]);
        payload.push(0x01);
        payload.push(0x99);
        payload.extend_from_slice(&mqtt_string(b"client"));

        let mut packet = vec![0x10, payload.len() as u8];
        packet.extend_from_slice(&payload);

        assert!(MqttHandler::new().handle_packet(&packet).is_empty());
    }

    fn mqtt_string(value: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(value.len() + 2);
        encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
        encoded.extend_from_slice(value);
        encoded
    }

    fn mqtt_connect_packet(version: u8, flags: u8, fields: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&mqtt_string(b"MQTT"));
        payload.push(version);
        payload.push(flags);
        payload.extend_from_slice(&[0x00, 0x3c]);
        for field in fields {
            payload.extend_from_slice(field);
        }

        let mut packet = vec![0x10, payload.len() as u8];
        packet.extend_from_slice(&payload);
        packet
    }

    fn ambiguous_subscribe_packet() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1234u16.to_be_bytes());
        payload.push(0x02);
        payload.push(0x0b);
        payload.push(0x01);
        payload.push(0x01);
        payload.push(0x01);
        payload.extend_from_slice(&[b'a'; 257]);
        payload.push(0x01);
        payload.push(0x01);
        payload.push(0x04);
        payload.extend_from_slice(&[0x62; 260]);
        payload.push(0x01);

        let mut packet = vec![0x82];
        push_remaining_length(&mut packet, payload.len());
        packet.extend_from_slice(&payload);
        packet
    }
}
