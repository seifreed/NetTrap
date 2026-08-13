use crate::mqtt::{
    MQTT_CONNECT, MQTT_DISCONNECT, MQTT_PINGREQ, MQTT_PINGRESP, MQTT_PUBLISH, MQTT_PUBREL,
    MQTT_SUBSCRIBE, MQTT_UNSUBSCRIBE,
};

const MQTT_MAX_VARIABLE_BYTE_INTEGER: usize = 268_435_455;
pub(crate) const MQTT_MAX_PACKET_BYTES: usize = 1024 * 1024;
const MQTT_MAX_TOPIC_FILTERS: usize = 1024;
const MQTT_PUBLISH_PAYLOAD_PREVIEW_BYTES: usize = 1024;
const MQTT_SUBSCRIBE_QOS_MASK: u8 = 0x03;
const MQTT_SUBSCRIBE_RESERVED_MASK: u8 = 0xC0;
const MQTT_SUBSCRIBE_RETAIN_HANDLING_MASK: u8 = 0x30;
const MQTT_SUBSCRIBE_RETAIN_HANDLING_RESERVED: u8 = 0x30;

pub struct MqttConnectInfo {
    pub client_id: String,
    pub username: Option<String>,
    pub password: Option<Vec<u8>>,
    pub protocol_level: u8,
    pub client_id_rejected: bool,
}

pub(crate) struct MqttPublishInfo {
    pub topic: String,
    pub payload_len: usize,
    pub payload_preview: Vec<u8>,
    pub packet_id: Option<u16>,
}

pub(crate) struct MqttSubscribeInfo {
    pub packet_id: u16,
    pub topic_count: usize,
    pub granted_qos: Vec<u8>,
    pub has_properties: bool,
}

pub(crate) struct MqttUnsubscribeInfo {
    pub packet_id: u16,
    pub topic_count: usize,
    pub has_properties: bool,
}

pub(crate) struct MqttPubrelInfo {
    pub packet_id: u16,
}

pub(crate) fn parse_disconnect_packet(payload: &[u8]) -> Option<()> {
    parse_disconnect_packet_for_level(payload, None)
}

pub(crate) fn parse_disconnect_packet_for_level(
    payload: &[u8],
    protocol_level: Option<u8>,
) -> Option<()> {
    if matches!(protocol_level, Some(3 | 4)) {
        return payload.is_empty().then_some(());
    }

    if payload.is_empty() {
        return Some(());
    }
    if !is_valid_disconnect_reason_code(payload[0]) {
        return None;
    }
    if payload.len() == 1 {
        return Some(());
    }

    let mut pos = 1usize;
    let properties_len = read_variable_int(payload, &mut pos)?;
    let properties_start = pos;
    let properties_end = properties_start.checked_add(properties_len)?;
    if properties_end != payload.len() {
        return None;
    }
    if !parse_disconnect_properties(&payload[properties_start..properties_end]) {
        return None;
    }

    Some(())
}

fn is_valid_disconnect_reason_code(reason_code: u8) -> bool {
    matches!(
        reason_code,
        0x00 | 0x04
            | 0x80
            | 0x81
            | 0x82
            | 0x83
            | 0x87
            | 0x89
            | 0x8B
            | 0x8D
            | 0x8E
            | 0x8F
            | 0x90
            | 0x93
            | 0x94
            | 0x95
            | 0x96
            | 0x97
            | 0x98
            | 0x99
            | 0x9A
            | 0x9B
            | 0x9C
            | 0x9D
            | 0x9E
            | 0x9F
            | 0xA0
            | 0xA1
            | 0xA2
    )
}

pub(crate) fn valid_fixed_header(first: u8, packet_type: u8, remaining_len: usize) -> bool {
    let flags = first & 0x0F;
    match packet_type {
        MQTT_CONNECT => flags == 0,
        MQTT_PINGREQ => flags == 0 && remaining_len == 0,
        MQTT_PINGRESP => flags == 0 && remaining_len == 0,
        MQTT_DISCONNECT => flags == 0,
        MQTT_PUBLISH => ((flags >> 1) & 0x03) != 0x03,
        MQTT_SUBSCRIBE => flags == 0x02,
        MQTT_UNSUBSCRIBE => flags == 0x02,
        MQTT_PUBREL => flags == 0x02,
        _ => false,
    }
}

/// Parse the remaining length field in MQTT fixed header.
/// Returns (remaining_length_value, start_of_payload) or None if invalid.
/// MQTT spec limits remaining length to 268,435,455 bytes (max 4 bytes encoding).
pub(crate) fn parse_remaining_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 2 {
        return None;
    }

    let mut multiplier = 1usize;
    let mut value = 0usize;
    let mut bytes_read = 0usize;

    loop {
        if bytes_read >= 4 || bytes_read + 1 >= data.len() {
            return None;
        }

        let byte = data[bytes_read + 1];
        bytes_read += 1;
        value = value.checked_add(((byte & 0x7F) as usize).checked_mul(multiplier)?)?;

        if byte & 0x80 == 0 {
            break;
        }
        multiplier = multiplier.checked_mul(128)?;
    }

    if value > MQTT_MAX_VARIABLE_BYTE_INTEGER || remaining_length_encoded_len(value) != bytes_read {
        return None;
    }

    Some((value, bytes_read + 1))
}

pub(crate) fn remaining_length_encoded_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 128 {
        value /= 128;
        len += 1;
    }
    len
}

pub(crate) fn parse_connect(data: &[u8]) -> Option<MqttConnectInfo> {
    if data.first().copied()? != (MQTT_CONNECT << 4) {
        return None;
    }
    let (remaining_len, start) = parse_remaining_length(data)?;
    if start.checked_add(remaining_len)? != data.len() {
        return None;
    }
    let payload = &data[start..];

    let mut proto_pos = 0usize;
    let proto_name = read_mqtt_string(payload, &mut proto_pos)?;
    let proto_level_pos = proto_pos;
    let variable_header_end = proto_level_pos.checked_add(4)?;
    if variable_header_end > payload.len() {
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
    let username_flag = flags & 0x80 != 0;
    let password_flag = flags & 0x40 != 0;
    if password_flag && !username_flag {
        return None;
    }
    let will_flag = flags & 0x04 != 0;
    let will_qos = (flags >> 3) & 0x03;
    let will_retain = flags & 0x20 != 0;
    if will_qos == 0x03 || (!will_flag && (will_qos != 0 || will_retain)) {
        return None;
    }

    let mut pos = variable_header_end; // protocol level + flags + keepalive
    if proto_level == 5 {
        let properties_len = read_variable_int(payload, &mut pos)?;
        let properties_start = pos;
        pos = pos.checked_add(properties_len)?;
        if pos > payload.len() || !parse_connect_properties(&payload[properties_start..pos]) {
            return None;
        }
    }

    let client_id = read_mqtt_utf8_string(payload, &mut pos)?;
    let client_id_rejected =
        matches!(proto_level, 3 | 4) && client_id.is_empty() && flags & 0x02 == 0;

    let mut username = None;
    let mut password = None;

    // MQTT 5 includes Will Properties before Will Topic and Will Message.
    if will_flag {
        if proto_level == 5 {
            let will_properties_len = read_variable_int(payload, &mut pos)?;
            let will_properties_start = pos;
            pos = pos.checked_add(will_properties_len)?;
            if pos > payload.len() || !parse_will_properties(&payload[will_properties_start..pos]) {
                return None;
            }
        }
        read_mqtt_utf8_string(payload, &mut pos)?;
        read_mqtt_string(payload, &mut pos)?;
    }

    if username_flag {
        username = Some(read_mqtt_utf8_string(payload, &mut pos)?);
    }

    if password_flag {
        password = Some(read_mqtt_binary_bytes(payload, &mut pos)?);
    }

    if pos != payload.len() {
        return None;
    }

    Some(MqttConnectInfo {
        client_id,
        username,
        password,
        protocol_level: proto_level,
        client_id_rejected,
    })
}

pub(crate) fn read_mqtt_string(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let len_end = (*pos).checked_add(2)?;
    if len_end > data.len() {
        return None;
    }
    let len = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
    *pos = len_end;
    let end = (*pos).checked_add(len)?;
    if end > data.len() {
        return None;
    }
    let value = data[*pos..end].to_vec();
    *pos = end;
    Some(value)
}

pub(crate) fn read_mqtt_utf8_string(data: &[u8], pos: &mut usize) -> Option<String> {
    let value = read_mqtt_string(data, pos)?;
    let value = std::str::from_utf8(&value).ok()?;
    if !valid_mqtt_utf8_string(value) {
        return None;
    }
    Some(value.to_string())
}

fn read_mqtt_binary_bytes(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    read_mqtt_string(data, pos)
}

pub(crate) fn valid_mqtt_utf8_string(value: &str) -> bool {
    value.chars().all(|ch| {
        !matches!(
            ch as u32,
            0x0000..=0x001f | 0x007f..=0x009f | 0xfdd0..=0xfdef | 0xfffe | 0xffff
        ) && (ch as u32 & 0xfffe) != 0xfffe
    })
}

pub(crate) fn valid_publish_topic_name(value: &str) -> bool {
    valid_mqtt_utf8_string(value) && !value.contains(['+', '#'])
}

pub(crate) fn valid_subscribe_topic_filter(value: &str) -> bool {
    if value.is_empty() || !valid_mqtt_utf8_string(value) {
        return false;
    }

    if value.bytes().filter(|&byte| byte == b'#').count() > 1 {
        return false;
    }
    if let Some(hash_pos) = value.find('#') {
        if hash_pos + 1 != value.len() {
            return false;
        }
        if hash_pos > 0 && value.as_bytes()[hash_pos - 1] != b'/' {
            return false;
        }
    }

    value
        .split('/')
        .all(|level| !level.contains('+') || level == "+")
}

pub(crate) fn read_variable_int(data: &[u8], pos: &mut usize) -> Option<usize> {
    let mut multiplier = 1usize;
    let mut value = 0usize;
    for bytes_read in 1..=4 {
        if *pos >= data.len() {
            return None;
        }
        let byte = data[*pos];
        *pos += 1;
        value = value.checked_add(((byte & 0x7F) as usize).checked_mul(multiplier)?)?;
        if byte & 0x80 == 0 {
            if value > MQTT_MAX_VARIABLE_BYTE_INTEGER
                || remaining_length_encoded_len(value) != bytes_read
            {
                return None;
            }
            return Some(value);
        }
        multiplier = multiplier.checked_mul(128)?;
    }
    None
}

pub(crate) fn parse_publish(data: &[u8]) -> Option<MqttPublishInfo> {
    let (remaining_len, start) = parse_remaining_length(data)?;
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
    let topic_end = 2usize.checked_add(topic_len)?;
    if topic_len == 0 || topic_end > payload.len() {
        return None; // topic_len exceeds available data
    }
    let mut pos = topic_end;
    let topic = std::str::from_utf8(&payload[2..topic_end]).ok()?;
    if !valid_publish_topic_name(topic) {
        return None;
    }
    let topic = topic.to_string();

    // Skip packet ID for QoS 1/2
    let qos = (data[0] >> 1) & 0x03;
    let packet_id = if qos >= 1 {
        let packet_id_end = pos.checked_add(2)?;
        if packet_id_end > payload.len() {
            return None;
        }
        let id = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        if id == 0 {
            return None;
        }
        pos = packet_id_end;
        Some(id)
    } else {
        None
    };

    let msg_payload = if pos < payload.len() {
        &payload[pos..]
    } else {
        &[]
    };
    let preview_len = msg_payload.len().min(MQTT_PUBLISH_PAYLOAD_PREVIEW_BYTES);
    Some(MqttPublishInfo {
        topic,
        payload_len: msg_payload.len(),
        payload_preview: msg_payload[..preview_len].to_vec(),
        packet_id,
    })
}

#[cfg(test)]
pub(crate) fn parse_subscribe_packet(payload: &[u8]) -> Option<MqttSubscribeInfo> {
    parse_subscribe_packet_for_level(payload, None)
}

pub(crate) fn parse_subscribe_packet_for_level(
    payload: &[u8],
    protocol_level: Option<u8>,
) -> Option<MqttSubscribeInfo> {
    if payload.len() < 5 {
        return None;
    }
    let packet_id = u16::from_be_bytes([payload[0], payload[1]]);
    if packet_id == 0 {
        return None;
    }

    if matches!(protocol_level, Some(3 | 4)) {
        let granted_qos = parse_subscribe_topics(payload, 2, protocol_level)?;
        return Some(MqttSubscribeInfo {
            packet_id,
            topic_count: granted_qos.len(),
            granted_qos,
            has_properties: false,
        });
    }

    let mut pos = 2usize;
    let Some(properties_len) = read_variable_int(payload, &mut pos) else {
        return parse_subscribe_topics(payload, 2, protocol_level).map(|granted_qos| {
            MqttSubscribeInfo {
                packet_id,
                topic_count: granted_qos.len(),
                granted_qos,
                has_properties: false,
            }
        });
    };
    let properties_start = pos;
    let properties_end = match pos.checked_add(properties_len) {
        Some(end) if end <= payload.len() => end,
        _ => return None,
    };

    if parse_subscribe_properties(&payload[properties_start..properties_end]) {
        let granted_qos = parse_subscribe_topics(payload, properties_end, protocol_level)?;
        return Some(MqttSubscribeInfo {
            packet_id,
            topic_count: granted_qos.len(),
            granted_qos,
            has_properties: true,
        });
    }

    None
}

#[cfg(test)]
pub(crate) fn parse_unsubscribe_packet(payload: &[u8]) -> Option<MqttUnsubscribeInfo> {
    parse_unsubscribe_packet_for_level(payload, None)
}

pub(crate) fn parse_unsubscribe_packet_for_level(
    payload: &[u8],
    protocol_level: Option<u8>,
) -> Option<MqttUnsubscribeInfo> {
    if payload.len() < 5 {
        return None;
    }
    let packet_id = u16::from_be_bytes([payload[0], payload[1]]);
    if packet_id == 0 {
        return None;
    }

    if matches!(protocol_level, Some(3 | 4)) {
        let topic_count = parse_unsubscribe_topics(payload, 2)?;
        return Some(MqttUnsubscribeInfo {
            packet_id,
            topic_count,
            has_properties: false,
        });
    }

    let mut pos = 2usize;
    let Some(properties_len) = read_variable_int(payload, &mut pos) else {
        let topic_count = parse_unsubscribe_topics(payload, 2)?;
        return Some(MqttUnsubscribeInfo {
            packet_id,
            topic_count,
            has_properties: false,
        });
    };
    let properties_start = pos;
    let properties_end = match pos.checked_add(properties_len) {
        Some(end) if end <= payload.len() => end,
        _ => return None,
    };

    if parse_unsubscribe_properties(&payload[properties_start..properties_end]) {
        let topic_count = parse_unsubscribe_topics(payload, properties_end)?;
        return Some(MqttUnsubscribeInfo {
            packet_id,
            topic_count,
            has_properties: true,
        });
    }

    None
}

pub(crate) fn parse_pubrel_packet(payload: &[u8]) -> Option<MqttPubrelInfo> {
    if payload.len() < 2 {
        return None;
    }
    let packet_id = u16::from_be_bytes([payload[0], payload[1]]);
    if packet_id == 0 {
        return None;
    }

    let mut pos = 2usize;
    if pos == payload.len() {
        return Some(MqttPubrelInfo { packet_id });
    }

    let reason_code = payload[pos];
    pos += 1;
    if !matches!(reason_code, 0x00 | 0x92) {
        return None;
    }

    if pos == payload.len() {
        return Some(MqttPubrelInfo { packet_id });
    }

    let properties_len = read_variable_int(payload, &mut pos)?;
    let properties_start = pos;
    pos = pos.checked_add(properties_len)?;
    if pos > payload.len() {
        return None;
    }
    if !parse_pubrel_properties(&payload[properties_start..pos]) {
        return None;
    }
    if pos != payload.len() {
        return None;
    }

    Some(MqttPubrelInfo { packet_id })
}

fn parse_disconnect_properties(properties: &[u8]) -> bool {
    parse_property_block(properties, PropertyContext::Disconnect)
}

fn parse_subscribe_topics(
    payload: &[u8],
    mut pos: usize,
    protocol_level: Option<u8>,
) -> Option<Vec<u8>> {
    let mut granted_qos = Vec::new();

    while pos < payload.len() {
        let topic_len_end = pos.checked_add(2)?;
        if topic_len_end > payload.len() {
            return None;
        }
        let topic_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos = topic_len_end;
        if topic_len == 0 {
            return None;
        }
        let topic_end = pos.checked_add(topic_len)?;
        if topic_end >= payload.len() {
            return None;
        }
        let topic = std::str::from_utf8(&payload[pos..topic_end]).ok()?;
        if !valid_subscribe_topic_filter(topic) {
            return None;
        }
        pos = topic_end;
        let subscription_options = payload[pos];
        if !valid_subscription_options(subscription_options, protocol_level) {
            return None;
        }
        if granted_qos.len() >= MQTT_MAX_TOPIC_FILTERS {
            return None;
        }
        pos += 1;
        granted_qos.push(subscription_options & MQTT_SUBSCRIBE_QOS_MASK);
    }

    if granted_qos.is_empty() {
        return None;
    }
    Some(granted_qos)
}

fn valid_subscription_options(options: u8, protocol_level: Option<u8>) -> bool {
    if options & MQTT_SUBSCRIBE_RESERVED_MASK != 0 || options & MQTT_SUBSCRIBE_QOS_MASK == 3 {
        return false;
    }

    if matches!(protocol_level, Some(3 | 4)) {
        return options == options & MQTT_SUBSCRIBE_QOS_MASK;
    }

    options & MQTT_SUBSCRIBE_RETAIN_HANDLING_MASK != MQTT_SUBSCRIBE_RETAIN_HANDLING_RESERVED
}

fn parse_subscribe_properties(properties: &[u8]) -> bool {
    let mut pos = 0usize;
    let mut saw_subscription_identifier = false;

    while pos < properties.len() {
        let property_id = properties[pos];
        pos += 1;
        match property_id {
            0x0B => {
                if saw_subscription_identifier {
                    return false;
                }
                let Some(subscription_identifier) = read_variable_int(properties, &mut pos) else {
                    return false;
                };
                if subscription_identifier == 0 {
                    return false;
                }
                saw_subscription_identifier = true;
            }
            0x26 => {
                if read_mqtt_utf8_string(properties, &mut pos).is_none()
                    || read_mqtt_utf8_string(properties, &mut pos).is_none()
                {
                    return false;
                }
            }
            _ => return false,
        }
    }

    true
}

fn parse_unsubscribe_topics(payload: &[u8], mut pos: usize) -> Option<usize> {
    let mut topic_count = 0usize;

    while pos < payload.len() {
        let topic_len_end = pos.checked_add(2)?;
        if topic_len_end > payload.len() {
            return None;
        }
        let topic_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos = topic_len_end;
        if topic_len == 0 {
            return None;
        }
        let topic_end = pos.checked_add(topic_len)?;
        if topic_end > payload.len() {
            return None;
        }
        let topic = std::str::from_utf8(&payload[pos..topic_end]).ok()?;
        if !valid_subscribe_topic_filter(topic) {
            return None;
        }
        if topic_count >= MQTT_MAX_TOPIC_FILTERS {
            return None;
        }
        pos = topic_end;
        topic_count += 1;
    }

    if topic_count == 0 {
        return None;
    }
    Some(topic_count)
}

fn parse_unsubscribe_properties(properties: &[u8]) -> bool {
    let mut pos = 0usize;

    while pos < properties.len() {
        let property_id = properties[pos];
        pos += 1;
        match property_id {
            0x26 => {
                if read_mqtt_utf8_string(properties, &mut pos).is_none()
                    || read_mqtt_utf8_string(properties, &mut pos).is_none()
                {
                    return false;
                }
            }
            _ => return false,
        }
    }

    true
}

fn parse_pubrel_properties(properties: &[u8]) -> bool {
    let mut pos = 0usize;
    let mut saw_reason_string = false;

    while pos < properties.len() {
        let property_id = properties[pos];
        pos += 1;
        match property_id {
            0x1F => {
                if saw_reason_string || read_mqtt_utf8_string(properties, &mut pos).is_none() {
                    return false;
                }
                saw_reason_string = true;
            }
            0x26 => {
                if read_mqtt_utf8_string(properties, &mut pos).is_none()
                    || read_mqtt_utf8_string(properties, &mut pos).is_none()
                {
                    return false;
                }
            }
            _ => return false,
        }
    }

    true
}

fn parse_connect_properties(properties: &[u8]) -> bool {
    parse_property_block(properties, PropertyContext::Connect)
}

fn parse_will_properties(properties: &[u8]) -> bool {
    parse_property_block(properties, PropertyContext::Will)
}

#[derive(Clone, Copy)]
enum PropertyContext {
    Connect,
    Will,
    Disconnect,
}

#[derive(Default)]
struct PropertyState {
    session_expiry_interval: bool,
    receive_maximum: bool,
    maximum_packet_size: bool,
    topic_alias_maximum: bool,
    request_response_information: bool,
    request_problem_information: bool,
    authentication_method: bool,
    authentication_data: bool,
    will_delay_interval: bool,
    payload_format_indicator: bool,
    message_expiry_interval: bool,
    content_type: bool,
    response_topic: bool,
    correlation_data: bool,
    reason_string: bool,
    server_reference: bool,
}

fn parse_property_block(properties: &[u8], context: PropertyContext) -> bool {
    let mut pos = 0usize;
    let mut state = PropertyState::default();

    while pos < properties.len() {
        let property_id = properties[pos];
        pos += 1;
        match (context, property_id) {
            (PropertyContext::Connect, 0x11) => {
                if state.session_expiry_interval || !consume_fixed_len(properties, &mut pos, 4) {
                    return false;
                }
                state.session_expiry_interval = true;
            }
            (PropertyContext::Connect, 0x21) => {
                if state.receive_maximum || !consume_fixed_len(properties, &mut pos, 2) {
                    return false;
                }
                state.receive_maximum = true;
            }
            (PropertyContext::Connect, 0x27) => {
                if state.maximum_packet_size || !consume_fixed_len(properties, &mut pos, 4) {
                    return false;
                }
                state.maximum_packet_size = true;
            }
            (PropertyContext::Connect, 0x22) => {
                if state.topic_alias_maximum || !consume_fixed_len(properties, &mut pos, 2) {
                    return false;
                }
                state.topic_alias_maximum = true;
            }
            (PropertyContext::Connect, 0x19) => {
                if state.request_response_information || !consume_fixed_len(properties, &mut pos, 1)
                {
                    return false;
                }
                state.request_response_information = true;
            }
            (PropertyContext::Connect, 0x17) => {
                if state.request_problem_information || !consume_fixed_len(properties, &mut pos, 1)
                {
                    return false;
                }
                state.request_problem_information = true;
            }
            (PropertyContext::Connect, 0x26) => {
                if !consume_utf8_pair(properties, &mut pos) {
                    return false;
                }
            }
            (PropertyContext::Connect, 0x15) => {
                if state.authentication_method || !consume_utf8_string(properties, &mut pos) {
                    return false;
                }
                state.authentication_method = true;
            }
            (PropertyContext::Connect, 0x16) => {
                if state.authentication_data || !consume_binary_string(properties, &mut pos) {
                    return false;
                }
                state.authentication_data = true;
            }
            (PropertyContext::Will, 0x18) => {
                if state.will_delay_interval || !consume_fixed_len(properties, &mut pos, 4) {
                    return false;
                }
                state.will_delay_interval = true;
            }
            (PropertyContext::Will, 0x01) => {
                if state.payload_format_indicator || !consume_fixed_len(properties, &mut pos, 1) {
                    return false;
                }
                state.payload_format_indicator = true;
            }
            (PropertyContext::Will, 0x02) => {
                if state.message_expiry_interval || !consume_fixed_len(properties, &mut pos, 4) {
                    return false;
                }
                state.message_expiry_interval = true;
            }
            (PropertyContext::Will, 0x23) => {
                if state.content_type || !consume_utf8_string(properties, &mut pos) {
                    return false;
                }
                state.content_type = true;
            }
            (PropertyContext::Will, 0x09) => {
                if state.response_topic || !consume_utf8_string(properties, &mut pos) {
                    return false;
                }
                state.response_topic = true;
            }
            (PropertyContext::Will, 0x08) => {
                if state.correlation_data || !consume_binary_string(properties, &mut pos) {
                    return false;
                }
                state.correlation_data = true;
            }
            (PropertyContext::Will, 0x26) => {
                if !consume_utf8_pair(properties, &mut pos) {
                    return false;
                }
            }
            (PropertyContext::Disconnect, 0x11) => {
                if state.session_expiry_interval || !consume_fixed_len(properties, &mut pos, 4) {
                    return false;
                }
                state.session_expiry_interval = true;
            }
            (PropertyContext::Disconnect, 0x1F) => {
                if state.reason_string || !consume_utf8_string(properties, &mut pos) {
                    return false;
                }
                state.reason_string = true;
            }
            (PropertyContext::Disconnect, 0x1C) => {
                if state.server_reference || !consume_utf8_string(properties, &mut pos) {
                    return false;
                }
                state.server_reference = true;
            }
            (PropertyContext::Disconnect, 0x26) => {
                if !consume_utf8_pair(properties, &mut pos) {
                    return false;
                }
            }
            _ => return false,
        }
    }

    true
}

fn consume_fixed_len(data: &[u8], pos: &mut usize, len: usize) -> bool {
    let Some(end) = pos.checked_add(len) else {
        return false;
    };
    if end > data.len() {
        return false;
    }
    *pos = end;
    true
}

fn consume_utf8_string(data: &[u8], pos: &mut usize) -> bool {
    read_mqtt_utf8_string(data, pos).is_some()
}

fn consume_binary_string(data: &[u8], pos: &mut usize) -> bool {
    read_mqtt_string(data, pos).is_some()
}

fn consume_utf8_pair(data: &[u8], pos: &mut usize) -> bool {
    consume_utf8_string(data, pos) && consume_utf8_string(data, pos)
}

#[cfg(test)]
mod tests {
    use super::{
        MQTT_MAX_TOPIC_FILTERS, parse_disconnect_packet, parse_pubrel_packet,
        parse_remaining_length, parse_subscribe_packet, parse_subscribe_packet_for_level,
        parse_unsubscribe_packet, valid_mqtt_utf8_string,
    };

    #[test]
    fn parse_remaining_length_rejects_overlong_encoding() {
        assert_eq!(
            parse_remaining_length(&[0x10, 0x80, 0x80, 0x80, 0x80, 0x00]),
            None
        );
    }

    #[test]
    fn mqtt_utf8_strings_reject_forbidden_codepoints() {
        assert!(valid_mqtt_utf8_string("client-id"));
        assert!(!valid_mqtt_utf8_string("client\u{1f}id"));
        assert!(!valid_mqtt_utf8_string("client\u{7f}id"));
        assert!(!valid_mqtt_utf8_string("client\u{fdd0}id"));
        assert!(!valid_mqtt_utf8_string("client\u{fffe}id"));
        assert!(!valid_mqtt_utf8_string("client\u{1ffff}id"));
    }

    #[test]
    fn parse_subscribe_packet_accepts_valid_user_properties() {
        let payload = [
            0x12, 0x34, 0x13, 0x26, 0x00, 0x08, b't', b'r', b'a', b'c', b'e', b'-', b'i', b'd',
            0x00, 0x06, b'a', b'b', b'c', b'1', b'2', b'3', 0x00, 0x01, b'a', 0x00,
        ];

        let info = parse_subscribe_packet(&payload).expect("valid subscribe packet");

        assert_eq!(info.packet_id, 0x1234);
        assert_eq!(info.topic_count, 1);
        assert!(info.has_properties);
    }

    #[test]
    fn parse_subscribe_packet_rejects_unknown_properties() {
        let payload = [0x12, 0x34, 0x01, 0x99, 0x00, 0x01, b'a', 0x00];

        assert!(parse_subscribe_packet(&payload).is_none());
    }

    #[test]
    fn parse_unsubscribe_packet_accepts_valid_user_properties() {
        let payload = [
            0x12, 0x34, 0x13, 0x26, 0x00, 0x08, b't', b'r', b'a', b'c', b'e', b'-', b'i', b'd',
            0x00, 0x06, b'a', b'b', b'c', b'1', b'2', b'3', 0x00, 0x01, b'a',
        ];

        let info = parse_unsubscribe_packet(&payload).expect("valid unsubscribe packet");

        assert_eq!(info.packet_id, 0x1234);
        assert_eq!(info.topic_count, 1);
    }

    #[test]
    fn parse_unsubscribe_packet_rejects_unknown_properties() {
        let payload = [0x12, 0x34, 0x01, 0x99, 0x00, 0x01, b'a'];

        assert!(parse_unsubscribe_packet(&payload).is_none());
    }

    #[test]
    fn parse_subscribe_packet_rejects_too_many_topic_filters() {
        let mut payload = vec![0x12, 0x34, 0x00];
        for _ in 0..=MQTT_MAX_TOPIC_FILTERS {
            payload.extend_from_slice(&[0x00, 0x01, b'a', 0x00]);
        }

        assert!(parse_subscribe_packet(&payload).is_none());
    }

    #[test]
    fn parse_subscribe_packet_rejects_reserved_retain_handling() {
        let payload = [0x12, 0x34, 0x00, 0x00, 0x01, b'a', 0x30];

        assert!(parse_subscribe_packet(&payload).is_none());
    }

    #[test]
    fn parse_subscribe_packet_rejects_mqtt3_non_qos_options() {
        let payload = [0x12, 0x34, 0x00, 0x01, b'a', 0x04];

        assert!(parse_subscribe_packet_for_level(&payload, Some(4)).is_none());
    }

    #[test]
    fn parse_unsubscribe_packet_rejects_too_many_topic_filters() {
        let mut payload = vec![0x12, 0x34, 0x00];
        for _ in 0..=MQTT_MAX_TOPIC_FILTERS {
            payload.extend_from_slice(&[0x00, 0x01, b'a']);
        }

        assert!(parse_unsubscribe_packet(&payload).is_none());
    }

    #[test]
    fn parse_subscribe_packet_prefers_explicit_properties_when_implicit_form_is_invalid() {
        let payload = ambiguous_subscribe_payload();

        let info = parse_subscribe_packet(&payload).expect("ambiguous subscribe packet");

        assert_eq!(info.packet_id, 0x1234);
        assert_eq!(info.topic_count, 2);
        assert_eq!(info.granted_qos, vec![1, 1]);
        assert!(info.has_properties);
    }

    #[test]
    fn parse_subscribe_packet_rejects_implicit_properties_length_fallback() {
        let payload = [0x12, 0x34, 0x00, 0x01, b'a', 0x00];

        assert!(parse_subscribe_packet(&payload).is_none());
    }

    #[test]
    fn parse_pubrel_packet_accepts_v5_reason_string_and_user_properties() {
        let payload = [
            0x12, 0x34, 0x00, 0x1a, 0x1f, 0x00, 0x04, b'r', b'e', b'l', b'y', 0x26, 0x00, 0x08,
            b't', b'r', b'a', b'c', b'e', b'-', b'i', b'd', 0x00, 0x06, b'a', b'b', b'c', b'1',
            b'2', b'3',
        ];

        let info = parse_pubrel_packet(&payload).expect("valid PUBREL packet");

        assert_eq!(info.packet_id, 0x1234);
    }

    #[test]
    fn parse_disconnect_packet_accepts_mqtt5_session_expiry_property() {
        let payload = [0x00, 0x05, 0x11, 0x00, 0x00, 0x00, 0x01];

        assert!(parse_disconnect_packet(&payload).is_some());
    }

    #[test]
    fn parse_disconnect_packet_accepts_reason_code_only() {
        assert!(parse_disconnect_packet(&[0x00]).is_some());
        assert!(parse_disconnect_packet(&[0x04]).is_some());
    }

    #[test]
    fn parse_disconnect_packet_rejects_trailing_bytes_after_properties() {
        assert!(parse_disconnect_packet(&[0x00, 0x00, 0x00]).is_none());
        assert!(parse_disconnect_packet(&[0x00, 0x01, 0x99]).is_none());
    }

    #[test]
    fn parse_unsubscribe_packet_rejects_implicit_properties_length_fallback() {
        let payload = [0x12, 0x34, 0x00, 0x01, b'a'];

        assert!(parse_unsubscribe_packet(&payload).is_none());
    }

    #[test]
    fn parse_pubrel_packet_rejects_unknown_properties() {
        let payload = [0x12, 0x34, 0x00, 0x02, 0x99, 0x00];

        assert!(parse_pubrel_packet(&payload).is_none());
    }

    fn ambiguous_subscribe_payload() -> Vec<u8> {
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
        payload
    }
}
