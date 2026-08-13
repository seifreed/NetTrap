use super::*;

pub(crate) fn mqtt_remaining_length(data: &[u8]) -> Option<(usize, usize)> {
    let mut multiplier = 1usize;
    let mut value = 0usize;

    for bytes_read in 1..=4 {
        if bytes_read >= data.len() {
            return None;
        }

        let byte = data[bytes_read];
        value = value.checked_add(((byte & 0x7f) as usize).checked_mul(multiplier)?)?;
        if byte & 0x80 == 0 {
            if mqtt_remaining_length_encoded_len(value) != bytes_read {
                return None;
            }
            return Some((value, bytes_read + 1));
        }
        multiplier = multiplier.checked_mul(128)?;
    }

    None
}

pub(crate) fn looks_like_mqtt_client_packet(data: &[u8]) -> bool {
    if data.len() > MQTT_MAX_PACKET_BYTES {
        return false;
    }

    let Some(packet_type) = data.first().copied().map(|byte| byte >> 4) else {
        return false;
    };

    match packet_type {
        1 => mqtt_connect_is_well_formed(data),
        3 => mqtt_publish_is_well_formed(data),
        6 => mqtt_pubrel_is_well_formed(data),
        8 => mqtt_subscribe_is_well_formed(data),
        10 => mqtt_unsubscribe_is_well_formed(data),
        12 => {
            data.len() >= 2
                && data[0] & 0x0f == 0
                && data[1] == 0
                && mqtt_sample_tail_is_plausible(data, 2)
        }
        14 => mqtt_disconnect_is_well_formed(data),
        _ => false,
    }
}

fn mqtt_connect_is_well_formed(data: &[u8]) -> bool {
    if data.len() < 7 || data[0] != 0x10 {
        return false;
    }
    let Some((remaining_len, remaining_start)) = mqtt_remaining_length(data) else {
        return false;
    };
    let Some(frame_end) = remaining_start.checked_add(remaining_len) else {
        return false;
    };
    if !mqtt_sample_tail_is_plausible(data, frame_end) {
        return false;
    }

    let Some(proto_len_end) = remaining_start.checked_add(2) else {
        return false;
    };
    if proto_len_end > frame_end {
        return false;
    }
    let proto_len = u16::from_be_bytes([data[remaining_start], data[remaining_start + 1]]) as usize;
    let Some(proto_end) = proto_len_end.checked_add(proto_len) else {
        return false;
    };
    if proto_len == 0 || proto_end > frame_end {
        return false;
    }

    let Ok(proto_name) = std::str::from_utf8(&data[proto_len_end..proto_end]) else {
        return false;
    };
    let Some(&level) = data.get(proto_end) else {
        return false;
    };

    if !matches!(
        (proto_name.as_bytes(), level),
        (b"MQTT", 4 | 5) | (b"MQIsdp", 3)
    ) {
        return false;
    }

    let Some(mut pos) = proto_end.checked_add(1) else {
        return false;
    };
    let Some(&flags) = data.get(pos) else {
        return false;
    };
    if flags & 0x01 != 0 {
        return false;
    }
    let username_flag = flags & 0x80 != 0;
    let password_flag = flags & 0x40 != 0;
    if password_flag && !username_flag {
        return false;
    }
    let will_flag = flags & 0x04 != 0;
    let will_qos = (flags >> 3) & 0x03;
    let will_retain = flags & 0x20 != 0;
    if will_qos == 0x03 || (!will_flag && (will_qos != 0 || will_retain)) {
        return false;
    }

    pos += 1;
    let Some(pos_after_keepalive) = pos.checked_add(2) else {
        return false;
    };
    if pos_after_keepalive > frame_end {
        return false;
    }
    pos = pos_after_keepalive;

    if level == 5 {
        let Some((properties_len, consumed)) = mqtt_read_variable_int(data, &mut pos) else {
            return false;
        };
        let properties_start = pos;
        let Some(next_pos) = pos.checked_add(properties_len) else {
            return false;
        };
        if consumed == 0
            || next_pos > frame_end
            || !mqtt_connect_properties_are_well_formed(&data[properties_start..next_pos])
        {
            return false;
        }
        pos = next_pos;
    }

    let client_id_start = pos;
    if !mqtt_read_mqtt_utf8_string(data, &mut pos) {
        return false;
    }
    if matches!(level, 3 | 4) && flags & 0x02 == 0 && pos == client_id_start + 2 {
        return false;
    }

    if will_flag {
        if level == 5 {
            let Some((properties_len, consumed)) = mqtt_read_variable_int(data, &mut pos) else {
                return false;
            };
            let properties_start = pos;
            let Some(next_pos) = pos.checked_add(properties_len) else {
                return false;
            };
            if consumed == 0
                || next_pos > frame_end
                || !mqtt_will_properties_are_well_formed(&data[properties_start..next_pos])
            {
                return false;
            }
            pos = next_pos;
        }
        if !mqtt_read_mqtt_utf8_string(data, &mut pos) {
            return false;
        }
        if !mqtt_read_mqtt_string(data, &mut pos) {
            return false;
        }
    }

    if username_flag && !mqtt_read_mqtt_utf8_string(data, &mut pos) {
        return false;
    }

    if password_flag && !mqtt_read_mqtt_string(data, &mut pos) {
        return false;
    }

    pos == frame_end
}

fn mqtt_read_mqtt_string(data: &[u8], pos: &mut usize) -> bool {
    let Some(end) = pos.checked_add(2) else {
        return false;
    };
    let Some(len_bytes) = data.get(*pos..end) else {
        return false;
    };
    let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
    *pos = end;
    let Some(end) = pos.checked_add(len) else {
        return false;
    };
    let Some(value) = data.get(*pos..end) else {
        return false;
    };
    *pos = end;
    let _ = value;
    true
}

fn mqtt_read_mqtt_utf8_string(data: &[u8], pos: &mut usize) -> bool {
    let start = *pos;
    if !mqtt_read_mqtt_string(data, pos) {
        return false;
    }
    let value = &data[start..*pos];
    let value = &value[2..];
    std::str::from_utf8(value).is_ok_and(mqtt_utf8_string_is_valid)
}

fn mqtt_read_variable_int(data: &[u8], pos: &mut usize) -> Option<(usize, usize)> {
    let mut multiplier = 1usize;
    let mut value = 0usize;
    let mut consumed = 0usize;

    while consumed < 4 {
        let byte = *data.get(*pos + consumed)?;
        consumed += 1;
        value = value.checked_add(((byte & 0x7f) as usize).checked_mul(multiplier)?)?;
        if byte & 0x80 == 0 {
            if value > MQTT_MAX_VARIABLE_BYTE_INTEGER
                || mqtt_remaining_length_encoded_len(value) != consumed
            {
                return None;
            }
            *pos += consumed;
            return Some((value, consumed));
        }
        multiplier = multiplier.checked_mul(128)?;
    }

    None
}

#[derive(Default)]
struct MqttPropertyState {
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
}

fn mqtt_connect_properties_are_well_formed(properties: &[u8]) -> bool {
    let mut pos = 0usize;
    let mut state = MqttPropertyState::default();

    while pos < properties.len() {
        let property_id = properties[pos];
        pos += 1;
        match property_id {
            0x11 => {
                if state.session_expiry_interval || !mqtt_consume_fixed_len(properties, &mut pos, 4)
                {
                    return false;
                }
                state.session_expiry_interval = true;
            }
            0x21 => {
                if state.receive_maximum || !mqtt_consume_fixed_len(properties, &mut pos, 2) {
                    return false;
                }
                state.receive_maximum = true;
            }
            0x27 => {
                if state.maximum_packet_size || !mqtt_consume_fixed_len(properties, &mut pos, 4) {
                    return false;
                }
                state.maximum_packet_size = true;
            }
            0x22 => {
                if state.topic_alias_maximum || !mqtt_consume_fixed_len(properties, &mut pos, 2) {
                    return false;
                }
                state.topic_alias_maximum = true;
            }
            0x19 => {
                if state.request_response_information
                    || !mqtt_consume_fixed_len(properties, &mut pos, 1)
                {
                    return false;
                }
                state.request_response_information = true;
            }
            0x17 => {
                if state.request_problem_information
                    || !mqtt_consume_fixed_len(properties, &mut pos, 1)
                {
                    return false;
                }
                state.request_problem_information = true;
            }
            0x26 => {
                if !mqtt_consume_utf8_pair(properties, &mut pos) {
                    return false;
                }
            }
            0x15 => {
                if state.authentication_method || !mqtt_read_mqtt_utf8_string(properties, &mut pos)
                {
                    return false;
                }
                state.authentication_method = true;
            }
            0x16 => {
                if state.authentication_data || !mqtt_read_mqtt_string(properties, &mut pos) {
                    return false;
                }
                state.authentication_data = true;
            }
            _ => return false,
        }
    }

    true
}

fn mqtt_will_properties_are_well_formed(properties: &[u8]) -> bool {
    let mut pos = 0usize;
    let mut state = MqttPropertyState::default();

    while pos < properties.len() {
        let property_id = properties[pos];
        pos += 1;
        match property_id {
            0x18 => {
                if state.will_delay_interval || !mqtt_consume_fixed_len(properties, &mut pos, 4) {
                    return false;
                }
                state.will_delay_interval = true;
            }
            0x01 => {
                if state.payload_format_indicator
                    || !mqtt_consume_fixed_len(properties, &mut pos, 1)
                {
                    return false;
                }
                state.payload_format_indicator = true;
            }
            0x02 => {
                if state.message_expiry_interval || !mqtt_consume_fixed_len(properties, &mut pos, 4)
                {
                    return false;
                }
                state.message_expiry_interval = true;
            }
            0x23 => {
                if state.content_type || !mqtt_read_mqtt_utf8_string(properties, &mut pos) {
                    return false;
                }
                state.content_type = true;
            }
            0x09 => {
                if state.response_topic || !mqtt_read_mqtt_utf8_string(properties, &mut pos) {
                    return false;
                }
                state.response_topic = true;
            }
            0x08 => {
                if state.correlation_data || !mqtt_read_mqtt_string(properties, &mut pos) {
                    return false;
                }
                state.correlation_data = true;
            }
            0x26 => {
                if !mqtt_consume_utf8_pair(properties, &mut pos) {
                    return false;
                }
            }
            _ => return false,
        }
    }

    true
}

fn mqtt_consume_fixed_len(data: &[u8], pos: &mut usize, len: usize) -> bool {
    let Some(end) = pos.checked_add(len) else {
        return false;
    };
    if end > data.len() {
        return false;
    }
    *pos = end;
    true
}

fn mqtt_consume_utf8_pair(data: &[u8], pos: &mut usize) -> bool {
    mqtt_read_mqtt_utf8_string(data, pos) && mqtt_read_mqtt_utf8_string(data, pos)
}

fn mqtt_publish_is_well_formed(data: &[u8]) -> bool {
    let Some((remaining_len, start)) = mqtt_remaining_length(data) else {
        return false;
    };
    let Some(frame_end) = start.checked_add(remaining_len) else {
        return false;
    };
    if !mqtt_sample_tail_is_plausible(data, frame_end) {
        return false;
    }

    let payload = &data[start..frame_end];
    if payload.len() < 2 {
        return false;
    }

    let topic_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    let Some(topic_end) = 2usize.checked_add(topic_len) else {
        return false;
    };
    if topic_len == 0 || topic_end > payload.len() {
        return false;
    }

    let Ok(topic) = std::str::from_utf8(&payload[2..topic_end]) else {
        return false;
    };
    if !mqtt_publish_topic_is_valid(topic) {
        return false;
    }

    let qos = (data[0] >> 1) & 0x03;
    if qos == 0x03 {
        return false;
    }
    if qos >= 1 {
        let Some(packet_id_end) = topic_end.checked_add(2) else {
            return false;
        };
        if packet_id_end > payload.len()
            || u16::from_be_bytes([payload[topic_end], payload[topic_end + 1]]) == 0
        {
            return false;
        }
    }

    true
}

fn mqtt_subscribe_is_well_formed(data: &[u8]) -> bool {
    if data[0] & 0x0f != 0x02 {
        return false;
    }

    let Some((remaining_len, start)) = mqtt_remaining_length(data) else {
        return false;
    };
    let Some(frame_end) = start.checked_add(remaining_len) else {
        return false;
    };
    if !mqtt_sample_tail_is_plausible(data, frame_end) {
        return false;
    }

    let payload = &data[start..frame_end];
    if payload.len() < 5 {
        return false;
    }

    let packet_id = u16::from_be_bytes([payload[0], payload[1]]);
    if packet_id == 0 {
        return false;
    }

    if mqtt_subscribe_topics_are_well_formed(payload, 2) {
        return true;
    }

    let mut pos = 2usize;
    let Some((properties_len, _consumed)) = mqtt_read_variable_int(payload, &mut pos) else {
        return false;
    };
    let Some(topics_start) = pos.checked_add(properties_len) else {
        return false;
    };
    if topics_start > payload.len() {
        return false;
    }

    topics_start <= payload.len()
        && mqtt_subscribe_properties_are_well_formed(&payload[pos..topics_start])
        && mqtt_subscribe_topics_are_well_formed(payload, topics_start)
}

fn mqtt_unsubscribe_is_well_formed(data: &[u8]) -> bool {
    if data[0] & 0x0f != 0x02 {
        return false;
    }

    let Some((remaining_len, start)) = mqtt_remaining_length(data) else {
        return false;
    };
    let Some(frame_end) = start.checked_add(remaining_len) else {
        return false;
    };
    if !mqtt_sample_tail_is_plausible(data, frame_end) {
        return false;
    }

    let payload = &data[start..frame_end];
    if payload.len() < 5 || u16::from_be_bytes([payload[0], payload[1]]) == 0 {
        return false;
    }

    if mqtt_unsubscribe_topics_are_well_formed(payload, 2) {
        return true;
    }

    let mut pos = 2usize;
    let Some((properties_len, _consumed)) = mqtt_read_variable_int(payload, &mut pos) else {
        return false;
    };
    let Some(topics_start) = pos.checked_add(properties_len) else {
        return false;
    };
    topics_start <= payload.len()
        && mqtt_user_properties_are_well_formed(&payload[pos..topics_start])
        && mqtt_unsubscribe_topics_are_well_formed(payload, topics_start)
}

fn mqtt_pubrel_is_well_formed(data: &[u8]) -> bool {
    if data[0] & 0x0f != 0x02 {
        return false;
    }

    let Some((remaining_len, start)) = mqtt_remaining_length(data) else {
        return false;
    };
    let Some(frame_end) = start.checked_add(remaining_len) else {
        return false;
    };
    if !mqtt_sample_tail_is_plausible(data, frame_end) {
        return false;
    }

    let payload = &data[start..frame_end];
    if payload.len() < 2 || u16::from_be_bytes([payload[0], payload[1]]) == 0 {
        return false;
    }
    if payload.len() == 2 {
        return true;
    }
    if !matches!(payload[2], 0x00 | 0x92) {
        return false;
    }
    if payload.len() == 3 {
        return true;
    }

    let mut pos = 3usize;
    let Some((properties_len, _consumed)) = mqtt_read_variable_int(payload, &mut pos) else {
        return false;
    };
    let Some(properties_end) = pos.checked_add(properties_len) else {
        return false;
    };
    properties_end == payload.len() && mqtt_pubrel_properties_are_well_formed(&payload[pos..])
}

fn mqtt_disconnect_is_well_formed(data: &[u8]) -> bool {
    if data[0] & 0x0f != 0 {
        return false;
    }

    let Some((remaining_len, start)) = mqtt_remaining_length(data) else {
        return false;
    };
    let Some(frame_end) = start.checked_add(remaining_len) else {
        return false;
    };
    if !mqtt_sample_tail_is_plausible(data, frame_end) {
        return false;
    }

    let payload = &data[start..frame_end];
    if payload.is_empty() {
        return true;
    }
    if !mqtt_disconnect_reason_code_is_valid(payload[0]) {
        return false;
    }
    if payload.len() == 1 {
        return true;
    }

    let mut pos = 1usize;
    let Some((properties_len, _consumed)) = mqtt_read_variable_int(payload, &mut pos) else {
        return false;
    };
    let Some(properties_end) = pos.checked_add(properties_len) else {
        return false;
    };
    properties_end == payload.len()
        && mqtt_disconnect_properties_are_well_formed(&payload[pos..properties_end])
}

fn mqtt_subscribe_topics_are_well_formed(payload: &[u8], mut pos: usize) -> bool {
    let mut topic_count = 0usize;
    while pos < payload.len() {
        let Some(topic_len_end) = pos.checked_add(2) else {
            return false;
        };
        if topic_len_end > payload.len() {
            return false;
        }
        let topic_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos = topic_len_end;
        if topic_len == 0 {
            return false;
        }
        let Some(topic_end) = pos.checked_add(topic_len) else {
            return false;
        };
        if topic_end >= payload.len() {
            return false;
        }
        let Ok(topic) = std::str::from_utf8(&payload[pos..topic_end]) else {
            return false;
        };
        if !mqtt_subscribe_topic_filter_is_valid(topic) {
            return false;
        }
        pos = topic_end;
        let subscription_options = payload[pos];
        if !mqtt_subscription_options_are_well_formed(subscription_options) {
            return false;
        }
        pos += 1;
        topic_count += 1;
    }

    topic_count > 0
}

fn mqtt_subscription_options_are_well_formed(options: u8) -> bool {
    options & 0xc0 == 0 && options & 0x03 != 3 && options & 0x30 != 0x30
}

fn mqtt_subscribe_properties_are_well_formed(properties: &[u8]) -> bool {
    let mut pos = 0usize;
    let mut saw_subscription_identifier = false;
    while pos < properties.len() {
        match properties[pos] {
            0x0b => {
                if saw_subscription_identifier {
                    return false;
                }
                pos += 1;
                let Some((subscription_identifier, _consumed)) =
                    mqtt_read_variable_int(properties, &mut pos)
                else {
                    return false;
                };
                if subscription_identifier == 0 {
                    return false;
                }
                saw_subscription_identifier = true;
            }
            0x26 => {
                pos += 1;
                if !mqtt_read_mqtt_utf8_string(properties, &mut pos)
                    || !mqtt_read_mqtt_utf8_string(properties, &mut pos)
                {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

fn mqtt_unsubscribe_topics_are_well_formed(payload: &[u8], mut pos: usize) -> bool {
    let mut topic_count = 0usize;
    while pos < payload.len() {
        let Some(topic_len_end) = pos.checked_add(2) else {
            return false;
        };
        if topic_len_end > payload.len() {
            return false;
        }
        let topic_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos = topic_len_end;
        if topic_len == 0 {
            return false;
        }
        let Some(topic_end) = pos.checked_add(topic_len) else {
            return false;
        };
        if topic_end > payload.len() {
            return false;
        }
        let Ok(topic) = std::str::from_utf8(&payload[pos..topic_end]) else {
            return false;
        };
        if !mqtt_subscribe_topic_filter_is_valid(topic) {
            return false;
        }
        pos = topic_end;
        topic_count += 1;
    }

    topic_count > 0
}

fn mqtt_user_properties_are_well_formed(properties: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos < properties.len() {
        if properties[pos] != 0x26 {
            return false;
        }
        pos += 1;
        if !mqtt_read_mqtt_utf8_string(properties, &mut pos)
            || !mqtt_read_mqtt_utf8_string(properties, &mut pos)
        {
            return false;
        }
    }
    true
}

fn mqtt_pubrel_properties_are_well_formed(properties: &[u8]) -> bool {
    let mut pos = 0usize;
    let mut saw_reason_string = false;
    while pos < properties.len() {
        match properties[pos] {
            0x1f => {
                if saw_reason_string {
                    return false;
                }
                pos += 1;
                if !mqtt_read_mqtt_utf8_string(properties, &mut pos) {
                    return false;
                }
                saw_reason_string = true;
            }
            0x26 => {
                pos += 1;
                if !mqtt_read_mqtt_utf8_string(properties, &mut pos)
                    || !mqtt_read_mqtt_utf8_string(properties, &mut pos)
                {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

fn mqtt_disconnect_properties_are_well_formed(properties: &[u8]) -> bool {
    let mut pos = 0usize;
    let mut saw_session_expiry = false;
    let mut saw_reason_string = false;
    let mut saw_server_reference = false;
    while pos < properties.len() {
        match properties[pos] {
            0x1f => {
                if saw_reason_string {
                    return false;
                }
                pos += 1;
                if !mqtt_read_mqtt_utf8_string(properties, &mut pos) {
                    return false;
                }
                saw_reason_string = true;
            }
            0x1c => {
                if saw_server_reference {
                    return false;
                }
                pos += 1;
                if !mqtt_read_mqtt_utf8_string(properties, &mut pos) {
                    return false;
                }
                saw_server_reference = true;
            }
            0x26 => {
                pos += 1;
                if !mqtt_read_mqtt_utf8_string(properties, &mut pos)
                    || !mqtt_read_mqtt_utf8_string(properties, &mut pos)
                {
                    return false;
                }
            }
            0x11 => {
                if saw_session_expiry {
                    return false;
                }
                pos += 1;
                let Some(next) = pos.checked_add(4) else {
                    return false;
                };
                if next > properties.len() {
                    return false;
                }
                pos = next;
                saw_session_expiry = true;
            }
            _ => return false,
        }
    }
    true
}

fn mqtt_disconnect_reason_code_is_valid(reason_code: u8) -> bool {
    matches!(
        reason_code,
        0x00 | 0x04
            | 0x80
            | 0x81
            | 0x82
            | 0x83
            | 0x87
            | 0x89
            | 0x8b
            | 0x8d
            | 0x8e
            | 0x8f
            | 0x90
            | 0x93
            | 0x94
            | 0x95
            | 0x96
            | 0x97
            | 0x98
            | 0x99
            | 0x9a
            | 0x9b
            | 0x9c
            | 0x9d
            | 0x9e
            | 0x9f
            | 0xa0
            | 0xa1
            | 0xa2
    )
}

fn mqtt_sample_tail_is_plausible(data: &[u8], frame_end: usize) -> bool {
    frame_end == data.len()
}

fn mqtt_publish_topic_is_valid(value: &str) -> bool {
    !value.is_empty() && mqtt_utf8_string_is_valid(value) && !value.contains(['+', '#'])
}

fn mqtt_subscribe_topic_filter_is_valid(value: &str) -> bool {
    if value.is_empty() || !mqtt_utf8_string_is_valid(value) {
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

fn mqtt_utf8_string_is_valid(value: &str) -> bool {
    value.chars().all(|ch| {
        !matches!(
            ch as u32,
            0x0000..=0x001f | 0x007f..=0x009f | 0xfdd0..=0xfdef | 0xfffe | 0xffff
        ) && (ch as u32 & 0xfffe) != 0xfffe
    })
}

pub(crate) fn mqtt_remaining_length_encoded_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 128 {
        value /= 128;
        len += 1;
    }
    len
}
