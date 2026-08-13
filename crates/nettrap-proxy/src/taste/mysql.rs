use super::*;

pub(crate) fn looks_like_mysql_client_packet(data: &[u8]) -> bool {
    let Some(frame_end) = mysql_client_packet_end(data) else {
        return false;
    };
    let packet = &data[..frame_end];

    if mysql_ssl_request_is_well_formed(packet) {
        return mysql_ssl_request_tail_is_plausible(data, frame_end);
    }

    mysql_client_packet_is_well_formed(packet) && frame_end == data.len()
}
fn mysql_client_packet_is_well_formed(packet: &[u8]) -> bool {
    let payload = &packet[4..];
    match payload.first().copied() {
        Some(0x01) => payload.len() == 1,
        Some(0x02) => mysql_init_db_is_well_formed(payload),
        Some(0x03) => mysql_query_is_well_formed(payload),
        Some(0x04) => mysql_field_list_is_well_formed(payload),
        Some(0x0e) => payload.len() == 1,
        _ => {
            packet[3] == 1
                && (mysql_handshake_response_41_is_well_formed(payload)
                    || mysql_handshake_response_320_is_well_formed(payload))
        }
    }
}

fn mysql_client_packet_end(data: &[u8]) -> Option<usize> {
    if data.len() < 5 {
        return None;
    }
    let declared_len = (data[0] as usize) | ((data[1] as usize) << 8) | ((data[2] as usize) << 16);
    4usize
        .checked_add(declared_len)
        .filter(|frame_end| *frame_end <= data.len())
}

fn mysql_ssl_request_tail_is_plausible(data: &[u8], frame_end: usize) -> bool {
    if frame_end > data.len() {
        return false;
    }
    if frame_end == data.len() {
        return true;
    }
    let tail = &data[frame_end..];
    looks_like_complete_tls_client_hello(tail) || looks_like_mysql_client_packet(tail)
}

fn mysql_handshake_response_41_is_well_formed(payload: &[u8]) -> bool {
    if payload.len() < 33 || payload[9..32].iter().any(|byte| *byte != 0) {
        return false;
    }

    let cap_flags = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if cap_flags & MYSQL_CLIENT_PROTOCOL_41 == 0 {
        return false;
    }

    let Some(username_end) = payload[32..].iter().position(|&byte| byte == 0) else {
        return false;
    };
    let mut tail = &payload[32 + username_end + 1..];
    tail = if cap_flags & MYSQL_CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
        let Some((auth_len, len_bytes)) = mysql_lenenc_int(tail) else {
            return false;
        };
        let Some(auth_end) = len_bytes.checked_add(auth_len) else {
            return false;
        };
        let Some(rest) = tail.get(auth_end..) else {
            return false;
        };
        rest
    } else if cap_flags & MYSQL_CLIENT_SECURE_CONNECTION != 0 {
        let Some((&auth_len, rest)) = tail.split_first() else {
            return false;
        };
        let auth_len = auth_len as usize;
        let Some(rest) = rest.get(auth_len..) else {
            return false;
        };
        rest
    } else {
        let Some(auth_end) = tail.iter().position(|&byte| byte == 0) else {
            return false;
        };
        &tail[auth_end + 1..]
    };

    if cap_flags & MYSQL_CLIENT_CONNECT_WITH_DB != 0 {
        let Some(db_end) = tail.iter().position(|&byte| byte == 0) else {
            return false;
        };
        tail = &tail[db_end + 1..];
    }

    if cap_flags & MYSQL_CLIENT_PLUGIN_AUTH != 0 {
        let Some(plugin_end) = tail.iter().position(|&byte| byte == 0) else {
            return false;
        };
        let plugin = &tail[..plugin_end];
        if plugin.is_empty()
            || plugin.len() > 128
            || !plugin
                .iter()
                .all(|byte| byte.is_ascii_graphic() && *byte != b'\\')
        {
            return false;
        }
        tail = &tail[plugin_end + 1..];
    }

    if cap_flags & MYSQL_CLIENT_CONNECT_ATTRS != 0 {
        let Some((attrs_len, len_bytes)) = mysql_lenenc_int(tail) else {
            return false;
        };
        let Some(attrs_end) = len_bytes.checked_add(attrs_len) else {
            return false;
        };
        let Some(attrs) = tail.get(len_bytes..attrs_end) else {
            return false;
        };
        if !mysql_connect_attrs_are_well_formed(attrs) {
            return false;
        }
        tail = &tail[attrs_end..];
    }

    tail.is_empty()
}

fn mysql_handshake_response_320_is_well_formed(payload: &[u8]) -> bool {
    if payload.len() <= 5 {
        return false;
    }
    let Some(username_end) = payload[5..].iter().position(|&byte| byte == 0) else {
        return false;
    };
    payload.len() == 5 + username_end + 1
}

fn mysql_lenenc_int(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    match first {
        0x00..=0xfa => Some((first as usize, 1)),
        0xfc => {
            let bytes = data.get(1..3)?;
            let value = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
            (value >= 251).then_some((value, 3))
        }
        0xfd => {
            let bytes = data.get(1..4)?;
            let value = usize::from(bytes[0])
                | (usize::from(bytes[1]) << 8)
                | (usize::from(bytes[2]) << 16);
            (value >= 0x1_0000).then_some((value, 4))
        }
        0xfe => {
            let bytes = data.get(1..9)?;
            let value = u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            let value = usize::try_from(value).ok()?;
            (value >= 0x100_0000).then_some((value, 9))
        }
        _ => None,
    }
}

fn mysql_connect_attrs_are_well_formed(attrs: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos < attrs.len() {
        let Some((key_len, key_len_bytes)) = mysql_lenenc_int(&attrs[pos..]) else {
            return false;
        };
        pos += key_len_bytes;
        let Some(key_end) = pos.checked_add(key_len) else {
            return false;
        };
        let Some(key) = attrs.get(pos..key_end) else {
            return false;
        };
        if key.is_empty() || !mysql_token_is_safe(key) {
            return false;
        }
        pos += key_len;

        let Some((value_len, value_len_bytes)) = mysql_lenenc_int(&attrs[pos..]) else {
            return false;
        };
        pos += value_len_bytes;
        let Some(value_end) = pos.checked_add(value_len) else {
            return false;
        };
        let Some(value) = attrs.get(pos..value_end) else {
            return false;
        };
        if !mysql_token_is_safe(value) {
            return false;
        }
        pos += value_len;
    }
    true
}

fn mysql_query_is_well_formed(payload: &[u8]) -> bool {
    if payload.len() <= 1 {
        return false;
    }
    std::str::from_utf8(&payload[1..]).is_ok_and(|query| !query.contains('\0'))
}

fn mysql_init_db_is_well_formed(payload: &[u8]) -> bool {
    if payload.len() <= 1 {
        return false;
    }
    std::str::from_utf8(&payload[1..]).is_ok_and(|db| {
        !db.is_empty()
            && !db
                .chars()
                .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
    })
}

fn mysql_field_list_is_well_formed(payload: &[u8]) -> bool {
    let Some(table_end) = payload[1..].iter().position(|&byte| byte == 0) else {
        return false;
    };
    if table_end == 0 {
        return false;
    }
    let table = &payload[1..1 + table_end];
    let wildcard = &payload[1 + table_end + 1..];
    mysql_token_is_safe(table) && mysql_token_is_safe(wildcard)
}

fn mysql_token_is_safe(value: &[u8]) -> bool {
    match std::str::from_utf8(value) {
        Ok(text) => text
            .chars()
            .all(|ch| !ch.is_control() && (!ch.is_whitespace() || ch == ' ')),
        Err(_) => value.iter().all(|byte| {
            !byte.is_ascii_control()
                && *byte != b'\n'
                && *byte != b'\r'
                && *byte != b'\t'
                && *byte != 0x0b
                && *byte != 0x0c
        }),
    }
}
