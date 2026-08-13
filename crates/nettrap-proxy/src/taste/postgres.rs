use super::*;

const POSTGRES_CANCEL_REQUEST: u32 = 80877102;
const POSTGRES_SSL_REQUEST: u32 = 80877103;
const POSTGRES_GSSENC_REQUEST: u32 = 80877104;
const POSTGRES_STARTUP_VERSION_3: u32 = 196608;

pub(crate) fn looks_like_postgres_startup_message(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if len > data.len() || len < 8 {
        return false;
    }

    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version == POSTGRES_SSL_REQUEST {
        return len == 8
            && (len == data.len() || looks_like_complete_tls_client_hello(&data[len..]));
    }
    if version == POSTGRES_GSSENC_REQUEST {
        return len == 8 && len == data.len();
    }
    if version != POSTGRES_STARTUP_VERSION_3 {
        return false;
    }
    if len != data.len() {
        return false;
    }

    postgres_startup_parameters_are_complete(&data[8..])
}

pub(crate) fn looks_like_postgres_cancel_request(data: &[u8]) -> bool {
    if data.len() != 16 {
        return false;
    }
    u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == 16
        && u32::from_be_bytes([data[4], data[5], data[6], data[7]]) == POSTGRES_CANCEL_REQUEST
}

pub(crate) fn looks_like_postgres_typed_message(data: &[u8]) -> bool {
    let Some(frame_end) = postgres_typed_message_end(data) else {
        return false;
    };
    frame_end == data.len()
}

fn postgres_typed_message_end(data: &[u8]) -> Option<usize> {
    if data.len() < 5 {
        return None;
    }
    let msg_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    let min_len = match data[0] {
        b'H' | b'S' | b'X' => 4,
        b'D' | b'C' => 6,
        b'E' => 9,
        b'P' | b'B' => 8,
        b'F' => 14,
        b'Q' => 5,
        _ => return None,
    };
    let frame_end = msg_len.checked_add(1)?;
    if msg_len < min_len || frame_end > data.len() {
        return None;
    }

    postgres_typed_message_body_is_valid(data[0], &data[5..frame_end]).then_some(frame_end)
}

fn postgres_typed_message_body_is_valid(tag: u8, body: &[u8]) -> bool {
    match tag {
        b'P' => postgres_parse_message_body_is_valid(body),
        b'B' => postgres_bind_message_body_is_valid(body),
        b'D' | b'C' => {
            matches!(body.first(), Some(b'S' | b'P'))
                && postgres_nul_terminated_field_is_valid(&body[1..])
        }
        b'E' => {
            let mut pos = 0usize;
            postgres_consume_nul_terminated_field(body, &mut pos)
                && pos.checked_add(4) == Some(body.len())
        }
        b'F' => postgres_function_call_body_is_valid(body),
        b'Q' => {
            body.last().copied() == Some(0)
                && std::str::from_utf8(&body[..body.len().saturating_sub(1)])
                    .is_ok_and(|query| !query.contains('\0'))
        }
        _ => true,
    }
}

fn postgres_bind_message_body_is_valid(body: &[u8]) -> bool {
    let mut pos = 0usize;
    postgres_consume_nul_terminated_field(body, &mut pos)
        && postgres_consume_nul_terminated_field(body, &mut pos)
        && postgres_consume_format_codes(body, &mut pos)
        && postgres_consume_parameter_values(body, &mut pos)
        && postgres_consume_format_codes(body, &mut pos)
        && pos == body.len()
}

fn postgres_function_call_body_is_valid(body: &[u8]) -> bool {
    let mut pos = 4usize;
    body.len() >= pos
        && postgres_consume_format_codes(body, &mut pos)
        && postgres_consume_parameter_values(body, &mut pos)
        && postgres_consume_format_codes(body, &mut pos)
        && pos == body.len()
}

fn postgres_parse_message_body_is_valid(body: &[u8]) -> bool {
    let mut pos = 0usize;
    if !postgres_consume_nul_terminated_field(body, &mut pos)
        || !postgres_consume_nul_terminated_field(body, &mut pos)
    {
        return false;
    }
    let Some(count_end) = pos.checked_add(2) else {
        return false;
    };
    let Some(count_bytes) = body.get(pos..count_end) else {
        return false;
    };
    let parameter_count = u16::from_be_bytes([count_bytes[0], count_bytes[1]]) as usize;
    pos = count_end;
    let Some(parameter_bytes) = parameter_count.checked_mul(4) else {
        return false;
    };
    pos.checked_add(parameter_bytes) == Some(body.len())
}

fn postgres_consume_format_codes(data: &[u8], pos: &mut usize) -> bool {
    let Some(count) = postgres_consume_u16(data, pos) else {
        return false;
    };
    let Some(bytes) = usize::from(count).checked_mul(2) else {
        return false;
    };
    let Some(end) = (*pos).checked_add(bytes) else {
        return false;
    };
    if end > data.len() {
        return false;
    }
    *pos = end;
    true
}

fn postgres_consume_parameter_values(data: &[u8], pos: &mut usize) -> bool {
    let Some(parameter_count) = postgres_consume_u16(data, pos) else {
        return false;
    };
    for _ in 0..parameter_count {
        let Some(length_end) = (*pos).checked_add(4) else {
            return false;
        };
        let Some(length_bytes) = data.get(*pos..length_end) else {
            return false;
        };
        let value_len = i32::from_be_bytes([
            length_bytes[0],
            length_bytes[1],
            length_bytes[2],
            length_bytes[3],
        ]);
        *pos = length_end;
        if value_len < -1 {
            return false;
        }
        if value_len >= 0 {
            let Some(value_end) = (*pos).checked_add(value_len as usize) else {
                return false;
            };
            if value_end > data.len() {
                return false;
            }
            *pos = value_end;
        }
    }
    true
}

fn postgres_consume_u16(data: &[u8], pos: &mut usize) -> Option<u16> {
    let end = pos.checked_add(2)?;
    let bytes = data.get(*pos..end)?;
    *pos = end;
    Some(u16::from_be_bytes(bytes.try_into().ok()?))
}

fn postgres_consume_nul_terminated_field(data: &[u8], pos: &mut usize) -> bool {
    let Some(rest) = data.get(*pos..) else {
        return false;
    };
    let Some(field_len) = rest.iter().position(|&byte| byte == 0) else {
        return false;
    };
    let Some(next_pos) = (*pos).checked_add(field_len + 1) else {
        return false;
    };
    *pos = next_pos;
    true
}

fn postgres_nul_terminated_field_is_valid(value: &[u8]) -> bool {
    value.last().copied() == Some(0) && !value[..value.len().saturating_sub(1)].contains(&0)
}

fn postgres_startup_parameters_are_complete(params: &[u8]) -> bool {
    if params.last().copied() != Some(0) {
        return false;
    }
    let final_terminator = params.len().saturating_sub(1);
    let mut pos = 0usize;
    while pos < final_terminator {
        let Some(name_len) = params[pos..final_terminator]
            .iter()
            .position(|&byte| byte == 0)
        else {
            return false;
        };
        if name_len == 0 {
            return false;
        }
        pos += name_len + 1;

        let Some(value_len) = params[pos..final_terminator]
            .iter()
            .position(|&byte| byte == 0)
        else {
            return false;
        };
        pos += value_len + 1;
    }
    pos == final_terminator
}
