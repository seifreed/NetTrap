/// Maximum allowed BER length (16MB) to prevent memory exhaustion attacks
const MAX_BER_LENGTH: usize = 16 * 1024 * 1024;
pub(crate) const MAX_LDAP_FILTER_DEPTH: usize = 32;

pub(crate) fn parse_message_id(data: &[u8]) -> Option<(u32, usize, usize)> {
    // Skip sequence tag + length
    if data.first().copied()? != 0x30 {
        return None;
    }
    let mut pos = 1;
    let (seq_len, len_bytes) = parse_ber_length(&data[pos..])?;
    pos += len_bytes;
    let seq_end = pos.checked_add(seq_len)?;
    if seq_end > data.len() {
        return None;
    }

    // Message ID: INTEGER tag (0x02) + length + value
    if pos >= seq_end || data[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let (id_len, len_bytes) = parse_ber_length(&data[pos..seq_end])?;
    pos += len_bytes;

    let id_end = pos.checked_add(id_len)?;
    if id_len == 0 || id_len > 4 || id_end > seq_end {
        return None;
    }

    let msg_id = parse_message_id_value(&data[pos..id_end])?;
    pos = id_end;

    Some((msg_id, pos, seq_end))
}

pub(crate) fn parse_message_id_value(value: &[u8]) -> Option<u32> {
    if value.is_empty() || value.len() > 4 {
        return None;
    }
    // LDAP MessageID is a non-negative BER INTEGER. If the high bit is set
    // without a leading zero octet, the value is negative.
    if value[0] & 0x80 != 0 {
        return None;
    }
    if value.len() > 1 && value[0] == 0x00 && value[1] & 0x80 == 0 {
        return None;
    }

    let mut msg_id = 0u32;
    for byte in value {
        msg_id = (msg_id << 8) | *byte as u32;
    }
    if msg_id == 0 || msg_id > i32::MAX as u32 {
        return None;
    }
    Some(msg_id)
}

pub(crate) fn parse_ber_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    if data[0] & 0x80 == 0 {
        // Short form: length in lower 7 bits
        Some((data[0] as usize, 1))
    } else {
        // Long form: lower 7 bits = number of following length bytes
        let num_bytes = (data[0] & 0x7F) as usize;
        // Ensure all length bytes are present and limit to reasonable size
        if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
            return None;
        }
        if num_bytes == 1 {
            if data[1] < 128 {
                return None;
            }
        } else if data[1] == 0 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[i + 1] as usize;
        }
        if len > MAX_BER_LENGTH {
            return None;
        }
        Some((len, 1 + num_bytes))
    }
}

pub(crate) fn operation_end(data: &[u8], op_offset: usize, seq_end: usize) -> Option<usize> {
    let mut pos = op_offset.checked_add(1)?;
    if pos > seq_end {
        return None;
    }
    let (op_len, len_bytes) = parse_ber_length(&data[pos..seq_end])?;
    pos += len_bytes;
    let op_end = pos.checked_add(op_len)?;
    if op_end > seq_end {
        return None;
    }
    Some(op_end)
}

pub(crate) fn message_tail_is_valid(data: &[u8], tail_start: usize, seq_end: usize) -> bool {
    if tail_start == seq_end {
        return true;
    }
    if tail_start >= seq_end || data[tail_start] != 0xa0 {
        return false;
    }

    let Some(mut pos) = tail_start.checked_add(1) else {
        return false;
    };
    let Some((controls_len, len_bytes)) = parse_ber_length(&data[pos..seq_end]) else {
        return false;
    };
    pos += len_bytes;
    let Some(controls_end) = pos.checked_add(controls_len) else {
        return false;
    };
    controls_end == seq_end && controls_are_well_formed(&data[pos..controls_end])
}

pub(crate) fn extract_bind_dn(data: &[u8], op_offset: usize, op_end: usize) -> Option<String> {
    let mut pos = op_offset.checked_add(1)?; // Skip tag
    if pos >= op_end {
        return None;
    }
    let (_, len_bytes) = parse_ber_length(&data[pos..op_end])?;
    pos += len_bytes;
    if pos >= op_end || data[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let (ver_len, len_bytes) = parse_ber_length(&data[pos..op_end])?;
    let advance = len_bytes.saturating_add(ver_len);
    let version_end = pos.checked_add(advance)?;
    if version_end > op_end {
        return None;
    }
    pos = version_end;
    if pos >= op_end || data[pos] != 0x04 {
        return None;
    }
    pos += 1;
    let (dn_len, len_bytes) = parse_ber_length(&data[pos..op_end])?;
    pos += len_bytes;
    let dn_end = pos.checked_add(dn_len)?;
    if dn_end > op_end {
        return None;
    }
    Some(nettrap_core::sanitize::single_line_bytes(
        &data[pos..dn_end],
    ))
}

pub(crate) fn bind_request_is_well_formed(data: &[u8], op_offset: usize, op_end: usize) -> bool {
    let Some(mut pos) = op_offset.checked_add(1) else {
        return false;
    };
    if pos >= op_end {
        return false;
    }
    let Some((_, len_bytes)) = parse_ber_length(&data[pos..op_end]) else {
        return false;
    };
    pos += len_bytes;

    let Some(version) = consume_expected_tlv_value(data, &mut pos, op_end, 0x02) else {
        return false;
    };
    if !is_canonical_non_negative_integer(version) {
        return false;
    }
    if consume_expected_tlv(data, &mut pos, op_end, 0x04).is_none() {
        return false;
    }

    let Some(tag) = data.get(pos).copied() else {
        return false;
    };
    if !matches!(tag, 0x80 | 0xa3) {
        return false;
    }
    pos += 1;
    let Some((auth_len, len_bytes)) = parse_ber_length(&data[pos..op_end]) else {
        return false;
    };
    pos += len_bytes;
    let Some(auth_end) = pos.checked_add(auth_len) else {
        return false;
    };
    if auth_end != op_end {
        return false;
    }
    if tag == 0xa3 {
        return sasl_auth_choice_is_well_formed(&data[pos..auth_end]);
    }
    true
}

fn sasl_auth_choice_is_well_formed(value: &[u8]) -> bool {
    let mut pos = 0usize;
    let Some(mechanism) = consume_expected_tlv_value(value, &mut pos, value.len(), 0x04) else {
        return false;
    };
    if mechanism.is_empty() || std::str::from_utf8(mechanism).is_err() {
        return false;
    }
    if pos == value.len() {
        return true;
    }
    consume_expected_tlv(value, &mut pos, value.len(), 0x04).is_some() && pos == value.len()
}

pub(crate) fn search_request_is_well_formed(data: &[u8], op_offset: usize, op_end: usize) -> bool {
    let Some(mut pos) = op_offset.checked_add(1) else {
        return false;
    };
    if pos >= op_end {
        return false;
    }
    let Some((_, len_bytes)) = parse_ber_length(&data[pos..op_end]) else {
        return false;
    };
    pos += len_bytes;

    if consume_expected_tlv(data, &mut pos, op_end, 0x04).is_none()
        || !consume_enumerated_in_range(data, &mut pos, op_end, 0..=2)
        || !consume_enumerated_in_range(data, &mut pos, op_end, 0..=3)
        || !consume_canonical_integer(data, &mut pos, op_end)
        || !consume_canonical_integer(data, &mut pos, op_end)
        || !consume_boolean(data, &mut pos, op_end)
    {
        return false;
    }
    let Some((filter_tag, filter_value)) = consume_any_tlv(data, &mut pos, op_end) else {
        return false;
    };
    if !filter_is_well_formed(filter_tag, filter_value, 0) {
        return false;
    }
    if consume_expected_tlv(data, &mut pos, op_end, 0x30).is_none() {
        return false;
    }

    pos == op_end
}

fn consume_any_tlv<'a>(data: &'a [u8], pos: &mut usize, limit: usize) -> Option<(u8, &'a [u8])> {
    let tag = *data.get(*pos)?;
    *pos += 1;
    let (len, len_bytes) = parse_ber_length(&data[*pos..limit])?;
    *pos += len_bytes;
    let end = (*pos).checked_add(len)?;
    if end > limit {
        return None;
    }
    let value = data.get(*pos..end)?;
    *pos = end;
    Some((tag, value))
}

fn filter_is_well_formed(tag: u8, value: &[u8], depth: usize) -> bool {
    if depth > MAX_LDAP_FILTER_DEPTH {
        return false;
    }

    match tag {
        0xa0 | 0xa1 => {
            if value.is_empty() {
                return false;
            }
            let mut pos = 0usize;
            let mut saw_child = false;
            while pos < value.len() {
                let Some((child_tag, child_value)) = consume_any_tlv(value, &mut pos, value.len())
                else {
                    return false;
                };
                if !filter_is_well_formed(child_tag, child_value, depth + 1) {
                    return false;
                }
                saw_child = true;
            }
            saw_child
        }
        0xa2 => {
            let mut pos = 0usize;
            let Some((child_tag, child_value)) = consume_any_tlv(value, &mut pos, value.len())
            else {
                return false;
            };
            pos == value.len() && filter_is_well_formed(child_tag, child_value, depth + 1)
        }
        0x87 => !value.is_empty(),
        0xa8 => approx_match_filter_is_well_formed(value),
        0xa3 | 0xa5 | 0xa6 => attribute_value_assertion_filter_is_well_formed(value),
        0xa4 => substring_filter_is_well_formed(value),
        0xa9 => !value.is_empty(),
        _ => false,
    }
}

fn attribute_value_assertion_filter_is_well_formed(value: &[u8]) -> bool {
    let mut pos = 0usize;
    let Some((seq_tag, seq_value)) = consume_any_tlv(value, &mut pos, value.len()) else {
        return false;
    };
    if seq_tag != 0x30 || pos != value.len() {
        return false;
    }
    let mut seq_pos = 0usize;
    consume_expected_tlv(seq_value, &mut seq_pos, seq_value.len(), 0x04).is_some()
        && consume_expected_tlv(seq_value, &mut seq_pos, seq_value.len(), 0x04).is_some()
        && seq_pos == seq_value.len()
}

fn approx_match_filter_is_well_formed(value: &[u8]) -> bool {
    attribute_value_assertion_filter_is_well_formed(value)
}

fn substring_filter_is_well_formed(value: &[u8]) -> bool {
    let mut pos = 0usize;
    let Some((seq_tag, seq_value)) = consume_any_tlv(value, &mut pos, value.len()) else {
        return false;
    };
    if seq_tag != 0x30 || pos != value.len() {
        return false;
    }
    let mut seq_pos = 0usize;
    if consume_expected_tlv(seq_value, &mut seq_pos, seq_value.len(), 0x04).is_none() {
        return false;
    }
    let mut saw_substring = false;
    while seq_pos < seq_value.len() {
        let Some(tag) = seq_value.get(seq_pos).copied() else {
            return false;
        };
        if !matches!(tag, 0x80..=0x82) {
            return false;
        }
        if consume_expected_tlv(seq_value, &mut seq_pos, seq_value.len(), tag).is_none() {
            return false;
        }
        saw_substring = true;
    }
    saw_substring
}

fn controls_are_well_formed(data: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos < data.len() {
        if data[pos] != 0x30 {
            return false;
        }
        pos += 1;
        let Some((len, len_bytes)) = parse_ber_length(&data[pos..]) else {
            return false;
        };
        pos += len_bytes;
        let Some(end) = pos.checked_add(len) else {
            return false;
        };
        if end > data.len() || !control_is_well_formed(&data[pos..end]) {
            return false;
        }
        pos = end;
    }
    true
}

fn control_is_well_formed(data: &[u8]) -> bool {
    let mut pos = 0usize;
    let Some(control_type) = consume_expected_tlv_value(data, &mut pos, data.len(), 0x04) else {
        return false;
    };
    if control_type.is_empty() {
        return false;
    }
    if pos == data.len() {
        return true;
    }
    if data[pos] == 0x01 {
        let Some(criticality) = consume_expected_tlv_value(data, &mut pos, data.len(), 0x01) else {
            return false;
        };
        if criticality.len() != 1 {
            return false;
        }
        if pos == data.len() {
            return true;
        }
    }
    data[pos] == 0x04
        && consume_expected_tlv(data, &mut pos, data.len(), 0x04).is_some()
        && pos == data.len()
}

fn consume_enumerated_in_range(
    data: &[u8],
    pos: &mut usize,
    limit: usize,
    range: std::ops::RangeInclusive<u32>,
) -> bool {
    let Some(value) = consume_expected_tlv_value(data, pos, limit, 0x0a) else {
        return false;
    };
    let Some(value) = parse_canonical_non_negative_integer(value) else {
        return false;
    };
    range.contains(&value)
}

fn consume_canonical_integer(data: &[u8], pos: &mut usize, limit: usize) -> bool {
    let Some(value) = consume_expected_tlv_value(data, pos, limit, 0x02) else {
        return false;
    };
    is_canonical_non_negative_integer(value)
}

fn consume_boolean(data: &[u8], pos: &mut usize, limit: usize) -> bool {
    let Some(value) = consume_expected_tlv_value(data, pos, limit, 0x01) else {
        return false;
    };
    value.len() == 1
}

fn parse_canonical_non_negative_integer(value: &[u8]) -> Option<u32> {
    if !is_canonical_non_negative_integer(value) {
        return None;
    }
    let mut parsed = 0u32;
    for byte in value {
        parsed = (parsed << 8) | u32::from(*byte);
    }
    Some(parsed)
}

fn is_canonical_non_negative_integer(value: &[u8]) -> bool {
    if value.is_empty() || value.len() > 4 || value[0] & 0x80 != 0 {
        return false;
    }
    !(value.len() > 1 && value[0] == 0x00 && value[1] & 0x80 == 0)
}

fn consume_expected_tlv_value<'a>(
    data: &'a [u8],
    pos: &mut usize,
    limit: usize,
    expected_tag: u8,
) -> Option<&'a [u8]> {
    if *pos >= limit || data[*pos] != expected_tag {
        return None;
    }
    *pos += 1;
    let (len, len_bytes) = parse_ber_length(&data[*pos..limit])?;
    *pos += len_bytes;
    let end = (*pos).checked_add(len)?;
    if end > limit {
        return None;
    }
    let value = data.get(*pos..end)?;
    *pos = end;
    Some(value)
}

fn consume_expected_tlv(
    data: &[u8],
    pos: &mut usize,
    limit: usize,
    expected_tag: u8,
) -> Option<usize> {
    if *pos >= limit || data[*pos] != expected_tag {
        return None;
    }
    *pos += 1;
    let (len, len_bytes) = parse_ber_length(&data[*pos..limit])?;
    *pos += len_bytes;
    let end = (*pos).checked_add(len)?;
    if end > limit {
        return None;
    }
    *pos = end;
    Some(len)
}

pub(crate) fn encode_ber_length(buf: &mut Vec<u8>, len: usize) -> bool {
    if let Ok(short) = u8::try_from(len) {
        if short < 128 {
            buf.push(short);
        } else {
            buf.extend_from_slice(&[0x81, short]);
        }
    } else if let Ok(two) = u16::try_from(len) {
        buf.push(0x82);
        buf.extend_from_slice(&two.to_be_bytes());
    } else if len < 0x100_0000 {
        let Ok(four) = u32::try_from(len) else {
            return false;
        };
        let four = four.to_be_bytes();
        buf.push(0x83);
        buf.extend_from_slice(&four[1..]);
    } else if let Ok(four) = u32::try_from(len) {
        buf.push(0x84);
        buf.extend_from_slice(&four.to_be_bytes());
    } else {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{
        bind_request_is_well_formed, encode_ber_length, extract_bind_dn, operation_end,
        parse_ber_length, parse_message_id, search_request_is_well_formed,
    };

    #[test]
    fn parse_ber_length_rejects_non_minimal_long_form_encoding() {
        assert!(parse_ber_length(&[0x81, 0x7f]).is_none());
        assert!(parse_ber_length(&[0x82, 0x00, 0x80]).is_none());
        assert!(parse_ber_length(&[0x82, 0x01, 0x00]).is_some());
    }

    #[test]
    fn parse_message_id_rejects_non_sequence_tag() {
        let data = [0x31, 0x03, 0x02, 0x01, 0x01];

        assert!(parse_message_id(&data).is_none());
    }

    #[test]
    fn encode_ber_length_supports_three_and_four_byte_forms() {
        let mut encoded = Vec::new();
        assert!(encode_ber_length(&mut encoded, 0x1_0000));
        assert_eq!(encoded, vec![0x83, 0x01, 0x00, 0x00]);

        let mut encoded = Vec::new();
        assert!(encode_ber_length(&mut encoded, 0x0102_0304));
        assert_eq!(encoded, vec![0x84, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn encode_ber_length_rejects_values_that_do_not_fit_four_bytes() {
        let mut encoded = Vec::new();

        assert!(!encode_ber_length(&mut encoded, usize::MAX));
        assert!(encoded.is_empty());
    }

    #[test]
    fn ldap_helpers_reject_overflowing_operation_offsets() {
        let data = [0x60, 0x00];

        assert_eq!(operation_end(&data, usize::MAX, usize::MAX), None);
        assert_eq!(extract_bind_dn(&data, usize::MAX, usize::MAX), None);
        assert!(!bind_request_is_well_formed(&data, usize::MAX, usize::MAX));
        assert!(!search_request_is_well_formed(
            &data,
            usize::MAX,
            usize::MAX
        ));
    }
}
