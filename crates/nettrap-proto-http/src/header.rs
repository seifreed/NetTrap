pub(crate) fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_token_char)
}

pub(crate) fn is_valid_header_value(value: &str) -> bool {
    value.chars().all(is_valid_header_value_char)
}

pub(crate) fn is_valid_reason_phrase(reason: &str) -> bool {
    !reason.is_empty()
        && is_valid_header_value(reason)
        && !reason.chars().next().is_some_and(char::is_whitespace)
        && !reason.chars().last().is_some_and(char::is_whitespace)
}

pub(crate) fn header_value_to_bytes(value: &str) -> Option<Vec<u8>> {
    if !is_valid_header_value(value) {
        return None;
    }

    value
        .chars()
        .map(|ch| u8::try_from(u32::from(ch)).ok())
        .collect()
}

fn is_valid_header_value_char(ch: char) -> bool {
    matches!(ch, ' ' | '\t')
        || matches!(ch as u32, 0x80..=0xff)
        || ((ch as u32) < 0x80 && !ch.is_control() && !ch.is_whitespace())
}

fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(test)]
mod tests {
    #[test]
    fn is_valid_reason_phrase_rejects_leading_whitespace() {
        assert!(!super::is_valid_reason_phrase(" Not Found"));
    }

    #[test]
    fn is_valid_header_value_rejects_unicode_whitespace() {
        assert!(!super::is_valid_header_value("ok\u{2028}value"));
    }

    #[test]
    fn header_value_to_bytes_rejects_non_latin1_values() {
        assert_eq!(super::header_value_to_bytes("ok\u{0100}value"), None);
    }
}
