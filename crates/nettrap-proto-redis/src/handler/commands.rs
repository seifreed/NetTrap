//! Stateless RESP parsing and Redis response-builder helpers.

use super::LOG_ARGS_PREVIEW_CHARS;

pub(crate) fn parse_resp_array_count(text: &str) -> Option<usize> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

pub(crate) fn parse_resp_bulk_len(text: &str) -> Option<Option<usize>> {
    if text == "-1" {
        return Some(None);
    }
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok().map(Some)
}

pub(crate) fn syntax_error() -> String {
    "-ERR syntax error\r\n".to_string()
}

pub(crate) fn wrong_number_of_arguments(command: &str) -> String {
    format!(
        "-ERR wrong number of arguments for '{}' command\r\n",
        command
    )
}

pub(crate) fn safe_log_args(args: &[&str]) -> String {
    let mut output = String::new();
    let mut emitted = 0usize;

    for (index, arg) in args.iter().enumerate() {
        if index > 0 {
            for ch in ", ".chars() {
                if emitted >= LOG_ARGS_PREVIEW_CHARS {
                    return output;
                }
                output.push(ch);
                emitted += 1;
            }
        }

        for ch in arg.chars().map(|ch| {
            if ch.is_control() || (ch.is_whitespace() && ch != ' ') {
                ' '
            } else {
                ch
            }
        }) {
            if emitted >= LOG_ARGS_PREVIEW_CHARS {
                return output;
            }
            output.push(ch);
            emitted += 1;
        }
    }

    output
}

pub(crate) fn find_crlf_from(haystack: &[u8], start: usize) -> Option<usize> {
    haystack
        .get(start..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
}
