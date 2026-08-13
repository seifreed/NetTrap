use super::*;

pub(super) fn sorted_set_card_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 1 {
        return wrong_number_of_arguments("zcard").into_bytes();
    }
    b":0\r\n".to_vec()
}

pub(super) fn sorted_set_count_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 3 {
        return wrong_number_of_arguments("zcount").into_bytes();
    }
    if parse_float_decimal_bytes(&args[1]).is_none()
        || parse_float_decimal_bytes(&args[2]).is_none()
    {
        return b"-ERR value is not a valid float\r\n".to_vec();
    }
    b":0\r\n".to_vec()
}

pub(super) fn sorted_set_incr_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 3 {
        return wrong_number_of_arguments("zincrby").into_bytes();
    }
    if parse_float_decimal_bytes(&args[1]).is_none() {
        return b"-ERR value is not a valid float\r\n".to_vec();
    }
    let mut response = Vec::with_capacity(args[1].len() + 8);
    response.extend_from_slice(b"$");
    response.extend_from_slice(args[1].len().to_string().as_bytes());
    response.extend_from_slice(b"\r\n");
    response.extend_from_slice(&args[1]);
    response.extend_from_slice(b"\r\n");
    response
}

pub(super) fn sorted_set_diff_store_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() < 4 {
        return wrong_number_of_arguments("zdiffstore").into_bytes();
    }
    let Some(numkeys) = parse_unsigned_decimal_bytes::<usize>(&args[1]) else {
        return b"-ERR value is not an integer or out of range\r\n".to_vec();
    };
    let Some(expected_len) = numkeys.checked_add(2) else {
        return wrong_number_of_arguments("zdiffstore").into_bytes();
    };
    if numkeys == 0 || args.len() != expected_len {
        return wrong_number_of_arguments("zdiffstore").into_bytes();
    }
    b":0\r\n".to_vec()
}

pub(super) fn sorted_set_inter_store_response(args: &[Vec<u8>]) -> Vec<u8> {
    sorted_set_store_with_options_response(args, "zinterstore")
}

pub(super) fn sorted_set_union_store_response(args: &[Vec<u8>]) -> Vec<u8> {
    sorted_set_store_with_options_response(args, "zunionstore")
}

fn sorted_set_store_with_options_response(args: &[Vec<u8>], command: &str) -> Vec<u8> {
    if args.len() < 4 {
        return wrong_number_of_arguments(command).into_bytes();
    }
    let Some(numkeys) = parse_unsigned_decimal_bytes::<usize>(&args[1]) else {
        return b"-ERR value is not an integer or out of range\r\n".to_vec();
    };
    let Some(first_option_index) = numkeys.checked_add(2) else {
        return wrong_number_of_arguments(command).into_bytes();
    };
    if numkeys == 0 || args.len() < first_option_index {
        return wrong_number_of_arguments(command).into_bytes();
    }

    let mut index = first_option_index;
    let mut saw_weights = false;
    let mut saw_aggregate = false;
    while index < args.len() {
        let Some(option) = text_command(&args[index]).map(|value| value.to_ascii_uppercase())
        else {
            return protocol_error();
        };
        match option.as_str() {
            "WEIGHTS" => {
                if saw_weights || saw_aggregate {
                    return syntax_error().into_bytes();
                }
                saw_weights = true;
                index += 1;
                let weights_end = index + numkeys;
                if weights_end > args.len() {
                    return syntax_error().into_bytes();
                }
                if args[index..weights_end]
                    .iter()
                    .any(|weight| parse_float_decimal_bytes(weight).is_none())
                {
                    return b"-ERR value is not a valid float\r\n".to_vec();
                }
                index = weights_end;
            }
            "AGGREGATE" => {
                if saw_aggregate {
                    return syntax_error().into_bytes();
                }
                saw_aggregate = true;
                index += 1;
                let Some(aggregate) = args.get(index) else {
                    return syntax_error().into_bytes();
                };
                if !matches!(
                    aggregate.as_slice(),
                    b"SUM" | b"sum" | b"MIN" | b"min" | b"MAX" | b"max"
                ) {
                    return syntax_error().into_bytes();
                }
                index += 1;
            }
            _ => return syntax_error().into_bytes(),
        }
    }

    b":0\r\n".to_vec()
}

pub(super) fn sorted_set_add_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() < 3 {
        return wrong_number_of_arguments("zadd").into_bytes();
    }

    let mut index = 1usize;
    let mut seen_nx = false;
    let mut seen_xx = false;
    let mut seen_gt = false;
    let mut seen_lt = false;
    let mut seen_ch = false;
    let mut seen_incr = false;

    while index < args.len() {
        let Some(option) = text_command(&args[index]).map(|value| value.to_ascii_uppercase())
        else {
            break;
        };
        match option.as_str() {
            "NX" => {
                if seen_nx || seen_xx {
                    return b"-ERR syntax error\r\n".to_vec();
                }
                seen_nx = true;
                index += 1;
            }
            "XX" => {
                if seen_nx || seen_xx {
                    return b"-ERR syntax error\r\n".to_vec();
                }
                seen_xx = true;
                index += 1;
            }
            "GT" => {
                if seen_gt || seen_lt {
                    return b"-ERR syntax error\r\n".to_vec();
                }
                seen_gt = true;
                index += 1;
            }
            "LT" => {
                if seen_gt || seen_lt {
                    return b"-ERR syntax error\r\n".to_vec();
                }
                seen_lt = true;
                index += 1;
            }
            "CH" => {
                if seen_ch {
                    return b"-ERR syntax error\r\n".to_vec();
                }
                seen_ch = true;
                index += 1;
            }
            "INCR" => {
                if seen_incr {
                    return b"-ERR syntax error\r\n".to_vec();
                }
                seen_incr = true;
                index += 1;
            }
            _ => break,
        }
    }

    let remaining = args.len().saturating_sub(index);
    if seen_incr {
        if remaining != 2 {
            return wrong_number_of_arguments("zadd").into_bytes();
        }
        if parse_float_decimal_bytes(&args[index]).is_none() {
            return b"-ERR value is not a valid float\r\n".to_vec();
        }
        let mut response = Vec::with_capacity(args[index].len() + 8);
        response.extend_from_slice(b"$");
        response.extend_from_slice(args[index].len().to_string().as_bytes());
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(&args[index]);
        response.extend_from_slice(b"\r\n");
        return response;
    }

    if remaining < 2 || !remaining.is_multiple_of(2) {
        if let Some(last) = args.last()
            && text_command(last).is_some_and(|value| {
                matches!(
                    value.to_ascii_uppercase().as_str(),
                    "NX" | "XX" | "GT" | "LT" | "CH" | "INCR"
                )
            })
        {
            return b"-ERR syntax error\r\n".to_vec();
        }
        return wrong_number_of_arguments("zadd").into_bytes();
    }

    if args[index..].chunks_exact(2).skip(1).any(|chunk| {
        text_command(&chunk[0])
            .map(|value| {
                matches!(
                    value.to_ascii_uppercase().as_str(),
                    "NX" | "XX" | "GT" | "LT" | "CH" | "INCR"
                )
            })
            .unwrap_or(false)
    }) {
        return b"-ERR syntax error\r\n".to_vec();
    }

    for score in args[index..].chunks_exact(2).map(|chunk| &chunk[0]) {
        if parse_float_decimal_bytes(score).is_none() {
            return b"-ERR value is not a valid float\r\n".to_vec();
        }
    }

    let pair_count = remaining / 2;
    format!(":{}\r\n", pair_count).into_bytes()
}

pub(super) fn sorted_set_range_response(args: &[Vec<u8>], command: &str) -> Vec<u8> {
    match command {
        "zrange" => {
            if args.len() < 3 {
                return wrong_number_of_arguments(command).into_bytes();
            }
            let mut index = 3usize;
            let mut saw_byscore = false;
            let mut saw_bylex = false;
            let mut saw_rev = false;
            let mut saw_limit = false;
            let mut saw_withscores = false;
            let mut phase = 0usize;

            while index < args.len() {
                let Some(option) =
                    text_command(&args[index]).map(|value| value.to_ascii_uppercase())
                else {
                    return protocol_error();
                };
                match option.as_str() {
                    "BYSCORE" => {
                        if phase != 0 || saw_byscore || saw_bylex {
                            return syntax_error().into_bytes();
                        }
                        saw_byscore = true;
                        phase = 1;
                        index += 1;
                    }
                    "BYLEX" => {
                        if phase != 0 || saw_byscore || saw_bylex {
                            return syntax_error().into_bytes();
                        }
                        saw_bylex = true;
                        phase = 1;
                        index += 1;
                    }
                    "REV" => {
                        if phase > 1 || saw_rev {
                            return syntax_error().into_bytes();
                        }
                        saw_rev = true;
                        phase = 2;
                        index += 1;
                    }
                    "LIMIT" => {
                        if phase > 2 || saw_limit {
                            return syntax_error().into_bytes();
                        }
                        if index + 2 >= args.len() {
                            return syntax_error().into_bytes();
                        }
                        if parse_unsigned_decimal_bytes::<u64>(&args[index + 1]).is_none()
                            || parse_signed_decimal_bytes::<i64>(&args[index + 2]).is_none()
                        {
                            return b"-ERR value is not an integer or out of range\r\n".to_vec();
                        }
                        saw_limit = true;
                        phase = 3;
                        index += 3;
                    }
                    "WITHSCORES" => {
                        if phase > 3 || saw_withscores {
                            return syntax_error().into_bytes();
                        }
                        saw_withscores = true;
                        phase = 4;
                        index += 1;
                    }
                    _ => return syntax_error().into_bytes(),
                }
            }
        }
        "zrevrange" => {
            if !(args.len() == 3 || args.len() == 4) {
                return wrong_number_of_arguments(command).into_bytes();
            }
            if args.len() == 4 && !args[3].eq_ignore_ascii_case(b"withscores") {
                return b"-ERR syntax error\r\n".to_vec();
            }
        }
        _ => return syntax_error().into_bytes(),
    }

    b"*0\r\n".to_vec()
}

pub(super) fn sorted_set_remove_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() < 2 {
        return wrong_number_of_arguments("zrem").into_bytes();
    }
    b":0\r\n".to_vec()
}

pub(super) fn sorted_set_score_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 2 {
        return wrong_number_of_arguments("zscore").into_bytes();
    }
    b"$-1\r\n".to_vec()
}

pub(super) fn sorted_set_rank_response(args: &[Vec<u8>], command: &str) -> Vec<u8> {
    if !(args.len() == 2 || args.len() == 3) {
        return wrong_number_of_arguments(command).into_bytes();
    }
    if args.len() == 3 && !args[2].eq_ignore_ascii_case(b"withscore") {
        return b"-ERR syntax error\r\n".to_vec();
    }
    b"$-1\r\n".to_vec()
}

pub(super) fn sorted_set_mscore_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() < 2 {
        return wrong_number_of_arguments("zmscore").into_bytes();
    }

    let mut response = Vec::with_capacity(args.len() * 4 + 8);
    response.extend_from_slice(b"*");
    response.extend_from_slice((args.len() - 1).to_string().as_bytes());
    response.extend_from_slice(b"\r\n");
    for _ in &args[1..] {
        response.extend_from_slice(b"$-1\r\n");
    }
    response
}

pub(super) fn sorted_set_random_member_response(args: &[Vec<u8>]) -> Vec<u8> {
    match args.len() {
        1 => b"$-1\r\n".to_vec(),
        2 => {
            if args[1].eq_ignore_ascii_case(b"withscores") {
                return b"-ERR syntax error\r\n".to_vec();
            }
            if parse_signed_decimal_bytes::<i64>(&args[1]).is_none() {
                return b"-ERR value is not an integer or out of range\r\n".to_vec();
            }
            b"*0\r\n".to_vec()
        }
        3 => {
            if !args[2].eq_ignore_ascii_case(b"withscores") {
                return b"-ERR syntax error\r\n".to_vec();
            }
            if parse_signed_decimal_bytes::<i64>(&args[1]).is_none() {
                return b"-ERR value is not an integer or out of range\r\n".to_vec();
            }
            b"*0\r\n".to_vec()
        }
        _ => wrong_number_of_arguments("zrandmember").into_bytes(),
    }
}

pub(super) fn sorted_set_range_store_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() < 4 {
        return wrong_number_of_arguments("zrangestore").into_bytes();
    }

    let mut index = 4usize;
    let mut saw_byscore = false;
    let mut saw_bylex = false;
    let mut saw_rev = false;
    let mut saw_limit = false;
    while index < args.len() {
        let Some(option) = text_command(&args[index]).map(|value| value.to_ascii_uppercase())
        else {
            return protocol_error();
        };
        match option.as_str() {
            "BYSCORE" => {
                if saw_byscore || saw_bylex {
                    return syntax_error().into_bytes();
                }
                saw_byscore = true;
                index += 1;
            }
            "BYLEX" => {
                if saw_byscore || saw_bylex {
                    return syntax_error().into_bytes();
                }
                saw_bylex = true;
                index += 1;
            }
            "REV" => {
                if saw_rev {
                    return syntax_error().into_bytes();
                }
                saw_rev = true;
                index += 1;
            }
            "LIMIT" => {
                if saw_limit {
                    return syntax_error().into_bytes();
                }
                saw_limit = true;
                if index + 2 >= args.len() {
                    return syntax_error().into_bytes();
                }
                if parse_unsigned_decimal_bytes::<u64>(&args[index + 1]).is_none()
                    || parse_signed_decimal_bytes::<i64>(&args[index + 2]).is_none()
                {
                    return b"-ERR value is not an integer or out of range\r\n".to_vec();
                }
                index += 3;
            }
            _ => return syntax_error().into_bytes(),
        }
    }

    if saw_limit && !(saw_byscore || saw_bylex) {
        return syntax_error().into_bytes();
    }

    b":0\r\n".to_vec()
}
