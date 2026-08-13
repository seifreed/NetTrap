use super::*;

pub(super) fn hash_set_response(args: &[Vec<u8>], command: &str) -> Vec<u8> {
    if args.len() < 3 || args.len() % 2 != 1 {
        return wrong_number_of_arguments(command).into_bytes();
    }
    format!(":{}\r\n", (args.len() - 1) / 2).into_bytes()
}

pub(super) fn hash_set_nx_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 3 {
        return wrong_number_of_arguments("hsetnx").into_bytes();
    }
    b":1\r\n".to_vec()
}

pub(super) fn hash_get_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 2 {
        return wrong_number_of_arguments("hget").into_bytes();
    }
    b"$-1\r\n".to_vec()
}

pub(super) fn hash_del_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() < 2 {
        return wrong_number_of_arguments("hdel").into_bytes();
    }
    b":0\r\n".to_vec()
}

pub(super) fn hash_exists_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 2 {
        return wrong_number_of_arguments("hexists").into_bytes();
    }
    b":0\r\n".to_vec()
}

pub(super) fn hash_len_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 1 {
        return wrong_number_of_arguments("hlen").into_bytes();
    }
    b":0\r\n".to_vec()
}

pub(super) fn hash_mget_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() < 2 {
        return wrong_number_of_arguments("hmget").into_bytes();
    }

    let mut response = Vec::with_capacity(args.len() * 5 + 8);
    response.extend_from_slice(b"*");
    response.extend_from_slice((args.len() - 1).to_string().as_bytes());
    response.extend_from_slice(b"\r\n");
    for _ in &args[1..] {
        response.extend_from_slice(b"$-1\r\n");
    }
    response
}

pub(super) fn set_add_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() < 2 {
        return wrong_number_of_arguments("sadd").into_bytes();
    }
    format!(":{}\r\n", args.len() - 1).into_bytes()
}

pub(super) fn set_remove_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() < 2 {
        return wrong_number_of_arguments("srem").into_bytes();
    }
    b":0\r\n".to_vec()
}

pub(super) fn set_member_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 2 {
        return wrong_number_of_arguments("sismember").into_bytes();
    }
    b":0\r\n".to_vec()
}

pub(super) fn set_card_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 1 {
        return wrong_number_of_arguments("scard").into_bytes();
    }
    b":0\r\n".to_vec()
}

pub(super) fn set_members_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 1 {
        return wrong_number_of_arguments("smembers").into_bytes();
    }
    b"*0\r\n".to_vec()
}

pub(super) fn set_multi_member_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() < 2 {
        return wrong_number_of_arguments("smismember").into_bytes();
    }

    let mut response = Vec::with_capacity(args.len() * 4 + 8);
    response.extend_from_slice(b"*");
    response.extend_from_slice((args.len() - 1).to_string().as_bytes());
    response.extend_from_slice(b"\r\n");
    for _ in &args[1..] {
        response.extend_from_slice(b":0\r\n");
    }
    response
}

pub(super) fn list_push_response(args: &[Vec<u8>], command: &str) -> Vec<u8> {
    if args.len() < 2 {
        return wrong_number_of_arguments(command).into_bytes();
    }
    format!(":{}\r\n", args.len() - 1).into_bytes()
}

pub(super) fn list_pop_response(args: &[Vec<u8>], command: &str) -> Vec<u8> {
    if args.is_empty() || args.len() > 2 {
        return wrong_number_of_arguments(command).into_bytes();
    }
    if args.len() == 2 && parse_unsigned_decimal_bytes::<u64>(&args[1]).is_none() {
        return b"-ERR value is not an integer or out of range\r\n".to_vec();
    }
    b"$-1\r\n".to_vec()
}

pub(super) fn list_len_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 1 {
        return wrong_number_of_arguments("llen").into_bytes();
    }
    b":0\r\n".to_vec()
}

pub(super) fn list_range_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 3 {
        return wrong_number_of_arguments("lrange").into_bytes();
    }
    if parse_signed_decimal_bytes::<i64>(&args[1]).is_none()
        || parse_signed_decimal_bytes::<i64>(&args[2]).is_none()
    {
        return b"-ERR value is not an integer or out of range\r\n".to_vec();
    }
    b"*0\r\n".to_vec()
}

pub(super) fn list_index_response(args: &[Vec<u8>]) -> Vec<u8> {
    if args.len() != 2 {
        return wrong_number_of_arguments("lindex").into_bytes();
    }
    if parse_signed_decimal_bytes::<i64>(&args[1]).is_none() {
        return b"-ERR value is not an integer or out of range\r\n".to_vec();
    }
    b"$-1\r\n".to_vec()
}
