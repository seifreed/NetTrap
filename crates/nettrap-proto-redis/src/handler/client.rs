use super::*;

pub(super) fn client_tracking_response(handler: &RedisHandler, rest: &[Vec<u8>]) -> Vec<u8> {
    let Some((mode, options)) = rest.split_first() else {
        return wrong_number_of_arguments("client|tracking").into_bytes();
    };
    let Some(mode) = text_command(mode) else {
        return protocol_error();
    };

    match mode.to_ascii_uppercase().as_str() {
        "ON" => {
            let mut bcast = false;
            let mut optin = false;
            let mut optout = false;
            let mut noloop = false;
            let mut redirect = 0i64;
            let existing_prefixes = handler.client_tracking_prefixes();
            let mut prefixes = Vec::new();

            let mut idx = 0usize;
            while idx < options.len() {
                let Some(option) = text_command(&options[idx]) else {
                    return protocol_error();
                };
                match option.to_ascii_uppercase().as_str() {
                    "REDIRECT" => {
                        let Some(value) = options.get(idx + 1) else {
                            return wrong_number_of_arguments("client|tracking").into_bytes();
                        };
                        let Some(value) = text_command(value) else {
                            return protocol_error();
                        };
                        let Some(parsed_redirect) =
                            parse_unsigned_decimal_bytes::<i64>(value.as_bytes())
                        else {
                            return b"-ERR invalid redirect id\r\n".to_vec();
                        };
                        if parsed_redirect <= 0 || parsed_redirect > 1 {
                            return b"-ERR invalid redirect id\r\n".to_vec();
                        }
                        redirect = if parsed_redirect == 1 {
                            0
                        } else {
                            parsed_redirect
                        };
                        idx += 2;
                    }
                    "PREFIX" => {
                        let Some(value) = options.get(idx + 1) else {
                            return wrong_number_of_arguments("client|tracking").into_bytes();
                        };
                        let Some(value) = text_command(value) else {
                            return protocol_error();
                        };
                        if value.len() > MAX_CLIENT_TRACKING_PREFIX_BYTES {
                            return b"-ERR client tracking prefix too large\r\n".to_vec();
                        }
                        if prefixes.len() >= MAX_CLIENT_TRACKING_PREFIXES {
                            return b"-ERR too many client tracking prefixes\r\n".to_vec();
                        }
                        prefixes.push(value.to_owned());
                        idx += 2;
                    }
                    "BCAST" => {
                        bcast = true;
                        idx += 1;
                    }
                    "OPTIN" => {
                        optin = true;
                        optout = false;
                        idx += 1;
                    }
                    "OPTOUT" => {
                        optout = true;
                        optin = false;
                        idx += 1;
                    }
                    "NOLOOP" => {
                        noloop = true;
                        idx += 1;
                    }
                    _ => return syntax_error().into_bytes(),
                }
            }

            if bcast {
                let has_explicit_prefixes = !prefixes.is_empty();
                if prefixes_have_overlap(&prefixes) {
                    return b"-ERR Prefixes for a single client must not overlap.\r\n".to_vec();
                }

                let mut merged_prefixes = existing_prefixes;
                for prefix in prefixes {
                    if merged_prefixes
                        .iter()
                        .any(|existing| prefixes_overlap(existing, &prefix))
                    {
                        return b"-ERR Prefixes for a single client must not overlap.\r\n".to_vec();
                    }
                    if merged_prefixes.len() >= MAX_CLIENT_TRACKING_PREFIXES {
                        return b"-ERR too many client tracking prefixes\r\n".to_vec();
                    }
                    merged_prefixes.push(prefix);
                }

                if merged_prefixes.is_empty() {
                    merged_prefixes.push(String::new());
                }
                if !has_explicit_prefixes && !merged_prefixes.iter().any(|prefix| prefix.is_empty())
                {
                    return b"-ERR Prefixes for a single client must not overlap.\r\n".to_vec();
                }

                handler.set_client_tracking_prefixes(merged_prefixes);
            }
            handler.set_client_tracking_enabled(true);
            handler.set_client_tracking_bcast(bcast);
            handler.set_client_tracking_optin(optin);
            handler.set_client_tracking_optout(optout);
            handler.set_client_tracking_noloop(noloop);
            handler.set_client_tracking_redirect(redirect);
            handler.set_client_tracking_caching(None);
            handler.set_client_tracking_broken_redir(false);
            b"+OK\r\n".to_vec()
        }
        "OFF" => {
            if options.is_empty() {
                handler.set_client_tracking_enabled(false);
                handler.set_client_tracking_bcast(false);
                handler.set_client_tracking_optin(false);
                handler.set_client_tracking_optout(false);
                handler.set_client_tracking_noloop(false);
                handler.set_client_tracking_redirect(-1);
                handler.set_client_tracking_prefixes(Vec::new());
                handler.set_client_tracking_caching(None);
                handler.set_client_tracking_broken_redir(false);
                b"+OK\r\n".to_vec()
            } else {
                wrong_number_of_arguments("client|tracking").into_bytes()
            }
        }
        _ => b"-ERR syntax error\r\n".to_vec(),
    }
}

pub(super) fn client_tracking_info_payload(handler: &RedisHandler) -> String {
    let mut flags = Vec::new();
    flags.push(if handler.client_tracking_enabled() {
        "on"
    } else {
        "off"
    });
    if handler.client_tracking_bcast() {
        flags.push("bcast");
    }
    if handler.client_tracking_optin() {
        flags.push("optin");
    }
    if handler.client_tracking_optout() {
        flags.push("optout");
    }
    if let Some(caching) = handler.client_tracking_caching() {
        if handler.client_tracking_optin() && caching {
            flags.push("caching-yes");
        } else if handler.client_tracking_optout() && !caching {
            flags.push("caching-no");
        }
    }
    if handler.client_tracking_noloop() {
        flags.push("noloop");
    }
    if handler.client_tracking_broken_redir() {
        flags.push("broken_redirect");
    }

    let flags = flags.into_iter().map(|flag| flag.to_owned()).collect();
    let prefixes = handler.client_tracking_prefixes();

    if handler.resp_version() >= 3 {
        let mut response = String::new();
        response.push_str("%3\r\n");
        response.push_str(&resp_bulk_string("flags"));
        response.push_str(&resp_bulk_array(flags));
        response.push_str(&resp_bulk_string("redirect"));
        response.push_str(&format!(":{}\r\n", handler.client_tracking_redirect()));
        response.push_str(&resp_bulk_string("prefixes"));
        response.push_str(&resp_bulk_array(prefixes));
        response
    } else {
        let mut response = String::new();
        response.push_str("*6\r\n");
        response.push_str(&resp_bulk_string("flags"));
        response.push_str(&resp_bulk_array(flags));
        response.push_str(&resp_bulk_string("redirect"));
        response.push_str(&format!(":{}\r\n", handler.client_tracking_redirect()));
        response.push_str(&resp_bulk_string("prefixes"));
        response.push_str(&resp_bulk_array(prefixes));
        response
    }
}

fn resp_bulk_string(value: &str) -> String {
    format!("${}\r\n{}\r\n", value.len(), value)
}

fn resp_bulk_array(values: Vec<String>) -> String {
    let mut response = String::new();
    response.push_str(&format!("*{}\r\n", values.len()));
    for value in values {
        response.push_str(&format!("${}\r\n{}\r\n", value.len(), value));
    }
    response
}

fn prefixes_have_overlap(prefixes: &[String]) -> bool {
    for i in 0..prefixes.len() {
        for j in (i + 1)..prefixes.len() {
            if prefixes_overlap(&prefixes[i], &prefixes[j]) {
                return true;
            }
        }
    }
    false
}

fn prefixes_overlap(left: &str, right: &str) -> bool {
    left.starts_with(right) || right.starts_with(left)
}
