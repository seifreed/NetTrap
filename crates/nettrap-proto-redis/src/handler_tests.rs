use super::*;

const LOG_FIELD_PREVIEW_CHARS: usize = 240;

fn info_field<'a>(info: &'a str, field: &str) -> Option<&'a str> {
    info.lines().find_map(|line| {
        line.split_once(':')
            .and_then(|(key, value)| (key == field).then_some(value))
    })
}

#[test]
fn resp_parser_respects_bulk_lengths() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"*1\r\n$4\r\nPING\r\n"),
        b"+PONG\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"*1\r\n$4\r\nPI\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn resp_parser_accepts_binary_bulk_strings_for_ping() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"*2\r\n$4\r\nPING\r\n$2\r\n\xff\x00\r\n"),
        b"$2\r\n\xff\x00\r\n".to_vec()
    );
}

#[test]
fn resp_parser_rejects_malformed_pipeline_without_partial_response() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nPI\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"*1\r\n$4\r\nPING\r\n*0\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn resp_pipeline_preserves_previous_replies_for_command_argument_errors() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"*1\r\n$4\r\nPING\r\n*2\r\n$4\r\nINFO\r\n$1\r\n\xff\r\n"),
        b"+PONG\r\n-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn resp_parser_rejects_signed_array_counts_and_bulk_lengths() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"*+1\r\n$4\r\nPING\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"*1\r\n$+4\r\nPING\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"*1\r\n$-0\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"*1\r\n$-1\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn resp_parser_rejects_invalid_utf8_in_inline_commands() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"PI\xffNG\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn resp_parser_rejects_tab_separated_inline_commands() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"PING\t\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn resp_parser_rejects_compressed_ascii_spaces_in_inline_commands() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"SET key  value\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn resp_parser_rejects_leading_whitespace_inline_commands() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b" PING\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b" AUTH secret\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn resp_parser_rejects_unicode_whitespace_inline_commands() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command("PING\u{00a0}\r\n".as_bytes()),
        b"-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn resp_parser_rejects_c1_controls_in_inline_commands() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command("PING\u{009f}\r\n".as_bytes()),
        b"-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn resp_parser_rejects_bare_lf_inline_commands() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"PING\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"\nPING\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PING\r\n\nPING\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn resp_parser_rejects_oversized_inline_commands() {
    let handler = RedisHandler::new();
    let mut command = vec![b'a'; MAX_INLINE_COMMAND_BYTES + 1];
    command.extend_from_slice(b"\r\n");

    assert_eq!(
        handler.handle_command(&command),
        b"-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn resp_parser_rejects_oversized_resp_frames() {
    let handler = RedisHandler::new();
    let bulk_len = MAX_RESP_BULK_SIZE;
    let bulk_count = (MAX_RESP_FRAME_SIZE / MAX_RESP_BULK_SIZE) + 1;
    let mut command = Vec::new();
    command.extend_from_slice(format!("*{bulk_count}\r\n").as_bytes());
    for _ in 0..bulk_count {
        command.extend_from_slice(format!("${bulk_len}\r\n").as_bytes());
        command.extend(std::iter::repeat_n(b'a', bulk_len));
        command.extend_from_slice(b"\r\n");
    }
    assert!(command.len() > MAX_RESP_FRAME_SIZE);

    assert_eq!(
        handler.handle_command(&command),
        b"-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn resp_parser_rejects_too_many_inline_arguments() {
    let handler = RedisHandler::new();
    let mut command = String::from("PING");
    for _ in 0..=MAX_INLINE_COMMAND_ARGS {
        command.push_str(" x");
    }
    command.push_str("\r\n");

    assert_eq!(
        handler.handle_command(command.as_bytes()),
        b"-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn resp_parser_rejects_too_many_commands() {
    let handler = RedisHandler::new();
    let mut commands = Vec::new();
    for _ in 0..=MAX_RESP_COMMANDS {
        commands.extend_from_slice(b"PING\r\n");
    }

    assert_eq!(
        handler.handle_command(&commands),
        b"-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn resp_parser_rejects_invalid_utf8_in_bulk_strings() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"*1\r\n$4\r\nPI\xffNG\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
}

#[test]
fn with_auth_blocks_commands_until_auth_succeeds() {
    let handler = RedisHandler::new().with_auth(true);
    let mut authenticated = false;

    assert_eq!(
        handler.handle_command_with_auth_state(b"PING\r\n", &mut authenticated),
        b"-NOAUTH Authentication required.\r\n".to_vec()
    );
    assert!(!authenticated);

    assert_eq!(
        handler.handle_command_with_auth_state(b"AUTH secret\r\n", &mut authenticated),
        b"+OK\r\n".to_vec()
    );
    assert!(authenticated);

    assert_eq!(
        handler.handle_command_with_auth_state(b"PING\r\n", &mut authenticated),
        b"+PONG\r\n".to_vec()
    );
}

#[test]
fn auth_requires_non_empty_credentials() {
    let handler = RedisHandler::new().with_auth(true);
    let mut authenticated = false;

    assert_eq!(
        handler.handle_command_with_auth_state(b"AUTH\r\n", &mut authenticated),
        b"-ERR wrong number of arguments for 'auth' command\r\n".to_vec()
    );
    assert!(!authenticated);

    assert_eq!(
        handler.handle_command_with_auth_state(b"*2\r\n$4\r\nAUTH\r\n$-1\r\n", &mut authenticated),
        b"-ERR Protocol error\r\n".to_vec()
    );
    assert!(!authenticated);

    assert_eq!(
        handler.handle_command_with_auth_state(
            b"*3\r\n$4\r\nAUTH\r\n$4\r\nuser\r\n$6\r\nsecret\r\n",
            &mut authenticated,
        ),
        b"+OK\r\n".to_vec()
    );
    assert!(authenticated);
}

#[test]
fn auth_rejects_whitespace_only_credentials() {
    let handler = RedisHandler::new().with_auth(true);
    let mut authenticated = false;

    assert_eq!(
        handler.handle_command_with_auth_state(
            b"*3\r\n$4\r\nAUTH\r\n$3\r\n \t \r\n$6\r\nsecret\r\n",
            &mut authenticated,
        ),
        b"-ERR wrong number of arguments for 'auth' command\r\n".to_vec()
    );
    assert!(!authenticated);

    assert_eq!(
        handler.handle_command_with_auth_state(
            b"*2\r\n$4\r\nAUTH\r\n$3\r\n \t \r\n",
            &mut authenticated,
        ),
        b"-ERR wrong number of arguments for 'auth' command\r\n".to_vec()
    );
    assert!(!authenticated);
}

#[test]
fn handle_command_enforces_auth_for_stateless_calls() {
    let handler = RedisHandler::new().with_auth(true);

    assert_eq!(
        handler.handle_command(b"PING\r\n"),
        b"-NOAUTH Authentication required.\r\n".to_vec()
    );
}

#[test]
fn configured_version_accepts_long_versions_within_budget() {
    let version = format!("7.0.15-{}", "a".repeat(504));
    let response = RedisHandler {
        version: version.clone(),
        require_auth: false,
        started_at: std::time::Instant::now(),
        now: chrono::Utc::now,
        client_name: std::sync::Mutex::new(None),
        client_lib_name: std::sync::Mutex::new(None),
        client_lib_ver: std::sync::Mutex::new(None),
        client_reply_mode: std::sync::Mutex::new(ClientReplyMode::On),
        client_no_evict: std::sync::Mutex::new(false),
        client_no_touch: std::sync::Mutex::new(false),
        client_tracking_enabled: std::sync::Mutex::new(false),
        client_tracking_bcast: std::sync::Mutex::new(false),
        client_tracking_optin: std::sync::Mutex::new(false),
        client_tracking_optout: std::sync::Mutex::new(false),
        client_tracking_noloop: std::sync::Mutex::new(false),
        client_tracking_redirect: std::sync::Mutex::new(-1),
        client_tracking_prefixes: std::sync::Mutex::new(Vec::new()),
        client_tracking_caching: std::sync::Mutex::new(None),
        client_tracking_broken_redir: std::sync::Mutex::new(false),
        resp_version: std::sync::Mutex::new(2),
        state: std::sync::Mutex::new(RedisState::Connected),
    }
    .handle_command(b"INFO\r\n");
    let text = String::from_utf8_lossy(&response);

    assert!(text.contains(&version));
}

#[test]
fn info_accepts_at_most_one_section_argument() {
    let handler = RedisHandler::new();

    assert!(handler.handle_command(b"INFO\r\n").starts_with(b"$"));
    assert!(handler.handle_command(b"INFO server\r\n").starts_with(b"$"));
    assert_eq!(
        handler.handle_command(b"INFO server memory\r\n"),
        b"-ERR wrong number of arguments for 'info' command\r\n".to_vec()
    );
}

#[test]
fn dbsize_rejects_extra_arguments() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"DBSIZE\r\n"), b":0\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"DBSIZE extra\r\n"),
        b"-ERR wrong number of arguments for 'dbsize' command\r\n".to_vec()
    );
}

#[test]
fn command_rejects_extra_arguments() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"COMMAND\r\n"), b"*0\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"COMMAND info\r\n"),
        b"-ERR wrong number of arguments for 'command' command\r\n".to_vec()
    );
}

#[test]
fn module_and_cluster_require_subcommands() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"MODULE\r\n"),
        b"-ERR wrong number of arguments for 'module' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"MODULE LOAD x\r\n"),
        b"-ERR Module loading is disabled\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLUSTER\r\n"),
        b"-ERR wrong number of arguments for 'cluster' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLUSTER INFO\r\n"),
        b"-ERR This instance has cluster support disabled\r\n".to_vec()
    );
}

#[test]
fn info_payload_uses_live_uptime_values() {
    let info = redis_info_payload("7.0.15", 172_801);

    assert_eq!(info_field(&info, "uptime_in_seconds"), Some("172801"));
    assert_eq!(info_field(&info, "uptime_in_days"), Some("2"));
}

#[test]
fn info_response_does_not_report_frozen_uptime() {
    let handler = RedisHandler::new();

    let response = handler.handle_command(b"INFO\r\n");
    let response = String::from_utf8(response).expect("INFO response should be UTF-8");

    assert!(response.contains("uptime_in_seconds:"));
    assert!(!response.contains("uptime_in_seconds:86400\r\n"));
}

#[test]
fn logged_redis_fields_are_single_line() {
    assert_eq!(
        nettrap_core::sanitize::single_line("alice\r\nadmin\x1b"),
        "alice  admin "
    );

    let long = "a".repeat(LOG_FIELD_PREVIEW_CHARS + 1);
    assert_eq!(
        nettrap_core::sanitize::single_line(&long).len(),
        LOG_FIELD_PREVIEW_CHARS
    );

    assert_eq!(safe_log_args(&["one\r\n", "two\x1b"]), "one  , two ");
    assert_eq!(
        safe_log_args(&["set", "key\u{2028}value"]),
        "set, key value"
    );

    let long = "a".repeat(LOG_ARGS_PREVIEW_CHARS + 1);
    assert_eq!(safe_log_args(&[&long]).len(), LOG_ARGS_PREVIEW_CHARS);
}

#[test]
fn logged_non_utf8_bytes_are_bounded() {
    let mut value = vec![0xff; nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS];
    value.push(b'a');

    let rendered = nettrap_core::sanitize::single_line_bytes(&value);

    assert!(rendered.starts_with("hex:"));
    assert!(rendered.len() <= nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS);
}

#[test]
fn ping_validates_arguments_and_echoes_single_message() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"PING\r\n"), b"+PONG\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"PING hello\r\n"),
        b"$5\r\nhello\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PING one two\r\n"),
        b"-ERR wrong number of arguments for 'ping' command\r\n".to_vec()
    );
}

#[test]
fn echo_validates_arguments_and_echoes_single_message() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"ECHO hello\r\n"),
        b"$5\r\nhello\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ECHO\r\n"),
        b"-ERR wrong number of arguments for 'echo' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ECHO one two\r\n"),
        b"-ERR wrong number of arguments for 'echo' command\r\n".to_vec()
    );
}

#[test]
fn hello_validates_protocol_version_and_returns_respb3_map() {
    let handler = RedisHandler::new();

    let response = handler.handle_command(b"HELLO 3\r\n");
    let response = String::from_utf8(response).expect("HELLO response should be UTF-8");

    assert!(response.starts_with("%7\r\n"));
    assert!(response.contains("$6\r\nserver\r\n$5\r\nredis\r\n"));
    assert!(response.contains("$7\r\nversion\r\n"));
    assert!(response.contains("$5\r\nproto\r\n:3\r\n"));
    assert!(response.contains("$4\r\nmode\r\n$10\r\nstandalone\r\n"));
    assert!(response.contains("$7\r\nmodules\r\n*0\r\n"));
    let client_info = String::from_utf8(handler.handle_command(b"CLIENT INFO\r\n"))
        .expect("CLIENT INFO response should be UTF-8");
    assert!(client_info.contains("resp=3"));
    assert_eq!(handler.handle_command(b"HELLO\r\n")[0], b'%');
    let client_info = String::from_utf8(handler.handle_command(b"CLIENT INFO\r\n"))
        .expect("CLIENT INFO response should be UTF-8");
    assert!(client_info.contains("resp=3"));
    assert_eq!(
            handler.handle_command(b"HELLO 2\r\n"),
            b"*14\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$6\r\n7.0.15\r\n$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:1\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n$4\r\nrole\r\n$6\r\nmaster\r\n$7\r\nmodules\r\n*0\r\n".to_vec()
        );
    let client_info = String::from_utf8(handler.handle_command(b"CLIENT INFO\r\n"))
        .expect("CLIENT INFO response should be UTF-8");
    assert!(client_info.contains("resp=2"));
    assert_eq!(
            handler.handle_command(b"HELLO\r\n"),
            b"*14\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$6\r\n7.0.15\r\n$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:1\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n$4\r\nrole\r\n$6\r\nmaster\r\n$7\r\nmodules\r\n*0\r\n".to_vec()
        );
}

#[test]
fn hello_supports_auth_and_setname_options() {
    let handler = RedisHandler::new().with_auth(true);
    let mut authenticated = false;

    assert!(
        handler
            .handle_command_with_auth_state(
                b"HELLO 3 AUTH alice secret SETNAME bob\r\n",
                &mut authenticated
            )
            .starts_with(b"%7\r\n")
    );
    assert_eq!(
        handler.handle_command_with_auth_state(b"PING\r\n", &mut authenticated),
        b"+PONG\r\n".to_vec()
    );

    let client_info = String::from_utf8(
        handler.handle_command_with_auth_state(b"CLIENT INFO\r\n", &mut authenticated),
    )
    .expect("CLIENT INFO response should be UTF-8");
    assert!(client_info.contains("name=bob"));
    assert!(client_info.contains("resp=3"));
}

#[test]
fn hello_requires_protover_before_optional_arguments() {
    let handler = RedisHandler::new();
    let mut authenticated = false;

    for command in [
        b"HELLO AUTH alice secret\r\n".as_slice(),
        b"HELLO SETNAME bob\r\n".as_slice(),
    ] {
        assert_eq!(
            handler.handle_command_with_auth_state(command, &mut authenticated),
            wrong_number_of_arguments("hello").into_bytes()
        );
    }

    let client_info = String::from_utf8(
        handler.handle_command_with_auth_state(b"CLIENT INFO\r\n", &mut authenticated),
    )
    .expect("CLIENT INFO response should be UTF-8");
    assert!(client_info.contains("resp=2"));
    assert!(!client_info.contains("name=bob"));
    assert!(!authenticated);
}

#[test]
fn hello_does_not_persist_partial_state_after_parse_error() {
    let handler = RedisHandler::new().with_auth(true);
    let mut authenticated = false;

    assert_eq!(
        handler.handle_command_with_auth_state(
            b"HELLO 3 AUTH alice secret FOO bar\r\n",
            &mut authenticated
        ),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command_with_auth_state(b"PING\r\n", &mut authenticated),
        b"-NOAUTH Authentication required.\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command_with_auth_state(b"AUTH alice secret\r\n", &mut authenticated),
        b"+OK\r\n".to_vec()
    );
    let client_info = String::from_utf8(
        handler.handle_command_with_auth_state(b"CLIENT INFO\r\n", &mut authenticated),
    )
    .expect("CLIENT INFO response should be UTF-8");
    assert!(client_info.contains("resp=2"));
    assert!(client_info.contains("name="));
}

#[test]
fn reset_restores_resp2_protocol_after_hello() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"HELLO 3\r\n")[0], b'%');
    let client_info = String::from_utf8(handler.handle_command(b"CLIENT INFO\r\n"))
        .expect("CLIENT INFO response should be UTF-8");
    assert!(client_info.contains("resp=3"));

    assert_eq!(handler.handle_command(b"RESET\r\n"), b"+RESET\r\n".to_vec());

    let client_info = String::from_utf8(handler.handle_command(b"CLIENT INFO\r\n"))
        .expect("CLIENT INFO response should be UTF-8");
    assert!(client_info.contains("resp=2"));
}

#[test]
fn client_id_returns_synthetic_id() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"CLIENT ID\r\n"), b":1\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"CLIENT ID extra\r\n"),
        b"-ERR wrong number of arguments for 'client|id' command\r\n".to_vec()
    );
}

#[test]
fn client_info_returns_synthetic_record() {
    let handler = RedisHandler::new();

    let response = handler.handle_command(b"CLIENT INFO\r\n");
    let response = String::from_utf8(response).expect("CLIENT INFO response should be UTF-8");

    assert!(response.starts_with("$"));
    assert!(response.contains("id=1 addr=127.0.0.1:0"));
    assert!(response.contains("laddr=127.0.0.1:0"));
    assert!(response.contains("cmd=client|info"));
    assert!(response.contains("lib-name="));
    assert!(response.contains("lib-ver="));
    assert!(response.contains("flags=N"));
    assert!(response.contains("redir=-1"));
    assert!(response.contains("resp=2"));
    assert_eq!(
        handler.handle_command(b"CLIENT INFO extra\r\n"),
        b"-ERR wrong number of arguments for 'client|info' command\r\n".to_vec()
    );
}

#[test]
fn client_setname_persists_name_across_getname_and_list() {
    let handler = RedisHandler::new();
    let mut authenticated = true;

    assert_eq!(
        handler.handle_command_with_auth_state(
            b"*3\r\n$6\r\nCLIENT\r\n$7\r\nSETNAME\r\n$5\r\nalice\r\n",
            &mut authenticated
        ),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT GETNAME\r\n"),
        b"$5\r\nalice\r\n".to_vec()
    );

    let info = String::from_utf8(
        handler.handle_command_with_auth_state(b"CLIENT INFO\r\n", &mut authenticated),
    )
    .expect("CLIENT INFO response should be UTF-8");
    assert!(info.contains("name=alice"));
    assert!(info.contains("cmd=client|info"));
    assert!(info.contains("flags=N"));

    let list = String::from_utf8(handler.handle_command(b"CLIENT LIST\r\n"))
        .expect("CLIENT LIST response should be UTF-8");
    assert!(list.contains("name=alice"));
    assert!(list.contains("cmd=client|list"));
    assert!(list.contains("flags=N"));
}

#[test]
fn client_setname_empty_string_clears_name() {
    let handler = RedisHandler::new();
    let mut authenticated = true;

    assert_eq!(
        handler.handle_command_with_auth_state(
            b"*3\r\n$6\r\nCLIENT\r\n$7\r\nSETNAME\r\n$5\r\nalice\r\n",
            &mut authenticated
        ),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command_with_auth_state(
            b"*3\r\n$6\r\nCLIENT\r\n$7\r\nSETNAME\r\n$0\r\n\r\n",
            &mut authenticated
        ),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT GETNAME\r\n"),
        b"$-1\r\n".to_vec()
    );
    let list = String::from_utf8(handler.handle_command(b"CLIENT LIST\r\n"))
        .expect("CLIENT LIST response should be UTF-8");
    assert!(list.contains("name="));
    assert!(!list.contains("name=alice"));
}

#[test]
fn client_setinfo_persists_library_metadata() {
    let handler = RedisHandler::new();
    let mut authenticated = true;

    assert_eq!(
        handler.handle_command_with_auth_state(
            b"*4\r\n$6\r\nCLIENT\r\n$7\r\nSETINFO\r\n$8\r\nLIB-NAME\r\n$11\r\nredis-rs-v2\r\n",
            &mut authenticated
        ),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command_with_auth_state(
            b"*4\r\n$6\r\nCLIENT\r\n$7\r\nSETINFO\r\n$7\r\nLIB-VER\r\n$4\r\n0.29\r\n",
            &mut authenticated
        ),
        b"+OK\r\n".to_vec()
    );

    let info = String::from_utf8(
        handler.handle_command_with_auth_state(b"CLIENT INFO\r\n", &mut authenticated),
    )
    .expect("CLIENT INFO response should be UTF-8");
    assert!(info.contains("lib-name=redis-rs-v2"));
    assert!(info.contains("lib-ver=0.29"));

    let list = String::from_utf8(handler.handle_command(b"CLIENT LIST\r\n"))
        .expect("CLIENT LIST response should be UTF-8");
    assert!(list.contains("lib-name=redis-rs-v2"));
    assert!(list.contains("lib-ver=0.29"));
}

#[test]
fn client_setinfo_accepts_empty_library_values() {
    let handler = RedisHandler::new();
    let mut authenticated = true;

    assert_eq!(
        handler.handle_command_with_auth_state(
            b"*4\r\n$6\r\nCLIENT\r\n$7\r\nSETINFO\r\n$8\r\nLIB-NAME\r\n$0\r\n\r\n",
            &mut authenticated
        ),
        b"+OK\r\n".to_vec()
    );
    let info = String::from_utf8(
        handler.handle_command_with_auth_state(b"CLIENT INFO\r\n", &mut authenticated),
    )
    .expect("CLIENT INFO response should be UTF-8");
    assert!(info.contains("lib-name="));
}

#[test]
fn client_help_lists_supported_subcommands() {
    let handler = RedisHandler::new();

    let response = handler.handle_command(b"CLIENT HELP\r\n");
    let response = String::from_utf8(response).expect("CLIENT HELP response should be UTF-8");

    assert!(response.starts_with("*14\r\n"));
    assert!(response.contains("$7\r\nSETNAME\r\n"));
    assert!(response.contains("$7\r\nSETINFO\r\n"));
    assert!(response.contains("$8\r\nGETREDIR\r\n"));
    assert!(response.contains("$7\r\nCACHING\r\n"));
    assert!(response.contains("$6\r\nREPLY\r\n"));
    assert!(response.contains("$8\r\nTRACKING\r\n"));
    assert!(response.contains("$12\r\nTRACKINGINFO\r\n"));
    assert!(response.contains("$4\r\nHELP\r\n"));
    assert_eq!(
        handler.handle_command(b"CLIENT HELP extra\r\n"),
        b"-ERR wrong number of arguments for 'client|help' command\r\n".to_vec()
    );
}

#[test]
fn client_getredir_reports_no_redirect_by_default() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT GETREDIR\r\n"),
        b":-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT GETREDIR extra\r\n"),
        b"-ERR wrong number of arguments for 'client|getredir' command\r\n".to_vec()
    );
}

#[test]
fn client_caching_rejects_without_optin_or_optout_tracking() {
    let handler = RedisHandler::new();

    assert_eq!(
            handler.handle_command(b"CLIENT CACHING YES\r\n"),
            b"-ERR CLIENT CACHING can only be called when tracking is enabled in OPTIN or OPTOUT mode\r\n"
                .to_vec()
        );
    assert_eq!(
            handler.handle_command(b"CLIENT CACHING no\r\n"),
            b"-ERR CLIENT CACHING can only be called when tracking is enabled in OPTIN or OPTOUT mode\r\n"
                .to_vec()
        );
    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON BCAST\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
            handler.handle_command(b"CLIENT CACHING YES\r\n"),
            b"-ERR CLIENT CACHING can only be called when tracking is enabled in OPTIN or OPTOUT mode\r\n"
                .to_vec()
        );
}

#[test]
fn client_caching_accepts_yes_and_no_modes_when_tracking_allows_it() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON OPTIN\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT CACHING YES\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT CACHING no\r\n"),
        b"-ERR CLIENT CACHING NO can only be called when tracking is enabled in OPTOUT mode\r\n"
            .to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT CACHING maybe\r\n"),
        b"-ERR argument must be yes or no\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT CACHING\r\n"),
        b"-ERR wrong number of arguments for 'client|caching' command\r\n".to_vec()
    );
}

#[test]
fn lowercase_client_caching_command_preserves_caching_state() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON OPTIN\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT CACHING YES\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT caching yes\r\n"),
        b"+OK\r\n".to_vec()
    );

    let tracking_info = String::from_utf8(handler.handle_command(b"CLIENT TRACKINGINFO\r\n"))
        .expect("CLIENT TRACKINGINFO response should be UTF-8");
    assert!(tracking_info.contains("caching-yes"));
}

#[test]
fn client_caching_accepts_no_mode_only_in_optout_tracking() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON OPTOUT\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT CACHING NO\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT CACHING YES\r\n"),
        b"-ERR CLIENT CACHING YES can only be called when tracking is enabled in OPTIN mode\r\n"
            .to_vec()
    );
}

#[test]
fn client_caching_applies_only_to_next_command() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON OPTIN\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT CACHING YES\r\n"),
        b"+OK\r\n".to_vec()
    );

    let tracking_info = String::from_utf8(handler.handle_command(b"CLIENT TRACKINGINFO\r\n"))
        .expect("CLIENT TRACKINGINFO response should be UTF-8");
    assert!(tracking_info.contains("caching-yes"));

    assert_eq!(handler.handle_command(b"PING\r\n"), b"+PONG\r\n".to_vec());

    let tracking_info = String::from_utf8(handler.handle_command(b"CLIENT TRACKINGINFO\r\n"))
        .expect("CLIENT TRACKINGINFO response should be UTF-8");
    assert!(!tracking_info.contains("caching-yes"));
}

#[test]
fn client_caching_is_consumed_when_next_reply_is_skipped() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON OPTIN\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT CACHING YES\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT REPLY SKIP\r\n"),
        Vec::<u8>::new()
    );
    assert_eq!(handler.handle_command(b"PING\r\n"), Vec::<u8>::new());

    let tracking_info = String::from_utf8(handler.handle_command(b"CLIENT TRACKINGINFO\r\n"))
        .expect("CLIENT TRACKINGINFO response should be UTF-8");
    assert!(!tracking_info.contains("caching-yes"));
}

#[test]
fn client_tracking_updates_tracking_state_and_info() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON REDIRECT 1 PREFIX foo: BCAST OPTIN NOLOOP\r\n"),
        b"+OK\r\n".to_vec()
    );

    let tracking_info = String::from_utf8(handler.handle_command(b"CLIENT TRACKINGINFO\r\n"))
        .expect("CLIENT TRACKINGINFO response should be UTF-8");
    assert!(tracking_info.starts_with("*6\r\n"));
    assert!(tracking_info.contains("flags"));
    assert!(tracking_info.contains("on"));
    assert!(tracking_info.contains("bcast"));
    assert!(tracking_info.contains("optin"));
    assert!(tracking_info.contains("noloop"));
    assert!(tracking_info.contains("redirect"));
    assert!(tracking_info.contains(":0"));
    assert!(tracking_info.contains("prefixes"));
    assert!(tracking_info.contains("foo:"));

    assert_eq!(
        handler.handle_command(b"CLIENT GETREDIR\r\n"),
        b":0\r\n".to_vec()
    );

    let client_info = String::from_utf8(handler.handle_command(b"CLIENT INFO\r\n"))
        .expect("CLIENT INFO response should be UTF-8");
    assert!(client_info.contains("flags=tB"));
    assert!(client_info.contains("redir=0"));

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING OFF\r\n"),
        b"+OK\r\n".to_vec()
    );

    let tracking_info = String::from_utf8(handler.handle_command(b"CLIENT TRACKINGINFO\r\n"))
        .expect("CLIENT TRACKINGINFO response should be UTF-8");
    assert!(tracking_info.starts_with("*6\r\n"));
    assert!(tracking_info.contains("off"));
    assert_eq!(
        handler.handle_command(b"CLIENT GETREDIR\r\n"),
        b":-1\r\n".to_vec()
    );
}

#[test]
fn client_tracking_rejects_nonpositive_redirect_ids() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON REDIRECT 0\r\n"),
        b"-ERR invalid redirect id\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON REDIRECT -1\r\n"),
        b"-ERR invalid redirect id\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON REDIRECT +1\r\n"),
        b"-ERR invalid redirect id\r\n".to_vec()
    );
}

#[test]
fn client_tracking_rejects_missing_redirect_target() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON REDIRECT 7\r\n"),
        b"-ERR invalid redirect id\r\n".to_vec()
    );
}

#[test]
fn client_tracking_reports_zero_for_self_redirect() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON REDIRECT 1\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT GETREDIR\r\n"),
        b":0\r\n".to_vec()
    );

    let client_info = String::from_utf8(handler.handle_command(b"CLIENT INFO\r\n"))
        .expect("CLIENT INFO response should be UTF-8");
    assert!(client_info.contains("redir=0"));

    let client_list = String::from_utf8(handler.handle_command(b"CLIENT LIST\r\n"))
        .expect("CLIENT LIST response should be UTF-8");
    assert!(client_list.contains("redir=0"));

    let tracking_info = String::from_utf8(handler.handle_command(b"CLIENT TRACKINGINFO\r\n"))
        .expect("CLIENT TRACKINGINFO response should be UTF-8");
    assert!(tracking_info.contains(":0"));
    assert!(!tracking_info.contains(":1"));
}

#[test]
fn client_trackinginfo_uses_resp3_map_after_hello() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"HELLO 3\r\n")[0], b'%');
    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON OPTIN\r\n"),
        b"+OK\r\n".to_vec()
    );

    let tracking_info = String::from_utf8(handler.handle_command(b"CLIENT TRACKINGINFO\r\n"))
        .expect("CLIENT TRACKINGINFO response should be UTF-8");
    assert!(tracking_info.starts_with("%3\r\n"));
    assert!(tracking_info.contains("flags"));
    assert!(tracking_info.contains("redirect"));
    assert!(tracking_info.contains("prefixes"));
}

#[test]
fn client_tracking_reports_zero_redirect_when_tracking_without_redirect() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON OPTIN\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT GETREDIR\r\n"),
        b":0\r\n".to_vec()
    );

    let tracking_info = String::from_utf8(handler.handle_command(b"CLIENT TRACKINGINFO\r\n"))
        .expect("CLIENT TRACKINGINFO response should be UTF-8");
    assert!(tracking_info.contains("redirect"));
    assert!(tracking_info.contains(":0"));

    let client_info = String::from_utf8(handler.handle_command(b"CLIENT INFO\r\n"))
        .expect("CLIENT INFO response should be UTF-8");
    assert!(client_info.contains("redir=0"));
}

#[test]
fn client_tracking_bcast_sets_b_flag_in_client_metadata() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON BCAST PREFIX foo\r\n"),
        b"+OK\r\n".to_vec()
    );

    let client_info = String::from_utf8(handler.handle_command(b"CLIENT INFO\r\n"))
        .expect("CLIENT INFO response should be UTF-8");
    assert!(client_info.contains("flags=tB"));

    let client_list = String::from_utf8(handler.handle_command(b"CLIENT LIST\r\n"))
        .expect("CLIENT LIST response should be UTF-8");
    assert!(client_list.contains("flags=tB"));
}

#[test]
fn client_tracking_preserves_prefixes_when_leaving_bcast_mode() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON BCAST PREFIX foo\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON OPTIN\r\n"),
        b"+OK\r\n".to_vec()
    );

    let tracking_info = String::from_utf8(handler.handle_command(b"CLIENT TRACKINGINFO\r\n"))
        .expect("CLIENT TRACKINGINFO response should be UTF-8");
    assert!(tracking_info.contains("foo"));
}

#[test]
fn client_no_evict_and_no_touch_preserve_redis_flag_order() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT NO-EVICT ON\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT NO-TOUCH ON\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON OPTIN\r\n"),
        b"+OK\r\n".to_vec()
    );

    let client_info = String::from_utf8(handler.handle_command(b"CLIENT INFO\r\n"))
        .expect("CLIENT INFO response should be UTF-8");
    assert!(client_info.contains("flags=etT"));
}

#[test]
fn client_tracking_bcast_without_prefix_tracks_empty_prefix() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON BCAST\r\n"),
        b"+OK\r\n".to_vec()
    );

    let tracking_info = String::from_utf8(handler.handle_command(b"CLIENT TRACKINGINFO\r\n"))
        .expect("CLIENT TRACKINGINFO response should be UTF-8");
    assert!(tracking_info.contains("*1\r\n$0\r\n\r\n"));
}

#[test]
fn client_tracking_bcast_without_prefix_rejects_existing_prefix_overlap() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON BCAST PREFIX foo\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON BCAST\r\n"),
        b"-ERR Prefixes for a single client must not overlap.\r\n".to_vec()
    );
}

#[test]
fn client_tracking_bcast_reenable_rejects_overlapping_prefixes() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON BCAST\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON BCAST PREFIX foo\r\n"),
        b"-ERR Prefixes for a single client must not overlap.\r\n".to_vec()
    );
}

#[test]
fn client_tracking_ignores_prefixes_without_bcast_mode() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON PREFIX foo PREFIX bar\r\n"),
        b"+OK\r\n".to_vec()
    );

    let tracking_info = String::from_utf8(handler.handle_command(b"CLIENT TRACKINGINFO\r\n"))
        .expect("CLIENT TRACKINGINFO response should be UTF-8");
    assert!(tracking_info.contains("flags"));
    assert!(tracking_info.contains("on"));
    assert!(!tracking_info.contains("foo"));
    assert!(!tracking_info.contains("bar"));
    assert!(tracking_info.contains("*0\r\n"));
}

#[test]
fn client_tracking_rejects_overlapping_bcast_prefixes() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON BCAST PREFIX foo PREFIX foobar\r\n"),
        b"-ERR Prefixes for a single client must not overlap.\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON BCAST PREFIX foo PREFIX bar\r\n"),
        b"+OK\r\n".to_vec()
    );
}

#[test]
fn client_tracking_rejects_too_many_bcast_prefixes_without_storing_extra() {
    let handler = RedisHandler::new();
    let mut command = b"CLIENT TRACKING ON BCAST".to_vec();
    for idx in 0..MAX_CLIENT_TRACKING_PREFIXES {
        command.extend_from_slice(format!(" PREFIX p{idx:03}:").as_bytes());
    }
    command.extend_from_slice(b"\r\n");

    assert_eq!(handler.handle_command(&command), b"+OK\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON BCAST PREFIX zzz:\r\n"),
        b"-ERR too many client tracking prefixes\r\n".to_vec()
    );

    let tracking_info = String::from_utf8(handler.handle_command(b"CLIENT TRACKINGINFO\r\n"))
        .expect("CLIENT TRACKINGINFO response should be UTF-8");
    assert!(tracking_info.contains("p000:"));
    assert!(!tracking_info.contains("zzz:"));
}

#[test]
fn client_tracking_rejected_prefix_does_not_update_flags() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON BCAST PREFIX foo\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT TRACKING ON OPTIN BCAST PREFIX foobar\r\n"),
        b"-ERR Prefixes for a single client must not overlap.\r\n".to_vec()
    );

    let tracking_info = String::from_utf8(handler.handle_command(b"CLIENT TRACKINGINFO\r\n"))
        .expect("CLIENT TRACKINGINFO response should be UTF-8");
    assert!(tracking_info.contains("bcast"));
    assert!(!tracking_info.contains("optin"));
    assert!(!tracking_info.contains("foobar"));
}

#[test]
fn client_reply_off_skips_next_responses_until_reenabled() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT REPLY OFF\r\n"),
        Vec::<u8>::new()
    );
    assert_eq!(handler.handle_command(b"PING\r\n"), Vec::<u8>::new());
    assert_eq!(
        handler.handle_command(b"CLIENT REPLY ON\r\n"),
        Vec::<u8>::new()
    );
    assert_eq!(handler.handle_command(b"PING\r\n"), b"+PONG\r\n".to_vec());
}

#[test]
fn client_reply_skip_only_suppresses_one_followup_command() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT REPLY SKIP\r\n"),
        Vec::<u8>::new()
    );
    assert_eq!(handler.handle_command(b"PING\r\n"), Vec::<u8>::new());
    assert_eq!(handler.handle_command(b"PING\r\n"), b"+PONG\r\n".to_vec());
}

#[test]
fn lowercase_client_reply_command_keeps_requested_mode_after_skip() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT REPLY SKIP\r\n"),
        Vec::<u8>::new()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT reply off\r\n"),
        Vec::<u8>::new()
    );
    assert_eq!(handler.handle_command(b"PING\r\n"), Vec::<u8>::new());
}

#[test]
fn client_no_evict_and_no_touch_toggle_connection_modes() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CLIENT NO-EVICT ON\r\n"),
        b"+OK\r\n".to_vec()
    );
    let info = String::from_utf8(handler.handle_command(b"CLIENT INFO\r\n"))
        .expect("CLIENT INFO response should be UTF-8");
    assert!(info.contains("flags=e"));
    assert_eq!(
        handler.handle_command(b"CLIENT NO-EVICT OFF\r\n"),
        b"+OK\r\n".to_vec()
    );
    let info = String::from_utf8(handler.handle_command(b"CLIENT INFO\r\n"))
        .expect("CLIENT INFO response should be UTF-8");
    assert!(info.contains("flags=N"));
    assert_eq!(
        handler.handle_command(b"CLIENT NO-TOUCH ON\r\n"),
        b"+OK\r\n".to_vec()
    );
    let info = String::from_utf8(handler.handle_command(b"CLIENT INFO\r\n"))
        .expect("CLIENT INFO response should be UTF-8");
    assert!(info.contains("flags=T"));
    assert_eq!(
        handler.handle_command(b"CLIENT NO-TOUCH OFF\r\n"),
        b"+OK\r\n".to_vec()
    );
    let info = String::from_utf8(handler.handle_command(b"CLIENT INFO\r\n"))
        .expect("CLIENT INFO response should be UTF-8");
    assert!(info.contains("flags=N"));
    assert_eq!(
        handler.handle_command(b"CLIENT NO-EVICT ON\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT NO-TOUCH ON\r\n"),
        b"+OK\r\n".to_vec()
    );
    let list = String::from_utf8(handler.handle_command(b"CLIENT LIST\r\n"))
        .expect("CLIENT LIST response should be UTF-8");
    assert!(list.contains("flags=eT"));
    assert_eq!(
        handler.handle_command(b"CLIENT NO-EVICT maybe\r\n"),
        b"-ERR invalid CLIENT NO-EVICT mode\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT NO-TOUCH maybe\r\n"),
        b"-ERR invalid CLIENT NO-TOUCH mode\r\n".to_vec()
    );
}

#[test]
fn reset_is_allowed_without_auth_and_clears_connection_state() {
    let handler = RedisHandler::new().with_auth(true);
    let mut authenticated = false;

    assert_eq!(
        handler.handle_command_with_auth_state(b"RESET\r\n", &mut authenticated),
        b"+RESET\r\n".to_vec()
    );
    assert!(!authenticated);
    assert_eq!(
        handler.handle_command_with_auth_state(b"AUTH password\r\n", &mut authenticated),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command_with_auth_state(b"CLIENT GETNAME\r\n", &mut authenticated),
        b"$-1\r\n".to_vec()
    );
}

#[test]
fn reset_clears_client_metadata_and_requires_reauth() {
    let handler = RedisHandler::new().with_auth(true);
    let mut authenticated = true;

    assert_eq!(
        handler.handle_command_with_auth_state(
            b"*3\r\n$6\r\nCLIENT\r\n$7\r\nSETNAME\r\n$5\r\nalice\r\n",
            &mut authenticated
        ),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command_with_auth_state(
            b"*4\r\n$6\r\nCLIENT\r\n$7\r\nSETINFO\r\n$8\r\nLIB-NAME\r\n$11\r\nredis-rs-v2\r\n",
            &mut authenticated
        ),
        b"+OK\r\n".to_vec()
    );

    assert_eq!(
        handler.handle_command_with_auth_state(b"RESET\r\n", &mut authenticated),
        b"+RESET\r\n".to_vec()
    );
    assert!(!authenticated);

    assert_eq!(
        handler.handle_command_with_auth_state(b"AUTH password\r\n", &mut authenticated),
        b"+OK\r\n".to_vec()
    );

    let info = String::from_utf8(
        handler.handle_command_with_auth_state(b"CLIENT INFO\r\n", &mut authenticated),
    )
    .expect("CLIENT INFO response should be UTF-8");
    assert!(info.contains("name="));
    assert!(!info.contains("name=alice"));
    assert!(info.contains("lib-name="));
    assert!(!info.contains("lib-name=redis-rs-v2"));

    assert_eq!(
        handler.handle_command(b"PING\r\n"),
        b"-NOAUTH Authentication required.\r\n".to_vec()
    );
}

#[test]
fn role_returns_synthetic_master_response() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"ROLE\r\n"),
        b"*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ROLE extra\r\n"),
        b"-ERR wrong number of arguments for 'role' command\r\n".to_vec()
    );
}

#[test]
fn mget_returns_nil_values_for_each_key() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"MGET a b\r\n"),
        b"*2\r\n$-1\r\n$-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"MGET\r\n"),
        b"-ERR wrong number of arguments for 'mget' command\r\n".to_vec()
    );
}

#[test]
fn del_returns_zero_deleted_items() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"DEL a b\r\n"), b":0\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"DEL\r\n"),
        b"-ERR wrong number of arguments for 'del' command\r\n".to_vec()
    );
}

#[test]
fn exists_returns_zero_matching_keys() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"EXISTS a b\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"EXISTS\r\n"),
        b"-ERR wrong number of arguments for 'exists' command\r\n".to_vec()
    );
}

#[test]
fn ttl_returns_missing_key_marker() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"TTL a\r\n"), b":-2\r\n".to_vec());
    assert_eq!(handler.handle_command(b"PTTL a\r\n"), b":-2\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"EXPIRETIME a\r\n"),
        b":-2\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PEXPIRETIME a\r\n"),
        b":-2\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"TTL\r\n"),
        b"-ERR wrong number of arguments for 'ttl' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PTTL\r\n"),
        b"-ERR wrong number of arguments for 'pttl' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"EXPIRETIME\r\n"),
        b"-ERR wrong number of arguments for 'expiretime' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PEXPIRETIME\r\n"),
        b"-ERR wrong number of arguments for 'pexpiretime' command\r\n".to_vec()
    );
}

#[test]
fn expire_commands_return_zero_for_missing_keys() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"EXPIRE a 10\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PEXPIRE a 10\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"EXPIRE a\r\n"),
        b"-ERR wrong number of arguments for 'expire' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PEXPIRE a\r\n"),
        b"-ERR wrong number of arguments for 'pexpire' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"EXPIRE a nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PEXPIRE a nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"EXPIRE a 10 NX\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PEXPIRE a 10 bad\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
}

#[test]
fn expireat_commands_return_zero_for_missing_keys() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"EXPIREAT a 10\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PEXPIREAT a 10\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"EXPIREAT a\r\n"),
        b"-ERR wrong number of arguments for 'expireat' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PEXPIREAT a\r\n"),
        b"-ERR wrong number of arguments for 'pexpireat' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"EXPIREAT a nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PEXPIREAT a nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"EXPIREAT a 10 GT\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PEXPIREAT a 10 bogus\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
}

#[test]
fn type_and_strlen_return_missing_key_defaults() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"TYPE a\r\n"), b"+none\r\n".to_vec());
    assert_eq!(handler.handle_command(b"STRLEN a\r\n"), b":0\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"TYPE\r\n"),
        b"-ERR wrong number of arguments for 'type' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"STRLEN\r\n"),
        b"-ERR wrong number of arguments for 'strlen' command\r\n".to_vec()
    );
}

#[test]
fn getset_returns_nil_old_value() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"GETSET a b\r\n"),
        b"$-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"GETSET a\r\n"),
        b"-ERR wrong number of arguments for 'getset' command\r\n".to_vec()
    );
}

#[test]
fn getdel_returns_nil_old_value() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"GETDEL a\r\n"), b"$-1\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"GETDEL a b\r\n"),
        b"-ERR wrong number of arguments for 'getdel' command\r\n".to_vec()
    );
}

#[test]
fn setex_commands_return_ok() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"SETEX a 10 b\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PSETEX a 10 b\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SETEX a 10\r\n"),
        b"-ERR wrong number of arguments for 'setex' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PSETEX a 10\r\n"),
        b"-ERR wrong number of arguments for 'psetex' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SETEX a nope b\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PSETEX a nope b\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SETEX a 0 b\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PSETEX a 0 b\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
}

#[test]
fn setnx_returns_one_for_missing_key() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"SETNX a b\r\n"), b":1\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"SETNX a\r\n"),
        b"-ERR wrong number of arguments for 'setnx' command\r\n".to_vec()
    );
}

#[test]
fn mset_commands_validate_pairs() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"MSET a b c d\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"MSETNX a b c d\r\n"),
        b":1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"MSET a b c\r\n"),
        b"-ERR wrong number of arguments for 'mset' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"MSETNX a b c\r\n"),
        b"-ERR wrong number of arguments for 'msetnx' command\r\n".to_vec()
    );
}

#[test]
fn append_returns_value_length_for_missing_key() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"APPEND a b\r\n"),
        b":1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"APPEND a\r\n"),
        b"-ERR wrong number of arguments for 'append' command\r\n".to_vec()
    );
}

#[test]
fn incr_and_decr_commands_return_stateless_values() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"INCR a\r\n"), b":1\r\n".to_vec());
    assert_eq!(handler.handle_command(b"DECR a\r\n"), b":-1\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"INCRBY a 5\r\n"),
        b":5\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"DECRBY a 5\r\n"),
        b":-5\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"INCRBY a nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"DECRBY a nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"INCR a b\r\n"),
        b"-ERR wrong number of arguments for 'incr' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"DECRBY a\r\n"),
        b"-ERR wrong number of arguments for 'decrby' command\r\n".to_vec()
    );
}

#[test]
fn hash_commands_return_stateless_values() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"HSET h f v\r\n"),
        b":1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"HSET h f v g w\r\n"),
        b":2\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"HSETNX h f v\r\n"),
        b":1\r\n".to_vec()
    );
    assert_eq!(handler.handle_command(b"HGET h f\r\n"), b"$-1\r\n".to_vec());
    assert_eq!(handler.handle_command(b"HDEL h f\r\n"), b":0\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"HEXISTS h f\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(handler.handle_command(b"HLEN h\r\n"), b":0\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"HMGET h f g\r\n"),
        b"*2\r\n$-1\r\n$-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"HSET h f\r\n"),
        b"-ERR wrong number of arguments for 'hset' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"HMGET h\r\n"),
        b"-ERR wrong number of arguments for 'hmget' command\r\n".to_vec()
    );
}

#[test]
fn set_commands_return_stateless_values() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"SADD s a b\r\n"),
        b":2\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SREM s a b\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SISMEMBER s a\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(handler.handle_command(b"SCARD s\r\n"), b":0\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"SMEMBERS s\r\n"),
        b"*0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SMISMEMBER s a b\r\n"),
        b"*2\r\n:0\r\n:0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SADD s\r\n"),
        b"-ERR wrong number of arguments for 'sadd' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SMISMEMBER s\r\n"),
        b"-ERR wrong number of arguments for 'smismember' command\r\n".to_vec()
    );
}

#[test]
fn list_commands_return_stateless_values() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"LPUSH l a b\r\n"),
        b":2\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"RPUSH l a b\r\n"),
        b":2\r\n".to_vec()
    );
    assert_eq!(handler.handle_command(b"LPOP l\r\n"), b"$-1\r\n".to_vec());
    assert_eq!(handler.handle_command(b"RPOP l\r\n"), b"$-1\r\n".to_vec());
    assert_eq!(handler.handle_command(b"LLEN l\r\n"), b":0\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"LRANGE l 0 -1\r\n"),
        b"*0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"LINDEX l 0\r\n"),
        b"$-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"LRANGE l nope -1\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"LINDEX l nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"LPUSH l\r\n"),
        b"-ERR wrong number of arguments for 'lpush' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"LPOP l extra\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
}

#[test]
fn bit_commands_return_stateless_values() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"GETBIT k 10\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SETBIT k 10 1\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"BITCOUNT k\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"BITCOUNT k 0 10\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"BITCOUNT k 0 10 BYTE\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"BITCOUNT k 0 10 nope\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"GETBIT k nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SETBIT k 10 2\r\n"),
        b"-ERR The bit argument must be 1 or 0.\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"BITCOUNT k nope nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"BITCOUNT\r\n"),
        b"-ERR wrong number of arguments for 'bitcount' command\r\n".to_vec()
    );
}

#[test]
fn hyperloglog_commands_return_stateless_values() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"PFADD h a b\r\n"),
        b":1\r\n".to_vec()
    );
    assert_eq!(handler.handle_command(b"PFCOUNT h\r\n"), b":0\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"PFMERGE h a b\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PFADD\r\n"),
        b"-ERR wrong number of arguments for 'pfadd' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PFCOUNT\r\n"),
        b"-ERR wrong number of arguments for 'pfcount' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PFMERGE h\r\n"),
        b"-ERR wrong number of arguments for 'pfmerge' command\r\n".to_vec()
    );
}

#[test]
fn time_returns_injected_clock_components() {
    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_800_000_000, 123_456_000).expect("valid instant")
    }

    let handler = RedisHandler::new().with_now(fixed_now);

    assert_eq!(
        handler.handle_command(b"TIME\r\n"),
        b"*2\r\n$10\r\n1800000000\r\n$6\r\n123456\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"TIME extra\r\n"),
        b"-ERR wrong number of arguments for 'time' command\r\n".to_vec()
    );
}

#[test]
fn pubsub_commands_return_stateless_values() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"PUBLISH c m\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PUBSUB CHANNELS\r\n"),
        b"*0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PUBSUB NUMPAT\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PUBSUB NUMSUB c d\r\n"),
        b"*4\r\n$1\r\nc\r\n:0\r\n$1\r\nd\r\n:0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PUBLISH c\r\n"),
        b"-ERR wrong number of arguments for 'publish' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PUBSUB\r\n"),
        b"-ERR wrong number of arguments for 'pubsub' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"PUBSUB FOO\r\n"),
        b"-ERR unknown PUBSUB subcommand\r\n".to_vec()
    );
}

#[test]
fn key_scan_commands_return_stateless_values() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"KEYS *\r\n"), b"*0\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"RANDOMKEY\r\n"),
        b"$-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SCAN 0\r\n"),
        b"*2\r\n$1\r\n0\r\n*0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SCAN 0 MATCH foo:* COUNT 10 TYPE string\r\n"),
        b"*2\r\n$1\r\n0\r\n*0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SCAN nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SCAN 0 COUNT nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SCAN 0 MATCH\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SCAN 0 BAD value\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"KEYS\r\n"),
        b"-ERR wrong number of arguments for 'keys' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"RANDOMKEY extra\r\n"),
        b"-ERR wrong number of arguments for 'randomkey' command\r\n".to_vec()
    );
}

#[test]
fn touch_and_unlink_return_zero_for_missing_keys() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"TOUCH a b\r\n"), b":0\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"UNLINK a b\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"TOUCH\r\n"),
        b"-ERR wrong number of arguments for 'touch' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"UNLINK\r\n"),
        b"-ERR wrong number of arguments for 'unlink' command\r\n".to_vec()
    );
}

#[test]
fn move_returns_zero_for_missing_keys() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"MOVE a 1\r\n"), b":0\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"MOVE a nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"MOVE a\r\n"),
        b"-ERR wrong number of arguments for 'move' command\r\n".to_vec()
    );
}

#[test]
fn copy_accepts_db_and_replace_options_in_order() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"COPY source dest\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"COPY source dest DB 2\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"COPY source dest DB 2 REPLACE\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"COPY source dest REPLACE\r\n"),
        b":0\r\n".to_vec()
    );
}

#[test]
fn copy_rejects_invalid_option_sequences() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"COPY source dest DB\r\n"),
        b"-ERR wrong number of arguments for 'copy' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"COPY source dest DB nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"COPY source dest REPLACE DB 2\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"COPY source dest BAD\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"COPY source dest DB 2 DB 3\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"COPY source\r\n"),
        b"-ERR wrong number of arguments for 'copy' command\r\n".to_vec()
    );
}

#[test]
fn sorted_set_commands_return_stateless_values() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"SORT k\r\n"), b"*0\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"SORT k LIMIT 0 10 DESC ALPHA\r\n"),
        b"*0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SORT k ASC DESC\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SORT k ALPHA ALPHA\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SORT k BY weight_* BY other_*\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SORT k BY weight_* GET object_* GET # STORE dest\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SORT_RO k STORE dest\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SORT k LIMIT 0 nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(handler.handle_command(b"ZCARD z\r\n"), b":0\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"ZCOUNT z 0 10\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZCOUNT z -inf +inf\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZCOUNT z nope 10\r\n"),
        b"-ERR value is not a valid float\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZINCRBY z 1.5 member\r\n"),
        b"$3\r\n1.5\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZINCRBY z nope member\r\n"),
        b"-ERR value is not a valid float\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZINCRBY z NaN member\r\n"),
        b"-ERR value is not a valid float\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZDIFFSTORE dst 2 a b\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZDIFFSTORE dst nope a b\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    let zdiffstore_overflow = format!("ZDIFFSTORE dst {} a b\r\n", usize::MAX);
    assert_eq!(
        handler.handle_command(zdiffstore_overflow.as_bytes()),
        b"-ERR wrong number of arguments for 'zdiffstore' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZDIFFSTORE dst 2 a\r\n"),
        b"-ERR wrong number of arguments for 'zdiffstore' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZUNIONSTORE dst 2 a b\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZUNIONSTORE dst nope a b\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    let zunionstore_overflow = format!("ZUNIONSTORE dst {} a b\r\n", usize::MAX);
    assert_eq!(
        handler.handle_command(zunionstore_overflow.as_bytes()),
        b"-ERR wrong number of arguments for 'zunionstore' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZUNIONSTORE dst 2 a\r\n"),
        b"-ERR wrong number of arguments for 'zunionstore' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZUNIONSTORE dst 2 a b WEIGHTS 2 3 AGGREGATE COUNT\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZUNIONSTORE dst 2 a b WEIGHTS 2 nope\r\n"),
        b"-ERR value is not a valid float\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZUNIONSTORE dst 2 a b AGGREGATE COUNT WEIGHTS 2 3\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZUNIONSTORE dst 2 a b AGGREGATE MEDIAN\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZINTERSTORE dst 2 a b\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZINTERSTORE dst nope a b\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZINTERSTORE dst 2 a\r\n"),
        b"-ERR wrong number of arguments for 'zinterstore' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZINTERSTORE dst 2 a b WEIGHTS 2 3 AGGREGATE MAX\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZINTERSTORE dst 2 a b WEIGHTS 2 3 AGGREGATE COUNT\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZINTERSTORE dst 2 a b AGGREGATE COUNT WEIGHTS 2 3\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZINTERSTORE dst 2 a b WEIGHTS 2 nope\r\n"),
        b"-ERR value is not a valid float\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZINTERSTORE dst 2 a b AGGREGATE MEDIAN\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANGESTORE dst src 0 -1\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANGESTORE dst src 0 -1 LIMIT 0 10\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANGESTORE dst src 0 -1 BYSCORE LIMIT 0 -1\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANGESTORE dst src 0 -1 REV REV\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANGESTORE dst src 0 -1 BYSCORE BYLEX\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANGESTORE dst src 0 -1 LIMIT 0 nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANGESTORE dst src 0 -1 BAD\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANGE z 0 -1 WITHSCORES\r\n"),
        b"*0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANGE z 0 -1 BYSCORE REV LIMIT 0 -1 WITHSCORES\r\n"),
        b"*0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANGE z 0 -1 WITHSCORES LIMIT 0 10\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANGE z 0 -1 LIMIT 0 10\r\n"),
        b"*0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZREVRANGE z 0 -1 WITHSCORES\r\n"),
        b"*0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZREVRANGE z 0 -1 REV\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZADD z 1 one\r\n"),
        b":1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZADD z NX CH 1 one 2 two\r\n"),
        b":2\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZADD z INCR 1 one\r\n"),
        b"$1\r\n1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZADD z NX XX 1 one\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZADD z INCR 1 one 2 two\r\n"),
        b"-ERR wrong number of arguments for 'zadd' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZADD z 1 one NX\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZADD z nope one\r\n"),
        b"-ERR value is not a valid float\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZADD z NaN one\r\n"),
        b"-ERR value is not a valid float\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANGE z 0 -1\r\n"),
        b"*0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZREVRANGE z 0 -1 WITHSCORES\r\n"),
        b"*0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZREM z a b\r\n"),
        b":0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZSCORE z a\r\n"),
        b"$-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANK z a\r\n"),
        b"$-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZREVRANK z a\r\n"),
        b"$-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANK z a WITHSCORE\r\n"),
        b"$-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZREVRANK z a WITHSCORE\r\n"),
        b"$-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZMSCORE z a b\r\n"),
        b"*2\r\n$-1\r\n$-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANDMEMBER z\r\n"),
        b"$-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANDMEMBER z 2\r\n"),
        b"*0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANDMEMBER z -2 WITHSCORES\r\n"),
        b"*0\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANDMEMBER z WITHSCORES\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANDMEMBER z nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANGE z 0 -1 BAD\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZRANK z a BAD\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"ZCARD\r\n"),
        b"-ERR wrong number of arguments for 'zcard' command\r\n".to_vec()
    );
}

#[test]
fn select_requires_single_numeric_database_index() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"SELECT 0\r\n"), b"+OK\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"SELECT\r\n"),
        b"-ERR wrong number of arguments for 'select' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SELECT abc\r\n"),
        b"-ERR invalid DB index\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SELECT +1\r\n"),
        b"-ERR invalid DB index\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SELECT 1 extra\r\n"),
        b"-ERR wrong number of arguments for 'select' command\r\n".to_vec()
    );
}

#[test]
fn get_and_set_validate_argument_counts() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"GET key\r\n"), b"$-1\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"GET\r\n"),
        b"-ERR wrong number of arguments for 'get' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"GET one two\r\n"),
        b"-ERR wrong number of arguments for 'get' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SET key value\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SET key value EX 60\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SET key value GET\r\n"),
        b"$-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SET key value GET NX\r\n"),
        b"$-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SET key value EXAT 1712345678\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SET key value PXAT 1712345678123 KEEPTTL\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SET key value EX 60 GET\r\n"),
        b"$-1\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SET key value PX 100 NX\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SET key value NX XX\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SET key value EX 60 PX 100\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SET key\r\n"),
        b"-ERR wrong number of arguments for 'set' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SET key value EX\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SET key value EX nope\r\n"),
        b"-ERR invalid expire time in 'set' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SET key value EX +60\r\n"),
        b"-ERR invalid expire time in 'set' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SET key value UNKNOWN\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
}

#[test]
fn config_validates_subcommand_and_argument_counts() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"CONFIG\r\n"),
        b"-ERR wrong number of arguments for 'config' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CONFIG GET\r\n"),
        b"-ERR wrong number of arguments for 'config|get' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CONFIG GET dir\r\n"),
        b"*2\r\n$3\r\ndir\r\n$5\r\n/tmp/\r\n".to_vec()
    );
    assert_eq!(
            handler.handle_command(b"CONFIG GET *\r\n"),
            b"*10\r\n$3\r\ndir\r\n$5\r\n/tmp/\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n$4\r\nsave\r\n$23\r\n3600 1 300 100 60 10000\r\n$9\r\nmaxmemory\r\n$1\r\n0\r\n$4\r\nbind\r\n$7\r\n0.0.0.0\r\n"
                .to_vec()
        );
    assert_eq!(
        handler.handle_command(b"CONFIG SET dir /tmp extra\r\n"),
        b"-ERR wrong number of arguments for 'config|set' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CONFIG SET dir /tmp\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CONFIG SET dir /tmp dbfilename dump.rdb\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CONFIG REWRITE\r\n"),
        b"-ERR unknown CONFIG subcommand\r\n".to_vec()
    );
}

#[test]
fn client_setname_rejects_whitespace_only_names() {
    let handler = RedisHandler::new();
    let mut authenticated = true;

    assert_eq!(
        handler.handle_command_with_auth_state(
            b"*3\r\n$6\r\nCLIENT\r\n$7\r\nSETNAME\r\n$3\r\n \t \r\n",
            &mut authenticated
        ),
        b"-ERR invalid client name\r\n".to_vec()
    );
    assert!(authenticated);
}

#[test]
fn client_setname_rejects_invalid_utf8_and_control_characters() {
    let handler = RedisHandler::new();
    let mut authenticated = true;

    assert_eq!(
        handler.handle_command_with_auth_state(
            b"*3\r\n$6\r\nCLIENT\r\n$7\r\nSETNAME\r\n$2\r\n\xff\xfe\r\n",
            &mut authenticated
        ),
        b"-ERR invalid client name\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command_with_auth_state(
            b"*3\r\n$6\r\nCLIENT\r\n$7\r\nSETNAME\r\n$3\r\na\x00b\r\n",
            &mut authenticated
        ),
        b"-ERR invalid client name\r\n".to_vec()
    );
    assert!(authenticated);
}

#[test]
fn replication_commands_validate_arguments() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"SLAVEOF NO ONE\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF host 6379\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SLAVEOF\r\n"),
        b"-ERR wrong number of arguments for 'slaveof' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF host nope\r\n"),
        b"-ERR invalid port\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SLAVEOF host +6379\r\n"),
        b"-ERR invalid port\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF host 0\r\n"),
        b"-ERR invalid port\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SLAVEOF host/name 6379\r\n"),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SLAVEOF host:6379 6379\r\n"),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF [not-an-ip] 6379\r\n"),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF 0.0.0.0 6379\r\n"),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF [::] 6379\r\n"),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF [::ffff:0.0.0.0] 6379\r\n"),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF 127.0.0.1 6379\r\n"),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF 224.0.0.1 6379\r\n"),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF 255.255.255.255 6379\r\n"),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF [::1] 6379\r\n"),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF [::ffff:127.0.0.1] 6379\r\n"),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF 12345 6379\r\n"),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF 192.0.2.10. 6379\r\n"),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF bad..example 6379\r\n"),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"REPLICAOF bad_example 6379\r\n"),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(
            format!("REPLICAOF {}.example.test 6379\r\n", "a".repeat(64)).as_bytes()
        ),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(
            format!(
                "REPLICAOF {}.{}.{}.{} 6379\r\n",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(62)
            )
            .as_bytes()
        ),
        b"-ERR invalid host\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"*3\r\n$7\r\nSLAVEOF\r\n$-1\r\n$4\r\n6379\r\n"),
        b"-ERR Protocol error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SLAVEOF NO ONE extra\r\n"),
        b"-ERR wrong number of arguments for 'slaveof' command\r\n".to_vec()
    );
}

#[test]
fn eval_commands_validate_script_and_key_count() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"EVAL return 0\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"EVALSHA abc 1 key\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"EVAL return\r\n"),
        b"-ERR wrong number of arguments for 'eval' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"EVAL return nope\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"EVAL return +1 key\r\n"),
        b"-ERR value is not an integer or out of range\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"EVAL return 2 onlykey\r\n"),
        b"-ERR Number of keys can't be greater than number of args\r\n".to_vec()
    );
}

#[test]
fn flush_quit_client_and_save_validate_arguments() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"FLUSHALL\r\n"), b"+OK\r\n".to_vec());
    assert_eq!(
        handler.handle_command(b"FLUSHDB ASYNC\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"FLUSHALL LATER\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"QUIT now\r\n"),
        b"-ERR wrong number of arguments for 'quit' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"SAVE x\r\n"),
        b"-ERR wrong number of arguments for 'save' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"BGSAVE SCHEDULE\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"BGSAVE NOW\r\n"),
        b"-ERR syntax error\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT SETNAME worker\r\n"),
        b"+OK\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT GETNAME\r\n"),
        b"$6\r\nworker\r\n".to_vec()
    );

    let client_list = handler.handle_command(b"CLIENT LIST\r\n");
    let client_list = String::from_utf8(client_list).expect("CLIENT LIST response should be UTF-8");
    assert!(client_list.starts_with('$'));
    assert!(client_list.contains("name=worker"));
    assert!(client_list.contains("cmd=client|list"));
    assert!(client_list.contains("laddr=127.0.0.1:0"));

    assert_eq!(
        handler.handle_command(b"CLIENT\r\n"),
        b"-ERR wrong number of arguments for 'client' command\r\n".to_vec()
    );
    assert_eq!(
        handler.handle_command(b"CLIENT KILL all\r\n"),
        b"-ERR unknown CLIENT subcommand\r\n".to_vec()
    );
}

#[test]
fn quit_closes_connection_for_follow_on_commands() {
    let handler = RedisHandler::new();

    assert_eq!(handler.handle_command(b"QUIT\r\n"), b"+OK\r\n".to_vec());
    assert_eq!(handler.handle_command(b"PING\r\n"), Vec::<u8>::new());
}

#[test]
fn quit_ignores_remaining_pipelined_commands() {
    let handler = RedisHandler::new();

    assert_eq!(
        handler.handle_command(b"QUIT\r\nPING\r\n"),
        b"+OK\r\n".to_vec()
    );
}
