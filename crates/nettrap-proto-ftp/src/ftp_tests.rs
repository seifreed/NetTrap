use super::*;
use std::ffi::OsStr;
#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

#[test]
fn hostname_banner_macro_requires_exact_name() {
    assert_eq!(
        resolve_banner("!hostnamebackup"),
        "220 !hostnamebackup".to_string()
    );
}

#[test]
fn random_banner_resolves_to_an_ftp_banner() {
    let banner = resolve_banner("!random");

    assert!(
        banner.starts_with("220"),
        "unexpected random banner: {banner}"
    );
    assert!(!banner.trim().is_empty());
}

#[test]
fn proftpd_banner_presets_do_not_emit_ipv4_mapped_placeholders() {
    for preset in ["!proftpd", "!proftpd136", "!proftpd137", "!proftpd138"] {
        let banner = resolve_banner(preset);

        assert!(
            !banner.contains("::ffff:"),
            "banner preset {preset} still exposes mapped IPv4: {banner}"
        );
    }
}

#[cfg(unix)]
#[test]
fn hostname_banner_preserves_non_utf8_host_bytes() {
    let hostname = OsString::from_vec(b"ftp-\xff".to_vec());

    assert_eq!(safe_ftp_hostname_field(&hostname), "hex:6674702dff");
}

#[test]
fn format_banner_expands_servername_and_tz_tokens() {
    let rendered = format_banner("220 {servername} ({tz}) ready", "host01");
    assert_eq!(rendered, "220 host01 (UTC) ready");
}

#[test]
fn format_banner_at_renders_the_injected_instant() {
    let now = chrono::DateTime::from_timestamp(2_085_000_000, 0).expect("valid instant");
    let rendered = format_banner_at("220 since %Y", "nettrap", now);
    assert_eq!(rendered, "220 since 2036");
}

#[test]
fn format_banner_renders_live_date_tokens() {
    use chrono::Datelike;
    let year = chrono::Local::now().year().to_string();
    let rendered = format_banner("220 ready %Y", "nettrap");
    assert!(
        rendered.ends_with(&year),
        "expected current year {year} in {rendered:?}"
    );
    assert!(!rendered.contains('%'));
}

#[test]
fn format_banner_leaves_invalid_strftime_specifier_literal() {
    let rendered = format_banner("220 Acme 100% done", "nettrap");
    assert!(rendered.contains("Acme 100% done"));
}

#[test]
fn zos_preset_uses_live_timestamp_not_frozen_placeholder() {
    let banner = FtpHandler::new()
        .with_preformatted_banner(resolve_banner("!zos"))
        .expect("valid FTP preset")
        .get_banner();
    let text = String::from_utf8_lossy(&banner);
    assert!(text.contains("FTPD1 IBM FTP CS"));
    assert!(!text.contains("2024-01-01"), "frozen date leaked: {text}");
    assert!(!text.contains("{servername}"));
}

#[test]
fn server_name_feeds_banner_token() {
    let banner = FtpHandler::new()
        .with_server_name("mainframe")
        .expect("valid FTP server name")
        .with_preformatted_banner(resolve_banner("!as400"))
        .expect("valid FTP preset")
        .get_banner();
    let text = String::from_utf8_lossy(&banner);
    assert!(text.contains("QTCP at mainframe."));
}

#[test]
fn server_name_rejects_leading_whitespace() {
    assert!(FtpHandler::new().with_server_name(" mainframe").is_err());
}

#[test]
fn server_name_rejects_empty_labels() {
    assert!(FtpHandler::new().with_server_name("mail..example").is_err());
}

#[test]
fn server_name_rejects_dashed_label_edges() {
    assert!(FtpHandler::new().with_server_name("bad-.example").is_err());
}

#[test]
fn server_name_rejects_underscores() {
    assert!(FtpHandler::new().with_server_name("main_frame").is_err());
}

#[test]
fn server_name_rejects_numeric_hostnames() {
    for name in ["12345", "192.0.2.10"] {
        assert!(
            FtpHandler::new().with_server_name(name).is_err(),
            "{name} should be rejected"
        );
    }
}

#[test]
fn server_name_accepts_absolute_hostnames_with_trailing_dots() {
    let banner = FtpHandler::new()
        .with_server_name("mainframe.example.")
        .expect("valid FTP server name")
        .with_preformatted_banner(resolve_banner("!as400"))
        .expect("valid FTP preset")
        .get_banner();
    let text = String::from_utf8_lossy(&banner);

    assert!(text.contains("QTCP at mainframe.example."));
}

#[test]
fn server_name_canonicalizes_hostname_case() {
    let upper = FtpHandler::new()
        .with_server_name("MAINFRAME.EXAMPLE.")
        .expect("valid FTP server name")
        .with_preformatted_banner(resolve_banner("!as400"))
        .expect("valid FTP preset")
        .get_banner();
    let lower = FtpHandler::new()
        .with_server_name("mainframe.example")
        .expect("valid FTP server name")
        .with_preformatted_banner(resolve_banner("!as400"))
        .expect("valid FTP preset")
        .get_banner();

    assert_eq!(upper, lower);
}

#[test]
fn server_name_rejects_overlong_host_labels() {
    let hostname = format!("{}.example.test", "a".repeat(64));
    assert!(FtpHandler::new().with_server_name(&hostname).is_err());
}

#[test]
fn server_name_rejects_multiple_trailing_dots() {
    assert!(
        FtpHandler::new()
            .with_server_name("mainframe.example...")
            .is_err()
    );
}

#[test]
fn server_name_cannot_inject_response_lines() {
    assert!(
        FtpHandler::new()
            .with_server_name("evil\r\n220 injected")
            .is_err()
    );
}

#[test]
fn server_name_rejects_unicode_line_separators() {
    assert!(
        FtpHandler::new()
            .with_server_name("evil\u{2028}220 injected")
            .is_err()
    );
}

#[test]
fn server_name_rejects_c1_controls() {
    assert!(
        FtpHandler::new()
            .with_server_name("main\u{009f}frame")
            .is_err()
    );
}

#[test]
fn custom_banner_cannot_inject_response_lines() {
    let banner = resolve_banner("Acme FTP\r\n220 injected");

    assert!(banner.contains("Acme FTP"));
    assert!(!banner.contains("injected"));
    assert_eq!(banner.matches("\r\n").count(), 0);
}

#[test]
fn direct_custom_banner_cannot_inject_response_lines() {
    let banner = FtpHandler::new()
        .with_preformatted_banner("220 Acme FTP\r\n220 injected")
        .is_err();

    assert!(banner);
}

#[test]
fn direct_custom_banner_preserves_ascii_padding() {
    let banner = FtpHandler::new()
        .with_preformatted_banner("220   Acme FTP   ")
        .expect("valid FTP banner")
        .get_banner();
    let text = String::from_utf8_lossy(&banner);

    assert!(text.contains("220   Acme FTP   "));
    assert!(!text.contains("220 Acme FTP"));
}

#[test]
fn direct_custom_banner_rejects_overlong_input() {
    let banner = FtpHandler::new().with_preformatted_banner(format!(
        "220 {}",
        "界".repeat(FTP_SAFE_FIELD_MAX_CHARS + 16)
    ));

    assert!(banner.is_err());
}

#[test]
fn listing_names_escape_unicode_line_separators() {
    let rendered = safe_ftp_listing_name_os(OsStr::new("alpha\u{2028}beta"));

    assert!(!rendered.contains('\u{2028}'));
    assert!(!rendered.contains('\u{2029}'));
    assert!(!rendered.contains('\u{0085}'));
}

#[cfg(windows)]
#[test]
fn listing_names_preserve_non_utf16_values_reversibly_on_windows() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let value = OsString::from_wide(&[0x0061, 0xd800, 0x0062]);
    let rendered = safe_ftp_listing_name_os(&value);

    assert_eq!(rendered, "hex:0061d8000062");
}

#[test]
fn preformatted_banner_cannot_inject_response_lines() {
    let banner = FtpHandler::new()
        .with_preformatted_banner("220-First line\r\n230 injected")
        .is_err();

    assert!(banner);
}

#[test]
fn preformatted_banner_preserves_known_multiline_presets() {
    let banner = FtpHandler::new()
        .with_preformatted_banner(resolve_banner("!iis7"))
        .expect("valid FTP preset banner")
        .get_banner();
    let text = String::from_utf8_lossy(&banner);

    assert!(text.contains("Microsoft FTP Service"));
    assert!(text.contains("nettrap"));
    assert!(text.matches("\r\n").count() >= 2);
}

#[test]
fn ftp_response_messages_are_single_line() {
    let response = FtpResponse::new(257, "\"safe\"\r\n220 injected").to_bytes();
    let text = String::from_utf8_lossy(&response);

    assert!(text.contains("\"safe\""));
    assert!(!text.contains("injected"));
    assert_eq!(text.matches("\r\n").count(), 1);

    let long = "a".repeat(FTP_SAFE_FIELD_MAX_CHARS + 128);
    let response = FtpResponse::new(257, long).to_bytes();
    let text = String::from_utf8_lossy(&response);
    assert_eq!(
        text.trim_end_matches("\r\n")
            .strip_prefix("257 ")
            .expect("FTP response code prefix")
            .chars()
            .count(),
        FTP_SAFE_FIELD_MAX_CHARS
    );
}

#[test]
fn ftp_response_code_zero_without_raw_fails_closed() {
    let response = FtpResponse {
        code: 0,
        message: "214-Feature list\r\n214 End".to_string(),
        raw: None,
    }
    .to_bytes();

    assert_eq!(response, b"500 Internal server error\r\n");
}

#[test]
fn ftp_response_invalid_codes_fail_closed() {
    assert_eq!(
        FtpResponse::new(99, "bad").to_bytes(),
        b"500 Internal server error\r\n"
    );
    assert_eq!(
        FtpResponse::new(600, "bad").to_bytes(),
        b"500 Internal server error\r\n"
    );
}

#[test]
fn pasv_address_accepts_only_ipv4_or_four_octets() {
    let dotted = FtpHandler::new()
        .with_pasv_address("192.0.2.9")
        .expect("valid dotted IPv4");
    let response = dotted.handle("PASV");
    assert!(response.message.contains("(192,0,2,9,"));

    let comma = FtpHandler::new()
        .with_pasv_address("198,51,100,10")
        .expect("valid comma-separated IPv4");
    let response = comma.handle("PASV");
    assert!(response.message.contains("(198,51,100,10,"));
}

#[test]
fn pasv_address_canonicalizes_ipv4_mapped_ipv6_input() {
    let handler = FtpHandler::new()
        .with_pasv_address("::ffff:192.0.2.9")
        .expect("mapped IPv6 PASV address should be accepted");

    assert_eq!(handler.passive_address(), "192,0,2,9");
}

#[test]
fn pasv_address_rejects_unspecified_ipv4_address() {
    for address in ["0.0.0.0", "0,0,0,0"] {
        assert!(
            FtpHandler::new().with_pasv_address(address).is_err(),
            "unspecified PASV address should fail: {address}"
        );
    }
}

#[test]
fn pasv_address_rejects_loopback_multicast_and_broadcast_ipv4_addresses() {
    for address in [
        "127.0.0.1",
        "127,0,0,1",
        "224.0.0.1",
        "224,0,0,1",
        "255.255.255.255",
        "255,255,255,255",
    ] {
        assert!(
            FtpHandler::new().with_pasv_address(address).is_err(),
            "special PASV address should fail: {address}"
        );
    }
}

#[test]
fn pasv_address_rejects_surrounding_whitespace() {
    let err = match FtpHandler::new().with_pasv_address(" 192.0.2.9 ") {
        Ok(_) => panic!("whitespace-padded PASV address should fail"),
        Err(err) => err,
    };

    assert!(err.contains("Invalid PASV address"));
}

#[test]
fn pasv_address_rejects_unicode_whitespace() {
    let err = match FtpHandler::new().with_pasv_address("\u{00a0}192.0.2.9\u{00a0}") {
        Ok(_) => panic!("unicode-whitespace padded PASV address should fail"),
        Err(err) => err,
    };

    assert!(err.contains("Invalid PASV address"));
}

#[test]
fn malformed_pasv_address_returns_error() {
    let err = match FtpHandler::new().with_pasv_address("bad,51,100,10") {
        Ok(_) => panic!("invalid PASV address should fail"),
        Err(err) => err,
    };

    assert!(err.contains("Invalid PASV address"));
}

#[test]
fn pasv_port_range_is_preserved_before_rotation() {
    let handler = FtpHandler::new()
        .with_pasv_ports(60000, 60002)
        .expect("valid PASV range");

    assert_eq!(handler.passive_ports(), (60000, 60002));
    assert_eq!(handler.next_passive_port(), 60000);
    assert_eq!(handler.next_passive_port(), 60001);
    assert_eq!(handler.next_passive_port(), 60002);
    assert_eq!(handler.next_passive_port(), 60000);
}

#[test]
fn pasv_port_range_rejects_inverted_range() {
    let err = FtpHandler::new()
        .with_pasv_ports(60002, 60000)
        .expect_err("inverted PASV range should fail");

    assert!(err.contains("must not be inverted"));
}

#[test]
fn pasv_port_range_rejects_zero_ports_with_default_range() {
    for handler in [
        FtpHandler::new()
            .with_pasv_ports(0, 60000)
            .expect("zero start should reset"),
        FtpHandler::new()
            .with_pasv_ports(60000, 0)
            .expect("zero end should reset"),
        FtpHandler::new()
            .with_pasv_ports(0, 0)
            .expect("zero range should reset"),
    ] {
        assert_eq!(handler.passive_ports(), (60000, 60100));
        assert_eq!(handler.next_passive_port(), 60000);
    }
}

#[test]
fn pasv_and_epsv_reject_extra_arguments() {
    let handler = FtpHandler::new();

    for command in ["PASV now", "EPSV 1"] {
        let response = handler.handle(command);

        assert_eq!(response.code, 501, "{command}");
        assert_eq!(response.message, "Syntax error in parameters");
    }
}

#[test]
fn feat_serializes_as_raw_multiline_response() {
    let handler = FtpHandler::new();
    let response = handler.handle("FEAT").to_bytes();
    let text = String::from_utf8(response).expect("FEAT response should be UTF-8");

    assert!(text.starts_with("211-Features:\r\n"));
    assert!(text.contains("\r\n HOST\r\n"));
    assert!(text.contains("\r\n UTF8\r\n"));
    assert!(text.ends_with("211 End\r\n"));
}

#[test]
fn retr_rejects_control_characters_in_paths() {
    let response = FtpHandler::new()
        .prepare_data_transfer("RETR file.txt\t226 injected")
        .expect_err("control characters should be rejected in RETR paths");

    assert_eq!(response.code, 501);
    assert_eq!(response.message, "Syntax error in parameters");
}

#[test]
fn with_root_dir_rejects_empty_path() {
    let err = FtpHandler::new()
        .with_root_dir(PathBuf::new())
        .expect_err("empty root directory should be rejected");

    assert!(matches!(err, Error::Config(message) if message.contains("must not be empty")));
}

#[test]
fn retr_rejects_files_over_response_limit() {
    let root = unique_temp_dir("nettrap-ftp-limit");
    std::fs::create_dir_all(&root).expect("create temp root");
    let path = root.join("large.bin");
    let file = std::fs::File::create(&path).expect("create sparse file");
    file.set_len(MAX_FTP_RETR_BYTES + 1)
        .expect("extend sparse file");

    let response = FtpHandler::new()
        .with_root_dir(&root)
        .expect("valid FTP root")
        .prepare_data_transfer("RETR large.bin")
        .expect_err("large file should be rejected");

    assert_eq!(response.code, 552);
    assert!(response.raw.is_none());
    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

#[test]
fn retr_accepts_benign_dotted_filename_inside_root() {
    let root = unique_temp_dir("nettrap-ftp-dotted-name");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create temp root");
    std::fs::write(root.join("file..txt"), b"fixture").expect("write fixture");

    let transfer = FtpHandler::new()
        .with_root_dir(&root)
        .expect("valid FTP root")
        .prepare_data_transfer("RETR file..txt")
        .expect("dotted filename should be accepted");

    assert_eq!(transfer.start_response.code, 150);
    assert_eq!(transfer.data, b"fixture");
    assert_eq!(transfer.complete_response.code, 226);
    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

#[test]
fn listing_line_rejects_content_that_would_exceed_limit() {
    let mut listing = String::from("150 Here comes the directory listing.\r\n");
    let oversized_line = "x".repeat(MAX_FTP_LIST_BYTES);

    assert!(!FtpHandler::push_listing_line(
        &mut listing,
        &oversized_line
    ));
    assert!(listing.len() < MAX_FTP_LIST_BYTES);
}

#[test]
fn nlst_without_root_returns_bounded_virtual_listing() {
    let transfer = FtpHandler::new()
        .prepare_data_transfer("NLST")
        .expect("nlst transfer");

    assert_eq!(transfer.start_response.code, 150);
    assert!(String::from_utf8_lossy(&transfer.data).contains("index.html\r\n"));
    assert!(transfer.data.len() <= MAX_FTP_LIST_BYTES);
    assert_eq!(transfer.complete_response.code, 226);
}

#[test]
fn listing_transfers_reject_unsafe_path_arguments() {
    let handler = FtpHandler::new();

    for command in [
        "LIST ../secret",
        "LIST /tmp",
        "NLST ..\\secret",
        "NLST C:\\tmp",
    ] {
        let response = handler
            .prepare_data_transfer(command)
            .expect_err("unsafe listing argument must be rejected");

        assert_eq!(response.code, 550, "{command} must reject unsafe paths");
        assert_eq!(response.message, "Invalid path");
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn list_with_non_utf8_filename_preserves_distinct_entry_name() {
    let root = unique_temp_dir("nettrap-ftp-nonutf8-list");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create temp root");
    let name = OsString::from_vec(b"entry-\xff".to_vec());
    std::fs::write(root.join(&name), b"fixture").expect("write fixture");

    let transfer = FtpHandler::new()
        .with_root_dir(&root)
        .expect("valid FTP root")
        .prepare_data_transfer("NLST")
        .expect("nlst transfer");

    let listing = String::from_utf8_lossy(&transfer.data);
    assert!(listing.contains("entry-\\xff\r\n"));
    assert!(!listing.contains("unnamed\r\n"));

    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

#[cfg(unix)]
#[test]
fn list_with_spaces_preserves_entry_name() {
    let root = unique_temp_dir("nettrap-ftp-spaced-list");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create temp root");
    std::fs::write(root.join("  spaced name  "), b"fixture").expect("write fixture");

    let transfer = FtpHandler::new()
        .with_root_dir(&root)
        .expect("valid FTP root")
        .prepare_data_transfer("NLST")
        .expect("nlst transfer");

    let listing = String::from_utf8_lossy(&transfer.data);
    assert!(listing.contains("  spaced name  \r\n"));

    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

#[test]
fn empty_root_list_uses_bounded_virtual_listing() {
    let root = unique_temp_dir("nettrap-ftp-empty-list");
    std::fs::create_dir_all(&root).expect("create temp root");

    let transfer = FtpHandler::new()
        .with_root_dir(&root)
        .expect("valid FTP root")
        .prepare_data_transfer("LIST")
        .expect("list transfer");

    assert_eq!(transfer.start_response.code, 150);
    assert!(String::from_utf8_lossy(&transfer.data).contains("index.html"));
    assert!(transfer.data.len() <= MAX_FTP_LIST_BYTES);
    assert_eq!(transfer.complete_response.code, 226);
    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

#[test]
fn listing_uses_requested_subdirectory() {
    let root = unique_temp_dir("nettrap-ftp-subdir-list");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("subdir")).expect("create subdir");
    std::fs::write(root.join("root.txt"), b"root").expect("write root file");
    std::fs::write(root.join("subdir").join("nested.txt"), b"nested").expect("write nested file");

    let transfer = FtpHandler::new()
        .with_root_dir(&root)
        .expect("valid FTP root")
        .prepare_data_transfer("NLST subdir")
        .expect("nlst subdir transfer");
    let listing = String::from_utf8_lossy(&transfer.data);

    assert!(listing.contains("nested.txt\r\n"));
    assert!(!listing.contains("root.txt\r\n"));
    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

#[cfg(unix)]
#[test]
fn listing_rejects_symlinked_subdirectory() {
    let root = unique_temp_dir("nettrap-ftp-subdir-list-link");
    let target = unique_temp_dir("nettrap-ftp-subdir-list-target");
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&target);
    std::fs::create_dir_all(&root).expect("create temp root");
    std::fs::create_dir_all(&target).expect("create target dir");
    std::os::unix::fs::symlink(&target, root.join("linked")).expect("create symlink");

    let response = FtpHandler::new()
        .with_root_dir(&root)
        .expect("valid FTP root")
        .prepare_data_transfer("LIST linked")
        .expect_err("symlinked subdirectory should fail");

    assert_eq!(response.code, 550);
    assert_eq!(response.message, "Directory unavailable");
    std::fs::remove_dir_all(root).expect("cleanup temp root");
    std::fs::remove_dir_all(target).expect("cleanup target dir");
}

#[test]
fn configured_listing_root_must_be_readable_directory() {
    let root = unique_temp_dir("nettrap-ftp-root-file");
    let _ = std::fs::remove_file(&root);
    std::fs::write(&root, b"not a directory").expect("write root file");

    let response = FtpHandler::new()
        .with_root_dir(&root)
        .expect("valid FTP root")
        .prepare_data_transfer("LIST")
        .expect_err("configured non-directory root should fail");

    assert_eq!(response.code, 550);
    assert_eq!(response.message, "Directory unavailable");
    std::fs::remove_file(root).expect("cleanup root file");
}

#[cfg(unix)]
#[test]
fn configured_listing_root_rejects_symlinked_directory() {
    let root = unique_temp_dir("nettrap-ftp-root-link");
    let target = unique_temp_dir("nettrap-ftp-root-link-target");
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&target);
    std::fs::create_dir_all(&target).expect("create target dir");
    std::os::unix::fs::symlink(&target, &root).expect("create root symlink");

    let response = FtpHandler::new()
        .with_root_dir(&root)
        .expect("valid FTP root")
        .prepare_data_transfer("LIST")
        .expect_err("symlinked listing root should fail");

    assert_eq!(response.code, 550);
    assert_eq!(response.message, "Directory unavailable");
    std::fs::remove_dir_all(target).expect("cleanup target dir");
    std::fs::remove_file(root).expect("cleanup root symlink");
}

#[test]
fn list_fails_when_entry_metadata_cannot_be_read() {
    let response = detailed_listing_line(
        "vanished.txt",
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "synthetic metadata failure",
        )),
    )
    .expect_err("metadata failure should fail");

    assert_eq!(response.code, 550);
    assert_eq!(response.message, "Directory unavailable");
}

#[test]
fn list_fails_when_directory_iteration_returns_error() {
    let response = FtpHandler::build_listing_payload(
        Some(std::iter::once(Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "synthetic read_dir failure",
        )))),
        FtpListStyle::Detailed,
    )
    .expect_err("directory iteration error should fail");

    assert_eq!(response.code, 550);
    assert_eq!(response.message, "Directory unavailable");
}

#[test]
fn size_metadata_errors_are_not_reported_as_zero_length() {
    let response = size_response_from_metadata(
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "synthetic metadata failure",
        )),
        Path::new("firmware.bin"),
    );

    assert_eq!(response.code, 550);
    assert_eq!(response.message, "Access denied");
}

#[cfg(unix)]
#[test]
fn root_listing_sanitizes_control_characters_in_names() {
    let root = unique_temp_dir("nettrap-ftp-listing-control");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create temp root");
    std::fs::create_dir(root.join("subdir")).expect("create subdir");
    std::fs::write(root.join("safe\r\n226 injected.txt"), b"fixture").expect("write fixture");

    let transfer = FtpHandler::new()
        .with_root_dir(&root)
        .expect("valid FTP root")
        .prepare_data_transfer("LIST")
        .expect("list transfer");
    let listing = String::from_utf8_lossy(&transfer.data);

    assert!(listing.contains("safe"));
    assert!(!listing.contains("injected"));
    assert!(listing.contains("drwxr-xr-x"));
    assert_eq!(listing.matches("\r\n").count(), 2);
    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

#[cfg(unix)]
#[test]
fn root_listing_preserves_symlink_entry_kind() {
    let root = unique_temp_dir("nettrap-ftp-listing-symlink");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create temp root");
    std::fs::write(root.join("target.txt"), b"fixture").expect("write target");
    std::os::unix::fs::symlink("target.txt", root.join("link.txt")).expect("create symlink");

    let transfer = FtpHandler::new()
        .with_root_dir(&root)
        .expect("valid FTP root")
        .prepare_data_transfer("LIST")
        .expect("list transfer");
    let listing = String::from_utf8_lossy(&transfer.data);
    let symlink_line = listing
        .lines()
        .find(|line| line.ends_with("link.txt"))
        .expect("symlink entry should be listed");

    assert!(symlink_line.starts_with('l'));
    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

#[cfg(unix)]
#[test]
fn retr_logging_keeps_non_utf8_paths_distinct() {
    let path = PathBuf::from(OsString::from_vec(b"/tmp/entry-\xff.bin".to_vec()));

    let rendered = safe_ftp_reply_text_path(&path);

    assert!(rendered.contains("\\xff"));
    assert!(!rendered.contains('\u{fffd}'));
}

#[test]
fn retr_logging_preserves_path_spaces() {
    let path = PathBuf::from("  /tmp/spaced file  ");

    let rendered = safe_ftp_reply_text_path(&path);

    assert_eq!(rendered, "  /tmp/spaced file  ");
}

#[cfg(unix)]
#[test]
fn retr_logging_stops_at_control_bytes() {
    let path = PathBuf::from(OsString::from_vec(b"/tmp/file-\x1b[31minjected".to_vec()));

    let rendered = safe_ftp_reply_text_path(&path);

    assert_eq!(rendered, "/tmp/file-");
    assert!(!rendered.contains("injected"));
}

#[cfg(not(unix))]
#[test]
fn retr_logging_stops_at_control_bytes_non_unix() {
    let path = PathBuf::from("C:\\tmp\\file-\x1b[31minjected");

    let rendered = safe_ftp_reply_text_path(&path);

    assert_eq!(rendered, "C:\\tmp\\file-");
    assert!(!rendered.contains("injected"));
}

#[test]
fn retr_logging_is_bounded_for_long_paths() {
    let path = PathBuf::from(format!(
        "/tmp/{}",
        "a".repeat(FTP_SAFE_FIELD_MAX_CHARS + 64)
    ));

    let rendered = safe_ftp_reply_text_path(&path);

    assert!(rendered.chars().count() <= FTP_SAFE_FIELD_MAX_CHARS);
}

#[test]
fn handle_list_requires_passive_connection() {
    let response = FtpHandler::new().handle("LIST");

    assert_eq!(response.code, 425);
}

#[test]
fn handle_rejects_partial_line_terminators() {
    let handler = FtpHandler::new();

    assert_eq!(handler.handle("QUIT\r\n").code, 221);
    assert_eq!(handler.handle("QUIT").code, 221);
    assert_eq!(handler.handle("QUIT\n").code, 502);
    assert_eq!(handler.handle("QUIT\r").code, 502);
}

#[test]
fn prefixed_data_verbs_do_not_trigger_transfers() {
    let handler = FtpHandler::new();

    let response = handler
        .prepare_data_transfer("LISTEN")
        .expect_err("LISTEN must not be parsed as LIST");
    assert_eq!(response.code, 502);
    assert_eq!(response.message, "Unsupported data command");

    let response = handler.handle("RETRIEVE file.txt");
    assert_ne!(response.code, 425);

    let response = handler.handle("PASVXYZ");
    assert_ne!(response.code, 227);
}

#[test]
fn tab_separated_ftp_commands_are_rejected() {
    let handler = FtpHandler::new();

    let response = handler.handle("USER\tname");
    assert_eq!(response.code, 502);

    let response = handler
        .prepare_data_transfer("RETR\tfile.txt")
        .expect_err("tab separated FTP transfer commands must be rejected");
    assert_eq!(response.code, 502);
}

#[test]
fn trailing_tabs_do_not_create_valid_ftp_verbs() {
    let handler = FtpHandler::new();

    assert_eq!(handler.handle("QUIT\t").code, 502);
    assert_eq!(handler.handle("NOOP\t").code, 502);
}

#[test]
fn trailing_spaces_do_not_create_valid_zero_argument_ftp_commands() {
    let handler = FtpHandler::new();

    for command in [
        "PWD ", "XPWD ", "PASV ", "EPSV ", "SYST ", "REIN ", "FEAT ", "CDUP ", "NOOP ", "STAT ",
        "ABOR ", "QUIT ",
    ] {
        let response = handler.handle(command);

        assert_eq!(response.code, 501, "{command}");
        assert_eq!(response.message, "Syntax error in parameters", "{command}");
    }
}

#[test]
fn leading_whitespace_ftp_commands_are_rejected() {
    let handler = FtpHandler::new();

    assert_eq!(handler.handle(" USER name").code, 502);
    assert_eq!(handler.handle(" PASV").code, 502);
    assert_eq!(handler.handle(" OPTS UTF8 ON").code, 502);
    assert_eq!(handler.handle(" ALLO 1024").code, 502);

    let response = handler
        .prepare_data_transfer(" RETR file.txt")
        .expect_err("leading-whitespace RETR must be rejected");
    assert_eq!(response.code, 502);

    let response = parse_ftp_data_addr(" PORT 127,0,0,1,4,20")
        .expect_err("leading-whitespace PORT must be rejected");
    assert_eq!(response.code, 501);
}

#[test]
fn embedded_line_breaks_in_commands_are_rejected() {
    let handler = FtpHandler::new();

    assert_eq!(handler.handle("QUIT\r\nNOOP").code, 502);
    assert_eq!(handler.handle("CWD /tmp\r\nMKD injected").code, 502);

    let response = parse_ftp_data_addr("PORT 127,0,0,1,4,20\r\nNOOP")
        .expect_err("embedded line breaks must be rejected");
    assert_eq!(response.code, 501);
}

#[test]
fn tab_separated_ftp_options_and_allo_are_rejected() {
    let handler = FtpHandler::new();

    assert_eq!(handler.handle("OPTS UTF8\tON").code, 501);
    assert_eq!(handler.handle("ALLO 1024\tR\t512").code, 501);
    assert_eq!(handler.handle("ALLO 1024  R 512").code, 501);
    assert_eq!(handler.handle("OPTS UTF8  ON").code, 501);
}

#[test]
fn port_command_rejects_whitespace_within_octets() {
    let response = parse_ftp_data_addr("PORT 127, 0,0,1,8,1").expect_err("spaced PORT must fail");

    assert_eq!(response.code, 501);
}

#[test]
fn unknown_commands_are_not_successful() {
    let response = FtpHandler::new().handle("INVALID");

    assert_eq!(response.code, 502);
    assert_eq!(response.message, "Command not recognized");
}

#[test]
fn oversized_control_lines_are_rejected() {
    let command = format!("USER {}", "a".repeat(513));
    let response = FtpHandler::new().handle(&command);

    assert_eq!(response.code, 502);
    assert_eq!(response.message, "Command not recognized");
}

#[test]
fn common_ftp_control_commands_have_explicit_responses() {
    let handler = FtpHandler::new();

    assert_eq!(handler.handle("REST 0").code, 350);
    assert_eq!(handler.handle("REST abc").code, 501);
    assert_eq!(handler.handle("REST 0 extra").code, 501);
    assert_eq!(handler.handle("ALLO 1024").code, 202);
    assert_eq!(handler.handle("ALLO 1024 R 512").code, 202);
    assert_eq!(handler.handle("ALLO 1024 X 512").code, 501);
    assert_eq!(handler.handle("MODE S").code, 200);
    assert_eq!(handler.handle("MODE s").code, 200);
    assert_eq!(handler.handle("MODE B").code, 504);
    assert_eq!(handler.handle("STRU F").code, 200);
    assert_eq!(handler.handle("STRU f").code, 200);
    assert_eq!(handler.handle("STRU R").code, 504);
    assert_eq!(handler.handle("ACCT billing").code, 230);
    assert_eq!(handler.handle("ACCT").code, 501);
    assert_eq!(handler.handle("REIN").code, 220);
    assert_eq!(handler.handle("SMNT /mnt").code, 502);
    assert_eq!(handler.handle("SMNT").code, 501);
    assert!(
        handler
            .handle("HELP")
            .to_bytes()
            .windows(4)
            .any(|w| w == b"HOST")
    );
    assert_eq!(handler.handle("USER alice extra").code, 501);
    assert_eq!(handler.handle("PASS secret extra").code, 501);
    assert_eq!(handler.handle("ACCT billing extra").code, 501);
    assert_eq!(handler.handle("SMNT /mnt extra").code, 501);
    assert_eq!(handler.handle("PWD extra").code, 501);
    assert_eq!(handler.handle("SYST extra").code, 501);
    assert_eq!(handler.handle("FEAT extra").code, 501);
    assert_eq!(handler.handle("HELP extra").code, 501);
    assert_eq!(handler.handle("CDUP extra").code, 501);
    assert_eq!(handler.handle("NOOP extra").code, 501);
    assert_eq!(handler.handle("STAT extra").code, 501);
    assert_eq!(handler.handle("ABOR extra").code, 501);
    assert_eq!(handler.handle("QUIT extra").code, 501);
}

#[test]
fn opts_utf8_is_honoured_since_feat_advertises_it() {
    let handler = FtpHandler::new();

    assert_eq!(handler.handle("OPTS UTF8 ON").code, 200);
    assert_eq!(handler.handle("OPTS UTF8 OFF").code, 200);
    assert_eq!(handler.handle("opts utf8 on").code, 200);
    assert_eq!(handler.handle("OPTS UTF8").code, 200);

    assert_eq!(handler.handle("OPTS UTF8 MAYBE").code, 501);
    assert_eq!(handler.handle("OPTS MLST").code, 501);
    let missing = handler.handle("OPTS");
    assert_eq!(missing.code, 501);
    assert_eq!(missing.message, "Syntax error in parameters");
}

#[test]
fn opts_rejects_extra_arguments() {
    let handler = FtpHandler::new();

    let response = handler.handle("OPTS UTF8 ON extra");

    assert_eq!(response.code, 501);
    assert_eq!(response.message, "Syntax error in parameters");
}

#[test]
fn mode_and_structure_reject_extra_arguments() {
    let handler = FtpHandler::new();

    for command in ["MODE S extra", "STRU F extra"] {
        let response = handler.handle(command);
        assert_eq!(response.code, 501, "{command}");
        assert_eq!(response.message, "Syntax error in parameters", "{command}");
    }
}

#[test]
fn opts_rejects_unicode_whitespace_separators() {
    let handler = FtpHandler::new();

    assert_eq!(handler.handle("OPTS UTF8\tON").code, 501);
    assert_eq!(handler.handle("OPTS UTF8\u{00a0}ON").code, 501);
    assert_eq!(handler.handle("OPTS UTF8\u{00a0}OFF").code, 501);
}

#[test]
fn user_and_pass_require_arguments() {
    let handler = FtpHandler::new();

    let user = handler.handle("USER");
    assert_eq!(user.code, 501);
    assert_eq!(user.message, "Missing argument");

    let pass = handler.handle("PASS");
    assert_eq!(pass.code, 501);
    assert_eq!(pass.message, "Missing argument");
}

#[test]
fn size_and_mdtm_require_filename() {
    let handler = FtpHandler::new();

    let size = handler.handle("SIZE");
    assert_eq!(size.code, 501);
    assert_eq!(size.message, "Missing argument");

    let mdtm = handler.handle("MDTM");
    assert_eq!(mdtm.code, 501);
    assert_eq!(mdtm.message, "Missing argument");

    let size_with_filename = handler.handle("SIZE file.txt");
    assert_eq!(size_with_filename.code, 213);
    assert_eq!(size_with_filename.message, "0");

    let mdtm_with_filename = handler.handle("MDTM file.txt");
    assert_eq!(mdtm_with_filename.code, 213);
    assert_eq!(mdtm_with_filename.message.len(), 14);
    assert!(
        mdtm_with_filename
            .message
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    );
    assert_ne!(mdtm_with_filename.message, "20240101000000");
}

#[test]
fn mdtm_uses_injected_clock_for_timestamp() {
    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant")
    }

    let handler = FtpHandler::new().with_now(fixed_now);
    let response = handler.handle("MDTM file.txt");

    assert_eq!(response.code, 213);
    assert_eq!(response.message, "20240101000000");
}

#[test]
fn mdtm_timestamp_uses_supplied_utc_time() {
    let now = chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant");

    assert_eq!(format_mdtm_timestamp(now), "20240101000000");
}

#[test]
fn path_commands_require_arguments() {
    let handler = FtpHandler::new();

    let cwd = handler.handle("CWD");
    assert_eq!(cwd.code, 501);
    assert_eq!(cwd.message, "Missing argument");

    let cwd_relative = handler.handle("CWD subdir");
    assert_eq!(cwd_relative.code, 250);

    let cdup = handler.handle("CDUP");
    assert_eq!(cdup.code, 250);

    for command in ["MKD", "XMKD", "RMD", "XRMD", "DELE", "RNFR", "RNTO"] {
        let response = handler.handle(command);
        assert_eq!(response.code, 501, "{command} must require an argument");
        assert_eq!(response.message, "Missing argument");
    }

    assert_eq!(handler.handle("MKD new").code, 257);
    assert_eq!(handler.handle("XMKD new").code, 257);
    assert_eq!(handler.handle("RMD old").code, 250);
    assert_eq!(handler.handle("XRMD old").code, 250);
    assert_eq!(handler.handle("DELE file").code, 250);
    assert_eq!(handler.handle("RNFR old").code, 350);
    assert_eq!(handler.handle("RNTO new").code, 250);
}

#[test]
fn path_commands_reject_traversal_and_absolute_paths() {
    let handler = FtpHandler::new();

    for command in [
        "MDTM ../secret",
        "CWD /tmp",
        "MKD ..\\secret",
        "XMKD ../secret",
        "RMD /tmp",
        "XRMD ../secret",
        "DELE ..\\secret",
        "RNFR /tmp/old",
        "RNTO ../new",
    ] {
        let response = handler.handle(command);
        assert_eq!(response.code, 550, "{command} must reject unsafe paths");
        assert_eq!(response.message, "Invalid path");
    }

    for command in ["CWD C:\\tmp", "CWD C:/tmp", "RMD C:\\tmp"] {
        let response = handler.handle(command);
        assert_eq!(response.code, 550, "{command} must reject unsafe paths");
        assert_eq!(response.message, "Invalid path");
    }

    let command = "CWD file:stream";
    let response = handler.handle(command);
    assert_eq!(response.code, 550, "{command} must reject unsafe paths");
    assert_eq!(response.message, "Invalid path");
}

#[test]
fn mkdir_responses_sanitize_reflected_paths() {
    let sanitized = safe_ftp_reply_text("new\r\n250 injected");

    assert_eq!(sanitized, "new");
    assert_eq!(
        FtpResponse::new(257, format!("\"{}\" directory created", sanitized)).to_bytes(),
        b"257 \"new\" directory created\r\n"
    );
}

#[test]
fn type_validates_transfer_mode() {
    let handler = FtpHandler::new();

    let ascii = handler.handle("TYPE A");
    assert_eq!(ascii.code, 200);
    assert_eq!(ascii.message, "Type set to A");

    let binary = handler.handle("TYPE I");
    assert_eq!(binary.code, 200);
    assert_eq!(binary.message, "Type set to I");

    let local = handler.handle("TYPE L 8");
    assert_eq!(local.code, 200);
    assert_eq!(local.message, "Type set to L 8");

    for command in ["TYPE", "TYPE E", "TYPE L 7", "TYPE I extra"] {
        let response = handler.handle(command);
        assert_eq!(response.code, 504, "{command} must be rejected");
        assert_eq!(response.message, "Unsupported type");
    }

    let response = handler.handle("TYPE I\textra");
    assert_eq!(response.code, 501);
    assert_eq!(response.message, "Syntax error in parameters");

    let response = handler.handle("TYPE L  8");
    assert_eq!(response.code, 501);
    assert_eq!(response.message, "Syntax error in parameters");

    let response = handler.handle("TYPE \u{00a0}I");
    assert_eq!(response.code, 504);
    assert_eq!(response.message, "Unsupported type");
}

#[cfg(unix)]
#[test]
fn retr_rejects_final_symlink_inside_root() {
    use std::os::unix::fs::symlink;

    let root = unique_temp_dir("nettrap-ftp-symlink");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create temp root");
    std::fs::write(root.join("real.txt"), b"secret").expect("write fixture");
    symlink("real.txt", root.join("link.txt")).expect("create symlink");

    let response = FtpHandler::new()
        .with_root_dir(&root)
        .expect("valid FTP root")
        .prepare_data_transfer("RETR link.txt")
        .expect_err("final symlink should be rejected");

    assert_eq!(response.code, 550);
    assert_eq!(response.message, "Access denied");
    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

#[cfg(unix)]
#[test]
fn retr_rejects_intermediate_symlink_escape() {
    use std::os::unix::fs::symlink;

    let root = unique_temp_dir("nettrap-ftp-intermediate-symlink");
    let outside = unique_temp_dir("nettrap-ftp-intermediate-outside");
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&root).expect("create temp root");
    std::fs::create_dir_all(&outside).expect("create outside dir");
    std::fs::write(outside.join("secret.txt"), b"secret").expect("write outside fixture");
    symlink(&outside, root.join("dir")).expect("create intermediate symlink");

    let response = FtpHandler::new()
        .with_root_dir(&root)
        .expect("valid FTP root")
        .prepare_data_transfer("RETR dir/secret.txt")
        .expect_err("intermediate symlink should be rejected");

    assert_eq!(response.code, 550);
    assert_eq!(response.message, "Access denied");
    std::fs::remove_dir_all(root).expect("cleanup temp root");
    std::fs::remove_dir_all(outside).expect("cleanup outside dir");
}

#[cfg(unix)]
#[test]
fn size_rejects_symlink_inside_root_as_access_denied() {
    use std::os::unix::fs::symlink;

    let root = unique_temp_dir("nettrap-ftp-size-symlink");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create temp root");
    std::fs::write(root.join("real.txt"), b"secret").expect("write fixture");
    symlink("real.txt", root.join("link.txt")).expect("create symlink");

    let response = FtpHandler::new()
        .with_root_dir(&root)
        .expect("valid FTP root")
        .handle("SIZE link.txt");

    assert_eq!(response.code, 550);
    assert_eq!(response.message, "Access denied");
    std::fs::remove_dir_all(root).expect("cleanup temp root");
}

static TEMP_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let seq = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{seq}", std::process::id()))
}

#[test]
fn stor_and_appe_open_a_receive_transfer() {
    let handler = FtpHandler::new();
    for cmd in ["STOR upload.bin", "APPE log.txt"] {
        let transfer = handler
            .prepare_data_transfer(cmd)
            .unwrap_or_else(|_| panic!("{cmd} must open a transfer"));
        assert!(transfer.receive, "{cmd} must be a receive transfer");
        assert!(transfer.data.is_empty(), "uploads are never echoed back");
        assert_eq!(transfer.start_response.code, 150);
        assert_eq!(transfer.complete_response.code, 226);
    }
}

#[test]
fn file_transfers_require_filenames() {
    let handler = FtpHandler::new();

    for command in ["RETR", "STOR", "APPE"] {
        let response = handler
            .prepare_data_transfer(command)
            .expect_err("file transfer command without filename must be rejected");

        assert_eq!(response.code, 501, "{command} must reject missing filename");
        assert_eq!(response.message, "Missing argument");
    }
}

#[test]
fn stor_rejects_path_traversal() {
    let response = FtpHandler::new()
        .prepare_data_transfer("STOR ../../etc/passwd")
        .expect_err("traversal upload must be rejected");
    assert_eq!(response.code, 550);
}

#[test]
fn upload_transfers_reject_unicode_whitespace_paths() {
    for command in ["STOR upload\u{00a0}.bin", "APPE log\u{00a0}.txt"] {
        let response = FtpHandler::new()
            .prepare_data_transfer(command)
            .expect_err("upload paths must use the shared safe path validator");
        assert_eq!(response.code, 501, "{command} must reject unsafe paths");
        assert_eq!(response.message, "Syntax error in parameters");
    }
}

#[test]
fn retr_rejects_unicode_whitespace_paths() {
    let response = FtpHandler::new()
        .prepare_data_transfer("RETR file\u{00a0}.txt")
        .expect_err("download paths must use the shared safe path validator");

    assert_eq!(response.code, 501);
    assert_eq!(response.message, "Syntax error in parameters");
}

#[test]
fn file_transfers_reject_colon_separated_paths() {
    let handler = FtpHandler::new();

    let response = handler
        .prepare_data_transfer("RETR file:stream")
        .expect_err("colon-bearing download path must be rejected");
    assert_eq!(response.code, 550);
    assert_eq!(response.message, "Invalid path");
}

#[test]
fn parse_port_command_yields_socket_addr() {
    let addr = parse_ftp_data_addr("PORT 192,0,2,5,4,210").expect("valid PORT");
    assert_eq!(addr.ip().to_string(), "192.0.2.5");
    assert_eq!(addr.port(), 4 * 256 + 210);
}

#[test]
fn parse_active_addr_rejects_unspecified_ip_literals() {
    for command in [
        "PORT 0,0,0,0,4,210",
        "EPRT |1|0.0.0.0|2048|",
        "EPRT |2|::|2048|",
        "EPRT |2|::ffff:0.0.0.0|2048|",
    ] {
        assert!(
            parse_ftp_data_addr(command).is_err(),
            "unspecified address should fail: {command}"
        );
    }
}

#[test]
fn parse_active_addr_rejects_loopback_and_multicast_literals() {
    for command in [
        "PORT 127,0,0,1,4,210",
        "PORT 224,0,0,1,4,210",
        "PORT 255,255,255,255,4,210",
        "EPRT |1|127.0.0.1|2048|",
        "EPRT |1|224.0.0.1|2048|",
        "EPRT |1|255.255.255.255|2048|",
        "EPRT |2|::1|2048|",
        "EPRT |2|ff02::1|2048|",
        "EPRT |2|::ffff:127.0.0.1|2048|",
    ] {
        assert!(
            parse_ftp_data_addr(command).is_err(),
            "special address should fail: {command}"
        );
    }
}

#[test]
fn parse_eprt_command_yields_socket_addr() {
    let addr = parse_ftp_data_addr("EPRT |1|192.0.2.7|2048|").expect("valid EPRT");
    assert_eq!(addr.ip().to_string(), "192.0.2.7");
    assert_eq!(addr.port(), 2048);
}

#[test]
fn parse_eprt_command_canonicalizes_ipv4_mapped_socket_addr() {
    let addr = parse_ftp_data_addr("EPRT |2|::ffff:192.0.2.7|2048|").expect("valid EPRT");
    assert_eq!(addr.ip().to_string(), "192.0.2.7");
    assert_eq!(addr.port(), 2048);
}

#[test]
fn parse_malformed_active_addr_is_501() {
    for bad in [
        "PORT 1,2,3",
        "PORT 999,0,0,1,4,2",
        "PORT 1,2,3,4,0,0",
        "PORT +192,0,2,5,4,210",
        "PORT 192,0,2,5,+4,210",
        "EPRT |1|notanip|80|",
        "EPRT |1|192.0.2.7|+2048|",
        "EPRT 1|192.0.2.1|80",
        "PORT",
    ] {
        let err = parse_ftp_data_addr(bad).expect_err("must reject");
        assert_eq!(err.code, 501, "{bad} should be a 501");
    }
}

#[test]
fn handle_port_acknowledges_well_formed_address() {
    let response = FtpHandler::new().handle("PORT 198,51,100,2,8,0");
    assert_eq!(response.code, 200);
}

#[test]
fn handle_eprt_acknowledges_well_formed_address() {
    let response = FtpHandler::new().handle("EPRT |1|198.51.100.2|2048|");
    assert_eq!(response.code, 200);
    assert!(response.message.starts_with("EPRT "));
}
