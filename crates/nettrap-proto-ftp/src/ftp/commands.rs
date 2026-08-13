use super::{FTP_SAFE_FIELD_MAX_CHARS, FtpResponse};
use std::path::Path;

const FTP_MAX_COMMAND_LINE_BYTES: usize = 512;

fn split_ftp_command(command: &str) -> Option<(&str, &str)> {
    let line = ftp_command_line(command)?;
    if line.chars().next().is_some_and(char::is_whitespace) {
        return None;
    }
    if line.chars().any(|ch| matches!(ch, '\r' | '\n' | '\0')) {
        return None;
    }

    let verb_end = line.find(' ').unwrap_or(line.len());
    let verb = &line[..verb_end];
    let arg = match line[verb_end..].strip_prefix(' ') {
        Some(arg) if !arg.starts_with([' ', '\t']) => arg,
        Some(_) => return None,
        None if verb_end == line.len() => "",
        None => return None,
    };
    Some((verb, arg))
}

fn ftp_command_line(command: &str) -> Option<&str> {
    if nettrap_core::sanitize::contains_unicode_line_separator(command) {
        return None;
    }
    if let Some(line) = command.strip_suffix("\r\n") {
        if line.chars().any(|ch| matches!(ch, '\r' | '\n')) {
            return None;
        }
        return bounded_ftp_command_line(line);
    }
    if command.ends_with(['\r', '\n']) {
        return None;
    }
    if command.chars().any(|ch| matches!(ch, '\r' | '\n')) {
        return None;
    }
    bounded_ftp_command_line(command)
}

fn bounded_ftp_command_line(line: &str) -> Option<&str> {
    (line.len() <= FTP_MAX_COMMAND_LINE_BYTES).then_some(line)
}

pub(crate) fn has_path_traversal(s: &str) -> bool {
    if s.starts_with(['/', '\\'])
        || s.contains('\0')
        || s.contains(':')
        || s.chars().any(char::is_control)
    {
        return true;
    }

    if nettrap_core::parse::looks_like_windows_drive_path(s) {
        return true;
    }

    s.split(['/', '\\']).any(|segment| segment == "..")
}

pub(crate) fn command_verb(command: &str) -> String {
    let Some((verb, _)) = split_ftp_command(command) else {
        return String::new();
    };
    verb.to_ascii_uppercase()
}

/// Parse the client's active-mode data address from a `PORT` or `EPRT`
/// command. Pure function (no I/O): the connection layer applies the
/// connect-back safety policy. Returns a `501` response on any malformed
/// argument so callers can forward it verbatim.
pub fn parse_ftp_data_addr(command: &str) -> Result<std::net::SocketAddr, FtpResponse> {
    let syntax_err = || FtpResponse::new(501, "Syntax error in parameters");
    let verb = command_verb(command);
    let arg = command_arg(command);

    if verb == "PORT" {
        let parts: Vec<&str> = arg.split(',').collect();
        if parts.len() != 6 {
            return Err(syntax_err());
        }
        let mut octets = [0u8; 4];
        let [p0, p1, p2, p3, p4, p5] = parts.as_slice() else {
            return Err(syntax_err());
        };
        for (slot, part) in octets.iter_mut().zip([p0, p1, p2, p3]) {
            if part.is_empty()
                || part.chars().next().is_some_and(char::is_whitespace)
                || part.chars().last().is_some_and(char::is_whitespace)
            {
                return Err(syntax_err());
            }
            *slot = parse_ftp_decimal(part).ok_or_else(syntax_err)?;
        }
        let ip = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
        if !is_usable_ftp_active_ipv4(ip) {
            return Err(syntax_err());
        }
        if p4.is_empty()
            || p4.chars().next().is_some_and(char::is_whitespace)
            || p4.chars().last().is_some_and(char::is_whitespace)
            || p5.is_empty()
            || p5.chars().next().is_some_and(char::is_whitespace)
            || p5.chars().last().is_some_and(char::is_whitespace)
        {
            return Err(syntax_err());
        }
        let p1 = parse_ftp_decimal::<u16>(p4).ok_or_else(syntax_err)?;
        let p2 = parse_ftp_decimal::<u16>(p5).ok_or_else(syntax_err)?;
        if p1 > 255 || p2 > 255 {
            return Err(syntax_err());
        }
        let port = (p1 << 8) | p2;
        if port == 0 {
            return Err(syntax_err());
        }
        return Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port));
    }

    if verb == "EPRT" {
        let delim = arg.chars().next().filter(|c| is_valid_eprt_delimiter(*c));
        let Some(delim) = delim else {
            return Err(syntax_err());
        };
        let mut fields = arg.split(delim);
        let first = fields.next().unwrap_or("");
        let proto = fields.next().ok_or_else(syntax_err)?;
        let addr = fields.next().ok_or_else(syntax_err)?;
        let port = fields.next().ok_or_else(syntax_err)?;
        let trailing = fields.next().unwrap_or("");
        let remaining = fields.next();
        if !first.is_empty() || !trailing.is_empty() || remaining.is_some() {
            return Err(syntax_err());
        }
        let port = parse_ftp_decimal::<u16>(port).ok_or_else(syntax_err)?;
        if port == 0 {
            return Err(syntax_err());
        }
        let ip = match proto {
            "1" => {
                let ip = addr
                    .parse::<std::net::Ipv4Addr>()
                    .map_err(|_| syntax_err())?;
                if !is_usable_ftp_active_ipv4(ip) {
                    return Err(syntax_err());
                }
                std::net::IpAddr::V4(ip)
            }
            "2" => {
                let ip = addr
                    .parse::<std::net::Ipv6Addr>()
                    .map_err(|_| syntax_err())?;
                if !is_usable_ftp_active_ipv6(ip) {
                    return Err(syntax_err());
                }
                normalize_ftp_active_ip(std::net::IpAddr::V6(ip))
            }
            _ => {
                return Err(FtpResponse::new(
                    522,
                    "Network protocol not supported, use (1,2)",
                ));
            }
        };
        return Ok(std::net::SocketAddr::new(ip, port));
    }

    Err(syntax_err())
}

fn is_usable_ftp_active_ipv4(ip: std::net::Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
}

fn is_usable_ftp_active_ipv6(ip: std::net::Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_usable_ftp_active_ipv4(mapped);
    }

    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
}

fn normalize_ftp_active_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V4(ip) => std::net::IpAddr::V4(ip),
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
    }
}

fn is_valid_eprt_delimiter(delim: char) -> bool {
    delim.is_ascii_graphic() && !delim.is_ascii_alphanumeric()
}

fn parse_ftp_decimal<T>(value: &str) -> Option<T>
where
    T: std::str::FromStr,
{
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

pub(crate) fn command_arg(command: &str) -> &str {
    let Some((_, arg)) = split_ftp_command(command) else {
        return "";
    };
    arg
}

/// Returns true when an FTP command line contains an argument separator after the verb.
pub fn ftp_command_has_args(command: &str) -> bool {
    let Some(line) = ftp_command_line(command) else {
        return false;
    };
    if line.chars().next().is_some_and(char::is_whitespace) {
        return false;
    }
    if line.chars().any(|ch| matches!(ch, '\r' | '\n' | '\0')) {
        return false;
    }

    let verb_end = line.find(' ').unwrap_or(line.len());
    line[verb_end..].starts_with(' ')
}

pub(crate) fn safe_ftp_single_line(value: &str, fallback: &str) -> String {
    let mut sanitized = String::new();
    let mut previous_space = false;
    let mut chars_written = 0usize;

    for ch in value.chars() {
        if matches!(ch, '\r' | '\n' | '\0') {
            break;
        }
        let ch = if ch.is_control() { ' ' } else { ch };
        if ch.is_whitespace() {
            if !previous_space {
                if chars_written >= FTP_SAFE_FIELD_MAX_CHARS {
                    break;
                }
                sanitized.push(' ');
                chars_written += 1;
                previous_space = true;
            }
        } else {
            if chars_written >= FTP_SAFE_FIELD_MAX_CHARS {
                break;
            }
            sanitized.push(ch);
            chars_written += 1;
            previous_space = false;
        }
    }

    if sanitized.is_empty()
        || sanitized.chars().next().is_some_and(char::is_whitespace)
        || sanitized.chars().last().is_some_and(char::is_whitespace)
    {
        fallback.to_string()
    } else {
        sanitized
    }
}

pub(crate) fn safe_ftp_reply_text(value: &str) -> String {
    safe_ftp_single_line(value, "")
}

pub(crate) fn safe_ftp_reply_text_path(path: &Path) -> String {
    #[cfg(unix)]
    {
        use std::fmt::Write as _;
        use std::os::unix::ffi::OsStrExt;

        let mut rendered = String::new();
        let mut chars_written = 0usize;
        for byte in path.as_os_str().as_bytes() {
            match byte {
                b if b.is_ascii_control() => {
                    break;
                }
                b if b.is_ascii_graphic() || *b == b' ' => {
                    if chars_written + 1 > FTP_SAFE_FIELD_MAX_CHARS {
                        break;
                    }
                    rendered.push(*b as char);
                    chars_written += 1;
                }
                b => {
                    if chars_written + 4 > FTP_SAFE_FIELD_MAX_CHARS {
                        break;
                    }
                    let _ = write!(&mut rendered, "\\x{:02x}", b);
                    chars_written += 4;
                }
            }
        }
        rendered
    }

    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        {
            use std::fmt::Write as _;
            use std::os::windows::ffi::OsStrExt;

            if let Some(value) = path.to_str() {
                let mut rendered = String::new();
                for ch in value.chars() {
                    if ch.is_control() || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}') {
                        break;
                    }
                    if rendered.chars().count() >= FTP_SAFE_FIELD_MAX_CHARS {
                        break;
                    }
                    rendered.push(ch);
                }
                return rendered;
            }

            let mut rendered = String::from("hex:");
            let mut chars_written = rendered.len();
            for unit in path.as_os_str().encode_wide() {
                if chars_written + 4 > FTP_SAFE_FIELD_MAX_CHARS {
                    break;
                }
                let _ = write!(&mut rendered, "{:04x}", unit);
                chars_written += 4;
            }
            rendered
        }

        #[cfg(all(not(unix), not(windows)))]
        {
            let mut rendered = String::new();
            for ch in path.to_string_lossy().chars() {
                if ch.is_control() || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}') {
                    break;
                }
                rendered.push(ch);
            }
            rendered
        }
    }
}

pub(crate) fn safe_ftp_banner_field(value: &str, fallback: &str) -> String {
    if nettrap_core::sanitize::contains_unicode_line_separator(value) {
        return fallback.to_string();
    }

    let mut rendered = String::new();
    for (chars_written, ch) in value.chars().enumerate() {
        if matches!(ch, '\r' | '\n' | '\0') {
            break;
        }
        let ch = if ch.is_control() { ' ' } else { ch };
        if chars_written >= FTP_SAFE_FIELD_MAX_CHARS {
            break;
        }
        rendered.push(ch);
    }

    if rendered.trim().is_empty() {
        fallback.to_string()
    } else {
        rendered
    }
}

pub(crate) fn safe_ftp_custom_banner(value: &str) -> String {
    let field = safe_ftp_banner_field(value, "NetTrap FTP Ready");
    if field.starts_with("220 ") || field.starts_with("220-") {
        field
    } else {
        format!("220 {}", field)
    }
}

pub(crate) fn missing_argument() -> FtpResponse {
    FtpResponse::new(501, "Missing argument")
}

pub(crate) fn required_arg(command: &str) -> Result<&str, FtpResponse> {
    let arg = command_arg(command);
    if arg.is_empty() {
        Err(missing_argument())
    } else {
        Ok(arg)
    }
}

pub(crate) fn type_response(command: &str) -> FtpResponse {
    let arg = command_arg(command);
    if arg.is_empty() {
        return FtpResponse::new(504, "Unsupported type");
    }

    let mut args = arg.split(' ');
    if args.clone().any(|token| {
        token.is_empty()
            || token
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    }) {
        return FtpResponse::new(501, "Syntax error in parameters");
    }
    match (args.next(), args.next(), args.next()) {
        (Some(mode), None, None) if mode.eq_ignore_ascii_case("A") => {
            FtpResponse::new(200, "Type set to A")
        }
        (Some(mode), None, None) if mode.eq_ignore_ascii_case("I") => {
            FtpResponse::new(200, "Type set to I")
        }
        (Some(mode), Some("8"), None) if mode.eq_ignore_ascii_case("L") => {
            FtpResponse::new(200, "Type set to L 8")
        }
        _ => FtpResponse::new(504, "Unsupported type"),
    }
}

#[cfg(test)]
mod tests {
    use super::{command_verb, parse_ftp_data_addr, type_response};

    #[test]
    fn type_response_rejects_unicode_whitespace_after_verb() {
        assert_eq!(type_response("TYPE \u{00a0}I").code, 504);
    }

    #[test]
    fn type_response_rejects_tab_separated_arguments() {
        assert_eq!(type_response("TYPE I\textra").code, 501);
    }

    #[test]
    fn command_verb_rejects_partial_line_terminators() {
        assert_eq!(command_verb("QUIT\r\n"), "QUIT");
        assert_eq!(command_verb("QUIT"), "QUIT");
        assert_eq!(command_verb("QUIT\n"), "");
        assert_eq!(command_verb("QUIT\r"), "");
    }

    #[test]
    fn command_verb_rejects_embedded_crlf_injection() {
        assert_eq!(command_verb("QUIT\r\nNOOP"), "");
        assert_eq!(command_verb("TYPE I\r\nUSER anonymous"), "");
    }

    #[test]
    fn command_verb_rejects_unicode_line_separators() {
        assert_eq!(command_verb("QUIT\u{2028}NOOP"), "");
    }

    #[test]
    fn safe_ftp_custom_banner_rejects_unicode_line_separators() {
        assert_eq!(
            super::safe_ftp_custom_banner("220 hello\u{2028}owned"),
            "220 NetTrap FTP Ready"
        );
    }

    #[cfg(windows)]
    #[test]
    fn safe_ftp_reply_text_path_preserves_non_utf16_units_reversibly() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        use std::path::Path;

        let raw = OsString::from_wide(&[
            b'c' as u16,
            b':' as u16,
            b'\\' as u16,
            b'f' as u16,
            b't' as u16,
            b'p' as u16,
            b'.' as u16,
            0xD800,
        ]);
        let path = Path::new(&raw);

        let rendered = super::safe_ftp_reply_text_path(path);

        assert_eq!(rendered, "hex:0063003a005c006600740070002ed800");
    }

    #[test]
    fn eprt_rejects_control_or_non_ascii_delimiters() {
        assert!(parse_ftp_data_addr("EPRT |1|192.0.2.1|1024|").is_ok());
        assert!(parse_ftp_data_addr("EPRT \u{1f}1\u{1f}192.0.2.1\u{1f}1024\u{1f}").is_err());
        assert!(
            parse_ftp_data_addr("EPRT \u{00a7}1\u{00a7}192.0.2.1\u{00a7}1024\u{00a7}").is_err()
        );
    }
}
