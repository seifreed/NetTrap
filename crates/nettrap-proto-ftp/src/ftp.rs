use crate::error::Error;
use std::ffi::OsStr;
use std::io::{self, Read};
use std::net::Ipv4Addr;
use std::path::Path;

use nettrap_fsutil::{ensure_no_symlink_ancestors, open_regular_file_beneath_root};

const MAX_FTP_RETR_BYTES: u64 = 10 * 1024 * 1024;
const MAX_FTP_LIST_ENTRIES: usize = 4096;
const MAX_FTP_LIST_BYTES: usize = 1024 * 1024;
const FTP_SAFE_FIELD_MAX_CHARS: usize = 240;
const FTP_LIST_OK_MESSAGE: &str = "Directory send OK.";
const FTP_LIST_TRUNCATED_MESSAGE: &str = "Directory send OK (truncated).";
const DEFAULT_PASV_PORT_START: u16 = 60000;
const DEFAULT_PASV_PORT_END: u16 = 60100;

mod commands;
pub use commands::ftp_command_has_args;
pub use commands::parse_ftp_data_addr;
use commands::*;

#[derive(Debug)]
pub struct FtpHandler {
    banner: String,
    server_name: String,
    root_dir: Option<std::path::PathBuf>,
    pasv_port_start: u16,
    pasv_port_end: u16,
    pasv_port_counter: std::sync::atomic::AtomicU16,
    pasv_address: String,
    now: fn() -> chrono::DateTime<chrono::Utc>,
}

impl FtpHandler {
    pub fn new() -> Self {
        Self {
            banner: "220 NetTrap FTP Ready".to_string(),
            server_name: "nettrap".to_string(),
            root_dir: None,
            pasv_port_start: DEFAULT_PASV_PORT_START,
            pasv_port_end: DEFAULT_PASV_PORT_END,
            pasv_port_counter: std::sync::atomic::AtomicU16::new(0),
            pasv_address: "0,0,0,0".to_string(),
            now: chrono::Utc::now,
        }
    }

    /// Set the server name interpolated into `{servername}` banner tokens.
    ///
    /// The value is sanitized to a single banner-safe field so it cannot
    /// inject extra FTP response lines.
    pub fn with_server_name(mut self, name: impl Into<String>) -> crate::error::Result<Self> {
        self.server_name = validate_ftp_server_name(&name.into())?;
        Ok(self)
    }

    pub fn with_preformatted_banner(
        mut self,
        banner: impl Into<String>,
    ) -> crate::error::Result<Self> {
        let banner = banner.into();
        validate_ftp_preformatted_banner_value(&banner)?;
        self.banner = safe_ftp_preformatted_banner(&banner);
        Ok(self)
    }

    pub fn with_root_dir(
        mut self,
        dir: impl Into<std::path::PathBuf>,
    ) -> crate::error::Result<Self> {
        let dir = dir.into();
        if dir.as_os_str().is_empty() {
            return Err(Error::Config(
                "FTP root directory must not be empty".to_string(),
            ));
        }
        self.root_dir = Some(dir);
        Ok(self)
    }

    pub fn with_pasv_ports(mut self, start: u16, end: u16) -> Result<Self, String> {
        if start == 0 || end == 0 {
            self.pasv_port_start = DEFAULT_PASV_PORT_START;
            self.pasv_port_end = DEFAULT_PASV_PORT_END;
            self.pasv_port_counter = std::sync::atomic::AtomicU16::new(0);
            return Ok(self);
        }

        if start > end {
            return Err("FTP PASV port range must not be inverted".to_string());
        }
        self.pasv_port_start = start;
        self.pasv_port_end = end;
        self.pasv_port_counter = std::sync::atomic::AtomicU16::new(0);
        Ok(self)
    }

    pub fn with_pasv_address(mut self, addr: impl Into<String>) -> Result<Self, String> {
        self.pasv_address = normalize_pasv_address(&addr.into()).ok_or_else(|| {
            "Invalid PASV address; expected IPv4 or four comma-separated octets".to_string()
        })?;
        Ok(self)
    }

    pub fn with_now(mut self, now: fn() -> chrono::DateTime<chrono::Utc>) -> Self {
        self.now = now;
        self
    }

    pub fn passive_ports(&self) -> (u16, u16) {
        (self.pasv_port_start, self.pasv_port_end)
    }

    pub fn next_passive_port(&self) -> u16 {
        let current = self
            .pasv_port_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u32;
        let start = self.pasv_port_start as u32;
        let end = self.pasv_port_end as u32;
        let range = end - start + 1;
        u16::try_from(start + (current % range)).unwrap_or(self.pasv_port_start)
    }

    pub fn passive_address(&self) -> &str {
        &self.pasv_address
    }
}

fn normalize_pasv_address(value: &str) -> Option<String> {
    if value.trim_matches([' ', '\t']) != value || value.is_empty() {
        return None;
    }
    if let Ok(ip) = value.parse::<Ipv4Addr>() {
        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast() {
            return None;
        }
        return Some(ipv4_to_pasv_address(ip));
    }

    if let Ok(ip) = value.parse::<std::net::Ipv6Addr>() {
        let mapped = ip.to_ipv4_mapped()?;
        if mapped.is_unspecified()
            || mapped.is_loopback()
            || mapped.is_multicast()
            || mapped.is_broadcast()
        {
            return None;
        }
        return Some(ipv4_to_pasv_address(mapped));
    }

    let mut octets = [0u8; 4];
    let mut parts = value.split(',');
    for octet in &mut octets {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        *octet = part.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    if octets == [0, 0, 0, 0] {
        return None;
    }
    if octets[0] == 127 || octets[0] >= 224 || octets == [255, 255, 255, 255] {
        return None;
    }

    Some(octets.map(|octet| octet.to_string()).join(","))
}

fn ipv4_to_pasv_address(ip: Ipv4Addr) -> String {
    let octets = ip.octets();
    format!("{},{},{},{}", octets[0], octets[1], octets[2], octets[3])
}

impl Default for FtpHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Get default file content for an extension.
fn default_file_for_extension(ext: &str) -> Option<&'static [u8]> {
    const PE_STUB: [u8; 256] = {
        let mut stub = [0u8; 256];
        stub[0] = 0x4d;
        stub[1] = 0x5a;
        stub[2] = 0x90;
        stub[3] = 0x00;
        stub[4] = 0x03;
        stub[5] = 0x00;
        stub[6] = 0x00;
        stub[7] = 0x00;
        stub
    };
    const BIN_STUB: [u8; 256] = [0u8; 256];

    match ext.to_lowercase().as_str() {
        "html" | "htm" => Some(b"<html><body><h1>NetTrap</h1></body></html>"),
        "txt" => Some(b"NetTrap default text file\n"),
        "xml" => Some(b"<?xml version=\"1.0\"?><root><data>NetTrap</data></root>"),
        "json" => Some(b"{\"status\": \"ok\", \"source\": \"nettrap\"}"),
        "exe" | "dll" => Some(&PE_STUB),
        "bin" => Some(&BIN_STUB),
        "pdf" => Some(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n0\n%%EOF"),
        "png" => Some(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE]), // 1x1 PNG header
        "jpg" | "jpeg" => Some(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01]), // JFIF header
        "ico" => Some(&[0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00]), // ICO header
        "gif" => Some(b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"),
        _ => None,
    }
}

/// Virtual file entries for LIST when directory is empty or file not found
const VIRTUAL_FILES: &[(&str, u64)] = &[
    ("index.html", 42),
    ("readme.txt", 26),
    ("data.xml", 54),
    ("config.json", 41),
    ("image.png", 33),
    ("photo.jpg", 12),
    ("favicon.ico", 10),
    ("animation.gif", 43),
    ("document.pdf", 260),
    ("setup.exe", 256),
];

fn read_file_limited_beneath_root(
    root: &Path,
    relative_path: &Path,
) -> std::io::Result<Option<Vec<u8>>> {
    let file = open_regular_file_beneath_root(root, relative_path)?;

    let mut content = Vec::new();
    let mut limited = file.take(MAX_FTP_RETR_BYTES + 1);
    limited.read_to_end(&mut content)?;
    if content.len() as u64 > MAX_FTP_RETR_BYTES {
        Ok(None)
    } else {
        Ok(Some(content))
    }
}

#[derive(Debug, Clone, Copy)]
enum FtpListStyle {
    Detailed,
    NamesOnly,
}

#[derive(Debug, Clone)]
pub struct FtpDataTransfer {
    pub start_response: FtpResponse,
    pub data: Vec<u8>,
    pub complete_response: FtpResponse,
    /// When true the data channel receives (and discards) client bytes
    /// instead of sending `data` (STOR/APPE uploads). The honeypot never
    /// persists uploaded content.
    pub receive: bool,
}

impl FtpHandler {
    fn push_listing_line(listing: &mut String, line: &str) -> bool {
        if listing
            .len()
            .saturating_add(line.len())
            .saturating_add(FTP_LIST_TRUNCATED_MESSAGE.len())
            > MAX_FTP_LIST_BYTES
        {
            return false;
        }
        listing.push_str(line);
        true
    }

    fn append_virtual_listing(listing: &mut String, style: FtpListStyle) {
        for (vname, vsize) in VIRTUAL_FILES {
            let line = match style {
                FtpListStyle::Detailed => format!(
                    "-rw-r--r--    1 ftp      ftp          {} Jan 01 00:00 {}\r\n",
                    vsize, vname
                ),
                FtpListStyle::NamesOnly => format!("{vname}\r\n"),
            };
            if !Self::push_listing_line(listing, &line) {
                break;
            }
        }
    }

    fn build_listing_payload<I>(
        entries: Option<I>,
        style: FtpListStyle,
    ) -> Result<(String, bool), FtpResponse>
    where
        I: IntoIterator<Item = io::Result<std::fs::DirEntry>>,
    {
        let mut listing = String::new();
        let mut saw_entry = false;
        let mut listed_entries = 0usize;
        let mut truncated = false;

        if let Some(entries) = entries {
            for entry in entries {
                let entry = entry.map_err(|err| {
                    tracing::warn!("FTP directory entry unavailable: {}", err);
                    FtpResponse::new(550, "Directory unavailable")
                })?;
                saw_entry = true;
                if listed_entries >= MAX_FTP_LIST_ENTRIES {
                    truncated = true;
                    break;
                }

                let line = match style {
                    FtpListStyle::Detailed => {
                        let name = safe_ftp_listing_name_os(&entry.file_name());
                        detailed_listing_line(&name, std::fs::symlink_metadata(entry.path()))?
                    }
                    FtpListStyle::NamesOnly => {
                        format!("{}\r\n", safe_ftp_listing_name_os(&entry.file_name()))
                    }
                };

                if !Self::push_listing_line(&mut listing, &line) {
                    truncated = true;
                    break;
                }
                listed_entries += 1;
            }
        }

        if !saw_entry {
            Self::append_virtual_listing(&mut listing, style);
        }

        Ok((listing, truncated))
    }

    pub fn prepare_data_transfer(&self, command: &str) -> Result<FtpDataTransfer, FtpResponse> {
        let verb = command_verb(command);

        if verb == "LIST" {
            let path = optional_safe_path_arg(command)?;
            let entries = self.list_entries(path)?;
            let (listing, truncated) =
                Self::build_listing_payload(entries, FtpListStyle::Detailed)?;
            return Ok(FtpDataTransfer {
                start_response: FtpResponse::new(150, "Here comes the directory listing."),
                data: listing.into_bytes(),
                complete_response: FtpResponse::new(
                    226,
                    if truncated {
                        FTP_LIST_TRUNCATED_MESSAGE
                    } else {
                        FTP_LIST_OK_MESSAGE
                    },
                ),
                receive: false,
            });
        }

        if verb == "NLST" {
            let path = optional_safe_path_arg(command)?;
            let entries = self.list_entries(path)?;
            let (listing, truncated) =
                Self::build_listing_payload(entries, FtpListStyle::NamesOnly)?;
            return Ok(FtpDataTransfer {
                start_response: FtpResponse::new(150, "Here comes the directory listing."),
                data: listing.into_bytes(),
                complete_response: FtpResponse::new(
                    226,
                    if truncated {
                        FTP_LIST_TRUNCATED_MESSAGE
                    } else {
                        FTP_LIST_OK_MESSAGE
                    },
                ),
                receive: false,
            });
        }

        if verb == "RETR" {
            required_safe_path_arg(command)?;
            return self.prepare_retr_transfer(command);
        }

        if verb == "STOR" || verb == "APPE" {
            required_safe_path_arg(command)?;
            // Honeypot: accept the upload data channel but never persist the
            // bytes (the listener reads and discards them, capped).
            return Ok(FtpDataTransfer {
                start_response: FtpResponse::new(150, "Ok to send data."),
                data: Vec::new(),
                complete_response: FtpResponse::new(226, "Transfer complete."),
                receive: true,
            });
        }

        Err(FtpResponse::new(502, "Unsupported data command"))
    }

    fn list_entries(
        &self,
        relative_path: Option<&str>,
    ) -> Result<Option<std::fs::ReadDir>, FtpResponse> {
        let Some(root) = self.root_dir.as_ref() else {
            return Ok(None);
        };

        let dir = relative_path.map_or_else(|| root.clone(), |path| root.join(path));
        if let Err(err) = ensure_no_symlink_ancestors(&dir) {
            tracing::warn!(
                "FTP directory listing unavailable for {}: {}",
                safe_ftp_reply_text_path(&dir),
                err
            );
            return Err(FtpResponse::new(550, "Directory unavailable"));
        }

        std::fs::read_dir(&dir).map(Some).map_err(|err| {
            tracing::warn!(
                "FTP directory listing unavailable for {}: {}",
                safe_ftp_reply_text_path(&dir),
                err
            );
            FtpResponse::new(550, "Directory unavailable")
        })
    }

    fn prepare_retr_transfer(&self, command: &str) -> Result<FtpDataTransfer, FtpResponse> {
        let filename = command_arg(command);

        if has_path_traversal(filename) {
            tracing::warn!(
                "FTP path traversal attempt blocked: {}",
                safe_ftp_reply_text(filename)
            );
            return Err(FtpResponse::new(550, "Invalid path"));
        }

        if let Some(ref root) = self.root_dir {
            let relative_path = Path::new(filename);
            match read_file_limited_beneath_root(root, relative_path) {
                Ok(Some(content)) => Ok(Self::retr_transfer(filename, content)),
                Ok(None) => {
                    tracing::warn!(
                        "FTP RETR file {} exceeds response size limit ({})",
                        safe_ftp_reply_text_path(relative_path),
                        MAX_FTP_RETR_BYTES
                    );
                    Err(FtpResponse::new(552, "File too large"))
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    if let Some(content) = default_file_for_extension(
                        std::path::Path::new(filename)
                            .extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or(""),
                    ) {
                        return Ok(Self::retr_transfer(filename, content.to_vec()));
                    }
                    Err(FtpResponse::new(550, "File not found"))
                }
                Err(err) => {
                    tracing::warn!(
                        "FTP RETR blocked for {}: {}",
                        safe_ftp_reply_text_path(relative_path),
                        err
                    );
                    Err(FtpResponse::new(550, "Access denied"))
                }
            }
        } else if let Some(content) = default_file_for_extension(
            std::path::Path::new(filename)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or(""),
        ) {
            Ok(Self::retr_transfer(filename, content.to_vec()))
        } else {
            Err(FtpResponse::new(550, "File not found"))
        }
    }

    fn retr_transfer(filename: &str, content: Vec<u8>) -> FtpDataTransfer {
        FtpDataTransfer {
            start_response: FtpResponse::new(
                150,
                format!(
                    "Opening BINARY mode data connection for {} ({} bytes).",
                    filename,
                    content.len()
                ),
            ),
            data: content,
            complete_response: FtpResponse::new(226, "Transfer complete."),
            receive: false,
        }
    }

    pub fn handle(&self, command: &str) -> FtpResponse {
        let verb = command_verb(command);

        match verb.as_str() {
            "USER" => {
                let arg = command_arg(command);
                if arg.is_empty() {
                    FtpResponse::new(501, "Missing argument")
                } else if arg.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
                    FtpResponse::new(501, "Syntax error in parameters")
                } else {
                    FtpResponse::new(331, "Username OK, need password")
                }
            }
            "PASS" => {
                let arg = command_arg(command);
                if arg.is_empty() {
                    FtpResponse::new(501, "Missing argument")
                } else if arg.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
                    FtpResponse::new(501, "Syntax error in parameters")
                } else {
                    FtpResponse::new(230, "User logged in")
                }
            }
            // RFC 959: the 257 reply quotes the pathname, e.g. `257 "/" is the
            // current directory.` Clients parse the quoted path; an unquoted
            // `257 /` is both non-conformant and a fingerprinting tell.
            "PWD" | "XPWD" => {
                if ftp_command_has_args(command) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                FtpResponse::new(257, "\"/\" is the current directory")
            }
            "TYPE" => type_response(command),
            "PASV" => {
                if ftp_command_has_args(command) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                let port = self.next_passive_port();
                let p1 = port / 256;
                let p2 = port % 256;
                FtpResponse::new(
                    227,
                    format!(
                        "Entering Passive Mode ({},{},{})",
                        self.pasv_address, p1, p2
                    ),
                )
            }
            "LIST" | "NLST" | "RETR" | "STOR" | "APPE" => {
                FtpResponse::new(425, "Use PASV, EPSV or PORT first")
            }
            "PORT" | "EPRT" => match parse_ftp_data_addr(command) {
                Ok(_) => FtpResponse::new(
                    200,
                    if command_verb(command) == "EPRT" {
                        "EPRT command successful"
                    } else {
                        "PORT command successful"
                    },
                ),
                Err(response) => response,
            },
            "EPSV" => {
                if ftp_command_has_args(command) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                let port = self.next_passive_port();
                FtpResponse::new(
                    229,
                    format!("Entering Extended Passive Mode (|||{}|)", port),
                )
            }
            "SYST" => {
                if ftp_command_has_args(command) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                FtpResponse::new(215, "UNIX Type: L8")
            }
            "HOST" => {
                let host = match required_arg(command) {
                    Ok(host) => host,
                    Err(response) => return response,
                };
                if host
                    .chars()
                    .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
                {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                if is_ftp_host_literal(host) {
                    return FtpResponse::new(504, "Host unavailable");
                }
                if !is_valid_ftp_host_name(host) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                FtpResponse::new(220, "Virtual host accepted")
            }
            "ACCT" => {
                let arg = match required_arg(command) {
                    Ok(arg) => arg,
                    Err(response) => return response,
                };
                if arg.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
                    FtpResponse::new(501, "Syntax error in parameters")
                } else {
                    FtpResponse::new(230, "Account information accepted")
                }
            }
            "REIN" => {
                if ftp_command_has_args(command) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                FtpResponse::new(220, "Service ready for new user")
            }
            "SMNT" => {
                let arg = match required_arg(command) {
                    Ok(arg) => arg,
                    Err(response) => return response,
                };
                if arg.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
                    FtpResponse::new(501, "Syntax error in parameters")
                } else {
                    FtpResponse::new(502, "Mount not supported")
                }
            }
            "FEAT" => {
                if ftp_command_has_args(command) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                FtpResponse::raw(
                    b"211-Features:\r\n PASV\r\n EPSV\r\n REST STREAM\r\n HOST\r\n UTF8\r\n SIZE\r\n MDTM\r\n211 End\r\n"
                        .to_vec(),
                )
            }
            "OPTS" => {
                // FEAT advertises UTF8, so clients (FileZilla, lftp, Windows
                // ftp.exe) follow up with `OPTS UTF8 ON`. Honour the advertised
                // option instead of returning 502 for the whole command.
                let arg = command_arg(command);
                if arg.is_empty() {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                let tokens: Vec<&str> = arg.split(' ').collect();
                if tokens.iter().skip(1).any(|part| part.is_empty()) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                if tokens.iter().any(|token| {
                    token
                        .chars()
                        .any(|ch| ch.is_control() || ch.is_whitespace() && ch != ' ')
                }) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                if tokens.len() > 2 {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                match tokens.as_slice() {
                    [option, state] if option.eq_ignore_ascii_case("UTF8") => {
                        if state.eq_ignore_ascii_case("ON") {
                            FtpResponse::new(200, "UTF8 set to on")
                        } else if state.eq_ignore_ascii_case("OFF") {
                            FtpResponse::new(200, "UTF8 set to off")
                        } else {
                            FtpResponse::new(501, "Syntax error in OPTS UTF8 argument")
                        }
                    }
                    [option] if option.eq_ignore_ascii_case("UTF8") => {
                        FtpResponse::new(200, "UTF8 set to on")
                    }
                    _ => FtpResponse::new(501, "Option not understood"),
                }
            }
            "SIZE" => {
                let filename = match required_safe_path_arg(command) {
                    Ok(filename) => filename,
                    Err(response) => return response,
                };
                if let Some(ref root) = self.root_dir {
                    let relative_path = Path::new(filename);
                    let file = match open_regular_file_beneath_root(root, relative_path) {
                        Ok(file) => file,
                        Err(err) if err.kind() == io::ErrorKind::NotFound => {
                            let ext = std::path::Path::new(filename)
                                .extension()
                                .and_then(|e| e.to_str())
                                .unwrap_or("");
                            if let Some(content) = default_file_for_extension(ext) {
                                return FtpResponse::new(213, content.len().to_string());
                            }
                            return FtpResponse::new(550, "File not found");
                        }
                        Err(err) => {
                            tracing::warn!(
                                "FTP SIZE blocked for {}: {}",
                                safe_ftp_reply_text_path(relative_path),
                                err
                            );
                            return FtpResponse::new(550, "Access denied");
                        }
                    };
                    size_response_from_metadata(file.metadata(), relative_path)
                } else {
                    FtpResponse::new(213, "0")
                }
            }
            "REST" => {
                let marker = match required_arg(command) {
                    Ok(marker) => marker,
                    Err(response) => return response,
                };
                let mut args = marker.split(' ');
                if args.clone().any(|token| {
                    token
                        .chars()
                        .any(|ch| ch.is_control() || ch.is_whitespace() && ch != ' ')
                }) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                if matches!(args.next(), Some(marker) if marker.bytes().all(|byte| byte.is_ascii_digit()))
                    && args.next().is_none()
                {
                    FtpResponse::new(350, "Restart position accepted")
                } else {
                    FtpResponse::new(501, "Syntax error in parameters")
                }
            }
            "ALLO" => {
                let size = match required_arg(command) {
                    Ok(size) => size,
                    Err(response) => return response,
                };
                if size.chars().any(|ch| ch.is_whitespace() && ch != ' ') {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                let mut args = size.split(' ');
                let valid = match (args.next(), args.next(), args.next(), args.next()) {
                    (Some(bytes), None, None, None) => {
                        bytes.bytes().all(|byte| byte.is_ascii_digit())
                    }
                    (Some(bytes), Some(record_marker), Some(record_size), None) => {
                        bytes.bytes().all(|byte| byte.is_ascii_digit())
                            && record_marker.eq_ignore_ascii_case("R")
                            && record_size.bytes().all(|byte| byte.is_ascii_digit())
                    }
                    _ => false,
                };
                if valid {
                    FtpResponse::new(202, "ALLO command ignored")
                } else {
                    FtpResponse::new(501, "Syntax error in parameters")
                }
            }
            "MODE" => {
                let mode = match required_arg(command) {
                    Ok(mode) => mode,
                    Err(response) => return response,
                };
                let mut args = mode.split(' ');
                if args.clone().any(|token| {
                    token
                        .chars()
                        .any(|ch| ch.is_control() || ch.is_whitespace() && ch != ' ')
                }) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                match (args.next(), args.next()) {
                    (Some(mode), None) if mode.eq_ignore_ascii_case("S") => {
                        FtpResponse::new(200, "Mode set to S")
                    }
                    (Some(mode), Some(_)) if mode.eq_ignore_ascii_case("S") => {
                        FtpResponse::new(501, "Syntax error in parameters")
                    }
                    _ => FtpResponse::new(504, "Unsupported mode"),
                }
            }
            "STRU" => {
                let structure = match required_arg(command) {
                    Ok(structure) => structure,
                    Err(response) => return response,
                };
                let mut args = structure.split(' ');
                if args.clone().any(|token| {
                    token
                        .chars()
                        .any(|ch| ch.is_control() || ch.is_whitespace() && ch != ' ')
                }) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                match (args.next(), args.next()) {
                    (Some(structure), None) if structure.eq_ignore_ascii_case("F") => {
                        FtpResponse::new(200, "Structure set to F")
                    }
                    (Some(structure), Some(_)) if structure.eq_ignore_ascii_case("F") => {
                        FtpResponse::new(501, "Syntax error in parameters")
                    }
                    _ => FtpResponse::new(504, "Unsupported structure"),
                }
            }
            "MDTM" => match required_safe_path_arg(command) {
                Ok(_) => FtpResponse::new(213, current_mdtm_timestamp((self.now)())),
                Err(response) => response,
            },
            "CWD" => match required_safe_path_arg(command) {
                Ok(_) => FtpResponse::new(250, "Directory changed"),
                Err(response) => response,
            },
            "CDUP" => {
                if ftp_command_has_args(command) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                FtpResponse::new(250, "Directory changed")
            }
            "MKD" | "XMKD" => match required_safe_path_arg(command) {
                Ok(dir) => FtpResponse::new(
                    257,
                    format!("\"{}\" directory created", safe_ftp_reply_text(dir)),
                ),
                Err(response) => response,
            },
            "RMD" | "XRMD" => match required_safe_path_arg(command) {
                Ok(_) => FtpResponse::new(250, "Directory removed"),
                Err(response) => response,
            },
            "DELE" => match required_safe_path_arg(command) {
                Ok(_) => FtpResponse::new(250, "File deleted"),
                Err(response) => response,
            },
            "RNFR" => match required_safe_path_arg(command) {
                Ok(_) => FtpResponse::new(350, "Ready for RNTO"),
                Err(response) => response,
            },
            "RNTO" => match required_safe_path_arg(command) {
                Ok(_) => FtpResponse::new(250, "Rename successful"),
                Err(response) => response,
            },
            "NOOP" => {
                if ftp_command_has_args(command) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                FtpResponse::new(200, "NOOP ok")
            }
            "HELP" => {
                if ftp_command_has_args(command) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                FtpResponse::raw(
                    b"214-The following commands are recognized:\r\n USER PASS HOST ACCT CWD CDUP QUIT REIN PASV PORT EPRT EPSV\r\n TYPE STRU MODE RETR STOR APPE LIST NLST SIZE MDTM SYST STAT FEAT\r\n OPTS REST ALLO MKD XMKD RMD XRMD DELE RNFR RNTO ABOR HELP NOOP\r\n214 Help OK.\r\n".to_vec(),
                )
            }
            "STAT" => {
                if ftp_command_has_args(command) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                FtpResponse::new(211, "NetTrap FTP Server status OK")
            }
            "ABOR" => {
                if ftp_command_has_args(command) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                FtpResponse::new(226, "Abort successful")
            }
            "QUIT" => {
                if ftp_command_has_args(command) {
                    return FtpResponse::new(501, "Syntax error in parameters");
                }
                FtpResponse::new(221, "Goodbye")
            }
            _ => FtpResponse::new(502, "Command not recognized"),
        }
    }

    pub fn get_banner(&self) -> Vec<u8> {
        self.get_banner_at((self.now)())
    }

    /// Like [`get_banner`] but renders banner date tokens against an explicit
    /// instant so the caller can inject the FakeTime clock.
    pub fn get_banner_at(&self, now: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
        let formatted = format_banner_at(&self.banner, &self.server_name, now);
        let mut b = formatted.into_bytes();
        if !b.ends_with(b"\r\n") {
            b.extend_from_slice(b"\r\n");
        }
        b
    }
}

fn required_safe_path_arg(command: &str) -> Result<&str, FtpResponse> {
    let path = required_arg(command)?;
    validate_safe_path_arg(path)?;
    Ok(path)
}

fn optional_safe_path_arg(command: &str) -> Result<Option<&str>, FtpResponse> {
    let path = command_arg(command);
    if path.is_empty() {
        return Ok(None);
    }
    validate_safe_path_arg(path)?;
    Ok(Some(path))
}

fn validate_safe_path_arg(path: &str) -> Result<(), FtpResponse> {
    if path
        .chars()
        .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return Err(FtpResponse::new(501, "Syntax error in parameters"));
    }
    if has_path_traversal(path) {
        Err(FtpResponse::new(550, "Invalid path"))
    } else {
        Ok(())
    }
}

fn detailed_listing_line(
    name: &str,
    metadata: io::Result<std::fs::Metadata>,
) -> Result<String, FtpResponse> {
    let metadata = metadata.map_err(|err| {
        tracing::warn!(
            "FTP directory entry metadata unavailable for {}: {}",
            name,
            err
        );
        FtpResponse::new(550, "Directory unavailable")
    })?;
    let size = metadata.len();
    let mode = if metadata.file_type().is_dir() {
        "drwxr-xr-x"
    } else if metadata.file_type().is_symlink() {
        "lrwxrwxrwx"
    } else {
        "-rw-r--r--"
    };
    Ok(format!(
        "{mode}    1 ftp      ftp          {} Jan 01 00:00 {}\r\n",
        size, name
    ))
}

fn safe_ftp_listing_name_os(value: &OsStr) -> String {
    #[cfg(unix)]
    {
        use std::fmt::Write as _;
        use std::os::unix::ffi::OsStrExt;

        let mut rendered = String::new();
        let mut chars_written = 0usize;
        for byte in value.as_bytes() {
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

        if rendered.is_empty() {
            "unnamed".to_string()
        } else {
            rendered
        }
    }

    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        {
            use std::fmt::Write as _;
            use std::os::windows::ffi::OsStrExt;

            if let Some(value) = value.to_str() {
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
                return if rendered.is_empty() {
                    "unnamed".to_string()
                } else {
                    rendered
                };
            }

            let mut rendered = String::new();
            let mut chars_written = 0usize;
            for unit in value.encode_wide() {
                if chars_written + 4 > FTP_SAFE_FIELD_MAX_CHARS {
                    break;
                }
                let _ = write!(&mut rendered, "{:04x}", unit);
                chars_written += 4;
            }
            if rendered.is_empty() {
                "unnamed".to_string()
            } else {
                format!("hex:{rendered}")
            }
        }

        #[cfg(all(not(unix), not(windows)))]
        {
            value
                .to_str()
                .map(|value| {
                    let mut rendered = String::new();
                    let mut chars_written = 0usize;
                    for ch in value.chars() {
                        if chars_written >= FTP_SAFE_FIELD_MAX_CHARS {
                            break;
                        }
                        if ch.is_control() || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}') {
                            break;
                        }
                        rendered.push(ch);
                        chars_written += 1;
                    }
                    if rendered.is_empty() {
                        "unnamed".to_string()
                    } else {
                        rendered
                    }
                })
                .unwrap_or_else(|| "unnamed".to_string())
        }
    }
}

fn size_response_from_metadata(
    metadata: io::Result<std::fs::Metadata>,
    relative_path: &Path,
) -> FtpResponse {
    let size = match metadata {
        Ok(metadata) => metadata.len(),
        Err(err) => {
            tracing::warn!(
                "FTP SIZE metadata failed for {}: {}",
                safe_ftp_reply_text_path(relative_path),
                err
            );
            return FtpResponse::new(550, "Access denied");
        }
    };

    if size > MAX_FTP_RETR_BYTES {
        FtpResponse::new(552, "File too large")
    } else {
        FtpResponse::new(213, size.to_string())
    }
}

fn safe_ftp_hostname_field(hostname: &OsStr) -> String {
    #[cfg(unix)]
    {
        use std::fmt::Write as _;
        use std::os::unix::ffi::OsStrExt;

        if let Some(value) = hostname.to_str() {
            return safe_ftp_banner_field(value, "nettrap");
        }

        let mut rendered = String::from("hex:");
        for byte in hostname.as_bytes() {
            let _ = write!(&mut rendered, "{:02x}", byte);
        }
        rendered
    }

    #[cfg(not(unix))]
    {
        hostname
            .to_str()
            .map(|value| safe_ftp_banner_field(value, "nettrap"))
            .unwrap_or_else(|| "nettrap".to_string())
    }
}

fn validate_ftp_preformatted_banner_value(value: &str) -> crate::error::Result<()> {
    if FTP_BANNERS.iter().any(|(_, banner)| *banner == value) {
        return Ok(());
    }

    validate_ftp_single_line_banner(value, "invalid FTP preformatted banner")
}

fn validate_ftp_single_line_banner(value: &str, message: &str) -> crate::error::Result<()> {
    if value.is_empty()
        || value.len() > FTP_SAFE_FIELD_MAX_CHARS
        || nettrap_core::sanitize::contains_line_separator(value)
        || value
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        Err(Error::Config(message.to_string()))
    } else {
        Ok(())
    }
}

fn validate_ftp_server_name(value: &str) -> crate::error::Result<String> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty()
        || nettrap_core::sanitize::contains_line_separator(value)
        || value.chars().next().is_some_and(char::is_whitespace)
        || value.chars().last().is_some_and(char::is_whitespace)
        || value.chars().any(|ch| ch.is_control())
        || !is_valid_ftp_host_name(value)
    {
        Err(Error::Config("invalid FTP server name".to_string()))
    } else {
        Ok(value.to_ascii_lowercase())
    }
}

fn is_valid_ftp_host_name(value: &str) -> bool {
    let value = if let Some(value) = value.strip_suffix('.') {
        if value.is_empty() || value.ends_with('.') {
            return false;
        }
        value
    } else {
        value
    };
    if value.is_empty() || value.len() > 253 || value.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }

    !nettrap_core::sanitize::has_numeric_domain_labels(value)
        && nettrap_core::sanitize::has_valid_domain_labels(value)
}

fn is_ftp_host_literal(value: &str) -> bool {
    if value.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .and_then(|host| host.parse::<std::net::Ipv6Addr>().ok())
        .is_some()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpResponse {
    pub code: u16,
    pub message: String,
    pub raw: Option<Vec<u8>>,
}

impl FtpResponse {
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            raw: None,
        }
    }

    pub fn raw(data: Vec<u8>) -> Self {
        Self {
            code: 0,
            message: String::new(),
            raw: Some(data),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        if let Some(ref raw) = self.raw {
            return raw.clone();
        }
        if !(100..=599).contains(&self.code) {
            invalid_ftp_response()
        } else {
            let message = safe_ftp_reply_text(&self.message);
            if message.is_empty() {
                format!("{}\r\n", self.code).into_bytes()
            } else {
                format!("{} {}\r\n", self.code, message).into_bytes()
            }
        }
    }
}

fn invalid_ftp_response() -> Vec<u8> {
    b"500 Internal server error\r\n".to_vec()
}

/// Static banner presets keyed by macro name.
static FTP_BANNERS: &[(&str, &str)] = &[
    ("!generic", "220 NetTrap FTP Ready"),
    ("", "220 NetTrap FTP Ready"),
    ("!vsftpd", "220 (vsFTPd 3.0.3)"),
    ("!vsftpd3", "220 (vsFTPd 3.0.3)"),
    ("!vsftpd2", "220 (vsFTPd 2.3.5)"),
    ("!vsftpd205", "220 (vsFTPd 2.0.5)"),
    ("!vsftpd207", "220 (vsFTPd 2.0.7)"),
    (
        "!wuftpd",
        "220 nettrap FTP server (Version wu-2.6.2(1)) ready.",
    ),
    (
        "!wuftpd24",
        "220 nettrap FTP server (Version wu-2.4.2-academ[BETA-18](1)) ready.",
    ),
    (
        "!wuftpd25",
        "220 nettrap FTP server (Version wu-2.5.0(1)) ready.",
    ),
    (
        "!wuftpd261",
        "220 nettrap FTP server (Version wu-2.6.1(1)) ready.",
    ),
    ("!proftpd", "220 ProFTPD 1.3.5 Server (nettrap) [0.0.0.0]"),
    (
        "!proftpd136",
        "220 ProFTPD 1.3.6 Server (nettrap) [0.0.0.0]",
    ),
    (
        "!proftpd137",
        "220 ProFTPD 1.3.7 Server (nettrap) [0.0.0.0]",
    ),
    (
        "!pureftpd",
        "220---------- Welcome to Pure-FTPd ----------\r\n220-Local time is now %H:%M.\r\n220 You will be disconnected after 15 minutes of inactivity.",
    ),
    ("!iis", "220 nettrap Microsoft FTP Service"),
    ("!iis5", "220 nettrap Microsoft FTP Service (Version 5.0)."),
    ("!iis6", "220 nettrap Microsoft FTP Service (Version 6.0)."),
    ("!iis7", "220-Microsoft FTP Service\r\n220 nettrap"),
    ("!iis75", "220-Microsoft FTP Service\r\n220 nettrap FTP"),
    (
        "!ncftpd",
        "220 nettrap NcFTPd Server (Licensed Non-commercial use only) ready.",
    ),
    (
        "!filezilla",
        "220-FileZilla Server 0.9.60 beta\r\n220-written by Tim Kosse (tim.kosse@filezilla-project.org)\r\n220 Please visit https://filezilla-project.org/",
    ),
    ("!filezilla1", "220 FileZilla Server 1.0.0"),
    ("!wsftp", "220 nettrap X2 WS_FTP Server 7.7(0)"),
    ("!servu", "220 Serv-U FTP Server v15.1 ready..."),
    ("!bpftp", "220 BulletProof FTP Server ready ..."),
    ("!gene6", "220 Gene6 FTP Server v3.10.0 (Build 2) ready..."),
    ("!glftpd", "220 nettrap (glFTPd 2.11 Linux+TLS)"),
    ("!crushftp", "220 CrushFTP Server Ready."),
    (
        "!openbsd",
        "220 nettrap FTP server (OpenBSD ftpd 6.9) ready.",
    ),
    ("!freebsd", "220 nettrap FTP server (Version 6.00LS) ready."),
    ("!vsftpd200", "220 (vsFTPd 2.0.0)"),
    ("!vsftpd201", "220 (vsFTPd 2.0.1)"),
    ("!vsftpd210", "220 (vsFTPd 2.1.0)"),
    ("!vsftpd212", "220 (vsFTPd 2.1.2)"),
    ("!vsftpd220", "220 (vsFTPd 2.2.0)"),
    ("!vsftpd222", "220 (vsFTPd 2.2.2)"),
    ("!vsftpd230", "220 (vsFTPd 2.3.0)"),
    ("!vsftpd232", "220 (vsFTPd 2.3.2)"),
    ("!vsftpd234", "220 (vsFTPd 2.3.4)"),
    ("!vsftpd300", "220 (vsFTPd 3.0.0)"),
    ("!vsftpd302", "220 (vsFTPd 3.0.2)"),
    ("!vsftpd305", "220 (vsFTPd 3.0.5)"),
    (
        "!wuftpd240",
        "220 nettrap FTP server (Version wu-2.4.0(1)) ready.",
    ),
    (
        "!wuftpd241",
        "220 nettrap FTP server (Version wu-2.4.1(1)) ready.",
    ),
    (
        "!wuftpd242",
        "220 nettrap FTP server (Version wu-2.4.2-academ[BETA-18](1)) ready.",
    ),
    (
        "!wuftpd250",
        "220 nettrap FTP server (Version wu-2.5.0(1)) ready.",
    ),
    (
        "!wuftpd260",
        "220 nettrap FTP server (Version wu-2.6.0(1)) ready.",
    ),
    (
        "!wuftpd262",
        "220 nettrap FTP server (Version wu-2.6.2(5)) ready.",
    ),
    ("!iis3", "220 nettrap Microsoft FTP Service (Version 3.0)."),
    ("!iis4", "220 nettrap Microsoft FTP Service (Version 4.0)."),
    (
        "!iis10",
        "220-Microsoft FTP Service\r\n220 nettrap FTP Service",
    ),
    ("!wsftp2", "220 nettrap V2 WS_FTP Server 2.0.4 (0)"),
    ("!wsftpx2", "220 nettrap X2 WS_FTP Server 7.7(0)"),
    ("!wsftp3", "220 nettrap WS_FTP Server 3.1.3 (0)"),
    ("!servu6", "220 Serv-U FTP Server v6.4 for WinSock ready..."),
    ("!servu15", "220 Serv-U FTP Server v15.1 ready..."),
    ("!servu153", "220 Serv-U FTP Server v15.3 ready..."),
    ("!proftpd131", "220 ProFTPD 1.3.1 Server (nettrap)"),
    ("!proftpd132", "220 ProFTPD 1.3.2 Server (nettrap)"),
    ("!proftpd133", "220 ProFTPD 1.3.3 Server (nettrap)"),
    ("!proftpd134", "220 ProFTPD 1.3.4 Server (nettrap)"),
    (
        "!proftpd138",
        "220 ProFTPD 1.3.8 Server (nettrap) [0.0.0.0]",
    ),
    (
        "!filezilla094",
        "220-FileZilla Server 0.9.41 beta\r\n220 Welcome",
    ),
    (
        "!filezilla095",
        "220-FileZilla Server 0.9.53 beta\r\n220 Welcome",
    ),
    ("!filezilla10", "220 FileZilla Server 1.0.0"),
    ("!filezilla11", "220 FileZilla Server 1.1.0"),
    (
        "!pureftpd13",
        "220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------\r\n220-Local time is now %H:%M.\r\n220 You will be disconnected after 15 minutes of inactivity.",
    ),
    ("!glftpd20", "220 nettrap (glFTPd 2.01 Linux+TLS)"),
    ("!glftpd211", "220 nettrap (glFTPd 2.11 Linux+TLS)"),
    (
        "!crushftp8",
        "220 CrushFTP Server Ready. (CrushFTP version 8.0)",
    ),
    (
        "!crushftp9",
        "220 CrushFTP Server Ready. (CrushFTP version 9.0)",
    ),
    (
        "!crushftp10",
        "220 CrushFTP Server Ready. (CrushFTP version 10.0)",
    ),
    (
        "!netbsd",
        "220 nettrap FTP server (NetBSD-ftpd 20100515) ready.",
    ),
    (
        "!dragonfly",
        "220 nettrap FTP server (Version 6.00LS) ready.",
    ),
    ("!solaris", "220 nettrap FTP server ready."),
    ("!solaris10", "220 nettrap FTP server (SunOS 5.10) ready."),
    ("!cisco", "220 nettrap FTP server (Cisco IOS) ready."),
    (
        "!cerberus",
        "220 Cerberus FTP Server - Professional Edition ready",
    ),
    ("!titan", "220 Titan FTP Server 2019 Ready."),
    (
        "!completeftp",
        "220 CompleteFTP-22.1.1 - www.completeftp.com",
    ),
    ("!raiden", "220 RaidenFTPd 2.4 ready."),
    (
        "!warftp",
        "220- War-FTPD 1.82.00-R13 (Nov 01 2006) Ready\r\n220 Please enter your user name.",
    ),
    ("!eft", "220 EFT Server Enterprise 8.0.0.0 ready"),
    ("!xlight", "220 Xlight FTP Server 3.9 ready..."),
    ("!hpnonstop", "220 nettrap HP NonStop FTP Server - T9552H01"),
    (
        "!tectia",
        "220 nettrap SSH Tectia Server - FTP subsystem ready",
    ),
    ("!asus", "220 Welcome to ASUS RT-AX88U FTP service."),
    ("!synology", "220 Synology FTP server ready."),
    ("!qnap", "220 NASFTPD Turbo station 4.5.4"),
    ("!mikrotik", "220 MikroTik FTP server (MikroTik 6.49) ready"),
    ("!dlink", "220 DI-804HV FTP server ready"),
    (
        "!zos",
        "220-FTPD1 IBM FTP CS V2R4 at {servername}, %H:%M:%S on %Y-%m-%d.\r\n220 Connection will close if idle for more than 5 minutes.",
    ),
    (
        "!as400",
        "220-QTCP at {servername}.\r\n220 Connection will close if idle more than 300 seconds.",
    ),
];

pub fn resolve_banner(input: &str) -> String {
    if input == "!random" {
        let presets = [
            "!vsftpd",
            "!vsftpd2",
            "!vsftpd305",
            "!wuftpd",
            "!wuftpd262",
            "!iis",
            "!iis6",
            "!iis7",
            "!ncftpd",
            "!proftpd",
            "!proftpd138",
            "!pureftpd",
            "!filezilla",
            "!filezilla11",
            "!servu",
            "!servu15",
            "!openbsd",
            "!freebsd",
            "!glftpd",
            "!crushftp10",
            "!cerberus",
            "!titan",
            "!synology",
            "!qnap",
        ];
        let idx = rand::random_range(0..presets.len());
        return resolve_banner(presets[idx]);
    }
    if matches!(input, "!hostname" | "!gethostname") {
        let hostname = hostname::get()
            .ok()
            .as_deref()
            .map(safe_ftp_hostname_field)
            .unwrap_or_else(|| "nettrap".to_string());
        return format!(
            "220 {} FTP Ready",
            safe_ftp_banner_field(&hostname, "nettrap")
        );
    }
    if let Some((_, banner)) = FTP_BANNERS.iter().find(|(key, _)| *key == input) {
        banner.to_string()
    } else {
        safe_ftp_custom_banner(input)
    }
}

/// Expand banner template tokens in a resolved banner.
///
/// Supports template insertions so emulated banners reflect live values:
///   * `{servername}` — the configured server name
///   * `{tz}` — time zone, hard-coded to `UTC`
///   * `strftime` — any `%`-specifier (e.g. `%H:%M:%S`, `%Y-%m-%d`) is rendered
///     against the current time
///
/// Expansion runs every time the banner is emitted so date/time tokens stay
/// current. The inputs are already single-line-sanitized (preset constants are
/// trusted; custom banners
/// pass through [`safe_ftp_custom_banner`]; the server name through
/// [`safe_ftp_banner_field`]), so token expansion cannot introduce new FTP
/// response-line injection. An invalid `strftime` specifier leaves the banner
/// text as-is rather than aborting.
pub fn format_banner(template: &str, server_name: &str) -> String {
    format_banner_at(template, server_name, chrono::Utc::now())
}

fn current_mdtm_timestamp(now: chrono::DateTime<chrono::Utc>) -> String {
    format_mdtm_timestamp(now)
}

fn format_mdtm_timestamp(now: chrono::DateTime<chrono::Utc>) -> String {
    now.format("%Y%m%d%H%M%S").to_string()
}

/// Like [`format_banner`] but renders date tokens against an explicit instant.
/// The caller injects the clock so FakeTime mode reaches banner timestamps
/// (keeping them consistent with the daytime/time/HTTP services).
pub fn format_banner_at(
    template: &str,
    server_name: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let mut out = template.to_string();
    if out.contains('{') {
        out = out
            .replace("{servername}", server_name)
            .replace("{tz}", "UTC");
    }
    if out.contains('%') {
        let fmt = out.clone();
        match std::panic::catch_unwind(move || now.format(&fmt).to_string()) {
            Ok(rendered) => out = rendered,
            Err(_) => {
                tracing::warn!("Invalid strftime specifier in FTP banner, leaving text literal");
            }
        }
    }
    out
}

fn safe_ftp_preformatted_banner(value: &str) -> String {
    if FTP_BANNERS.iter().any(|(_, banner)| *banner == value) {
        value.to_string()
    } else {
        safe_ftp_custom_banner(value)
    }
}

#[cfg(test)]
#[path = "ftp_tests.rs"]
mod tests;
