use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

fn has_path_traversal(s: &str) -> bool {
    let lower = s.to_lowercase();
    s.contains("..")
        || s.contains('\\')
        || s.starts_with('/')
        || lower.contains("%2e%2e")
        || lower.contains("%2e%2e%2f")
        || lower.contains("%2e%2e%5c")
        || lower.contains("..%2f")
        || lower.contains("..%5c")
        || lower.contains("%2e.")
        || lower.contains(".%2e")
        || s.contains('\0')
        || lower.contains("%252e")
}

const MAX_FTP_RETR_BYTES: u64 = 10 * 1024 * 1024;
const MAX_FTP_LIST_ENTRIES: usize = 4096;
const MAX_FTP_LIST_BYTES: usize = 1024 * 1024;
const FTP_LIST_OK_MESSAGE: &str = "Directory send OK.";
const FTP_LIST_TRUNCATED_MESSAGE: &str = "Directory send OK (truncated).";

fn command_verb(command: &str) -> String {
    command
        .split_ascii_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches('\r')
        .to_ascii_uppercase()
}

fn command_arg(command: &str) -> &str {
    let trimmed = command.trim();
    let verb_end = trimmed
        .find(|ch: char| ch.is_ascii_whitespace())
        .unwrap_or(trimmed.len());
    trimmed[verb_end..].trim()
}

pub struct FtpHandler {
    banner: String,
    root_dir: Option<std::path::PathBuf>,
    pasv_port_start: u16,
    pasv_port_end: u16,
    pasv_port_counter: std::sync::atomic::AtomicU16,
    pasv_address: String,
}

impl FtpHandler {
    pub fn new() -> Self {
        Self {
            banner: "220 NetTrap FTP Ready".to_string(),
            root_dir: None,
            pasv_port_start: 60000,
            pasv_port_end: 60100,
            pasv_port_counter: std::sync::atomic::AtomicU16::new(0),
            pasv_address: "0,0,0,0".to_string(),
        }
    }

    pub fn with_banner(mut self, banner: impl Into<String>) -> Self {
        self.banner = banner.into();
        self
    }

    pub fn with_root_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.root_dir = Some(dir.into());
        self
    }

    pub fn with_pasv_ports(mut self, start: u16, end: u16) -> Self {
        self.pasv_port_start = start;
        self.pasv_port_end = end;
        self.pasv_port_counter = std::sync::atomic::AtomicU16::new(0);
        self
    }

    pub fn with_pasv_address(mut self, addr: impl Into<String>) -> Self {
        self.pasv_address = addr.into();
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
        let range = end.saturating_sub(start).saturating_add(1).max(1);
        (start + (current % range)) as u16
    }

    pub fn passive_address(&self) -> &str {
        &self.pasv_address
    }
}

impl Default for FtpHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Get default file content for an extension (FakeNet-NG compatible fallback)
fn default_file_for_extension(ext: &str) -> Option<&'static [u8]> {
    match ext.to_lowercase().as_str() {
        "html" | "htm" => Some(b"<html><body><h1>NetTrap</h1></body></html>"),
        "txt" => Some(b"NetTrap default text file\n"),
        "xml" => Some(b"<?xml version=\"1.0\"?><root><data>NetTrap</data></root>"),
        "json" => Some(b"{\"status\": \"ok\", \"source\": \"nettrap\"}"),
        "exe" | "dll" | "bin" => Some(&[0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00]), // MZ header stub
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
    ("setup.exe", 16),
];

#[cfg(unix)]
fn open_regular_file_no_final_symlink(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn open_regular_file_no_final_symlink(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_regular_file_no_final_symlink(path: &Path) -> io::Result<File> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

fn read_file_limited(path: &std::path::Path) -> std::io::Result<Option<Vec<u8>>> {
    let file = open_regular_file_no_final_symlink(path)?;

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

    fn build_listing_payload(
        entries: Option<std::fs::ReadDir>,
        style: FtpListStyle,
    ) -> (String, bool) {
        let mut listing = String::new();
        let mut saw_entry = false;
        let mut listed_entries = 0usize;
        let mut truncated = false;

        if let Some(entries) = entries {
            for entry in entries.flatten() {
                saw_entry = true;
                if listed_entries >= MAX_FTP_LIST_ENTRIES {
                    truncated = true;
                    break;
                }

                let line = match style {
                    FtpListStyle::Detailed => {
                        let name = entry.file_name().to_string_lossy().to_string();
                        let meta = entry.metadata().ok();
                        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                        format!(
                            "-rw-r--r--    1 ftp      ftp          {} Jan 01 00:00 {}\r\n",
                            size, name
                        )
                    }
                    FtpListStyle::NamesOnly => {
                        format!("{}\r\n", entry.file_name().to_string_lossy())
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

        (listing, truncated)
    }

    pub fn prepare_data_transfer(&self, command: &str) -> Result<FtpDataTransfer, FtpResponse> {
        let verb = command_verb(command);

        if verb == "LIST" {
            let entries = self
                .root_dir
                .as_ref()
                .and_then(|root| std::fs::read_dir(root).ok());
            let (listing, truncated) = Self::build_listing_payload(entries, FtpListStyle::Detailed);
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
            });
        }

        if verb == "NLST" {
            let entries = self
                .root_dir
                .as_ref()
                .and_then(|root| std::fs::read_dir(root).ok());
            let (listing, truncated) =
                Self::build_listing_payload(entries, FtpListStyle::NamesOnly);
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
            });
        }

        if verb == "RETR" {
            return self.prepare_retr_transfer(command);
        }

        Err(FtpResponse::new(502, "Data command not implemented"))
    }

    fn prepare_retr_transfer(&self, command: &str) -> Result<FtpDataTransfer, FtpResponse> {
        let filename = command_arg(command);

        if has_path_traversal(filename) {
            tracing::warn!("FTP path traversal attempt blocked: {:?}", filename);
            return Err(FtpResponse::new(550, "Invalid path"));
        }

        if let Some(ref root) = self.root_dir {
            let path = root.join(filename);
            let canonical_root = match root.canonicalize() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!("FTP root directory cannot be canonicalized");
                    return Err(FtpResponse::new(550, "Server configuration error"));
                }
            };
            let canonical_path = match path.canonicalize() {
                Ok(p) => p,
                Err(_) => {
                    if let Some(content) = default_file_for_extension(
                        std::path::Path::new(filename)
                            .extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or(""),
                    ) {
                        return Ok(Self::retr_transfer(filename, content.to_vec()));
                    }
                    return Err(FtpResponse::new(550, "File not found"));
                }
            };

            if !canonical_path.starts_with(&canonical_root) {
                tracing::warn!("Path traversal attempt blocked: {:?}", canonical_path);
                return Err(FtpResponse::new(550, "Access denied"));
            }

            match read_file_limited(&path) {
                Ok(Some(content)) => Ok(Self::retr_transfer(filename, content)),
                Ok(None) => {
                    tracing::warn!(
                        "FTP RETR file {:?} exceeds response size limit ({})",
                        canonical_path,
                        MAX_FTP_RETR_BYTES
                    );
                    Err(FtpResponse::new(552, "File too large"))
                }
                Err(_) => Err(FtpResponse::new(550, "File not found")),
            }
        } else {
            Ok(FtpDataTransfer {
                start_response: FtpResponse::new(150, "Opening data connection"),
                data: Vec::new(),
                complete_response: FtpResponse::new(226, "Transfer complete."),
            })
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
        }
    }

    pub fn handle(&self, command: &str) -> FtpResponse {
        let verb = command_verb(command);

        if verb == "USER" {
            FtpResponse::new(331, "Username OK, need password")
        } else if verb == "PASS" {
            FtpResponse::new(230, "User logged in")
        } else if verb == "PWD" {
            FtpResponse::new(257, "/")
        } else if verb == "TYPE" {
            FtpResponse::new(200, "Type set to I")
        } else if verb == "PASV" {
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
        } else if matches!(verb.as_str(), "LIST" | "NLST" | "RETR") {
            FtpResponse::new(425, "Use PASV or EPSV first")
        } else if matches!(verb.as_str(), "PORT" | "EPRT") {
            FtpResponse::new(502, "Active mode is not supported")
        } else if verb == "EPSV" {
            let port = self.next_passive_port();
            FtpResponse::new(
                229,
                format!("Entering Extended Passive Mode (|||{}|)", port),
            )
        } else if verb == "SYST" {
            FtpResponse::new(215, "UNIX Type: L8")
        } else if verb == "FEAT" {
            FtpResponse {
                code: 0,
                message:
                    "211-Features:\r\n PASV\r\n EPSV\r\n UTF8\r\n SIZE\r\n MDTM\r\n211 End\r\n"
                        .to_string(),
                raw: None,
            }
        } else if verb == "SIZE" {
            let filename = command_arg(command);
            if has_path_traversal(filename) {
                return FtpResponse::new(550, "Invalid path");
            }
            if let Some(ref root) = self.root_dir {
                let path = root.join(filename);
                let canonical_root = match root.canonicalize() {
                    Ok(p) => p,
                    Err(_) => return FtpResponse::new(550, "Server configuration error"),
                };
                let canonical_path = match path.canonicalize() {
                    Ok(p) => p,
                    Err(_) => {
                        // File doesn't exist, try extension fallback
                        let ext = std::path::Path::new(filename)
                            .extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("");
                        if let Some(content) = default_file_for_extension(ext) {
                            return FtpResponse::new(213, content.len().to_string());
                        }
                        return FtpResponse::new(550, "File not found");
                    }
                };
                if !canonical_path.starts_with(&canonical_root) {
                    return FtpResponse::new(550, "File not found");
                }
                let file = match open_regular_file_no_final_symlink(&path) {
                    Ok(file) => file,
                    Err(_) => return FtpResponse::new(550, "File not found"),
                };
                let size = file.metadata().map(|m| m.len()).unwrap_or(0);
                if size > MAX_FTP_RETR_BYTES {
                    FtpResponse::new(552, "File too large")
                } else {
                    FtpResponse::new(213, size.to_string())
                }
            } else {
                FtpResponse::new(213, "0")
            }
        } else if verb == "MDTM" {
            FtpResponse::new(213, "20240101000000")
        } else if matches!(verb.as_str(), "CWD" | "CDUP") {
            FtpResponse::new(250, "Directory changed")
        } else if matches!(verb.as_str(), "MKD" | "XMKD") {
            let dir = command_arg(command);
            let dir = if dir.is_empty() { "/new" } else { dir };
            FtpResponse::new(257, format!("\"{}\" directory created", dir))
        } else if matches!(verb.as_str(), "RMD" | "XRMD") {
            FtpResponse::new(250, "Directory removed")
        } else if verb == "DELE" {
            FtpResponse::new(250, "File deleted")
        } else if verb == "RNFR" {
            FtpResponse::new(350, "Ready for RNTO")
        } else if verb == "RNTO" {
            FtpResponse::new(250, "Rename successful")
        } else if matches!(verb.as_str(), "STOR" | "APPE") {
            FtpResponse::new(502, "Upload data transfers are not supported")
        } else if verb == "NOOP" {
            FtpResponse::new(200, "NOOP ok")
        } else if verb == "HELP" {
            FtpResponse { code: 0, message: "214-The following commands are recognized:\r\n USER PASS CWD CDUP QUIT PASV EPSV TYPE RETR\r\n PWD LIST NLST SIZE MDTM SYST STAT HELP NOOP\r\n214 Help OK.\r\n".to_string(), raw: None }
        } else if verb == "STAT" {
            FtpResponse::new(211, "NetTrap FTP Server status OK")
        } else if verb == "ABOR" {
            FtpResponse::new(226, "Abort successful")
        } else if verb == "QUIT" {
            FtpResponse::new(221, "Goodbye")
        } else {
            FtpResponse::new(200, "OK")
        }
    }

    pub fn get_banner(&self) -> Vec<u8> {
        let mut b = self.banner.as_bytes().to_vec();
        if !b.ends_with(b"\r\n") {
            b.extend_from_slice(b"\r\n");
        }
        b
    }
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
        if self.code == 0 {
            self.message.clone().into_bytes()
        } else {
            format!("{} {}\r\n", self.code, self.message).into_bytes()
        }
    }
}

pub fn resolve_banner(input: &str) -> String {
    match input {
        "!generic" | "" => "220 NetTrap FTP Ready".to_string(),
        // vsFTPd variants
        "!vsftpd" | "!vsftpd3" => "220 (vsFTPd 3.0.3)".to_string(),
        "!vsftpd2" => "220 (vsFTPd 2.3.5)".to_string(),
        "!vsftpd205" => "220 (vsFTPd 2.0.5)".to_string(),
        "!vsftpd207" => "220 (vsFTPd 2.0.7)".to_string(),
        // wu-ftpd variants
        "!wuftpd" => "220 nettrap FTP server (Version wu-2.6.2(1)) ready.".to_string(),
        "!wuftpd24" => "220 nettrap FTP server (Version wu-2.4.2-academ[BETA-18](1)) ready.".to_string(),
        "!wuftpd25" => "220 nettrap FTP server (Version wu-2.5.0(1)) ready.".to_string(),
        "!wuftpd261" => "220 nettrap FTP server (Version wu-2.6.1(1)) ready.".to_string(),
        // ProFTPD
        "!proftpd" => "220 ProFTPD 1.3.5 Server (nettrap) [::ffff:0.0.0.0]".to_string(),
        "!proftpd136" => "220 ProFTPD 1.3.6 Server (nettrap) [::ffff:0.0.0.0]".to_string(),
        "!proftpd137" => "220 ProFTPD 1.3.7 Server (nettrap) [::ffff:0.0.0.0]".to_string(),
        // PureFTPd
        "!pureftpd" => "220---------- Welcome to Pure-FTPd ----------\r\n220-Local time is now 00:00.\r\n220 You will be disconnected after 15 minutes of inactivity.".to_string(),
        // IIS variants
        "!iis" => "220 nettrap Microsoft FTP Service".to_string(),
        "!iis5" => "220 nettrap Microsoft FTP Service (Version 5.0).".to_string(),
        "!iis6" => "220 nettrap Microsoft FTP Service (Version 6.0).".to_string(),
        "!iis7" => "220-Microsoft FTP Service\r\n220 nettrap".to_string(),
        "!iis75" => "220-Microsoft FTP Service\r\n220 nettrap FTP".to_string(),
        // NcFTPD
        "!ncftpd" => "220 nettrap NcFTPd Server (Licensed Non-commercial use only) ready.".to_string(),
        // FileZilla
        "!filezilla" => "220-FileZilla Server 0.9.60 beta\r\n220-written by Tim Kosse (tim.kosse@filezilla-project.org)\r\n220 Please visit https://filezilla-project.org/".to_string(),
        "!filezilla1" => "220 FileZilla Server 1.0.0".to_string(),
        // WS_FTP
        "!wsftp" => "220 nettrap X2 WS_FTP Server 7.7(0)".to_string(),
        // Serv-U
        "!servu" => "220 Serv-U FTP Server v15.1 ready...".to_string(),
        // BulletProof FTP
        "!bpftp" => "220 BulletProof FTP Server ready ...".to_string(),
        // Gene6
        "!gene6" => "220 Gene6 FTP Server v3.10.0 (Build 2) ready...".to_string(),
        // glFTPd
        "!glftpd" => "220 nettrap (glFTPd 2.11 Linux+TLS)".to_string(),
        // CrushFTP
        "!crushftp" => "220 CrushFTP Server Ready.".to_string(),
        // OpenBSD ftpd
        "!openbsd" => "220 nettrap FTP server (OpenBSD ftpd 6.9) ready.".to_string(),
        // FreeBSD ftpd
        "!freebsd" => "220 nettrap FTP server (Version 6.00LS) ready.".to_string(),

        // vsFTPd extended
        "!vsftpd200" => "220 (vsFTPd 2.0.0)".to_string(),
        "!vsftpd201" => "220 (vsFTPd 2.0.1)".to_string(),
        "!vsftpd210" => "220 (vsFTPd 2.1.0)".to_string(),
        "!vsftpd212" => "220 (vsFTPd 2.1.2)".to_string(),
        "!vsftpd220" => "220 (vsFTPd 2.2.0)".to_string(),
        "!vsftpd222" => "220 (vsFTPd 2.2.2)".to_string(),
        "!vsftpd230" => "220 (vsFTPd 2.3.0)".to_string(),
        "!vsftpd232" => "220 (vsFTPd 2.3.2)".to_string(),
        "!vsftpd234" => "220 (vsFTPd 2.3.4)".to_string(),
        "!vsftpd300" => "220 (vsFTPd 3.0.0)".to_string(),
        "!vsftpd302" => "220 (vsFTPd 3.0.2)".to_string(),
        "!vsftpd305" => "220 (vsFTPd 3.0.5)".to_string(),

        // wu-ftpd extended
        "!wuftpd240" => "220 nettrap FTP server (Version wu-2.4.0(1)) ready.".to_string(),
        "!wuftpd241" => "220 nettrap FTP server (Version wu-2.4.1(1)) ready.".to_string(),
        "!wuftpd242" => "220 nettrap FTP server (Version wu-2.4.2-academ[BETA-18](1)) ready.".to_string(),
        "!wuftpd250" => "220 nettrap FTP server (Version wu-2.5.0(1)) ready.".to_string(),
        "!wuftpd260" => "220 nettrap FTP server (Version wu-2.6.0(1)) ready.".to_string(),
        "!wuftpd262" => "220 nettrap FTP server (Version wu-2.6.2(5)) ready.".to_string(),

        // IIS extended
        "!iis3" => "220 nettrap Microsoft FTP Service (Version 3.0).".to_string(),
        "!iis4" => "220 nettrap Microsoft FTP Service (Version 4.0).".to_string(),
        "!iis10" => "220-Microsoft FTP Service\r\n220 nettrap FTP Service".to_string(),

        // WS_FTP extended
        "!wsftp2" => "220 nettrap V2 WS_FTP Server 2.0.4 (0)".to_string(),
        "!wsftpx2" => "220 nettrap X2 WS_FTP Server 7.7(0)".to_string(),
        "!wsftp3" => "220 nettrap WS_FTP Server 3.1.3 (0)".to_string(),

        // Serv-U extended
        "!servu6" => "220 Serv-U FTP Server v6.4 for WinSock ready...".to_string(),
        "!servu15" => "220 Serv-U FTP Server v15.1 ready...".to_string(),
        "!servu153" => "220 Serv-U FTP Server v15.3 ready...".to_string(),

        // ProFTPD extended
        "!proftpd131" => "220 ProFTPD 1.3.1 Server (nettrap)".to_string(),
        "!proftpd132" => "220 ProFTPD 1.3.2 Server (nettrap)".to_string(),
        "!proftpd133" => "220 ProFTPD 1.3.3 Server (nettrap)".to_string(),
        "!proftpd134" => "220 ProFTPD 1.3.4 Server (nettrap)".to_string(),
        "!proftpd138" => "220 ProFTPD 1.3.8 Server (nettrap) [::ffff:0.0.0.0]".to_string(),

        // FileZilla extended
        "!filezilla094" => "220-FileZilla Server 0.9.41 beta\r\n220 Welcome".to_string(),
        "!filezilla095" => "220-FileZilla Server 0.9.53 beta\r\n220 Welcome".to_string(),
        "!filezilla10" => "220 FileZilla Server 1.0.0".to_string(),
        "!filezilla11" => "220 FileZilla Server 1.1.0".to_string(),

        // PureFTPd extended
        "!pureftpd13" => "220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------\r\n220-Local time is now 00:00.\r\n220 You will be disconnected after 15 minutes of inactivity.".to_string(),

        // glFTPd extended
        "!glftpd20" => "220 nettrap (glFTPd 2.01 Linux+TLS)".to_string(),
        "!glftpd211" => "220 nettrap (glFTPd 2.11 Linux+TLS)".to_string(),

        // CrushFTP extended
        "!crushftp8" => "220 CrushFTP Server Ready. (CrushFTP version 8.0)".to_string(),
        "!crushftp9" => "220 CrushFTP Server Ready. (CrushFTP version 9.0)".to_string(),
        "!crushftp10" => "220 CrushFTP Server Ready. (CrushFTP version 10.0)".to_string(),

        // BSD ftpd
        "!netbsd" => "220 nettrap FTP server (NetBSD-ftpd 20100515) ready.".to_string(),
        "!dragonfly" => "220 nettrap FTP server (Version 6.00LS) ready.".to_string(),

        // Solaris ftpd
        "!solaris" => "220 nettrap FTP server ready.".to_string(),
        "!solaris10" => "220 nettrap FTP server (SunOS 5.10) ready.".to_string(),

        // Cisco
        "!cisco" => "220 nettrap FTP server (Cisco IOS) ready.".to_string(),

        // Cerberus
        "!cerberus" => "220 Cerberus FTP Server - Professional Edition ready".to_string(),

        // Titan FTP
        "!titan" => "220 Titan FTP Server 2019 Ready.".to_string(),

        // CompleteFTP
        "!completeftp" => "220 CompleteFTP-22.1.1 - www.completeftp.com".to_string(),

        // RaidenFTPD
        "!raiden" => "220 RaidenFTPd 2.4 ready.".to_string(),

        // War-FTPD
        "!warftp" => "220- War-FTPD 1.82.00-R13 (Nov 01 2006) Ready\r\n220 Please enter your user name.".to_string(),

        // GlobalSCAPE EFT
        "!eft" => "220 EFT Server Enterprise 8.0.0.0 ready".to_string(),

        // Xlight FTP
        "!xlight" => "220 Xlight FTP Server 3.9 ready...".to_string(),

        // HP NonStop FTP
        "!hpnonstop" => "220 nettrap HP NonStop FTP Server - T9552H01".to_string(),

        // Tectia SSH
        "!tectia" => "220 nettrap SSH Tectia Server - FTP subsystem ready".to_string(),

        // ASUS Router
        "!asus" => "220 Welcome to ASUS RT-AX88U FTP service.".to_string(),

        // Synology NAS
        "!synology" => "220 Synology FTP server ready.".to_string(),

        // QNAP NAS
        "!qnap" => "220 NASFTPD Turbo station 4.5.4".to_string(),

        // MikroTik
        "!mikrotik" => "220 MikroTik FTP server (MikroTik 6.49) ready".to_string(),

        // D-Link
        "!dlink" => "220 DI-804HV FTP server ready".to_string(),

        // z/OS MVS
        "!zos" => "220-FTPD1 IBM FTP CS V2R4 at nettrap, 00:00:00 on 2024-01-01.\r\n220 Connection will close if idle for more than 5 minutes.".to_string(),

        // AS/400
        "!as400" => "220-QTCP at nettrap.\r\n220 Connection will close if idle more than 300 seconds.".to_string(),

        // Random
        "!random" => {
            let presets = [
                "!vsftpd", "!vsftpd2", "!vsftpd305", "!wuftpd", "!wuftpd262",
                "!iis", "!iis6", "!iis7", "!ncftpd", "!proftpd", "!proftpd138",
                "!pureftpd", "!filezilla", "!filezilla11", "!servu", "!servu15",
                "!openbsd", "!freebsd", "!glftpd", "!crushftp10", "!cerberus",
                "!titan", "!synology", "!qnap",
            ];
            let idx = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as usize % presets.len();
            resolve_banner(presets[idx])
        }
        other => {
            if other.starts_with("!hostname") || other.starts_with("!gethostname") {
                let hostname = hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "nettrap".to_string());
                format!("220 {} FTP Ready", hostname)
            } else {
                format!("220 {}", other)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
            .prepare_data_transfer("RETR large.bin")
            .expect_err("large file should be rejected");

        assert_eq!(response.code, 552);
        assert!(response.raw.is_none());
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
    fn empty_root_list_uses_bounded_virtual_listing() {
        let root = unique_temp_dir("nettrap-ftp-empty-list");
        std::fs::create_dir_all(&root).expect("create temp root");

        let transfer = FtpHandler::new()
            .with_root_dir(&root)
            .prepare_data_transfer("LIST")
            .expect("list transfer");

        assert_eq!(transfer.start_response.code, 150);
        assert!(String::from_utf8_lossy(&transfer.data).contains("index.html"));
        assert!(transfer.data.len() <= MAX_FTP_LIST_BYTES);
        assert_eq!(transfer.complete_response.code, 226);
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn handle_list_requires_passive_connection() {
        let response = FtpHandler::new().handle("LIST");

        assert_eq!(response.code, 425);
    }

    #[test]
    fn prefixed_data_verbs_do_not_trigger_transfers() {
        let handler = FtpHandler::new();

        let response = handler
            .prepare_data_transfer("LISTEN")
            .expect_err("LISTEN must not be parsed as LIST");
        assert_eq!(response.code, 502);

        let response = handler.handle("RETRIEVE file.txt");
        assert_ne!(response.code, 425);

        let response = handler.handle("PASVXYZ");
        assert_ne!(response.code, 227);
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
            .prepare_data_transfer("RETR link.txt")
            .expect_err("final symlink should be rejected");

        assert_eq!(response.code, 550);
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!("{}-{}", prefix, std::process::id()))
    }
}
