use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const MAX_FILE_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;

enum WebrootServeResult {
    Found { content: Vec<u8>, mime: String },
    TooLarge,
    NotFound,
}

enum LimitedFileRead {
    Content(Vec<u8>),
    TooLarge,
    NotFile,
}

/// Serves files from a webroot directory with MIME type detection
pub struct WebrootServer {
    root: PathBuf,
    mime_types: HashMap<String, String>,
}

impl WebrootServer {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let mut mime_types = HashMap::new();
        mime_types.insert("html".into(), "text/html".into());
        mime_types.insert("htm".into(), "text/html".into());
        mime_types.insert("css".into(), "text/css".into());
        mime_types.insert("js".into(), "application/javascript".into());
        mime_types.insert("json".into(), "application/json".into());
        mime_types.insert("xml".into(), "application/xml".into());
        mime_types.insert("txt".into(), "text/plain".into());
        mime_types.insert("png".into(), "image/png".into());
        mime_types.insert("jpg".into(), "image/jpeg".into());
        mime_types.insert("jpeg".into(), "image/jpeg".into());
        mime_types.insert("gif".into(), "image/gif".into());
        mime_types.insert("ico".into(), "image/x-icon".into());
        mime_types.insert("svg".into(), "image/svg+xml".into());
        mime_types.insert("pdf".into(), "application/pdf".into());
        mime_types.insert("zip".into(), "application/zip".into());
        mime_types.insert("exe".into(), "application/octet-stream".into());
        mime_types.insert("dll".into(), "application/octet-stream".into());
        mime_types.insert("bin".into(), "application/octet-stream".into());

        Self {
            root: root.into(),
            mime_types,
        }
    }

    /// Resolve a request path to a file and return (content, mime_type)
    pub fn serve(&self, path: &str) -> Option<(Vec<u8>, String)> {
        match self.serve_result(path) {
            WebrootServeResult::Found { content, mime } => Some((content, mime)),
            WebrootServeResult::TooLarge | WebrootServeResult::NotFound => None,
        }
    }

    fn serve_result(&self, path: &str) -> WebrootServeResult {
        let clean_path = path.trim_start_matches('/');
        // Reject paths containing traversal components (both Unix and Windows separators)
        if clean_path.contains("..") || clean_path.contains('\\') {
            tracing::warn!("Path traversal attempt blocked: {}", path);
            return WebrootServeResult::NotFound;
        }
        let file_path = self.root.join(clean_path);

        // Try canonicalize root; if it fails (dir doesn't exist yet), use the path directly
        // but still check for traversal using a simpler approach
        let canonical_root = match self.root.canonicalize() {
            Ok(p) => p,
            Err(_) => {
                // Root doesn't exist yet - check file existence with symlink validation
                let candidates = vec![file_path.clone(), file_path.join("index.html")];
                for candidate in candidates {
                    if candidate.is_file() {
                        // Verify the resolved path doesn't escape the root via symlinks
                        if let Ok(canon) = candidate.canonicalize() {
                            let abs_root =
                                std::path::absolute(&self.root).unwrap_or(self.root.clone());
                            if !canon.starts_with(&abs_root) {
                                tracing::warn!(
                                    "Symlink escape blocked: {:?} -> {:?}",
                                    candidate,
                                    canon
                                );
                                return WebrootServeResult::NotFound;
                            }
                        }
                        match self.read_candidate(&candidate) {
                            WebrootServeResult::NotFound => {}
                            result => return result,
                        }
                    }
                }
                return WebrootServeResult::NotFound;
            }
        };
        // Try exact path, then with index.html
        // Each candidate is canonicalized individually in the loop below
        let candidates = vec![file_path.clone(), file_path.join("index.html")];

        for candidate in candidates {
            if candidate.is_file() {
                // Canonicalize each candidate individually to prevent symlink escapes
                let canonical_candidate = match candidate.canonicalize() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                if !canonical_candidate.starts_with(&canonical_root) {
                    tracing::warn!("Path traversal attempt blocked: {:?}", candidate);
                    continue;
                }
                match self.read_candidate(&candidate) {
                    WebrootServeResult::NotFound => {}
                    result => return result,
                }
            }
        }

        WebrootServeResult::NotFound
    }

    fn read_candidate(&self, candidate: &Path) -> WebrootServeResult {
        match read_limited_file(candidate, MAX_FILE_RESPONSE_BYTES) {
            Ok(LimitedFileRead::Content(content)) => WebrootServeResult::Found {
                mime: self.mime_for_path(candidate),
                content,
            },
            Ok(LimitedFileRead::TooLarge) => {
                tracing::warn!(
                    "Webroot file {:?} exceeds response size limit (>{})",
                    candidate,
                    MAX_FILE_RESPONSE_BYTES
                );
                WebrootServeResult::TooLarge
            }
            Ok(LimitedFileRead::NotFile) | Err(_) => WebrootServeResult::NotFound,
        }
    }

    fn mime_for_path(&self, path: &Path) -> String {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        self.mime_types
            .get(&ext)
            .cloned()
            .unwrap_or_else(|| "application/octet-stream".into())
    }

    /// Try to find the defaultFiles directory relative to the executable
    pub fn default_files_dir() -> Option<PathBuf> {
        // Try relative to executable
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let default_dir = dir.join("defaultFiles");
                if default_dir.is_dir() {
                    return Some(default_dir);
                }
                // Try one level up (for dev builds)
                if let Some(parent) = dir.parent() {
                    let default_dir = parent.join("defaultFiles");
                    if default_dir.is_dir() {
                        return Some(default_dir);
                    }
                }
            }
        }
        // Try current directory
        let cwd = PathBuf::from("defaultFiles");
        if cwd.is_dir() {
            return Some(cwd);
        }
        None
    }

    /// Build an HTTP response from webroot file, falling back to fake file generation
    pub fn build_http_response(&self, path: &str) -> Vec<u8> {
        // Try webroot first; if not found, try fake file by extension
        match self.serve_result(path) {
            WebrootServeResult::Found { content, mime } => {
                let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
                return format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nDate: {}\r\nServer: NetTrap\r\n\r\n",
                    mime, content.len(), date
                ).into_bytes()
                .into_iter()
                .chain(content)
                .collect();
            }
            WebrootServeResult::TooLarge => {
                return simple_http_response(413, "Payload Too Large", "Payload Too Large");
            }
            WebrootServeResult::NotFound => {}
        }

        // Fallback: fake file by extension
        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        if let Some((content, mime)) = fake_file_for_extension(&ext) {
            let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
            return format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nDate: {}\r\nServer: NetTrap\r\n\r\n",
                mime, content.len(), date
            ).into_bytes()
            .into_iter()
            .chain(content)
            .collect();
        }

        // Default 404
        let body = b"<html><body><h1>404 Not Found</h1></body></html>";
        format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .collect()
    }
}

fn simple_http_response(code: u16, reason: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        code,
        reason,
        body.len(),
        body
    )
    .into_bytes()
}

fn read_limited_file(path: &Path, max_bytes: u64) -> std::io::Result<LimitedFileRead> {
    let file = match open_regular_file_no_final_symlink(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => {
            return Ok(LimitedFileRead::NotFile);
        }
        Err(err) => return Err(err),
    };
    let metadata = file.metadata()?;
    if metadata.len() > max_bytes {
        return Ok(LimitedFileRead::TooLarge);
    }

    let mut limited = file.take(max_bytes + 1);
    let mut content = Vec::new();
    limited.read_to_end(&mut content)?;
    if content.len() as u64 > max_bytes {
        return Ok(LimitedFileRead::TooLarge);
    }

    Ok(LimitedFileRead::Content(content))
}

#[cfg(unix)]
fn open_regular_file_no_final_symlink(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure_regular_file(file)
}

#[cfg(windows)]
fn open_regular_file_no_final_symlink(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    ensure_regular_file(file)
}

#[cfg(not(any(unix, windows)))]
fn open_regular_file_no_final_symlink(path: &Path) -> io::Result<File> {
    ensure_regular_file(File::open(path)?)
}

fn ensure_regular_file(file: File) -> io::Result<File> {
    if file.metadata()?.is_file() {
        Ok(file)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ))
    }
}

/// Generate a fake file with appropriate content and MIME type for a given extension.
/// Returns None if the extension is not recognized.
pub fn fake_file_for_extension(ext: &str) -> Option<(Vec<u8>, String)> {
    match ext {
        // ── Text / markup ────────────────────────────────────────────
        "html" | "htm" => Some((
            b"<html><head><title>Welcome</title></head><body><h1>Hello</h1><p>Welcome to the server.</p></body></html>".to_vec(),
            "text/html".into(),
        )),
        "txt" => Some((
            b"This is a text file served by the server.\r\n".to_vec(),
            "text/plain".into(),
        )),
        "xml" => Some((
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root><message>Hello</message></root>".to_vec(),
            "application/xml".into(),
        )),
        "json" => Some((
            b"{\"status\":\"ok\",\"message\":\"Hello\"}".to_vec(),
            "application/json".into(),
        )),
        "css" => Some((
            b"body { margin: 0; font-family: sans-serif; }\n".to_vec(),
            "text/css".into(),
        )),
        "js" => Some((
            b"// JavaScript\nconsole.log('loaded');\n".to_vec(),
            "application/javascript".into(),
        )),
        "csv" => Some((
            b"name,value\r\nfoo,1\r\nbar,2\r\n".to_vec(),
            "text/csv".into(),
        )),

        // ── Executables / binaries ───────────────────────────────────
        "exe" => {
            // Minimal MZ PE header stub
            let mut pe = vec![0x4Du8, 0x5A]; // MZ
            pe.extend_from_slice(&[0x90, 0x00, 0x03, 0x00, 0x00, 0x00]); // DOS header padding
            pe.resize(256, 0x00);
            Some((pe, "application/octet-stream".into()))
        }
        "dll" => {
            let mut pe = vec![0x4Du8, 0x5A];
            pe.extend_from_slice(&[0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
            pe.resize(256, 0x00);
            Some((pe, "application/octet-stream".into()))
        }
        "bin" | "dat" => Some((
            vec![0x00u8; 256],
            "application/octet-stream".into(),
        )),
        "msi" => Some((
            // Minimal OLE compound document magic
            vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00, 0x00],
            "application/x-msi".into(),
        )),

        // ── PDF ──────────────────────────────────────────────────────
        "pdf" => Some((
            b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n\
              2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n\
              3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n\
              xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n\
              0000000052 00000 n \n0000000101 00000 n \n\
              trailer<</Size 4/Root 1 0 R>>\nstartxref\n170\n%%EOF"
                .to_vec(),
            "application/pdf".into(),
        )),

        // ── Images ───────────────────────────────────────────────────
        "png" => {
            // 1x1 transparent PNG
            let png: Vec<u8> = vec![
                0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
                0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
                0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89,
                0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, // IDAT chunk
                0x78, 0x9C, 0x62, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xE5,
                0x27, 0xDE, 0xFC,
                0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, // IEND chunk
                0xAE, 0x42, 0x60, 0x82,
            ];
            Some((png, "image/png".into()))
        }
        "jpg" | "jpeg" => {
            // Minimal JFIF header (1x1 white pixel)
            let jpg: Vec<u8> = vec![
                0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00,
                0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
                0xFF, 0xD9,
            ];
            Some((jpg, "image/jpeg".into()))
        }
        "gif" => {
            // 1x1 GIF89a
            let gif: Vec<u8> = vec![
                0x47, 0x49, 0x46, 0x38, 0x39, 0x61, // GIF89a
                0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
                0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, // color table
                0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
                0x02, 0x02, 0x44, 0x01, 0x00, 0x3B,
            ];
            Some((gif, "image/gif".into()))
        }
        "ico" => {
            // Minimal ICO (1x1)
            let mut ico = vec![0x00u8, 0x00, 0x01, 0x00, 0x01, 0x00]; // ICO header, 1 image
            ico.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x18, 0x00]); // 1x1, 24bpp
            ico.extend_from_slice(&[0x0A, 0x00, 0x00, 0x00]); // size
            ico.extend_from_slice(&[0x16, 0x00, 0x00, 0x00]); // offset
            // BMP data
            ico.extend_from_slice(&[0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00]);
            Some((ico, "image/x-icon".into()))
        }
        "svg" => Some((
            b"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1\" height=\"1\"><rect width=\"1\" height=\"1\" fill=\"white\"/></svg>".to_vec(),
            "image/svg+xml".into(),
        )),
        "bmp" => {
            // 1x1 BMP
            let mut bmp = vec![0x42u8, 0x4D]; // BM
            bmp.extend_from_slice(&[0x3A, 0x00, 0x00, 0x00]); // file size = 58
            bmp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved
            bmp.extend_from_slice(&[0x36, 0x00, 0x00, 0x00]); // offset
            bmp.extend_from_slice(&[0x28, 0x00, 0x00, 0x00]); // DIB header size
            bmp.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // width = 1
            bmp.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // height = 1
            bmp.extend_from_slice(&[0x01, 0x00, 0x18, 0x00]); // planes=1, bpp=24
            bmp.resize(58, 0x00);
            bmp[54] = 0xFF; bmp[55] = 0xFF; bmp[56] = 0xFF; // white pixel
            Some((bmp, "image/bmp".into()))
        }

        // ── Archives ─────────────────────────────────────────────────
        "zip" => {
            // Empty ZIP (end of central directory record)
            let zip: Vec<u8> = vec![
                0x50, 0x4B, 0x05, 0x06, // EOCD signature
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ];
            Some((zip, "application/zip".into()))
        }
        "tar" => Some((
            vec![0x00u8; 512], // empty tar block
            "application/x-tar".into(),
        )),
        "gz" | "tgz" => Some((
            vec![0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03],
            "application/gzip".into(),
        )),
        "7z" => Some((
            vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], // 7z magic
            "application/x-7z-compressed".into(),
        )),
        "rar" => Some((
            vec![0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00], // RAR5 magic
            "application/x-rar-compressed".into(),
        )),

        // ── Documents ────────────────────────────────────────────────
        "doc" | "xls" | "ppt" => Some((
            // OLE compound document magic
            vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00, 0x00],
            "application/octet-stream".into(),
        )),
        "docx" | "xlsx" | "pptx" => {
            // These are ZIP-based; use empty ZIP
            let zip: Vec<u8> = vec![
                0x50, 0x4B, 0x05, 0x06,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ];
            Some((zip, "application/octet-stream".into()))
        }
        "rtf" => Some((
            b"{\\rtf1\\ansi{\\fonttbl{\\f0 Times New Roman;}}\\pard Hello\\par}".to_vec(),
            "application/rtf".into(),
        )),

        // ── Flash / Java / Android ───────────────────────────────────
        "swf" => Some((
            vec![0x46, 0x57, 0x53, 0x09, 0x00, 0x00, 0x00, 0x00], // FWS (uncompressed SWF)
            "application/x-shockwave-flash".into(),
        )),
        "class" => {
            // Java class magic
            let class: Vec<u8> = vec![
                0xCA, 0xFE, 0xBA, 0xBE, // magic
                0x00, 0x00, 0x00, 0x34, // Java 8 class version
            ];
            Some((class, "application/java-vm".into()))
        }
        "jar" => {
            // JAR = ZIP with META-INF
            let zip: Vec<u8> = vec![
                0x50, 0x4B, 0x05, 0x06,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ];
            Some((zip, "application/java-archive".into()))
        }
        "apk" => {
            // APK = ZIP
            let zip: Vec<u8> = vec![
                0x50, 0x4B, 0x05, 0x06,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ];
            Some((zip, "application/vnd.android.package-archive".into()))
        }

        // ── Audio / Video ────────────────────────────────────────────
        "mp3" => Some((
            vec![0xFF, 0xFB, 0x90, 0x00], // MP3 frame header
            "audio/mpeg".into(),
        )),
        "mp4" | "m4a" => Some((
            vec![0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D],
            "video/mp4".into(),
        )),
        "wav" => {
            let mut wav = b"RIFF".to_vec();
            wav.extend_from_slice(&[0x24, 0x00, 0x00, 0x00]); // file size - 8
            wav.extend_from_slice(b"WAVE");
            wav.extend_from_slice(b"fmt ");
            wav.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // chunk size
            wav.extend_from_slice(&[0x01, 0x00]); // PCM
            wav.extend_from_slice(&[0x01, 0x00]); // mono
            wav.extend_from_slice(&[0x44, 0xAC, 0x00, 0x00]); // 44100 Hz
            wav.extend_from_slice(&[0x88, 0x58, 0x01, 0x00]); // byte rate
            wav.extend_from_slice(&[0x02, 0x00, 0x10, 0x00]); // block align, bits
            wav.extend_from_slice(b"data");
            wav.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // data size
            Some((wav, "audio/wav".into()))
        }

        // ── Fonts ────────────────────────────────────────────────────
        "woff" => Some((
            vec![0x77, 0x4F, 0x46, 0x46], // wOFF magic
            "font/woff".into(),
        )),
        "woff2" => Some((
            vec![0x77, 0x4F, 0x46, 0x32], // wOF2 magic
            "font/woff2".into(),
        )),

        // ── Other ────────────────────────────────────────────────────
        "eml" => Some((
            b"From: user@example.com\r\nTo: admin@example.com\r\nSubject: Test\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\nTest email.\r\n".to_vec(),
            "message/rfc822".into(),
        )),
        "elf" | "so" => {
            // ELF magic
            let elf = vec![0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
            Some((elf, "application/octet-stream".into()))
        }
        "deb" => Some((
            b"!<arch>\ndebian-binary   0           0     0     100644  4         `\n2.0\n".to_vec(),
            "application/vnd.debian.binary-package".into(),
        )),
        "rpm" => Some((
            vec![0xED, 0xAB, 0xEE, 0xDB], // RPM magic
            "application/x-rpm".into(),
        )),
        "dmg" => Some((
            vec![0x78, 0x01, 0x73, 0x0D, 0x62, 0x62, 0x60], // compressed DMG stub
            "application/x-apple-diskimage".into(),
        )),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_http_response_rejects_large_webroot_file() {
        let root = unique_temp_dir("nettrap-webroot-limit");
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("large.bin");
        let file = std::fs::File::create(&path).expect("create sparse file");
        file.set_len(MAX_FILE_RESPONSE_BYTES + 1)
            .expect("extend sparse file");

        let response = WebrootServer::new(&root).build_http_response("/large.bin");

        assert!(response.starts_with(b"HTTP/1.1 413 Payload Too Large"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn build_http_response_allows_webroot_file_at_size_limit() {
        let root = unique_temp_dir("nettrap-webroot-limit-ok");
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("limit.bin");
        let file = std::fs::File::create(&path).expect("create sparse file");
        file.set_len(MAX_FILE_RESPONSE_BYTES)
            .expect("extend sparse file");

        let response = WebrootServer::new(&root).build_http_response("/limit.bin");

        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(String::from_utf8_lossy(&response[..128]).contains("Content-Length: 10485760"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[cfg(unix)]
    #[test]
    fn build_http_response_rejects_final_symlink_inside_root() {
        use std::os::unix::fs::symlink;

        let root = unique_temp_dir("nettrap-webroot-symlink");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(root.join("real.html"), b"<html>secret</html>").expect("write fixture");
        symlink("real.html", root.join("link.html")).expect("create symlink");

        let response = WebrootServer::new(&root).build_http_response("/link.html");

        assert!(!String::from_utf8_lossy(&response).contains("secret"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!("{}-{}", prefix, std::process::id()))
    }
}
