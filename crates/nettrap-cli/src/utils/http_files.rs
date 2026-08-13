use std::borrow::Cow;
use std::io::Read;
use std::path::{Path, PathBuf};

use nettrap_fsutil::open_regular_file_beneath_root;

use super::*;

/// Build an HTTP response with fake file content based on path extension.
pub fn build_http_response_with_fakefile(path: &str, server: &str) -> Vec<u8> {
    let exact_path = normalize_request_path(path).to_string();
    let lookup_path = normalize_request_path_for_lookup(path);
    if request_path_is_unsafe(&exact_path) {
        return build_http_response_with_text(404, "Not Found", server);
    }

    match load_default_file_for_path(&exact_path, false) {
        Ok(DefaultFileLookup::Content { content, mime }) => {
            return build_http_response_with_body(content, &mime, server);
        }
        Ok(DefaultFileLookup::TooLarge) => {
            return build_http_response_with_text(413, "Payload Too Large", server);
        }
        Ok(DefaultFileLookup::NotFound) => {}
        Err(err) => {
            tracing::warn!(
                "Failed to read defaultFiles asset for {}: {}",
                exact_path,
                err
            );
            return build_http_response_with_text(500, "Internal Server Error", server);
        }
    }

    if lookup_path != exact_path {
        match load_default_file_for_path(&lookup_path, false) {
            Ok(DefaultFileLookup::Content { content, mime }) => {
                return build_http_response_with_body(content, &mime, server);
            }
            Ok(DefaultFileLookup::TooLarge) => {
                return build_http_response_with_text(413, "Payload Too Large", server);
            }
            Ok(DefaultFileLookup::NotFound) => {}
            Err(err) => {
                tracing::warn!(
                    "Failed to read defaultFiles asset for {}: {}",
                    lookup_path,
                    err
                );
                return build_http_response_with_text(500, "Internal Server Error", server);
            }
        }
    }

    if request_path_is_unsafe(&lookup_path) {
        return build_http_response_with_text(404, "Not Found", server);
    }

    let ext = std::path::Path::new(&lookup_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let (content, mime) = crate::webroot::fake_file_for_extension(&ext)
        .unwrap_or_else(|| (DEFAULT_FAKE_HTML.to_vec(), "text/html".to_string()));

    build_http_response_with_body(content, &mime, server)
}

const DEFAULT_FAKE_HTML: &[u8] =
    b"<html><head><title>Index</title></head><body><h1>Index</h1></body></html>";
pub(crate) const MAX_DEFAULT_FILE_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;

enum DefaultFileLookup {
    Content { content: Vec<u8>, mime: String },
    TooLarge,
    NotFound,
}

fn load_default_file_for_path(
    path: &str,
    strip_path_parameters: bool,
) -> Result<DefaultFileLookup, std::io::Error> {
    let Some(root) = crate::webroot::WebrootServer::default_files_dir() else {
        return Ok(DefaultFileLookup::NotFound);
    };
    let candidates = default_file_candidate_paths(path, strip_path_parameters);
    if candidates.is_empty() {
        return Ok(DefaultFileLookup::NotFound);
    }

    let mut saw_strict_non_file_candidate = false;
    for (candidate, strict) in candidates {
        let Some(file_name) = candidate.file_name() else {
            continue;
        };
        let path_name = file_name.to_string_lossy().to_ascii_lowercase();
        let candidate_is_unsafe = candidate_is_unsafe(&candidate);

        let file = match open_regular_file_beneath_root(&root, &candidate) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput && candidate_is_unsafe => {
                continue;
            }
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                saw_strict_non_file_candidate |= strict;
                continue;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };

        let metadata = file.metadata()?;
        if metadata.len() > MAX_DEFAULT_FILE_RESPONSE_BYTES {
            return Ok(DefaultFileLookup::TooLarge);
        }

        let mut file = file.take(MAX_DEFAULT_FILE_RESPONSE_BYTES + 1);
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        if content.len() as u64 > MAX_DEFAULT_FILE_RESPONSE_BYTES {
            return Ok(DefaultFileLookup::TooLarge);
        }
        let mime = match path_name.as_str() {
            "fake.net.html" | "fake.net.htm" | "index.html" | "index.htm" | "ncsi.html" => {
                "text/html"
            }
            "fake.net.json" | "ncsi.json" => "application/json",
            "fake.net.txt" | "ncsi.txt" => "text/plain",
            "fake.net.xml" | "ncsi.xml" => "application/xml",
            _ => match candidate
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.to_ascii_lowercase())
                .as_deref()
            {
                Some("html") | Some("htm") => "text/html",
                Some("json") => "application/json",
                Some("txt") => "text/plain",
                Some("xml") => "application/xml",
                _ => "application/octet-stream",
            },
        };

        return Ok(DefaultFileLookup::Content {
            content,
            mime: mime.to_string(),
        });
    }

    if saw_strict_non_file_candidate {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "defaultFiles asset is not a regular file",
        ));
    }

    Ok(DefaultFileLookup::NotFound)
}

fn default_file_candidate_paths(path: &str, strip_path_parameters: bool) -> Vec<(PathBuf, bool)> {
    let normalized_path = if strip_path_parameters {
        normalize_request_path_for_lookup(path)
    } else {
        normalize_request_path(path).to_string()
    };
    let clean_path = normalized_path.trim_start_matches('/');
    let relative_path = Path::new(clean_path);
    let mut candidates = Vec::new();
    let strict_file_lookup = !clean_path.ends_with('/');

    if !relative_path.as_os_str().is_empty() {
        candidates.push((relative_path.to_path_buf(), strict_file_lookup));
        candidates.push((relative_path.join("index.html"), false));

        if let Some(file_name) = relative_path.file_name().and_then(|name| name.to_str()) {
            let file_name_path = PathBuf::from(file_name);
            if file_name_path != relative_path {
                candidates.push((file_name_path.clone(), strict_file_lookup));
            }
            candidates.push((file_name_path.join("index.html"), false));

            let ext = Path::new(file_name)
                .extension()
                .and_then(|e| e.to_str())
                .map(|ext| ext.to_ascii_lowercase());
            let mapped = match file_name {
                "NCSI.txt" | "ncsi.txt" => Some(PathBuf::from("NCSI.txt")),
                _ => match ext.as_deref() {
                    Some("htm") | Some("html") => Some(PathBuf::from("NetTrap.html")),
                    Some("json") => Some(PathBuf::from("NetTrap.json")),
                    Some("txt") => Some(PathBuf::from("NetTrap.txt")),
                    Some("xml") => Some(PathBuf::from("NetTrap.xml")),
                    None => Some(PathBuf::from("NetTrap.html")),
                    _ => None,
                },
            };
            if let Some(mapped) = mapped {
                candidates.push((mapped, true));
            }
        }
    } else {
        candidates.push((PathBuf::from("NetTrap.html"), true));
    }

    candidates
        .into_iter()
        .fold(Vec::new(), |mut unique, (candidate, strict)| {
            if let Some((_, existing_strict)) = unique
                .iter_mut()
                .find(|(existing, _)| existing == &candidate)
            {
                *existing_strict |= strict;
            } else {
                unique.push((candidate, strict));
            }
            unique
        })
}

pub(crate) fn build_http_response_with_body(content: Vec<u8>, mime: &str, server: &str) -> Vec<u8> {
    let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
    let server = safe_server_header_value(server);

    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nDate: {}\r\nServer: {}\r\n\r\n",
        mime,
        content.len(),
        date,
        server
    )
    .into_bytes()
    .into_iter()
    .chain(content)
    .collect()
}

fn build_http_response_with_text(code: u16, reason: &str, server: &str) -> Vec<u8> {
    let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
    let server = safe_server_header_value(server);
    let body = reason.as_bytes();

    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nDate: {}\r\nServer: {}\r\n\r\n",
        code,
        reason,
        body.len(),
        date,
        server
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

pub(crate) fn safe_server_header_value(server: &str) -> Cow<'_, str> {
    if server.trim_matches([' ', '\t']) != server
        || server.is_empty()
        || nettrap_core::sanitize::contains_unicode_line_separator(server)
        || server
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        Cow::Borrowed("NetTrap")
    } else {
        Cow::Borrowed(server)
    }
}
