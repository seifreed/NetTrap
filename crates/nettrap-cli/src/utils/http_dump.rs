use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use nettrap_fsutil::create_regular_file;

static HTTP_POST_DUMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Dump HTTP POST data to a file for analysis.
pub async fn dump_http_post(data: &[u8], prefix: &Option<String>, peer: &std::net::SocketAddr) {
    let filename = match http_post_dump_path(prefix, peer) {
        Ok(filename) => filename,
        Err(e) => {
            tracing::warn!("Failed to build HTTP POST dump path: {}", e);
            return;
        }
    };
    match create_regular_file(&filename) {
        Ok(mut file) => {
            use std::io::Write;

            match file.write_all(data) {
                Ok(()) => tracing::info!("HTTP POST dumped to {}", filename.display()),
                Err(e) => tracing::warn!("Failed to dump HTTP POST {:?}: {}", filename, e),
            }
        }
        Err(e) => tracing::warn!("Failed to dump HTTP POST {:?}: {}", filename, e),
    }
}

pub(crate) fn http_post_dump_path(
    prefix: &Option<String>,
    peer: &std::net::SocketAddr,
) -> std::io::Result<PathBuf> {
    let seq = HTTP_POST_DUMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let filename = format!(
        "{}_{}_{}_{}.bin",
        std::process::id(),
        uuid::Uuid::new_v4(),
        seq,
        peer.port()
    );
    let Some(value) = prefix.as_deref() else {
        return Ok(PathBuf::from(format!("http_post_{filename}")));
    };

    if value.chars().all(char::is_whitespace) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "HTTP POST dump prefix must not be blank",
        ));
    }
    if nettrap_core::sanitize::contains_unicode_line_separator(value)
        || value.chars().any(char::is_control)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "HTTP POST dump prefix contains control characters or unicode separators",
        ));
    }

    Ok(std::path::Path::new(value).join(&filename))
}
