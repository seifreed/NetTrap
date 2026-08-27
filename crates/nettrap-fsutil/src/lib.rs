//! Secure filesystem access primitives shared across NetTrap protocol handlers.
//!
//! These helpers provide TOCTOU/symlink-resistant file opening so honeypot
//! protocol emulators can serve files from a configured root without being
//! tricked into escaping it via symbolic links or path traversal.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Mutex;

// ponytail: one process-wide lock keeps append lines atomic; split locks only if throughput requires it.
static APPEND_LINE_LOCK: Mutex<()> = Mutex::new(());

#[cfg(unix)]
pub fn open_regular_file_beneath_root(root: &Path, relative_path: &Path) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::path::Component;

    let normalized_root = normalize_platform_path_alias(root);
    let root = normalized_root.as_path();
    ensure_no_symlink_ancestors(root)?;
    let root_metadata = root.symlink_metadata()?;
    if root_metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "symlink path component",
        ));
    }
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(root)?;
    let mut components = relative_path
        .components()
        .filter(|component| !matches!(component, Component::CurDir))
        .peekable();

    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid path component",
            ));
        };

        let name = CString::new(name.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "nul byte in path component")
        })?;
        let is_last = components.peek().is_none();
        let flags = if is_last {
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
        };
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let file = unsafe { File::from_raw_fd(fd) };
        if is_last {
            return ensure_regular_file(file);
        }
        dir = file;
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "missing file path",
    ))
}

#[cfg(not(unix))]
pub fn open_regular_file_beneath_root(root: &Path, relative_path: &Path) -> io::Result<File> {
    use std::path::Component;

    ensure_no_symlink_ancestors(root)?;
    for component in relative_path.components() {
        if !matches!(component, Component::Normal(_) | Component::CurDir) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid path component",
            ));
        }
    }

    let root_metadata = root.symlink_metadata()?;
    if root_metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "symlink path component",
        ));
    }
    let canonical_root = root.canonicalize()?;
    let candidate = root.join(relative_path);
    let canonical_candidate = candidate.canonicalize()?;
    if !canonical_candidate.starts_with(&canonical_root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path escapes root",
        ));
    }
    open_regular_file_no_final_symlink(&candidate)
}

pub fn ensure_regular_file(file: File) -> io::Result<File> {
    if file.metadata()?.is_file() {
        Ok(file)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ))
    }
}

/// Result of reading a regular file under an explicit byte budget.
#[derive(Debug, PartialEq, Eq)]
pub enum LimitedFileRead {
    Content(Vec<u8>),
    TooLarge,
    NotFile,
}

/// Read a regular file without following symlinks, up to `max_bytes`.
///
/// Invalid path components and non-regular files are reported as `NotFile`.
pub fn read_limited_file(path: &Path, max_bytes: u64) -> io::Result<LimitedFileRead> {
    let normalized_path = normalize_platform_path_alias(&strip_current_dir_components(path));
    let file = match open_regular_file_no_final_symlink(&normalized_path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => {
            return Ok(LimitedFileRead::NotFile);
        }
        Err(err) => return Err(err),
    };
    read_limited_open_file(file, max_bytes)
}

/// Read a regular file beneath `root` without following symlinks, up to `max_bytes`.
pub fn read_limited_file_beneath_root(
    root: &Path,
    relative_path: &Path,
    max_bytes: u64,
) -> io::Result<LimitedFileRead> {
    let file = match open_regular_file_beneath_root(root, relative_path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => {
            return Ok(LimitedFileRead::NotFile);
        }
        Err(err) => return Err(err),
    };
    read_limited_open_file(file, max_bytes)
}

fn read_limited_open_file(file: File, max_bytes: u64) -> io::Result<LimitedFileRead> {
    let metadata = file.metadata()?;
    if metadata.len() > max_bytes {
        return Ok(LimitedFileRead::TooLarge);
    }

    let sentinel_limit = max_bytes.checked_add(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "file read limit is too large")
    })?;
    let mut content = Vec::new();
    file.take(sentinel_limit).read_to_end(&mut content)?;
    if content.len() as u64 > max_bytes {
        return Ok(LimitedFileRead::TooLarge);
    }

    Ok(LimitedFileRead::Content(content))
}

#[cfg(unix)]
fn open_regular_file_no_final_symlink(path: &Path) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::path::Component;

    ensure_no_symlink_ancestors(path)?;
    let path = normalize_platform_path_alias(path);
    let base = if path.is_absolute() { "/" } else { "." };
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(base)?;
    let mut components = path
        .components()
        .filter(|component| !matches!(component, Component::CurDir))
        .peekable();

    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir) {
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid path component",
            ));
        };
        let name = CString::new(name.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "nul byte in path component")
        })?;
        let is_last = components.peek().is_none();
        let flags = if is_last {
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
        };
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        if is_last {
            return ensure_regular_file(file);
        }
        dir = file;
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "missing file path",
    ))
}

#[cfg(windows)]
fn open_regular_file_no_final_symlink(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    ensure_no_symlink_ancestors(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    ensure_regular_file(file)
}

#[cfg(not(any(unix, windows)))]
fn open_regular_file_no_final_symlink(path: &Path) -> io::Result<File> {
    ensure_no_symlink_ancestors(path)?;
    ensure_regular_file(File::open(path)?)
}

pub fn ensure_no_symlink_ancestors(path: &Path) -> io::Result<()> {
    use std::path::Component;

    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {
                current.push(component.as_os_str());
            }
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid path component",
                ));
            }
            Component::Normal(name) => {
                current.push(name);
                match std::fs::symlink_metadata(&current) {
                    Ok(metadata) => {
                        if metadata.file_type().is_symlink()
                            && !is_platform_path_alias(current.as_path())
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "symlink path component",
                            ));
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err),
                }
            }
            Component::Prefix(_) => {
                current.push(component.as_os_str());
            }
        }
    }

    Ok(())
}

pub fn normalize_platform_path_alias(path: &Path) -> std::path::PathBuf {
    normalize_platform_path_alias_impl(path)
}

#[cfg(target_os = "macos")]
fn is_platform_path_alias(path: &Path) -> bool {
    matches!(path.to_str(), Some("/etc" | "/var" | "/tmp"))
}

#[cfg(target_os = "macos")]
fn normalize_platform_path_alias_impl(path: &Path) -> std::path::PathBuf {
    if let Ok(rest) = path.strip_prefix("/var") {
        return Path::new("/private/var").join(rest);
    }
    if let Ok(rest) = path.strip_prefix("/tmp") {
        return Path::new("/private/tmp").join(rest);
    }
    if let Ok(rest) = path.strip_prefix("/etc") {
        return Path::new("/private/etc").join(rest);
    }
    path.to_path_buf()
}

#[cfg(not(target_os = "macos"))]
fn is_platform_path_alias(_path: &Path) -> bool {
    false
}

#[cfg(not(target_os = "macos"))]
fn normalize_platform_path_alias_impl(path: &Path) -> std::path::PathBuf {
    path.to_path_buf()
}

/// Remove `.` path components without resolving symlinks or parent traversal.
pub fn strip_current_dir_components(path: &Path) -> std::path::PathBuf {
    use std::path::Component;

    let mut normalized = std::path::PathBuf::new();
    for component in path.components() {
        if !matches!(component, Component::CurDir) {
            normalized.push(component.as_os_str());
        }
    }
    normalized
}

pub fn create_regular_file(path: &Path) -> io::Result<File> {
    let path = strip_current_dir_components(path);

    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing file path",
        ));
    }

    if let Ok(metadata) = path.symlink_metadata() {
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "symlink path component",
            ));
        }
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path is not a regular file",
            ));
        }
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_no_symlink_ancestors(parent)?;
        std::fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        ensure_regular_file(file)
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        ensure_regular_file(file)
    }

    #[cfg(not(any(unix, windows)))]
    {
        ensure_regular_file(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)?,
        )
    }
}

pub fn append_regular_file(path: &Path) -> io::Result<File> {
    let path = strip_current_dir_components(path);

    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing file path",
        ));
    }

    if let Ok(metadata) = path.symlink_metadata() {
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "symlink path component",
            ));
        }
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path is not a regular file",
            ));
        }
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_no_symlink_ancestors(parent)?;
        std::fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        ensure_regular_file(file)
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        ensure_regular_file(file)
    }

    #[cfg(not(any(unix, windows)))]
    {
        ensure_regular_file(OpenOptions::new().append(true).create(true).open(path)?)
    }
}

/// Append one complete record to a regular file without interleaving writers.
pub fn append_regular_file_line(path: &Path, line: &[u8]) -> io::Result<()> {
    let _guard = APPEND_LINE_LOCK
        .lock()
        .map_err(|_| io::Error::other("append line lock poisoned"))?;
    let mut file = append_regular_file(path)?;
    file.write_all(line)
}

#[cfg(test)]
mod tests {
    use super::{
        append_regular_file, append_regular_file_line, create_regular_file, read_limited_file,
    };
    #[cfg(unix)]
    use super::{ensure_no_symlink_ancestors, open_regular_file_beneath_root};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn read_limited_file_rejects_unrepresentable_sentinel_limit() {
        let root = temp_dir("nettrap-fsutil-overflow-limit");
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("empty.bin");
        std::fs::write(&path, b"").expect("write fixture");

        let err =
            read_limited_file(&path, u64::MAX).expect_err("overflowing sentinel limit should fail");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("read limit is too large"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[cfg(unix)]
    #[test]
    fn create_regular_file_rejects_symlinked_final_path() {
        let root = temp_dir("nettrap-fsutil-final");
        let real = root.join("real");
        std::fs::create_dir_all(&real).expect("create real dir");
        let target = real.join("output.txt");
        std::fs::write(&target, "secret").expect("write target");
        let linked = root.join("linked.txt");
        std::os::unix::fs::symlink(&target, &linked).expect("create symlink");

        let err = create_regular_file(&linked).expect_err("symlinked file should be rejected");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn append_regular_file_rejects_symlinked_final_path() {
        let root = temp_dir("nettrap-fsutil-append");
        let real = root.join("real");
        std::fs::create_dir_all(&real).expect("create real dir");
        let target = real.join("output.txt");
        std::fs::write(&target, "secret").expect("write target");
        let linked = root.join("linked.txt");
        std::os::unix::fs::symlink(&target, &linked).expect("create symlink");

        let err = append_regular_file(&linked).expect_err("symlinked file should be rejected");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn append_regular_file_rejects_existing_non_regular_path_before_open() {
        let root = temp_dir("nettrap-fsutil-append-socket");
        std::fs::create_dir_all(&root).expect("create root");
        let socket_path = root.join("events.jsonl");
        let _listener =
            std::os::unix::net::UnixListener::bind(&socket_path).expect("bind unix socket");

        let err = append_regular_file(&socket_path).expect_err("socket path should be rejected");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn open_regular_file_beneath_root_rejects_existing_fifo_without_blocking() {
        let root = temp_dir("nettrap-fsutil-open-fifo");
        std::fs::create_dir_all(&root).expect("create root");
        let fifo = root.join("events.jsonl");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo should succeed");

        let err = open_regular_file_beneath_root(&root, std::path::Path::new("events.jsonl"))
            .expect_err("FIFO should be rejected");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn open_regular_file_beneath_root_rejects_symlinked_final_path() {
        let root = temp_dir("nettrap-fsutil-root");
        let real = root.join("real");
        std::fs::create_dir_all(&real).expect("create real dir");
        std::fs::write(real.join("payload.txt"), "secret").expect("write payload");
        let linked = root.join("linked");
        std::os::unix::fs::symlink(&real, &linked).expect("create symlink");

        let err = open_regular_file_beneath_root(&root, std::path::Path::new("linked/payload.txt"))
            .expect_err("symlinked final path should be rejected");

        assert!(matches!(
            err.kind(),
            std::io::ErrorKind::InvalidInput | std::io::ErrorKind::NotADirectory
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_no_symlink_ancestors_reports_invalid_component_errors() {
        use std::os::unix::ffi::OsStringExt;

        let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(
            b"nettrap-invalid\0path".to_vec(),
        ));

        let err = ensure_no_symlink_ancestors(&path).expect_err("nul path should be invalid");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn open_regular_file_beneath_root_accepts_trailing_current_dir_component() {
        let root = temp_dir("nettrap-fsutil-curdir");
        std::fs::create_dir_all(&root).expect("create root");
        std::fs::write(root.join("payload.txt"), "secret").expect("write payload");

        let file = open_regular_file_beneath_root(&root, std::path::Path::new("payload.txt/."))
            .expect("trailing current-dir component should be accepted");

        assert!(file.metadata().expect("metadata").is_file());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn open_regular_file_beneath_root_accepts_macos_tmp_alias() {
        let name = format!(
            "nettrap-fsutil-tmp-alias-{}-{}.txt",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::path::Path::new("/tmp").join(&name);
        std::fs::write(&path, "secret").expect("write payload");

        let file = open_regular_file_beneath_root(
            std::path::Path::new("/tmp"),
            std::path::Path::new(&name),
        )
        .expect("macOS /tmp alias should be accepted");

        assert!(file.metadata().expect("metadata").is_file());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn create_regular_file_accepts_trailing_current_dir_component() {
        let root = temp_dir("nettrap-fsutil-create-curdir");
        std::fs::create_dir_all(&root).expect("create root");

        let file = create_regular_file(&root.join("payload.txt/."))
            .expect("trailing current-dir component should be accepted");

        assert!(file.metadata().expect("metadata").is_file());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn append_regular_file_accepts_trailing_current_dir_component() {
        let root = temp_dir("nettrap-fsutil-append-curdir");
        std::fs::create_dir_all(&root).expect("create root");

        let file = append_regular_file(&root.join("payload.txt/."))
            .expect("trailing current-dir component should be accepted");

        assert!(file.metadata().expect("metadata").is_file());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn append_regular_file_line_keeps_concurrent_records_intact() {
        let root = temp_dir("nettrap-fsutil-append-line");
        std::fs::create_dir_all(&root).expect("create root");
        let path = root.join("events.jsonl");
        let mut threads = Vec::new();

        for index in 0..128 {
            let path = path.clone();
            threads.push(std::thread::spawn(move || {
                let line = format!("{{\"index\":{index}}}\n");
                append_regular_file_line(&path, line.as_bytes()).expect("append complete line");
            }));
        }
        for thread in threads {
            thread.join().expect("append thread should finish");
        }

        let content = std::fs::read_to_string(&path).expect("read appended lines");
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 128);
        assert!(lines.iter().all(|line| line.starts_with("{\"index\":")));
        let _ = std::fs::remove_dir_all(root);
    }
}
