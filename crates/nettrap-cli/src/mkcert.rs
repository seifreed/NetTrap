//! mkcert integration for trusted TLS certificate generation.
//!
//! When mkcert is available, NetTrap generates certificates that are trusted
//! by the local system, enabling full SSL inspection of malware HTTPS traffic.
//! Without mkcert, falls back to the built-in self-signed CA (untrusted).

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nettrap_core::sanitize::command_output_preview as render_command_output;
use nettrap_fsutil::create_regular_file;

const MAX_MKCERT_DOWNLOAD_BYTES: usize = 32 * 1024 * 1024;
const MAX_MKCERT_COMMAND_OUTPUT_BYTES: usize = 64 * 1024;
const MKCERT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Check if mkcert is installed and available in PATH
pub fn is_mkcert_installed() -> bool {
    which::which("mkcert").is_ok()
}

fn mkcert_version_result() -> Result<Option<String>, String> {
    mkcert_version_from_output(run_mkcert_command(&["-version"], "mkcert -version"))
}

fn mkcert_version_from_output(output: std::io::Result<Output>) -> Result<Option<String>, String> {
    let output = output.map_err(|err| format!("Failed to run mkcert -version: {err}"))?;
    if output.status.success() {
        let rendered = render_command_output(&output.stdout);
        Ok((!rendered.is_empty()).then_some(rendered))
    } else {
        let stderr = render_command_output(&output.stderr);
        if !stderr.is_empty() {
            Ok(Some(stderr))
        } else {
            Err(format!(
                "mkcert -version failed with status {}",
                output.status
            ))
        }
    }
}

pub(crate) fn mkcert_caroot_result() -> Result<Option<PathBuf>, String> {
    mkcert_caroot_from_output(run_mkcert_command(&["-CAROOT"], "mkcert -CAROOT"))
}

fn mkcert_caroot_from_output(output: std::io::Result<Output>) -> Result<Option<PathBuf>, String> {
    let output = output.map_err(|err| format!("Failed to run mkcert -CAROOT: {err}"))?;
    if output.status.success() {
        return Ok(non_empty_path_output(&output.stdout));
    }

    let stderr = render_command_output(&output.stderr);
    if stderr.is_empty() {
        Err(format!(
            "mkcert -CAROOT failed with status {}",
            output.status
        ))
    } else {
        Err(format!("mkcert -CAROOT failed: {}", stderr))
    }
}

fn non_empty_path_output(output: &[u8]) -> Option<PathBuf> {
    let output = trim_command_line_endings(output);
    if output.is_empty() {
        return None;
    }

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;

        Some(PathBuf::from(std::ffi::OsString::from_vec(output.to_vec())))
    }

    #[cfg(not(unix))]
    {
        Some(PathBuf::from(String::from_utf8_lossy(output).to_string()))
    }
}

fn trim_command_line_endings(mut output: &[u8]) -> &[u8] {
    while let Some(stripped) = output.strip_suffix(b"\n") {
        output = stripped;
    }
    while let Some(stripped) = output.strip_suffix(b"\r") {
        output = stripped;
    }
    output
}

fn run_mkcert_command(args: &[&str], label: &str) -> std::io::Result<Output> {
    let mut command = Command::new("mkcert");
    command.args(args);
    run_command_with_limited_output(command, label, MAX_MKCERT_COMMAND_OUTPUT_BYTES)
}

fn run_command_with_limited_output(
    mut command: Command,
    label: &str,
    output_limit: usize,
) -> std::io::Result<Output> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other(format!("{label} stdout pipe was not available")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other(format!("{label} stderr pipe was not available")))?;

    let stdout_reader = thread::spawn(move || read_limited_command_stream(stdout, output_limit));
    let stderr_reader = thread::spawn(move || read_limited_command_stream(stderr, output_limit));
    let status = wait_for_command(&mut child, label, MKCERT_COMMAND_TIMEOUT)?;
    let stdout = join_command_reader(stdout_reader, label, "stdout")?;
    let stderr = join_command_reader(stderr_reader, label, "stderr")?;

    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn wait_for_command(child: &mut Child, label: &str, timeout: Duration) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(status),
            None if Instant::now() >= deadline => {
                child.kill().map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("{label} timeout kill failed: {err}"),
                    )
                })?;
                child.wait().map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("{label} timeout cleanup wait failed: {err}"),
                    )
                })?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{label} exceeded {} seconds", timeout.as_secs()),
                ));
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn read_limited_command_stream<R: Read>(
    reader: R,
    output_limit: usize,
) -> std::io::Result<Vec<u8>> {
    let limit = u64::try_from(output_limit)
        .map_err(|_| io::Error::other("mkcert command output limit exceeds u64 range"))?;
    let _sentinel_limit = limit
        .checked_add(1)
        .ok_or_else(|| io::Error::other("mkcert command output limit sentinel overflowed"))?;
    let mut output = Vec::new();
    let mut reader = reader;
    let mut buffer = [0u8; 8192];
    let mut too_large = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let previous_len = output.len();
        if output.len() < output_limit {
            let retained = (output_limit - output.len()).min(read);
            output.extend_from_slice(&buffer[..retained]);
        }
        if previous_len.saturating_add(read) > output_limit {
            too_large = true;
        }
    }
    if too_large {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("mkcert command output exceeded {output_limit} byte limit"),
        ));
    }
    Ok(output)
}

fn join_command_reader(
    handle: thread::JoinHandle<std::io::Result<Vec<u8>>>,
    label: &str,
    stream: &str,
) -> std::io::Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| io::Error::other(format!("{label} {stream} reader panicked")))?
        .map_err(|err| io::Error::new(err.kind(), format!("{label} {stream}: {err}")))
}

fn checked_mkcert_download_len(
    current_len: usize,
    chunk_len: usize,
    max_bytes: usize,
) -> Result<usize, String> {
    let next_len = current_len
        .checked_add(chunk_len)
        .ok_or_else(|| "mkcert download size overflows platform usize".to_string())?;
    if next_len > max_bytes {
        return Err(format!(
            "mkcert download exceeds size limit ({} > {} bytes)",
            next_len, max_bytes
        ));
    }
    Ok(next_len)
}

async fn download_mkcert_binary(url: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut resp = reqwest::get(url)
        .await
        .map_err(|e| format!("Download failed: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("Download failed: HTTP {}", resp.status()));
    }
    if let Some(content_length) = resp.content_length() {
        let max_bytes_u64 = u64::try_from(max_bytes)
            .map_err(|_| "mkcert download limit exceeds u64 range".to_string())?;
        if content_length > max_bytes_u64 {
            return Err(format!(
                "mkcert download exceeds size limit ({} > {} bytes)",
                content_length, max_bytes
            ));
        }
    }

    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("Download read failed: {}", e))?
    {
        checked_mkcert_download_len(body.len(), chunk.len(), max_bytes)?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn write_mkcert_binary(install_path: &Path, body: &[u8]) -> Result<(), String> {
    use std::io::Write;

    let mut file = create_regular_file(install_path).map_err(|e| {
        format!(
            "Failed to open mkcert install path {}: {} (try with sudo)",
            install_path.display(),
            e
        )
    })?;
    file.write_all(body).map_err(|e| {
        format!(
            "Failed to write mkcert to {}: {} (try with sudo)",
            install_path.display(),
            e
        )
    })
}

/// Install mkcert local CA into system trust stores.
/// This runs `mkcert -install` which adds the CA to:
/// - macOS: System Keychain
/// - Linux: NSS (certutil) and/or ca-certificates
/// - Windows: Certificate Store
pub fn install_ca() -> Result<(), String> {
    tracing::info!("Installing mkcert CA into system trust stores...");
    let output = run_mkcert_command(&["-install"], "mkcert -install")
        .map_err(|e| format!("Failed to run mkcert -install: {}", e))?;

    if output.status.success() {
        tracing::info!("mkcert CA installed successfully");
        let stderr = render_command_output(&output.stderr);
        if !stderr.is_empty() {
            tracing::info!("{}", stderr);
        }
        Ok(())
    } else {
        let stderr = render_command_output(&output.stderr);
        Err(format!("mkcert -install failed: {}", stderr))
    }
}

/// Generate a certificate for the given hostnames using mkcert.
/// Returns (cert_path, key_path) of the generated PEM files.
pub fn generate_cert(hostnames: &[&str], output_dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    std::fs::create_dir_all(output_dir).map_err(|e| format!("Failed to create cert dir: {}", e))?;

    let cert_path = output_dir.join("cert.pem");
    let key_path = output_dir.join("key.pem");

    let mut cmd = Command::new("mkcert");
    cmd.arg("-cert-file")
        .arg(&cert_path)
        .arg("-key-file")
        .arg(&key_path);

    for host in hostnames {
        cmd.arg(host);
    }

    let output = run_command_with_limited_output(
        cmd,
        "mkcert certificate generation",
        MAX_MKCERT_COMMAND_OUTPUT_BYTES,
    )
    .map_err(|e| format!("Failed to run mkcert: {}", e))?;

    if output.status.success() {
        tracing::debug!("Generated trusted cert for {:?}", hostnames);
        Ok((cert_path, key_path))
    } else {
        let stderr = render_command_output(&output.stderr);
        Err(format!("mkcert cert generation failed: {}", stderr))
    }
}

/// Generate the root CA cert/key using mkcert and return their paths.
/// The CA files are in mkcert's CAROOT directory.
pub fn get_ca_paths() -> Result<(PathBuf, PathBuf), String> {
    let caroot =
        mkcert_caroot_result()?.ok_or_else(|| "Could not determine mkcert CAROOT".to_string())?;
    let ca_cert = caroot.join("rootCA.pem");
    let ca_key = caroot.join("rootCA-key.pem");

    if !ca_cert.exists() {
        return Err(format!(
            "CA cert not found at {}. Run 'nettrap tls install' first.",
            ca_cert.display()
        ));
    }
    if !ca_key.exists() {
        return Err(format!(
            "CA key not found at {}. Run 'nettrap tls install' first.",
            ca_key.display()
        ));
    }

    Ok((ca_cert, ca_key))
}

/// Install mkcert binary. Detects platform and downloads from GitHub releases.
pub async fn install_mkcert() -> Result<(), String> {
    if is_mkcert_installed() {
        let version = mkcert_version_text(mkcert_version_result())?;
        println!("mkcert is already installed: {}", version);
        return Ok(());
    }

    println!("Installing mkcert...");

    // Detect platform
    let (os, arch) = detect_platform()?;
    // The Windows release assets carry a `.exe` suffix in their published
    // download name (e.g. `mkcert-v1.4.4-windows-arm64.exe`); the Linux and
    // macOS assets have no extension. Omitting `.exe` on Windows produced a 404.
    let asset_ext = if os == "windows" { ".exe" } else { "" };
    let filename = format!("mkcert-v1.4.4-{}-{}{}", os, arch, asset_ext);
    let url = format!(
        "https://github.com/FiloSottile/mkcert/releases/download/v1.4.4/{}",
        filename
    );

    println!("Downloading from {}", url);

    let install_dir = if cfg!(target_os = "windows") {
        dirs_for_install_windows()
    } else {
        PathBuf::from("/usr/local/bin")
    };

    let install_path = if cfg!(target_os = "windows") {
        install_dir.join("mkcert.exe")
    } else {
        install_dir.join("mkcert")
    };

    // This runs inside the CLI's `#[tokio::main]` runtime, so await directly.
    let body = download_mkcert_binary(&url, MAX_MKCERT_DOWNLOAD_BYTES).await?;
    write_mkcert_binary(&install_path, &body)?;

    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&install_path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("Failed to set permissions: {}", e))?;
    }

    println!("mkcert installed to {}", install_path.display());

    let version = if is_mkcert_installed() {
        mkcert_version_text(mkcert_version_result())?
    } else {
        mkcert_version_text(mkcert_version_from_binary_path(&install_path))?
    };

    println!("Verified: mkcert {}", version);
    Ok(())
}

fn detect_platform() -> Result<(&'static str, &'static str), String> {
    detect_platform_from(
        if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else {
            "unsupported"
        },
        if cfg!(target_arch = "x86_64") {
            "x86_64"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else if cfg!(target_arch = "arm") {
            "arm"
        } else {
            "unsupported"
        },
    )
}

fn detect_platform_from(os: &str, arch: &str) -> Result<(&'static str, &'static str), String> {
    let os = match os {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        other => {
            return Err(format!(
                "Unsupported platform for mkcert download: operating system '{}'",
                other
            ));
        }
    };

    let arch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "arm",
        other => {
            return Err(format!(
                "Unsupported platform for mkcert download: architecture '{}'",
                other
            ));
        }
    };

    Ok((os, arch))
}

#[cfg(target_os = "windows")]
fn dirs_for_install_windows() -> PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\Program Files"))
        .join("mkcert")
}

#[cfg(not(target_os = "windows"))]
fn dirs_for_install_windows() -> PathBuf {
    PathBuf::from("/usr/local/bin")
}

fn render_status_lines(
    installed: bool,
    version: Option<Result<String, String>>,
    caroot: Option<Result<Option<PathBuf>, String>>,
) -> Result<Vec<String>, String> {
    if !installed {
        return Ok(vec![
            "mkcert: NOT installed".to_string(),
            "Install with: nettrap tls install-mkcert".to_string(),
        ]);
    }

    let version = version.ok_or_else(|| "Could not determine mkcert version".to_string())??;

    let mut lines = vec![format!("mkcert: installed ({})", version)];

    if let Some(caroot) = caroot {
        let Some(caroot) = caroot? else {
            return Ok(lines);
        };
        let ca_cert = caroot.join("rootCA.pem");
        let ca_key = caroot.join("rootCA-key.pem");
        lines.push(format!("CAROOT: {}", caroot.display()));
        lines.push(format!(
            "CA cert: {} ({})",
            ca_cert.display(),
            if ca_cert.exists() {
                "exists"
            } else {
                "MISSING"
            }
        ));
        lines.push(format!(
            "CA key:  {} ({})",
            ca_key.display(),
            if ca_key.exists() { "exists" } else { "MISSING" }
        ));
    }

    Ok(lines)
}

/// Print mkcert status information
pub fn print_status() -> Result<(), String> {
    let installed = is_mkcert_installed();
    let version = installed.then(|| mkcert_version_text(mkcert_version_result()));
    let caroot = installed.then(mkcert_caroot_result);
    let lines = render_status_lines(installed, version, caroot)?;

    for line in lines {
        println!("{}", line);
    }

    Ok(())
}

fn mkcert_version_text(version: Result<Option<String>, String>) -> Result<String, String> {
    version?.ok_or_else(|| "Could not determine mkcert version".to_string())
}

fn mkcert_version_from_binary_path(binary_path: &Path) -> Result<Option<String>, String> {
    let mut command = Command::new(binary_path);
    command.arg("-version");
    let output = run_command_with_limited_output(
        command,
        "mkcert -version (installed binary)",
        MAX_MKCERT_COMMAND_OUTPUT_BYTES,
    )
    .map_err(|e| format!("Failed to run installed mkcert binary: {}", e))?;

    if output.status.success() {
        let rendered = render_command_output(&output.stdout);
        Ok((!rendered.is_empty()).then_some(rendered))
    } else {
        let stderr = render_command_output(&output.stderr);
        if !stderr.is_empty() {
            Ok(Some(stderr))
        } else {
            Err(format!(
                "installed mkcert -version failed with status {}",
                output.status
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        checked_mkcert_download_len, detect_platform_from, mkcert_caroot_from_output,
        mkcert_version_from_binary_path, mkcert_version_from_output, mkcert_version_text,
        read_limited_command_stream, render_status_lines,
    };
    #[cfg(unix)]
    use super::{wait_for_command, write_mkcert_binary};

    use std::io::Cursor;

    #[cfg(unix)]
    #[test]
    fn wait_for_command_kills_process_after_timeout() {
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sleep 1"])
            .spawn()
            .expect("spawn sleeping command");

        let err = wait_for_command(
            &mut child,
            "test command",
            std::time::Duration::from_millis(10),
        )
        .expect_err("sleeping command should time out");

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn mkcert_version_reports_command_spawn_errors() {
        let err = mkcert_version_from_output(Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing mkcert",
        )))
        .expect_err("spawn failure must be reported");

        assert!(err.contains("Failed to run mkcert -version"), "{err}");
    }

    #[test]
    fn mkcert_caroot_reports_command_spawn_errors() {
        let err = mkcert_caroot_from_output(Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing mkcert",
        )))
        .expect_err("spawn failure must be reported");

        assert!(err.contains("Failed to run mkcert -CAROOT"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn mkcert_caroot_preserves_non_utf8_path_bytes() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::process::ExitStatusExt;

        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"/tmp/mkcert-\xff\n".to_vec(),
            stderr: Vec::new(),
        };

        let caroot = mkcert_caroot_from_output(Ok(output))
            .expect("mkcert output should parse")
            .expect("caroot should be present");

        assert_eq!(caroot.as_os_str().as_bytes(), b"/tmp/mkcert-\xff");
    }

    #[test]
    fn render_status_lines_returns_error_when_caroot_lookup_fails() {
        let err = render_status_lines(
            true,
            Some(Ok("1.4.4".to_string())),
            Some(Err(
                "Failed to run mkcert -CAROOT: missing mkcert".to_string()
            )),
        )
        .expect_err("status should surface CAROOT lookup failures");

        assert!(err.contains("Failed to run mkcert -CAROOT"), "{err}");
    }

    #[test]
    fn render_status_lines_returns_error_when_version_lookup_fails() {
        let err = render_status_lines(
            true,
            Some(Err(
                "Failed to run mkcert -version: missing mkcert".to_string()
            )),
            Some(Err("ignored".to_string())),
        )
        .expect_err("status should surface version lookup failures");

        assert!(err.contains("Failed to run mkcert -version"), "{err}");
    }

    #[test]
    fn mkcert_version_text_rejects_empty_version_output() {
        let err = mkcert_version_text(Ok(None)).expect_err("empty version output should fail");

        assert!(err.contains("Could not determine mkcert version"), "{err}");
    }

    #[test]
    fn mkcert_version_from_binary_path_prefers_the_installed_binary() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let dir = std::env::temp_dir().join(format!(
                "nettrap-mkcert-binary-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&dir).expect("temp dir should be created");
            let binary_path = dir.join("mkcert");
            std::fs::write(
                &binary_path,
                "#!/bin/sh\nprintf 'mkcert version 1.2.3\\n'\n",
            )
            .expect("temp binary should be writable");
            std::fs::set_permissions(&binary_path, std::fs::Permissions::from_mode(0o755))
                .expect("temp binary should be executable");

            let version = mkcert_version_from_binary_path(&binary_path)
                .expect("installed binary should run")
                .expect("installed binary should print a version");

            assert_eq!(version, "mkcert version 1.2.3");

            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn mkcert_version_from_binary_path_reports_spawn_errors() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-mkcert-missing-binary-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let err = mkcert_version_from_binary_path(&path)
            .expect_err("missing installed binary should fail");

        assert!(err.contains("Failed to run installed mkcert binary"));
    }

    #[test]
    fn render_status_lines_reports_missing_installation() {
        let lines = render_status_lines(false, None, None).expect("uninstalled status");

        assert_eq!(
            lines,
            vec![
                "mkcert: NOT installed".to_string(),
                "Install with: nettrap tls install-mkcert".to_string()
            ]
        );
    }

    #[test]
    fn mkcert_command_stream_rejects_oversized_output() {
        let err = read_limited_command_stream(Cursor::new(b"abcdef"), 5)
            .expect_err("oversized command output should be rejected");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeded 5 byte limit"), "{err}");
    }

    #[test]
    fn mkcert_command_stream_allows_output_at_limit() {
        let output = read_limited_command_stream(Cursor::new(b"abcde"), 5)
            .expect("output at the limit should pass");

        assert_eq!(output, b"abcde");
    }

    #[test]
    fn mkcert_command_stream_rejects_unrepresentable_sentinel_limit() {
        let err = read_limited_command_stream(Cursor::new(b""), usize::MAX)
            .expect_err("overflowing sentinel limit should fail");

        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(err.to_string().contains("sentinel overflowed"), "{err}");
    }

    #[test]
    fn mkcert_download_len_rejects_oversized_chunks() {
        let err = checked_mkcert_download_len(9, 2, 10)
            .expect_err("download chunks beyond the limit should fail");

        assert!(err.contains("mkcert download exceeds size limit"), "{err}");
    }

    #[test]
    fn mkcert_download_len_rejects_usize_overflow() {
        let err = checked_mkcert_download_len(usize::MAX, 1, usize::MAX)
            .expect_err("overflowing download length should fail");

        assert!(err.contains("overflows platform usize"), "{err}");
    }

    #[test]
    fn detect_platform_from_accepts_supported_targets() {
        assert_eq!(
            detect_platform_from("linux", "x86_64").expect("linux x86_64 should be supported"),
            ("linux", "amd64")
        );
        assert_eq!(
            detect_platform_from("macos", "aarch64").expect("macos aarch64 should be supported"),
            ("darwin", "arm64")
        );
        assert_eq!(
            detect_platform_from("windows", "arm").expect("windows arm should be supported"),
            ("windows", "arm")
        );
    }

    #[test]
    fn detect_platform_from_rejects_unsupported_os_and_arch() {
        let os_err = detect_platform_from("freebsd", "x86_64")
            .expect_err("unsupported operating systems should fail");
        assert!(os_err.contains("Unsupported platform for mkcert download"));

        let arch_err = detect_platform_from("linux", "riscv64")
            .expect_err("unsupported architectures should fail");
        assert!(arch_err.contains("Unsupported platform for mkcert download"));
    }

    #[cfg(unix)]
    #[test]
    fn write_mkcert_binary_rejects_symlinked_final_path() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-mkcert-symlink-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("create temp root");
        let target = root.join("target");
        let linked = root.join("mkcert");
        std::fs::write(&target, b"old").expect("write target");
        std::os::unix::fs::symlink(&target, &linked).expect("create symlink");

        let err = write_mkcert_binary(&linked, b"new")
            .expect_err("symlinked mkcert install path should fail");

        assert!(err.contains("Failed to open mkcert install path"), "{err}");
        assert_eq!(
            std::fs::read(&target).expect("target should remain readable"),
            b"old"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
