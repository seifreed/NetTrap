//! mkcert integration for trusted TLS certificate generation.
//!
//! When mkcert is available, NetTrap generates certificates that are trusted
//! by the local system, enabling full SSL inspection of malware HTTPS traffic.
//! Without mkcert, falls back to the built-in self-signed CA (untrusted).

use std::path::{Path, PathBuf};
use std::process::Command;

/// Check if mkcert is installed and available in PATH
pub fn is_mkcert_installed() -> bool {
    which::which("mkcert").is_ok()
}

/// Get mkcert version string
pub fn mkcert_version() -> Option<String> {
    let output = Command::new("mkcert").arg("-version").output().ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        // mkcert -version outputs to stderr on some versions
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if !stderr.is_empty() { Some(stderr) } else { None }
    }
}

/// Get the mkcert CAROOT directory
pub fn mkcert_caroot() -> Option<PathBuf> {
    let output = Command::new("mkcert").arg("-CAROOT").output().ok()?;
    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    None
}

/// Install mkcert local CA into system trust stores.
/// This runs `mkcert -install` which adds the CA to:
/// - macOS: System Keychain
/// - Linux: NSS (certutil) and/or ca-certificates
/// - Windows: Certificate Store
pub fn install_ca() -> Result<(), String> {
    tracing::info!("Installing mkcert CA into system trust stores...");
    let output = Command::new("mkcert")
        .arg("-install")
        .output()
        .map_err(|e| format!("Failed to run mkcert -install: {}", e))?;

    if output.status.success() {
        tracing::info!("mkcert CA installed successfully");
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            tracing::info!("{}", stderr.trim());
        }
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("mkcert -install failed: {}", stderr.trim()))
    }
}

/// Generate a certificate for the given hostnames using mkcert.
/// Returns (cert_path, key_path) of the generated PEM files.
pub fn generate_cert(
    hostnames: &[&str],
    output_dir: &Path,
) -> Result<(PathBuf, PathBuf), String> {
    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("Failed to create cert dir: {}", e))?;

    let cert_path = output_dir.join("cert.pem");
    let key_path = output_dir.join("key.pem");

    let mut cmd = Command::new("mkcert");
    cmd.arg("-cert-file").arg(&cert_path)
       .arg("-key-file").arg(&key_path);

    for host in hostnames {
        cmd.arg(host);
    }

    let output = cmd.output()
        .map_err(|e| format!("Failed to run mkcert: {}", e))?;

    if output.status.success() {
        tracing::debug!("Generated trusted cert for {:?}", hostnames);
        Ok((cert_path, key_path))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("mkcert cert generation failed: {}", stderr.trim()))
    }
}

/// Generate the root CA cert/key using mkcert and return their paths.
/// The CA files are in mkcert's CAROOT directory.
pub fn get_ca_paths() -> Result<(PathBuf, PathBuf), String> {
    let caroot = mkcert_caroot().ok_or_else(|| "Could not determine mkcert CAROOT".to_string())?;
    let ca_cert = caroot.join("rootCA.pem");
    let ca_key = caroot.join("rootCA-key.pem");

    if !ca_cert.exists() {
        return Err(format!("CA cert not found at {}. Run 'nettrap tls install' first.", ca_cert.display()));
    }
    if !ca_key.exists() {
        return Err(format!("CA key not found at {}. Run 'nettrap tls install' first.", ca_key.display()));
    }

    Ok((ca_cert, ca_key))
}

/// Install mkcert binary. Detects platform and downloads from GitHub releases.
pub fn install_mkcert() -> Result<(), String> {
    if is_mkcert_installed() {
        let version = mkcert_version().unwrap_or_else(|| "unknown".to_string());
        println!("mkcert is already installed: {}", version);
        return Ok(());
    }

    println!("Installing mkcert...");

    // Detect platform
    let (os, arch) = detect_platform();
    let filename = format!("mkcert-v1.4.4-{}-{}", os, arch);
    let url = format!(
        "https://github.com/FiloSottile/mkcert/releases/download/v1.4.4/{}",
        filename
    );

    println!("Downloading from {}", url);

    // Determine install path
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

    // Download using reqwest (blocking since this is a CLI command)
    let body = {
        let rt = tokio::runtime::Runtime::new().map_err(|e| format!("Runtime error: {}", e))?;
        rt.block_on(async {
            let resp = reqwest::get(&url).await.map_err(|e| format!("Download failed: {}", e))?;
            if !resp.status().is_success() {
                return Err(format!("Download failed: HTTP {}", resp.status()));
            }
            resp.bytes().await.map_err(|e| format!("Download read failed: {}", e))
        })?
    };

    // Write binary
    std::fs::write(&install_path, &body)
        .map_err(|e| format!("Failed to write mkcert to {}: {} (try with sudo)", install_path.display(), e))?;

    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&install_path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("Failed to set permissions: {}", e))?;
    }

    println!("mkcert installed to {}", install_path.display());

    // Verify installation
    if is_mkcert_installed() {
        let version = mkcert_version().unwrap_or_else(|| "unknown".to_string());
        println!("Verified: mkcert {}", version);
        Ok(())
    } else {
        Err(format!("mkcert installed to {} but not found in PATH. Add it to your PATH.", install_path.display()))
    }
}

fn detect_platform() -> (&'static str, &'static str) {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else {
        "amd64"
    };

    (os, arch)
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

/// Print mkcert status information
pub fn print_status() {
    if is_mkcert_installed() {
        let version = mkcert_version().unwrap_or_else(|| "unknown".to_string());
        println!("mkcert: installed ({})", version);
        if let Some(caroot) = mkcert_caroot() {
            println!("CAROOT: {}", caroot.display());
            let ca_cert = caroot.join("rootCA.pem");
            let ca_key = caroot.join("rootCA-key.pem");
            println!("CA cert: {} ({})", ca_cert.display(), if ca_cert.exists() { "exists" } else { "MISSING" });
            println!("CA key:  {} ({})", ca_key.display(), if ca_key.exists() { "exists" } else { "MISSING" });
        }
    } else {
        println!("mkcert: NOT installed");
        println!("Install with: nettrap tls install-mkcert");
    }
}
