//! Windows-specific network configuration utilities.
//! Only compiled on Windows.

#[cfg(target_os = "windows")]
use std::process::Command;

/// Fix missing gateway on Windows (e.g., VMware Host-Only adapter)
#[cfg(target_os = "windows")]
pub fn fix_gateway() {
    tracing::info!("Attempting to fix Windows gateway configuration...");
    let output = Command::new("netsh")
        .args(["interface", "ip", "show", "config"])
        .output();
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if !stdout.contains("Default Gateway")
                || stdout.contains("Default Gateway:                          \r\n")
            {
                tracing::warn!(
                    "No default gateway detected. Configure one manually if needed."
                );
            } else {
                tracing::info!("Gateway configuration looks OK");
            }
        }
        Err(e) => tracing::warn!("Failed to check gateway: {}", e),
    }
}

/// Set DNS server to localhost for traffic capture
#[cfg(target_os = "windows")]
pub fn fix_dns() {
    tracing::info!("Setting DNS to localhost for traffic capture...");
    let _ = Command::new("netsh")
        .args([
            "interface",
            "ip",
            "set",
            "dns",
            "name=Ethernet",
            "static",
            "127.0.0.1",
        ])
        .output();
}

/// Stop Windows DNS Client service to see actual resolving processes
#[cfg(target_os = "windows")]
pub fn stop_dns_service() {
    tracing::info!("Stopping Windows DNS Client service...");
    let _ = Command::new("net").args(["stop", "Dnscache"]).output();
}

/// Restore Windows DNS Client service
#[cfg(target_os = "windows")]
pub fn start_dns_service() {
    tracing::info!("Starting Windows DNS Client service...");
    let _ = Command::new("net").args(["start", "Dnscache"]).output();
}

/// Install CA certificate in Windows trust store
#[cfg(target_os = "windows")]
pub fn install_ca_trust(cert_path: &str) {
    tracing::info!("Installing CA certificate in Windows trust store...");
    let output = Command::new("certutil")
        .args(["-addstore", "Root", cert_path])
        .output();
    match output {
        Ok(o) if o.status.success() => tracing::info!("CA certificate installed successfully"),
        Ok(o) => tracing::warn!("certutil failed: {}", String::from_utf8_lossy(&o.stderr)),
        Err(e) => tracing::warn!("Failed to run certutil: {}", e),
    }
}

/// Remove CA certificate from Windows trust store
#[cfg(target_os = "windows")]
pub fn remove_ca_trust(cert_subject: &str) {
    let _ = Command::new("certutil")
        .args(["-delstore", "Root", cert_subject])
        .output();
}

/// Restore DNS settings that were modified (set back to DHCP)
#[cfg(target_os = "windows")]
pub fn restore_dns() {
    tracing::info!("Restoring DNS settings...");
    let _ = Command::new("netsh")
        .args(["interface", "ip", "set", "dns", "name=Ethernet", "dhcp"])
        .output();
}

// No-ops for non-Windows
#[cfg(not(target_os = "windows"))]
pub fn fix_gateway() {}
#[cfg(not(target_os = "windows"))]
pub fn fix_dns() {}
#[cfg(not(target_os = "windows"))]
pub fn stop_dns_service() {}
#[cfg(not(target_os = "windows"))]
pub fn start_dns_service() {}
#[cfg(not(target_os = "windows"))]
pub fn install_ca_trust(_cert_path: &str) {}
#[cfg(not(target_os = "windows"))]
pub fn remove_ca_trust(_cert_subject: &str) {}
#[cfg(not(target_os = "windows"))]
pub fn restore_dns() {}
