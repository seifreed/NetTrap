use nettrap_core::prelude::*;

#[cfg(target_os = "linux")]
pub fn get_process_for_socket(
    local_ip: std::net::IpAddr,
    local_port: u16,
    _protocol: Protocol,
) -> Option<ProcessInfo> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let path = if local_ip.is_ipv4() {
        "/proc/net/tcp"
    } else {
        "/proc/net/tcp6"
    };

    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);

    for line in reader.lines().skip(1).flatten() {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 10 {
            continue;
        }

        let local_port_hex = parts[1].split(':').nth(1)?;
        let port = u16::from_str_radix(local_port_hex, 16).ok()?;

        if port == local_port {
            let inode: u64 = parts[9].parse().ok()?;

            if let Some(pid) = find_pid_by_inode(inode) {
                return Some(get_process_info(pid));
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn find_pid_by_inode(inode: u64) -> Option<u32> {
    use std::fs;

    for entry in fs::read_dir("/proc").ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let pid: u32 = name_str.parse().ok()?;

        let fd_dir = format!("/proc/{}/fd", pid);
        if let Ok(fd_entries) = fs::read_dir(&fd_dir) {
            for fd_entry in fd_entries.flatten() {
                if let Ok(link) = fd_entry.path().read_link() {
                    if link.to_string_lossy().contains(&format!("[{}]", inode)) {
                        return Some(pid);
                    }
                }
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn get_process_info(pid: u32) -> ProcessInfo {
    use std::fs;

    let cmdline_path = format!("/proc/{}/cmdline", pid);
    let cmdline = fs::read_to_string(&cmdline_path)
        .unwrap_or_default()
        .replace('\0', " ");

    let status_path = format!("/proc/{}/status", pid);
    let name = fs::read_to_string(&status_path)
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Name:"))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
        })
        .unwrap_or_else(|| format!("pid-{}", pid));

    let exe_path = format!("/proc/{}/exe", pid);
    let path = fs::read_link(&exe_path)
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    ProcessInfo::new(pid, name)
        .with_path(path.unwrap_or_default())
        .with_command_line(cmdline)
}

#[cfg(target_os = "windows")]
pub fn get_process_for_socket(
    _local_ip: std::net::IpAddr,
    _local_port: u16,
    _protocol: Protocol,
) -> Option<ProcessInfo> {
    None
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn get_process_for_socket(
    _local_ip: std::net::IpAddr,
    _local_port: u16,
    _protocol: Protocol,
) -> Option<ProcessInfo> {
    None
}

#[cfg(target_os = "linux")]
pub fn get_all_processes() -> Vec<ProcessInfo> {
    use std::fs;
    let mut processes = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if !name_str.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }

            if let Ok(pid) = name_str.parse::<u32>() {
                if let Some(info) = get_process_info_impl(pid) {
                    processes.push(info);
                }
            }
        }
    }

    processes
}

#[cfg(target_os = "linux")]
fn get_process_info_impl(pid: u32) -> Option<ProcessInfo> {
    use std::fs;

    let name = fs::read_to_string(format!("/proc/{}/status", pid))
        .ok()?
        .lines()
        .find(|l| l.starts_with("Name:"))
        .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())?;

    let path = fs::read_link(&format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    Some(ProcessInfo::new(pid, name).with_path(path.unwrap_or_default()))
}

#[cfg(not(target_os = "linux"))]
pub fn get_all_processes() -> Vec<ProcessInfo> {
    Vec::new()
}
