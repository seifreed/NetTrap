use nettrap_core::prelude::*;

#[cfg(target_os = "linux")]
const MAX_PROC_CMDLINE_BYTES: u64 = 64 * 1024;
#[cfg(target_os = "linux")]
const MAX_PROC_STATUS_BYTES: u64 = 16 * 1024;

#[cfg(target_os = "linux")]
pub fn get_process_for_socket(
    local_ip: std::net::IpAddr,
    local_port: u16,
    protocol: Protocol,
) -> Option<ProcessInfo> {
    use std::fs::File;
    use std::io::BufReader;

    for path in linux_proc_net_paths(local_ip, protocol)
        .into_iter()
        .flatten()
    {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(err) => {
                tracing::debug!("Failed to open {} for process attribution: {}", path, err);
                continue;
            }
        };
        let reader = BufReader::new(file);
        let inode = match find_matching_inode_in_proc_net(reader, local_ip, local_port) {
            Ok(inode) => inode,
            Err(err) => {
                tracing::debug!("Failed to read {} for process attribution: {}", path, err);
                continue;
            }
        };

        if let Some(inode) = inode {
            return find_pid_by_inode(inode).map(get_process_info);
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn find_matching_inode_in_proc_net<R: std::io::BufRead>(
    reader: R,
    local_ip: std::net::IpAddr,
    local_port: u16,
) -> std::io::Result<Option<u64>> {
    let mut wildcard_inode = None;

    for line in reader.lines().skip(1) {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 10 {
            continue;
        }

        let mut local_addr_parts = parts[1].split(':');
        let Some(local_ip_hex) = local_addr_parts.next() else {
            continue;
        };
        let Some(local_port_hex) = local_addr_parts.next() else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(local_port_hex, 16) else {
            continue;
        };

        if port != local_port {
            continue;
        }

        let Ok(inode) = parts[9].parse::<u64>() else {
            continue;
        };

        // Match the local IP too, not just the port: the same port can be bound
        // on multiple local addresses (loopback vs a wildcard listener, or
        // distinct interfaces on a multi-homed host), and a port-only match
        // would attribute the flow to whichever row appears first. Accept the
        // row when its address equals the flow's local IP, or when the socket
        // is bound to the wildcard address (0.0.0.0 / ::), which serves every
        // local IP.
        match parse_proc_net_ip(local_ip_hex) {
            Some(row_ip) if socket_ip_matches(row_ip, local_ip) => return Ok(Some(inode)),
            Some(row_ip) if row_ip.is_unspecified() => {
                wildcard_inode = Some(inode);
                continue;
            }
            Some(_) => continue,
            // Unparseable address field means we cannot trust the row; skip it
            // rather than risking a wrong attribution on a shared port.
            None => continue,
        }
    }

    Ok(wildcard_inode)
}

/// Decode the local-address field from a `/proc/net/{tcp,udp}{,6}` row.
///
/// The kernel writes these addresses in host byte order as hex: an IPv4 row
/// stores the 32-bit address little-endian on x86 (so `127.0.0.1` appears as
/// `0100007F`), and an IPv6 row stores four 32-bit words each in host byte
/// order. Both must be byte-swapped back to network order before building an
/// `IpAddr`. Returns `None` for an unrecognized field width.
#[cfg(target_os = "linux")]
fn parse_proc_net_ip(hex: &str) -> Option<std::net::IpAddr> {
    match hex.len() {
        8 => {
            let raw = u32::from_str_radix(hex, 16).ok()?;
            // /proc stores the address in host byte order; swap to network order.
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(raw.to_be())))
        }
        32 => {
            let mut octets = [0u8; 16];
            // Four 32-bit words, each in host byte order.
            for word in 0..4 {
                let chunk = &hex[word * 8..word * 8 + 8];
                let raw = u32::from_str_radix(chunk, 16).ok()?;
                let bytes = raw.to_be().to_be_bytes();
                octets[word * 4..word * 4 + 4].copy_from_slice(&bytes);
            }
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn find_pid_by_inode(inode: u64) -> Option<u32> {
    match find_pid_by_inode_in_proc_root(std::path::Path::new("/proc"), inode) {
        Ok(pid) => pid,
        Err(err) => {
            tracing::warn!(
                "Failed to scan /proc for socket inode {} during process attribution: {}",
                inode,
                err
            );
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn find_pid_by_inode_in_proc_root(
    proc_root: &std::path::Path,
    inode: u64,
) -> std::io::Result<Option<u32>> {
    use std::fs;

    for entry in fs::read_dir(proc_root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if name_str.is_empty() || !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };

        let fd_dir = proc_root.join(pid.to_string()).join("fd");
        let fd_entries = match fs::read_dir(&fd_dir) {
            Ok(entries) => entries,
            Err(err) => {
                tracing::debug!(
                    "Failed to open {} during process attribution: {}",
                    fd_dir.display(),
                    err
                );
                continue;
            }
        };

        // A socket fd resolves to exactly "socket:[<inode>]". Match on that
        // exact form rather than a substring: inode numbers are not unique
        // across fd types, so a `contains("[<inode>]")` test also matches
        // pipes, anon_inodes, or even a regular file whose path happens to
        // contain "[<inode>]", attributing the connection to the wrong PID.
        let socket_link = format!("socket:[{}]", inode);
        for fd_entry in fd_entries {
            let fd_entry = match fd_entry {
                Ok(fd_entry) => fd_entry,
                Err(err) => {
                    tracing::debug!(
                        "Failed to read an entry in {} during process attribution: {}",
                        fd_dir.display(),
                        err
                    );
                    continue;
                }
            };

            let link = match fd_entry.path().read_link() {
                Ok(link) => link,
                Err(err) => {
                    tracing::debug!(
                        "Failed to read {} during process attribution: {}",
                        fd_entry.path().display(),
                        err
                    );
                    continue;
                }
            };

            if link.to_string_lossy() == socket_link {
                return Ok(Some(pid));
            }
        }
    }

    Ok(None)
}

#[cfg(target_os = "linux")]
fn get_process_info(pid: u32) -> ProcessInfo {
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    let cmdline = read_limited_proc_file(&cmdline_path, MAX_PROC_CMDLINE_BYTES)
        .ok()
        .flatten()
        .and_then(|value| process_cmdline_from_bytes(&value));

    let status_path = format!("/proc/{}/status", pid);
    let status_name = read_limited_proc_file(&status_path, MAX_PROC_STATUS_BYTES)
        .ok()
        .flatten()
        .and_then(|status| String::from_utf8(status).ok())
        .map(|status| process_name_from_status(&status, pid))
        .unwrap_or_else(|| format!("pid-{}", pid));

    let path = std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| process_path_to_string(&p));

    let name = process_name_from_status_or_path(status_name, path.as_deref());

    process_info_with_optional_metadata(pid, name, path, cmdline)
}

/// Resolve the process owning the socket bound to `(local_ip, local_port)` by
/// walking the Windows extended TCP/UDP connection tables and matching the
/// owning PID, then resolving that PID to an image name.
///
#[cfg(target_os = "windows")]
pub fn get_process_for_socket(
    local_ip: std::net::IpAddr,
    local_port: u16,
    protocol: Protocol,
) -> Option<ProcessInfo> {
    windows_owner_pid_candidates(local_ip, local_port, protocol)
        .into_iter()
        .flatten()
        .next()
        .map(windows_process_info)
}

/// True when a connection-table row whose local address is `row_ip` should be
/// considered a match for a flow whose local address is `want_ip`. A wildcard
/// bind (0.0.0.0 / ::) serves every local IP, so it always matches.
#[cfg(target_os = "windows")]
fn windows_local_ip_matches(row_ip: std::net::IpAddr, want_ip: std::net::IpAddr) -> bool {
    row_ip.is_unspecified() || socket_ip_matches(row_ip, want_ip)
}

#[cfg(target_os = "windows")]
fn windows_tcp4_owner_pid(want_ip: std::net::Ipv4Addr, want_port: u16) -> Option<u32> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let buffer = windows_extended_table(|buf, size| unsafe {
        GetExtendedTcpTable(
            Some(buf as *mut _),
            size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;

    let reported_entries = windows_table_reported_entries(&buffer)?;

    for row in windows_table_rows::<MIB_TCPROW_OWNER_PID>(
        &buffer,
        std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table),
        reported_entries,
    ) {
        // dwLocalAddr is the IPv4 address in network byte order; dwLocalPort is
        // the port in network byte order in the low 16 bits.
        let row_ip = std::net::Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
        let row_port = u16::from_be((row.dwLocalPort & 0xffff) as u16);
        if row_port == want_port && windows_local_ip_matches(row_ip.into(), want_ip.into()) {
            return Some(row.dwOwningPid);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn windows_tcp6_owner_pid(want_ip: std::net::Ipv6Addr, want_port: u16) -> Option<u32> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::AF_INET6;

    let buffer = windows_extended_table(|buf, size| unsafe {
        GetExtendedTcpTable(
            Some(buf as *mut _),
            size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;

    let reported_entries = windows_table_reported_entries(&buffer)?;

    for row in windows_table_rows::<MIB_TCP6ROW_OWNER_PID>(
        &buffer,
        std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
        reported_entries,
    ) {
        let row_ip = std::net::Ipv6Addr::from(row.ucLocalAddr);
        let row_port = u16::from_be((row.dwLocalPort & 0xffff) as u16);
        if row_port == want_port && windows_local_ip_matches(row_ip.into(), want_ip.into()) {
            return Some(row.dwOwningPid);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn windows_udp4_owner_pid(want_ip: std::net::Ipv4Addr, want_port: u16) -> Option<u32> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let buffer = windows_extended_table(|buf, size| unsafe {
        GetExtendedUdpTable(
            Some(buf as *mut _),
            size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    })?;

    let reported_entries = windows_table_reported_entries(&buffer)?;

    for row in windows_table_rows::<MIB_UDPROW_OWNER_PID>(
        &buffer,
        std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table),
        reported_entries,
    ) {
        let row_ip = std::net::Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
        let row_port = u16::from_be((row.dwLocalPort & 0xffff) as u16);
        if row_port == want_port && windows_local_ip_matches(row_ip.into(), want_ip.into()) {
            return Some(row.dwOwningPid);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn windows_udp6_owner_pid(want_ip: std::net::Ipv6Addr, want_port: u16) -> Option<u32> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::AF_INET6;

    let buffer = windows_extended_table(|buf, size| unsafe {
        GetExtendedUdpTable(
            Some(buf as *mut _),
            size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    })?;

    let reported_entries = windows_table_reported_entries(&buffer)?;

    for row in windows_table_rows::<MIB_UDP6ROW_OWNER_PID>(
        &buffer,
        std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
        reported_entries,
    ) {
        let row_ip = std::net::Ipv6Addr::from(row.ucLocalAddr);
        let row_port = u16::from_be((row.dwLocalPort & 0xffff) as u16);
        if row_port == want_port && windows_local_ip_matches(row_ip.into(), want_ip.into()) {
            return Some(row.dwOwningPid);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn windows_owner_pid_candidates(
    local_ip: std::net::IpAddr,
    local_port: u16,
    protocol: Protocol,
) -> [Option<u32>; 2] {
    match (local_ip, protocol) {
        (std::net::IpAddr::V4(ip), Protocol::Tcp) => [windows_tcp4_owner_pid(ip, local_port), None],
        (std::net::IpAddr::V6(ip), Protocol::Tcp) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                [
                    windows_tcp4_owner_pid(mapped, local_port),
                    windows_tcp6_owner_pid(ip, local_port),
                ]
            } else {
                [windows_tcp6_owner_pid(ip, local_port), None]
            }
        }
        (std::net::IpAddr::V4(ip), Protocol::Udp) => [windows_udp4_owner_pid(ip, local_port), None],
        (std::net::IpAddr::V6(ip), Protocol::Udp) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                [
                    windows_udp4_owner_pid(mapped, local_port),
                    windows_udp6_owner_pid(ip, local_port),
                ]
            } else {
                [windows_udp6_owner_pid(ip, local_port), None]
            }
        }
        _ => [None, None],
    }
}

#[cfg(target_os = "windows")]
fn windows_table_reported_entries(buffer: &[u8]) -> Option<u32> {
    let bytes = buffer.get(..std::mem::size_of::<u32>())?;
    Some(u32::from_ne_bytes(bytes.try_into().ok()?))
}

#[cfg(target_os = "windows")]
fn windows_table_rows<T: Copy>(
    buffer: &[u8],
    header_len: usize,
    reported_entries: u32,
) -> impl Iterator<Item = T> + '_ {
    let row_len = std::mem::size_of::<T>();
    let row_count =
        bounded_windows_table_entries(buffer.len(), header_len, row_len, reported_entries);
    let row_bytes_len = row_count.saturating_mul(row_len);
    buffer
        .get(header_len..header_len + row_bytes_len)
        .unwrap_or(&[])
        .chunks_exact(row_len)
        .map(|chunk| unsafe { std::ptr::read_unaligned(chunk.as_ptr().cast::<T>()) })
}

#[cfg(any(target_os = "windows", test))]
fn bounded_windows_table_entries(
    buffer_len: usize,
    header_len: usize,
    row_len: usize,
    reported_entries: u32,
) -> usize {
    if buffer_len < header_len || row_len == 0 {
        return 0;
    }
    let capacity = (buffer_len - header_len) / row_len;
    usize::try_from(reported_entries).map_or(capacity, |entries| entries.min(capacity))
}

/// Call a `GetExtended*Table` function with the grow-on-`ERROR_INSUFFICIENT_BUFFER`
/// protocol and return a byte buffer sized to the table. `call(ptr, &mut size)`
/// must invoke the API with the given buffer pointer (null on the sizing pass)
/// and in/out size, returning the Win32 error code.
#[cfg(target_os = "windows")]
fn windows_extended_table(mut call: impl FnMut(*mut u8, &mut u32) -> u32) -> Option<Vec<u8>> {
    use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};

    let mut size: u32 = 0;
    // First call sizes the table.
    let rc = call(std::ptr::null_mut(), &mut size);
    if rc != ERROR_INSUFFICIENT_BUFFER.0 && rc != NO_ERROR.0 {
        return None;
    }
    if size == 0 {
        return None;
    }

    // Retry a few times: the table can grow between the sizing call and the
    // fetch as connections come and go.
    for _ in 0..4 {
        let allocation_size = bounded_windows_table_size(size)?;
        let mut buffer = vec![0u8; allocation_size];
        let rc = call(buffer.as_mut_ptr(), &mut size);
        if rc == NO_ERROR.0 {
            return Some(buffer);
        }
        if rc != ERROR_INSUFFICIENT_BUFFER.0 {
            return None;
        }
    }
    None
}

#[cfg(any(target_os = "windows", test))]
const MAX_WINDOWS_TABLE_BYTES: u32 = 16 * 1024 * 1024;

#[cfg(any(target_os = "windows", test))]
fn bounded_windows_table_size(size: u32) -> Option<usize> {
    (size <= MAX_WINDOWS_TABLE_BYTES).then_some(size as usize)
}

/// Resolve a PID to a `ProcessInfo`, using the executable's base name. Falls
/// back to `pid-<n>` when the image name cannot be queried (e.g. a protected or
/// already-exited process).
#[cfg(target_os = "windows")]
fn windows_process_info(pid: u32) -> ProcessInfo {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };

    let mut full_path = String::new();

    unsafe {
        if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            && !handle.is_invalid()
        {
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_FORMAT(0),
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut len,
            );
            if ok.is_ok() && len > 0 {
                full_path = String::from_utf16_lossy(&buf[..len as usize]);
            }
            let _ = CloseHandle(handle);
        }
    }

    let name = full_path
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("pid-{}", pid));

    let info = ProcessInfo::new(pid, name);
    if full_path.is_empty() {
        info
    } else {
        info.with_path(full_path)
    }
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

    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(err) => {
            tracing::warn!("Failed to open /proc while listing processes: {}", err);
            return processes;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                tracing::warn!(
                    "Failed to read a /proc entry while listing processes: {}",
                    err
                );
                continue;
            }
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        if let Ok(pid) = name_str.parse::<u32>()
            && let Some(info) = get_process_info_impl(pid)
        {
            processes.push(info);
        }
    }

    processes
}

#[cfg(target_os = "linux")]
fn get_process_info_impl(pid: u32) -> Option<ProcessInfo> {
    let status_name =
        read_limited_proc_file(format!("/proc/{}/status", pid), MAX_PROC_STATUS_BYTES)
            .ok()
            .flatten()
            .and_then(|status| String::from_utf8(status).ok())
            .map(|status| process_name_from_status(&status, pid))
            .unwrap_or_else(|| format!("pid-{}", pid));

    let path = std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| process_path_to_string(&p));

    Some(process_info_from_status_and_path(
        pid,
        status_name,
        path,
        None,
    ))
}

#[cfg(target_os = "linux")]
fn process_info_with_optional_path(pid: u32, name: String, path: Option<String>) -> ProcessInfo {
    process_info_with_optional_metadata(pid, name, path, None)
}

#[cfg(target_os = "linux")]
fn process_info_with_optional_metadata(
    pid: u32,
    name: String,
    path: Option<String>,
    cmdline: Option<String>,
) -> ProcessInfo {
    let mut info = ProcessInfo::new(pid, name);
    if let Some(path) = path {
        info = info.with_path(path);
    }
    if let Some(cmdline) = cmdline.filter(|value| !value.trim().is_empty()) {
        info = info.with_command_line(cmdline);
    }
    info
}

#[cfg(target_os = "linux")]
fn read_limited_proc_file(
    path: impl AsRef<std::path::Path>,
    max_bytes: u64,
) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read as _;

    let file = std::fs::File::open(path)?;
    let sentinel_limit = max_bytes.checked_add(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "proc file read limit is too large",
        )
    })?;
    let mut content = Vec::new();
    file.take(sentinel_limit).read_to_end(&mut content)?;
    if content.len() as u64 > max_bytes {
        return Ok(None);
    }
    Ok(Some(content))
}

#[cfg(target_os = "linux")]
fn process_path_to_string(path: &std::path::Path) -> String {
    if let Some(path) = path.to_str() {
        return path.to_string();
    }

    use std::fmt::Write as _;
    use std::os::unix::ffi::OsStrExt;

    let mut rendered = String::from("hex:");
    for byte in path.as_os_str().as_bytes() {
        let _ = write!(&mut rendered, "{:02x}", byte);
    }
    rendered
}

#[cfg(target_os = "linux")]
fn process_cmdline_from_bytes(bytes: &[u8]) -> Option<String> {
    let cmdline = process_cmdline_to_string(bytes);
    (!cmdline.trim().is_empty()).then_some(cmdline)
}

#[cfg(target_os = "linux")]
fn process_cmdline_to_string(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.replace('\0', " ");
    }

    use std::fmt::Write as _;

    let mut rendered = String::from("hex:");
    for byte in bytes {
        let _ = write!(&mut rendered, "{:02x}", byte);
    }
    rendered
}

#[cfg(any(target_os = "linux", test))]
fn process_name_from_status(status: &str, pid: u32) -> String {
    status
        .lines()
        .find(|line| line.starts_with("Name:"))
        .and_then(|line| {
            let name = line.strip_prefix("Name:")?.trim();
            (!name.is_empty()).then(|| name.to_string())
        })
        .unwrap_or_else(|| format!("pid-{}", pid))
}

#[cfg(test)]
mod process_status_tests {
    #[test]
    fn process_name_from_status_preserves_colons_in_name() {
        let name = super::process_name_from_status("Name:\tsvc:worker\n", 4321);

        assert_eq!(name, "svc:worker");
    }
}

#[cfg(target_os = "linux")]
fn process_name_from_path(path: &str) -> Option<String> {
    let name = path.rsplit(['\\', '/']).next()?;
    let name = name.strip_suffix(" (deleted)").unwrap_or(name);
    (!name.is_empty()).then(|| name.to_string())
}

#[cfg(target_os = "linux")]
fn process_name_from_status_or_path(status_name: String, path: Option<&str>) -> String {
    path.and_then(process_name_from_path).unwrap_or(status_name)
}

#[cfg(target_os = "linux")]
fn process_info_from_status_and_path(
    pid: u32,
    status_name: String,
    path: Option<String>,
    cmdline: Option<String>,
) -> ProcessInfo {
    let name = process_name_from_status_or_path(status_name, path.as_deref());
    match cmdline {
        Some(cmdline) => process_info_with_optional_metadata(pid, name, path, Some(cmdline)),
        None => process_info_with_optional_path(pid, name, path),
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn socket_ip_matches(row_ip: std::net::IpAddr, want_ip: std::net::IpAddr) -> bool {
    if row_ip == want_ip {
        return true;
    }

    match (row_ip, want_ip) {
        (std::net::IpAddr::V4(row), std::net::IpAddr::V6(want)) => {
            want.to_ipv4_mapped().is_some_and(|mapped| row == mapped)
        }
        (std::net::IpAddr::V6(row), std::net::IpAddr::V4(want)) => {
            row.to_ipv4_mapped().is_some_and(|mapped| mapped == want)
        }
        (std::net::IpAddr::V6(row), std::net::IpAddr::V6(want)) => row
            .to_ipv4_mapped()
            .zip(want.to_ipv4_mapped())
            .is_some_and(|(row, want)| row == want),
        (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_)) => false,
    }
}

#[cfg(target_os = "linux")]
fn linux_proc_net_paths(
    local_ip: std::net::IpAddr,
    protocol: Protocol,
) -> [Option<&'static str>; 2] {
    match (local_ip, protocol) {
        (std::net::IpAddr::V4(_), Protocol::Udp) => [Some("/proc/net/udp"), None],
        (std::net::IpAddr::V6(ip), Protocol::Udp) if ip.to_ipv4_mapped().is_some() => {
            [Some("/proc/net/udp"), Some("/proc/net/udp6")]
        }
        (std::net::IpAddr::V6(_), Protocol::Udp) => [Some("/proc/net/udp6"), None],
        (std::net::IpAddr::V4(_), _) => [Some("/proc/net/tcp"), None],
        (std::net::IpAddr::V6(ip), _) if ip.to_ipv4_mapped().is_some() => {
            [Some("/proc/net/tcp"), Some("/proc/net/tcp6")]
        }
        (std::net::IpAddr::V6(_), _) => [Some("/proc/net/tcp6"), None],
    }
}

#[cfg(not(target_os = "linux"))]
pub fn get_all_processes() -> Vec<ProcessInfo> {
    Vec::new()
}

#[cfg(test)]
mod windows_table_tests {
    use super::{bounded_windows_table_entries, bounded_windows_table_size};

    #[test]
    fn windows_table_entries_are_bounded_by_buffer_capacity() {
        assert_eq!(bounded_windows_table_entries(24, 4, 4, 10), 5);
        assert_eq!(bounded_windows_table_entries(24, 4, 4, 3), 3);
        assert_eq!(bounded_windows_table_entries(3, 4, 4, 1), 0);
        assert_eq!(bounded_windows_table_entries(24, 4, 0, 1), 0);
    }

    #[test]
    fn windows_table_allocation_rejects_oversized_api_report() {
        assert_eq!(bounded_windows_table_size(u32::MAX), None);
        assert_eq!(
            bounded_windows_table_size(16 * 1024 * 1024),
            Some(16 * 1024 * 1024)
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod proc_net_ip_tests {
    use super::{
        find_matching_inode_in_proc_net, find_pid_by_inode_in_proc_root, parse_proc_net_ip,
    };
    use std::fs;
    use std::io::{self, Cursor, Read};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::{Path, PathBuf};

    #[test]
    fn decodes_ipv4_loopback_from_host_order_hex() {
        // /proc/net/tcp renders 127.0.0.1 as 0100007F on a little-endian host.
        assert_eq!(
            parse_proc_net_ip("0100007F"),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
    }

    #[test]
    fn decodes_ipv4_wildcard() {
        let ip = parse_proc_net_ip("00000000").expect("wildcard parses");
        assert!(ip.is_unspecified());
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn decodes_ipv4_routable_address() {
        // 192.168.1.10 -> bytes C0 A8 01 0A -> LE u32 hex 0A01A8C0.
        assert_eq!(
            parse_proc_net_ip("0A01A8C0"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)))
        );
    }

    #[test]
    fn decodes_ipv6_loopback() {
        // ::1 -> the last 32-bit word holds byte 01 last; rendered host-order
        // (little-endian) the four words are 00000000 00000000 00000000 01000000.
        assert_eq!(
            parse_proc_net_ip("00000000000000000000000001000000"),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }

    #[test]
    fn decodes_ipv6_wildcard() {
        let ip = parse_proc_net_ip(&"0".repeat(32)).expect("v6 wildcard parses");
        assert!(ip.is_unspecified());
    }

    #[test]
    fn rejects_malformed_width() {
        assert_eq!(parse_proc_net_ip("12AB"), None);
        assert_eq!(parse_proc_net_ip(""), None);
        assert_eq!(parse_proc_net_ip("ZZ"), None);
    }

    #[test]
    fn proc_net_reader_finds_matching_inode() {
        let proc_net = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 424242 1\n";

        let inode = find_matching_inode_in_proc_net(
            Cursor::new(proc_net),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
        )
        .expect("proc net read should succeed");

        assert_eq!(inode, Some(424242));
    }

    #[test]
    fn proc_net_reader_prefers_specific_bindings_over_wildcards() {
        let proc_net = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsnt   uid  timeout inode\n\
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111111 1\n\
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 222222 1\n";

        let inode = find_matching_inode_in_proc_net(
            Cursor::new(proc_net),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
        )
        .expect("proc net read should succeed");

        assert_eq!(inode, Some(222222));
    }

    #[test]
    fn proc_net_reader_skips_unparseable_rows_on_shared_ports() {
        let proc_net = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: ZZZZZZZZ:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111111 1\n\
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 222222 1\n";

        let inode = find_matching_inode_in_proc_net(
            Cursor::new(proc_net),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
        )
        .expect("proc net read should succeed");

        assert_eq!(inode, Some(222222));
    }

    #[test]
    fn proc_net_reader_propagates_line_read_errors() {
        let reader = io::BufReader::new(FailingProcNetReader {
            state: FailingReaderState::Header,
        });

        let err = find_matching_inode_in_proc_net(reader, IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
            .expect_err("read failure must be propagated");

        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn pid_lookup_finds_socket_inode_in_proc_root() {
        let proc_root = TestProcRoot::new("nettrap-attribution-proc-root-match");
        let fd_dir = proc_root.path().join("1234").join("fd");
        fs::create_dir_all(&fd_dir).expect("create fd directory");
        std::os::unix::fs::symlink("socket:[424242]", fd_dir.join("0"))
            .expect("create socket fd symlink");

        let pid = find_pid_by_inode_in_proc_root(proc_root.path(), 424242)
            .expect("proc root scan should succeed");

        assert_eq!(pid, Some(1234));
    }

    #[test]
    fn pid_lookup_reports_unreadable_proc_root() {
        let proc_root = TestProcRoot::new("nettrap-attribution-proc-root-missing");
        let missing_root = proc_root.path().join("missing");

        let err = find_pid_by_inode_in_proc_root(&missing_root, 424242)
            .expect_err("missing proc root must be reported");

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_info_without_exe_path_keeps_path_unset() {
        let info = super::process_info_with_optional_path(1234, "proc".to_string(), None);

        assert_eq!(info.pid(), 1234);
        assert_eq!(info.name(), "proc");
        assert_eq!(info.path(), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_info_without_cmdline_keeps_command_line_unset() {
        let info = super::process_info_with_optional_metadata(
            1234,
            "proc".to_string(),
            Some("/bin/proc".to_string()),
            None,
        );

        assert_eq!(info.pid(), 1234);
        assert_eq!(info.name(), "proc");
        assert_eq!(info.path(), Some("/bin/proc"));
        assert_eq!(info.command_line(), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_name_from_status_falls_back_when_name_is_empty() {
        let name = super::process_name_from_status("Name:\t \n", 4321);

        assert_eq!(name, "pid-4321");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_name_from_status_falls_back_when_name_line_is_missing() {
        let name = super::process_name_from_status("State:\tR (running)\n", 4321);

        assert_eq!(name, "pid-4321");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_name_from_path_uses_executable_basename() {
        assert_eq!(
            super::process_name_from_path("/usr/bin/python3.11"),
            Some("python3.11".to_string())
        );
        assert_eq!(
            super::process_name_from_path("/usr/bin/python3.11 (deleted)"),
            Some("python3.11".to_string())
        );
        assert_eq!(super::process_name_from_path("/usr/bin/"), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_name_from_status_or_path_prefers_path_basename() {
        let status_name = super::process_name_from_status("Name:\tvery-long-binary-n\n", 1234);
        let derived = super::process_name_from_status_or_path(
            status_name,
            Some("/opt/vendor/very-long-binary-name"),
        );

        assert_eq!(derived, "very-long-binary-name");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_info_from_status_and_path_prefers_executable_basename() {
        let info = super::process_info_from_status_and_path(
            4321,
            "status-name".to_string(),
            Some("/opt/vendor/very-long-binary-name".to_string()),
            None,
        );

        assert_eq!(info.pid(), 4321);
        assert_eq!(info.name(), "very-long-binary-name");
        assert_eq!(info.path(), Some("/opt/vendor/very-long-binary-name"));
        assert_eq!(info.command_line(), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_info_without_cmdline_content_keeps_command_line_unset() {
        let info = super::process_info_with_optional_metadata(
            4321,
            "proc".to_string(),
            None,
            Some(String::new()),
        );

        assert_eq!(info.command_line(), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_path_to_string_preserves_utf8_paths() {
        let path = std::path::Path::new("/bin/proc");

        let rendered = super::process_path_to_string(path);

        assert_eq!(rendered, "/bin/proc");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_path_to_string_preserves_non_utf8_paths_reversibly() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let raw = OsString::from_vec(b"/bin/proc\xff".to_vec());
        let path = std::path::Path::new(&raw);

        let rendered = super::process_path_to_string(path);

        assert_eq!(rendered, "hex:2f62696e2f70726f63ff");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_info_whitespace_only_cmdline_keeps_command_line_unset() {
        let info = super::process_info_with_optional_metadata(
            4321,
            "proc".to_string(),
            None,
            Some("   ".to_string()),
        );

        assert_eq!(info.command_line(), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_cmdline_from_bytes_preserves_non_utf8_arguments() {
        let cmdline = super::process_cmdline_from_bytes(b"/usr/bin/app\xff\0--flag\xfe\0")
            .expect("non-empty cmdline should be preserved");

        assert_eq!(cmdline, "hex:2f7573722f62696e2f617070ff002d2d666c6167fe00");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_cmdline_from_bytes_preserves_utf8_arguments() {
        let cmdline = super::process_cmdline_from_bytes(b"/usr/bin/app\0--flag\0")
            .expect("utf8 cmdline should be preserved");

        assert_eq!(cmdline, "/usr/bin/app --flag ");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn limited_proc_file_rejects_content_past_limit() {
        let proc_root = TestProcRoot::new("nettrap-attribution-proc-file-large");
        let path = proc_root.path().join("status");
        fs::write(&path, b"Name:\tproc\n").expect("write proc fixture");

        assert_eq!(
            super::read_limited_proc_file(&path, 11).expect("read proc fixture"),
            Some(b"Name:\tproc\n".to_vec())
        );
        assert_eq!(
            super::read_limited_proc_file(&path, 10).expect("read proc fixture"),
            None
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn limited_proc_file_rejects_unrepresentable_sentinel_limit() {
        let proc_root = TestProcRoot::new("nettrap-attribution-proc-file-overflow");
        let path = proc_root.path().join("status");
        fs::write(&path, b"").expect("write proc fixture");

        let err = super::read_limited_proc_file(&path, u64::MAX)
            .expect_err("overflowing sentinel limit should fail");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("read limit is too large"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn socket_ip_matches_ipv4_mapped_addresses() {
        assert!(super::socket_ip_matches(
            IpAddr::V6(Ipv6Addr::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 10
            ])),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
        ));
    }

    struct FailingProcNetReader {
        state: FailingReaderState,
    }

    enum FailingReaderState {
        Header,
        Failed,
    }

    impl Read for FailingProcNetReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.state {
                FailingReaderState::Header => {
                    self.state = FailingReaderState::Failed;
                    let header = b"sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
                    let len = header.len().min(buf.len());
                    buf[..len].copy_from_slice(&header[..len]);
                    Ok(len)
                }
                FailingReaderState::Failed => Err(io::Error::other("synthetic proc read error")),
            }
        }
    }

    struct TestProcRoot {
        path: PathBuf,
    }

    impl TestProcRoot {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!("{}-{}", name, std::process::id()));
            if path.exists() {
                fs::remove_dir_all(&path).expect("remove stale test proc root");
            }
            fs::create_dir_all(&path).expect("create test proc root");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestProcRoot {
        fn drop(&mut self) {
            if self.path.exists() {
                fs::remove_dir_all(&self.path).expect("remove test proc root");
            }
        }
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_socket_owner_tests {
    use super::get_process_for_socket;
    use nettrap_core::prelude::Protocol;
    use std::net::{IpAddr, Ipv4Addr, TcpListener};

    #[test]
    fn resolves_own_listening_socket_to_this_process() {
        // Bind a real listener on loopback, then look up its owning process via
        // the extended TCP table. It must resolve to this test process (a
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();

        let info = get_process_for_socket(IpAddr::V4(Ipv4Addr::LOCALHOST), port, Protocol::Tcp)
            .expect("owning process must resolve for our own bound socket");

        assert_eq!(
            info.pid(),
            std::process::id(),
            "socket should be attributed to this test process"
        );
        assert!(
            !info.name().is_empty(),
            "resolved process name must not be empty"
        );
    }

    #[test]
    fn unbound_port_resolves_to_nothing() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = probe.local_addr().unwrap().port();
        drop(probe); // release the port so nothing owns it

        let result = get_process_for_socket(IpAddr::V4(Ipv4Addr::LOCALHOST), port, Protocol::Tcp);
        assert!(
            result.is_none(),
            "an unbound port must not resolve to a process"
        );
    }
}
