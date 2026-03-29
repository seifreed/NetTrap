use std::process::Command;

/// Execute a command template when a connection is received.
/// Available template variables:
/// - {pid}: Process ID
/// - {procname}: Process name
/// - {src_addr}: Source IP address
/// - {src_port}: Source port
/// - {dst_addr}: Destination IP address
/// - {dst_port}: Destination port
/// - {listener}: Listener name
pub fn execute_on_connect(
    template: &str,
    pid: Option<u32>,
    procname: Option<&str>,
    src_addr: &str,
    src_port: u16,
    dst_addr: &str,
    dst_port: u16,
    listener: &str,
) {
    let cmd = template
        .replace("{pid}", &pid.map(|p| p.to_string()).unwrap_or_default())
        .replace("{procname}", procname.unwrap_or("unknown"))
        .replace("{src_addr}", src_addr)
        .replace("{src_port}", &src_port.to_string())
        .replace("{dst_addr}", dst_addr)
        .replace("{dst_port}", &dst_port.to_string())
        .replace("{listener}", listener);

    tracing::info!("Executing command: {}", cmd);

    let result = if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", &cmd]).spawn()
    } else {
        Command::new("sh").args(["-c", &cmd]).spawn()
    };

    match result {
        Ok(mut child) => {
            // Don't wait - fire and forget
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(e) => {
            tracing::warn!("Failed to execute command: {}", e);
        }
    }
}
