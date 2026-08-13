//! FTP command execution and passive data-transfer helpers for TCP listeners.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use nettrap_protocols::handlers::nettrap_proto_ftp;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::session::SessionDestination;

const FTP_PASSIVE_ACCEPT_TIMEOUT: Duration = Duration::from_secs(2);
const FTP_PASSIVE_TRANSFER_TIMEOUT: Duration = Duration::from_secs(2);
const FTP_ACTIVE_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_FTP_PASSIVE_TRANSFERS: usize = 128;
const FTP_MAX_COMMAND_LINE_BYTES: usize = 512;
/// Uploaded bytes are read and discarded (honeypot never persists them);
/// this caps how much a single STOR/APPE may stream before we stop reading.
const MAX_FTP_UPLOAD_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct FtpPassiveState {
    pub(super) listener: Option<tokio::net::TcpListener>,
    pub(super) permit: Option<OwnedSemaphorePermit>,
    /// Client-provided active-mode (PORT/EPRT) data address, validated to be
    /// the control connection's own peer (no FTP-bounce / SSRF).
    pub(super) active_addr: Option<SocketAddr>,
}

impl FtpPassiveState {
    fn clear(&mut self) {
        self.listener = None;
        self.permit = None;
        self.active_addr = None;
    }
}

pub(super) enum FtpCommandAction {
    Response(Vec<u8>),
    Transfer {
        listener: tokio::net::TcpListener,
        permit: OwnedSemaphorePermit,
        transfer: nettrap_proto_ftp::FtpDataTransfer,
    },
}

pub(super) async fn handle_ftp_command(
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    ftp_passive_state: &mut FtpPassiveState,
    command: &str,
    peer: &SocketAddr,
    destination: &SessionDestination,
    control_local_addr: Option<SocketAddr>,
) -> Vec<u8> {
    match prepare_ftp_command(
        ftp_handler,
        ftp_passive_state,
        command,
        peer,
        destination,
        control_local_addr,
    )
    .await
    {
        FtpCommandAction::Response(response) => response,
        FtpCommandAction::Transfer {
            listener,
            permit,
            transfer,
        } => {
            let mut response = transfer.start_response.to_bytes();
            response
                .extend_from_slice(&finish_ftp_passive_transfer(listener, permit, transfer).await);
            response
        }
    }
}

pub(super) async fn prepare_ftp_command(
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    ftp_passive_state: &mut FtpPassiveState,
    command: &str,
    peer: &SocketAddr,
    destination: &SessionDestination,
    control_local_addr: Option<SocketAddr>,
) -> FtpCommandAction {
    let Some(command) = ftp_command_line(command) else {
        return FtpCommandAction::Response(ftp_handler.handle(command).to_bytes());
    };

    let verb = ftp_command_verb(command);
    if verb == "PASV" || verb == "EPSV" {
        if nettrap_proto_ftp::ftp_command_has_args(command) {
            return FtpCommandAction::Response(
                nettrap_proto_ftp::FtpResponse::new(501, "Syntax error in parameters").to_bytes(),
            );
        }
        return FtpCommandAction::Response(
            open_ftp_passive_data_socket(
                ftp_handler,
                ftp_passive_state,
                peer,
                destination,
                control_local_addr,
                verb == "EPSV",
            )
            .await,
        );
    }

    if verb == "PORT" || verb == "EPRT" {
        ftp_passive_state.active_addr = None;
        let success_message = if verb == "EPRT" {
            "EPRT command successful"
        } else {
            "PORT command successful"
        };
        let response = match nettrap_proto_ftp::parse_ftp_data_addr(command) {
            Ok(addr) => match validate_active_target(&addr, peer) {
                Ok(()) => {
                    ftp_passive_state.clear();
                    ftp_passive_state.active_addr = Some(addr);
                    nettrap_proto_ftp::FtpResponse::new(200, success_message)
                }
                Err(resp) => resp,
            },
            Err(resp) => resp,
        };
        return FtpCommandAction::Response(response.to_bytes());
    }

    if matches!(verb.as_str(), "ABOR" | "QUIT") {
        ftp_passive_state.clear();
    }

    if matches!(verb.as_str(), "LIST" | "NLST" | "RETR" | "STOR" | "APPE") {
        let passive = (
            ftp_passive_state.listener.take(),
            ftp_passive_state.permit.take(),
        );
        let active = ftp_passive_state.active_addr.take();

        let transfer = match ftp_handler.prepare_data_transfer(command) {
            Ok(transfer) => transfer,
            Err(response) => return FtpCommandAction::Response(response.to_bytes()),
        };

        if let (Some(listener), Some(permit)) = passive {
            return FtpCommandAction::Transfer {
                listener,
                permit,
                transfer,
            };
        }

        // Active mode: connect back to the validated client-provided address.
        // Acquire the same global transfer permit the passive path uses so
        // active transfers share the concurrency ceiling.
        if let Some(target) = active {
            let Ok(permit) = ftp_passive_transfer_semaphore().try_acquire_owned() else {
                return FtpCommandAction::Response(
                    nettrap_proto_ftp::FtpResponse::new(425, "Too many data transfers").to_bytes(),
                );
            };
            return FtpCommandAction::Response(
                finish_ftp_active_transfer(permit, target, transfer).await,
            );
        }

        return FtpCommandAction::Response(
            nettrap_proto_ftp::FtpResponse::new(425, "Use PASV, EPSV or PORT first").to_bytes(),
        );
    }

    FtpCommandAction::Response(ftp_handler.handle(command).to_bytes())
}

/// FTP-bounce / SSRF guard: an active-mode data connection may only ever go
/// back to the IP that owns the control connection, and never to
/// loopback/unspecified/multicast or port 0.
fn validate_active_target(
    addr: &SocketAddr,
    peer: &SocketAddr,
) -> Result<(), nettrap_proto_ftp::FtpResponse> {
    if normalize_ftp_peer_ip(addr.ip()) != normalize_ftp_peer_ip(peer.ip()) {
        return Err(nettrap_proto_ftp::FtpResponse::new(
            501,
            "Data address must match the control connection",
        ));
    }
    let ip = addr.ip();
    if is_unacceptable_data_ip(&ip) {
        return Err(nettrap_proto_ftp::FtpResponse::new(
            501,
            "Unacceptable data address",
        ));
    }
    if addr.port() == 0 {
        return Err(nettrap_proto_ftp::FtpResponse::new(
            501,
            "Unacceptable data port",
        ));
    }
    Ok(())
}

fn normalize_ftp_peer_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V4(ip) => std::net::IpAddr::V4(ip),
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
    }
}

fn is_unacceptable_data_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast()
        }
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.to_ipv4_mapped().is_some_and(|mapped| {
                    mapped.is_loopback()
                        || mapped.is_unspecified()
                        || mapped.is_multicast()
                        || mapped.is_broadcast()
                })
        }
    }
}

fn ftp_command_verb(command: &str) -> String {
    command.split(' ').next().unwrap_or("").to_ascii_uppercase()
}

fn ftp_command_line(command: &str) -> Option<&str> {
    if command.len() > FTP_MAX_COMMAND_LINE_BYTES {
        return None;
    }
    if command.chars().any(|ch| ch == '\0') {
        return None;
    }
    if command
        .chars()
        .any(|ch| matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
    {
        return None;
    }
    if let Some(line) = command.strip_suffix("\r\n") {
        if line
            .as_bytes()
            .iter()
            .any(|&byte| matches!(byte, b'\r' | b'\n'))
        {
            return None;
        }
        return Some(line);
    }
    if command.ends_with(['\r', '\n']) {
        return None;
    }
    if command
        .as_bytes()
        .iter()
        .any(|&byte| matches!(byte, b'\r' | b'\n'))
    {
        return None;
    }
    Some(command)
}

pub(super) async fn open_ftp_passive_data_socket(
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    ftp_passive_state: &mut FtpPassiveState,
    peer: &SocketAddr,
    destination: &SessionDestination,
    control_local_addr: Option<SocketAddr>,
    extended: bool,
) -> Vec<u8> {
    ftp_passive_state.clear();

    let Ok(permit) = ftp_passive_transfer_semaphore().try_acquire_owned() else {
        return nettrap_proto_ftp::FtpResponse::new(425, "Too many passive transfers").to_bytes();
    };

    match bind_ftp_passive_listener(ftp_handler, peer, control_local_addr).await {
        Ok((listener, port)) => {
            ftp_passive_state.listener = Some(listener);
            ftp_passive_state.permit = Some(permit);
            if extended {
                nettrap_proto_ftp::FtpResponse::new(
                    229,
                    format!("Entering Extended Passive Mode (|||{}|)", port),
                )
                .to_bytes()
            } else {
                let host = ftp_passive_response_host(ftp_handler, destination, control_local_addr);
                let p1 = port / 256;
                let p2 = port % 256;
                nettrap_proto_ftp::FtpResponse::new(
                    227,
                    format!("Entering Passive Mode ({},{},{})", host, p1, p2),
                )
                .to_bytes()
            }
        }
        Err(err) => {
            tracing::warn!("FTP passive bind failed for {}: {}", peer, err);
            nettrap_proto_ftp::FtpResponse::new(425, "Can't open passive connection").to_bytes()
        }
    }
}

async fn bind_ftp_passive_listener(
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    peer: &SocketAddr,
    control_local_addr: Option<SocketAddr>,
) -> std::io::Result<(tokio::net::TcpListener, u16)> {
    let (start, end) = ftp_handler.passive_ports();
    let (lo, hi) = if start <= end {
        (start, end)
    } else {
        (end, start)
    };
    let range = (hi as u32).saturating_sub(lo as u32).saturating_add(1);
    let first = ftp_handler.next_passive_port();
    let first_offset = if (lo..=hi).contains(&first) {
        first - lo
    } else {
        0
    } as u32;
    let bind_ip = ftp_passive_bind_ip(peer, control_local_addr);
    let mut last_error = None;

    for offset in 0..range {
        let port_offset = u16::try_from((first_offset + offset) % range).unwrap_or(0);
        let port = lo + port_offset;
        let bind_addr = SocketAddr::new(bind_ip, port);
        match tokio::net::TcpListener::bind(bind_addr).await {
            Ok(listener) => {
                let bound_port = listener
                    .local_addr()
                    .map(|addr| addr.port())
                    .unwrap_or(port);
                return Ok((listener, bound_port));
            }
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "empty FTP PASV range")
    }))
}

fn ftp_passive_bind_ip(peer: &SocketAddr, control_local_addr: Option<SocketAddr>) -> IpAddr {
    if let Some(local_addr) = control_local_addr
        && let Some(local_ip) = ftp_passive_bind_local_ip(local_addr.ip())
    {
        return local_ip;
    }

    match crate::session::normalize_session_ip(peer.ip()) {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

fn ftp_passive_bind_local_ip(ip: IpAddr) -> Option<IpAddr> {
    match ip {
        IpAddr::V4(ip) if !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast() => {
            Some(IpAddr::V4(ip))
        }
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .filter(|mapped| {
                !mapped.is_unspecified() && !mapped.is_multicast() && !mapped.is_broadcast()
            })
            .map(IpAddr::V4),
        IpAddr::V4(_) => None,
    }
}

pub(super) fn ftp_passive_response_host(
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    destination: &SessionDestination,
    control_local_addr: Option<SocketAddr>,
) -> String {
    ftp_passive_response_host_from_configured(
        ftp_handler.passive_address(),
        destination,
        control_local_addr,
    )
}

fn ftp_passive_response_host_from_configured(
    configured: &str,
    destination: &SessionDestination,
    control_local_addr: Option<SocketAddr>,
) -> String {
    let configured = configured.trim_matches([' ', '\t']);
    if let Some(host) = normalize_pasv_response_host(configured)
        && host != "0,0,0,0"
    {
        return host;
    }

    if let Some(host) = ftp_passive_response_host_from_local_addr(control_local_addr) {
        return host;
    }

    if let Some(ip) = ftp_passive_response_destination_ip(destination)
        && ip.is_loopback()
    {
        return ipv4_to_ftp_host(ip);
    }

    "127,0,0,1".to_string()
}

fn ftp_passive_response_host_from_local_addr(
    control_local_addr: Option<SocketAddr>,
) -> Option<String> {
    let local_addr = control_local_addr?;
    match local_addr.ip() {
        std::net::IpAddr::V4(ip) if !is_special_pasv_ipv4(ip) => Some(ipv4_to_ftp_host(ip)),
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .filter(|mapped| !is_special_pasv_ipv4(*mapped))
            .map(ipv4_to_ftp_host),
        std::net::IpAddr::V4(_) => None,
    }
}

fn ftp_passive_response_destination_ip(destination: &SessionDestination) -> Option<Ipv4Addr> {
    let ip = destination.ip().parse::<IpAddr>().ok()?;
    match ip {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(ip) => ip.to_ipv4_mapped(),
    }
}

fn normalize_pasv_response_host(value: &str) -> Option<String> {
    if value.is_empty()
        || value.chars().next().is_some_and(char::is_whitespace)
        || value.chars().last().is_some_and(char::is_whitespace)
        || value
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return None;
    }

    if let Ok(ip) = value.parse::<Ipv4Addr>() {
        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast() {
            return None;
        }
        return Some(ipv4_to_ftp_host(ip));
    }

    let mut octets = [0u8; 4];
    let mut parts = value.split(',');
    for octet in &mut octets {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        *octet = part.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    if octets == [0, 0, 0, 0] {
        return None;
    }
    if octets[0] == 127 || octets[0] >= 224 || octets == [255, 255, 255, 255] {
        return None;
    }

    Some(octets.map(|octet| octet.to_string()).join(","))
}

fn ipv4_to_ftp_host(ip: Ipv4Addr) -> String {
    let octets = ip.octets();
    format!("{},{},{},{}", octets[0], octets[1], octets[2], octets[3])
}

fn is_special_pasv_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()
}

fn ftp_passive_transfer_semaphore() -> Arc<Semaphore> {
    static SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();
    Arc::clone(SEMAPHORE.get_or_init(|| Arc::new(Semaphore::new(MAX_FTP_PASSIVE_TRANSFERS))))
}

pub(super) async fn finish_ftp_passive_transfer(
    listener: tokio::net::TcpListener,
    _permit: OwnedSemaphorePermit,
    transfer: nettrap_proto_ftp::FtpDataTransfer,
) -> Vec<u8> {
    let accept_result = tokio::time::timeout(FTP_PASSIVE_ACCEPT_TIMEOUT, listener.accept()).await;
    let (mut data_stream, data_peer) = match accept_result {
        Ok(Ok(accepted)) => accepted,
        Ok(Err(err)) => {
            tracing::warn!("FTP passive accept failed: {}", err);
            return nettrap_proto_ftp::FtpResponse::new(425, "Can't open data connection")
                .to_bytes();
        }
        Err(_) => {
            return nettrap_proto_ftp::FtpResponse::new(425, "Data connection timed out")
                .to_bytes();
        }
    };

    tracing::debug!("FTP passive data connection accepted from {}", data_peer);
    let transfer_result: std::io::Result<()> = if transfer.receive {
        recv_and_discard_ftp_data(&mut data_stream, FTP_PASSIVE_TRANSFER_TIMEOUT)
            .await
            .map(|_| ())
    } else {
        send_ftp_passive_data(&mut data_stream, &transfer, FTP_PASSIVE_TRANSFER_TIMEOUT).await
    };

    if let Err(err) = transfer_result {
        tracing::warn!("FTP passive transfer failed: {}", err);
        nettrap_proto_ftp::FtpResponse::new(426, "Connection closed; transfer aborted").to_bytes()
    } else {
        transfer.complete_response.to_bytes()
    }
}

/// Connect back to a validated active-mode (PORT/EPRT) data address and run
/// the transfer. Returns the combined start + completion responses (active
/// transfers are not split because there is no pre-bound listener to await).
async fn finish_ftp_active_transfer(
    _permit: OwnedSemaphorePermit,
    target: SocketAddr,
    transfer: nettrap_proto_ftp::FtpDataTransfer,
) -> Vec<u8> {
    let mut out = transfer.start_response.to_bytes();
    let connect = tokio::time::timeout(
        FTP_ACTIVE_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(target),
    )
    .await;
    let mut data_stream = match connect {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            tracing::warn!("FTP active connect to {} failed: {}", target, err);
            out.extend_from_slice(
                &nettrap_proto_ftp::FtpResponse::new(425, "Can't open data connection").to_bytes(),
            );
            return out;
        }
        Err(_) => {
            out.extend_from_slice(
                &nettrap_proto_ftp::FtpResponse::new(425, "Data connection timed out").to_bytes(),
            );
            return out;
        }
    };

    let transfer_result: std::io::Result<()> = if transfer.receive {
        recv_and_discard_ftp_data(&mut data_stream, FTP_PASSIVE_TRANSFER_TIMEOUT)
            .await
            .map(|_| ())
    } else {
        send_ftp_passive_data(&mut data_stream, &transfer, FTP_PASSIVE_TRANSFER_TIMEOUT).await
    };

    if let Err(err) = transfer_result {
        tracing::warn!("FTP active transfer to {} failed: {}", target, err);
        out.extend_from_slice(
            &nettrap_proto_ftp::FtpResponse::new(426, "Connection closed; transfer aborted")
                .to_bytes(),
        );
    } else {
        out.extend_from_slice(&transfer.complete_response.to_bytes());
    }
    out
}

/// Read and discard an upload (STOR/APPE), bounded by size and time. The
/// honeypot never persists uploaded bytes.
pub(super) async fn recv_and_discard_ftp_data<R>(
    data_stream: &mut R,
    transfer_timeout: Duration,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
{
    recv_and_discard_ftp_data_limited(data_stream, transfer_timeout, MAX_FTP_UPLOAD_BYTES).await
}

async fn recv_and_discard_ftp_data_limited<R>(
    data_stream: &mut R,
    transfer_timeout: Duration,
    max_bytes: u64,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let sentinel_limit = max_bytes.checked_add(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "FTP upload byte limit is too large",
        )
    })?;

    tokio::time::timeout(transfer_timeout, async {
        let mut buf = [0u8; 8192];
        let mut total: u64 = 0;
        while total < sentinel_limit {
            let buf_len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
            let read_len =
                usize::try_from((sentinel_limit - total).min(buf_len)).unwrap_or(buf.len());
            let n = data_stream.read(&mut buf[..read_len]).await?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "FTP upload exceeds byte limit",
                ));
            }
        }
        Ok::<u64, std::io::Error>(total)
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "FTP upload timed out"))?
}

pub(super) async fn send_ftp_passive_data<W>(
    data_stream: &mut W,
    transfer: &nettrap_proto_ftp::FtpDataTransfer,
    transfer_timeout: Duration,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    tokio::time::timeout(transfer_timeout, async {
        data_stream.write_all(&transfer.data).await?;
        data_stream.flush().await?;
        data_stream.shutdown().await
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "FTP data transfer timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    static FTP_TRANSFER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn failed_data_command_releases_reserved_passive_channel() {
        let _lock = FTP_TRANSFER_TEST_LOCK.lock().await;
        let handler = nettrap_proto_ftp::FtpHandler::new();
        let mut state = FtpPassiveState::default();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral listener");
        let permit = ftp_passive_transfer_semaphore()
            .try_acquire_owned()
            .expect("a permit should be available");
        state.listener = Some(listener);
        state.permit = Some(permit);

        let peer: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);

        let action = prepare_ftp_command(
            &handler,
            &mut state,
            "STOR ../../etc/passwd",
            &peer,
            &destination,
            None,
        )
        .await;

        match action {
            FtpCommandAction::Response(bytes) => {
                assert!(
                    String::from_utf8_lossy(&bytes).contains("550"),
                    "traversal upload must be rejected with 550"
                );
            }
            FtpCommandAction::Transfer { .. } => panic!("must not start a transfer"),
        }

        assert!(
            state.listener.is_none(),
            "passive listener must be released on a failed data command"
        );
        assert!(
            state.permit.is_none(),
            "passive transfer permit must be released on a failed data command"
        );
    }

    #[tokio::test]
    async fn successful_active_command_releases_reserved_passive_channel() {
        let _lock = FTP_TRANSFER_TEST_LOCK.lock().await;
        let handler = nettrap_proto_ftp::FtpHandler::new();
        let mut state = FtpPassiveState::default();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral listener");
        let permit = ftp_passive_transfer_semaphore()
            .try_acquire_owned()
            .expect("a permit should be available");
        state.listener = Some(listener);
        state.permit = Some(permit);

        let peer: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);

        let action = prepare_ftp_command(
            &handler,
            &mut state,
            "PORT 203,0,113,5,156,64",
            &peer,
            &destination,
            None,
        )
        .await;

        match action {
            FtpCommandAction::Response(bytes) => {
                assert!(
                    String::from_utf8_lossy(&bytes).starts_with("200 "),
                    "valid active mode should be accepted"
                );
            }
            FtpCommandAction::Transfer { .. } => panic!("PORT must not start a transfer"),
        }

        assert!(
            state.listener.is_none(),
            "passive listener must be released"
        );
        assert!(state.permit.is_none(), "passive permit must be released");
        assert!(
            state.active_addr.is_some(),
            "active target must be recorded"
        );
    }

    #[tokio::test]
    async fn successful_eprt_command_uses_eprt_success_text() {
        let _lock = FTP_TRANSFER_TEST_LOCK.lock().await;
        let handler = nettrap_proto_ftp::FtpHandler::new();
        let mut state = FtpPassiveState::default();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral listener");
        let permit = ftp_passive_transfer_semaphore()
            .try_acquire_owned()
            .expect("a permit should be available");
        state.listener = Some(listener);
        state.permit = Some(permit);

        let peer: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);

        let action = prepare_ftp_command(
            &handler,
            &mut state,
            "EPRT |1|203.0.113.5|40000|",
            &peer,
            &destination,
            None,
        )
        .await;

        match action {
            FtpCommandAction::Response(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                assert!(
                    text.starts_with("200 EPRT "),
                    "valid EPRT should be accepted"
                );
            }
            FtpCommandAction::Transfer { .. } => panic!("EPRT must not start a transfer"),
        }

        assert!(
            state.listener.is_none(),
            "passive listener must be released"
        );
        assert!(state.permit.is_none(), "passive permit must be released");
        assert!(
            state.active_addr.is_some(),
            "active target must be recorded"
        );
    }

    #[tokio::test]
    async fn active_transfers_hold_the_global_permit_until_completion() {
        let _lock = FTP_TRANSFER_TEST_LOCK.lock().await;
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);
        let peer: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind active transfer listener");
        let port = listener.local_addr().expect("listener addr").port();
        let accepted = std::sync::Arc::new(tokio::sync::Notify::new());
        let accepted_signal = std::sync::Arc::clone(&accepted);

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept active transfer");
            accepted_signal.notify_one();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let mut buf = [0u8; 1];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
            })
            .await;
        });

        let mut permits = Vec::with_capacity(MAX_FTP_PASSIVE_TRANSFERS - 1);
        for _ in 0..(MAX_FTP_PASSIVE_TRANSFERS - 1) {
            permits.push(
                ftp_passive_transfer_semaphore()
                    .try_acquire_owned()
                    .expect("reserve permit"),
            );
        }

        let first_handler = nettrap_proto_ftp::FtpHandler::new();
        let mut first_state = FtpPassiveState {
            active_addr: Some(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port,
            )),
            ..Default::default()
        };
        let first_peer = peer;
        let first_destination = destination.clone();

        let first = tokio::spawn(async move {
            prepare_ftp_command(
                &first_handler,
                &mut first_state,
                "STOR upload.bin",
                &first_peer,
                &first_destination,
                None,
            )
            .await
        });

        accepted.notified().await;

        let second_handler = nettrap_proto_ftp::FtpHandler::new();
        let mut second_state = FtpPassiveState {
            active_addr: Some(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port,
            )),
            ..Default::default()
        };
        let second_peer = peer;
        let second_destination = destination.clone();

        let second_response = prepare_ftp_command(
            &second_handler,
            &mut second_state,
            "STOR upload.bin",
            &second_peer,
            &second_destination,
            None,
        )
        .await;

        match second_response {
            FtpCommandAction::Response(bytes) => {
                assert!(
                    String::from_utf8_lossy(&bytes).starts_with("425 "),
                    "second active transfer should be rejected while the first still holds the permit"
                );
            }
            FtpCommandAction::Transfer { .. } => {
                panic!("second active transfer must not start while the permit is held")
            }
        }

        first.abort();
        let _ = first.await;
        server_task.abort();
        drop(permits);
    }

    #[tokio::test]
    async fn invalid_active_command_clears_stale_active_target_without_releasing_passive_state() {
        let _lock = FTP_TRANSFER_TEST_LOCK.lock().await;
        let handler = nettrap_proto_ftp::FtpHandler::new();
        let mut state = FtpPassiveState::default();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral listener");
        let permit = ftp_passive_transfer_semaphore()
            .try_acquire_owned()
            .expect("a permit should be available");
        state.listener = Some(listener);
        state.permit = Some(permit);
        state.active_addr = Some("203.0.113.5:40000".parse().unwrap());

        let peer: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);

        let action = prepare_ftp_command(
            &handler,
            &mut state,
            "PORT 127,0,0,1,1,1",
            &peer,
            &destination,
            None,
        )
        .await;

        match action {
            FtpCommandAction::Response(bytes) => {
                assert!(String::from_utf8_lossy(&bytes).starts_with("501 "));
            }
            FtpCommandAction::Transfer { .. } => panic!("invalid PORT must not start a transfer"),
        }

        assert!(
            state.listener.is_some(),
            "passive listener must remain reserved"
        );
        assert!(
            state.permit.is_some(),
            "passive permit must remain reserved"
        );
        assert!(
            state.active_addr.is_none(),
            "stale active target must be cleared"
        );
    }

    #[tokio::test]
    async fn passive_commands_reject_extra_arguments_without_opening_listener() {
        let handler = nettrap_proto_ftp::FtpHandler::new();
        let peer: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);

        for command in ["PASV now", "EPSV 1"] {
            let mut state = FtpPassiveState::default();
            let action =
                prepare_ftp_command(&handler, &mut state, command, &peer, &destination, None).await;

            match action {
                FtpCommandAction::Response(bytes) => {
                    assert!(
                        String::from_utf8_lossy(&bytes).starts_with("501 "),
                        "{command}"
                    );
                }
                FtpCommandAction::Transfer { .. } => {
                    panic!("{command} must not open a passive transfer")
                }
            }
            assert!(state.listener.is_none(), "{command}");
            assert!(state.permit.is_none(), "{command}");
        }
    }

    #[tokio::test]
    async fn oversized_pasv_command_does_not_open_passive_listener() {
        let handler = nettrap_proto_ftp::FtpHandler::new();
        let mut state = FtpPassiveState::default();
        let peer: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);
        let command = format!("PASV {}", "x".repeat(FTP_MAX_COMMAND_LINE_BYTES));

        let action =
            prepare_ftp_command(&handler, &mut state, &command, &peer, &destination, None).await;

        match action {
            FtpCommandAction::Response(bytes) => {
                assert!(
                    !String::from_utf8_lossy(&bytes).starts_with("227 "),
                    "oversized PASV must not open a passive listener"
                );
            }
            FtpCommandAction::Transfer { .. } => panic!("oversized PASV must not transfer"),
        }
        assert!(state.listener.is_none());
        assert!(state.permit.is_none());
    }

    #[tokio::test]
    async fn ftp_command_verb_rejects_tab_separated_pasv() {
        let handler = nettrap_proto_ftp::FtpHandler::new();
        let mut state = FtpPassiveState::default();
        let peer: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);

        let action =
            prepare_ftp_command(&handler, &mut state, "PASV\tnow", &peer, &destination, None).await;

        match action {
            FtpCommandAction::Response(bytes) => {
                assert!(
                    !String::from_utf8_lossy(&bytes).starts_with("227 "),
                    "tab-separated PASV must not open a passive listener"
                );
            }
            FtpCommandAction::Transfer { .. } => panic!("tab-separated PASV must not transfer"),
        }
        assert!(state.listener.is_none());
        assert!(state.permit.is_none());
    }

    #[tokio::test]
    async fn ftp_command_verb_rejects_unicode_line_separators() {
        let handler = nettrap_proto_ftp::FtpHandler::new();
        let mut state = FtpPassiveState::default();
        let peer: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);

        let action = prepare_ftp_command(
            &handler,
            &mut state,
            "PASV\u{2028}now",
            &peer,
            &destination,
            None,
        )
        .await;

        match action {
            FtpCommandAction::Response(bytes) => {
                assert!(
                    !String::from_utf8_lossy(&bytes).starts_with("227 "),
                    "unicode-separated PASV must not open a passive listener"
                );
            }
            FtpCommandAction::Transfer { .. } => {
                panic!("unicode-separated PASV must not transfer")
            }
        }
        assert!(state.listener.is_none());
        assert!(state.permit.is_none());
    }

    #[tokio::test]
    async fn ftp_command_rejects_bare_cr_pasv_without_opening_listener() {
        let handler = nettrap_proto_ftp::FtpHandler::new();
        let mut state = FtpPassiveState::default();
        let peer: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);

        let action =
            prepare_ftp_command(&handler, &mut state, "PASV\r", &peer, &destination, None).await;

        match action {
            FtpCommandAction::Response(bytes) => {
                assert!(
                    !String::from_utf8_lossy(&bytes).starts_with("227 "),
                    "bare CR PASV must not open a passive listener"
                );
            }
            FtpCommandAction::Transfer { .. } => panic!("bare CR PASV must not transfer"),
        }
        assert!(state.listener.is_none());
        assert!(state.permit.is_none());
    }

    #[tokio::test]
    async fn ftp_command_rejects_embedded_nul_pasv_without_opening_listener() {
        let handler = nettrap_proto_ftp::FtpHandler::new();
        let mut state = FtpPassiveState::default();
        let peer: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);

        let action =
            prepare_ftp_command(&handler, &mut state, "PASV\0now", &peer, &destination, None).await;

        match action {
            FtpCommandAction::Response(bytes) => {
                assert!(
                    !String::from_utf8_lossy(&bytes).starts_with("227 "),
                    "embedded NUL PASV must not open a passive listener"
                );
            }
            FtpCommandAction::Transfer { .. } => {
                panic!("embedded NUL PASV must not transfer")
            }
        }
        assert!(state.listener.is_none());
        assert!(state.permit.is_none());
    }

    #[tokio::test]
    async fn ftp_upload_discard_stops_at_exact_byte_limit() {
        let mut stream = std::io::Cursor::new(vec![b'x'; 17]);

        let total = recv_and_discard_ftp_data_limited(&mut stream, Duration::from_secs(1), 17)
            .await
            .expect("discard should succeed");

        assert_eq!(total, 17);
        assert_eq!(stream.position(), 17);
    }

    #[tokio::test]
    async fn ftp_upload_discard_rejects_bytes_over_limit() {
        let mut stream = std::io::Cursor::new(vec![b'x'; 18]);

        let err = recv_and_discard_ftp_data_limited(&mut stream, Duration::from_secs(1), 17)
            .await
            .expect_err("oversized upload should fail");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn ftp_passive_response_host_ignores_unicode_whitespace_pasv_address() {
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);

        let host =
            ftp_passive_response_host_from_configured("10.1.2.3\u{00a0}", &destination, None);

        assert_eq!(host, "127,0,0,1");
    }

    #[test]
    fn ftp_passive_response_host_rejects_unspecified_pasv_addresses() {
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);

        for configured in ["0.0.0.0", "0,0,0,0"] {
            let host = ftp_passive_response_host_from_configured(configured, &destination, None);

            assert_eq!(host, "127,0,0,1");
        }
    }

    #[test]
    fn ftp_passive_response_host_rejects_loopback_pasv_addresses() {
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);
        let control_local_addr = Some("203.0.113.10:2121".parse().unwrap());

        for configured in ["127.0.0.1", "127,0,0,1"] {
            let host = ftp_passive_response_host_from_configured(
                configured,
                &destination,
                control_local_addr,
            );

            assert_eq!(host, "203,0,113,10");
        }
    }

    #[test]
    fn ftp_passive_response_host_uses_ipv4_mapped_control_local_addr() {
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);
        let control_local_addr = Some("[::ffff:203.0.113.10]:2121".parse().unwrap());

        let host =
            ftp_passive_response_host_from_configured("0.0.0.0", &destination, control_local_addr);

        assert_eq!(host, "203,0,113,10");
    }

    #[test]
    fn ftp_passive_bind_ip_treats_ipv4_mapped_peer_as_ipv4() {
        let peer = "[::ffff:192.0.2.10]:2121".parse().unwrap();

        assert_eq!(
            ftp_passive_bind_ip(&peer, None),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn ftp_passive_response_host_rejects_special_mapped_control_local_addr() {
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);
        let control_local_addr = Some("[::ffff:255.255.255.255]:2121".parse().unwrap());

        let host =
            ftp_passive_response_host_from_configured("0.0.0.0", &destination, control_local_addr);

        assert_eq!(host, "127,0,0,1");
    }

    #[test]
    fn ftp_passive_response_host_uses_ipv4_mapped_destination_loopback() {
        let destination = SessionDestination::new_unchecked("::ffff:127.0.0.1", 21);

        let host = ftp_passive_response_host_from_configured("0.0.0.0", &destination, None);

        assert_eq!(host, "127,0,0,1");
    }

    #[test]
    fn ftp_passive_bind_ip_uses_ipv4_for_mapped_local_addresses() {
        let peer: SocketAddr = "[2001:db8::1]:21".parse().unwrap();
        let control_local_addr: SocketAddr = "[::ffff:203.0.113.10]:2121".parse().unwrap();

        let bind_ip = ftp_passive_bind_ip(&peer, Some(control_local_addr));

        assert_eq!(bind_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
    }

    #[test]
    fn ftp_passive_bind_ip_rejects_special_mapped_local_addresses() {
        assert!(ftp_passive_bind_local_ip(IpAddr::V4(Ipv4Addr::BROADCAST)).is_none());
        assert!(ftp_passive_bind_local_ip(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))).is_none());

        let mapped_broadcast: IpAddr = "::ffff:255.255.255.255".parse().unwrap();
        let mapped_multicast: IpAddr = "::ffff:224.0.0.1".parse().unwrap();

        assert!(ftp_passive_bind_local_ip(mapped_broadcast).is_none());
        assert!(ftp_passive_bind_local_ip(mapped_multicast).is_none());
    }

    #[test]
    fn ftp_passive_response_host_rejects_multicast_and_broadcast_pasv_addresses() {
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);

        for configured in [
            "224.0.0.1",
            "239.255.255.250",
            "255.255.255.255",
            "224,0,0,1",
            "239,255,255,250",
            "255,255,255,255",
        ] {
            let host = ftp_passive_response_host_from_configured(configured, &destination, None);

            assert_eq!(host, "127,0,0,1", "{configured}");
        }
    }

    #[test]
    fn ftp_active_target_rejects_broadcast_addresses() {
        let broadcast = "255.255.255.255:20".parse().expect("broadcast addr");

        let err = validate_active_target(&broadcast, &broadcast)
            .expect_err("broadcast active target should fail");

        assert!(
            err.to_bytes()
                .starts_with(b"501 Unacceptable data address\r\n")
        );
    }

    #[test]
    fn ftp_active_target_rejects_ipv4_mapped_loopback_addresses() {
        let target: std::net::SocketAddr = "[::ffff:127.0.0.1]:20".parse().expect("mapped addr");

        let err = validate_active_target(&target, &target)
            .expect_err("mapped loopback active target should fail");

        assert!(
            err.to_bytes()
                .starts_with(b"501 Unacceptable data address\r\n")
        );
    }

    #[test]
    fn ftp_active_target_accepts_ipv4_mapped_control_peer_for_same_ipv4_address() {
        let addr: std::net::SocketAddr = "192.0.2.10:20".parse().expect("ipv4 addr");
        let peer: std::net::SocketAddr = "[::ffff:192.0.2.10]:21".parse().expect("mapped peer");

        validate_active_target(&addr, &peer).expect("logical peers should match");
    }

    #[test]
    fn ftp_passive_response_host_rejects_malformed_comma_addresses() {
        let destination = SessionDestination::new_unchecked("198.51.100.1", 21);

        let host =
            ftp_passive_response_host_from_configured("10,1,2,3\u{00a0}", &destination, None);

        assert_eq!(host, "127,0,0,1");
    }
}
