use nettrap_proto_dns::handler::DnsHandlerTrait;
use nettrap_proto_tftp::TftpHandlerTrait;
use nettrap_protocols::handlers::*;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::listener_context::ListenerContext;
use crate::session::SessionDestination;
use crate::utils::log_event;

const TFTP_TRANSFER_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_TFTP_ACTIVE_TRANSFERS: usize = 1024;
const MAX_TFTP_UPLOAD_BYTES: u64 = 8 * 1024 * 1024;

type TftpTransfers = Arc<Mutex<HashMap<TftpTransferKey, TftpTransferState>>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TftpTransferKey {
    src: SocketAddr,
    dst_ip: String,
    dst_port: u16,
}

impl TftpTransferKey {
    fn new(src: SocketAddr, destination: &SessionDestination) -> Self {
        Self {
            src,
            dst_ip: destination.ip.clone(),
            dst_port: destination.port,
        }
    }
}

#[derive(Debug, Clone)]
enum TftpTransferState {
    Read {
        filename: String,
        last_block_sent: u16,
        last_response: nettrap_proto_tftp::TftpPacket,
        complete: bool,
        last_activity: Instant,
    },
    Write {
        filename: String,
        next_block_expected: u16,
        bytes_received: u64,
        last_ack: nettrap_proto_tftp::TftpPacket,
        complete: bool,
        last_activity: Instant,
    },
}

impl TftpTransferState {
    fn last_activity(&self) -> Instant {
        match self {
            Self::Read { last_activity, .. } | Self::Write { last_activity, .. } => *last_activity,
        }
    }
}

#[cfg(not(target_os = "windows"))]
#[derive(Clone, Copy, Default)]
struct UdpDestinationCapture;

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Default)]
struct UdpDestinationCapture {
    recv_msg: windows::Win32::Networking::WinSock::LPFN_WSARECVMSG,
}

fn direct_destination_from_local_addr(
    local_addr: SocketAddr,
    bind_addr: IpAddr,
) -> SessionDestination {
    let ip = if local_addr.ip().is_unspecified() && !bind_addr.is_unspecified() {
        bind_addr
    } else {
        local_addr.ip()
    };
    SessionDestination::new(ip.to_string(), local_addr.port())
}

#[cfg(unix)]
fn configure_udp_destination_capture(
    socket: &UdpSocket,
    bind_addr: IpAddr,
) -> io::Result<UdpDestinationCapture> {
    use std::mem::size_of_val;
    use std::os::fd::AsRawFd;

    let fd = socket.as_raw_fd();
    let enabled: libc::c_int = 1;
    let enabled_ptr = (&enabled as *const libc::c_int).cast::<libc::c_void>();
    let enabled_len = size_of_val(&enabled) as libc::socklen_t;

    let result = unsafe {
        match bind_addr {
            IpAddr::V4(_) => {
                #[cfg(target_os = "linux")]
                let optname = libc::IP_PKTINFO;
                #[cfg(not(target_os = "linux"))]
                let optname = libc::IP_RECVDSTADDR;

                libc::setsockopt(fd, libc::IPPROTO_IP, optname, enabled_ptr, enabled_len)
            }
            IpAddr::V6(_) => libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVPKTINFO,
                enabled_ptr,
                enabled_len,
            ),
        }
    };

    if result == -1 {
        return Err(io::Error::last_os_error());
    }

    #[cfg(target_os = "linux")]
    {
        const IP_RECVORIGDSTADDR: libc::c_int = 20;
        const IPV6_RECVORIGDSTADDR: libc::c_int = 74;

        let result = unsafe {
            match bind_addr {
                IpAddr::V4(_) => libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    IP_RECVORIGDSTADDR,
                    enabled_ptr,
                    enabled_len,
                ),
                IpAddr::V6(_) => libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    IPV6_RECVORIGDSTADDR,
                    enabled_ptr,
                    enabled_len,
                ),
            }
        };
        if result == -1 {
            tracing::debug!(
                "UDP original destination capture is unavailable on {}: {}",
                bind_addr,
                io::Error::last_os_error()
            );
        }
    }

    Ok(UdpDestinationCapture)
}

#[cfg(unix)]
fn max_cmsg_space() -> usize {
    let ipv4_pktinfo =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as _) } as usize;
    let ipv6_pktinfo =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as _) } as usize;
    #[cfg(target_os = "linux")]
    {
        let ipv4_original =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::sockaddr_in>() as _) } as usize;
        let ipv6_original =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::sockaddr_in6>() as _) } as usize;
        (ipv4_pktinfo + ipv4_original).max(ipv6_pktinfo + ipv6_original)
    }
    #[cfg(not(target_os = "linux"))]
    {
        ipv4_pktinfo.max(ipv6_pktinfo)
    }
}

#[cfg(unix)]
fn parse_ipv4(s_addr: libc::in_addr) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(u32::from_be(s_addr.s_addr)))
}

#[cfg(unix)]
fn parse_ipv6(s_addr: libc::in6_addr) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(s_addr.s6_addr))
}

#[cfg(unix)]
unsafe fn socket_addr_from_storage(storage: &libc::sockaddr_storage) -> io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Ok(SocketAddr::new(
                parse_ipv4(addr.sin_addr),
                u16::from_be(addr.sin_port),
            ))
        }
        libc::AF_INET6 => {
            let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Ok(SocketAddr::new(
                parse_ipv6(addr.sin6_addr),
                u16::from_be(addr.sin6_port),
            ))
        }
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported sockaddr family {}", family),
        )),
    }
}

#[cfg(unix)]
fn destination_ip_from_control_message(message: &libc::msghdr) -> Option<IpAddr> {
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(message);
        while !cmsg.is_null() {
            let header = &*cmsg;
            if header.cmsg_level == libc::IPPROTO_IP {
                #[cfg(target_os = "linux")]
                if header.cmsg_type == libc::IP_PKTINFO {
                    let pktinfo = &*(libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo);
                    return Some(parse_ipv4(pktinfo.ipi_addr));
                }

                #[cfg(not(target_os = "linux"))]
                if header.cmsg_type == libc::IP_RECVDSTADDR {
                    let addr = &*(libc::CMSG_DATA(cmsg) as *const libc::in_addr);
                    return Some(parse_ipv4(*addr));
                }
            }

            if header.cmsg_level == libc::IPPROTO_IPV6 && header.cmsg_type == libc::IPV6_PKTINFO {
                let pktinfo = &*(libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo);
                return Some(parse_ipv6(pktinfo.ipi6_addr));
            }

            cmsg = libc::CMSG_NXTHDR(message, cmsg);
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn original_destination_from_control_message(message: &libc::msghdr) -> Option<SessionDestination> {
    const IP_ORIGDSTADDR: libc::c_int = 20;
    const IPV6_ORIGDSTADDR: libc::c_int = 74;

    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(message);
        while !cmsg.is_null() {
            let header = &*cmsg;
            if header.cmsg_level == libc::IPPROTO_IP && header.cmsg_type == IP_ORIGDSTADDR {
                let addr = *(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in);
                return Some(session_destination_from_sockaddr_in(addr));
            }

            if header.cmsg_level == libc::IPPROTO_IPV6 && header.cmsg_type == IPV6_ORIGDSTADDR {
                let addr = *(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6);
                return Some(session_destination_from_sockaddr_in6(addr));
            }

            cmsg = libc::CMSG_NXTHDR(message, cmsg);
        }
    }

    None
}

#[cfg(not(target_os = "linux"))]
#[cfg(unix)]
fn original_destination_from_control_message(
    _message: &libc::msghdr,
) -> Option<SessionDestination> {
    None
}

#[cfg(target_os = "linux")]
fn session_destination_from_sockaddr_in(addr: libc::sockaddr_in) -> SessionDestination {
    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    SessionDestination::new(ip.to_string(), port)
}

#[cfg(target_os = "linux")]
fn session_destination_from_sockaddr_in6(addr: libc::sockaddr_in6) -> SessionDestination {
    let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
    let port = u16::from_be(addr.sin6_port);
    SessionDestination::new(ip.to_string(), port)
}

#[cfg(unix)]
fn recv_from_with_destination_now(
    socket: &UdpSocket,
    buf: &mut [u8],
    listener_port: u16,
) -> io::Result<(usize, SocketAddr, Option<SessionDestination>)> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    let fd = socket.as_raw_fd();
    let mut source_addr = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut control = vec![0u8; max_cmsg_space()];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_name = source_addr.as_mut_ptr().cast();
    message.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as _;
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len() as _;

    let received = unsafe { libc::recvmsg(fd, &mut message, 0) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }

    let src = unsafe { socket_addr_from_storage(&source_addr.assume_init())? };
    let destination = original_destination_from_control_message(&message).or_else(|| {
        destination_ip_from_control_message(&message)
            .map(|ip| SessionDestination::new(ip.to_string(), listener_port))
    });

    Ok((received as usize, src, destination))
}

#[cfg(unix)]
async fn recv_udp_packet(
    socket: &UdpSocket,
    _capture: &UdpDestinationCapture,
    buf: &mut [u8],
    listener_port: u16,
) -> io::Result<(usize, SocketAddr, Option<SessionDestination>)> {
    use tokio::io::Interest;

    socket
        .async_io(Interest::READABLE, || {
            recv_from_with_destination_now(socket, buf, listener_port)
        })
        .await
}

#[cfg(target_os = "windows")]
fn windows_cmsg_align(len: usize) -> usize {
    let alignment = std::mem::size_of::<usize>();
    (len + alignment - 1) & !(alignment - 1)
}

#[cfg(target_os = "windows")]
fn windows_cmsg_space(data_len: usize) -> usize {
    windows_cmsg_align(std::mem::size_of::<
        windows::Win32::Networking::WinSock::CMSGHDR,
    >()) + windows_cmsg_align(data_len)
}

#[cfg(target_os = "windows")]
fn parse_ipv4_windows(addr: windows::Win32::Networking::WinSock::IN_ADDR) -> IpAddr {
    let value = unsafe { addr.S_un.S_addr };
    IpAddr::V4(Ipv4Addr::from(u32::from_be(value)))
}

#[cfg(target_os = "windows")]
fn parse_ipv6_windows(addr: windows::Win32::Networking::WinSock::IN6_ADDR) -> IpAddr {
    let bytes = unsafe { addr.u.Byte };
    IpAddr::V6(Ipv6Addr::from(bytes))
}

#[cfg(target_os = "windows")]
fn windows_wsa_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe {
        windows::Win32::Networking::WinSock::WSAGetLastError().0
    })
}

#[cfg(target_os = "windows")]
fn configure_udp_destination_capture(
    socket: &UdpSocket,
    bind_addr: IpAddr,
) -> io::Result<UdpDestinationCapture> {
    use std::mem::{size_of, size_of_val};
    use std::os::windows::io::AsRawSocket;
    use std::slice;
    use windows::Win32::Networking::WinSock::{
        IP_PKTINFO, IPPROTO_IP, IPPROTO_IPV6, IPV6_PKTINFO, LPFN_WSARECVMSG,
        SIO_GET_EXTENSION_FUNCTION_POINTER, SOCKET, SOCKET_ERROR, WSAID_WSARECVMSG, WSAIoctl,
        setsockopt,
    };

    let raw = SOCKET(socket.as_raw_socket() as usize);
    let enabled: i32 = 1;
    let enabled_bytes = unsafe {
        slice::from_raw_parts((&enabled as *const i32).cast::<u8>(), size_of_val(&enabled))
    };

    let opt_result = unsafe {
        match bind_addr {
            IpAddr::V4(_) => setsockopt(raw, IPPROTO_IP.0, IP_PKTINFO, Some(enabled_bytes)),
            IpAddr::V6(_) => setsockopt(raw, IPPROTO_IPV6.0, IPV6_PKTINFO, Some(enabled_bytes)),
        }
    };
    if opt_result == SOCKET_ERROR {
        return Err(windows_wsa_error());
    }

    let guid = WSAID_WSARECVMSG;
    let mut recv_msg = LPFN_WSARECVMSG::default();
    let mut bytes_returned = 0u32;
    let ioctl_result = unsafe {
        WSAIoctl(
            raw,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            Some((&guid as *const _).cast()),
            size_of::<windows::core::GUID>() as u32,
            Some((&mut recv_msg as *mut _).cast()),
            size_of::<LPFN_WSARECVMSG>() as u32,
            &mut bytes_returned,
            None,
            None,
        )
    };
    if ioctl_result == SOCKET_ERROR {
        return Err(windows_wsa_error());
    }

    if recv_msg.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "WSARecvMsg extension is unavailable",
        ));
    }

    let _ = bytes_returned;
    Ok(UdpDestinationCapture { recv_msg })
}

#[cfg(target_os = "windows")]
unsafe fn socket_addr_from_storage_windows(
    storage: &windows::Win32::Networking::WinSock::SOCKADDR_STORAGE,
) -> io::Result<SocketAddr> {
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};

    match storage.ss_family {
        AF_INET => {
            let addr = unsafe { &*(storage as *const _ as *const SOCKADDR_IN) };
            Ok(SocketAddr::new(
                parse_ipv4_windows(addr.sin_addr),
                u16::from_be(addr.sin_port),
            ))
        }
        AF_INET6 => {
            let addr = unsafe { &*(storage as *const _ as *const SOCKADDR_IN6) };
            Ok(SocketAddr::new(
                parse_ipv6_windows(addr.sin6_addr),
                u16::from_be(addr.sin6_port),
            ))
        }
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported sockaddr family {}", family.0),
        )),
    }
}

#[cfg(target_os = "windows")]
fn destination_ip_from_control_message_windows(control: &[u8]) -> Option<IpAddr> {
    use windows::Win32::Networking::WinSock::{
        CMSGHDR, IN_PKTINFO, IN6_PKTINFO, IP_PKTINFO, IPPROTO_IP, IPPROTO_IPV6, IPV6_PKTINFO,
    };

    let mut offset = 0usize;
    let header_len = std::mem::size_of::<CMSGHDR>();
    let data_offset = windows_cmsg_align(header_len);

    while offset + header_len <= control.len() {
        let header = unsafe { &*(control.as_ptr().add(offset) as *const CMSGHDR) };
        let cmsg_len = header.cmsg_len;
        if cmsg_len < header_len || offset + cmsg_len > control.len() {
            break;
        }

        if header.cmsg_level == IPPROTO_IP.0 && header.cmsg_type == IP_PKTINFO {
            let needed = std::mem::size_of::<IN_PKTINFO>();
            if offset + data_offset + needed <= control.len() && needed <= cmsg_len - header_len {
                let pktinfo =
                    unsafe { &*(control.as_ptr().add(offset + data_offset) as *const IN_PKTINFO) };
                return Some(parse_ipv4_windows(pktinfo.ipi_addr));
            }
        }

        if header.cmsg_level == IPPROTO_IPV6.0 && header.cmsg_type == IPV6_PKTINFO {
            let needed = std::mem::size_of::<IN6_PKTINFO>();
            if offset + data_offset + needed <= control.len() && needed <= cmsg_len - header_len {
                let pktinfo =
                    unsafe { &*(control.as_ptr().add(offset + data_offset) as *const IN6_PKTINFO) };
                return Some(parse_ipv6_windows(pktinfo.ipi6_addr));
            }
        }

        let next = offset + windows_cmsg_align(cmsg_len);
        if next <= offset {
            break;
        }
        offset = next;
    }

    None
}

#[cfg(target_os = "windows")]
fn recv_from_with_destination_now(
    socket: &UdpSocket,
    capture: &UdpDestinationCapture,
    buf: &mut [u8],
    listener_port: u16,
) -> io::Result<(usize, SocketAddr, Option<SessionDestination>)> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{
        SOCKADDR, SOCKADDR_STORAGE, SOCKET, SOCKET_ERROR, WSABUF, WSAMSG,
    };
    use windows::core::PSTR;

    let raw = SOCKET(socket.as_raw_socket() as usize);
    let recv_msg = capture.recv_msg.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "WSARecvMsg extension is unavailable",
        )
    })?;

    let mut source_addr = SOCKADDR_STORAGE::default();
    let mut data_buf = WSABUF {
        len: buf.len() as u32,
        buf: PSTR(buf.as_mut_ptr()),
    };
    let mut control =
        vec![
            0u8;
            windows_cmsg_space(size_of::<windows::Win32::Networking::WinSock::IN_PKTINFO>()).max(
                windows_cmsg_space(size_of::<windows::Win32::Networking::WinSock::IN6_PKTINFO>())
            )
        ];
    let mut msg = WSAMSG {
        name: (&mut source_addr as *mut SOCKADDR_STORAGE).cast::<SOCKADDR>(),
        namelen: size_of::<SOCKADDR_STORAGE>() as i32,
        lpBuffers: &mut data_buf,
        dwBufferCount: 1,
        Control: WSABUF {
            len: control.len() as u32,
            buf: PSTR(control.as_mut_ptr()),
        },
        dwFlags: 0,
    };
    let mut bytes_received = 0u32;

    let result = unsafe {
        recv_msg(
            raw,
            &mut msg,
            &mut bytes_received,
            std::ptr::null_mut(),
            None,
        )
    };
    if result == SOCKET_ERROR {
        return Err(windows_wsa_error());
    }

    let src = unsafe { socket_addr_from_storage_windows(&source_addr)? };
    let destination =
        destination_ip_from_control_message_windows(&control[..msg.Control.len as usize])
            .map(|ip| SessionDestination::new(ip.to_string(), listener_port));

    Ok((bytes_received as usize, src, destination))
}

#[cfg(target_os = "windows")]
async fn recv_udp_packet(
    socket: &UdpSocket,
    capture: &UdpDestinationCapture,
    buf: &mut [u8],
    listener_port: u16,
) -> io::Result<(usize, SocketAddr, Option<SessionDestination>)> {
    use tokio::io::Interest;

    socket
        .async_io(Interest::READABLE, || {
            recv_from_with_destination_now(socket, capture, buf, listener_port)
        })
        .await
}

#[cfg(not(any(unix, target_os = "windows")))]
fn configure_udp_destination_capture(
    _socket: &UdpSocket,
    _bind_addr: IpAddr,
) -> io::Result<UdpDestinationCapture> {
    Ok(UdpDestinationCapture)
}

#[cfg(not(any(unix, target_os = "windows")))]
async fn recv_udp_packet(
    socket: &UdpSocket,
    _capture: &UdpDestinationCapture,
    buf: &mut [u8],
    _listener_port: u16,
) -> io::Result<(usize, SocketAddr, Option<SessionDestination>)> {
    socket
        .recv_from(buf)
        .await
        .map(|(len, src)| (len, src, None))
}

/// Run a UDP listener for DNS, TFTP, and other UDP protocols.
pub async fn run_udp_listener(
    ctx: ListenerContext,
    socket: UdpSocket,
    bind_addr: std::net::IpAddr,
    output_path: Option<&std::path::Path>,
) -> crate::Result<()> {
    let addr = socket.local_addr()?;
    let destination_capture = match configure_udp_destination_capture(&socket, bind_addr) {
        Ok(capture) => capture,
        Err(e) => {
            #[cfg(not(target_os = "windows"))]
            let capture = UdpDestinationCapture;
            #[cfg(target_os = "windows")]
            let capture = UdpDestinationCapture::default();
            tracing::warn!(
                "UDP listener '{}' could not enable destination capture on {}: {}",
                ctx.name(),
                addr,
                e
            );
            capture
        }
    };
    let local_addr = socket.local_addr()?;

    tracing::info!("UDP listener '{}' listening on {}", ctx.name(), addr);

    let ctx = Arc::new(ctx);
    let dns_handler = Arc::new(crate::protocol_handlers::init_dns_handler(&ctx));
    let tftp_handler = Arc::new(crate::protocol_handlers::init_tftp_handler(&ctx));
    let tftp_transfers = Arc::new(Mutex::new(HashMap::new()));
    let output_path = output_path.map(|p| p.to_path_buf());
    let socket = Arc::new(socket);
    let listener_port = local_addr.port();
    let direct_destination = direct_destination_from_local_addr(local_addr, bind_addr);
    let mut buf = vec![0u8; 65535];
    // Limit concurrent UDP handler tasks to prevent resource exhaustion from floods
    let udp_semaphore = Arc::new(tokio::sync::Semaphore::new(1024));

    loop {
        match recv_udp_packet(&socket, &destination_capture, &mut buf, listener_port).await {
            Ok((len, src, packet_destination)) => {
                if !ctx.is_host_allowed(&src.ip().to_string()) {
                    tracing::debug!("Host {} blocked by filter on {}", src.ip(), ctx.name());
                    continue;
                }

                let (destination, is_new_session) = ctx.register_session_state(
                    &src,
                    "UDP",
                    Some(packet_destination.unwrap_or_else(|| direct_destination.clone())),
                );

                let query_data = buf[..len].to_vec();

                let ctx_clone = Arc::clone(&ctx);
                let dns_handler_clone = Arc::clone(&dns_handler);
                let tftp_handler_clone = Arc::clone(&tftp_handler);
                let tftp_transfers_clone = Arc::clone(&tftp_transfers);
                let socket_clone = Arc::clone(&socket);
                let out_clone = output_path.clone();
                let sem = Arc::clone(&udp_semaphore);

                let permit = match sem.try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!("UDP task limit reached, dropping packet from {}", src);
                        continue;
                    }
                };

                tokio::spawn(async move {
                    let _permit = permit; // held until task completes
                    if !apply_udp_process_filter(&ctx_clone, &src, &destination).await {
                        tracing::debug!("UDP process blocked by filter on {}", ctx_clone.name());
                        return;
                    }

                    tracing::debug!(
                        "UDP '{}' received {} bytes from {}",
                        ctx_clone.name(),
                        len,
                        src
                    );

                    if ctx_clone.config.log_hexdump {
                        tracing::debug!("Hexdump:\n{}", crate::hexdump::hexdump(&query_data, 256));
                    }

                    ctx_clone.write_pcap_event_udp_for_destination(&query_data, &src, &destination);

                    let packet = UdpPacket {
                        output_path: out_clone.as_deref(),
                        query_data: &query_data,
                        src: &src,
                        destination: &destination,
                        len,
                    };
                    if let Some(protocol) = explicit_udp_protocol_name(ctx_clone.name()) {
                        handle_explicit_udp_protocol(
                            &ctx_clone,
                            &socket_clone,
                            &dns_handler_clone,
                            &tftp_handler_clone,
                            &tftp_transfers_clone,
                            packet,
                            protocol,
                        )
                        .await;
                    } else {
                        handle_detected_udp(
                            &ctx_clone,
                            &socket_clone,
                            &dns_handler_clone,
                            &tftp_handler_clone,
                            &tftp_transfers_clone,
                            packet,
                        )
                        .await;
                    }

                    if is_new_session {
                        ctx_clone.fire_execute_cmd_for_session(&src, "UDP", &destination);
                    }
                });
            }
            Err(e) => {
                tracing::warn!("UDP recv_from error: {}", e);
            }
        }
    }
}

async fn apply_udp_process_filter(
    ctx: &Arc<ListenerContext>,
    src: &std::net::SocketAddr,
    destination: &SessionDestination,
) -> bool {
    let Some(attr_engine) = ctx.runtime.attribution.as_ref() else {
        return true;
    };

    let dst_ip = destination
        .ip
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let five_tuple = nettrap_core::prelude::FiveTuple::new(
        src.ip(),
        dst_ip,
        src.port(),
        destination.port,
        nettrap_core::prelude::Protocol::Udp,
    );

    match tokio::time::timeout(
        ctx.runtime.attribution_timeout,
        tokio::task::spawn_blocking({
            let attr_engine = Arc::clone(attr_engine);
            move || attr_engine.attribute_flow(&five_tuple)
        }),
    )
    .await
    {
        Ok(Ok(attr)) if attr.confidence != nettrap_core::prelude::AttributionConfidence::None => {
            apply_attributed_process_filter(ctx, src, destination, &attr)
        }
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            tracing::warn!("UDP attribution timeout/error for {}: {}", src, e);
            true
        }
        Err(_) => {
            tracing::warn!(
                "UDP attribution timed out after {} ms for {}",
                ctx.runtime.attribution_timeout.as_millis(),
                src
            );
            true
        }
    }
}

fn apply_attributed_process_filter(
    ctx: &ListenerContext,
    src: &std::net::SocketAddr,
    destination: &SessionDestination,
    attr: &nettrap_core::prelude::Attribution,
) -> bool {
    let proc_name = &attr.process.name;
    ctx.runtime.session_tracker.set_process(
        src,
        "UDP",
        destination,
        Some(proc_name.to_string()),
        Some(attr.process.pid),
    );
    ctx.is_process_allowed(proc_name)
}

async fn handle_tftp(
    ctx: &ListenerContext,
    socket: &UdpSocket,
    tftp_handler: &nettrap_proto_tftp::TftpHandler,
    transfers: &TftpTransfers,
    packet: UdpPacket<'_>,
) {
    {
        let mut active = transfers.lock().await;
        prune_tftp_transfers(&mut active);
    }

    if let Some(tftp_packet) = nettrap_proto_tftp::TftpPacket::parse(packet.query_data) {
        log_event(
            packet.output_path,
            ctx.name(),
            packet.src,
            "tftp_request",
            &format!("{:?}", tftp_packet),
        )
        .await;
        let nbi = crate::nbi::tftp_nbi(
            ctx.name(),
            &packet.src.ip().to_string(),
            packet.src.port(),
            packet.destination,
            &format!("{:?}", tftp_packet),
            "",
        );
        ctx.record_nbi(&nbi).await;
        let responses_result: nettrap_core::error::Result<Vec<nettrap_proto_tftp::TftpPacket>> =
            match &tftp_packet {
                nettrap_proto_tftp::TftpPacket::ReadRequest { filename, .. } => {
                    let key = TftpTransferKey::new(*packet.src, packet.destination);
                    let mut active = transfers.lock().await;
                    prune_tftp_transfers(&mut active);
                    if let Some(response) =
                        duplicate_tftp_read_request_response(&mut active, &key, filename)
                    {
                        Ok(vec![response])
                    } else if tftp_transfer_limit_reached(&active, &key) {
                        Ok(vec![tftp_error(4, "Too many active transfers")])
                    } else {
                        let response = tftp_handler.handle_read_request_block(filename, 1);
                        remember_tftp_read_response(
                            &mut active,
                            key,
                            filename.clone(),
                            1,
                            &response,
                        );
                        Ok(vec![response])
                    }
                }
                nettrap_proto_tftp::TftpPacket::WriteRequest { filename, .. } => {
                    let key = TftpTransferKey::new(*packet.src, packet.destination);
                    let mut active = transfers.lock().await;
                    prune_tftp_transfers(&mut active);
                    if let Some(response) =
                        duplicate_tftp_write_request_response(&mut active, &key, filename)
                    {
                        Ok(vec![response])
                    } else if tftp_transfer_limit_reached(&active, &key) {
                        Ok(vec![tftp_error(4, "Too many active transfers")])
                    } else {
                        let response = tftp_handler.handle_write_request(filename);
                        active.insert(
                            key,
                            TftpTransferState::Write {
                                filename: filename.clone(),
                                next_block_expected: 1,
                                bytes_received: 0,
                                last_ack: response.clone(),
                                complete: false,
                                last_activity: Instant::now(),
                            },
                        );
                        Ok(vec![response])
                    }
                }
                nettrap_proto_tftp::TftpPacket::Ack { block } => {
                    let key = TftpTransferKey::new(*packet.src, packet.destination);
                    let action = {
                        let mut active = transfers.lock().await;
                        prune_tftp_transfers(&mut active);
                        next_tftp_read_action(&mut active, &key, *block)
                    };
                    match action {
                        Some(TftpReadAckAction::SendNext {
                            filename,
                            next_block,
                        }) => {
                            let response =
                                tftp_handler.handle_read_request_block(&filename, next_block);
                            let mut active = transfers.lock().await;
                            remember_tftp_read_response(
                                &mut active,
                                key,
                                filename,
                                next_block,
                                &response,
                            );
                            Ok(vec![response])
                        }
                        Some(TftpReadAckAction::Retransmit(response)) => Ok(vec![response]),
                        Some(TftpReadAckAction::Complete) | None => Ok(Vec::new()),
                    }
                }
                nettrap_proto_tftp::TftpPacket::Data { block, data } => {
                    let key = TftpTransferKey::new(*packet.src, packet.destination);
                    let mut active = transfers.lock().await;
                    prune_tftp_transfers(&mut active);
                    Ok(handle_tftp_write_data(
                        &mut active,
                        &key,
                        tftp_handler,
                        *block,
                        data,
                    ))
                }
                nettrap_proto_tftp::TftpPacket::Error { .. } => {
                    let key = TftpTransferKey::new(*packet.src, packet.destination);
                    transfers.lock().await.remove(&key);
                    tftp_handler.handle_packet(&tftp_packet).await
                }
            };
        match responses_result {
            Ok(responses) => {
                let mut sent_bytes = 0u64;
                if !responses.is_empty() {
                    ctx.apply_response_delay().await;
                }
                for resp in responses {
                    let resp_bytes = resp.to_bytes();
                    if resp_bytes.is_empty() {
                        continue;
                    }
                    ctx.write_pcap_response_udp_for_destination(
                        &resp_bytes,
                        packet.src,
                        packet.destination,
                    );
                    match socket.send_to(&resp_bytes, *packet.src).await {
                        Ok(_) => {
                            sent_bytes += resp_bytes.len() as u64;
                        }
                        Err(e) => {
                            tracing::warn!("Failed to send TFTP response to {}: {}", packet.src, e);
                        }
                    }
                }
                ctx.update_session_bytes(
                    packet.src,
                    "UDP",
                    packet.destination,
                    packet.len as u64,
                    sent_bytes,
                );
            }
            Err(e) => tracing::warn!("TFTP handler error: {}", e),
        }
    }
}

fn prune_tftp_transfers(transfers: &mut HashMap<TftpTransferKey, TftpTransferState>) {
    transfers.retain(|_, state| state.last_activity().elapsed() <= TFTP_TRANSFER_TIMEOUT);
}

fn tftp_transfer_limit_reached(
    transfers: &HashMap<TftpTransferKey, TftpTransferState>,
    key: &TftpTransferKey,
) -> bool {
    !transfers.contains_key(key) && transfers.len() >= MAX_TFTP_ACTIVE_TRANSFERS
}

fn remember_tftp_read_response(
    transfers: &mut HashMap<TftpTransferKey, TftpTransferState>,
    key: TftpTransferKey,
    filename: String,
    block: u16,
    response: &nettrap_proto_tftp::TftpPacket,
) {
    match response {
        nettrap_proto_tftp::TftpPacket::Data { data, .. } => {
            transfers.insert(
                key,
                TftpTransferState::Read {
                    filename,
                    last_block_sent: block,
                    last_response: response.clone(),
                    complete: data.len() < nettrap_proto_tftp::TFTP_BLOCK_SIZE,
                    last_activity: Instant::now(),
                },
            );
        }
        _ => {
            transfers.remove(&key);
        }
    }
}

#[derive(Debug, Clone)]
enum TftpReadAckAction {
    SendNext { filename: String, next_block: u16 },
    Retransmit(nettrap_proto_tftp::TftpPacket),
    Complete,
}

fn duplicate_tftp_read_request_response(
    transfers: &mut HashMap<TftpTransferKey, TftpTransferState>,
    key: &TftpTransferKey,
    requested_filename: &str,
) -> Option<nettrap_proto_tftp::TftpPacket> {
    let state = transfers.get_mut(key)?;
    match state {
        TftpTransferState::Read {
            filename,
            last_response,
            last_activity,
            ..
        } if filename == requested_filename => {
            *last_activity = Instant::now();
            Some(last_response.clone())
        }
        _ => Some(tftp_error(4, "Transfer already active")),
    }
}

fn duplicate_tftp_write_request_response(
    transfers: &mut HashMap<TftpTransferKey, TftpTransferState>,
    key: &TftpTransferKey,
    requested_filename: &str,
) -> Option<nettrap_proto_tftp::TftpPacket> {
    let state = transfers.get_mut(key)?;
    match state {
        TftpTransferState::Write {
            filename,
            last_ack,
            last_activity,
            ..
        } if filename == requested_filename => {
            *last_activity = Instant::now();
            Some(last_ack.clone())
        }
        _ => Some(tftp_error(4, "Transfer already active")),
    }
}

fn next_tftp_read_action(
    transfers: &mut HashMap<TftpTransferKey, TftpTransferState>,
    key: &TftpTransferKey,
    ack_block: u16,
) -> Option<TftpReadAckAction> {
    let mut remove_after = false;
    let action = {
        let Some(TftpTransferState::Read {
            filename,
            last_block_sent,
            last_response,
            complete,
            last_activity,
        }) = transfers.get_mut(key)
        else {
            return None;
        };

        if ack_block == *last_block_sent {
            if *complete {
                remove_after = true;
                Some(TftpReadAckAction::Complete)
            } else {
                *last_activity = Instant::now();
                Some(TftpReadAckAction::SendNext {
                    filename: filename.clone(),
                    next_block: ack_block.wrapping_add(1),
                })
            }
        } else if ack_block.wrapping_add(1) == *last_block_sent {
            *last_activity = Instant::now();
            Some(TftpReadAckAction::Retransmit(last_response.clone()))
        } else {
            None
        }
    };

    if remove_after {
        transfers.remove(key);
    }
    action
}

fn handle_tftp_write_data(
    transfers: &mut HashMap<TftpTransferKey, TftpTransferState>,
    key: &TftpTransferKey,
    tftp_handler: &nettrap_proto_tftp::TftpHandler,
    block: u16,
    data: &[u8],
) -> Vec<nettrap_proto_tftp::TftpPacket> {
    let (response, remove_after) = {
        let Some(state) = transfers.get_mut(key) else {
            return vec![tftp_error(5, "Unknown transfer id")];
        };

        let TftpTransferState::Write {
            filename,
            next_block_expected,
            bytes_received,
            last_ack,
            complete,
            last_activity,
        } = state
        else {
            return vec![tftp_error(4, "Unexpected DATA for read transfer")];
        };

        if *complete {
            if block.wrapping_add(1) == *next_block_expected {
                *last_activity = Instant::now();
                return vec![last_ack.clone()];
            }
            return vec![tftp_error(4, "Unexpected DATA block")];
        }

        if block != *next_block_expected {
            if block.wrapping_add(1) == *next_block_expected {
                *last_activity = Instant::now();
                return vec![last_ack.clone()];
            }
            tracing::warn!(
                "TFTP DATA block {} for {} does not match expected block {}",
                block,
                filename,
                *next_block_expected
            );
            return vec![tftp_error(4, "Unexpected DATA block")];
        }

        if data.len() > nettrap_proto_tftp::TFTP_BLOCK_SIZE {
            (tftp_error(4, "DATA block too large"), true)
        } else {
            match bytes_received.checked_add(data.len() as u64) {
                Some(new_total) if new_total <= MAX_TFTP_UPLOAD_BYTES => {
                    *bytes_received = new_total;
                    *next_block_expected = block.wrapping_add(1);
                    *last_activity = Instant::now();
                    let response = tftp_handler.handle_data_block(block, data);
                    *last_ack = response.clone();
                    *complete = data.len() < nettrap_proto_tftp::TFTP_BLOCK_SIZE;
                    (response, false)
                }
                _ => (tftp_error(3, "Upload too large"), true),
            }
        }
    };

    if remove_after {
        transfers.remove(key);
    }

    vec![response]
}

fn tftp_error(code: u16, message: impl Into<String>) -> nettrap_proto_tftp::TftpPacket {
    nettrap_proto_tftp::TftpPacket::Error {
        code,
        message: message.into(),
    }
}

async fn handle_dns(
    ctx: &ListenerContext,
    socket: &UdpSocket,
    dns_handler: &nettrap_proto_dns::handler::DnsHandler,
    packet: UdpPacket<'_>,
) {
    match dns_handler
        .handle_query(packet.query_data, *packet.src)
        .await
    {
        Ok(response) => {
            ctx.apply_response_delay().await;
            let sent = match socket.send_to(&response, *packet.src).await {
                Ok(sent) => {
                    ctx.write_pcap_response_udp_for_destination(
                        &response,
                        packet.src,
                        packet.destination,
                    );
                    sent
                }
                Err(e) => {
                    tracing::warn!("Failed to send UDP response to {}: {}", packet.src, e);
                    0
                }
            };
            ctx.update_session_bytes(
                packet.src,
                "UDP",
                packet.destination,
                packet.len as u64,
                sent as u64,
            );
            log_event(
                packet.output_path,
                ctx.name(),
                packet.src,
                "dns_query",
                &format!("{} bytes", packet.len),
            )
            .await;
            let nbi = crate::nbi::dns_nbi(
                ctx.name(),
                &packet.src.ip().to_string(),
                packet.src.port(),
                packet.destination,
                "",
                "query",
            );
            ctx.record_nbi(&nbi).await;
        }
        Err(e) => {
            tracing::warn!("UDP handler error from {}: {}", packet.src, e);
            ctx.update_session_bytes(packet.src, "UDP", packet.destination, packet.len as u64, 0);
        }
    }
}

struct UdpPacket<'a> {
    output_path: Option<&'a std::path::Path>,
    query_data: &'a [u8],
    src: &'a std::net::SocketAddr,
    destination: &'a SessionDestination,
    len: usize,
}

fn udp_listener_name_matches_protocol(listener_name: &str, protocol: &str) -> bool {
    let listener = listener_name.trim().to_ascii_lowercase();
    listener == protocol
        || listener
            .strip_prefix(protocol)
            .and_then(|suffix| suffix.as_bytes().first().copied())
            .is_some_and(|byte| matches!(byte, b'-' | b'_'))
}

fn explicit_udp_protocol_name(listener_name: &str) -> Option<&'static str> {
    [
        "dns",
        "tftp",
        "snmp",
        "sip",
        "upnp",
        "ntp",
        "coap",
        "quic",
        "daytime",
        "time",
        "chargen",
        "quotd",
        "syslogrecv",
        "raw",
    ]
    .into_iter()
    .find(|protocol| udp_listener_name_matches_protocol(listener_name, protocol))
}

async fn handle_explicit_udp_protocol(
    ctx: &ListenerContext,
    socket: &UdpSocket,
    dns_handler: &nettrap_proto_dns::handler::DnsHandler,
    tftp_handler: &nettrap_proto_tftp::TftpHandler,
    tftp_transfers: &TftpTransfers,
    packet: UdpPacket<'_>,
    protocol: &str,
) {
    match protocol {
        "dns" => handle_dns(ctx, socket, dns_handler, packet).await,
        "tftp" => handle_tftp(ctx, socket, tftp_handler, tftp_transfers, packet).await,
        "snmp" => {
            let response = nettrap_proto_snmp::SnmpHandler::new().handle(packet.query_data);
            crate::protocol_handlers::handle_udp_generic(
                ctx,
                socket,
                crate::protocol_handlers::UdpGenericResponse {
                    response: &response,
                    src: *packet.src,
                    destination: packet.destination,
                    len: packet.len,
                    output_path: packet.output_path,
                    protocol_name: "snmp",
                },
            )
            .await;
        }
        "sip" => {
            let response = nettrap_proto_sip::SipHandler::new().handle(packet.query_data);
            crate::protocol_handlers::handle_udp_generic(
                ctx,
                socket,
                crate::protocol_handlers::UdpGenericResponse {
                    response: &response,
                    src: *packet.src,
                    destination: packet.destination,
                    len: packet.len,
                    output_path: packet.output_path,
                    protocol_name: "sip",
                },
            )
            .await;
        }
        "upnp" => {
            let response = nettrap_proto_upnp::UpnpHandler::new()
                .with_listen_ip(packet.destination.ip.clone())
                .handle_ssdp(packet.query_data);
            crate::protocol_handlers::handle_udp_generic(
                ctx,
                socket,
                crate::protocol_handlers::UdpGenericResponse {
                    response: &response,
                    src: *packet.src,
                    destination: packet.destination,
                    len: packet.len,
                    output_path: packet.output_path,
                    protocol_name: "upnp",
                },
            )
            .await;
        }
        "ntp" => {
            let response = nettrap_proto_ntp::NtpHandler::new().handle(packet.query_data);
            crate::protocol_handlers::handle_udp_generic(
                ctx,
                socket,
                crate::protocol_handlers::UdpGenericResponse {
                    response: &response,
                    src: *packet.src,
                    destination: packet.destination,
                    len: packet.len,
                    output_path: packet.output_path,
                    protocol_name: "ntp",
                },
            )
            .await;
        }
        "coap" => {
            let response = nettrap_proto_coap::CoapHandler::new().handle(packet.query_data);
            crate::protocol_handlers::handle_udp_generic(
                ctx,
                socket,
                crate::protocol_handlers::UdpGenericResponse {
                    response: &response,
                    src: *packet.src,
                    destination: packet.destination,
                    len: packet.len,
                    output_path: packet.output_path,
                    protocol_name: "coap",
                },
            )
            .await;
        }
        "quic" => handle_quic_udp(ctx, packet).await,
        "daytime" => {
            let response = nettrap_proto_daytime::DaytimeHandler::new().handle();
            crate::protocol_handlers::handle_udp_generic(
                ctx,
                socket,
                crate::protocol_handlers::UdpGenericResponse {
                    response: response.as_bytes(),
                    src: *packet.src,
                    destination: packet.destination,
                    len: packet.len,
                    output_path: packet.output_path,
                    protocol_name: "daytime",
                },
            )
            .await;
        }
        "time" => {
            let response = nettrap_proto_time::TimeHandler::new().handle();
            crate::protocol_handlers::handle_udp_generic(
                ctx,
                socket,
                crate::protocol_handlers::UdpGenericResponse {
                    response: &response,
                    src: *packet.src,
                    destination: packet.destination,
                    len: packet.len,
                    output_path: packet.output_path,
                    protocol_name: "time",
                },
            )
            .await;
        }
        "chargen" => {
            let mut handler = nettrap_proto_chargen::ChargenHandler::new();
            let response = handler.handle_udp();
            crate::protocol_handlers::handle_udp_generic(
                ctx,
                socket,
                crate::protocol_handlers::UdpGenericResponse {
                    response: &response,
                    src: *packet.src,
                    destination: packet.destination,
                    len: packet.len,
                    output_path: packet.output_path,
                    protocol_name: "chargen",
                },
            )
            .await;
        }
        "quotd" => {
            let response = nettrap_proto_quotd::QuotdHandler::new().handle();
            crate::protocol_handlers::handle_udp_generic(
                ctx,
                socket,
                crate::protocol_handlers::UdpGenericResponse {
                    response: response.as_bytes(),
                    src: *packet.src,
                    destination: packet.destination,
                    len: packet.len,
                    output_path: packet.output_path,
                    protocol_name: "quotd",
                },
            )
            .await;
        }
        "syslogrecv" => handle_syslogrecv_udp(ctx, packet).await,
        "raw" => {
            let raw_handler = if let Some(custom) = ctx.custom_response() {
                nettrap_proto_raw::RawHandler::from_custom_response(custom)
            } else {
                nettrap_proto_raw::RawHandler::new()
            };
            let response = raw_handler.handle(packet.query_data).to_bytes();
            crate::protocol_handlers::handle_udp_generic(
                ctx,
                socket,
                crate::protocol_handlers::UdpGenericResponse {
                    response: &response,
                    src: *packet.src,
                    destination: packet.destination,
                    len: packet.len,
                    output_path: packet.output_path,
                    protocol_name: "raw",
                },
            )
            .await;
        }
        _ => {
            handle_detected_udp(
                ctx,
                socket,
                dns_handler,
                tftp_handler,
                tftp_transfers,
                packet,
            )
            .await
        }
    }
}

async fn handle_detected_udp(
    ctx: &ListenerContext,
    socket: &UdpSocket,
    dns_handler: &nettrap_proto_dns::handler::DnsHandler,
    tftp_handler: &nettrap_proto_tftp::TftpHandler,
    tftp_transfers: &TftpTransfers,
    packet: UdpPacket<'_>,
) {
    let detected = ctx
        .runtime
        .router
        .route_udp(packet.query_data, packet.destination.port);
    match detected {
        Some((ref name, score))
            if score >= 50
                || ctx.runtime.router.default_udp_handler() == Some(name.as_str())
                || name == "raw" =>
        {
            tracing::debug!(
                "taste() routed {} (score={}) from {} on UDP",
                name,
                score,
                packet.src
            );
            match name.as_str() {
                "dns" => {
                    handle_dns(ctx, socket, dns_handler, packet).await;
                }
                "tftp" => {
                    handle_tftp(ctx, socket, tftp_handler, tftp_transfers, packet).await;
                }
                "snmp" => {
                    let response = nettrap_proto_snmp::SnmpHandler::new().handle(packet.query_data);
                    crate::protocol_handlers::handle_udp_generic(
                        ctx,
                        socket,
                        crate::protocol_handlers::UdpGenericResponse {
                            response: &response,
                            src: *packet.src,
                            destination: packet.destination,
                            len: packet.len,
                            output_path: packet.output_path,
                            protocol_name: "snmp",
                        },
                    )
                    .await;
                }
                "sip" => {
                    let response = nettrap_proto_sip::SipHandler::new().handle(packet.query_data);
                    crate::protocol_handlers::handle_udp_generic(
                        ctx,
                        socket,
                        crate::protocol_handlers::UdpGenericResponse {
                            response: &response,
                            src: *packet.src,
                            destination: packet.destination,
                            len: packet.len,
                            output_path: packet.output_path,
                            protocol_name: "sip",
                        },
                    )
                    .await;
                }
                "upnp" => {
                    let response = nettrap_proto_upnp::UpnpHandler::new()
                        .with_listen_ip(packet.destination.ip.clone())
                        .handle_ssdp(packet.query_data);
                    crate::protocol_handlers::handle_udp_generic(
                        ctx,
                        socket,
                        crate::protocol_handlers::UdpGenericResponse {
                            response: &response,
                            src: *packet.src,
                            destination: packet.destination,
                            len: packet.len,
                            output_path: packet.output_path,
                            protocol_name: "upnp",
                        },
                    )
                    .await;
                }
                "ntp" => {
                    let response = nettrap_proto_ntp::NtpHandler::new().handle(packet.query_data);
                    crate::protocol_handlers::handle_udp_generic(
                        ctx,
                        socket,
                        crate::protocol_handlers::UdpGenericResponse {
                            response: &response,
                            src: *packet.src,
                            destination: packet.destination,
                            len: packet.len,
                            output_path: packet.output_path,
                            protocol_name: "ntp",
                        },
                    )
                    .await;
                }
                "coap" => {
                    let response = nettrap_proto_coap::CoapHandler::new().handle(packet.query_data);
                    crate::protocol_handlers::handle_udp_generic(
                        ctx,
                        socket,
                        crate::protocol_handlers::UdpGenericResponse {
                            response: &response,
                            src: *packet.src,
                            destination: packet.destination,
                            len: packet.len,
                            output_path: packet.output_path,
                            protocol_name: "coap",
                        },
                    )
                    .await;
                }
                "daytime" => {
                    let response = nettrap_proto_daytime::DaytimeHandler::new().handle();
                    crate::protocol_handlers::handle_udp_generic(
                        ctx,
                        socket,
                        crate::protocol_handlers::UdpGenericResponse {
                            response: response.as_bytes(),
                            src: *packet.src,
                            destination: packet.destination,
                            len: packet.len,
                            output_path: packet.output_path,
                            protocol_name: "daytime",
                        },
                    )
                    .await;
                }
                "time" => {
                    let response = nettrap_proto_time::TimeHandler::new().handle();
                    crate::protocol_handlers::handle_udp_generic(
                        ctx,
                        socket,
                        crate::protocol_handlers::UdpGenericResponse {
                            response: &response,
                            src: *packet.src,
                            destination: packet.destination,
                            len: packet.len,
                            output_path: packet.output_path,
                            protocol_name: "time",
                        },
                    )
                    .await;
                }
                "chargen" => {
                    let mut handler = nettrap_proto_chargen::ChargenHandler::new();
                    let response = handler.handle_udp();
                    crate::protocol_handlers::handle_udp_generic(
                        ctx,
                        socket,
                        crate::protocol_handlers::UdpGenericResponse {
                            response: &response,
                            src: *packet.src,
                            destination: packet.destination,
                            len: packet.len,
                            output_path: packet.output_path,
                            protocol_name: "chargen",
                        },
                    )
                    .await;
                }
                "quotd" => {
                    let response = nettrap_proto_quotd::QuotdHandler::new().handle();
                    crate::protocol_handlers::handle_udp_generic(
                        ctx,
                        socket,
                        crate::protocol_handlers::UdpGenericResponse {
                            response: response.as_bytes(),
                            src: *packet.src,
                            destination: packet.destination,
                            len: packet.len,
                            output_path: packet.output_path,
                            protocol_name: "quotd",
                        },
                    )
                    .await;
                }
                "syslogrecv" => {
                    handle_syslogrecv_udp(ctx, packet).await;
                }
                "raw" => {
                    let raw_handler = if let Some(custom) = ctx.custom_response() {
                        nettrap_proto_raw::RawHandler::from_custom_response(custom)
                    } else {
                        nettrap_proto_raw::RawHandler::new()
                    };
                    let response = raw_handler.handle(packet.query_data).to_bytes();
                    crate::protocol_handlers::handle_udp_generic(
                        ctx,
                        socket,
                        crate::protocol_handlers::UdpGenericResponse {
                            response: &response,
                            src: *packet.src,
                            destination: packet.destination,
                            len: packet.len,
                            output_path: packet.output_path,
                            protocol_name: "raw",
                        },
                    )
                    .await;
                }
                "quic" => {
                    handle_quic_udp(ctx, packet).await;
                }
                _ => {
                    log_event(
                        packet.output_path,
                        ctx.name(),
                        packet.src,
                        "udp_unknown",
                        &format!("{} bytes, detected={}", packet.len, name),
                    )
                    .await;
                    let nbi = crate::nbi::raw_nbi(
                        ctx.name(),
                        &packet.src.ip().to_string(),
                        packet.src.port(),
                        packet.destination,
                        packet.len,
                        "",
                    );
                    ctx.record_nbi(&nbi).await;
                    ctx.apply_response_delay().await;
                    ctx.write_pcap_response_udp_for_destination(
                        b"OK\n",
                        packet.src,
                        packet.destination,
                    );
                    let _ = socket.send_to(b"OK\n", *packet.src).await;
                }
            }
        }
        _ => {
            tracing::debug!(
                "UDP '{}' unclassified {} bytes from {} (no protocol match)",
                ctx.name(),
                packet.len,
                packet.src
            );
            log_event(
                packet.output_path,
                ctx.name(),
                packet.src,
                "udp_unclassified",
                &format!("{} bytes", packet.len),
            )
            .await;
            let nbi = crate::nbi::raw_nbi(
                ctx.name(),
                &packet.src.ip().to_string(),
                packet.src.port(),
                packet.destination,
                packet.len,
                "unknown",
            );
            ctx.record_nbi(&nbi).await;
            ctx.update_session_bytes(packet.src, "UDP", packet.destination, packet.len as u64, 0);
        }
    }
}

async fn handle_syslogrecv_udp(ctx: &ListenerContext, packet: UdpPacket<'_>) {
    let parsed = nettrap_proto_syslogrecv::SyslogRecvHandler::new().handle(packet.query_data);
    let detail = parsed.as_ref().map_or_else(
        || format!("{} bytes, invalid", packet.len),
        |message| {
            format!(
                "{} bytes, facility={}, severity={}",
                packet.len, message.facility_name, message.severity_name
            )
        },
    );
    log_event(
        packet.output_path,
        ctx.name(),
        packet.src,
        "syslogrecv_message",
        &detail,
    )
    .await;

    let mut nbi = crate::nbi::raw_nbi(
        ctx.name(),
        &packet.src.ip().to_string(),
        packet.src.port(),
        packet.destination,
        packet.len,
        "syslogrecv",
    );
    if let Some(message) = parsed {
        nbi.add("facility", message.facility_name);
        nbi.add("severity", message.severity_name);
    }
    ctx.record_nbi(&nbi).await;
    ctx.update_session_bytes(packet.src, "UDP", packet.destination, packet.len as u64, 0);
}

async fn handle_quic_udp(ctx: &ListenerContext, packet: UdpPacket<'_>) {
    let handler = nettrap_proto_quic::QuicHandler::new();
    let sni = handler.extract_sni(packet.query_data);
    let detail = match sni.as_deref() {
        Some(sni) => format!("{} bytes, sni={}", packet.len, sni),
        None => format!("{} bytes", packet.len),
    };
    log_event(
        packet.output_path,
        ctx.name(),
        packet.src,
        "quic_packet",
        &detail,
    )
    .await;

    let mut nbi = crate::nbi::NetworkBehaviorIndicator::new(
        ctx.name(),
        "QUIC",
        &packet.src.ip().to_string(),
        packet.src.port(),
        packet.destination,
    );
    nbi.add("data_length", packet.len.to_string());
    if let Some(sni) = sni {
        nbi.add("sni", sni);
    }
    ctx.record_nbi(&nbi).await;
    ctx.update_session_bytes(packet.src, "UDP", packet.destination, packet.len as u64, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener_context::ListenerContext;
    use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
    use crate::process_filter::ProcessFilter;
    use crate::session::{PortForwardTable, SessionTracker};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_udp_sockaddr_in_original_destination_preserves_ip_and_port() {
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 5353u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_be_bytes([198, 51, 100, 7]).to_be(),
            },
            sin_zero: [0; 8],
        };

        assert_eq!(
            session_destination_from_sockaddr_in(addr),
            SessionDestination::new("198.51.100.7", 5353)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_udp_sockaddr_in6_original_destination_preserves_ip_and_port() {
        let addr = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: 5353u16.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
            },
            sin6_scope_id: 0,
        };

        assert_eq!(
            session_destination_from_sockaddr_in6(addr),
            SessionDestination::new("2001:db8::7", 5353)
        );
    }

    #[test]
    fn attributed_udp_process_is_recorded_and_filtered() {
        let tracker = Arc::new(SessionTracker::new());
        let ctx = ListenerContext::builder().name("dns").port(53).build(
            ListenerSecurity::new(
                ProcessFilter::build(
                    Vec::new(),
                    Vec::new(),
                    vec!["allowed.exe".into()],
                    Vec::new(),
                ),
                Vec::new(),
                Vec::new(),
            )
            .expect("host rules should compile"),
            ListenerRuntime::new(ListenerRuntimeResources {
                ca: None,
                router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                attribution: None,
                attribution_timeout: std::time::Duration::from_millis(5000),
                pcap_writer: None,
                nbi_collector: Arc::new(crate::nbi::NbiCollector::new(None)),
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::new(PortForwardTable::new()),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        );
        let src: std::net::SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let attr = nettrap_core::prelude::Attribution::new(
            nettrap_core::prelude::ProcessInfo::new(4242, "allowed.exe"),
            nettrap_core::prelude::AttributionConfidence::High,
            nettrap_core::prelude::AttributionMethod::SocketTable,
        );

        let destination = SessionDestination::unknown(53);
        tracker.register(&src, &destination, "dns", "UDP");

        assert!(apply_attributed_process_filter(
            &ctx,
            &src,
            &destination,
            &attr
        ));
        assert_eq!(
            tracker.get_process(&src, "UDP", &destination),
            Some((Some("allowed.exe".to_string()), Some(4242)))
        );
    }

    #[test]
    fn blocked_udp_process_keeps_session_visible_until_ttl() {
        let tracker = Arc::new(SessionTracker::new());
        let ctx = ListenerContext::builder().name("dns").port(53).build(
            ListenerSecurity::new(
                ProcessFilter::build(
                    Vec::new(),
                    Vec::new(),
                    vec!["allowed.exe".into()],
                    Vec::new(),
                ),
                Vec::new(),
                Vec::new(),
            )
            .expect("host rules should compile"),
            ListenerRuntime::new(ListenerRuntimeResources {
                ca: None,
                router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                attribution: None,
                attribution_timeout: std::time::Duration::from_millis(5000),
                pcap_writer: None,
                nbi_collector: Arc::new(crate::nbi::NbiCollector::new(None)),
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::new(PortForwardTable::new()),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        );
        let src: std::net::SocketAddr = "127.0.0.1:53001".parse().unwrap();
        let attr = nettrap_core::prelude::Attribution::new(
            nettrap_core::prelude::ProcessInfo::new(4243, "blocked.exe"),
            nettrap_core::prelude::AttributionConfidence::High,
            nettrap_core::prelude::AttributionMethod::SocketTable,
        );

        let destination = SessionDestination::unknown(53);
        tracker.register(&src, &destination, "dns", "UDP");

        assert!(!apply_attributed_process_filter(
            &ctx,
            &src,
            &destination,
            &attr
        ));
        assert_eq!(tracker.active_count(), 1);
        assert_eq!(
            tracker.get_process(&src, "UDP", &destination),
            Some((Some("blocked.exe".to_string()), Some(4243)))
        );
    }

    #[test]
    fn direct_destination_uses_explicit_bind_when_socket_addr_is_unspecified() {
        let local_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
        let bind_addr: IpAddr = "192.168.10.25".parse().unwrap();

        let destination = direct_destination_from_local_addr(local_addr, bind_addr);

        assert_eq!(destination, SessionDestination::new("192.168.10.25", 5353));
    }

    #[test]
    fn tftp_data_without_write_state_returns_unknown_transfer() {
        let mut transfers = HashMap::new();
        let destination = SessionDestination::new("127.0.0.1", 69);
        let src: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let key = TftpTransferKey::new(src, &destination);

        let responses = handle_tftp_write_data(
            &mut transfers,
            &key,
            &nettrap_proto_tftp::TftpHandler::new(),
            1,
            b"data",
        );

        assert!(matches!(
            responses.as_slice(),
            [nettrap_proto_tftp::TftpPacket::Error { code: 5, .. }]
        ));
    }

    #[test]
    fn tftp_write_state_accepts_expected_final_block_and_keeps_ack_for_retransmit() {
        let mut transfers = HashMap::new();
        let destination = SessionDestination::new("127.0.0.1", 69);
        let src: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let key = TftpTransferKey::new(src, &destination);
        transfers.insert(
            key.clone(),
            TftpTransferState::Write {
                filename: "upload.bin".to_string(),
                next_block_expected: 1,
                bytes_received: 0,
                last_ack: nettrap_proto_tftp::TftpPacket::Ack { block: 0 },
                complete: false,
                last_activity: Instant::now(),
            },
        );

        let responses = handle_tftp_write_data(
            &mut transfers,
            &key,
            &nettrap_proto_tftp::TftpHandler::new(),
            1,
            b"final",
        );

        assert!(matches!(
            responses.as_slice(),
            [nettrap_proto_tftp::TftpPacket::Ack { block: 1 }]
        ));
        assert!(transfers.contains_key(&key));

        let duplicate = handle_tftp_write_data(
            &mut transfers,
            &key,
            &nettrap_proto_tftp::TftpHandler::new(),
            1,
            b"final",
        );
        assert!(matches!(
            duplicate.as_slice(),
            [nettrap_proto_tftp::TftpPacket::Ack { block: 1 }]
        ));
    }

    #[test]
    fn tftp_read_ack_uses_active_read_filename() {
        let mut transfers = HashMap::new();
        let destination = SessionDestination::new("127.0.0.1", 69);
        let src: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let key = TftpTransferKey::new(src, &destination);
        transfers.insert(
            key.clone(),
            TftpTransferState::Read {
                filename: "first.bin".to_string(),
                last_block_sent: 1,
                last_response: nettrap_proto_tftp::TftpPacket::Data {
                    block: 1,
                    data: vec![b'x'; nettrap_proto_tftp::TFTP_BLOCK_SIZE],
                },
                complete: false,
                last_activity: Instant::now(),
            },
        );

        assert!(transfers.contains_key(&key));
        match next_tftp_read_action(&mut transfers, &key, 1) {
            Some(TftpReadAckAction::SendNext {
                filename,
                next_block,
            }) => {
                assert_eq!(filename, "first.bin");
                assert_eq!(next_block, 2);
            }
            other => panic!("expected next read block, got {other:?}"),
        }
        assert!(matches!(
            next_tftp_read_action(&mut transfers, &key, 0),
            Some(TftpReadAckAction::Retransmit(
                nettrap_proto_tftp::TftpPacket::Data { block: 1, .. }
            ))
        ));
    }

    #[test]
    fn tftp_duplicate_requests_retransmit_matching_state() {
        let mut transfers = HashMap::new();
        let destination = SessionDestination::new("127.0.0.1", 69);
        let src: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let key = TftpTransferKey::new(src, &destination);
        transfers.insert(
            key.clone(),
            TftpTransferState::Read {
                filename: "first.bin".to_string(),
                last_block_sent: 1,
                last_response: nettrap_proto_tftp::TftpPacket::Data {
                    block: 1,
                    data: b"hello".to_vec(),
                },
                complete: true,
                last_activity: Instant::now(),
            },
        );

        assert!(matches!(
            duplicate_tftp_read_request_response(&mut transfers, &key, "first.bin"),
            Some(nettrap_proto_tftp::TftpPacket::Data { block: 1, .. })
        ));
        assert!(matches!(
            duplicate_tftp_read_request_response(&mut transfers, &key, "other.bin"),
            Some(nettrap_proto_tftp::TftpPacket::Error { code: 4, .. })
        ));
    }

    #[test]
    fn tftp_transfer_limit_rejects_new_keys_but_allows_existing_key() {
        let mut transfers = HashMap::new();
        let destination = SessionDestination::new("127.0.0.1", 69);

        for i in 0..MAX_TFTP_ACTIVE_TRANSFERS {
            let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40000 + i as u16);
            transfers.insert(
                TftpTransferKey::new(src, &destination),
                TftpTransferState::Read {
                    filename: format!("file-{i}.bin"),
                    last_block_sent: 1,
                    last_response: nettrap_proto_tftp::TftpPacket::Data {
                        block: 1,
                        data: vec![b'x'; nettrap_proto_tftp::TFTP_BLOCK_SIZE],
                    },
                    complete: false,
                    last_activity: Instant::now(),
                },
            );
        }

        let existing = TftpTransferKey::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40000),
            &destination,
        );
        let new_key = TftpTransferKey::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53000),
            &destination,
        );

        assert!(!tftp_transfer_limit_reached(&transfers, &existing));
        assert!(tftp_transfer_limit_reached(&transfers, &new_key));
    }

    #[test]
    fn tftp_transfer_prune_releases_capacity() {
        let mut transfers = HashMap::new();
        let destination = SessionDestination::new("127.0.0.1", 69);
        let expired = Instant::now() - TFTP_TRANSFER_TIMEOUT - Duration::from_secs(1);
        let key = TftpTransferKey::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53000),
            &destination,
        );
        transfers.insert(
            key,
            TftpTransferState::Write {
                filename: "upload.bin".to_string(),
                next_block_expected: 1,
                bytes_received: 0,
                last_ack: nettrap_proto_tftp::TftpPacket::Ack { block: 0 },
                complete: false,
                last_activity: expired,
            },
        );

        prune_tftp_transfers(&mut transfers);

        assert!(transfers.is_empty());
    }

    fn udp_test_context(
        listener_port: u16,
        router: Arc<nettrap_proxy::ProtocolRouter>,
        custom_response: Option<String>,
    ) -> ListenerContext {
        udp_test_context_named("raw", listener_port, router, custom_response)
    }

    fn udp_test_context_named(
        name: &str,
        listener_port: u16,
        router: Arc<nettrap_proxy::ProtocolRouter>,
        custom_response: Option<String>,
    ) -> ListenerContext {
        ListenerContext::builder()
            .name(name)
            .port(listener_port)
            .custom_response(custom_response)
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router,
                    attribution: None,
                    attribution_timeout: std::time::Duration::from_millis(5000),
                    pcap_writer: None,
                    nbi_collector: Arc::new(crate::nbi::NbiCollector::new(None)),
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
    }

    fn dns_query_bytes() -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&0x1234u16.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.push(7);
        query.extend_from_slice(b"example");
        query.push(3);
        query.extend_from_slice(b"com");
        query.push(0);
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query
    }

    fn flow_bytes(
        ctx: &ListenerContext,
        src: SocketAddr,
        destination: &SessionDestination,
    ) -> (u64, u64) {
        let five_tuple = nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            destination
                .ip
                .parse()
                .expect("test destination should be an IP"),
            src.port(),
            destination.port,
            nettrap_core::prelude::Protocol::Udp,
        );
        let key = nettrap_core::prelude::FlowKey::from_five_tuple(&five_tuple);
        let flow = ctx
            .runtime
            .flow_manager
            .get(&key)
            .expect("flow should exist");
        (flow.metadata.bytes_received, flow.metadata.bytes_sent)
    }

    #[test]
    fn explicit_udp_protocol_names_require_exact_or_separator_match() {
        assert_eq!(explicit_udp_protocol_name("daytime-alt"), Some("daytime"));
        assert_eq!(explicit_udp_protocol_name("time_37"), Some("time"));
        assert_eq!(explicit_udp_protocol_name("timeout"), None);
        assert_eq!(explicit_udp_protocol_name("raw"), Some("raw"));
    }

    #[tokio::test]
    async fn udp_raw_uses_custom_response() {
        let bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .expect("bind UDP listener socket");
        let listener_port = socket.local_addr().expect("listener addr").port();
        let receiver = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .expect("bind UDP receiver");
        let src = receiver.local_addr().expect("receiver addr");
        let router = Arc::new(nettrap_proxy::ProtocolRouter::new());
        router.register("raw", Box::new(nettrap_proxy::RawTaste), false);
        let ctx = udp_test_context(listener_port, router, Some("static:pong".to_string()));
        let destination = SessionDestination::new(bind_ip.to_string(), listener_port);
        let transfers = Arc::new(Mutex::new(HashMap::new()));

        handle_detected_udp(
            &ctx,
            &socket,
            &nettrap_proto_dns::handler::DnsHandler::new(),
            &nettrap_proto_tftp::TftpHandler::new(),
            &transfers,
            UdpPacket {
                output_path: None,
                query_data: b"ping",
                src: &src,
                destination: &destination,
                len: 4,
            },
        )
        .await;

        let mut buf = [0u8; 16];
        let (len, peer) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("raw response timed out")
        .expect("receive raw response");
        assert_eq!(&buf[..len], b"pong");
        assert_eq!(peer, socket.local_addr().expect("listener addr"));
    }

    #[tokio::test]
    async fn udp_raw_silent_custom_response_sends_no_datagram() {
        let bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .expect("bind UDP listener socket");
        let listener_port = socket.local_addr().expect("listener addr").port();
        let receiver = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .expect("bind UDP receiver");
        let src = receiver.local_addr().expect("receiver addr");
        let router = Arc::new(nettrap_proxy::ProtocolRouter::new());
        router.register("raw", Box::new(nettrap_proxy::RawTaste), false);
        let ctx = udp_test_context(listener_port, router, Some("silent".to_string()));
        let destination = SessionDestination::new(bind_ip.to_string(), listener_port);
        let transfers = Arc::new(Mutex::new(HashMap::new()));

        handle_detected_udp(
            &ctx,
            &socket,
            &nettrap_proto_dns::handler::DnsHandler::new(),
            &nettrap_proto_tftp::TftpHandler::new(),
            &transfers,
            UdpPacket {
                output_path: None,
                query_data: b"ping",
                src: &src,
                destination: &destination,
                len: 4,
            },
        )
        .await;

        let mut buf = [0u8; 16];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            receiver.recv_from(&mut buf),
        )
        .await;
        assert!(result.is_err(), "silent raw response should not send data");
    }

    #[tokio::test]
    async fn dns_handler_records_received_bytes_on_parse_error() {
        let bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .expect("bind UDP listener socket");
        let listener_port = socket.local_addr().expect("listener addr").port();
        let router = Arc::new(nettrap_proxy::ProtocolRouter::new());
        let ctx = udp_test_context_named("dns", listener_port, router, None);
        let src = SocketAddr::new(bind_ip, 53000);
        let destination = SessionDestination::new(bind_ip.to_string(), listener_port);
        ctx.register_session(&src, "UDP", Some(destination.clone()));

        handle_dns(
            &ctx,
            &socket,
            &nettrap_proto_dns::handler::DnsHandler::new(),
            UdpPacket {
                output_path: None,
                query_data: b"\x00",
                src: &src,
                destination: &destination,
                len: 1,
            },
        )
        .await;

        assert_eq!(flow_bytes(&ctx, src, &destination), (1, 0));
    }

    #[tokio::test]
    async fn dns_handler_records_zero_sent_bytes_when_send_fails() {
        let bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .expect("bind UDP listener socket");
        let listener_port = socket.local_addr().expect("listener addr").port();
        let router = Arc::new(nettrap_proxy::ProtocolRouter::new());
        let ctx = udp_test_context_named("dns", listener_port, router, None);
        let src = "[::1]:53000".parse::<SocketAddr>().expect("IPv6 source");
        let destination = SessionDestination::new(bind_ip.to_string(), listener_port);
        ctx.register_session(&src, "UDP", Some(destination.clone()));
        let query = dns_query_bytes();

        handle_dns(
            &ctx,
            &socket,
            &nettrap_proto_dns::handler::DnsHandler::new(),
            UdpPacket {
                output_path: None,
                query_data: &query,
                src: &src,
                destination: &destination,
                len: query.len(),
            },
        )
        .await;

        assert_eq!(flow_bytes(&ctx, src, &destination), (query.len() as u64, 0));
    }

    #[tokio::test]
    async fn explicit_udp_daytime_responds_on_custom_port_without_router_taste() {
        let bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .expect("bind UDP listener socket");
        let listener_port = socket.local_addr().expect("listener addr").port();
        let receiver = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .expect("bind UDP receiver");
        let src = receiver.local_addr().expect("receiver addr");
        let router = Arc::new(nettrap_proxy::ProtocolRouter::new());
        let ctx = udp_test_context_named("daytime-custom", listener_port, router, None);
        let destination = SessionDestination::new(bind_ip.to_string(), listener_port);
        let transfers = Arc::new(Mutex::new(HashMap::new()));
        let protocol = explicit_udp_protocol_name(ctx.name()).expect("explicit UDP protocol");

        handle_explicit_udp_protocol(
            &ctx,
            &socket,
            &nettrap_proto_dns::handler::DnsHandler::new(),
            &nettrap_proto_tftp::TftpHandler::new(),
            &transfers,
            UdpPacket {
                output_path: None,
                query_data: b"",
                src: &src,
                destination: &destination,
                len: 0,
            },
            protocol,
        )
        .await;

        let mut buf = [0u8; 128];
        let (len, peer) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("daytime response timed out")
        .expect("receive daytime response");
        assert!(len > 0);
        assert_eq!(peer, socket.local_addr().expect("listener addr"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recv_udp_packet_resolves_wildcard_destination_ip() {
        let bind_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let socket = UdpSocket::bind(SocketAddr::new(bind_addr, 0))
            .await
            .expect("bind wildcard UDP socket");
        configure_udp_destination_capture(&socket, bind_addr)
            .expect("enable UDP destination capture");

        let listener_port = socket.local_addr().expect("listener addr").port();
        let sender = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind sender");
        sender
            .send_to(
                b"ping",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listener_port),
            )
            .await
            .expect("send UDP datagram");

        let mut buf = [0u8; 32];
        let capture = configure_udp_destination_capture(&socket, bind_addr)
            .expect("enable UDP destination capture");
        let (len, src, destination) = recv_udp_packet(&socket, &capture, &mut buf, listener_port)
            .await
            .expect("recv UDP datagram with destination");

        assert_eq!(&buf[..len], b"ping");
        assert_eq!(src.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            destination,
            Some(SessionDestination::new(
                Ipv4Addr::LOCALHOST.to_string(),
                listener_port
            ))
        );
    }

    #[tokio::test]
    async fn udp_listener_keeps_session_and_flow_alive_after_single_datagram() {
        let tracker = Arc::new(SessionTracker::new());
        let flow_manager = Arc::new(nettrap_flow::FlowManager::default());
        let port_forward_table = Arc::new(PortForwardTable::new());
        let bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .expect("bind UDP listener socket");
        let listener_port = socket.local_addr().expect("listener addr").port();

        let ctx = ListenerContext::builder()
            .name("raw")
            .port(listener_port)
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    attribution: None,
                    attribution_timeout: std::time::Duration::from_millis(5000),
                    pcap_writer: None,
                    nbi_collector: Arc::new(crate::nbi::NbiCollector::new(None)),
                    session_tracker: Arc::clone(&tracker),
                    port_forward_table: Arc::clone(&port_forward_table),
                    flow_manager: Arc::clone(&flow_manager),
                }),
            );

        let listener =
            tokio::spawn(async move { run_udp_listener(ctx, socket, bind_ip, None).await });
        let sender = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .expect("bind sender");
        let src = sender.local_addr().expect("sender addr");
        sender
            .send_to(b"hello", SocketAddr::new(bind_ip, listener_port))
            .await
            .expect("send UDP datagram");

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let destination = SessionDestination::new(bind_ip.to_string(), listener_port);
        let flow_key = nettrap_core::prelude::FlowKey::from_five_tuple(
            &nettrap_core::prelude::FiveTuple::new(
                src.ip(),
                bind_ip,
                src.port(),
                listener_port,
                nettrap_core::prelude::Protocol::Udp,
            ),
        );

        assert_eq!(tracker.active_count(), 1);
        assert_eq!(
            tracker.get_destination_for_port(&src, "UDP", listener_port),
            Some(destination)
        );
        assert!(flow_manager.get(&flow_key).is_some());

        listener.abort();
        let _ = listener.await;
    }
}
