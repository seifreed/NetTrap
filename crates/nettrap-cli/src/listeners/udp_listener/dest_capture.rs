//! Low-level OS-socket UDP destination-capture infrastructure.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::UdpSocket;

use crate::session::SessionDestination;
use crate::session::is_usable_session_destination_ip;
use crate::session::normalize_session_ip;

#[cfg(not(target_os = "windows"))]
#[derive(Clone, Copy, Default)]
pub(crate) struct UdpDestinationCapture;

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Default)]
pub(crate) struct UdpDestinationCapture {
    recv_msg: windows::Win32::Networking::WinSock::LPFN_WSARECVMSG,
}

pub(crate) fn direct_destination_from_local_addr(
    local_addr: SocketAddr,
    bind_addr: IpAddr,
) -> SessionDestination {
    let ip = if local_addr.ip().is_unspecified() && !bind_addr.is_unspecified() {
        bind_addr
    } else {
        local_addr.ip()
    };
    SessionDestination::new_unchecked(normalize_session_ip(ip).to_string(), local_addr.port())
}

#[cfg(any(target_os = "windows", test))]
fn wsabuf_len(len: usize) -> io::Result<u32> {
    u32::try_from(len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("WSABUF length exceeds u32::MAX ({len} bytes)"),
        )
    })
}

#[cfg(unix)]
pub(crate) fn configure_udp_destination_capture(
    socket: &UdpSocket,
    bind_addr: IpAddr,
) -> io::Result<UdpDestinationCapture> {
    use std::mem::size_of_val;
    use std::os::fd::AsRawFd;

    let fd = socket.as_raw_fd();
    let enabled: libc::c_int = 1;
    let enabled_ptr = (&enabled as *const libc::c_int).cast::<libc::c_void>();
    let enabled_len = libc::socklen_t::try_from(size_of_val(&enabled))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket option too large"))?;

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
pub(crate) fn max_cmsg_space() -> usize {
    let ipv4_pktinfo = cmsg_space(std::mem::size_of::<libc::in_pktinfo>()).unwrap_or(0);
    let ipv6_pktinfo = cmsg_space(std::mem::size_of::<libc::in6_pktinfo>()).unwrap_or(0);
    #[cfg(target_os = "linux")]
    {
        let ipv4_original = cmsg_space(std::mem::size_of::<libc::sockaddr_in>()).unwrap_or(0);
        let ipv6_original = cmsg_space(std::mem::size_of::<libc::sockaddr_in6>()).unwrap_or(0);
        (ipv4_pktinfo + ipv4_original).max(ipv6_pktinfo + ipv6_original)
    }
    #[cfg(not(target_os = "linux"))]
    {
        ipv4_pktinfo.max(ipv6_pktinfo)
    }
}

#[cfg(unix)]
pub(crate) fn parse_ipv4(s_addr: libc::in_addr) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(u32::from_be(s_addr.s_addr)))
}

#[cfg(unix)]
pub(crate) fn parse_ipv6(s_addr: libc::in6_addr) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(s_addr.s6_addr))
}

#[cfg(unix)]
pub(crate) unsafe fn socket_addr_from_storage(
    storage: &libc::sockaddr_storage,
) -> io::Result<SocketAddr> {
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
fn cmsg_space(payload_len: usize) -> Option<usize> {
    let payload_len = libc::c_uint::try_from(payload_len).ok()?;
    let space = unsafe { libc::CMSG_SPACE(payload_len) };
    usize::try_from(space).ok()
}

#[cfg(unix)]
fn cmsg_len(payload_len: usize) -> Option<usize> {
    let payload_len = libc::c_uint::try_from(payload_len).ok()?;
    let len = unsafe { libc::CMSG_LEN(payload_len) };
    usize::try_from(len).ok()
}

#[cfg(unix)]
fn cmsg_payload_fits(
    message: &libc::msghdr,
    cmsg: *const libc::cmsghdr,
    payload_len: usize,
) -> bool {
    if message.msg_control.is_null() || cmsg.is_null() {
        return false;
    }

    let header = unsafe { read_cmsghdr(cmsg) };
    #[cfg(target_os = "linux")]
    let header_len = header.cmsg_len;
    #[cfg(not(target_os = "linux"))]
    let Ok(header_len) = usize::try_from(header.cmsg_len) else {
        return false;
    };
    #[cfg(target_os = "linux")]
    let msg_controllen = message.msg_controllen;
    #[cfg(not(target_os = "linux"))]
    let Ok(msg_controllen) = usize::try_from(message.msg_controllen) else {
        return false;
    };
    let Some(needed) = cmsg_len(payload_len) else {
        return false;
    };
    if header_len < needed {
        return false;
    }

    let control_start = message.msg_control as usize;
    let Some(control_end) = control_start.checked_add(msg_controllen) else {
        return false;
    };
    let cmsg_start = cmsg as usize;
    if cmsg_start < control_start {
        return false;
    }

    cmsg_start
        .checked_add(header_len)
        .is_some_and(|cmsg_end| cmsg_end <= control_end)
}

#[cfg(unix)]
unsafe fn read_cmsghdr(cmsg: *const libc::cmsghdr) -> libc::cmsghdr {
    unsafe { std::ptr::read_unaligned(cmsg) }
}

#[cfg(unix)]
unsafe fn read_cmsg_payload<T: Copy>(cmsg: *const libc::cmsghdr) -> T {
    unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(cmsg as *mut libc::cmsghdr).cast::<T>()) }
}

#[cfg(unix)]
pub(crate) fn destination_ip_from_control_message(message: &libc::msghdr) -> Option<IpAddr> {
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(message);
        while !cmsg.is_null() {
            let header = read_cmsghdr(cmsg);
            if header.cmsg_level == libc::IPPROTO_IP {
                #[cfg(target_os = "linux")]
                if header.cmsg_type == libc::IP_PKTINFO {
                    if !cmsg_payload_fits(message, cmsg, std::mem::size_of::<libc::in_pktinfo>()) {
                        return None;
                    }
                    let pktinfo = read_cmsg_payload::<libc::in_pktinfo>(cmsg);
                    return Some(parse_ipv4(pktinfo.ipi_addr));
                }

                #[cfg(not(target_os = "linux"))]
                if header.cmsg_type == libc::IP_RECVDSTADDR {
                    if !cmsg_payload_fits(message, cmsg, std::mem::size_of::<libc::in_addr>()) {
                        return None;
                    }
                    let addr = read_cmsg_payload::<libc::in_addr>(cmsg);
                    return Some(parse_ipv4(addr));
                }
            }

            if header.cmsg_level == libc::IPPROTO_IPV6 && header.cmsg_type == libc::IPV6_PKTINFO {
                if !cmsg_payload_fits(message, cmsg, std::mem::size_of::<libc::in6_pktinfo>()) {
                    return None;
                }
                let pktinfo = read_cmsg_payload::<libc::in6_pktinfo>(cmsg);
                return Some(parse_ipv6(pktinfo.ipi6_addr));
            }

            cmsg = libc::CMSG_NXTHDR(message, cmsg);
        }
    }

    None
}

#[cfg(target_os = "linux")]
pub(crate) fn original_destination_from_control_message(
    message: &libc::msghdr,
) -> Option<SessionDestination> {
    const IP_ORIGDSTADDR: libc::c_int = 20;
    const IPV6_ORIGDSTADDR: libc::c_int = 74;

    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(message);
        while !cmsg.is_null() {
            let header = read_cmsghdr(cmsg);
            if header.cmsg_level == libc::IPPROTO_IP && header.cmsg_type == IP_ORIGDSTADDR {
                if !cmsg_payload_fits(message, cmsg, std::mem::size_of::<libc::sockaddr_in>()) {
                    return None;
                }
                let addr = read_cmsg_payload::<libc::sockaddr_in>(cmsg);
                if let Some(destination) = session_destination_from_sockaddr_in(addr) {
                    return Some(destination);
                }
            }

            if header.cmsg_level == libc::IPPROTO_IPV6 && header.cmsg_type == IPV6_ORIGDSTADDR {
                if !cmsg_payload_fits(message, cmsg, std::mem::size_of::<libc::sockaddr_in6>()) {
                    return None;
                }
                let addr = read_cmsg_payload::<libc::sockaddr_in6>(cmsg);
                if let Some(destination) = session_destination_from_sockaddr_in6(addr) {
                    return Some(destination);
                }
            }

            cmsg = libc::CMSG_NXTHDR(message, cmsg);
        }
    }

    None
}

#[cfg(not(target_os = "linux"))]
#[cfg(unix)]
pub(crate) fn original_destination_from_control_message(
    _message: &libc::msghdr,
) -> Option<SessionDestination> {
    None
}

#[cfg(target_os = "linux")]
pub(crate) fn session_destination_from_sockaddr_in(
    addr: libc::sockaddr_in,
) -> Option<SessionDestination> {
    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    if port == 0 || !is_usable_session_destination_ip(std::net::IpAddr::V4(ip)) {
        return None;
    }

    Some(SessionDestination::new_unchecked(ip.to_string(), port))
}

#[cfg(target_os = "linux")]
pub(crate) fn session_destination_from_sockaddr_in6(
    addr: libc::sockaddr_in6,
) -> Option<SessionDestination> {
    let ip = normalize_session_ip(IpAddr::V6(std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr)));
    let port = u16::from_be(addr.sin6_port);
    if port == 0 || !is_usable_session_destination_ip(ip) {
        return None;
    }

    Some(SessionDestination::new_unchecked(ip.to_string(), port))
}

#[cfg(unix)]
pub(crate) fn recv_from_with_destination_now(
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
    message.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket address too large"))?;
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
        destination_ip_from_control_message(&message).and_then(|ip| {
            if is_usable_session_destination_ip(ip) {
                Some(SessionDestination::new_unchecked(
                    ip.to_string(),
                    listener_port,
                ))
            } else {
                None
            }
        })
    });

    let received = usize::try_from(received)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative recvmsg length"))?;
    Ok((received, src, destination))
}

#[cfg(unix)]
pub(crate) async fn recv_udp_packet(
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

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_cmsg_align(len: usize) -> Option<usize> {
    let alignment = std::mem::size_of::<usize>();
    Some(len.checked_add(alignment - 1)? & !(alignment - 1))
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_cmsg_space(data_len: usize) -> Option<usize> {
    let header = windows_cmsg_align(std::mem::size_of::<
        windows::Win32::Networking::WinSock::CMSGHDR,
    >())?;
    let data = windows_cmsg_align(data_len)?;
    header.checked_add(data)
}

#[cfg(any(target_os = "windows", test))]
fn windows_cmsg_payload_fits(
    control_len: usize,
    offset: usize,
    cmsg_len: usize,
    data_offset: usize,
    payload_len: usize,
) -> bool {
    let Some(required_cmsg_len) = data_offset.checked_add(payload_len) else {
        return false;
    };
    if required_cmsg_len > cmsg_len {
        return false;
    }

    offset
        .checked_add(required_cmsg_len)
        .is_some_and(|end| end <= control_len)
}

#[cfg(any(target_os = "windows", test))]
fn bounded_windows_control_len(buffer_len: usize, reported_len: u32) -> usize {
    (reported_len as usize).min(buffer_len)
}

#[cfg(target_os = "windows")]
pub(crate) fn parse_ipv4_windows(addr: windows::Win32::Networking::WinSock::IN_ADDR) -> IpAddr {
    let value = unsafe { addr.S_un.S_addr };
    IpAddr::V4(Ipv4Addr::from(u32::from_be(value)))
}

#[cfg(target_os = "windows")]
pub(crate) fn parse_ipv6_windows(addr: windows::Win32::Networking::WinSock::IN6_ADDR) -> IpAddr {
    let bytes = unsafe { addr.u.Byte };
    IpAddr::V6(Ipv6Addr::from(bytes))
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_wsa_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe {
        windows::Win32::Networking::WinSock::WSAGetLastError().0
    })
}

#[cfg(target_os = "windows")]
pub(crate) fn configure_udp_destination_capture(
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
            Some((&guid as *const windows::core::GUID).cast::<core::ffi::c_void>()),
            size_of::<windows::core::GUID>() as u32,
            Some((&mut recv_msg as *mut LPFN_WSARECVMSG).cast::<core::ffi::c_void>()),
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
pub(crate) unsafe fn socket_addr_from_storage_windows(
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
pub(crate) fn destination_ip_from_control_message_windows(control: &[u8]) -> Option<IpAddr> {
    use windows::Win32::Networking::WinSock::{
        CMSGHDR, IN_PKTINFO, IN6_PKTINFO, IP_PKTINFO, IPPROTO_IP, IPPROTO_IPV6, IPV6_PKTINFO,
    };

    let mut offset = 0usize;
    let header_len = std::mem::size_of::<CMSGHDR>();
    let data_offset = windows_cmsg_align(header_len)?;

    while offset
        .checked_add(header_len)
        .is_some_and(|end| end <= control.len())
    {
        let header =
            unsafe { std::ptr::read_unaligned(control.as_ptr().add(offset).cast::<CMSGHDR>()) };
        let cmsg_len = header.cmsg_len;
        let Some(cmsg_end) = offset.checked_add(cmsg_len) else {
            break;
        };
        if cmsg_len < header_len || cmsg_end > control.len() {
            break;
        }

        if header.cmsg_level == IPPROTO_IP.0 && header.cmsg_type == IP_PKTINFO {
            let needed = std::mem::size_of::<IN_PKTINFO>();
            if windows_cmsg_payload_fits(control.len(), offset, cmsg_len, data_offset, needed) {
                let pktinfo = unsafe {
                    std::ptr::read_unaligned(
                        control
                            .as_ptr()
                            .add(offset + data_offset)
                            .cast::<IN_PKTINFO>(),
                    )
                };
                return Some(parse_ipv4_windows(pktinfo.ipi_addr));
            }
        }

        if header.cmsg_level == IPPROTO_IPV6.0 && header.cmsg_type == IPV6_PKTINFO {
            let needed = std::mem::size_of::<IN6_PKTINFO>();
            if windows_cmsg_payload_fits(control.len(), offset, cmsg_len, data_offset, needed) {
                let pktinfo = unsafe {
                    std::ptr::read_unaligned(
                        control
                            .as_ptr()
                            .add(offset + data_offset)
                            .cast::<IN6_PKTINFO>(),
                    )
                };
                return Some(parse_ipv6_windows(pktinfo.ipi6_addr));
            }
        }

        let Some(aligned_len) = windows_cmsg_align(cmsg_len) else {
            break;
        };
        let Some(next) = offset.checked_add(aligned_len) else {
            break;
        };
        if next <= offset {
            break;
        }
        offset = next;
    }

    None
}

#[cfg(target_os = "windows")]
pub(crate) fn recv_from_with_destination_now(
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
    let data_len = wsabuf_len(buf.len())?;

    let mut source_addr = SOCKADDR_STORAGE::default();
    let mut data_buf = WSABUF {
        len: data_len,
        buf: PSTR(buf.as_mut_ptr()),
    };
    let ipv4_control_len =
        windows_cmsg_space(size_of::<windows::Win32::Networking::WinSock::IN_PKTINFO>())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "control buffer length overflow",
                )
            })?;
    let ipv6_control_len =
        windows_cmsg_space(size_of::<windows::Win32::Networking::WinSock::IN6_PKTINFO>())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "control buffer length overflow",
                )
            })?;
    let mut control = vec![0u8; ipv4_control_len.max(ipv6_control_len)];
    let mut msg = WSAMSG {
        name: (&mut source_addr as *mut SOCKADDR_STORAGE).cast::<SOCKADDR>(),
        namelen: size_of::<SOCKADDR_STORAGE>() as i32,
        lpBuffers: &mut data_buf,
        dwBufferCount: 1,
        Control: WSABUF {
            len: wsabuf_len(control.len())?,
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
    let control_len = bounded_windows_control_len(control.len(), msg.Control.len);
    let destination = destination_ip_from_control_message_windows(&control[..control_len])
        .and_then(|ip| {
            if is_usable_session_destination_ip(ip) {
                Some(SessionDestination::new_unchecked(
                    ip.to_string(),
                    listener_port,
                ))
            } else {
                None
            }
        });

    Ok((bytes_received as usize, src, destination))
}

#[cfg(target_os = "windows")]
pub(crate) async fn recv_udp_packet(
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
pub(crate) fn configure_udp_destination_capture(
    _socket: &UdpSocket,
    _bind_addr: IpAddr,
) -> io::Result<UdpDestinationCapture> {
    Ok(UdpDestinationCapture)
}

#[cfg(not(any(unix, target_os = "windows")))]
pub(crate) async fn recv_udp_packet(
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

#[cfg(test)]
mod tests {
    use std::io;

    use super::{
        bounded_windows_control_len, windows_cmsg_align, windows_cmsg_payload_fits, wsabuf_len,
    };

    #[cfg(target_os = "linux")]
    use super::destination_ip_from_control_message;

    #[test]
    fn wsabuf_len_accepts_u32_max() {
        assert_eq!(
            wsabuf_len(u32::MAX as usize).expect("u32 max fits"),
            u32::MAX
        );
    }

    #[test]
    fn wsabuf_len_rejects_values_above_u32_max() {
        if usize::BITS <= u32::BITS {
            return;
        }

        let len = u32::MAX as usize + 1;
        let err = wsabuf_len(len).expect_err("oversized length should be rejected");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("exceeds u32::MAX"));
    }

    #[test]
    fn windows_cmsg_align_rejects_overflowing_length() {
        assert_eq!(windows_cmsg_align(usize::MAX), None);
    }

    #[test]
    fn windows_cmsg_payload_must_fit_declared_message_length() {
        let alignment = std::mem::size_of::<usize>();
        let header_len = alignment + 1;
        let data_offset = windows_cmsg_align(header_len).expect("header length aligns");
        let payload_len = alignment;
        let cmsg_len_without_padding = header_len + payload_len;
        let control_len = data_offset + payload_len;

        assert!(
            data_offset > header_len,
            "test requires aligned data offset to include padding"
        );
        assert!(windows_cmsg_payload_fits(
            control_len,
            0,
            control_len,
            data_offset,
            payload_len
        ));
        assert!(!windows_cmsg_payload_fits(
            control_len,
            0,
            cmsg_len_without_padding,
            data_offset,
            payload_len
        ));
    }

    #[test]
    fn bounded_windows_control_len_clamps_reported_length() {
        assert_eq!(bounded_windows_control_len(16, 8), 8);
        assert_eq!(bounded_windows_control_len(16, 32), 16);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn destination_control_message_rejects_truncated_pktinfo_payload() {
        let payload_len = std::mem::size_of::<libc::in_pktinfo>();
        let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(payload_len as _) } as usize];
        let cmsg = control.as_mut_ptr() as *mut libc::cmsghdr;
        unsafe {
            (*cmsg).cmsg_level = libc::IPPROTO_IP;
            (*cmsg).cmsg_type = libc::IP_PKTINFO;
            (*cmsg).cmsg_len = libc::CMSG_LEN((payload_len - 1) as _) as _;
        }
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len() as _;

        assert_eq!(destination_ip_from_control_message(&message), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn destination_control_message_reads_misaligned_pktinfo() {
        let payload_len = std::mem::size_of::<libc::in_pktinfo>();
        let control_len = unsafe { libc::CMSG_SPACE(payload_len as _) } as usize;
        let mut storage = vec![0u8; control_len + 1];
        let control = unsafe { storage.as_mut_ptr().add(1) };
        let cmsg = control as *mut libc::cmsghdr;
        let expected_ip = std::net::Ipv4Addr::new(203, 0, 113, 9);
        let mut pktinfo: libc::in_pktinfo = unsafe { std::mem::zeroed() };
        pktinfo.ipi_addr = libc::in_addr {
            s_addr: u32::from(expected_ip).to_be(),
        };
        unsafe {
            let mut header: libc::cmsghdr = std::mem::zeroed();
            header.cmsg_level = libc::IPPROTO_IP;
            header.cmsg_type = libc::IP_PKTINFO;
            header.cmsg_len = libc::CMSG_LEN(payload_len as _) as _;
            std::ptr::write_unaligned(cmsg, header);
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::in_pktinfo>(), pktinfo);
        }
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_control = control.cast();
        message.msg_controllen = control_len;

        assert_eq!(
            destination_ip_from_control_message(&message),
            Some(std::net::IpAddr::V4(expected_ip))
        );
    }
}
