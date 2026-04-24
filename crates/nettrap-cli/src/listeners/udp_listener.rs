use nettrap_proto_dns::handler::DnsHandlerTrait;
use nettrap_proto_tftp::TftpHandlerTrait;
use nettrap_protocols::handlers::*;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::listener_context::ListenerContext;
use crate::session::SessionDestination;
use crate::utils::log_event;

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

    Ok(UdpDestinationCapture)
}

#[cfg(unix)]
fn max_cmsg_space() -> usize {
    let ipv4 = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as _) } as usize;
    let ipv6 = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as _) } as usize;
    ipv4.max(ipv6)
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
    let destination = destination_ip_from_control_message(&message)
        .map(|ip| SessionDestination::new(ip.to_string(), listener_port));

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

                if !apply_udp_process_filter(&ctx, &src, &destination).await {
                    tracing::debug!("UDP process blocked by filter on {}", ctx.name());
                    continue;
                }

                tracing::debug!("UDP '{}' received {} bytes from {}", ctx.name(), len, src);

                if ctx.config.log_hexdump {
                    tracing::debug!("Hexdump:\n{}", crate::hexdump::hexdump(&buf[..len], 256));
                }

                let query_data = buf[..len].to_vec();
                ctx.write_pcap_event_udp_for_destination(&query_data, &src, &destination);

                let ctx_clone = Arc::clone(&ctx);
                let dns_handler_clone = Arc::clone(&dns_handler);
                let tftp_handler_clone = Arc::clone(&tftp_handler);
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
                    if ctx_clone.name() == "tftp" || ctx_clone.name().starts_with("tftp") {
                        let packet = UdpPacket {
                            output_path: out_clone.as_deref(),
                            query_data: &query_data,
                            src: &src,
                            destination: &destination,
                            len,
                        };
                        handle_tftp(&ctx_clone, &socket_clone, &tftp_handler_clone, packet).await;
                    } else if ctx_clone.name() == "dns" || ctx_clone.name().starts_with("dns") {
                        let packet = UdpPacket {
                            output_path: out_clone.as_deref(),
                            query_data: &query_data,
                            src: &src,
                            destination: &destination,
                            len,
                        };
                        handle_dns(&ctx_clone, &socket_clone, &dns_handler_clone, packet).await;
                    } else {
                        let packet = UdpPacket {
                            output_path: out_clone.as_deref(),
                            query_data: &query_data,
                            src: &src,
                            destination: &destination,
                            len,
                        };
                        handle_detected_udp(
                            &ctx_clone,
                            &socket_clone,
                            &dns_handler_clone,
                            &tftp_handler_clone,
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

    match tokio::task::spawn_blocking({
        let attr_engine = Arc::clone(attr_engine);
        move || attr_engine.attribute_flow(&five_tuple)
    })
    .await
    {
        Ok(attr) if attr.confidence != nettrap_core::prelude::AttributionConfidence::None => {
            apply_attributed_process_filter(ctx, src, destination, &attr)
        }
        Ok(_) => true,
        Err(e) => {
            tracing::warn!("UDP attribution timeout/error for {}: {}", src, e);
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
    packet: UdpPacket<'_>,
) {
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
        match tftp_handler.handle_packet(&tftp_packet).await {
            Ok(responses) => {
                let mut sent_bytes = 0u64;
                ctx.apply_response_delay().await;
                for resp in responses {
                    let resp_bytes = resp.to_bytes();
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
            ctx.write_pcap_response_udp_for_destination(&response, packet.src, packet.destination);
            if let Err(e) = socket.send_to(&response, *packet.src).await {
                tracing::warn!("Failed to send UDP response to {}: {}", packet.src, e);
            }
            ctx.update_session_bytes(
                packet.src,
                "UDP",
                packet.destination,
                packet.len as u64,
                response.len() as u64,
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

async fn handle_detected_udp(
    ctx: &ListenerContext,
    socket: &UdpSocket,
    dns_handler: &nettrap_proto_dns::handler::DnsHandler,
    tftp_handler: &nettrap_proto_tftp::TftpHandler,
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
                    handle_tftp(ctx, socket, tftp_handler, packet).await;
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
                    let response = nettrap_proto_upnp::UpnpHandler::new().handle(packet.query_data);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener_context::ListenerContext;
    use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
    use crate::process_filter::ProcessFilter;
    use crate::session::{PortForwardTable, SessionTracker};
    use std::sync::Arc;

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
