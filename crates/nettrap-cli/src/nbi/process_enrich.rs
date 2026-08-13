use nettrap_core::NetworkBehaviorIndicator;
use nettrap_core::prelude::Protocol;

use crate::session::{SessionDestination, SessionTracker};

pub(super) fn with_session_process(
    nbi: &NetworkBehaviorIndicator,
    tracker: Option<&SessionTracker>,
    listener_protocol: Option<Protocol>,
) -> NetworkBehaviorIndicator {
    let Some(tracker) = tracker else {
        return nbi.clone();
    };

    let transport = match listener_protocol {
        Some(Protocol::Tcp) => "TCP",
        Some(Protocol::Udp) => "UDP",
        _ => return nbi.clone(),
    };

    let src_ip = match nbi.src_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return nbi.clone(),
    };

    let src = std::net::SocketAddr::new(src_ip, nbi.src_port);
    let destination = SessionDestination::new_unchecked(
        normalize_destination_ip_for_peer(&src, &nbi.dst_ip),
        nbi.dst_port,
    );
    match tracker.get_process(&src, transport, &destination) {
        Some((name, pid)) => {
            let name = nbi.process_name.clone().or(name);
            let pid = nbi.process_pid.or(pid);
            if name.is_some() || pid.is_some() {
                nbi.clone().with_process(name, pid)
            } else {
                nbi.clone()
            }
        }
        None => nbi.clone(),
    }
}

fn normalize_destination_ip_for_peer(peer: &std::net::SocketAddr, ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(ip) => crate::session::normalize_session_ip(ip).to_string(),
        Err(_) => match peer.ip() {
            std::net::IpAddr::V4(_) => std::net::Ipv4Addr::UNSPECIFIED.to_string(),
            std::net::IpAddr::V6(_) => std::net::Ipv6Addr::UNSPECIFIED.to_string(),
        },
    }
}
