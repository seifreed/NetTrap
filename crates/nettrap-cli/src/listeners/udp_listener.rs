use nettrap_proto_dns::handler::DnsHandlerTrait;
use nettrap_protocols::handlers::*;
use std::collections::HashMap;
#[cfg(test)]
use std::net::Ipv4Addr;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use super::udp_tftp::{TftpTransfers, handle_tftp};
use crate::listener_context::ListenerContext;
use crate::listeners::attribution_semaphore;
use crate::session::SessionDestination;
use crate::utils::canonical_socket_ip_string;
use crate::utils::log_event;

mod dest_capture;
pub(crate) use dest_capture::*;

/// Run a UDP listener for DNS, TFTP, and other UDP protocols.
pub async fn run_udp_listener(
    ctx: ListenerContext,
    socket: UdpSocket,
    bind_addr: std::net::IpAddr,
    output_path: Option<&std::path::Path>,
) -> crate::Result<()> {
    run_udp_listener_with_policy(
        ctx,
        socket,
        bind_addr,
        output_path,
        nettrap_engine::FlowPolicy::new(nettrap_engine::FlowDecision::Emulate).resolve(true),
    )
    .await
}

pub(crate) async fn run_udp_listener_with_policy(
    ctx: ListenerContext,
    socket: UdpSocket,
    bind_addr: std::net::IpAddr,
    output_path: Option<&std::path::Path>,
    policy: nettrap_engine::FlowPolicyResolution,
) -> crate::Result<()> {
    run_udp_listener_with_flow_policy(
        ctx,
        socket,
        bind_addr,
        output_path,
        Arc::new(nettrap_engine::ConfiguredFlowPolicy::new(
            policy.decision(),
            Vec::new(),
        )),
        true,
    )
    .await
}

pub(crate) async fn run_udp_listener_with_flow_policy(
    ctx: ListenerContext,
    socket: UdpSocket,
    bind_addr: std::net::IpAddr,
    output_path: Option<&std::path::Path>,
    policy: Arc<nettrap_engine::ConfiguredFlowPolicy>,
    emulate_response: bool,
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
    let dns_handler = Arc::new(crate::protocol_handlers::init_dns_handler(&ctx)?);
    let tftp_handler = Arc::new(crate::protocol_handlers::init_tftp_handler(&ctx)?);
    let chargen_handler = Arc::new(nettrap_proto_chargen::ChargenHandler::new());
    let tftp_transfers = Arc::new(Mutex::new(HashMap::new()));
    let output_path = output_path.map(|p| p.to_path_buf());
    let socket = Arc::new(socket);
    let listener_port = local_addr.port();
    let direct_destination = direct_destination_from_local_addr(local_addr, bind_addr);
    let mut buf = vec![0u8; 65535];
    // Limit concurrent UDP handler tasks to prevent resource exhaustion from floods
    let udp_semaphore = Arc::new(tokio::sync::Semaphore::new(1024));
    let mut packet_tasks = JoinSet::new();

    loop {
        while let Some(result) = packet_tasks.try_join_next() {
            if let Err(err) = result
                && !err.is_cancelled()
            {
                tracing::warn!("UDP packet task failed: {}", err);
            }
        }

        match recv_udp_packet(&socket, &destination_capture, &mut buf, listener_port).await {
            Ok((len, src, packet_destination)) => {
                if !ctx.is_host_allowed(&canonical_socket_ip_string(&src)) {
                    tracing::debug!("Host {} blocked by filter on {}", src.ip(), ctx.name());
                    log_event(
                        output_path.as_deref(),
                        ctx.name(),
                        &src,
                        "policy_decision",
                        "decision=block rule=host_filter",
                    )
                    .await;
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
                let chargen_handler_clone = Arc::clone(&chargen_handler);
                let tftp_transfers_clone = Arc::clone(&tftp_transfers);
                let socket_clone = Arc::clone(&socket);
                let out_clone = output_path.clone();
                let sem = Arc::clone(&udp_semaphore);
                let policy_clone = Arc::clone(&policy);

                let permit = match sem.try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!("UDP task limit reached, dropping packet from {}", src);
                        continue;
                    }
                };

                packet_tasks.spawn(async move {
                    let _permit = permit; // held until task completes
                    if !apply_udp_process_filter(&ctx_clone, &src, &destination).await {
                        tracing::debug!("UDP process blocked by filter on {}", ctx_clone.name());
                        log_event(
                            out_clone.as_deref(),
                            ctx_clone.name(),
                            &src,
                            "policy_decision",
                            "decision=block rule=process_filter",
                        )
                        .await;
                        return;
                    }

                    let source_host = src.ip().to_string();
                    let configured = policy_clone.resolve_for_context(
                        nettrap_engine::FlowPolicyContext {
                            listener: ctx_clone.name(),
                            protocol: "udp",
                            source_host: Some(&source_host),
                            destination_host: Some(destination.ip()),
                            destination_port: Some(destination.port()),
                            process_name: ctx_clone
                                .runtime
                                .session_tracker
                                .get_process(&src, "UDP", &destination)
                                .and_then(|(name, _)| name)
                                .as_deref(),
                        },
                        emulate_response,
                    );

                    if is_new_session {
                        log_event(
                            out_clone.as_deref(),
                            ctx_clone.name(),
                            &src,
                            "policy_decision",
                            &format!(
                                "decision={} rule={}",
                                configured.decision(),
                                configured.rule_label()
                            ),
                        )
                        .await;
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

                    match configured.decision() {
                        nettrap_engine::FlowDecision::Pass
                        | nettrap_engine::FlowDecision::Capture => {
                            if let Err(error) = forward_udp_datagram(
                                &ctx_clone,
                                &socket_clone,
                                &query_data,
                                &src,
                                &destination,
                                matches!(
                                    configured.decision(),
                                    nettrap_engine::FlowDecision::Capture
                                ),
                            )
                            .await
                            {
                                tracing::debug!("UDP forward from {} failed: {}", src, error);
                            }
                            if is_new_session {
                                ctx_clone.fire_execute_cmd_for_session(&src, "UDP", &destination);
                            }
                            return;
                        }
                        nettrap_engine::FlowDecision::Sinkhole => {
                            ctx_clone.write_pcap_event_udp_for_destination(
                                &query_data,
                                &src,
                                &destination,
                            );
                            ctx_clone.update_session_bytes(
                                &src,
                                "UDP",
                                &destination,
                                len as u64,
                                0,
                            );
                            if is_new_session {
                                ctx_clone.fire_execute_cmd_for_session(&src, "UDP", &destination);
                            }
                            return;
                        }
                        nettrap_engine::FlowDecision::Block => return,
                        nettrap_engine::FlowDecision::Emulate => {
                            ctx_clone.write_pcap_event_udp_for_destination(
                                &query_data,
                                &src,
                                &destination,
                            );
                        }
                    }

                    let packet = UdpPacket {
                        output_path: out_clone.as_deref(),
                        query_data: &query_data,
                        src: &src,
                        destination: &destination,
                        len,
                    };
                    if let Some(protocol) = explicit_udp_protocol_name(ctx_clone.name()) {
                        let handlers = UdpHandlers {
                            dns: &dns_handler_clone,
                            tftp: &tftp_handler_clone,
                            chargen: &chargen_handler_clone,
                        };
                        handle_explicit_udp_protocol(
                            &ctx_clone,
                            &socket_clone,
                            &handlers,
                            &tftp_transfers_clone,
                            packet,
                            protocol,
                        )
                        .await;
                    } else {
                        let handlers = UdpHandlers {
                            dns: &dns_handler_clone,
                            tftp: &tftp_handler_clone,
                            chargen: &chargen_handler_clone,
                        };
                        handle_detected_udp(
                            &ctx_clone,
                            &socket_clone,
                            &handlers,
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

async fn forward_udp_datagram(
    ctx: &ListenerContext,
    listener_socket: &UdpSocket,
    query: &[u8],
    src: &SocketAddr,
    destination: &SessionDestination,
    capture: bool,
) -> crate::Result<()> {
    let local_addr = listener_socket.local_addr()?;
    let target = resolve_udp_forward_target(destination, local_addr).ok_or_else(|| {
        crate::Error::Other(format!(
            "no usable UDP original destination {}:{}",
            destination.ip(),
            destination.port()
        ))
    })?;
    let bind_addr = match target.ip() {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let upstream = UdpSocket::bind(bind_addr).await?;
    upstream.connect(target).await?;
    let mut response = [0_u8; u16::MAX as usize];
    let response_length = tokio::time::timeout(Duration::from_millis(ctx.timeout_ms()), async {
        upstream.send(query).await?;
        upstream.recv(&mut response).await
    })
    .await
    .map_err(|_| {
        crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "UDP forward response timed out",
        ))
    })??;

    if capture {
        ctx.write_pcap_event_udp_for_destination(query, src, destination);
        ctx.write_pcap_response_udp_for_destination(&response[..response_length], src, destination);
    }
    listener_socket
        .send_to(&response[..response_length], src)
        .await?;
    ctx.update_session_bytes(
        src,
        "UDP",
        destination,
        query.len() as u64,
        response_length as u64,
    );
    Ok(())
}

fn resolve_udp_forward_target(
    destination: &SessionDestination,
    listener_addr: SocketAddr,
) -> Option<SocketAddr> {
    if destination.port() == 0 {
        return None;
    }
    let ip = normalize_udp_forward_ip(destination.ip().parse().ok()?);
    let unusable = match ip {
        IpAddr::V4(ip) => ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast(),
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast(),
    };
    if unusable {
        return None;
    }
    let target = SocketAddr::new(ip, destination.port());
    let listener_addr = SocketAddr::new(
        normalize_udp_forward_ip(listener_addr.ip()),
        listener_addr.port(),
    );
    (target != listener_addr).then_some(target)
}

fn normalize_udp_forward_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(ip),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
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

    let Some(five_tuple) = ctx.session_flow_five_tuple(src, "UDP", destination) else {
        return true;
    };

    let permit = match tokio::time::timeout(
        ctx.runtime.attribution_timeout,
        attribution_semaphore().acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        Ok(Err(err)) => {
            tracing::warn!("Attribution semaphore unavailable for {}: {}", src, err);
            return true;
        }
        Err(_) => {
            tracing::warn!(
                "Attribution queue timed out after {} ms for {}",
                ctx.runtime.attribution_timeout.as_millis(),
                src
            );
            return true;
        }
    };

    match tokio::time::timeout(
        ctx.runtime.attribution_timeout,
        tokio::task::spawn_blocking({
            let attr_engine = Arc::clone(attr_engine);
            move || {
                let _permit = permit;
                attr_engine.attribute_flow(&five_tuple)
            }
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
    let proc_name = attr.process.name();
    ctx.runtime.session_tracker.set_process(
        src,
        "UDP",
        destination,
        Some(proc_name.to_string()),
        Some(attr.process.pid()),
    );
    ctx.is_process_allowed(proc_name)
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
            if let Some((domain, query_type)) =
                nettrap_proto_dns::handler::parse_query_summary(packet.query_data)
            {
                let nbi = crate::nbi::dns_nbi(
                    ctx.name(),
                    &canonical_socket_ip_string(packet.src),
                    packet.src.port(),
                    packet.destination,
                    &domain,
                    &query_type,
                );
                ctx.record_nbi(&nbi).await;
            } else {
                tracing::debug!("Skipping DNS NBI record for malformed UDP query");
            }
        }
        Err(e) => {
            tracing::warn!("UDP handler error from {}: {}", packet.src, e);
            ctx.update_session_bytes(packet.src, "UDP", packet.destination, packet.len as u64, 0);
        }
    }
}

pub(crate) struct UdpPacket<'a> {
    pub(crate) output_path: Option<&'a std::path::Path>,
    pub(crate) query_data: &'a [u8],
    pub(crate) src: &'a std::net::SocketAddr,
    pub(crate) destination: &'a SessionDestination,
    pub(crate) len: usize,
}

struct UdpHandlers<'a> {
    dns: &'a nettrap_proto_dns::handler::DnsHandler,
    tftp: &'a nettrap_proto_tftp::TftpHandler,
    chargen: &'a nettrap_proto_chargen::ChargenHandler,
}

fn udp_listener_name_matches_protocol(listener_name: &str, protocol: &str) -> bool {
    if listener_name.trim_matches([' ', '\t']) != listener_name
        || listener_name.is_empty()
        || listener_name
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && !matches!(ch, ' ' | '\t')))
    {
        return false;
    }

    let listener = canonical_udp_protocol_alias(listener_name);
    listener == protocol
        || listener
            .strip_prefix(protocol)
            .and_then(|suffix| suffix.as_bytes().first().copied())
            .is_some_and(|byte| matches!(byte, b'-' | b'_'))
}

fn canonical_udp_protocol_alias(listener_name: &str) -> String {
    let lower = listener_name.to_lowercase();
    match lower.as_str() {
        "echo" => "raw".to_string(),
        other if other.starts_with("echo-") || other.starts_with("echo_") => {
            format!("raw{}", &other["echo".len()..])
        }
        "qotd" => "quotd".to_string(),
        other if other.starts_with("qotd-") || other.starts_with("qotd_") => {
            format!("quotd{}", &other["qotd".len()..])
        }
        _ => lower,
    }
}

pub(crate) fn explicit_udp_protocol_name(listener_name: &str) -> Option<&'static str> {
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
    handlers: &UdpHandlers<'_>,
    tftp_transfers: &TftpTransfers,
    packet: UdpPacket<'_>,
    protocol: &str,
) {
    match protocol {
        "dns" => handle_dns(ctx, socket, handlers.dns, packet).await,
        "tftp" => handle_tftp(ctx, socket, handlers.tftp, tftp_transfers, packet).await,
        "snmp" => handle_snmp_udp(ctx, socket, packet).await,
        "sip" => handle_sip_udp(ctx, socket, packet).await,
        "upnp" => handle_upnp_udp(ctx, socket, packet).await,
        "ntp" => handle_ntp_udp(ctx, socket, packet).await,
        "coap" => handle_coap_udp(ctx, socket, packet).await,
        "quic" => handle_quic_udp(ctx, packet).await,
        "daytime" => handle_daytime_udp(ctx, socket, packet).await,
        "time" => handle_time_udp(ctx, socket, packet).await,
        "chargen" => handle_chargen_udp(ctx, socket, handlers.chargen, packet).await,
        "quotd" => handle_quotd_udp(ctx, socket, packet).await,
        "syslogrecv" => handle_syslogrecv_udp(ctx, packet).await,
        "raw" => handle_raw_udp(ctx, socket, packet).await,
        _ => handle_detected_udp(ctx, socket, handlers, tftp_transfers, packet).await,
    }
}

async fn handle_detected_udp(
    ctx: &ListenerContext,
    socket: &UdpSocket,
    handlers: &UdpHandlers<'_>,
    tftp_transfers: &TftpTransfers,
    packet: UdpPacket<'_>,
) {
    let detected = ctx
        .runtime
        .router
        .route_udp(packet.query_data, packet.destination.port());
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
                    handle_dns(ctx, socket, handlers.dns, packet).await;
                }
                "tftp" => {
                    handle_tftp(ctx, socket, handlers.tftp, tftp_transfers, packet).await;
                }
                "snmp" => {
                    handle_snmp_udp(ctx, socket, packet).await;
                }
                "sip" => {
                    handle_sip_udp(ctx, socket, packet).await;
                }
                "upnp" => {
                    handle_upnp_udp(ctx, socket, packet).await;
                }
                "ntp" => {
                    handle_ntp_udp(ctx, socket, packet).await;
                }
                "coap" => {
                    handle_coap_udp(ctx, socket, packet).await;
                }
                "daytime" => {
                    handle_daytime_udp(ctx, socket, packet).await;
                }
                "time" => {
                    handle_time_udp(ctx, socket, packet).await;
                }
                "chargen" => {
                    handle_chargen_udp(ctx, socket, handlers.chargen, packet).await;
                }
                "quotd" => {
                    handle_quotd_udp(ctx, socket, packet).await;
                }
                "syslogrecv" => {
                    handle_syslogrecv_udp(ctx, packet).await;
                }
                "raw" => {
                    handle_raw_udp(ctx, socket, packet).await;
                }
                "quic" => {
                    handle_quic_udp(ctx, packet).await;
                }
                _ => {
                    handle_unknown_detected_udp(ctx, socket, packet, name).await;
                }
            }
        }
        _ => {
            handle_unclassified_udp(ctx, packet).await;
        }
    }
}

async fn handle_snmp_udp(ctx: &ListenerContext, socket: &UdpSocket, packet: UdpPacket<'_>) {
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

async fn handle_sip_udp(ctx: &ListenerContext, socket: &UdpSocket, packet: UdpPacket<'_>) {
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

async fn handle_upnp_udp(ctx: &ListenerContext, socket: &UdpSocket, packet: UdpPacket<'_>) {
    let Ok(handler) = crate::protocol_handlers::init_upnp_handler(packet.destination.ip()) else {
        tracing::warn!(
            "Ignoring UPnP UDP request for invalid listener IP {}",
            packet.destination.ip()
        );
        return;
    };
    let response = handler.handle_ssdp(packet.query_data);
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

async fn handle_ntp_udp(ctx: &ListenerContext, socket: &UdpSocket, packet: UdpPacket<'_>) {
    let response = nettrap_proto_ntp::NtpHandler::new()
        .with_now(crate::faketime::fake_now)
        .handle(packet.query_data);
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

async fn handle_coap_udp(ctx: &ListenerContext, socket: &UdpSocket, packet: UdpPacket<'_>) {
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

async fn handle_daytime_udp(ctx: &ListenerContext, socket: &UdpSocket, packet: UdpPacket<'_>) {
    let response =
        nettrap_proto_daytime::DaytimeHandler::new().handle_at(crate::faketime::fake_now());
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

async fn handle_time_udp(ctx: &ListenerContext, socket: &UdpSocket, packet: UdpPacket<'_>) {
    let response = nettrap_proto_time::TimeHandler::new().handle_at(crate::faketime::fake_now());
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

async fn handle_chargen_udp(
    ctx: &ListenerContext,
    socket: &UdpSocket,
    handler: &nettrap_proto_chargen::ChargenHandler,
    packet: UdpPacket<'_>,
) {
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

async fn handle_quotd_udp(ctx: &ListenerContext, socket: &UdpSocket, packet: UdpPacket<'_>) {
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

async fn handle_raw_udp(ctx: &ListenerContext, socket: &UdpSocket, packet: UdpPacket<'_>) {
    let response = if let Some(custom) = ctx.custom_response() {
        match nettrap_proto_raw::RawHandler::from_custom_response(custom) {
            Ok(handler) => handler.handle(packet.query_data).to_bytes(),
            Err(err) => {
                tracing::warn!(
                    "invalid raw custom response config for {}: {}",
                    ctx.name(),
                    err
                );
                nettrap_proto_raw::RawResponse::new(b"ERROR\n".to_vec()).to_bytes()
            }
        }
    } else {
        nettrap_proto_raw::RawHandler::new()
            .handle(packet.query_data)
            .to_bytes()
    };
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

async fn handle_unknown_detected_udp(
    ctx: &ListenerContext,
    socket: &UdpSocket,
    packet: UdpPacket<'_>,
    name: &str,
) {
    log_event(
        packet.output_path,
        ctx.name(),
        packet.src,
        "udp_unknown",
        &format!("{} bytes, detected={}", packet.len, name),
    )
    .await;
    let mut nbi = crate::nbi::raw_nbi(
        ctx.name(),
        &canonical_socket_ip_string(packet.src),
        packet.src.port(),
        packet.destination,
        packet.len,
        "",
    );
    nbi.add("detected_protocol", name);
    ctx.record_nbi(&nbi).await;
    ctx.apply_response_delay().await;
    let response = b"OK\n";
    let sent = if socket.send_to(response, *packet.src).await.is_ok() {
        ctx.write_pcap_response_udp_for_destination(response, packet.src, packet.destination);
        response.len() as u64
    } else {
        0
    };
    ctx.update_session_bytes(
        packet.src,
        "UDP",
        packet.destination,
        packet.len as u64,
        sent,
    );
}

async fn handle_unclassified_udp(ctx: &ListenerContext, packet: UdpPacket<'_>) {
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
    let mut nbi = crate::nbi::raw_nbi(
        ctx.name(),
        &canonical_socket_ip_string(packet.src),
        packet.src.port(),
        packet.destination,
        packet.len,
        "",
    );
    nbi.add("note", "no protocol detected");
    ctx.record_nbi(&nbi).await;
    ctx.update_session_bytes(packet.src, "UDP", packet.destination, packet.len as u64, 0);
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
        &canonical_socket_ip_string(packet.src),
        packet.src.port(),
        packet.destination,
        packet.len,
        "",
    );
    nbi.add("detected_protocol", "syslogrecv");
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

    let nbi = crate::nbi::quic_nbi(
        ctx.name(),
        &canonical_socket_ip_string(packet.src),
        packet.src.port(),
        packet.destination,
        sni.as_deref(),
        packet.len,
    );
    ctx.record_nbi(&nbi).await;
    ctx.update_session_bytes(packet.src, "UDP", packet.destination, packet.len as u64, 0);
}

#[cfg(test)]
#[path = "udp_listener_tests.rs"]
mod tests;
