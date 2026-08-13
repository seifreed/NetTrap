//! TFTP transfer-state tracking and request handling for the UDP listener.

use nettrap_proto_tftp::TftpHandlerTrait;
use nettrap_protocols::handlers::nettrap_proto_tftp;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use super::udp_listener::UdpPacket;
use crate::listener_context::ListenerContext;
use crate::session::SessionDestination;
use crate::utils::canonical_socket_ip_string;
use crate::utils::log_event;

const TFTP_TRANSFER_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_TFTP_ACTIVE_TRANSFERS: usize = 1024;
const MAX_TFTP_UPLOAD_BYTES: u64 = 8 * 1024 * 1024;

fn add_tftp_sent_bytes(total: u64, chunk_len: usize) -> u64 {
    let chunk = u64::try_from(chunk_len).unwrap_or(u64::MAX);
    total.saturating_add(chunk)
}

fn safe_tftp_log_text(value: &str) -> String {
    nettrap_core::sanitize::single_line(value)
}

fn tftp_packet_operation(packet: &nettrap_proto_tftp::TftpPacket) -> &'static str {
    match packet {
        nettrap_proto_tftp::TftpPacket::ReadRequest { .. } => "read",
        nettrap_proto_tftp::TftpPacket::WriteRequest { .. } => "write",
        nettrap_proto_tftp::TftpPacket::Data { .. } => "data",
        nettrap_proto_tftp::TftpPacket::Ack { .. } => "ack",
        nettrap_proto_tftp::TftpPacket::Error { .. } => "error",
    }
}

fn tftp_packet_filename(packet: &nettrap_proto_tftp::TftpPacket) -> &str {
    match packet {
        nettrap_proto_tftp::TftpPacket::ReadRequest { filename, .. }
        | nettrap_proto_tftp::TftpPacket::WriteRequest { filename, .. } => filename,
        _ => "",
    }
}

fn tftp_packet_log_detail(packet: &nettrap_proto_tftp::TftpPacket) -> String {
    match packet {
        nettrap_proto_tftp::TftpPacket::ReadRequest {
            filename, options, ..
        } => format!(
            "operation=read filename={} options={}",
            safe_tftp_log_text(filename),
            options.len()
        ),
        nettrap_proto_tftp::TftpPacket::WriteRequest {
            filename, options, ..
        } => format!(
            "operation=write filename={} options={}",
            safe_tftp_log_text(filename),
            options.len()
        ),
        nettrap_proto_tftp::TftpPacket::Data { block, data } => {
            format!("operation=data block={} data_length={}", block, data.len())
        }
        nettrap_proto_tftp::TftpPacket::Ack { block } => {
            format!("operation=ack block={}", block)
        }
        nettrap_proto_tftp::TftpPacket::Error { code, message } => format!(
            "operation=error code={} message={}",
            code,
            safe_tftp_log_text(message)
        ),
    }
}

pub(crate) type TftpTransfers = Arc<Mutex<HashMap<TftpTransferKey, TftpTransferState>>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct TftpTransferKey {
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
}

impl TftpTransferKey {
    pub(crate) fn new(src: SocketAddr, destination: &SessionDestination) -> crate::Result<Self> {
        let src_ip = crate::session::normalize_session_ip(src.ip()).to_string();
        let dst_ip = destination
            .ip()
            .parse::<std::net::IpAddr>()
            .map_err(|err| {
                crate::Error::Config(format!(
                    "invalid TFTP destination address {}:{}: {}",
                    destination.ip(),
                    destination.port(),
                    err
                ))
            })?;
        Ok(Self {
            src_ip,
            src_port: src.port(),
            dst_ip: crate::session::normalize_session_ip(dst_ip).to_string(),
            dst_port: destination.port(),
        })
    }
}

#[derive(Debug)]
pub(crate) enum TftpTransferState {
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
        upload_file: Option<File>,
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

pub(crate) async fn handle_tftp(
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
            &tftp_packet_log_detail(&tftp_packet),
        )
        .await;
        let nbi = crate::nbi::tftp_nbi(
            ctx.name(),
            &canonical_socket_ip_string(packet.src),
            packet.src.port(),
            packet.destination,
            tftp_packet_operation(&tftp_packet),
            tftp_packet_filename(&tftp_packet),
        );
        ctx.record_nbi(&nbi).await;
        let responses_result: nettrap_core::error::Result<Vec<nettrap_proto_tftp::TftpPacket>> =
            match &tftp_packet {
                nettrap_proto_tftp::TftpPacket::ReadRequest {
                    filename, options, ..
                } if !options.is_empty() => {
                    Ok(vec![nettrap_proto_tftp::option_negotiation_failed(
                        filename,
                    )])
                }
                nettrap_proto_tftp::TftpPacket::ReadRequest { filename, .. } => {
                    let key = match TftpTransferKey::new(*packet.src, packet.destination) {
                        Ok(key) => key,
                        Err(err) => {
                            tracing::warn!(
                                "Ignoring TFTP read request from {} with invalid destination {}:{}: {}",
                                packet.src,
                                packet.destination.ip(),
                                packet.destination.port(),
                                err
                            );
                            ctx.update_session_bytes(
                                packet.src,
                                "UDP",
                                packet.destination,
                                packet.len as u64,
                                0,
                            );
                            return;
                        }
                    };
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
                nettrap_proto_tftp::TftpPacket::WriteRequest {
                    filename, options, ..
                } if !options.is_empty() => {
                    Ok(vec![nettrap_proto_tftp::option_negotiation_failed(
                        filename,
                    )])
                }
                nettrap_proto_tftp::TftpPacket::WriteRequest { filename, .. } => {
                    let key = match TftpTransferKey::new(*packet.src, packet.destination) {
                        Ok(key) => key,
                        Err(err) => {
                            tracing::warn!(
                                "Ignoring TFTP write request from {} with invalid destination {}:{}: {}",
                                packet.src,
                                packet.destination.ip(),
                                packet.destination.port(),
                                err
                            );
                            ctx.update_session_bytes(
                                packet.src,
                                "UDP",
                                packet.destination,
                                packet.len as u64,
                                0,
                            );
                            return;
                        }
                    };
                    let mut active = transfers.lock().await;
                    prune_tftp_transfers(&mut active);
                    if let Some(response) =
                        duplicate_tftp_write_request_response(&mut active, &key, filename)
                    {
                        Ok(vec![response])
                    } else if tftp_transfer_limit_reached(&active, &key) {
                        Ok(vec![tftp_error(4, "Too many active transfers")])
                    } else {
                        match tftp_handler.open_upload_file(filename) {
                            Ok(upload_file) => {
                                let response = tftp_handler.handle_write_request(filename);
                                active.insert(
                                    key,
                                    TftpTransferState::Write {
                                        filename: filename.clone(),
                                        next_block_expected: 1,
                                        bytes_received: 0,
                                        last_ack: response.clone(),
                                        upload_file,
                                        complete: false,
                                        last_activity: Instant::now(),
                                    },
                                );
                                Ok(vec![response])
                            }
                            Err(err) => {
                                tracing::warn!(
                                    "Failed to prepare TFTP upload for {}: {}",
                                    safe_tftp_log_text(filename),
                                    err
                                );
                                Ok(vec![tftp_error(2, "Access violation")])
                            }
                        }
                    }
                }
                nettrap_proto_tftp::TftpPacket::Ack { block } => {
                    let key = match TftpTransferKey::new(*packet.src, packet.destination) {
                        Ok(key) => key,
                        Err(err) => {
                            tracing::warn!(
                                "Ignoring TFTP ACK from {} with invalid destination {}:{}: {}",
                                packet.src,
                                packet.destination.ip(),
                                packet.destination.port(),
                                err
                            );
                            ctx.update_session_bytes(
                                packet.src,
                                "UDP",
                                packet.destination,
                                packet.len as u64,
                                0,
                            );
                            return;
                        }
                    };
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
                    let key = match TftpTransferKey::new(*packet.src, packet.destination) {
                        Ok(key) => key,
                        Err(err) => {
                            tracing::warn!(
                                "Ignoring TFTP data from {} with invalid destination {}:{}: {}",
                                packet.src,
                                packet.destination.ip(),
                                packet.destination.port(),
                                err
                            );
                            ctx.update_session_bytes(
                                packet.src,
                                "UDP",
                                packet.destination,
                                packet.len as u64,
                                0,
                            );
                            return;
                        }
                    };
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
                    let key = match TftpTransferKey::new(*packet.src, packet.destination) {
                        Ok(key) => key,
                        Err(err) => {
                            tracing::warn!(
                                "Ignoring TFTP error from {} with invalid destination {}:{}: {}",
                                packet.src,
                                packet.destination.ip(),
                                packet.destination.port(),
                                err
                            );
                            ctx.update_session_bytes(
                                packet.src,
                                "UDP",
                                packet.destination,
                                packet.len as u64,
                                0,
                            );
                            return;
                        }
                    };
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
                    let Ok(resp_bytes) = resp.to_bytes() else {
                        tracing::warn!("Dropped invalid TFTP response packet for {}", packet.src);
                        continue;
                    };
                    match socket.send_to(&resp_bytes, *packet.src).await {
                        Ok(_) => {
                            ctx.write_pcap_response_udp_for_destination(
                                &resp_bytes,
                                packet.src,
                                packet.destination,
                            );
                            sent_bytes = add_tftp_sent_bytes(sent_bytes, resp_bytes.len());
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
    } else {
        tracing::debug!(
            "Ignoring malformed TFTP datagram from {} ({} bytes)",
            packet.src,
            packet.len
        );
        ctx.update_session_bytes(packet.src, "UDP", packet.destination, packet.len as u64, 0);
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
    if block == 0 {
        return vec![tftp_error(4, "Invalid block")];
    }

    let (response, remove_after) = {
        let Some(state) = transfers.get_mut(key) else {
            return vec![tftp_error(5, "Unknown transfer id")];
        };

        let TftpTransferState::Write {
            filename,
            next_block_expected,
            bytes_received,
            last_ack,
            upload_file,
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
                    if let Some(file) = upload_file.as_mut() {
                        if let Err(err) = file.write_all(data).and_then(|_| file.flush()) {
                            tracing::warn!(
                                "Failed to persist TFTP upload for {}: {}",
                                safe_tftp_log_text(filename),
                                err
                            );
                            (tftp_error(3, "Disk full or allocation exceeded"), true)
                        } else {
                            *bytes_received = new_total;
                            *next_block_expected = block.wrapping_add(1);
                            *last_activity = Instant::now();
                            let response = tftp_handler.handle_data_block(block, data);
                            *last_ack = response.clone();
                            *complete = data.len() < nettrap_proto_tftp::TFTP_BLOCK_SIZE;
                            if *complete {
                                upload_file.take();
                            }
                            (response, false)
                        }
                    } else {
                        *bytes_received = new_total;
                        *next_block_expected = block.wrapping_add(1);
                        *last_activity = Instant::now();
                        let response = tftp_handler.handle_data_block(block, data);
                        *last_ack = response.clone();
                        *complete = data.len() < nettrap_proto_tftp::TFTP_BLOCK_SIZE;
                        (response, false)
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
    use crate::process_filter::ProcessFilter;
    use crate::session::{PortForwardTable, SessionTracker};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn add_tftp_sent_bytes_saturates_at_u64_max() {
        assert_eq!(add_tftp_sent_bytes(u64::MAX - 1, 8), u64::MAX);
        assert_eq!(add_tftp_sent_bytes(40, 2), 42);
    }

    #[test]
    fn safe_tftp_log_text_removes_control_chars_and_caps_length() {
        let value = safe_tftp_log_text("firmware\n.bin\x1b");

        assert_eq!(value, "firmware .bin ");
        assert!(!value.chars().any(char::is_control));
        assert_eq!(
            safe_tftp_log_text(&"a".repeat(nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS + 1))
                .len(),
            nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS
        );
    }

    #[test]
    fn tftp_packet_summary_does_not_log_data_payload_bytes() {
        let packet = nettrap_proto_tftp::TftpPacket::Data {
            block: 7,
            data: b"secret-payload".to_vec(),
        };

        assert_eq!(tftp_packet_operation(&packet), "data");
        assert_eq!(tftp_packet_filename(&packet), "");
        assert_eq!(
            tftp_packet_log_detail(&packet),
            "operation=data block=7 data_length=14"
        );
        assert!(!tftp_packet_log_detail(&packet).contains("secret"));
    }

    #[test]
    fn tftp_data_without_write_state_returns_unknown_transfer() {
        let mut transfers = HashMap::new();
        let destination = SessionDestination::new_unchecked("127.0.0.1", 69);
        let src: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let key = TftpTransferKey::new(src, &destination).expect("transfer key");

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
    fn tftp_transfer_key_canonicalizes_ipv4_mapped_destination_ips() {
        let src: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let mapped_src: SocketAddr = "[::ffff:127.0.0.1]:53000".parse().unwrap();
        let mapped = SessionDestination::new_unchecked("::ffff:192.0.2.10", 69);
        let canonical = SessionDestination::new_unchecked("192.0.2.10", 69);

        let mapped_key = TftpTransferKey::new(src, &mapped).expect("transfer key");
        let canonical_key = TftpTransferKey::new(mapped_src, &canonical).expect("transfer key");

        assert_eq!(mapped_key, canonical_key);
    }

    #[test]
    fn tftp_transfer_key_rejects_invalid_destination_ip() {
        let src: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let destination = SessionDestination::new_unchecked("not-an-ip", 69);

        assert!(TftpTransferKey::new(src, &destination).is_err());
    }

    #[test]
    fn tftp_transfer_key_rejects_invalid_destination_ip_for_ipv6_peer() {
        let src: SocketAddr = "[2001:db8::10]:53000".parse().unwrap();
        let destination = SessionDestination::new_unchecked("not-an-ip", 69);

        assert!(TftpTransferKey::new(src, &destination).is_err());
    }

    #[test]
    fn tftp_write_state_accepts_expected_final_block_and_keeps_ack_for_retransmit() {
        let mut transfers = HashMap::new();
        let destination = SessionDestination::new_unchecked("127.0.0.1", 69);
        let src: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let key = TftpTransferKey::new(src, &destination).expect("transfer key");
        transfers.insert(
            key.clone(),
            TftpTransferState::Write {
                filename: "upload.bin".to_string(),
                next_block_expected: 1,
                bytes_received: 0,
                last_ack: nettrap_proto_tftp::TftpPacket::Ack { block: 0 },
                upload_file: None,
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
    fn tftp_write_state_rejects_block_zero_as_invalid() {
        let mut transfers = HashMap::new();
        let destination = SessionDestination::new_unchecked("127.0.0.1", 69);
        let src: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let key = TftpTransferKey::new(src, &destination).expect("transfer key");
        transfers.insert(
            key.clone(),
            TftpTransferState::Write {
                filename: "upload.bin".to_string(),
                next_block_expected: 1,
                bytes_received: 0,
                last_ack: nettrap_proto_tftp::TftpPacket::Ack { block: 0 },
                upload_file: None,
                complete: false,
                last_activity: Instant::now(),
            },
        );

        let responses = handle_tftp_write_data(
            &mut transfers,
            &key,
            &nettrap_proto_tftp::TftpHandler::new(),
            0,
            b"bad",
        );

        assert!(matches!(
            responses.as_slice(),
            [nettrap_proto_tftp::TftpPacket::Error { code: 4, .. }]
        ));
        assert!(transfers.contains_key(&key));
    }

    #[test]
    fn tftp_read_ack_uses_active_read_filename() {
        let mut transfers = HashMap::new();
        let destination = SessionDestination::new_unchecked("127.0.0.1", 69);
        let src: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let key = TftpTransferKey::new(src, &destination).expect("transfer key");
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
        let destination = SessionDestination::new_unchecked("127.0.0.1", 69);
        let src: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let key = TftpTransferKey::new(src, &destination).expect("transfer key");
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
        let destination = SessionDestination::new_unchecked("127.0.0.1", 69);

        for i in 0..MAX_TFTP_ACTIVE_TRANSFERS {
            let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40000 + i as u16);
            transfers.insert(
                TftpTransferKey::new(src, &destination).expect("transfer key"),
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
        )
        .expect("transfer key");
        let new_key = TftpTransferKey::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53000),
            &destination,
        )
        .expect("transfer key");

        assert!(!tftp_transfer_limit_reached(&transfers, &existing));
        assert!(tftp_transfer_limit_reached(&transfers, &new_key));
    }

    #[test]
    fn tftp_transfer_prune_releases_capacity() {
        let mut transfers = HashMap::new();
        let destination = SessionDestination::new_unchecked("127.0.0.1", 69);
        let expired = Instant::now() - TFTP_TRANSFER_TIMEOUT - Duration::from_secs(1);
        let key = TftpTransferKey::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53000),
            &destination,
        )
        .expect("transfer key");
        transfers.insert(
            key,
            TftpTransferState::Write {
                filename: "upload.bin".to_string(),
                next_block_expected: 1,
                bytes_received: 0,
                last_ack: nettrap_proto_tftp::TftpPacket::Ack { block: 0 },
                upload_file: None,
                complete: false,
                last_activity: expired,
            },
        );

        prune_tftp_transfers(&mut transfers);

        assert!(transfers.is_empty());
    }

    #[test]
    fn tftp_write_state_persists_upload_to_prefixed_path() {
        let root = std::env::temp_dir().join(format!("nettrap-tftp-upload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");

        let handler = nettrap_proto_tftp::TftpHandler::new()
            .with_root_dir(&root)
            .expect("valid TFTP root")
            .with_upload_prefix("incoming")
            .expect("valid upload prefix");
        let upload_file = handler
            .open_upload_file("firmware.bin")
            .expect("open upload file");

        let mut transfers = HashMap::new();
        let destination = SessionDestination::new_unchecked("127.0.0.1", 69);
        let src: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let key = TftpTransferKey::new(src, &destination).expect("transfer key");
        transfers.insert(
            key.clone(),
            TftpTransferState::Write {
                filename: "firmware.bin".to_string(),
                next_block_expected: 1,
                bytes_received: 0,
                last_ack: nettrap_proto_tftp::TftpPacket::Ack { block: 0 },
                upload_file,
                complete: false,
                last_activity: Instant::now(),
            },
        );

        let responses = handle_tftp_write_data(&mut transfers, &key, &handler, 1, b"payload");

        assert!(matches!(
            responses.as_slice(),
            [nettrap_proto_tftp::TftpPacket::Ack { block: 1 }]
        ));
        let path = root
            .join(std::path::PathBuf::from("incoming"))
            .join("firmware.bin");
        assert_eq!(
            std::fs::read(&path).expect("read uploaded file"),
            b"payload"
        );
        match transfers.get(&key) {
            Some(TftpTransferState::Write { upload_file, .. }) => {
                assert!(
                    upload_file.is_none(),
                    "completed upload file must be closed"
                );
            }
            other => panic!("expected retained write transfer state, got {other:?}"),
        }

        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[tokio::test]
    async fn malformed_tftp_datagram_records_received_bytes() {
        let tracker = Arc::new(SessionTracker::new());
        let flow_manager = Arc::new(nettrap_flow::FlowManager::default());
        let ctx = ListenerContext::builder()
            .name("tftp")
            .port(69)
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    attribution: None,
                    attribution_timeout: std::time::Duration::from_millis(5000),
                    pcap_writer: None,
                    nbi_collector: Arc::new(
                        crate::nbi::NbiCollector::new(None).expect("collector should build"),
                    ),
                    session_tracker: Arc::clone(&tracker),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::clone(&flow_manager),
                }),
            )
            .expect("listener context should build");
        let bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .expect("bind UDP listener socket");
        let src: SocketAddr = SocketAddr::new(bind_ip, 53000);
        let destination = SessionDestination::new_unchecked(bind_ip.to_string(), 69);
        ctx.register_session(&src, "UDP", Some(destination.clone()));

        handle_tftp(
            &ctx,
            &socket,
            &nettrap_proto_tftp::TftpHandler::new(),
            &Arc::new(Mutex::new(HashMap::new())),
            UdpPacket {
                output_path: None,
                query_data: b"\x00",
                src: &src,
                destination: &destination,
                len: 1,
            },
        )
        .await;

        let flow_key = nettrap_core::prelude::FlowKey::from_five_tuple(
            &nettrap_core::prelude::FiveTuple::new(
                src.ip(),
                bind_ip,
                src.port(),
                destination.port(),
                nettrap_core::prelude::Protocol::Udp,
            ),
        );
        let flow = flow_manager.get(&flow_key).expect("flow should exist");
        assert_eq!(flow.metadata.bytes_received, 1);
        assert_eq!(flow.metadata.bytes_sent, 0);
    }
}
