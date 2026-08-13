//! Offline PCAP replay: read a capture file, group it into flows, identify
//! each flow's protocol with the same detector set the live engine uses, and
//! emit Network Behaviour Indicators.
//!
//! NBIs are derived from the *request* (the same way the live path derives
//! them), so we do protocol detection + request parsing rather than invoking
//! stateful handlers whose responses would be discarded. Encrypted flows
//! cannot be replayed and are recorded as TLS indicators, never dropped.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use nettrap_core::prelude::*;
use nettrap_protocols::handlers::nettrap_proto_http;

use crate::nbi::{
    HttpNbiInput, NetworkBehaviorIndicator, dns_nbi, http_nbi, quic_nbi, raw_nbi, tls_nbi,
};
use crate::session::{SessionDestination, normalize_session_ip};

/// Upper bound on distinct flows replayed from one capture.
const MAX_REPLAY_FLOWS: usize = 100_000;
/// Upper bound on concatenated client bytes fed to detection for one flow.
const MAX_REPLAY_FLOW_BYTES: usize = 16 * 1024 * 1024;
/// Upper bound on retained client payload bytes across all replayed flows.
const MAX_REPLAY_TOTAL_PAYLOAD_BYTES: usize = 128 * 1024 * 1024;
/// Upper bound on retained client payload chunks per flow.
const MAX_REPLAY_FLOW_CHUNKS: usize = 4_096;
/// Upper bound on retained client payload chunks across all replayed flows.
const MAX_REPLAY_TOTAL_PAYLOAD_CHUNKS: usize = 100_000;
/// Upper bound on NBIs emitted by one replay operation.
const MAX_REPLAY_EVENTS: usize = 100_000;

const REPLAY_LISTENER: &str = "pcap-replay";

#[derive(Debug, Clone, Copy)]
struct ReplayLimits {
    max_flows: usize,
    max_flow_bytes: usize,
    max_total_payload_bytes: usize,
    max_flow_chunks: usize,
    max_total_payload_chunks: usize,
}

impl Default for ReplayLimits {
    fn default() -> Self {
        Self {
            max_flows: MAX_REPLAY_FLOWS,
            max_flow_bytes: MAX_REPLAY_FLOW_BYTES,
            max_total_payload_bytes: MAX_REPLAY_TOTAL_PAYLOAD_BYTES,
            max_flow_chunks: MAX_REPLAY_FLOW_CHUNKS,
            max_total_payload_chunks: MAX_REPLAY_TOTAL_PAYLOAD_CHUNKS,
        }
    }
}

struct ReplayFlow {
    protocol: Protocol,
    client_ip: IpAddr,
    client_port: u16,
    server_ip: IpAddr,
    server_port: u16,
    /// Capture timestamp of the first packet seen for this flow, so replayed
    /// NBIs preserve when the traffic actually occurred rather than the
    /// wall-clock time of the replay run.
    first_ts: Timestamp,
    /// (is_client_to_server, payload) in capture order.
    packets: Vec<(bool, Bytes)>,
    retained_payload_bytes: usize,
}

/// Canonicalize a 5-tuple so both directions of a flow map to one key.
fn canonical_five_tuple(ft: &FiveTuple) -> FiveTuple {
    let src_ip = canonical_replay_ip(ft.src_ip);
    let dst_ip = canonical_replay_ip(ft.dst_ip);
    let a = (src_ip, ft.src_port);
    let b = (dst_ip, ft.dst_port);
    if a <= b {
        FiveTuple::new(src_ip, dst_ip, ft.src_port, ft.dst_port, ft.protocol)
    } else {
        FiveTuple::new(dst_ip, src_ip, ft.dst_port, ft.src_port, ft.protocol)
    }
}

fn canonical_replay_ip(ip: IpAddr) -> IpAddr {
    normalize_session_ip(ip)
}

fn group_flows(packets: Vec<Packet>) -> Vec<ReplayFlow> {
    group_flows_with_limits(packets, ReplayLimits::default())
}

fn group_flows_with_limits(packets: Vec<Packet>, limits: ReplayLimits) -> Vec<ReplayFlow> {
    let mut flows: Vec<ReplayFlow> = Vec::new();
    let mut index: HashMap<FlowKey, usize> = HashMap::new();
    let mut capped_warned = false;
    let mut payload_capped_warned = false;
    let mut retained_payload_bytes = 0usize;
    let mut retained_payload_chunks = 0usize;

    for pkt in packets {
        let ft = pkt.five_tuple;
        let key = canonical_five_tuple(&ft).to_flow_key();

        let slot = match index.get(&key) {
            Some(&i) => i,
            None => {
                if flows.len() >= limits.max_flows {
                    if !capped_warned {
                        tracing::warn!(
                            "pcap replay flow cap ({}) reached; remaining flows skipped",
                            limits.max_flows
                        );
                        capped_warned = true;
                    }
                    continue;
                }
                // Client = side that opened the connection. Prefer inferred
                // packet direction when the capture supplies it, then a pure
                // SYN; a SYN|ACK means we only saw the server side first.
                // When neither signal is available (mid-stream capture, or
                // UDP) fall back to a port heuristic: the server is the side
                // on the lower / well-known port, so the client is the
                // higher-port endpoint.
                let client_is_src = match pkt.direction {
                    PacketDirection::Outbound => true,
                    PacketDirection::Inbound => false,
                    PacketDirection::Unknown => match pkt.tcp_flags {
                        Some(f) if f.contains(TcpFlags::SYN) && f.contains(TcpFlags::ACK) => false,
                        Some(f) if f.contains(TcpFlags::SYN) => true,
                        _ => ft.src_port >= ft.dst_port,
                    },
                };
                let (client_ip, client_port, server_ip, server_port) = if client_is_src {
                    (ft.src_ip, ft.src_port, ft.dst_ip, ft.dst_port)
                } else {
                    (ft.dst_ip, ft.dst_port, ft.src_ip, ft.src_port)
                };
                flows.push(ReplayFlow {
                    protocol: ft.protocol,
                    client_ip,
                    client_port,
                    server_ip,
                    server_port,
                    first_ts: pkt.timestamp,
                    packets: Vec::new(),
                    retained_payload_bytes: 0,
                });
                index.insert(key, flows.len() - 1);
                flows.len() - 1
            }
        };

        if pkt.payload.is_empty() {
            continue;
        }
        let flow = &mut flows[slot];
        let c2s = match pkt.direction {
            PacketDirection::Outbound => true,
            PacketDirection::Inbound => false,
            PacketDirection::Unknown => {
                ft.src_ip == flow.client_ip && ft.src_port == flow.client_port
            }
        };
        if !c2s {
            continue;
        }

        let Some(flow_room) = limits
            .max_flow_bytes
            .checked_sub(flow.retained_payload_bytes)
        else {
            continue;
        };
        let Some(total_room) = limits
            .max_total_payload_bytes
            .checked_sub(retained_payload_bytes)
        else {
            continue;
        };
        let capped_by_chunks = flow.packets.len() >= limits.max_flow_chunks
            || retained_payload_chunks >= limits.max_total_payload_chunks;
        let take = flow_room.min(total_room).min(pkt.payload.len());
        if take == 0 || capped_by_chunks {
            if !payload_capped_warned {
                tracing::warn!(
                    "pcap replay payload retention cap reached; remaining client payload bytes skipped"
                );
                payload_capped_warned = true;
            }
            continue;
        }

        flow.retained_payload_bytes += take;
        retained_payload_bytes += take;
        retained_payload_chunks += 1;
        flow.packets.push((true, pkt.payload.slice(..take)));
    }

    flows
}

/// Concatenated client→server payload for TCP (one chunk), or one chunk per
/// client datagram for UDP/other. Each chunk capped at MAX_REPLAY_FLOW_BYTES.
fn client_payloads(flow: &ReplayFlow) -> Vec<Vec<u8>> {
    if flow.protocol.is_stream() {
        let mut buf = Vec::new();
        for (c2s, payload) in &flow.packets {
            if !*c2s {
                continue;
            }
            if buf.len() >= MAX_REPLAY_FLOW_BYTES {
                break;
            }
            let room = MAX_REPLAY_FLOW_BYTES - buf.len();
            let take = room.min(payload.len());
            buf.extend_from_slice(&payload[..take]);
        }
        if buf.is_empty() {
            Vec::new()
        } else {
            vec![buf]
        }
    } else {
        flow.packets
            .iter()
            .filter(|(c2s, _)| *c2s)
            .map(|(_, p)| {
                let take = MAX_REPLAY_FLOW_BYTES.min(p.len());
                p[..take].to_vec()
            })
            .collect()
    }
}

fn dns_qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        255 => "ANY".into(),
        other => other.to_string(),
    }
}

/// Minimal, bounds-checked parse of the first DNS question (name + type).
fn parse_dns_question(data: &[u8]) -> Option<(String, String)> {
    if data.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let nscount = u16::from_be_bytes([data[8], data[9]]);
    let arcount = u16::from_be_bytes([data[10], data[11]]);
    if flags & 0x8000 != 0
        || ((flags >> 11) & 0x0f) > 2
        || ancount != 0
        || nscount != 0
        || arcount != 0
    {
        return None;
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    if qdcount != 1 {
        return None;
    }
    let mut pos = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *data.get(pos)? as usize;
        pos = pos.checked_add(1)?;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        if len > 63 {
            return None;
        }
        let end = pos.checked_add(len)?;
        let label = data.get(pos..end)?;
        labels.push(safe_dns_label(label));
        pos = end;
        if labels.len() > 127 {
            return None;
        }
    }
    let _qclass = u16::from_be_bytes([*data.get(pos + 2)?, *data.get(pos + 3)?]);
    let qtype = u16::from_be_bytes([*data.get(pos)?, *data.get(pos + 1)?]);
    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".").to_ascii_lowercase()
    };
    Some((name, dns_qtype_name(qtype)))
}

fn safe_dns_label(label: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(label) {
        return text.to_string();
    }

    use std::fmt::Write as _;

    let mut rendered = String::from("hex:");
    for byte in label {
        let _ = write!(&mut rendered, "{:02x}", byte);
    }
    rendered
}

fn looks_like_tls(chunk: &[u8]) -> bool {
    chunk.len() >= 3 && chunk[0] == 0x16 && chunk[1] == 0x03 && chunk[2] <= 0x04
}

fn dns_tcp_payload(chunk: &[u8]) -> std::result::Result<&[u8], &'static str> {
    if chunk.len() < 2 {
        return Err("truncated DNS-over-TCP length prefix");
    }

    let dlen = u16::from_be_bytes([chunk[0], chunk[1]]) as usize;
    let end = 2usize
        .checked_add(dlen)
        .ok_or("DNS-over-TCP length overflow")?;
    if end > chunk.len() {
        return Err("truncated DNS-over-TCP frame");
    }

    Ok(&chunk[2..end])
}

fn dns_tcp_payloads(chunk: &[u8]) -> std::result::Result<Vec<&[u8]>, &'static str> {
    let mut payloads = Vec::new();
    let mut pos = 0usize;
    while pos < chunk.len() {
        let remaining = &chunk[pos..];
        let payload = dns_tcp_payload(remaining)?;
        let end = pos
            .checked_add(2)
            .and_then(|pos| pos.checked_add(payload.len()))
            .ok_or("DNS-over-TCP length overflow")?;
        payloads.push(payload);
        pos = end;
    }
    Ok(payloads)
}

fn dns_tcp_partial_payload_looks_plausible(chunk: &[u8]) -> bool {
    if chunk.len() < 15 {
        return false;
    }

    let payload = &chunk[2..];
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_query = (flags & 0x8000) == 0;
    let opcode = (flags >> 11) & 0x0f;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    let nscount = u16::from_be_bytes([payload[8], payload[9]]);
    let first_label_len = payload[12];

    is_query
        && opcode <= 2
        && qdcount == 1
        && ancount == 0
        && nscount == 0
        && (1..=63).contains(&first_label_len)
}

fn should_strip_dns_tcp_prefix(
    router: &nettrap_proxy::ProtocolRouter,
    flow: &ReplayFlow,
    payload: &[u8],
) -> bool {
    if flow.server_port == 53 {
        return true;
    }

    router
        .route_tcp(payload, flow.server_port)
        .as_ref()
        .is_some_and(|(name, _)| name == "dns")
}

fn replay_chunk_to_nbi(
    router: &nettrap_proxy::ProtocolRouter,
    flow: &ReplayFlow,
    chunk: &[u8],
) -> NetworkBehaviorIndicator {
    // DNS-over-TCP frames carry a 2-byte big-endian length prefix; strip it
    // only after proving the declared frame is present. Port 53 remains an
    // explicit DNS case, while other stream ports only strip when the framed
    // payload itself still routes as DNS. This keeps non-DNS stream protocols
    // intact while still handling DNS-over-TCP on alternate ports.
    if flow.protocol.is_stream() {
        match dns_tcp_payload(chunk) {
            Ok(payload) if should_strip_dns_tcp_prefix(router, flow, payload) => {
                return replay_payload_to_nbi(router, flow, payload);
            }
            Ok(_) => {}
            Err(reason)
                if flow.server_port == 53 || dns_tcp_partial_payload_looks_plausible(chunk) =>
            {
                let destination =
                    SessionDestination::new_unchecked(flow.server_ip.to_string(), flow.server_port);
                let mut nbi = raw_nbi(
                    REPLAY_LISTENER,
                    &flow.client_ip.to_string(),
                    flow.client_port,
                    &destination,
                    chunk.len(),
                    "",
                );
                nbi.add("detected_protocol", "dns");
                nbi.add("note", reason);
                nbi.add("flow_protocol", flow.protocol.to_string());
                nbi.add("client_to_server_bytes", chunk.len().to_string());
                nbi.timestamp = flow.first_ts.to_rfc3339();
                return nbi;
            }
            Err(_) => {}
        }
    }

    replay_payload_to_nbi(router, flow, chunk)
}

fn replay_chunk_to_nbis(
    router: &nettrap_proxy::ProtocolRouter,
    flow: &ReplayFlow,
    chunk: &[u8],
) -> Vec<NetworkBehaviorIndicator> {
    if flow.protocol.is_stream()
        && let Ok(payloads) = dns_tcp_payloads(chunk)
        && payloads.len() > 1
        && payloads
            .first()
            .is_some_and(|payload| should_strip_dns_tcp_prefix(router, flow, payload))
    {
        return payloads
            .into_iter()
            .map(|payload| replay_payload_to_nbi(router, flow, payload))
            .collect();
    }

    vec![replay_chunk_to_nbi(router, flow, chunk)]
}

fn replay_payload_to_nbi(
    router: &nettrap_proxy::ProtocolRouter,
    flow: &ReplayFlow,
    chunk: &[u8],
) -> NetworkBehaviorIndicator {
    let destination =
        SessionDestination::new_unchecked(flow.server_ip.to_string(), flow.server_port);
    let src_ip = flow.client_ip.to_string();
    let src_port = flow.client_port;

    let make_raw = || {
        raw_nbi(
            REPLAY_LISTENER,
            &src_ip,
            src_port,
            &destination,
            chunk.len(),
            "",
        )
    };

    let mut nbi = if looks_like_tls(chunk) {
        let sni = nettrap_protocols::handlers::nettrap_proto_tls::sni_from_handshake(chunk)
            .unwrap_or_default();
        let mut n = tls_nbi(REPLAY_LISTENER, &src_ip, src_port, &destination, &sni);
        n.add("data_length", chunk.len().to_string());
        if let Some((ja3_str, ja3_hash)) =
            nettrap_protocols::handlers::nettrap_proto_tls::ja3::ja3_from_handshake(chunk)
        {
            n.add("ja3", ja3_str);
            n.add("ja3_hash", ja3_hash);
        }
        if let Some(ja4) =
            nettrap_protocols::handlers::nettrap_proto_tls::ja3::ja4_from_handshake(chunk)
        {
            n.add("ja4", ja4);
        }
        n.add("note", "encrypted, not replayed");
        n
    } else {
        let route = if flow.protocol.is_stream() {
            router.route_tcp(chunk, flow.server_port)
        } else {
            router.route_udp(chunk, flow.server_port)
        };
        match route.as_ref().map(|(name, _)| name.as_str()) {
            Some("tls") => {
                let sni = nettrap_protocols::handlers::nettrap_proto_tls::sni_from_handshake(chunk)
                    .unwrap_or_default();
                let mut n = tls_nbi(REPLAY_LISTENER, &src_ip, src_port, &destination, &sni);
                n.add("data_length", chunk.len().to_string());
                if let Some((ja3_str, ja3_hash)) =
                    nettrap_protocols::handlers::nettrap_proto_tls::ja3::ja3_from_handshake(chunk)
                {
                    n.add("ja3", ja3_str);
                    n.add("ja3_hash", ja3_hash);
                }
                if let Some(ja4) =
                    nettrap_protocols::handlers::nettrap_proto_tls::ja3::ja4_from_handshake(chunk)
                {
                    n.add("ja4", ja4);
                }
                n.add("note", "encrypted, not replayed");
                n
            }
            Some("http") => match nettrap_proto_http::HttpRequest::parse(chunk) {
                Ok(Some(req)) => {
                    let host = req.host.as_deref().unwrap_or("");
                    let mut nbi = http_nbi(HttpNbiInput {
                        listener: REPLAY_LISTENER,
                        src_ip: &src_ip,
                        src_port,
                        destination: &destination,
                        method: &req.method,
                        uri: &req.uri,
                        host,
                        user_agent: req.user_agent.as_deref().unwrap_or(""),
                        body_len: req.body.len(),
                    });
                    // Match the live listener path: surface IOCs embedded in the
                    // request target and body (exfil domains, C2 IPs, payload
                    // URLs, hashes, emails) so offline PCAP analysis is not blind
                    // to indicators the live engine would have captured.
                    crate::nbi::enrich_nbi_with_iocs(&mut nbi, host, &req.uri, &req.body);
                    nbi
                }
                _ => {
                    let mut n = make_raw();
                    n.add("detected_protocol", "http");
                    n.add("note", "http detected but not parseable");
                    n
                }
            },
            Some("quic") => {
                let sni = nettrap_protocols::handlers::nettrap_proto_quic::QuicHandler::new()
                    .extract_sni(chunk);
                quic_nbi(
                    REPLAY_LISTENER,
                    &src_ip,
                    src_port,
                    &destination,
                    sni.as_deref(),
                    chunk.len(),
                )
            }
            Some("dns") => match parse_dns_question(chunk) {
                Some((domain, qtype)) => dns_nbi(
                    REPLAY_LISTENER,
                    &src_ip,
                    src_port,
                    &destination,
                    &domain,
                    &qtype,
                ),
                None => {
                    let mut n = make_raw();
                    n.add("detected_protocol", "dns");
                    n
                }
            },
            Some(other) => {
                let mut n = make_raw();
                n.add("detected_protocol", other);
                n
            }
            None => {
                let mut n = make_raw();
                n.add("note", "no protocol detected");
                n
            }
        }
    };

    nbi.add("flow_protocol", flow.protocol.to_string());
    nbi.add("client_to_server_bytes", chunk.len().to_string());
    nbi.timestamp = flow.first_ts.to_rfc3339();
    nbi
}

pub(crate) fn replay_pcap(
    input: &Path,
    requested_output: Option<&Path>,
) -> crate::Result<(PathBuf, usize)> {
    let packets = nettrap_pcap::PcapReader::new(input)
        .read_file()
        .map_err(|e| {
            crate::Error::Other(format!("Failed to read PCAP '{}': {}", input.display(), e))
        })?;

    let flows = group_flows(packets);
    let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);

    let mut events: Vec<NetworkBehaviorIndicator> = Vec::new();
    'flows: for flow in &flows {
        if events.len() >= MAX_REPLAY_EVENTS {
            tracing::warn!(
                "pcap replay event cap ({}) reached; remaining flows skipped",
                MAX_REPLAY_EVENTS
            );
            break;
        }
        let chunks = client_payloads(flow);
        if chunks.is_empty() {
            let destination =
                SessionDestination::new_unchecked(flow.server_ip.to_string(), flow.server_port);
            let mut n = raw_nbi(
                REPLAY_LISTENER,
                &flow.client_ip.to_string(),
                flow.client_port,
                &destination,
                0,
                "",
            );
            n.add("flow_protocol", flow.protocol.to_string());
            n.add(
                "note",
                "no client payload (server-initiated or handshake-only)",
            );
            n.timestamp = flow.first_ts.to_rfc3339();
            events.push(n);
            continue;
        }
        for chunk in chunks {
            if events.len() >= MAX_REPLAY_EVENTS {
                tracing::warn!(
                    "pcap replay event cap ({}) reached; remaining chunks skipped",
                    MAX_REPLAY_EVENTS
                );
                break 'flows;
            }
            for nbi in replay_chunk_to_nbis(&router, flow, &chunk) {
                if events.len() >= MAX_REPLAY_EVENTS {
                    tracing::warn!(
                        "pcap replay event cap ({}) reached; remaining chunks skipped",
                        MAX_REPLAY_EVENTS
                    );
                    break 'flows;
                }
                events.push(nbi);
            }
        }
    }

    events.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));

    let format = requested_output
        .and_then(super::infer_report_format_from_path)
        .unwrap_or(crate::output::ExportFormat::Jsonl);
    let output_path = requested_output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| derived_replay_output_path(input, format));

    crate::output::export_nbis(&events, format, &output_path)
        .map_err(|e| crate::Error::Other(format!("Failed to write replay output: {}", e)))?;

    Ok((output_path, events.len()))
}

fn derived_replay_output_path(
    input: &Path,
    format: crate::output::ExportFormat,
) -> std::path::PathBuf {
    let derived = input.with_extension(format.extension());
    if derived != input {
        return derived;
    }

    let mut file_name = input
        .file_stem()
        .map(std::ffi::OsString::from)
        .unwrap_or_else(|| std::ffi::OsString::from("output"));
    file_name.push(".generated.");
    file_name.push(format.extension());

    input
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(file_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ft(s: [u8; 4], sp: u16, d: [u8; 4], dp: u16, proto: Protocol) -> FiveTuple {
        FiveTuple::new(
            IpAddr::V4(std::net::Ipv4Addr::from(s)),
            IpAddr::V4(std::net::Ipv4Addr::from(d)),
            sp,
            dp,
            proto,
        )
    }

    #[test]
    fn group_flows_merges_bidirectional_tcp_into_one() {
        let c2s = Packet::new(
            ft([10, 0, 0, 1], 5000, [1, 1, 1, 1], 80, Protocol::Tcp),
            PacketDirection::Outbound,
            Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n"),
        );
        let s2c = Packet::new(
            ft([1, 1, 1, 1], 80, [10, 0, 0, 1], 5000, Protocol::Tcp),
            PacketDirection::Inbound,
            Bytes::from_static(b"HTTP/1.1 200 OK\r\n\r\n"),
        );
        let flows = group_flows(vec![c2s, s2c]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].client_port, 5000);
        assert_eq!(flows[0].server_port, 80);
        let chunks = client_payloads(&flows[0]);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].starts_with(b"GET / HTTP/1.1"));
    }

    #[test]
    fn group_flows_uses_port_heuristic_for_midstream_capture() {
        // Capture starts mid-stream: first packet is server->client, no SYN.
        let s2c = Packet::new(
            ft([1, 1, 1, 1], 80, [10, 0, 0, 1], 50000, Protocol::Tcp),
            PacketDirection::Unknown,
            Bytes::from_static(b"HTTP/1.1 200 OK\r\n\r\n"),
        );
        let c2s = Packet::new(
            ft([10, 0, 0, 1], 50000, [1, 1, 1, 1], 80, Protocol::Tcp),
            PacketDirection::Unknown,
            Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n"),
        );
        let flows = group_flows(vec![s2c, c2s]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].client_port, 50000);
        assert_eq!(flows[0].server_port, 80);
        let chunks = client_payloads(&flows[0]);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].starts_with(b"GET / HTTP/1.1"));
    }

    #[test]
    fn group_flows_uses_packet_direction_for_high_port_dns_flow() {
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01,
        ];
        let response = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01,
        ];
        let c2s = Packet::new(
            ft([10, 0, 0, 1], 5000, [1, 1, 1, 1], 5353, Protocol::Tcp),
            PacketDirection::Outbound,
            Bytes::from(query),
        );
        let s2c = Packet::new(
            ft([1, 1, 1, 1], 5353, [10, 0, 0, 1], 5000, Protocol::Tcp),
            PacketDirection::Inbound,
            Bytes::from(response),
        );

        let flows = group_flows(vec![s2c, c2s]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].client_port, 5000);
        assert_eq!(flows[0].server_port, 5353);
        let chunks = client_payloads(&flows[0]);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].starts_with(&[0x12, 0x34]));
    }

    #[test]
    fn group_flows_caps_retained_client_payload_bytes() {
        let limits = ReplayLimits {
            max_flows: 10,
            max_flow_bytes: 5,
            max_total_payload_bytes: 5,
            max_flow_chunks: 10,
            max_total_payload_chunks: 10,
        };
        let pkt = Packet::new(
            ft([10, 0, 0, 1], 5000, [1, 1, 1, 1], 80, Protocol::Tcp),
            PacketDirection::Outbound,
            Bytes::from_static(b"abcdef"),
        );

        let flows = group_flows_with_limits(vec![pkt], limits);
        let chunks = client_payloads(&flows[0]);

        assert_eq!(flows[0].retained_payload_bytes, 5);
        assert_eq!(chunks, vec![b"abcde".to_vec()]);
    }

    #[test]
    fn group_flows_canonicalizes_ipv4_mapped_addresses() {
        let c2s = Packet::new(
            FiveTuple::new(
                IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V6(std::net::Ipv6Addr::from([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 10,
                ])),
                5000,
                80,
                Protocol::Tcp,
            ),
            PacketDirection::Outbound,
            Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n"),
        );
        let s2c = Packet::new(
            FiveTuple::new(
                IpAddr::V6(std::net::Ipv6Addr::from([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 10,
                ])),
                IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                80,
                5000,
                Protocol::Tcp,
            ),
            PacketDirection::Inbound,
            Bytes::from_static(b"HTTP/1.1 200 OK\r\n\r\n"),
        );

        let flows = group_flows(vec![c2s, s2c]);
        assert_eq!(flows.len(), 1);
        assert_eq!(
            flows[0].client_ip,
            IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(
            flows[0].server_ip,
            IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10))
        );
    }

    #[test]
    fn group_flows_caps_retained_client_payload_chunks() {
        let limits = ReplayLimits {
            max_flows: 10,
            max_flow_bytes: 100,
            max_total_payload_bytes: 100,
            max_flow_chunks: 2,
            max_total_payload_chunks: 10,
        };
        let packets = (0..3)
            .map(|idx| {
                Packet::new(
                    ft([10, 0, 0, 1], 5000, [1, 1, 1, 1], 53, Protocol::Udp),
                    PacketDirection::Outbound,
                    Bytes::from(vec![b'a' + idx]),
                )
            })
            .collect();

        let flows = group_flows_with_limits(packets, limits);
        let chunks = client_payloads(&flows[0]);

        assert_eq!(flows[0].retained_payload_bytes, 2);
        assert_eq!(chunks, vec![b"a".to_vec(), b"b".to_vec()]);
    }

    #[test]
    fn replay_preserves_capture_timestamp() {
        let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
        let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid ts");
        let mut pkt = Packet::new(
            ft([10, 0, 0, 1], 5000, [1, 1, 1, 1], 80, Protocol::Tcp),
            PacketDirection::Outbound,
            Bytes::from_static(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"),
        );
        pkt.timestamp = ts;
        let flows = group_flows(vec![pkt]);
        let nbi = replay_chunk_to_nbi(&router, &flows[0], &client_payloads(&flows[0])[0]);
        assert_eq!(
            nbi.timestamp,
            ts.to_rfc3339(),
            "replayed NBI must carry the capture time, not replay time"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replay_pcap_reads_non_utf8_input_paths() {
        use std::os::unix::ffi::OsStringExt;

        let root = std::env::temp_dir().join(format!(
            "nettrap-replay-nonutf8-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create temp root");
        let input = root.join(std::ffi::OsString::from_vec(b"capture-\xff.pcap".to_vec()));
        let output = root.join("events.jsonl");
        let writer = nettrap_pcap::PcapWriter::new(&input).expect("valid pcap path");
        writer.open().expect("pcap writer should open");
        writer
            .write_packet(&Packet::new(
                ft([10, 0, 0, 1], 5000, [1, 1, 1, 1], 80, Protocol::Tcp),
                PacketDirection::Outbound,
                Bytes::from_static(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"),
            ))
            .expect("packet should write");
        writer.close().expect("pcap writer should close");

        let (actual_output, event_count) =
            replay_pcap(&input, Some(&output)).expect("replay should read non-UTF8 path");

        assert_eq!(actual_output, output);
        assert_eq!(event_count, 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn dns_over_tcp_length_prefix_is_stripped() {
        let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
        // 2-byte big-endian length prefix + a DNS query for example.com A.
        let mut msg = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        msg.push(7);
        msg.extend_from_slice(b"example");
        msg.push(3);
        msg.extend_from_slice(b"com");
        msg.push(0);
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&msg);

        let flow = ReplayFlow {
            protocol: Protocol::Tcp,
            client_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            client_port: 5000,
            server_ip: IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            server_port: 53,
            first_ts: nettrap_core::prelude::now(),
            packets: Vec::new(),
            retained_payload_bytes: 0,
        };
        let nbi = replay_chunk_to_nbi(&router, &flow, &framed);
        assert_eq!(nbi.protocol, "DNS");
        assert_eq!(
            nbi.indicators.get("domain").map(String::as_str),
            Some("example.com")
        );
    }

    #[test]
    fn dns_over_tcp_multiple_frames_emit_multiple_nbis() {
        let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
        let mut first = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        first.push(7);
        first.extend_from_slice(b"example");
        first.push(3);
        first.extend_from_slice(b"com");
        first.push(0);
        first.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let mut second = vec![0x56, 0x78, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        second.push(7);
        second.extend_from_slice(b"malware");
        second.push(4);
        second.extend_from_slice(b"test");
        second.push(0);
        second.extend_from_slice(&[0x00, 0x1c, 0x00, 0x01]);

        let mut chunk = (first.len() as u16).to_be_bytes().to_vec();
        chunk.extend_from_slice(&first);
        chunk.extend_from_slice(&(second.len() as u16).to_be_bytes());
        chunk.extend_from_slice(&second);

        let flow = ReplayFlow {
            protocol: Protocol::Tcp,
            client_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            client_port: 5000,
            server_ip: IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            server_port: 53,
            first_ts: nettrap_core::prelude::now(),
            packets: Vec::new(),
            retained_payload_bytes: 0,
        };

        let nbis = replay_chunk_to_nbis(&router, &flow, &chunk);

        assert_eq!(nbis.len(), 2);
        assert_eq!(nbis[0].protocol, "DNS");
        assert_eq!(nbis[1].protocol, "DNS");
        assert_eq!(
            nbis[0].indicators.get("domain").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(
            nbis[1].indicators.get("domain").map(String::as_str),
            Some("malware.test")
        );
        assert_eq!(
            nbis[1].indicators.get("query_type").map(String::as_str),
            Some("AAAA")
        );
    }

    #[test]
    fn dns_over_tcp_length_prefix_is_stripped_on_non_53_port() {
        let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
        let mut msg = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        msg.push(7);
        msg.extend_from_slice(b"example");
        msg.push(3);
        msg.extend_from_slice(b"com");
        msg.push(0);
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&msg);

        let flow = ReplayFlow {
            protocol: Protocol::Tcp,
            client_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            client_port: 5000,
            server_ip: IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            server_port: 5353,
            first_ts: nettrap_core::prelude::now(),
            packets: Vec::new(),
            retained_payload_bytes: 0,
        };

        let nbi = replay_chunk_to_nbi(&router, &flow, &framed);
        assert_eq!(nbi.protocol, "DNS");
        assert_eq!(
            nbi.indicators.get("domain").map(String::as_str),
            Some("example.com")
        );
    }

    #[test]
    fn truncated_dns_over_tcp_frame_is_reported_as_raw() {
        let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
        let flow = ReplayFlow {
            protocol: Protocol::Tcp,
            client_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            client_port: 5000,
            server_ip: IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            server_port: 53,
            first_ts: nettrap_core::prelude::now(),
            packets: Vec::new(),
            retained_payload_bytes: 0,
        };
        let nbi = replay_chunk_to_nbi(&router, &flow, &[0x00, 0x20, 0x12, 0x34]);

        assert_eq!(nbi.protocol, "RAW");
        assert_eq!(
            nbi.indicators.get("detected_protocol").map(String::as_str),
            Some("dns")
        );
        assert_eq!(
            nbi.indicators.get("note").map(String::as_str),
            Some("truncated DNS-over-TCP frame")
        );
    }

    #[test]
    fn truncated_dns_over_tcp_frame_on_alternate_port_is_reported_as_raw() {
        let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
        let flow = ReplayFlow {
            protocol: Protocol::Tcp,
            client_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            client_port: 5000,
            server_ip: IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            server_port: 5353,
            first_ts: nettrap_core::prelude::now(),
            packets: Vec::new(),
            retained_payload_bytes: 0,
        };

        let framed = vec![
            0x00, 0x20, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7, 0,
        ];

        let nbi = replay_chunk_to_nbi(&router, &flow, &framed);

        assert_eq!(nbi.protocol, "RAW");
        assert_eq!(
            nbi.indicators.get("detected_protocol").map(String::as_str),
            Some("dns")
        );
        assert_eq!(
            nbi.indicators.get("note").map(String::as_str),
            Some("truncated DNS-over-TCP frame")
        );
    }

    #[test]
    fn truncated_dns_over_tcp_frame_on_alternate_port_without_question_is_reported_as_raw() {
        let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
        let flow = ReplayFlow {
            protocol: Protocol::Tcp,
            client_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            client_port: 5000,
            server_ip: IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            server_port: 5353,
            first_ts: nettrap_core::prelude::now(),
            packets: Vec::new(),
            retained_payload_bytes: 0,
        };

        let framed = [
            0x00, 0x10, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7,
        ];

        let nbi = replay_chunk_to_nbi(&router, &flow, &framed);

        assert_eq!(nbi.protocol, "RAW");
        assert_eq!(
            nbi.indicators.get("detected_protocol").map(String::as_str),
            Some("dns")
        );
        assert_eq!(
            nbi.indicators.get("note").map(String::as_str),
            Some("truncated DNS-over-TCP frame")
        );
    }

    #[test]
    fn parse_dns_question_extracts_name_and_type() {
        // header (id, flags, qd=1, an=0, ns=0, ar=0) + example.com A
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q.push(7);
        q.extend_from_slice(b"example");
        q.push(3);
        q.extend_from_slice(b"com");
        q.push(0);
        q.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        q.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
        let (name, qtype) = parse_dns_question(&q).expect("question must parse");
        assert_eq!(name, "example.com");
        assert_eq!(qtype, "A");
    }

    #[test]
    fn parse_dns_question_lowercases_ascii_labels() {
        // header (id, flags, qd=1, an=0, ns=0, ar=0) + EVIL.Example.COM A
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q.push(4);
        q.extend_from_slice(b"EVIL");
        q.push(7);
        q.extend_from_slice(b"Example");
        q.push(3);
        q.extend_from_slice(b"COM");
        q.push(0);
        q.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        q.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        let (name, qtype) = parse_dns_question(&q).expect("question must parse");

        assert_eq!(name, "evil.example.com");
        assert_eq!(qtype, "A");
    }

    #[test]
    fn parse_dns_question_preserves_non_utf8_labels_as_hex() {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q.push(3);
        q.extend_from_slice(b"www");
        q.push(2);
        q.extend_from_slice(&[0xff, 0x00]);
        q.push(3);
        q.extend_from_slice(b"com");
        q.push(0);
        q.extend_from_slice(&[0x00, 0x01]);
        q.extend_from_slice(&[0x00, 0x01]);

        let (name, qtype) = parse_dns_question(&q).expect("question must parse");

        assert_eq!(name, "www.hex:ff00.com");
        assert_eq!(qtype, "A");
    }

    #[test]
    fn parse_dns_question_rejects_truncated_input() {
        assert!(parse_dns_question(&[0u8; 4]).is_none());
        assert!(parse_dns_question(&[0u8; 12]).is_none()); // qd=0

        let missing_qclass = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1,
        ];
        assert!(parse_dns_question(&missing_qclass).is_none());
    }

    #[test]
    fn parse_dns_question_rejects_malformed_question_count_and_labels() {
        let two_questions = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
        ];
        assert!(parse_dns_question(&two_questions).is_none());

        let mut overlong_label = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 64];
        overlong_label.extend(std::iter::repeat_n(b'a', 64));
        overlong_label.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(parse_dns_question(&overlong_label).is_none());
    }

    #[test]
    fn parse_dns_question_rejects_responses_and_resource_sections() {
        let response = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
        ];
        assert!(parse_dns_question(&response).is_none());

        let answer_count = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 1, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
        ];
        assert!(parse_dns_question(&answer_count).is_none());
    }

    fn client_hello_with_sni(hostname: &[u8]) -> Vec<u8> {
        let mut extension = Vec::new();
        let sni_ext_len = 2 + 1 + 2 + hostname.len();
        extension.extend_from_slice(&0x0000u16.to_be_bytes());
        extension.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        extension.extend_from_slice(&((1 + 2 + hostname.len()) as u16).to_be_bytes());
        extension.push(0);
        extension.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        extension.extend_from_slice(hostname);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
        body.extend_from_slice(&extension);

        let handshake_len = body.len();
        let mut record_body = vec![
            0x01,
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ];
        record_body.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(record_body.len() as u16).to_be_bytes());
        record.extend_from_slice(&record_body);
        record
    }

    fn quic_initial_packet(payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0xc3, 0, 0, 0, 1, 0, 0, 0];
        write_quic_varint(4 + payload.len(), &mut packet);
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(payload);
        packet
    }

    fn write_quic_varint(value: usize, out: &mut Vec<u8>) {
        if value < 64 {
            out.push(value as u8);
            return;
        }
        out.push(0x40 | ((value >> 8) as u8));
        out.push(value as u8);
    }

    #[test]
    fn tls_chunk_is_recorded_not_dropped() {
        let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
        let flow = ReplayFlow {
            protocol: Protocol::Tcp,
            client_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            client_port: 5000,
            server_ip: IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            server_port: 443,
            first_ts: nettrap_core::prelude::now(),
            packets: Vec::new(),
            retained_payload_bytes: 0,
        };
        let nbi = replay_chunk_to_nbi(&router, &flow, &[0x16, 0x03, 0x01, 0x00, 0x10]);
        assert_eq!(nbi.protocol, "TLS");
        assert_eq!(
            nbi.indicators.get("note").map(String::as_str),
            Some("encrypted, not replayed")
        );
    }

    #[test]
    fn tls_chunk_with_sni_is_recorded_with_sni() {
        let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
        let flow = ReplayFlow {
            protocol: Protocol::Tcp,
            client_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            client_port: 5000,
            server_ip: IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            server_port: 443,
            first_ts: nettrap_core::prelude::now(),
            packets: Vec::new(),
            retained_payload_bytes: 0,
        };
        let chunk = client_hello_with_sni(b"example.com");

        let nbi = replay_chunk_to_nbi(&router, &flow, &chunk);

        assert_eq!(nbi.protocol, "TLS");
        assert_eq!(
            nbi.indicators.get("sni").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(
            nbi.indicators.get("note").map(String::as_str),
            Some("encrypted, not replayed")
        );
    }

    #[test]
    fn tls_chunk_with_sni_is_recorded_with_fingerprints() {
        let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
        let flow = ReplayFlow {
            protocol: Protocol::Tcp,
            client_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            client_port: 5000,
            server_ip: IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            server_port: 443,
            first_ts: nettrap_core::prelude::now(),
            packets: Vec::new(),
            retained_payload_bytes: 0,
        };
        let chunk = client_hello_with_sni(b"example.com");

        let nbi = replay_chunk_to_nbi(&router, &flow, &chunk);

        assert_eq!(
            nbi.indicators.get("sni").map(String::as_str),
            Some("example.com")
        );
        assert!(nbi.indicators.contains_key("data_length"));
        assert!(nbi.indicators.contains_key("ja3"));
        assert!(nbi.indicators.contains_key("ja3_hash"));
        assert!(nbi.indicators.contains_key("ja4"));
    }

    #[test]
    fn quic_chunk_with_embedded_tls_hello_is_recorded_with_sni() {
        let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
        let flow = ReplayFlow {
            protocol: Protocol::Udp,
            client_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            client_port: 5000,
            server_ip: IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            server_port: 443,
            first_ts: nettrap_core::prelude::now(),
            packets: Vec::new(),
            retained_payload_bytes: 0,
        };
        let chunk = quic_initial_packet(&client_hello_with_sni(b"example.com"));
        let expected_len = chunk.len().to_string();

        let nbi = replay_chunk_to_nbi(&router, &flow, &chunk);

        assert_eq!(nbi.protocol, "QUIC");
        assert_eq!(
            nbi.indicators.get("sni").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(
            nbi.indicators.get("data_length").map(String::as_str),
            Some(expected_len.as_str())
        );
    }
}
