use serde::{Deserialize, Serialize};

use nettrap_core::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    ProcessStarted(ProcessStartEvent),
    ProcessTerminated(ProcessEndEvent),
    FlowCreated(FlowEvent),
    FlowUpdated(FlowEvent),
    FlowClosed(FlowEvent),
    PacketCaptured(PacketEvent),
    DnsQuery(DnsEvent),
    DnsResponse(DnsEvent),
    HttpRequest(HttpEvent),
    HttpResponse(HttpEvent),
    TlsHandshake(TlsEvent),
    TlsData(TlsEvent),
    PayloadCaptured(PayloadEvent),
    ConnectionAttempt(ConnectionEvent),
    ConnectionClosed(ConnectionEvent),
    DataTransferred(DataEvent),
    IoDetected(IoCEvent),
    Warning(WarningEvent),
    Error(ErrorEvent),
}

impl Event {
    pub fn timestamp(&self) -> Timestamp {
        match self {
            Event::ProcessStarted(e) => e.timestamp,
            Event::ProcessTerminated(e) => e.timestamp,
            Event::FlowCreated(e) => e.timestamp,
            Event::FlowUpdated(e) => e.timestamp,
            Event::FlowClosed(e) => e.timestamp,
            Event::PacketCaptured(e) => e.timestamp,
            Event::DnsQuery(e) => e.timestamp,
            Event::DnsResponse(e) => e.timestamp,
            Event::HttpRequest(e) => e.timestamp,
            Event::HttpResponse(e) => e.timestamp,
            Event::TlsHandshake(e) => e.timestamp,
            Event::TlsData(e) => e.timestamp,
            Event::PayloadCaptured(e) => e.timestamp,
            Event::ConnectionAttempt(e) => e.timestamp,
            Event::ConnectionClosed(e) => e.timestamp,
            Event::DataTransferred(e) => e.timestamp,
            Event::IoDetected(e) => e.timestamp,
            Event::Warning(e) => e.timestamp,
            Event::Error(e) => e.timestamp,
        }
    }

    pub fn event_type(&self) -> &'static str {
        match self {
            Event::ProcessStarted(_) => "process_started",
            Event::ProcessTerminated(_) => "process_terminated",
            Event::FlowCreated(_) => "flow_created",
            Event::FlowUpdated(_) => "flow_updated",
            Event::FlowClosed(_) => "flow_closed",
            Event::PacketCaptured(_) => "packet_captured",
            Event::DnsQuery(_) => "dns_query",
            Event::DnsResponse(_) => "dns_response",
            Event::HttpRequest(_) => "http_request",
            Event::HttpResponse(_) => "http_response",
            Event::TlsHandshake(_) => "tls_handshake",
            Event::TlsData(_) => "tls_data",
            Event::PayloadCaptured(_) => "payload_captured",
            Event::ConnectionAttempt(_) => "connection_attempt",
            Event::ConnectionClosed(_) => "connection_closed",
            Event::DataTransferred(_) => "data_transferred",
            Event::IoDetected(_) => "ioc_detected",
            Event::Warning(_) => "warning",
            Event::Error(_) => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessStartEvent {
    pub timestamp: Timestamp,
    pub process: ProcessInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEndEvent {
    pub timestamp: Timestamp,
    pub pid: ProcessId,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEvent {
    pub timestamp: Timestamp,
    pub flow_id: FlowId,
    pub five_tuple: FiveTuple,
    pub state: FlowState,
    pub metadata: FlowMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEvent {
    pub timestamp: Timestamp,
    pub packet_id: PacketId,
    pub flow_id: FlowId,
    pub five_tuple: FiveTuple,
    pub direction: PacketDirection,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEvent {
    pub timestamp: Timestamp,
    pub flow_id: FlowId,
    pub query: String,
    pub query_type: u16,
    pub response_code: Option<u16>,
    pub answers: Vec<DnsAnswer>,
    pub is_query: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub name: String,
    pub ttl: u32,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpEvent {
    pub timestamp: Timestamp,
    pub flow_id: FlowId,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub status_code: Option<u16>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub headers: std::collections::HashMap<String, String>,
    pub is_request: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsEvent {
    pub timestamp: Timestamp,
    pub flow_id: FlowId,
    pub version: Option<String>,
    pub sni: Option<String>,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub cipher_suite: Option<String>,
    pub alpn: Option<String>,
    pub is_handshake: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadEvent {
    pub timestamp: Timestamp,
    pub flow_id: FlowId,
    pub direction: PacketDirection,
    pub length: usize,
    pub data: Option<Vec<u8>>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEvent {
    pub timestamp: Timestamp,
    pub flow_id: FlowId,
    pub five_tuple: FiveTuple,
    pub process: Option<ProcessInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEvent {
    pub timestamp: Timestamp,
    pub flow_id: FlowId,
    pub direction: PacketDirection,
    pub bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoCEvent {
    pub timestamp: Timestamp,
    pub flow_id: FlowId,
    pub ioc_type: IoCType,
    pub value: String,
    pub confidence: f32,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IoCType {
    Domain,
    IpAddress,
    Url,
    Hash,
    Email,
    FilePath,
    Registry,
    Mutex,
    Mutant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarningEvent {
    pub timestamp: Timestamp,
    pub message: String,
    pub flow_id: Option<FlowId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEvent {
    pub timestamp: Timestamp,
    pub message: String,
    pub flow_id: Option<FlowId>,
    pub recoverable: bool,
}
