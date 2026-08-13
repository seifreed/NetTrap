//! Distributed deployment support for NetTrap.

pub use nettrap_distributed::{
    EventFanout, EventSink, HttpSink, NodeIdentity, SinkSendResult, bind_health_server,
    bind_metrics_server, build_event_fanout, run_heartbeat, run_heartbeat_with_now,
    serve_health_server, serve_metrics_server,
};
