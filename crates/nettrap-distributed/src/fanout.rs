//! Multi-sink event fanout for the distributed subsystem.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use parking_lot::RwLock;

use nettrap_core::DistributedConfig;
use nettrap_core::health::HealthSink;

use crate::{
    DISTRIBUTED_EXPORT_FAILURE_LIMIT, Error, EventSink, HttpSink, Result, SinkDeliveryState,
    SyslogUdpSink, TcpSink,
};

/// Sends events to multiple sinks simultaneously
pub struct EventFanout {
    sinks: Vec<Box<dyn EventSink>>,
    runtime_health: RwLock<FanoutRuntimeHealth>,
    consecutive_failures: AtomicU32,
    pub(crate) pending_records: parking_lot::Mutex<HashMap<String, EventDeliveryTracker>>,
    terminally_dropped_event_ids: parking_lot::Mutex<HashSet<String>>,
    last_observed_error: RwLock<Option<String>>,
}

#[derive(Debug, Default)]
pub(crate) struct EventDeliveryTracker {
    queued: bool,
    in_flight: bool,
    buffered_by: HashSet<usize>,
    delivered: bool,
    unknown: bool,
    unknown_reported: bool,
}

#[derive(Clone, Default)]
enum FanoutRuntimeHealth {
    #[default]
    None,
    Active(Arc<dyn HealthSink>),
    Retired(Arc<dyn HealthSink>),
}

impl EventFanout {
    pub fn new() -> Self {
        Self {
            sinks: Vec::new(),
            runtime_health: RwLock::new(FanoutRuntimeHealth::None),
            consecutive_failures: AtomicU32::new(0),
            pending_records: parking_lot::Mutex::new(HashMap::new()),
            terminally_dropped_event_ids: parking_lot::Mutex::new(HashSet::new()),
            last_observed_error: RwLock::new(None),
        }
    }

    pub fn add_sink(&mut self, sink: Box<dyn EventSink>) {
        // No logging here: the fanout is built both during config validation
        // (then discarded) and at startup, so logging per add would emit
        // duplicate "registered" lines. The application logs once after build
        // via `sink_names()`.
        self.sinks.push(sink);
    }

    /// Names of the registered sinks, for one-shot startup logging.
    pub fn sink_names(&self) -> Vec<&str> {
        self.sinks.iter().map(|sink| sink.name()).collect()
    }

    pub fn attach_runtime_health(&self, runtime_health: Arc<dyn HealthSink>) {
        *self.runtime_health.write() = FanoutRuntimeHealth::Active(Arc::clone(&runtime_health));
        if let Some(error) = self.last_observed_error.read().clone() {
            runtime_health.set_distributed_export_degraded(&format!(
                "distributed export previously failed before runtime health attachment: {}",
                error
            ));
        } else if self.has_sinks() {
            runtime_health.set_distributed_export_running();
        } else {
            runtime_health.set_distributed_export_disabled();
        }
    }

    pub fn attach_retired_runtime_health(&self, runtime_health: Arc<dyn HealthSink>) {
        *self.runtime_health.write() = FanoutRuntimeHealth::Retired(runtime_health);
        if let Some(error) = self.last_observed_error.read().clone()
            && let FanoutRuntimeHealth::Retired(runtime_health) = self.runtime_health.read().clone()
        {
            runtime_health.set_distributed_export_degraded(&format!(
                "retired distributed export failed while draining backlog: {}",
                error
            ));
        }
    }

    pub fn clear_runtime_health(&self) {
        *self.runtime_health.write() = FanoutRuntimeHealth::None;
        *self.last_observed_error.write() = None;
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    pub fn retire_runtime_health(&self) {
        let mut binding = self.runtime_health.write();
        if let FanoutRuntimeHealth::Active(runtime_health) = &*binding {
            *binding = FanoutRuntimeHealth::Retired(Arc::clone(runtime_health));
        }
    }

    pub fn has_sinks(&self) -> bool {
        !self.sinks.is_empty()
    }

    pub fn pending_events(&self) -> usize {
        self.pending_event_ids().len()
    }

    pub fn note_queued_record(&self, event_id: &str) {
        self.terminally_dropped_event_ids.lock().remove(event_id);
        let mut pending = self.pending_records.lock();
        let tracker = pending.entry(event_id.to_string()).or_default();
        tracker.queued = true;
        if tracker.in_flight {
            return;
        }
        tracker.buffered_by.clear();
        tracker.delivered = false;
        tracker.unknown = false;
        tracker.unknown_reported = false;
    }

    /// Removes a record that was marked queued but never handed to a worker.
    pub fn forget_queued_record(&self, event_id: &str) {
        let mut pending = self.pending_records.lock();
        if pending
            .get(event_id)
            .is_some_and(|tracker| tracker.queued && !tracker.in_flight)
        {
            pending.remove(event_id);
        }
    }

    pub fn note_send_started(&self, event_id: &str) {
        let mut pending = self.pending_records.lock();
        let tracker = pending.entry(event_id.to_string()).or_default();
        tracker.queued = false;
        tracker.in_flight = true;
    }

    pub fn note_dequeued_record(&self, event_id: &str) -> SendCompletion {
        let mut pending = self.pending_records.lock();
        let Some(tracker) = pending.get_mut(event_id) else {
            return SendCompletion::default();
        };
        tracker.queued = false;
        tracker.in_flight = false;
        let became_unknown = if tracker.unknown && !tracker.unknown_reported {
            tracker.unknown_reported = true;
            true
        } else {
            false
        };
        let final_loss = Self::finalize_tracker_if_resolved(&mut pending, event_id);
        SendCompletion {
            final_loss,
            became_unknown,
        }
    }

    pub fn mark_inflight_unknown(&self) -> usize {
        let mut pending = self.pending_records.lock();
        let mut newly_unknown = 0;
        let mut unknown_ids = Vec::new();
        for (event_id, tracker) in pending.iter_mut() {
            if tracker.in_flight {
                tracker.in_flight = false;
                tracker.unknown = true;
                unknown_ids.push(event_id.clone());
                if !tracker.unknown_reported {
                    tracker.unknown_reported = true;
                    newly_unknown += 1;
                }
            }
        }
        for event_id in unknown_ids {
            let _ = Self::finalize_tracker_if_resolved(&mut pending, &event_id);
        }
        newly_unknown
    }

    pub fn consume_unknown_sink_events(&self) -> usize {
        let mut unknown_ids = HashSet::new();
        for sink in &self.sinks {
            unknown_ids.extend(sink.take_unknown_event_ids());
        }
        if unknown_ids.is_empty() {
            return 0;
        }

        let current_buffered = self.current_sink_buffered_event_ids();
        let terminally_dropped = self.terminally_dropped_event_ids.lock().clone();
        let mut pending = self.pending_records.lock();
        Self::sync_pending_records_with_buffers(
            &mut pending,
            &current_buffered,
            &terminally_dropped,
        );

        let mut newly_unknown = 0;
        let mut reported_unknown_ids = Vec::new();
        for event_id in unknown_ids {
            if terminally_dropped.contains(&event_id) {
                continue;
            }
            let tracker = pending.entry(event_id.clone()).or_default();
            tracker.queued = false;
            tracker.in_flight = false;
            tracker.unknown = true;
            if !tracker.unknown_reported {
                tracker.unknown_reported = true;
                newly_unknown += 1;
            }
            reported_unknown_ids.push(event_id);
        }
        for event_id in reported_unknown_ids {
            let _ = Self::finalize_tracker_if_resolved(&mut pending, &event_id);
        }
        newly_unknown
    }

    pub fn drop_queued_records(&self) -> usize {
        let current_buffered = self.current_sink_buffered_event_ids();
        let mut terminally_dropped = self.terminally_dropped_event_ids.lock();
        let mut pending = self.pending_records.lock();
        Self::sync_pending_records_with_buffers(
            &mut pending,
            &current_buffered,
            &terminally_dropped,
        );
        let queued_ids = pending
            .iter()
            .filter_map(|(event_id, tracker)| tracker.queued.then_some(event_id.clone()))
            .collect::<HashSet<_>>();
        let mut lost = 0;
        for event_id in &queued_ids {
            terminally_dropped.insert(event_id.clone());
            if let Some(tracker) = pending.get_mut(event_id) {
                tracker.queued = false;
                tracker.buffered_by.clear();
            }
            lost += usize::from(Self::finalize_tracker_if_resolved(&mut pending, event_id));
        }
        drop(pending);
        drop(terminally_dropped);
        self.purge_buffered_events(&queued_ids);
        self.forget_terminally_dropped_ids(&queued_ids);
        lost
    }

    pub fn drop_pending_records(&self) -> usize {
        let current_buffered = self.current_sink_buffered_event_ids();
        let mut terminally_dropped = self.terminally_dropped_event_ids.lock();
        let mut pending = self.pending_records.lock();
        Self::sync_pending_records_with_buffers(
            &mut pending,
            &current_buffered,
            &terminally_dropped,
        );
        let all_ids = pending.keys().cloned().collect::<HashSet<_>>();
        let mut lost = 0;
        for event_id in &all_ids {
            let count_as_loss = pending.get(event_id).is_some_and(|tracker| {
                !tracker.in_flight
                    && !tracker.unknown
                    && (tracker.queued || !tracker.buffered_by.is_empty())
            });
            if count_as_loss {
                terminally_dropped.insert(event_id.clone());
            }
            if let Some(tracker) = pending.remove(event_id)
                && count_as_loss
                && !tracker.delivered
            {
                lost += 1;
            }
        }
        drop(pending);
        drop(terminally_dropped);
        self.purge_buffered_events(&all_ids);
        self.forget_terminally_dropped_ids(&all_ids);
        lost
    }

    fn pending_event_ids(&self) -> HashSet<String> {
        let current_buffered = self.current_sink_buffered_event_ids();
        let terminally_dropped = self.terminally_dropped_event_ids.lock().clone();
        let mut pending = self.pending_records.lock();
        Self::sync_pending_records_with_buffers(
            &mut pending,
            &current_buffered,
            &terminally_dropped,
        );
        let resolved_ids = pending
            .keys()
            .filter(|event_id| {
                pending.get(*event_id).is_some_and(|tracker| {
                    !tracker.queued
                        && !tracker.in_flight
                        && !tracker.unknown
                        && tracker.buffered_by.is_empty()
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        for event_id in resolved_ids {
            let _ = Self::finalize_tracker_if_resolved(&mut pending, &event_id);
        }
        pending
            .iter()
            .filter_map(|(event_id, tracker)| {
                (tracker.queued || tracker.in_flight || !tracker.buffered_by.is_empty())
                    .then_some(event_id.clone())
            })
            .collect()
    }

    pub fn has_pending_event(&self, event_id: &str) -> bool {
        self.pending_event_ids().contains(event_id)
    }

    pub async fn send(&self, event: &nettrap_core::NetworkBehaviorIndicator) -> FanoutSendOutcome {
        let mut errors = Vec::new();
        let event_id = event.normalized_event_id();
        let mut sink_states = Vec::with_capacity(self.sinks.len());

        for (sink_idx, sink) in self.sinks.iter().enumerate() {
            let result = sink.send(event).await;
            if let Some(error) = result.error {
                let error = format!("Event sink '{}' error: {}", sink.name(), error);
                tracing::warn!("{}", error);
                errors.push(error);
            }
            sink_states.push((sink_idx, result.state));
        }

        {
            let mut pending = self.pending_records.lock();
            let tracker = pending.entry(event_id.clone()).or_default();
            for (sink_idx, state) in sink_states {
                match state {
                    SinkDeliveryState::Delivered => {
                        tracker.delivered = true;
                        tracker.buffered_by.remove(&sink_idx);
                    }
                    SinkDeliveryState::Buffered => {
                        tracker.buffered_by.insert(sink_idx);
                    }
                    SinkDeliveryState::Lost => {
                        tracker.buffered_by.remove(&sink_idx);
                    }
                    SinkDeliveryState::Unknown => {
                        tracker.unknown = true;
                        tracker.buffered_by.remove(&sink_idx);
                    }
                }
            }
            let _ = Self::finalize_tracker_if_resolved(&mut pending, &event_id);
        }

        let error = (!errors.is_empty()).then(|| errors.join("; "));
        self.update_runtime_health(error.clone());
        FanoutSendOutcome { error }
    }

    pub async fn flush_all(&self) -> std::result::Result<(), String> {
        let mut errors = Vec::new();

        for sink in &self.sinks {
            if let Err(e) = sink.flush().await {
                tracing::warn!("Event sink '{}' flush error: {}", sink.name(), e);
                errors.push(format!("Event sink '{}' flush error: {}", sink.name(), e));
            }
        }

        self.consume_unknown_sink_events();
        let result = if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        };
        self.refresh_pending_records_from_buffers();
        self.update_runtime_health(result.clone().err());
        result
    }

    pub async fn flush_stale_batches(&self) -> std::result::Result<bool, String> {
        let mut errors = Vec::new();
        let mut attempted = false;

        for sink in &self.sinks {
            match sink.flush_stale().await {
                Ok(flushed) => attempted |= flushed,
                Err(err) => {
                    tracing::warn!("Event sink '{}' stale flush error: {}", sink.name(), err);
                    errors.push(format!(
                        "Event sink '{}' stale flush error: {}",
                        sink.name(),
                        err
                    ));
                }
            }
        }

        self.consume_unknown_sink_events();
        if errors.is_empty() {
            if attempted {
                self.refresh_pending_records_from_buffers();
                self.update_runtime_health(None);
            }
            Ok(attempted)
        } else {
            let joined = errors.join("; ");
            self.refresh_pending_records_from_buffers();
            self.update_runtime_health(Some(joined.clone()));
            Err(joined)
        }
    }

    fn current_sink_buffered_event_ids(&self) -> Vec<HashSet<String>> {
        self.sinks
            .iter()
            .map(|sink| sink.buffered_event_ids().into_iter().collect())
            .collect()
    }

    fn refresh_pending_records_from_buffers(&self) {
        let current_buffered = self.current_sink_buffered_event_ids();
        let terminally_dropped = self.terminally_dropped_event_ids.lock().clone();
        let mut pending = self.pending_records.lock();
        Self::sync_pending_records_with_buffers(
            &mut pending,
            &current_buffered,
            &terminally_dropped,
        );
        let resolved_ids = pending
            .keys()
            .filter(|event_id| {
                pending.get(*event_id).is_some_and(|tracker| {
                    !tracker.queued
                        && !tracker.in_flight
                        && !tracker.unknown
                        && tracker.buffered_by.is_empty()
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        for event_id in resolved_ids {
            let _ = Self::finalize_tracker_if_resolved(&mut pending, &event_id);
        }
    }

    fn sync_pending_records_with_buffers(
        pending: &mut HashMap<String, EventDeliveryTracker>,
        current_buffered: &[HashSet<String>],
        terminally_dropped: &HashSet<String>,
    ) {
        pending.retain(|event_id, _| !terminally_dropped.contains(event_id));

        for (sink_idx, event_ids) in current_buffered.iter().enumerate() {
            for event_id in event_ids {
                if terminally_dropped.contains(event_id) {
                    continue;
                }
                pending
                    .entry(event_id.clone())
                    .or_default()
                    .buffered_by
                    .insert(sink_idx);
            }
        }

        let event_ids = pending.keys().cloned().collect::<Vec<_>>();
        for event_id in event_ids {
            if terminally_dropped.contains(&event_id) {
                pending.remove(&event_id);
                continue;
            }
            let Some(tracker) = pending.get_mut(&event_id) else {
                continue;
            };

            let previous_buffered = tracker.buffered_by.clone();
            tracker.buffered_by.retain(|sink_idx| {
                current_buffered
                    .get(*sink_idx)
                    .is_some_and(|event_ids| event_ids.contains(&event_id))
            });
            if previous_buffered
                .iter()
                .any(|sink_idx| !tracker.buffered_by.contains(sink_idx))
            {
                tracker.delivered = true;
            }
        }
    }

    fn finalize_tracker_if_resolved(
        pending: &mut HashMap<String, EventDeliveryTracker>,
        event_id: &str,
    ) -> bool {
        let should_remove = pending.get(event_id).is_some_and(|tracker| {
            !tracker.queued
                && !tracker.in_flight
                && tracker.buffered_by.is_empty()
                && (!tracker.unknown || tracker.unknown_reported)
        });
        if !should_remove {
            return false;
        }

        pending
            .remove(event_id)
            .is_some_and(|tracker| !tracker.delivered && !tracker.unknown)
    }

    fn purge_buffered_events(&self, event_ids: &HashSet<String>) {
        if event_ids.is_empty() {
            return;
        }

        for sink in &self.sinks {
            let _ = sink.drop_buffered_events(event_ids);
        }
    }

    fn forget_terminally_dropped_ids(&self, event_ids: &HashSet<String>) {
        if event_ids.is_empty() {
            return;
        }

        self.terminally_dropped_event_ids
            .lock()
            .retain(|event_id| !event_ids.contains(event_id));
    }

    fn update_runtime_health(&self, error: Option<String>) {
        match (self.runtime_health.read().clone(), error) {
            (FanoutRuntimeHealth::None, Some(error)) => {
                *self.last_observed_error.write() = Some(error);
            }
            (FanoutRuntimeHealth::None, None) => {
                *self.last_observed_error.write() = None;
            }
            (FanoutRuntimeHealth::Retired(runtime_health), Some(error)) => {
                *self.last_observed_error.write() = Some(error.clone());
                if self.pending_events() > 0 {
                    runtime_health.set_distributed_export_degraded(&format!(
                        "retired distributed export failed while draining backlog: {}",
                        error
                    ));
                }
            }
            (FanoutRuntimeHealth::Retired(_), None) => {
                *self.last_observed_error.write() = None;
            }
            (FanoutRuntimeHealth::Active(runtime_health), Some(error)) => {
                *self.last_observed_error.write() = Some(error.clone());
                let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
                if failures >= DISTRIBUTED_EXPORT_FAILURE_LIMIT {
                    runtime_health.set_distributed_export_degraded(&format!(
                        "distributed export failed {} consecutive times: {}",
                        DISTRIBUTED_EXPORT_FAILURE_LIMIT, error
                    ));
                }
            }
            (FanoutRuntimeHealth::Active(runtime_health), None) => {
                *self.last_observed_error.write() = None;
                self.consecutive_failures.store(0, Ordering::Relaxed);
                if self.has_sinks() {
                    runtime_health.set_distributed_export_running();
                } else {
                    runtime_health.set_distributed_export_disabled();
                }
            }
        }
    }
}

impl Default for EventFanout {
    fn default() -> Self {
        Self::new()
    }
}

pub struct FanoutSendOutcome {
    pub error: Option<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SendCompletion {
    pub final_loss: bool,
    pub became_unknown: bool,
}

/// Build event fanout from config
pub fn build_event_fanout(config: &DistributedConfig) -> Result<EventFanout> {
    let mut fanout = EventFanout::new();

    for sink_cfg in &config.event_sinks {
        match sink_cfg.sink_type.as_str() {
            "http" | "webhook" | "elasticsearch" | "splunk" => {
                let target = normalize_http_sink_target(&sink_cfg.target)?;
                fanout.add_sink(Box::new(HttpSink::new(
                    target,
                    sink_cfg.auth.clone(),
                    sink_cfg.batch_size,
                    sink_cfg.flush_interval_ms,
                    sink_cfg.request_timeout_ms,
                )));
            }
            "tcp" | "nats" | "logstash" | "fluentd" => {
                fanout.add_sink(Box::new(TcpSink::new(normalize_socket_sink_target(
                    "TCP",
                    &sink_cfg.target,
                )?)));
            }
            "syslog" | "syslog_udp" => {
                fanout.add_sink(Box::new(SyslogUdpSink::new(normalize_socket_sink_target(
                    "syslog",
                    &sink_cfg.target,
                )?)));
            }
            other => {
                return Err(Error::Config(format!(
                    "Unknown distributed event sink type: {}",
                    other
                )));
            }
        }
    }

    Ok(fanout)
}

fn normalize_http_sink_target(target: &str) -> Result<String> {
    let trimmed = target.trim_matches([' ', '\t']);
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return Err(Error::Config(
            "Invalid distributed HTTP sink target: target must not be blank".to_string(),
        ));
    }

    let url = reqwest::Url::parse(trimmed).map_err(|err| {
        Error::Config(format!(
            "Invalid distributed HTTP sink target '{}': {}",
            target, err
        ))
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::Config(format!(
            "Invalid distributed HTTP sink target '{}': unsupported scheme '{}'",
            target,
            url.scheme()
        )));
    }

    Ok(url.to_string())
}

fn normalize_socket_sink_target(kind: &str, target: &str) -> Result<String> {
    let trimmed = target.trim_matches([' ', '\t']);
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return Err(Error::Config(format!(
            "Invalid distributed {} sink target: target must not be blank",
            kind
        )));
    }
    if is_valid_socket_target(trimmed) {
        Ok(match trimmed.parse::<std::net::SocketAddr>() {
            Ok(addr) => normalize_socket_addr_target(addr),
            Err(_) => trimmed.to_string(),
        })
    } else {
        Err(Error::Config(format!(
            "Invalid distributed {} sink target '{}': expected host:port",
            kind, target
        )))
    }
}

fn normalize_socket_addr_target(addr: std::net::SocketAddr) -> String {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            std::net::SocketAddr::new(std::net::IpAddr::V4(ip), addr.port()).to_string()
        }
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or(addr, |mapped| {
                std::net::SocketAddr::new(std::net::IpAddr::V4(mapped), addr.port())
            })
            .to_string(),
    }
}

fn is_valid_socket_target(target: &str) -> bool {
    if let Ok(addr) = target.parse::<std::net::SocketAddr>() {
        return addr.port() != 0;
    }

    let Some((host, port)) = target.rsplit_once(':') else {
        return false;
    };
    !host.trim_matches([' ', '\t']).is_empty()
        && host == host.trim_matches([' ', '\t'])
        && !host.contains(':')
        && !host.chars().any(char::is_whitespace)
        && !host.contains('/')
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}

#[cfg(test)]
mod tests {
    use super::EventFanout;

    #[test]
    fn drop_queued_records_does_not_retain_terminal_ids() {
        let fanout = EventFanout::new();
        fanout.note_queued_record("queued-event");

        assert_eq!(fanout.drop_queued_records(), 1);

        assert!(fanout.pending_records.lock().is_empty());
        assert!(fanout.terminally_dropped_event_ids.lock().is_empty());
    }

    #[test]
    fn drop_pending_records_does_not_retain_terminal_ids() {
        let fanout = EventFanout::new();
        fanout.note_queued_record("pending-event");

        assert_eq!(fanout.drop_pending_records(), 1);

        assert!(fanout.pending_records.lock().is_empty());
        assert!(fanout.terminally_dropped_event_ids.lock().is_empty());
    }

    #[test]
    fn late_queue_marker_preserves_inflight_delivery_state() {
        let fanout = EventFanout::new();
        fanout.note_send_started("started-event");

        fanout.note_queued_record("started-event");

        assert_eq!(fanout.mark_inflight_unknown(), 1);
        let completion = fanout.note_dequeued_record("started-event");
        assert!(!completion.became_unknown);
        assert!(!completion.final_loss);
        assert_eq!(fanout.pending_events(), 0);
    }

    #[test]
    fn late_queue_marker_does_not_reset_delivered_state() {
        let fanout = EventFanout::new();
        fanout.note_send_started("started-event");
        fanout
            .pending_records
            .lock()
            .get_mut("started-event")
            .expect("started event should be tracked")
            .delivered = true;

        fanout.note_queued_record("started-event");

        assert!(!fanout.note_dequeued_record("started-event").final_loss);
        assert_eq!(fanout.pending_events(), 0);
    }

    #[test]
    fn forget_queued_record_keeps_started_events() {
        let fanout = EventFanout::new();
        fanout.note_queued_record("queued-event");
        fanout.note_send_started("started-event");

        fanout.forget_queued_record("queued-event");
        fanout.forget_queued_record("started-event");

        assert!(!fanout.has_pending_event("queued-event"));
        assert!(fanout.has_pending_event("started-event"));
    }

    #[test]
    fn normalize_socket_sink_target_canonicalizes_ipv4_mapped_addresses() {
        let target = super::normalize_socket_sink_target("TCP", "[::ffff:127.0.0.1]:18888")
            .expect("mapped sink target should parse");

        assert_eq!(target, "127.0.0.1:18888");
    }
}
