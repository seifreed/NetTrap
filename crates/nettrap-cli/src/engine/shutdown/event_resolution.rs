//! Shutdown-time NBI event-source reconciliation.
//!
//! Reconciles the primary JSONL artifact, the in-memory collector snapshot,
//! and the database-backed event store into a single resolved event set, and
//! repairs the primary JSONL when integrity issues or divergence are detected.

use super::ShutdownContext;

pub(crate) async fn resolve_shutdown_events(
    ctx: &ShutdownContext,
) -> Vec<crate::nbi::NetworkBehaviorIndicator> {
    let jsonl_load = ctx
        .nbi_path
        .as_ref()
        .map(|path| crate::output::load_nbis_from_jsonl_detailed(path))
        .unwrap_or_default();
    let jsonl_invalid_lines = jsonl_load.invalid_lines;
    let jsonl_read_error = jsonl_load.read_error.clone();
    let jsonl_events = jsonl_load.events;
    if jsonl_invalid_lines > 0 {
        tracing::warn!(
            "Detected {} invalid NBI JSONL lines during shutdown; considering database fallback",
            jsonl_invalid_lines
        );
    }
    if let Some(error) = &jsonl_read_error {
        tracing::warn!(
            "Failed to read NBI JSONL during shutdown: {}; considering database fallback",
            error
        );
    }

    let collector_snapshot = ctx
        .nbi_collector
        .as_ref()
        .map(|collector| collector.snapshot());
    let db_events = if let Some(ref db) = ctx.database {
        let result = if let Some(run_id) = ctx.run_id.as_deref() {
            db.load_events_for_run(run_id).await
        } else if let Some(node_id) = ctx.database_node_id.as_deref() {
            db.load_events_for_node(node_id).await
        } else {
            db.load_events().await
        };
        match result {
            Ok(events) => events,
            Err(err) => {
                tracing::warn!("Failed to load NBI events from database: {}", err);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    let had_integrity_signals = jsonl_invalid_lines > 0
        || jsonl_read_error.is_some()
        || collector_snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.local_persist_failures > 0);

    let jsonl_event_ids = event_id_set(&jsonl_events);
    let db_event_ids = event_id_set(&db_events);

    let jsonl_payloads = event_payload_map(&jsonl_events);
    let db_payloads = event_payload_map(&db_events);
    let divergent_events = count_payload_divergences(&jsonl_payloads, &db_payloads);
    let jsonl_has_duplicates = has_duplicate_event_ids(&jsonl_events);
    let db_has_duplicates = has_duplicate_event_ids(&db_events);
    let has_duplicate_event_ids = jsonl_has_duplicates || db_has_duplicates;

    if jsonl_events.is_empty() {
        if db_has_duplicates {
            tracing::warn!(
                "Database shutdown events contain duplicate event IDs without JSONL backing; deduplicating database before shutdown"
            );
            merge_event_sources(&jsonl_events, &db_events, false)
        } else {
            db_events
        }
    } else if db_events.is_empty() {
        if jsonl_has_duplicates {
            tracing::warn!(
                "JSONL shutdown events contain duplicate event IDs without a database fallback; deduplicating JSONL before shutdown"
            );
            merge_event_sources(&jsonl_events, &db_events, false)
        } else {
            jsonl_events
        }
    } else if events_match(&jsonl_events, &db_events) {
        if has_duplicate_event_ids {
            tracing::warn!(
                "JSONL and database match structurally but one source contains duplicate event records; deduplicating shutdown events"
            );
            merge_event_sources(&jsonl_events, &db_events, true)
        } else {
            jsonl_events
        }
    } else if jsonl_event_ids == db_event_ids {
        if jsonl_payloads == db_payloads {
            if had_integrity_signals || has_duplicate_event_ids {
                tracing::warn!(
                    "JSONL and database contain the same NBI event IDs but one source contains duplicate event records or other integrity signals; preferring database-backed resolution for shutdown"
                );
                merge_event_sources(&jsonl_events, &db_events, true)
            } else {
                tracing::warn!(
                    "JSONL and database contain the same NBI event set but differ in ordering; preserving JSONL ordering for shutdown"
                );
                jsonl_events
            }
        } else {
            if had_integrity_signals {
                tracing::warn!(
                    "JSONL and database share the same NBI event IDs but {} event payloads diverge; preferring database because shutdown already detected local integrity issues",
                    divergent_events
                );
                merge_event_sources(&jsonl_events, &db_events, true)
            } else {
                tracing::warn!(
                    "JSONL and database share the same NBI event IDs but {} event payloads diverge; preserving JSONL and surfacing the integrity mismatch",
                    divergent_events
                );
                jsonl_events
            }
        }
    } else if db_event_ids.is_superset(&jsonl_event_ids) {
        if divergent_events > 0 {
            if had_integrity_signals {
                tracing::warn!(
                    "Database contains a strict superset of JSONL NBI events (db={}, jsonl={}) but {} shared payloads diverge; preferring database because shutdown already detected local integrity issues",
                    db_events.len(),
                    jsonl_events.len(),
                    divergent_events
                );
                merge_event_sources(&jsonl_events, &db_events, true)
            } else {
                tracing::warn!(
                    "Database contains a strict superset of JSONL NBI events (db={}, jsonl={}) but {} shared payloads diverge; preserving JSONL payloads for shared events and merging database-only events",
                    db_events.len(),
                    jsonl_events.len(),
                    divergent_events
                );
                merge_event_sources(&jsonl_events, &db_events, false)
            }
        } else {
            tracing::warn!(
                "Database contains a strict superset of JSONL NBI events (db={}, jsonl={}); preferring database as the more complete shutdown source",
                db_events.len(),
                jsonl_events.len()
            );
            db_events
        }
    } else if jsonl_event_ids.is_superset(&db_event_ids) {
        if divergent_events > 0 {
            if had_integrity_signals {
                tracing::warn!(
                    "JSONL contains a strict superset of database NBI events (jsonl={}, db={}) but {} shared payloads diverge; preferring database payloads for shared events because shutdown already detected local integrity issues",
                    jsonl_events.len(),
                    db_events.len(),
                    divergent_events
                );
                merge_event_sources(&jsonl_events, &db_events, true)
            } else {
                tracing::warn!(
                    "JSONL contains a strict superset of database NBI events (jsonl={}, db={}) but {} shared payloads diverge; preserving JSONL payloads for shared events",
                    jsonl_events.len(),
                    db_events.len(),
                    divergent_events
                );
                jsonl_events
            }
        } else {
            tracing::warn!(
                "JSONL contains a strict superset of database NBI events (jsonl={}, db={}); preserving JSONL as the more complete shutdown source",
                jsonl_events.len(),
                db_events.len()
            );
            jsonl_events
        }
    } else {
        tracing::warn!(
            "JSONL and database both contain unique NBI events; merging both sources for shutdown integrity{}",
            if had_integrity_signals {
                " after detecting local integrity issues"
            } else {
                ""
            }
        );
        merge_event_sources(&jsonl_events, &db_events, false)
    }
}

pub(crate) fn normalize_event_id(event: &crate::nbi::NetworkBehaviorIndicator) -> String {
    event.normalized_event_id()
}

pub(crate) fn events_match(
    left: &[crate::nbi::NetworkBehaviorIndicator],
    right: &[crate::nbi::NetworkBehaviorIndicator],
) -> bool {
    left.len() == right.len()
        && left.iter().zip(right.iter()).all(|(left, right)| {
            normalize_event_id(left) == normalize_event_id(right)
                && left.content_fingerprint() == right.content_fingerprint()
        })
}

pub(crate) fn event_id_set(
    events: &[crate::nbi::NetworkBehaviorIndicator],
) -> std::collections::HashSet<String> {
    events.iter().map(normalize_event_id).collect()
}

pub(crate) fn event_payload_map(
    events: &[crate::nbi::NetworkBehaviorIndicator],
) -> std::collections::HashMap<String, String> {
    events
        .iter()
        .map(|event| (normalize_event_id(event), event.content_fingerprint()))
        .collect()
}

pub(crate) fn has_duplicate_event_ids(events: &[crate::nbi::NetworkBehaviorIndicator]) -> bool {
    let mut seen = std::collections::HashSet::with_capacity(events.len());
    events
        .iter()
        .any(|event| !seen.insert(normalize_event_id(event)))
}

pub(crate) fn count_payload_divergences(
    left: &std::collections::HashMap<String, String>,
    right: &std::collections::HashMap<String, String>,
) -> usize {
    left.iter()
        .filter(|(event_id, payload)| {
            right
                .get(*event_id)
                .is_some_and(|other_payload| other_payload != *payload)
        })
        .count()
}

pub(crate) fn merge_event_sources(
    jsonl_events: &[crate::nbi::NetworkBehaviorIndicator],
    db_events: &[crate::nbi::NetworkBehaviorIndicator],
    prefer_db_for_shared: bool,
) -> Vec<crate::nbi::NetworkBehaviorIndicator> {
    let mut merged = Vec::with_capacity(jsonl_events.len().max(db_events.len()));
    let mut seen = std::collections::HashSet::new();
    let db_events_by_id: std::collections::HashMap<_, _> = db_events
        .iter()
        .map(|event| (normalize_event_id(event), event))
        .collect();

    for event in jsonl_events {
        let event_id = normalize_event_id(event);
        if seen.insert(event_id.clone()) {
            if prefer_db_for_shared && let Some(db_event) = db_events_by_id.get(&event_id) {
                merged.push((*db_event).clone());
                continue;
            }
            merged.push(event.clone());
        }
    }

    for event in db_events {
        let event_id = normalize_event_id(event);
        if seen.insert(event_id) {
            merged.push(event.clone());
        }
    }

    merged
}

pub(crate) fn repair_primary_jsonl_if_needed(
    ctx: &ShutdownContext,
    events: &[crate::nbi::NetworkBehaviorIndicator],
) {
    let Some(ref nbi_path) = ctx.nbi_path else {
        return;
    };

    let current_load = crate::output::load_nbis_from_jsonl_detailed(nbi_path);
    if !current_load.has_integrity_issues() && events_match(events, &current_load.events) {
        return;
    }

    if let Err(err) =
        crate::output::export_nbis(events, crate::output::ExportFormat::Jsonl, nbi_path)
    {
        tracing::warn!(
            "Failed to repair primary NBI JSONL from resolved shutdown events: {}",
            err
        );
    }
}
