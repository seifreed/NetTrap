use std::path::PathBuf;
use std::sync::Arc;

use crate::config::EngineConfig;
use crate::database::DatabaseBackend;

mod event_resolution;

pub(crate) use event_resolution::*;

pub struct ShutdownContext {
    pub output_path: Option<PathBuf>,
    pub nbi_path: Option<PathBuf>,
    pub pcap_writer: Option<Arc<nettrap_pcap::PcapWriter>>,
    pub database: Option<Arc<DatabaseBackend>>,
    pub nbi_collector: Option<Arc<crate::nbi::NbiCollector>>,
    pub database_node_id: Option<String>,
    pub run_id: Option<String>,
    pub windows_ca_trust_thumbprint: Option<String>,
}

impl ShutdownContext {
    pub fn new(
        output_path: Option<PathBuf>,
        nbi_path: Option<PathBuf>,
        pcap_writer: Option<Arc<nettrap_pcap::PcapWriter>>,
        database: Option<Arc<DatabaseBackend>>,
        nbi_collector: Option<Arc<crate::nbi::NbiCollector>>,
        database_node_id: Option<String>,
        run_id: Option<String>,
    ) -> Self {
        Self {
            output_path,
            nbi_path,
            pcap_writer,
            database,
            nbi_collector,
            database_node_id,
            run_id,
            windows_ca_trust_thumbprint: None,
        }
    }
}

pub async fn execute_shutdown(ctx: &ShutdownContext, config: &EngineConfig) {
    if let Some(ref collector) = ctx.nbi_collector {
        collector.flush_all_pending().await;
        collector.finalize_distributed_shutdown().await;
        collector.stop_background_tasks();
    }

    let resolved_events = resolve_shutdown_events(ctx).await;
    repair_primary_jsonl_if_needed(ctx, &resolved_events);

    restore_windows_network(ctx, config);

    print_nbi_summary(&resolved_events);

    generate_html_report(ctx, config, &resolved_events);

    export_nbi_formats(ctx, config, &resolved_events);

    close_database(ctx).await;

    close_pcap_writer(ctx);
}

#[cfg(target_os = "windows")]
fn restore_windows_network(ctx: &ShutdownContext, config: &EngineConfig) {
    if crate::engine::platform::should_modify_local_dns(config) {
        crate::windows_setup::restore_dns(config.restrict_interface.as_deref());
        crate::windows_setup::flush_dns(config.dns_flush_command.as_deref());
    }
    if let Some(thumbprint) = ctx.windows_ca_trust_thumbprint.as_deref() {
        crate::windows_setup::remove_ca_trust(thumbprint);
    } else if config.tls_cert_dir.is_some() {
        tracing::debug!("Windows CA trust was not installed during startup");
    }
    if config.has_debug_flag("STOPDNSSERVICE") {
        crate::windows_setup::start_dns_service();
    }
}

#[cfg(not(target_os = "windows"))]
fn restore_windows_network(_ctx: &ShutdownContext, _config: &EngineConfig) {}

async fn close_database(ctx: &ShutdownContext) {
    if let Some(ref db) = ctx.database {
        db.close().await;
    }
}

fn print_nbi_summary(events: &[crate::nbi::NetworkBehaviorIndicator]) {
    crate::nbi::print_summary_from_events(events);
}

fn generate_html_report(
    ctx: &ShutdownContext,
    config: &EngineConfig,
    events: &[crate::nbi::NetworkBehaviorIndicator],
) {
    if let Some(base_path) = artifact_base_path(ctx) {
        let html_path = derived_artifact_path(&base_path, "html");
        match crate::nbi::NbiCollector::generate_html_report_from_events(
            events,
            &html_path,
            &config.report_language,
        ) {
            Ok(()) => tracing::info!("NBI HTML report generated: {}", html_path.display()),
            Err(e) => tracing::warn!("Failed to generate NBI report: {}", e),
        }
    }
}

fn export_nbi_formats(
    ctx: &ShutdownContext,
    config: &EngineConfig,
    events: &[crate::nbi::NetworkBehaviorIndicator],
) {
    if let Some(base_path) = artifact_base_path(ctx) {
        if events.is_empty() {
            return;
        }

        let format = match config.output_format.parse::<crate::output::ExportFormat>() {
            Ok(format) => format,
            Err(err) => {
                tracing::warn!("Skipping NBI export: {}", err);
                return;
            }
        };

        if format != crate::output::ExportFormat::Jsonl {
            let export_path = derived_artifact_path(&base_path, format.extension());
            match crate::output::export_nbis(events, format, &export_path) {
                Ok(()) => tracing::info!(
                    "NBI exported as {}: {}",
                    config.output_format,
                    export_path.display()
                ),
                Err(e) => tracing::warn!("Failed to export NBI as {}: {}", config.output_format, e),
            }
        }

        if format != crate::output::ExportFormat::Sarif {
            let sarif_path = derived_artifact_path(&base_path, "sarif.json");
            match crate::output::export_nbis(
                events,
                crate::output::ExportFormat::Sarif,
                &sarif_path,
            ) {
                Ok(()) => tracing::info!("SARIF report: {}", sarif_path.display()),
                Err(e) => tracing::warn!("Failed to generate SARIF: {}", e),
            }
        }

        if format != crate::output::ExportFormat::Csv {
            let csv_path = derived_artifact_path(&base_path, "csv");
            match crate::output::export_nbis(events, crate::output::ExportFormat::Csv, &csv_path) {
                Ok(()) => tracing::info!("CSV report: {}", csv_path.display()),
                Err(e) => tracing::warn!("Failed to generate CSV: {}", e),
            }
        }
    }
}

fn artifact_base_path(ctx: &ShutdownContext) -> Option<PathBuf> {
    ctx.nbi_path.clone().or_else(|| ctx.output_path.clone())
}

fn derived_artifact_path(base_path: &std::path::Path, extension: &str) -> PathBuf {
    let derived = base_path.with_extension(extension);
    if derived != base_path {
        return derived;
    }

    let mut file_name = base_path
        .file_stem()
        .map(std::ffi::OsString::from)
        .unwrap_or_else(|| std::ffi::OsString::from("output"));
    file_name.push(".generated.");
    file_name.push(extension);

    base_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(file_name)
}

fn close_pcap_writer(ctx: &ShutdownContext) {
    if let Some(ref writer) = ctx.pcap_writer {
        match writer.close() {
            Ok(()) => tracing::info!("PCAP writer closed"),
            Err(err) => tracing::error!("Failed to close PCAP writer cleanly: {}", err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{DatabaseBackend, SqliteStorage};
    use crate::nbi::{NbiCollector, raw_nbi};
    use crate::session::SessionDestination;

    const TEST_RUN_ID: &str = "test-run";

    fn write_jsonl(path: &std::path::Path, events: &[crate::nbi::NetworkBehaviorIndicator]) {
        crate::output::export_nbis(events, crate::output::ExportFormat::Jsonl, path).unwrap();
    }

    #[tokio::test]
    async fn resolve_shutdown_events_falls_back_to_database_when_jsonl_is_empty() {
        let db_path =
            std::env::temp_dir().join(format!("nettrap-shutdown-test-{}.db", uuid::Uuid::new_v4()));
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-test-{}.jsonl",
            uuid::Uuid::new_v4()
        ));

        let db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap(),
        ));
        let collector =
            Arc::new(NbiCollector::new(Some(nbi_path.clone())).expect("valid NBI path"));

        let nbi = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        db.insert_event(&nbi).await.unwrap();

        let ctx = ShutdownContext::new(
            None,
            Some(nbi_path.clone()),
            None,
            Some(Arc::clone(&db)),
            Some(collector),
            Some("test-node".to_string()),
            Some(TEST_RUN_ID.to_string()),
        );

        let events = resolve_shutdown_events(&ctx).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].src_ip, "127.0.0.1");

        repair_primary_jsonl_if_needed(&ctx, &events);
        let repaired = crate::output::load_nbis_from_jsonl(&nbi_path).unwrap();
        assert_eq!(repaired.len(), 1);

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
        let _ = std::fs::remove_file(&nbi_path);
    }

    #[tokio::test]
    async fn resolve_shutdown_events_merges_sources_when_content_differs_at_same_count() {
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-equal-count-{}.db",
            uuid::Uuid::new_v4()
        ));
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-equal-count-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let failing_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-failing-dir-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&failing_path).unwrap();

        let db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap(),
        ));
        let collector =
            Arc::new(NbiCollector::new(Some(failing_path.clone())).expect("valid NBI path"));
        collector.attach_database(Arc::clone(&db));

        let db_event = raw_nbi(
            "raw",
            "127.0.0.2",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        collector.record(&db_event).await;
        collector.flush_all_pending().await;
        assert_eq!(collector.snapshot().local_persist_failures, 1);

        let jsonl_event = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        write_jsonl(&nbi_path, std::slice::from_ref(&jsonl_event));

        let ctx = ShutdownContext::new(
            None,
            Some(nbi_path.clone()),
            None,
            Some(Arc::clone(&db)),
            Some(Arc::clone(&collector)),
            Some("test-node".to_string()),
            Some(TEST_RUN_ID.to_string()),
        );

        let events = resolve_shutdown_events(&ctx).await;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].src_ip, "127.0.0.1");
        assert_eq!(events[1].src_ip, "127.0.0.2");

        repair_primary_jsonl_if_needed(&ctx, &events);
        let repaired = crate::output::load_nbis_from_jsonl(&nbi_path).unwrap();
        assert_eq!(repaired.len(), 2);
        assert_eq!(repaired[0].src_ip, "127.0.0.1");
        assert_eq!(repaired[1].src_ip, "127.0.0.2");

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
        let _ = std::fs::remove_file(&nbi_path);
        let _ = std::fs::remove_dir_all(&failing_path);
    }

    #[tokio::test]
    async fn resolve_shutdown_events_preserves_duplicate_content_with_distinct_event_ids() {
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-duplicate-content-{}.db",
            uuid::Uuid::new_v4()
        ));
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-duplicate-content-{}.jsonl",
            uuid::Uuid::new_v4()
        ));

        let jsonl_event = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        let db_event = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        assert_ne!(jsonl_event.event_id, db_event.event_id);
        write_jsonl(&nbi_path, std::slice::from_ref(&jsonl_event));

        let db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap(),
        ));
        db.insert_event(&db_event).await.unwrap();

        let ctx = ShutdownContext::new(
            None,
            Some(nbi_path.clone()),
            None,
            Some(Arc::clone(&db)),
            None,
            Some("test-node".to_string()),
            Some(TEST_RUN_ID.to_string()),
        );

        let events = resolve_shutdown_events(&ctx).await;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_id, jsonl_event.event_id);
        assert_eq!(events[1].event_id, db_event.event_id);

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
        let _ = std::fs::remove_file(&nbi_path);
    }

    #[tokio::test]
    async fn resolve_shutdown_events_deduplicates_duplicate_jsonl_event_ids_without_database() {
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-duplicate-jsonl-{}.jsonl",
            uuid::Uuid::new_v4()
        ));

        let first = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        let mut second = first.clone();
        second.timestamp = first.timestamp.clone();
        second.event_id = first.event_id.clone();
        write_jsonl(&nbi_path, &[first.clone(), second]);

        let ctx = ShutdownContext::new(None, Some(nbi_path.clone()), None, None, None, None, None);

        let events = resolve_shutdown_events(&ctx).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, first.event_id);

        let _ = std::fs::remove_file(&nbi_path);
    }

    #[tokio::test]
    async fn resolve_shutdown_events_deduplicates_duplicate_database_event_ids_without_jsonl() {
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-duplicate-db-{}.db",
            uuid::Uuid::new_v4()
        ));

        let db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap(),
        ));

        let event = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        db.insert_event(&event).await.unwrap();
        let mut duplicate = event.clone();
        duplicate.timestamp = "2026-01-01T00:00:01Z".to_string();
        db.insert_event(&duplicate).await.unwrap();

        let ctx = ShutdownContext::new(None, None, None, Some(db), None, None, None);

        let events = resolve_shutdown_events(&ctx).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, event.event_id);

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
    }

    #[tokio::test]
    async fn resolve_shutdown_events_deduplicates_legacy_events_without_event_ids() {
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-legacy-dedupe-{}.db",
            uuid::Uuid::new_v4()
        ));
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-legacy-dedupe-{}.jsonl",
            uuid::Uuid::new_v4()
        ));

        let mut legacy_event = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        legacy_event.event_id.clear();
        std::fs::write(
            &nbi_path,
            format!("{}\n", legacy_event.to_json().expect("serialize NBI")),
        )
        .unwrap();

        let db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap(),
        ));
        db.insert_event(&legacy_event).await.unwrap();

        let ctx = ShutdownContext::new(
            None,
            Some(nbi_path.clone()),
            None,
            Some(Arc::clone(&db)),
            None,
            Some("test-node".to_string()),
            Some(TEST_RUN_ID.to_string()),
        );

        let events = resolve_shutdown_events(&ctx).await;
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].normalized_event_id(),
            legacy_event.normalized_event_id()
        );

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
        let _ = std::fs::remove_file(&nbi_path);
    }

    #[tokio::test]
    async fn resolve_shutdown_events_deduplicates_legacy_migrated_database_event_ids() {
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-legacy-migrated-dedupe-{}.db",
            uuid::Uuid::new_v4()
        ));
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-legacy-migrated-dedupe-{}.jsonl",
            uuid::Uuid::new_v4()
        ));

        let mut legacy_event = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        legacy_event.event_id.clear();
        std::fs::write(
            &nbi_path,
            format!("{}\n", legacy_event.to_json().expect("serialize NBI")),
        )
        .unwrap();

        let db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap(),
        ));
        db.insert_event(&legacy_event).await.unwrap();

        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute(
                "UPDATE nbi_events SET event_id = 'legacy-db-1' WHERE event_id = ''",
                [],
            )
            .unwrap();
        }

        let ctx = ShutdownContext::new(
            None,
            Some(nbi_path.clone()),
            None,
            Some(Arc::clone(&db)),
            None,
            Some("test-node".to_string()),
            Some(TEST_RUN_ID.to_string()),
        );

        let events = resolve_shutdown_events(&ctx).await;
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].normalized_event_id(),
            legacy_event.normalized_event_id()
        );

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
        let _ = std::fs::remove_file(&nbi_path);
    }

    #[tokio::test]
    async fn resolve_shutdown_events_preserves_jsonl_when_event_ids_match_but_payload_differs() {
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-payload-divergence-{}.db",
            uuid::Uuid::new_v4()
        ));
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-payload-divergence-{}.jsonl",
            uuid::Uuid::new_v4()
        ));

        let mut jsonl_event = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        jsonl_event.event_id = "shared-event-id".to_string();
        let mut db_event = jsonl_event.clone();
        db_event.dst_port = 9090;
        db_event.add("db_only", "1");

        write_jsonl(&nbi_path, std::slice::from_ref(&jsonl_event));
        let db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap(),
        ));
        db.insert_event(&db_event).await.unwrap();

        let ctx = ShutdownContext::new(
            None,
            Some(nbi_path.clone()),
            None,
            Some(Arc::clone(&db)),
            None,
            Some("test-node".to_string()),
            Some(TEST_RUN_ID.to_string()),
        );

        let events = resolve_shutdown_events(&ctx).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].dst_port, jsonl_event.dst_port);
        assert_eq!(events[0].indicators.get("db_only"), None);

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
        let _ = std::fs::remove_file(&nbi_path);
    }

    #[tokio::test]
    async fn resolve_shutdown_events_prefers_db_on_payload_divergence_when_jsonl_has_integrity_issues()
     {
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-payload-divergence-invalid-{}.db",
            uuid::Uuid::new_v4()
        ));
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-payload-divergence-invalid-{}.jsonl",
            uuid::Uuid::new_v4()
        ));

        let mut jsonl_event = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        jsonl_event.event_id = "shared-event-id".to_string();
        let mut db_event = jsonl_event.clone();
        db_event.dst_port = 9090;
        db_event.add("db_only", "1");

        std::fs::write(
            &nbi_path,
            format!(
                "{}\n{{invalid-json}}\n",
                jsonl_event.to_json().expect("serialize NBI")
            ),
        )
        .unwrap();
        let db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap(),
        ));
        db.insert_event(&db_event).await.unwrap();

        let ctx = ShutdownContext::new(
            None,
            Some(nbi_path.clone()),
            None,
            Some(Arc::clone(&db)),
            None,
            Some("test-node".to_string()),
            Some(TEST_RUN_ID.to_string()),
        );

        let events = resolve_shutdown_events(&ctx).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].dst_port, db_event.dst_port);
        assert_eq!(events[0].indicators.get("db_only"), Some(&"1".to_string()));

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
        let _ = std::fs::remove_file(&nbi_path);
    }

    #[tokio::test]
    async fn resolve_shutdown_events_merges_superset_sources_when_shared_payloads_diverge() {
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-superset-divergence-{}.db",
            uuid::Uuid::new_v4()
        ));
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-superset-divergence-{}.jsonl",
            uuid::Uuid::new_v4()
        ));

        let mut jsonl_shared = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        jsonl_shared.event_id = "shared-event-id".to_string();

        let mut db_shared = jsonl_shared.clone();
        db_shared.dst_port = 9090;
        db_shared.add("db_only_payload", "1");

        let mut db_only = raw_nbi(
            "raw",
            "127.0.0.1",
            12346,
            &SessionDestination::unknown(8081),
            4,
            "",
        );
        db_only.event_id = "db-only-event-id".to_string();

        write_jsonl(&nbi_path, std::slice::from_ref(&jsonl_shared));
        let db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap(),
        ));
        db.insert_event(&db_shared).await.unwrap();
        db.insert_event(&db_only).await.unwrap();

        let ctx = ShutdownContext::new(
            None,
            Some(nbi_path.clone()),
            None,
            Some(Arc::clone(&db)),
            None,
            Some("test-node".to_string()),
            Some(TEST_RUN_ID.to_string()),
        );

        let events = resolve_shutdown_events(&ctx).await;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_id, jsonl_shared.event_id);
        assert_eq!(events[0].dst_port, jsonl_shared.dst_port);
        assert_eq!(events[1].event_id, db_only.event_id);

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
        let _ = std::fs::remove_file(&nbi_path);
    }

    #[tokio::test]
    async fn resolve_shutdown_events_prefers_database_when_jsonl_has_invalid_lines() {
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-invalid-jsonl-{}.db",
            uuid::Uuid::new_v4()
        ));
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-invalid-jsonl-{}.jsonl",
            uuid::Uuid::new_v4()
        ));

        let db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap(),
        ));
        let collector =
            Arc::new(NbiCollector::new(Some(nbi_path.clone())).expect("valid NBI path"));

        let first = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        let second = raw_nbi(
            "raw",
            "127.0.0.2",
            12346,
            &SessionDestination::unknown(8081),
            4,
            "",
        );
        db.insert_event(&first).await.unwrap();
        db.insert_event(&second).await.unwrap();
        std::fs::write(
            &nbi_path,
            format!(
                "{}\n{{invalid-json}}\n",
                first.to_json().expect("serialize NBI")
            ),
        )
        .unwrap();

        let ctx = ShutdownContext::new(
            None,
            Some(nbi_path.clone()),
            None,
            Some(Arc::clone(&db)),
            Some(collector),
            Some("test-node".to_string()),
            Some(TEST_RUN_ID.to_string()),
        );

        let events = resolve_shutdown_events(&ctx).await;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].src_ip, "127.0.0.1");
        assert_eq!(events[1].src_ip, "127.0.0.2");

        repair_primary_jsonl_if_needed(&ctx, &events);
        let repaired = crate::output::load_nbis_from_jsonl(&nbi_path).unwrap();
        assert_eq!(repaired.len(), 2);
        assert_eq!(repaired[1].src_ip, "127.0.0.2");

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
        let _ = std::fs::remove_file(&nbi_path);
    }

    #[tokio::test]
    async fn resolve_shutdown_events_prefers_database_when_jsonl_is_valid_but_truncated() {
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-truncated-jsonl-{}.db",
            uuid::Uuid::new_v4()
        ));
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-truncated-jsonl-{}.jsonl",
            uuid::Uuid::new_v4()
        ));

        let db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap(),
        ));

        let first = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        let second = raw_nbi(
            "raw",
            "127.0.0.2",
            12346,
            &SessionDestination::unknown(8081),
            4,
            "",
        );
        db.insert_event(&first).await.unwrap();
        db.insert_event(&second).await.unwrap();
        write_jsonl(&nbi_path, std::slice::from_ref(&first));

        let ctx = ShutdownContext::new(
            None,
            Some(nbi_path.clone()),
            None,
            Some(Arc::clone(&db)),
            None,
            Some("test-node".to_string()),
            Some(TEST_RUN_ID.to_string()),
        );

        let events = resolve_shutdown_events(&ctx).await;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].src_ip, "127.0.0.1");
        assert_eq!(events[1].src_ip, "127.0.0.2");

        repair_primary_jsonl_if_needed(&ctx, &events);
        let repaired = crate::output::load_nbis_from_jsonl(&nbi_path).unwrap();
        assert_eq!(repaired.len(), 2);
        assert_eq!(repaired[1].src_ip, "127.0.0.2");

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
        let _ = std::fs::remove_file(&nbi_path);
    }

    #[tokio::test]
    async fn resolve_shutdown_events_ignores_database_rows_from_other_runs() {
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-run-filter-{}.db",
            uuid::Uuid::new_v4()
        ));
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-run-filter-{}.jsonl",
            uuid::Uuid::new_v4()
        ));

        let current_db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path, "current-node", "run-a").unwrap(),
        ));
        let other_db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path, "current-node", "run-b").unwrap(),
        ));

        let current_event = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        let other_event = raw_nbi(
            "raw",
            "127.0.0.9",
            12399,
            &SessionDestination::unknown(8099),
            4,
            "",
        );
        current_db.insert_event(&current_event).await.unwrap();
        other_db.insert_event(&other_event).await.unwrap();

        let ctx = ShutdownContext::new(
            None,
            Some(nbi_path.clone()),
            None,
            Some(Arc::clone(&current_db)),
            None,
            Some("current-node".to_string()),
            Some("run-a".to_string()),
        );

        let events = resolve_shutdown_events(&ctx).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].src_ip, "127.0.0.1");

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
        let _ = std::fs::remove_file(&nbi_path);
    }

    #[tokio::test]
    async fn resolve_shutdown_events_uses_effective_database_node_id() {
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-effective-node-{}.db",
            uuid::Uuid::new_v4()
        ));
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-effective-node-{}.jsonl",
            uuid::Uuid::new_v4()
        ));

        let db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path, "db-node", TEST_RUN_ID).unwrap(),
        ));
        let event = raw_nbi(
            "raw",
            "127.0.0.7",
            31337,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        db.insert_event(&event).await.unwrap();

        let ctx = ShutdownContext::new(
            None,
            Some(nbi_path.clone()),
            None,
            Some(Arc::clone(&db)),
            None,
            Some("db-node".to_string()),
            Some(TEST_RUN_ID.to_string()),
        );

        let events = resolve_shutdown_events(&ctx).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].src_ip, "127.0.0.7");

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
        let _ = std::fs::remove_file(&nbi_path);
    }

    #[tokio::test]
    async fn resolve_shutdown_events_keeps_jsonl_when_database_indicators_are_corrupt() {
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-corrupt-db-{}.db",
            uuid::Uuid::new_v4()
        ));
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-corrupt-db-{}.jsonl",
            uuid::Uuid::new_v4()
        ));

        let db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap(),
        ));
        let jsonl_event = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        write_jsonl(&nbi_path, std::slice::from_ref(&jsonl_event));

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO nbi_events (timestamp, node_id, run_id, listener, protocol, src_ip, src_port, dst_ip, dst_port, indicators) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                "2026-01-01T00:00:00Z",
                "test-node",
                TEST_RUN_ID,
                "raw",
                "RAW",
                "127.0.0.9",
                12399u16,
                "127.0.0.10",
                8099u16,
                "{invalid-json}",
            ],
        )
        .unwrap();

        let ctx = ShutdownContext::new(
            None,
            Some(nbi_path.clone()),
            None,
            Some(Arc::clone(&db)),
            None,
            Some("test-node".to_string()),
            Some(TEST_RUN_ID.to_string()),
        );

        let events = resolve_shutdown_events(&ctx).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].src_ip, "127.0.0.1");

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
        let _ = std::fs::remove_file(&nbi_path);
    }

    #[test]
    fn repair_primary_jsonl_rewrites_when_content_differs_at_same_count() {
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-repair-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let current = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        let resolved = raw_nbi(
            "raw",
            "127.0.0.2",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        write_jsonl(&nbi_path, std::slice::from_ref(&current));

        let ctx = ShutdownContext::new(None, Some(nbi_path.clone()), None, None, None, None, None);
        repair_primary_jsonl_if_needed(&ctx, std::slice::from_ref(&resolved));

        let repaired = crate::output::load_nbis_from_jsonl(&nbi_path).unwrap();
        assert_eq!(repaired.len(), 1);
        assert_eq!(repaired[0].src_ip, "127.0.0.2");

        let _ = std::fs::remove_file(&nbi_path);
    }

    #[test]
    fn repair_primary_jsonl_rewrites_when_file_contains_invalid_lines() {
        let nbi_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-repair-invalid-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let event = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        std::fs::write(
            &nbi_path,
            format!(
                "{}\n{{invalid-json}}\n",
                event.to_json().expect("serialize NBI")
            ),
        )
        .unwrap();

        let ctx = ShutdownContext::new(None, Some(nbi_path.clone()), None, None, None, None, None);
        repair_primary_jsonl_if_needed(&ctx, std::slice::from_ref(&event));

        let repaired_load = crate::output::load_nbis_from_jsonl_detailed(&nbi_path);
        assert_eq!(repaired_load.events.len(), 1);
        assert_eq!(repaired_load.invalid_lines, 0);

        let _ = std::fs::remove_file(&nbi_path);
    }

    #[test]
    fn shutdown_generates_artifacts_from_output_path_when_nbi_path_is_missing() {
        let output_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-output-only-{}.log",
            uuid::Uuid::new_v4()
        ));
        let html_path = output_path.with_extension("html");
        let csv_path = output_path.with_extension("csv");
        let sarif_path = output_path.with_extension("sarif.json");

        let event = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        let config = EngineConfig::default();
        let ctx = ShutdownContext::new(
            Some(output_path.clone()),
            None,
            None,
            None,
            None,
            None,
            None,
        );

        generate_html_report(&ctx, &config, std::slice::from_ref(&event));
        export_nbi_formats(&ctx, &config, std::slice::from_ref(&event));

        assert!(html_path.exists());
        assert!(csv_path.exists());
        assert!(sarif_path.exists());

        let _ = std::fs::remove_file(&output_path);
        let _ = std::fs::remove_file(&html_path);
        let _ = std::fs::remove_file(&csv_path);
        let _ = std::fs::remove_file(&sarif_path);
    }

    #[test]
    fn shutdown_generated_artifacts_avoid_colliding_with_base_csv_path() {
        let output_path = std::env::temp_dir().join(format!(
            "nettrap-shutdown-colliding-{}.csv",
            uuid::Uuid::new_v4()
        ));
        let html_path = output_path.with_extension("html");
        let sarif_path = output_path.with_extension("sarif.json");
        let csv_path = output_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(format!(
                "{}.generated.csv",
                output_path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .expect("test path should be utf-8")
            ));

        let event = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        let config = EngineConfig::default();
        let ctx = ShutdownContext::new(
            Some(output_path.clone()),
            None,
            None,
            None,
            None,
            None,
            None,
        );

        std::fs::write(&output_path, b"marker").expect("write base marker");
        generate_html_report(&ctx, &config, std::slice::from_ref(&event));
        export_nbi_formats(&ctx, &config, std::slice::from_ref(&event));

        assert_eq!(
            std::fs::read(&output_path).expect("read base marker"),
            b"marker"
        );
        assert!(html_path.exists());
        assert!(sarif_path.exists());
        assert!(csv_path.exists());

        let _ = std::fs::remove_file(&output_path);
        let _ = std::fs::remove_file(&html_path);
        let _ = std::fs::remove_file(&sarif_path);
        let _ = std::fs::remove_file(&csv_path);
    }

    #[test]
    fn shutdown_context_initializes_without_windows_ca_thumbprint() {
        let ctx = ShutdownContext::new(None, None, None, None, None, None, None);

        assert!(ctx.windows_ca_trust_thumbprint.is_none());
    }
}
