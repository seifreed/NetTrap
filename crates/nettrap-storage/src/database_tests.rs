use super::*;

const TEST_RUN_ID: &str = "test-run";

fn cleanup_sqlite(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}

#[cfg(unix)]
#[test]
fn sqlite_storage_rejects_symlinked_final_path() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-sqlite-final-symlink-{}",
        uuid::Uuid::new_v4()
    ));
    let real_target = root.join("real").join("nbi.db");
    let link = root.join("linked").join("nbi.db");
    std::fs::create_dir_all(real_target.parent().expect("target parent"))
        .expect("create target parent");
    std::fs::create_dir_all(link.parent().expect("link parent")).expect("create link parent");
    std::os::unix::fs::symlink(&real_target, &link).expect("create symlink");

    let err = match SqliteStorage::new(&link, "node", TEST_RUN_ID) {
        Ok(_) => panic!("symlinked sqlite path should be rejected"),
        Err(err) => err,
    };
    assert!(err.to_lowercase().contains("symlink") || err.to_lowercase().contains("nofollow"));

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn sqlite_storage_rejects_symlinked_parent_directory() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-sqlite-parent-symlink-{}",
        uuid::Uuid::new_v4()
    ));
    let real_parent = root.join("real");
    let linked_parent = root.join("linked");
    std::fs::create_dir_all(&real_parent).expect("create real parent");
    std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");

    let path = linked_parent.join("nbi.db");
    let err = match SqliteStorage::new(&path, "node", TEST_RUN_ID) {
        Ok(_) => panic!("symlinked sqlite parent should be rejected"),
        Err(err) => err,
    };
    assert!(err.to_lowercase().contains("symlink"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn sqlite_storage_rejects_empty_path() {
    let err = match SqliteStorage::new(std::path::PathBuf::new(), "node", TEST_RUN_ID) {
        Ok(_) => panic!("empty sqlite path should fail"),
        Err(err) => err,
    };

    assert!(err.contains("must not be empty"));
}

#[test]
fn sqlite_storage_accepts_trailing_current_dir_component() {
    let root = std::env::temp_dir().join(format!("nettrap-sqlite-curdir-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("create temp root");
    let path = root.join("nbi.db");

    let storage = SqliteStorage::new(path.join("."), "node", TEST_RUN_ID)
        .expect("trailing current-dir component should be accepted");

    assert!(path.is_file());
    drop(storage);
    cleanup_sqlite(&path);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn sqlite_storage_accepts_non_utf8_output_path() {
    use std::os::unix::ffi::OsStringExt;

    let root =
        std::env::temp_dir().join(format!("nettrap-sqlite-nonutf8-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("create temp root");
    let path = root.join(std::ffi::OsString::from_vec(b"nbi-\xff.db".to_vec()));

    let storage = SqliteStorage::new(&path, "node", TEST_RUN_ID)
        .expect("non-UTF8 sqlite path should be preserved");

    assert!(path.is_file());
    drop(storage);
    cleanup_sqlite(&path);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn sqlite_storage_migrates_legacy_event_table_to_usable_schema() {
    let db_path = std::env::temp_dir().join(format!(
        "nettrap-db-legacy-schema-{}.db",
        uuid::Uuid::new_v4()
    ));
    {
        let conn = rusqlite::Connection::open(&db_path).expect("open legacy sqlite");
        conn.execute(
            "CREATE TABLE nbi_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_json TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL
                )",
            [],
        )
        .expect("create old schema");
    }

    let db = DatabaseBackend::Sqlite(
        SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID)
            .expect("legacy schema should migrate"),
    );
    let event = raw_nbi("raw", "127.0.0.1", 12345, "0.0.0.0", 8080, 4, "");

    db.insert_event(&event)
        .await
        .expect("migrated legacy schema should accept inserts");
    let events = db
        .load_events_for_run(TEST_RUN_ID)
        .await
        .expect("migrated legacy schema should support loads");

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].listener, "raw");
    cleanup_sqlite(&db_path);
}

/// Mirror of the cli `raw_nbi` factory for "RAW" events: builds a
/// `NetworkBehaviorIndicator` with protocol "RAW" and a `data_length`
/// indicator, without depending on the cli-internal `raw_nbi` /
/// `SessionDestination` helpers.
fn raw_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    data_len: usize,
    hexdump_preview: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi =
        NetworkBehaviorIndicator::new(listener, "RAW", src_ip, src_port, dst_ip, dst_port);
    nbi.add("data_length", data_len.to_string());
    if !hexdump_preview.is_empty() {
        nbi.add("hexdump", hexdump_preview);
    }
    nbi
}

fn stored_event_with_bounds(src_port: i64, dst_port: i64, process_pid: Option<i64>) -> StoredEvent {
    StoredEvent {
        id: 42,
        event_id: "test-event".to_string(),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        node_id: "test-node".to_string(),
        listener: "raw".to_string(),
        protocol: "RAW".to_string(),
        src_ip: "127.0.0.1".to_string(),
        src_port,
        dst_ip: "127.0.0.2".to_string(),
        dst_port,
        process_name: None,
        process_pid,
        indicators: "{}".to_string(),
    }
}

#[test]
fn stored_event_rejects_out_of_range_ports() {
    let err = stored_event_with_bounds(-1, 8080, None)
        .try_into_network_behavior_indicator()
        .unwrap_err();
    assert!(err.contains("invalid src_port"));
    assert!(err.contains("-1"));

    let err = stored_event_with_bounds(12345, 65_536, None)
        .try_into_network_behavior_indicator()
        .unwrap_err();
    assert!(err.contains("invalid dst_port"));
    assert!(err.contains("65536"));
}

#[test]
fn stored_event_rejects_out_of_range_process_pid() {
    let err = stored_event_with_bounds(12345, 8080, Some(-1))
        .try_into_network_behavior_indicator()
        .unwrap_err();
    assert!(err.contains("invalid process_pid"));
    assert!(err.contains("-1"));

    let err = stored_event_with_bounds(12345, 8080, Some(i64::from(u32::MAX) + 1))
        .try_into_network_behavior_indicator()
        .unwrap_err();
    assert!(err.contains("invalid process_pid"));
    assert!(err.contains("4294967296"));
}

#[test]
fn stored_event_rejects_indicator_count_over_limit() {
    let mut stored = stored_event_with_bounds(12345, 8080, None);
    let indicators: std::collections::HashMap<String, String> = (0
        ..=NetworkBehaviorIndicator::MAX_INDICATORS)
        .map(|index| (format!("key-{index}"), "value".to_string()))
        .collect();
    stored.indicators = serde_json::to_string(&indicators).unwrap();

    let err = stored.try_into_network_behavior_indicator().unwrap_err();

    assert!(err.contains("failed NBI validation"));
    assert!(err.contains("too many indicators"));
}

#[test]
fn stored_event_rejects_oversized_indicator_values() {
    let mut stored = stored_event_with_bounds(12345, 8080, None);
    let indicators: std::collections::HashMap<String, String> = [(
        "key".to_string(),
        "v".repeat(nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS + 1),
    )]
    .into_iter()
    .collect();
    stored.indicators = serde_json::to_string(&indicators).unwrap();

    let err = stored.try_into_network_behavior_indicator().unwrap_err();

    assert!(err.contains("failed NBI validation"));
    assert!(err.contains("indicator value"));
    assert!(err.contains("exceeds text limit"));
}

#[test]
fn stored_event_canonicalizes_ipv4_mapped_addresses() {
    let mut stored = stored_event_with_bounds(12345, 8080, None);
    stored.src_ip = "::ffff:192.0.2.10".to_string();
    stored.dst_ip = "::ffff:198.51.100.7".to_string();

    let event = stored.try_into_network_behavior_indicator().unwrap();

    assert_eq!(event.src_ip, "192.0.2.10");
    assert_eq!(event.dst_ip, "198.51.100.7");
}

#[test]
fn stored_event_uses_peer_family_for_default_destination_ip() {
    let mut stored = stored_event_with_bounds(12345, 8080, None);
    stored.src_ip = "::1".to_string();
    stored.dst_ip = "0.0.0.0".to_string();

    let event = stored.try_into_network_behavior_indicator().unwrap();

    assert_eq!(event.src_ip, "::1");
    assert_eq!(event.dst_ip, "::");
}

#[test]
fn stored_event_canonicalizes_protocol_case() {
    let mut stored = stored_event_with_bounds(12345, 8080, None);
    stored.protocol = "dns".to_string();

    let event = stored.try_into_network_behavior_indicator().unwrap();

    assert_eq!(event.protocol, "DNS");
}

#[test]
fn stored_event_trims_legacy_listener_and_protocol_padding() {
    let mut stored = stored_event_with_bounds(12345, 8080, None);
    stored.listener = " raw\t".to_string();
    stored.protocol = " dns ".to_string();

    let event = stored.try_into_network_behavior_indicator().unwrap();

    assert_eq!(event.listener, "raw");
    assert_eq!(event.protocol, "DNS");
}

#[test]
fn stored_event_drops_whitespace_only_process_name() {
    let mut stored = stored_event_with_bounds(12345, 8080, None);
    stored.process_name = Some("   ".to_string());

    let event = stored.try_into_network_behavior_indicator().unwrap();

    assert!(event.process_name.is_none());
}

#[test]
fn stored_event_rejects_invalid_ips() {
    let mut stored = stored_event_with_bounds(12345, 8080, None);
    stored.src_ip = "not-an-ip".to_string();

    let err = stored.try_into_network_behavior_indicator().unwrap_err();
    assert!(err.contains("invalid src_ip"));
    assert!(err.contains("not-an-ip"));

    let mut stored = stored_event_with_bounds(12345, 8080, None);
    stored.dst_ip = "not-an-ip".to_string();

    let err = stored.try_into_network_behavior_indicator().unwrap_err();
    assert!(err.contains("invalid dst_ip"));
    assert!(err.contains("not-an-ip"));
}

#[tokio::test]
async fn init_database_rejects_blank_backend() {
    let config = DatabaseConfig {
        backend: String::new(),
        sqlite_path: None,
        postgres_url: None,
        pool_size: 5,
        node_id: None,
    };

    let err = match init_database(&config, TEST_RUN_ID).await {
        Ok(_) => panic!("blank database backend should fail"),
        Err(err) => err,
    };

    assert!(err.contains("must not be blank"));
}

#[test]
fn postgres_process_pid_param_rejects_values_that_do_not_fit_integer() {
    assert_eq!(postgres_process_pid_param(None).unwrap(), None);
    assert_eq!(
        postgres_process_pid_param(Some(i32::MAX as u32)).unwrap(),
        Some(i32::MAX)
    );

    let err = postgres_process_pid_param(Some(i32::MAX as u32 + 1)).unwrap_err();
    assert!(err.contains("process_pid"));
    assert!(err.contains("2147483648"));
}

#[tokio::test]
async fn stats_for_node_only_counts_events_for_current_node() {
    let db_path =
        std::env::temp_dir().join(format!("nettrap-db-stats-node-{}.db", uuid::Uuid::new_v4()));
    let current =
        DatabaseBackend::Sqlite(SqliteStorage::new(&db_path, "current-node", TEST_RUN_ID).unwrap());
    let other =
        DatabaseBackend::Sqlite(SqliteStorage::new(&db_path, "other-node", TEST_RUN_ID).unwrap());

    let current_event = raw_nbi("raw", "127.0.0.1", 12345, "0.0.0.0", 8080, 4, "");
    let other_event = raw_nbi("raw", "127.0.0.2", 12346, "0.0.0.0", 8081, 4, "");
    current.insert_event(&current_event).await.unwrap();
    other.insert_event(&other_event).await.unwrap();

    let stats = current.stats_for_node("current-node").await.unwrap();
    assert_eq!(stats.total_events, 1);
    assert_eq!(stats.unique_sources, 1);
    assert_eq!(stats.unique_nodes, 1);
    assert_eq!(stats.protocol_counts.len(), 1);
    assert_eq!(stats.protocol_counts[0], ("RAW".to_string(), 1));

    cleanup_sqlite(&db_path);
}

#[tokio::test]
async fn stats_for_node_canonicalizes_ipv4_mapped_sources() {
    let db_path = std::env::temp_dir().join(format!(
        "nettrap-db-stats-canonical-sources-{}.db",
        uuid::Uuid::new_v4()
    ));
    let db =
        DatabaseBackend::Sqlite(SqliteStorage::new(&db_path, "current-node", TEST_RUN_ID).unwrap());

    let event = raw_nbi("raw", "127.0.0.1", 12345, "0.0.0.0", 8080, 4, "");
    db.insert_event(&event).await.unwrap();

    if let DatabaseBackend::Sqlite(storage) = &db {
        let conn = storage.conn.lock();
        conn.execute(
                "INSERT INTO nbi_events (timestamp, node_id, run_id, listener, protocol, src_ip, src_port, dst_ip, dst_port, indicators) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    "2026-01-01T00:00:00Z",
                    "current-node",
                    TEST_RUN_ID,
                    "raw",
                    "RAW",
                    "::ffff:127.0.0.1",
                    12346u16,
                    "127.0.0.2",
                    8081u16,
                    "{}",
                ],
            )
            .unwrap();
        conn.execute(
                "INSERT INTO nbi_events (timestamp, node_id, run_id, listener, protocol, src_ip, src_port, dst_ip, dst_port, indicators) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    "2026-01-01T00:00:01Z",
                    "current-node",
                    TEST_RUN_ID,
                    "raw",
                    "RAW",
                    "::FFFF:127.0.0.1",
                    12347u16,
                    "127.0.0.3",
                    8082u16,
                    "{}",
                ],
            )
            .unwrap();
    }

    let stats = db.stats_for_node("current-node").await.unwrap();
    assert_eq!(stats.total_events, 3);
    assert_eq!(stats.unique_sources, 1);
    assert_eq!(stats.unique_nodes, 1);

    cleanup_sqlite(&db_path);
}

#[tokio::test]
async fn sqlite_insert_rejects_indicator_count_over_limit() {
    let db_path = std::env::temp_dir().join(format!(
        "nettrap-db-indicator-limit-{}.db",
        uuid::Uuid::new_v4()
    ));
    let db =
        DatabaseBackend::Sqlite(SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap());
    let mut event = raw_nbi("raw", "127.0.0.1", 12345, "0.0.0.0", 8080, 4, "");
    for index in 0..=NetworkBehaviorIndicator::MAX_INDICATORS {
        event
            .indicators
            .insert(format!("key-{index}"), "value".to_string());
    }

    let err = db.insert_event(&event).await.unwrap_err();

    assert!(err.contains("NBI validation failed"));
    assert!(err.contains("too many indicators"));

    cleanup_sqlite(&db_path);
}

#[tokio::test]
async fn load_events_for_node_fails_when_indicators_are_corrupt() {
    let db_path = std::env::temp_dir().join(format!(
        "nettrap-db-corrupt-indicators-{}.db",
        uuid::Uuid::new_v4()
    ));
    let db =
        DatabaseBackend::Sqlite(SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap());

    if let DatabaseBackend::Sqlite(storage) = &db {
        let conn = storage.conn.lock();
        conn.execute(
                "INSERT INTO nbi_events (timestamp, node_id, run_id, listener, protocol, src_ip, src_port, dst_ip, dst_port, indicators) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    "2026-01-01T00:00:00Z",
                    "test-node",
                    TEST_RUN_ID,
                    "raw",
                    "TCP",
                    "127.0.0.1",
                    12345u16,
                    "127.0.0.2",
                    8080u16,
                    "{invalid-json}",
                ],
            )
            .unwrap();
    }

    let err = db.load_events_for_node("test-node").await.unwrap_err();
    assert!(err.contains("invalid indicators JSON"));
    assert!(err.contains("test-node"));

    cleanup_sqlite(&db_path);
}

#[tokio::test]
async fn sqlite_stats_fail_instead_of_dropping_invalid_protocol_rows() {
    let db_path = std::env::temp_dir().join(format!(
        "nettrap-db-stats-corrupt-{}.db",
        uuid::Uuid::new_v4()
    ));
    let db =
        DatabaseBackend::Sqlite(SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap());

    if let DatabaseBackend::Sqlite(storage) = &db {
        let conn = storage.conn.lock();
        conn.execute(
                "INSERT INTO nbi_events (timestamp, node_id, run_id, listener, protocol, src_ip, src_port, dst_ip, dst_port, indicators) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    "2026-01-01T00:00:00Z",
                    "test-node",
                    TEST_RUN_ID,
                    "raw",
                    rusqlite::types::Value::Blob(vec![0x80]),
                    "127.0.0.1",
                    12345u16,
                    "127.0.0.2",
                    8080u16,
                    "{}",
                ],
            )
            .unwrap();
    }

    let err = db.stats().await.unwrap_err();
    assert!(err.contains("stats error"));

    cleanup_sqlite(&db_path);
}

#[tokio::test]
async fn load_events_for_run_only_returns_current_run() {
    let db_path =
        std::env::temp_dir().join(format!("nettrap-db-run-filter-{}.db", uuid::Uuid::new_v4()));
    let current =
        DatabaseBackend::Sqlite(SqliteStorage::new(&db_path, "test-node", "run-a").unwrap());
    let previous =
        DatabaseBackend::Sqlite(SqliteStorage::new(&db_path, "test-node", "run-b").unwrap());

    let current_event = raw_nbi("raw", "127.0.0.1", 12345, "0.0.0.0", 8080, 4, "");
    let previous_event = raw_nbi("raw", "127.0.0.2", 12346, "0.0.0.0", 8081, 4, "");
    current.insert_event(&current_event).await.unwrap();
    previous.insert_event(&previous_event).await.unwrap();

    let events = current.load_events_for_run("run-a").await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].src_ip, "127.0.0.1");

    cleanup_sqlite(&db_path);
}

#[tokio::test]
async fn sqlite_load_events_fails_when_event_limit_is_exceeded() {
    let db_path =
        std::env::temp_dir().join(format!("nettrap-db-load-limit-{}.db", uuid::Uuid::new_v4()));
    let db =
        DatabaseBackend::Sqlite(SqliteStorage::new(&db_path, "test-node", TEST_RUN_ID).unwrap());
    let first = raw_nbi("raw", "127.0.0.1", 12345, "0.0.0.0", 8080, 4, "");
    let second = raw_nbi("raw", "127.0.0.2", 12346, "0.0.0.0", 8081, 4, "");
    db.insert_event(&first).await.unwrap();
    db.insert_event(&second).await.unwrap();

    let err = db.load_events_with_limit(1).await.unwrap_err();

    assert!(err.contains("database event load exceeds limit"));
    cleanup_sqlite(&db_path);
}

#[tokio::test]
async fn sqlite_load_events_for_node_fails_when_event_limit_is_exceeded() {
    let db_path = std::env::temp_dir().join(format!(
        "nettrap-db-node-load-limit-{}.db",
        uuid::Uuid::new_v4()
    ));
    let current =
        DatabaseBackend::Sqlite(SqliteStorage::new(&db_path, "current-node", TEST_RUN_ID).unwrap());
    let other =
        DatabaseBackend::Sqlite(SqliteStorage::new(&db_path, "other-node", TEST_RUN_ID).unwrap());
    let first = raw_nbi("raw", "127.0.0.1", 12345, "0.0.0.0", 8080, 4, "");
    let second = raw_nbi("raw", "127.0.0.2", 12346, "0.0.0.0", 8081, 4, "");
    let other_event = raw_nbi("raw", "127.0.0.3", 12347, "0.0.0.0", 8082, 4, "");
    current.insert_event(&first).await.unwrap();
    current.insert_event(&second).await.unwrap();
    other.insert_event(&other_event).await.unwrap();

    let err = current
        .load_events_for_node_with_limit("current-node", 1)
        .await
        .unwrap_err();

    assert!(err.contains("database event load exceeds limit"));
    cleanup_sqlite(&db_path);
}

#[tokio::test]
async fn sqlite_load_events_for_run_fails_when_event_limit_is_exceeded() {
    let db_path = std::env::temp_dir().join(format!(
        "nettrap-db-run-load-limit-{}.db",
        uuid::Uuid::new_v4()
    ));
    let current =
        DatabaseBackend::Sqlite(SqliteStorage::new(&db_path, "test-node", "run-a").unwrap());
    let previous =
        DatabaseBackend::Sqlite(SqliteStorage::new(&db_path, "test-node", "run-b").unwrap());
    let first = raw_nbi("raw", "127.0.0.1", 12345, "0.0.0.0", 8080, 4, "");
    let second = raw_nbi("raw", "127.0.0.2", 12346, "0.0.0.0", 8081, 4, "");
    let previous_event = raw_nbi("raw", "127.0.0.3", 12347, "0.0.0.0", 8082, 4, "");
    current.insert_event(&first).await.unwrap();
    current.insert_event(&second).await.unwrap();
    previous.insert_event(&previous_event).await.unwrap();

    let err = current
        .load_events_for_run_with_limit("run-a", 1)
        .await
        .unwrap_err();

    assert!(err.contains("database event load exceeds limit"));
    cleanup_sqlite(&db_path);
}
