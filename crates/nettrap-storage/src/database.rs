//! Database storage for NBI events.
//! Supports SQLite (standalone) and PostgreSQL (distributed).
//! All database features are optional — file-based JSONL remains the default.

use nettrap_core::DatabaseConfig;
use nettrap_core::NetworkBehaviorIndicator;
use nettrap_fsutil::{
    ensure_no_symlink_ancestors, normalize_platform_path_alias, strip_current_dir_components,
};
use sqlx::Row;
use std::path::Path;
use std::sync::Arc;

mod schema;
use schema::*;

const MAX_DATABASE_LOAD_EVENTS: usize = 100_000;

pub struct SqliteStorage {
    conn: Arc<parking_lot::Mutex<rusqlite::Connection>>,
    node_id: String,
    run_id: String,
}

fn trim_ascii_edges(value: &str) -> &str {
    value.trim_matches(|ch| matches!(ch, ' ' | '\t' | '\r' | '\n' | '\u{000C}'))
}

fn normalize_optional_process_name(name: Option<String>) -> Option<String> {
    name.and_then(|name| {
        let name = nettrap_core::sanitize::single_line(&name);
        if name.trim().is_empty() {
            None
        } else {
            Some(name)
        }
    })
}

fn normalize_legacy_nbi_event_for_validation(
    event: &NetworkBehaviorIndicator,
) -> NetworkBehaviorIndicator {
    let mut event = event.clone();
    event.event_id = event.normalized_event_id();
    event
}

impl SqliteStorage {
    pub fn new(path: impl AsRef<Path>, node_id: &str, run_id: &str) -> Result<Self, String> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err("SQLite path must not be empty".to_string());
        }
        let conn = open_sqlite_connection(path).map_err(|e| format!("SQLite open error: {}", e))?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| format!("SQLite pragma error: {}", e))?;

        conn.execute_batch(SQLITE_TABLE_SQL)
            .map_err(|e| format!("SQLite schema error: {}", e))?;
        ensure_sqlite_schema(&conn)?;
        conn.execute_batch(SQLITE_INDEX_SQL)
            .map_err(|e| format!("SQLite index error: {}", e))?;

        tracing::info!("SQLite database initialized at {}", path.display());

        Ok(Self {
            conn: Arc::new(parking_lot::Mutex::new(conn)),
            node_id: node_id.to_string(),
            run_id: run_id.to_string(),
        })
    }
}

fn open_sqlite_connection(path: &Path) -> Result<rusqlite::Connection, String> {
    use rusqlite::OpenFlags;

    let normalized_path = strip_current_dir_components(path);
    let path = normalized_path.as_path();

    if let Ok(metadata) = path.symlink_metadata()
        && metadata.file_type().is_symlink()
    {
        return Err("symlink path component".to_string());
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_no_symlink_ancestors(parent).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let sqlite_path = normalize_platform_path_alias(path);
    rusqlite::Connection::open_with_flags(&sqlite_path, flags).map_err(|e| e.to_string())
}

pub struct PostgresStorage {
    pool: sqlx::PgPool,
    node_id: String,
    run_id: String,
}

impl PostgresStorage {
    pub async fn new(
        url: &str,
        node_id: &str,
        run_id: &str,
        pool_size: u32,
    ) -> Result<Self, String> {
        // Bound the initial connection attempt so an unreachable or misconfigured
        // PostgreSQL endpoint fails startup fast with a clear error instead of
        // blocking on sqlx's 30s default acquire timeout (which makes the engine
        // appear to hang before any listener comes up).
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(pool_size)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(url)
            .await
            .map_err(|e| format!("PostgreSQL connect error: {}", e))?;

        // `PG_SCHEMA_SQL` contains multiple statements (CREATE TABLE + CREATE
        // INDEX). The prepared-statement protocol used by `sqlx::query` rejects
        // multiple commands ("cannot insert multiple commands into a prepared
        // statement"), so use `raw_sql`, which runs them via the simple query
        // protocol.
        sqlx::raw_sql(PG_SCHEMA_SQL)
            .execute(&pool)
            .await
            .map_err(|e| format!("PostgreSQL schema error: {}", e))?;

        ensure_postgres_schema(&pool)
            .await
            .map_err(|e| format!("PostgreSQL migration error: {}", e))?;

        tracing::info!("PostgreSQL connected (pool_size={})", pool_size);

        Ok(Self {
            pool,
            node_id: node_id.to_string(),
            run_id: run_id.to_string(),
        })
    }

    pub async fn insert_event(&self, event: &NetworkBehaviorIndicator) -> Result<(), String> {
        let event = normalize_legacy_nbi_event_for_validation(event);
        event
            .validate_resource_bounds()
            .map_err(|err| format!("NBI validation failed: {}", err))?;

        let indicators_json = match serde_json::to_string(&event.indicators) {
            Ok(json) => json,
            Err(e) => {
                tracing::warn!("Failed to serialize NBI indicators: {}", e);
                "{}".to_string()
            }
        };
        let process_pid = postgres_process_pid_param(event.process_pid)?;

        sqlx::query(
            // `indicators` is a JSONB column; bind the serialized JSON as text
            // and cast it (`$13::jsonb`) since Postgres does not implicitly
            // coerce a text parameter to jsonb in a parameterized statement.
            "INSERT INTO nbi_events (event_id, timestamp, node_id, run_id, listener, protocol, src_ip, src_port, dst_ip, dst_port, process_name, process_pid, indicators) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb)"
        )
            .bind(&event.event_id)
            .bind(&event.timestamp)
            .bind(&self.node_id)
            .bind(&self.run_id)
            .bind(&event.listener)
            .bind(&event.protocol)
            .bind(&event.src_ip)
            .bind(event.src_port as i32)
            .bind(&event.dst_ip)
            .bind(event.dst_port as i32)
            .bind(&event.process_name)
            .bind(process_pid)
            .bind(&indicators_json)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("PostgreSQL insert error: {}", e))?;

        Ok(())
    }

    pub async fn count_events(&self) -> Result<i64, String> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM nbi_events")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| format!("PostgreSQL count error: {}", e))?;
        Ok(row.0)
    }

    pub async fn stats(&self) -> Result<DbStats, String> {
        let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM nbi_events")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| format!("stats error: {}", e))?;

        let protocol_counts: Vec<(String, i64)> = sqlx::query_as(
            "SELECT protocol, COUNT(*) as cnt FROM nbi_events GROUP BY protocol ORDER BY cnt DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("stats error: {}", e))?;

        let (unique_ips,): (i64,) = sqlx::query_as(
            "SELECT COUNT(DISTINCT CASE WHEN lower(src_ip) LIKE '::ffff:%' THEN substr(lower(src_ip), 8) ELSE lower(src_ip) END) FROM nbi_events",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| format!("stats error: {}", e))?;

        let (unique_nodes,): (i64,) =
            sqlx::query_as("SELECT COUNT(DISTINCT node_id) FROM nbi_events")
                .fetch_one(&self.pool)
                .await
                .map_err(|e| format!("stats error: {}", e))?;

        Ok(DbStats {
            total_events: total,
            unique_sources: unique_ips,
            unique_nodes,
            protocol_counts,
        })
    }

    pub async fn stats_for_node(&self, node_id: &str) -> Result<DbStats, String> {
        let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM nbi_events WHERE node_id = $1")
            .bind(node_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| format!("stats error: {}", e))?;

        let protocol_counts: Vec<(String, i64)> = sqlx::query_as(
            "SELECT protocol, COUNT(*) as cnt FROM nbi_events WHERE node_id = $1 GROUP BY protocol ORDER BY cnt DESC",
        )
        .bind(node_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("stats error: {}", e))?;

        let (unique_ips,): (i64,) = sqlx::query_as(
            "SELECT COUNT(DISTINCT CASE WHEN lower(src_ip) LIKE '::ffff:%' THEN substr(lower(src_ip), 8) ELSE lower(src_ip) END) FROM nbi_events WHERE node_id = $1",
        )
        .bind(node_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| format!("stats error: {}", e))?;

        let (unique_nodes,): (i64,) =
            sqlx::query_as("SELECT COUNT(DISTINCT node_id) FROM nbi_events WHERE node_id = $1")
                .bind(node_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| format!("stats error: {}", e))?;

        Ok(DbStats {
            total_events: total,
            unique_sources: unique_ips,
            unique_nodes,
            protocol_counts,
        })
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }

    pub async fn load_events_for_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<NetworkBehaviorIndicator>, String> {
        self.load_events_for_run_with_limit(run_id, MAX_DATABASE_LOAD_EVENTS)
            .await
    }

    async fn load_events_for_run_with_limit(
        &self,
        run_id: &str,
        max_events: usize,
    ) -> Result<Vec<NetworkBehaviorIndicator>, String> {
        let query_limit = database_query_limit(max_events)?;
        let rows = sqlx::query(
            "SELECT id, timestamp, node_id, listener, protocol, src_ip, src_port, \
             dst_ip, dst_port, process_name, process_pid, indicators::text AS indicators, event_id \
             FROM nbi_events WHERE run_id = $1 ORDER BY id ASC LIMIT $2",
        )
        .bind(run_id)
        .bind(query_limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("load events error: {}", e))?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let stored = StoredEvent {
                id: row.get::<i64, _>("id"),
                timestamp: row.get::<String, _>("timestamp"),
                node_id: row.get::<String, _>("node_id"),
                listener: row.get::<String, _>("listener"),
                protocol: row.get::<String, _>("protocol"),
                src_ip: row.get::<String, _>("src_ip"),
                src_port: i64::from(row.get::<i32, _>("src_port")),
                dst_ip: row.get::<String, _>("dst_ip"),
                dst_port: i64::from(row.get::<i32, _>("dst_port")),
                process_name: row.get::<Option<String>, _>("process_name"),
                process_pid: row.get::<Option<i32>, _>("process_pid").map(i64::from),
                indicators: row.get::<String, _>("indicators"),
                event_id: row.get::<String, _>("event_id"),
            };
            push_loaded_event(&mut events, stored, max_events)?;
        }

        Ok(events)
    }
}

#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub id: i64,
    pub event_id: String,
    pub timestamp: String,
    pub node_id: String,
    pub listener: String,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: i64,
    pub dst_ip: String,
    pub dst_port: i64,
    pub process_name: Option<String>,
    pub process_pid: Option<i64>,
    pub indicators: String,
}

impl StoredEvent {
    fn try_into_network_behavior_indicator(self) -> Result<NetworkBehaviorIndicator, String> {
        let StoredEvent {
            id,
            event_id,
            timestamp,
            node_id,
            listener,
            protocol,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            process_name,
            process_pid,
            indicators,
        } = self;

        let src_port = validate_port(id, &node_id, "src_port", src_port)?;
        let dst_port = validate_port(id, &node_id, "dst_port", dst_port)?;
        let process_pid = process_pid
            .map(|pid| validate_process_pid(id, &node_id, pid))
            .transpose()?;

        let indicators = serde_json::from_str(&indicators).map_err(|err| {
            format!(
                "stored event {} for node '{}' has invalid indicators JSON: {}",
                id, node_id, err
            )
        })?;
        let src_ip = canonicalize_stored_event_ip(id, &node_id, "src_ip", &src_ip)?;
        let dst_ip = canonicalize_stored_event_destination_ip(id, &node_id, &src_ip, &dst_ip)?;

        let mut event = NetworkBehaviorIndicator {
            event_id,
            timestamp,
            listener: trim_ascii_edges(&listener).to_string(),
            protocol: trim_ascii_edges(&protocol).to_ascii_uppercase(),
            src_ip: src_ip.to_string(),
            src_port,
            dst_ip: dst_ip.to_string(),
            dst_port,
            process_name: normalize_optional_process_name(process_name),
            process_pid,
            indicators,
        };
        event.event_id = event.normalized_event_id();
        event.validate_resource_bounds().map_err(|err| {
            format!(
                "stored event {} for node '{}' failed NBI validation: {}",
                id, node_id, err
            )
        })?;

        Ok(event)
    }
}

fn validate_port(id: i64, node_id: &str, field: &str, value: i64) -> Result<u16, String> {
    u16::try_from(value).map_err(|_| {
        format!(
            "stored event {} for node '{}' has invalid {}: {}",
            id, node_id, field, value
        )
    })
}

fn validate_process_pid(id: i64, node_id: &str, value: i64) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| {
        format!(
            "stored event {} for node '{}' has invalid process_pid: {}",
            id, node_id, value
        )
    })
}

fn canonicalize_stored_event_ip(
    id: i64,
    node_id: &str,
    field: &str,
    ip: &str,
) -> Result<String, String> {
    let ip = ip.parse::<std::net::IpAddr>().map_err(|err| {
        format!(
            "stored event {} for node '{}' has invalid {} '{}': {}",
            id, node_id, field, ip, err
        )
    })?;

    Ok(match ip {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or_else(
            || std::net::IpAddr::V6(ip).to_string(),
            |mapped| mapped.to_string(),
        ),
    })
}

fn canonicalize_stored_event_destination_ip(
    id: i64,
    node_id: &str,
    src_ip: &str,
    dst_ip: &str,
) -> Result<String, String> {
    let dst_ip = canonicalize_stored_event_ip(id, node_id, "dst_ip", dst_ip)?;
    if dst_ip != "0.0.0.0" {
        return Ok(dst_ip);
    }

    let src_ip = src_ip.parse::<std::net::IpAddr>().map_err(|err| {
        format!(
            "stored event {} for node '{}' has invalid src_ip '{}': {}",
            id, node_id, src_ip, err
        )
    })?;

    Ok(match src_ip {
        std::net::IpAddr::V4(_) => dst_ip,
        std::net::IpAddr::V6(_) => std::net::Ipv6Addr::UNSPECIFIED.to_string(),
    })
}

fn postgres_process_pid_param(process_pid: Option<u32>) -> Result<Option<i32>, String> {
    process_pid
        .map(|pid| {
            i32::try_from(pid)
                .map_err(|_| format!("process_pid {} exceeds PostgreSQL INTEGER range", pid))
        })
        .transpose()
}

fn database_query_limit(max_events: usize) -> Result<i64, String> {
    let fetch_limit = max_events
        .checked_add(1)
        .ok_or_else(|| "database event load limit overflows platform usize".to_string())?;
    i64::try_from(fetch_limit).map_err(|_| {
        format!(
            "database event load limit {} exceeds i64 range",
            fetch_limit
        )
    })
}

fn push_loaded_event(
    events: &mut Vec<NetworkBehaviorIndicator>,
    stored: StoredEvent,
    max_events: usize,
) -> Result<(), String> {
    if events.len() >= max_events {
        return Err(format!(
            "database event load exceeds limit ({} > {} events)",
            events.len() + 1,
            max_events
        ));
    }
    events.push(stored.try_into_network_behavior_indicator()?);
    Ok(())
}

#[derive(Debug, Clone)]
pub struct DbStats {
    pub total_events: i64,
    pub unique_sources: i64,
    pub unique_nodes: i64,
    pub protocol_counts: Vec<(String, i64)>,
}

impl DbStats {
    pub fn print_summary(&self) {
        println!("\n=== Database Stats ===");
        println!("Total events:    {}", self.total_events);
        println!("Unique sources:  {}", self.unique_sources);
        println!("Unique nodes:    {}", self.unique_nodes);
        println!("Protocols:");
        for (proto, count) in &self.protocol_counts {
            println!("  {:<12} {}", proto, count);
        }
        println!("======================\n");
    }
}

fn sqlite_stats(conn: &rusqlite::Connection, node_id: Option<&str>) -> Result<DbStats, String> {
    let (count_sql, sources_sql, nodes_sql, protocol_sql) = if node_id.is_some() {
        (
            "SELECT COUNT(*) FROM nbi_events WHERE node_id = ?1",
            "SELECT COUNT(DISTINCT CASE WHEN lower(src_ip) LIKE '::ffff:%' THEN substr(lower(src_ip), 8) ELSE lower(src_ip) END) FROM nbi_events WHERE node_id = ?1",
            "SELECT COUNT(DISTINCT node_id) FROM nbi_events WHERE node_id = ?1",
            "SELECT protocol, COUNT(*) FROM nbi_events WHERE node_id = ?1 GROUP BY protocol ORDER BY COUNT(*) DESC",
        )
    } else {
        (
            "SELECT COUNT(*) FROM nbi_events",
            "SELECT COUNT(DISTINCT CASE WHEN lower(src_ip) LIKE '::ffff:%' THEN substr(lower(src_ip), 8) ELSE lower(src_ip) END) FROM nbi_events",
            "SELECT COUNT(DISTINCT node_id) FROM nbi_events",
            "SELECT protocol, COUNT(*) FROM nbi_events GROUP BY protocol ORDER BY COUNT(*) DESC",
        )
    };

    let total: i64 = if let Some(node_id) = node_id {
        conn.query_row(count_sql, [node_id], |row| row.get(0))
    } else {
        conn.query_row(count_sql, [], |row| row.get(0))
    }
    .map_err(|e| format!("stats error: {}", e))?;

    let mut stmt = conn
        .prepare(protocol_sql)
        .map_err(|e| format!("stats error: {}", e))?;
    let mut protocol_counts = Vec::new();
    if let Some(node_id) = node_id {
        let rows = stmt
            .query_map([node_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| format!("stats error: {}", e))?;
        for row in rows {
            protocol_counts.push(row.map_err(|e| format!("stats error: {}", e))?);
        }
    } else {
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| format!("stats error: {}", e))?;
        for row in rows {
            protocol_counts.push(row.map_err(|e| format!("stats error: {}", e))?);
        }
    }

    let unique_ips: i64 = if let Some(node_id) = node_id {
        conn.query_row(sources_sql, [node_id], |row| row.get(0))
    } else {
        conn.query_row(sources_sql, [], |row| row.get(0))
    }
    .map_err(|e| format!("stats error: {}", e))?;

    let unique_nodes: i64 = if let Some(node_id) = node_id {
        conn.query_row(nodes_sql, [node_id], |row| row.get(0))
    } else {
        conn.query_row(nodes_sql, [], |row| row.get(0))
    }
    .map_err(|e| format!("stats error: {}", e))?;

    Ok(DbStats {
        total_events: total,
        unique_sources: unique_ips,
        unique_nodes,
        protocol_counts,
    })
}

/// Wraps either SQLite or PostgreSQL, providing a uniform async interface
pub enum DatabaseBackend {
    Sqlite(SqliteStorage),
    Postgres(PostgresStorage),
}

impl DatabaseBackend {
    pub async fn insert_event(&self, event: &NetworkBehaviorIndicator) -> Result<(), String> {
        let event = normalize_legacy_nbi_event_for_validation(event);
        event
            .validate_resource_bounds()
            .map_err(|err| format!("NBI validation failed: {}", err))?;

        match self {
            DatabaseBackend::Sqlite(db) => {
                // SQLite operations are blocking, use spawn_blocking to avoid
                // blocking the async runtime
                let conn = Arc::clone(&db.conn);
                let node_id = db.node_id.clone();
                let run_id = db.run_id.clone();
                let timestamp = event.timestamp.clone();
                let listener = event.listener.clone();
                let protocol = event.protocol.clone();
                let src_ip = event.src_ip.clone();
                let src_port = event.src_port;
                let dst_ip = event.dst_ip.clone();
                let dst_port = event.dst_port;
                let process_name = event.process_name.clone();
                let process_pid = event.process_pid;
                let indicators_json = match serde_json::to_string(&event.indicators) {
                    Ok(json) => json,
                    Err(e) => {
                        tracing::warn!("Failed to serialize NBI indicators (SQLite): {}", e);
                        "{}".to_string()
                    }
                };

                let event_id = event.event_id.clone();
                tokio::task::spawn_blocking(move || {
                    let guard = conn.lock();
                    guard.execute(
                        "INSERT INTO nbi_events (event_id, timestamp, node_id, run_id, listener, protocol, src_ip, src_port, dst_ip, dst_port, process_name, process_pid, indicators) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                        rusqlite::params![
                            event_id,
                            timestamp,
                            node_id,
                            run_id,
                            listener,
                            protocol,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                            process_name,
                            process_pid,
                            indicators_json,
                        ],
                    ).map(|_| ()).map_err(|e| format!("SQLite insert error: {}", e))
                })
                .await
                .map_err(|e| format!("spawn_blocking error: {}", e))?
            }
            DatabaseBackend::Postgres(db) => db.insert_event(&event).await,
        }
    }

    pub async fn stats(&self) -> Result<DbStats, String> {
        match self {
            DatabaseBackend::Sqlite(db) => {
                let conn = Arc::clone(&db.conn);

                tokio::task::spawn_blocking(move || {
                    let guard = conn.lock();
                    sqlite_stats(&guard, None)
                })
                .await
                .map_err(|e| format!("spawn_blocking error: {}", e))?
            }
            DatabaseBackend::Postgres(db) => db.stats().await,
        }
    }

    pub async fn stats_for_node(&self, node_id: &str) -> Result<DbStats, String> {
        match self {
            DatabaseBackend::Sqlite(db) => {
                let conn = Arc::clone(&db.conn);
                let node_id = node_id.to_string();

                tokio::task::spawn_blocking(move || {
                    let guard = conn.lock();
                    sqlite_stats(&guard, Some(&node_id))
                })
                .await
                .map_err(|e| format!("spawn_blocking error: {}", e))?
            }
            DatabaseBackend::Postgres(db) => db.stats_for_node(node_id).await,
        }
    }

    pub async fn load_events(&self) -> Result<Vec<NetworkBehaviorIndicator>, String> {
        self.load_events_with_limit(MAX_DATABASE_LOAD_EVENTS).await
    }

    async fn load_events_with_limit(
        &self,
        max_events: usize,
    ) -> Result<Vec<NetworkBehaviorIndicator>, String> {
        let query_limit = database_query_limit(max_events)?;
        match self {
            DatabaseBackend::Sqlite(db) => {
                let conn = Arc::clone(&db.conn);

                tokio::task::spawn_blocking(move || {
                    let guard = conn.lock();
                    let mut stmt = guard
                        .prepare(
                            "SELECT id, timestamp, node_id, listener, protocol, src_ip, src_port, \
                             dst_ip, dst_port, process_name, process_pid, indicators, event_id \
                             FROM nbi_events ORDER BY id ASC LIMIT ?1",
                        )
                        .map_err(|e| format!("load events error: {}", e))?;

                    let rows = stmt
                        .query_map([query_limit], |row| {
                            Ok(StoredEvent {
                                id: row.get(0)?,
                                timestamp: row.get(1)?,
                                node_id: row.get(2)?,
                                listener: row.get(3)?,
                                protocol: row.get(4)?,
                                src_ip: row.get(5)?,
                                src_port: row.get(6)?,
                                dst_ip: row.get(7)?,
                                dst_port: row.get(8)?,
                                process_name: row.get(9)?,
                                process_pid: row.get(10)?,
                                indicators: row.get(11)?,
                                event_id: row.get(12)?,
                            })
                        })
                        .map_err(|e| format!("load events error: {}", e))?;

                    let mut events = Vec::new();
                    for row in rows {
                        let stored = row.map_err(|e| format!("load events error: {}", e))?;
                        push_loaded_event(&mut events, stored, max_events)?;
                    }

                    Ok(events)
                })
                .await
                .map_err(|e| format!("spawn_blocking error: {}", e))?
            }
            DatabaseBackend::Postgres(db) => {
                let rows = sqlx::query(
                    "SELECT id, timestamp, node_id, listener, protocol, src_ip, src_port, \
                     dst_ip, dst_port, process_name, process_pid, indicators::text AS indicators, event_id \
                     FROM nbi_events ORDER BY id ASC LIMIT $1",
                )
                .bind(query_limit)
                .fetch_all(&db.pool)
                .await
                .map_err(|e| format!("load events error: {}", e))?;

                let mut events = Vec::with_capacity(rows.len());
                for row in rows {
                    let stored = StoredEvent {
                        id: row.get::<i64, _>("id"),
                        timestamp: row.get::<String, _>("timestamp"),
                        node_id: row.get::<String, _>("node_id"),
                        listener: row.get::<String, _>("listener"),
                        protocol: row.get::<String, _>("protocol"),
                        src_ip: row.get::<String, _>("src_ip"),
                        src_port: i64::from(row.get::<i32, _>("src_port")),
                        dst_ip: row.get::<String, _>("dst_ip"),
                        dst_port: i64::from(row.get::<i32, _>("dst_port")),
                        process_name: row.get::<Option<String>, _>("process_name"),
                        process_pid: row.get::<Option<i32>, _>("process_pid").map(i64::from),
                        indicators: row.get::<String, _>("indicators"),
                        event_id: row.get::<String, _>("event_id"),
                    };
                    push_loaded_event(&mut events, stored, max_events)?;
                }

                Ok(events)
            }
        }
    }

    pub async fn load_events_for_node(
        &self,
        node_id: &str,
    ) -> Result<Vec<NetworkBehaviorIndicator>, String> {
        self.load_events_for_node_with_limit(node_id, MAX_DATABASE_LOAD_EVENTS)
            .await
    }

    async fn load_events_for_node_with_limit(
        &self,
        node_id: &str,
        max_events: usize,
    ) -> Result<Vec<NetworkBehaviorIndicator>, String> {
        let query_limit = database_query_limit(max_events)?;
        match self {
            DatabaseBackend::Sqlite(db) => {
                let conn = Arc::clone(&db.conn);
                let node_id = node_id.to_string();

                tokio::task::spawn_blocking(move || {
                    let guard = conn.lock();
                    let mut stmt = guard
                        .prepare(
                            "SELECT id, timestamp, node_id, listener, protocol, src_ip, src_port, \
                             dst_ip, dst_port, process_name, process_pid, indicators, event_id \
                             FROM nbi_events WHERE node_id = ?1 ORDER BY id ASC LIMIT ?2",
                        )
                        .map_err(|e| format!("load events error: {}", e))?;

                    let rows = stmt
                        .query_map(rusqlite::params![node_id, query_limit], |row| {
                            Ok(StoredEvent {
                                id: row.get(0)?,
                                timestamp: row.get(1)?,
                                node_id: row.get(2)?,
                                listener: row.get(3)?,
                                protocol: row.get(4)?,
                                src_ip: row.get(5)?,
                                src_port: row.get(6)?,
                                dst_ip: row.get(7)?,
                                dst_port: row.get(8)?,
                                process_name: row.get(9)?,
                                process_pid: row.get(10)?,
                                indicators: row.get(11)?,
                                event_id: row.get(12)?,
                            })
                        })
                        .map_err(|e| format!("load events error: {}", e))?;

                    let mut events = Vec::new();
                    for row in rows {
                        let stored = row.map_err(|e| format!("load events error: {}", e))?;
                        push_loaded_event(&mut events, stored, max_events)?;
                    }

                    Ok(events)
                })
                .await
                .map_err(|e| format!("spawn_blocking error: {}", e))?
            }
            DatabaseBackend::Postgres(db) => {
                let rows = sqlx::query(
                    "SELECT id, timestamp, node_id, listener, protocol, src_ip, src_port, \
                     dst_ip, dst_port, process_name, process_pid, indicators::text AS indicators, event_id \
                     FROM nbi_events WHERE node_id = $1 ORDER BY id ASC LIMIT $2",
                )
                .bind(node_id)
                .bind(query_limit)
                .fetch_all(&db.pool)
                .await
                .map_err(|e| format!("load events error: {}", e))?;

                let mut events = Vec::with_capacity(rows.len());
                for row in rows {
                    let stored = StoredEvent {
                        id: row.get::<i64, _>("id"),
                        timestamp: row.get::<String, _>("timestamp"),
                        node_id: row.get::<String, _>("node_id"),
                        listener: row.get::<String, _>("listener"),
                        protocol: row.get::<String, _>("protocol"),
                        src_ip: row.get::<String, _>("src_ip"),
                        src_port: i64::from(row.get::<i32, _>("src_port")),
                        dst_ip: row.get::<String, _>("dst_ip"),
                        dst_port: i64::from(row.get::<i32, _>("dst_port")),
                        process_name: row.get::<Option<String>, _>("process_name"),
                        process_pid: row.get::<Option<i32>, _>("process_pid").map(i64::from),
                        indicators: row.get::<String, _>("indicators"),
                        event_id: row.get::<String, _>("event_id"),
                    };
                    push_loaded_event(&mut events, stored, max_events)?;
                }

                Ok(events)
            }
        }
    }

    pub async fn load_events_for_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<NetworkBehaviorIndicator>, String> {
        self.load_events_for_run_with_limit(run_id, MAX_DATABASE_LOAD_EVENTS)
            .await
    }

    async fn load_events_for_run_with_limit(
        &self,
        run_id: &str,
        max_events: usize,
    ) -> Result<Vec<NetworkBehaviorIndicator>, String> {
        let query_limit = database_query_limit(max_events)?;
        match self {
            DatabaseBackend::Sqlite(db) => {
                let conn = Arc::clone(&db.conn);
                let run_id = run_id.to_string();

                tokio::task::spawn_blocking(move || {
                    let guard = conn.lock();
                    let mut stmt = guard
                        .prepare(
                            "SELECT id, timestamp, node_id, listener, protocol, src_ip, src_port, \
                             dst_ip, dst_port, process_name, process_pid, indicators, event_id \
                             FROM nbi_events WHERE run_id = ?1 ORDER BY id ASC LIMIT ?2",
                        )
                        .map_err(|e| format!("load events error: {}", e))?;

                    let rows = stmt
                        .query_map(rusqlite::params![run_id, query_limit], |row| {
                            Ok(StoredEvent {
                                id: row.get(0)?,
                                timestamp: row.get(1)?,
                                node_id: row.get(2)?,
                                listener: row.get(3)?,
                                protocol: row.get(4)?,
                                src_ip: row.get(5)?,
                                src_port: row.get(6)?,
                                dst_ip: row.get(7)?,
                                dst_port: row.get(8)?,
                                process_name: row.get(9)?,
                                process_pid: row.get(10)?,
                                indicators: row.get(11)?,
                                event_id: row.get(12)?,
                            })
                        })
                        .map_err(|e| format!("load events error: {}", e))?;

                    let mut events = Vec::new();
                    for row in rows {
                        let stored = row.map_err(|e| format!("load events error: {}", e))?;
                        push_loaded_event(&mut events, stored, max_events)?;
                    }

                    Ok(events)
                })
                .await
                .map_err(|e| format!("spawn_blocking error: {}", e))?
            }
            DatabaseBackend::Postgres(db) => {
                db.load_events_for_run_with_limit(run_id, max_events).await
            }
        }
    }

    pub async fn close(&self) {
        match self {
            DatabaseBackend::Sqlite(_) => {}
            DatabaseBackend::Postgres(db) => db.close().await,
        }
    }
}

/// Initialize database from config. Returns `Ok(None)` only when DB is disabled.
pub async fn init_database(
    config: &DatabaseConfig,
    run_id: &str,
) -> Result<Option<DatabaseBackend>, String> {
    match config.backend.as_str() {
        "none" => Ok(None),
        "" => Err("Database backend must not be blank".into()),
        "sqlite" => {
            let path = config
                .sqlite_path
                .as_deref()
                .unwrap_or(Path::new("nettrap.db"));
            let node_id = config.node_id.as_deref().unwrap_or("standalone");
            SqliteStorage::new(path, node_id, run_id)
                .map(DatabaseBackend::Sqlite)
                .map(Some)
        }
        "postgres" | "postgresql" => {
            let url = match &config.postgres_url {
                Some(u) => u.as_str(),
                None => {
                    return Err("PostgreSQL backend configured but no postgres_url provided".into());
                }
            };
            let node_id = config.node_id.as_deref().unwrap_or("standalone");
            PostgresStorage::new(url, node_id, run_id, config.pool_size)
                .await
                .map(DatabaseBackend::Postgres)
                .map(Some)
        }
        backend => Err(format!("Unknown database backend '{}'", backend)),
    }
}

// ─── SQL Schemas ─────────────────────────────────────────────────────────────

const SQLITE_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS nbi_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL,
    node_id TEXT NOT NULL DEFAULT 'standalone',
    run_id TEXT NOT NULL DEFAULT '',
    listener TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip TEXT NOT NULL DEFAULT '0.0.0.0',
    dst_port INTEGER NOT NULL,
    process_name TEXT,
    process_pid INTEGER,
    indicators TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (datetime('now'))
);
"#;

const SQLITE_INDEX_SQL: &str = r#"
CREATE INDEX IF NOT EXISTS idx_nbi_timestamp ON nbi_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_nbi_node_id ON nbi_events (node_id);
CREATE INDEX IF NOT EXISTS idx_nbi_run_id ON nbi_events (run_id);
CREATE INDEX IF NOT EXISTS idx_nbi_event_id ON nbi_events (event_id);
CREATE INDEX IF NOT EXISTS idx_nbi_protocol ON nbi_events (protocol);
CREATE INDEX IF NOT EXISTS idx_nbi_src_ip ON nbi_events (src_ip);
CREATE INDEX IF NOT EXISTS idx_nbi_dst_ip ON nbi_events (dst_ip);
"#;

const PG_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS nbi_events (
    id BIGSERIAL PRIMARY KEY,
    event_id VARCHAR(128) NOT NULL DEFAULT '',
    timestamp VARCHAR(64) NOT NULL,
    node_id VARCHAR(128) NOT NULL DEFAULT 'standalone',
    run_id VARCHAR(128) NOT NULL DEFAULT '',
    listener VARCHAR(64) NOT NULL,
    protocol VARCHAR(32) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip VARCHAR(45) NOT NULL DEFAULT '0.0.0.0',
    dst_port INTEGER NOT NULL,
    process_name VARCHAR(256),
    process_pid INTEGER,
    indicators JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_nbi_timestamp ON nbi_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_nbi_node_id ON nbi_events (node_id);
CREATE INDEX IF NOT EXISTS idx_nbi_run_id ON nbi_events (run_id);
CREATE INDEX IF NOT EXISTS idx_nbi_event_id ON nbi_events (event_id);
CREATE INDEX IF NOT EXISTS idx_nbi_protocol ON nbi_events (protocol);
CREATE INDEX IF NOT EXISTS idx_nbi_src_ip ON nbi_events (src_ip);
CREATE INDEX IF NOT EXISTS idx_nbi_dst_ip ON nbi_events (dst_ip);
"#;

#[cfg(test)]
#[path = "database_tests.rs"]
mod tests;
