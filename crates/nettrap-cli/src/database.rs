//! Database storage for NBI events.
//! Supports SQLite (standalone) and PostgreSQL (distributed).
//! All database features are optional — file-based JSONL remains the default.

use crate::config::DatabaseConfig;
use crate::nbi::NetworkBehaviorIndicator;
use sqlx::Row;
use std::sync::Arc;

// ─── SQLite Backend ──────────────────────────────────────────────────────────

pub struct SqliteStorage {
    conn: Arc<parking_lot::Mutex<rusqlite::Connection>>,
    node_id: String,
    run_id: String,
}

impl SqliteStorage {
    pub fn new(path: &str, node_id: &str, run_id: &str) -> Result<Self, String> {
        let conn =
            rusqlite::Connection::open(path).map_err(|e| format!("SQLite open error: {}", e))?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| format!("SQLite pragma error: {}", e))?;

        conn.execute_batch(SCHEMA_SQL)
            .map_err(|e| format!("SQLite schema error: {}", e))?;
        ensure_sqlite_schema(&conn)?;

        tracing::info!("SQLite database initialized at {}", path);

        Ok(Self {
            conn: Arc::new(parking_lot::Mutex::new(conn)),
            node_id: node_id.to_string(),
            run_id: run_id.to_string(),
        })
    }
}

// ─── PostgreSQL Backend ───────────────────────────────────────────────────────

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
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(pool_size)
            .connect(url)
            .await
            .map_err(|e| format!("PostgreSQL connect error: {}", e))?;

        sqlx::query(PG_SCHEMA_SQL)
            .execute(&pool)
            .await
            .map_err(|e| format!("PostgreSQL schema error: {}", e))?;

        if let Err(e) =
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_nbi_timestamp ON nbi_events (timestamp)")
                .execute(&pool)
                .await
        {
            tracing::warn!("Failed to create index idx_nbi_timestamp: {}", e);
        }
        if let Err(e) =
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_nbi_node_id ON nbi_events (node_id)")
                .execute(&pool)
                .await
        {
            tracing::warn!("Failed to create index idx_nbi_node_id: {}", e);
        }
        if let Err(e) =
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_nbi_protocol ON nbi_events (protocol)")
                .execute(&pool)
                .await
        {
            tracing::warn!("Failed to create index idx_nbi_protocol: {}", e);
        }
        if let Err(e) =
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_nbi_src_ip ON nbi_events (src_ip)")
                .execute(&pool)
                .await
        {
            tracing::warn!("Failed to create index idx_nbi_src_ip: {}", e);
        }
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
        let indicators_json = match serde_json::to_string(&event.indicators) {
            Ok(json) => json,
            Err(e) => {
                tracing::warn!("Failed to serialize NBI indicators: {}", e);
                "{}".to_string()
            }
        };

        sqlx::query(
            "INSERT INTO nbi_events (event_id, timestamp, node_id, run_id, listener, protocol, src_ip, src_port, dst_ip, dst_port, process_name, process_pid, indicators) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)"
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
            .bind(event.process_pid.map(|p| p as i32))
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

        let (unique_ips,): (i64,) = sqlx::query_as("SELECT COUNT(DISTINCT src_ip) FROM nbi_events")
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

        let (unique_ips,): (i64,) =
            sqlx::query_as("SELECT COUNT(DISTINCT src_ip) FROM nbi_events WHERE node_id = $1")
                .bind(node_id)
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

    pub async fn close(&self) {
        self.pool.close().await;
    }

    pub async fn load_events_for_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<NetworkBehaviorIndicator>, String> {
        let rows = sqlx::query(
            "SELECT id, timestamp, node_id, listener, protocol, src_ip, src_port, \
             dst_ip, dst_port, process_name, process_pid, indicators::text AS indicators, event_id \
             FROM nbi_events WHERE run_id = $1 ORDER BY id ASC",
        )
        .bind(run_id)
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
                src_port: row.get::<i32, _>("src_port") as u16,
                dst_ip: row.get::<String, _>("dst_ip"),
                dst_port: row.get::<i32, _>("dst_port") as u16,
                process_name: row.get::<Option<String>, _>("process_name"),
                process_pid: row
                    .get::<Option<i32>, _>("process_pid")
                    .map(|pid| pid as u32),
                indicators: row.get::<String, _>("indicators"),
                event_id: row.get::<String, _>("event_id"),
            };
            events.push(stored.try_into_network_behavior_indicator()?);
        }

        Ok(events)
    }
}

// ─── Shared Types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub id: i64,
    pub event_id: String,
    pub timestamp: String,
    pub node_id: String,
    pub listener: String,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
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

        let indicators = serde_json::from_str(&indicators).map_err(|err| {
            format!(
                "stored event {} for node '{}' has invalid indicators JSON: {}",
                id, node_id, err
            )
        })?;

        let mut event = NetworkBehaviorIndicator {
            event_id,
            timestamp,
            listener,
            protocol,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            process_name,
            process_pid,
            indicators,
        };
        event.event_id = event.normalized_event_id();

        Ok(event)
    }
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
            "SELECT COUNT(DISTINCT src_ip) FROM nbi_events WHERE node_id = ?1",
            "SELECT COUNT(DISTINCT node_id) FROM nbi_events",
            "SELECT protocol, COUNT(*) FROM nbi_events WHERE node_id = ?1 GROUP BY protocol ORDER BY COUNT(*) DESC",
        )
    } else {
        (
            "SELECT COUNT(*) FROM nbi_events",
            "SELECT COUNT(DISTINCT src_ip) FROM nbi_events",
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

    // nodes_sql always counts all nodes (no per-node filter makes sense here)
    let unique_nodes: i64 = conn
        .query_row(nodes_sql, [], |row| row.get(0))
        .map_err(|e| format!("stats error: {}", e))?;

    Ok(DbStats {
        total_events: total,
        unique_sources: unique_ips,
        unique_nodes,
        protocol_counts,
    })
}

// ─── Unified Database Wrapper ────────────────────────────────────────────────

/// Wraps either SQLite or PostgreSQL, providing a uniform async interface
pub enum DatabaseBackend {
    Sqlite(SqliteStorage),
    Postgres(PostgresStorage),
}

impl DatabaseBackend {
    pub async fn insert_event(&self, event: &NetworkBehaviorIndicator) -> Result<(), String> {
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
            DatabaseBackend::Postgres(db) => db.insert_event(event).await,
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
        match self {
            DatabaseBackend::Sqlite(db) => {
                let conn = Arc::clone(&db.conn);

                tokio::task::spawn_blocking(move || {
                    let guard = conn.lock();
                    let mut stmt = guard
                        .prepare(
                            "SELECT id, timestamp, node_id, listener, protocol, src_ip, src_port, \
                             dst_ip, dst_port, process_name, process_pid, indicators, event_id \
                             FROM nbi_events ORDER BY id ASC",
                        )
                        .map_err(|e| format!("load events error: {}", e))?;

                    let rows = stmt
                        .query_map([], |row| {
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
                        events.push(stored.try_into_network_behavior_indicator()?);
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
                     FROM nbi_events ORDER BY id ASC",
                )
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
                        src_port: row.get::<i32, _>("src_port") as u16,
                        dst_ip: row.get::<String, _>("dst_ip"),
                        dst_port: row.get::<i32, _>("dst_port") as u16,
                        process_name: row.get::<Option<String>, _>("process_name"),
                        process_pid: row
                            .get::<Option<i32>, _>("process_pid")
                            .map(|pid| pid as u32),
                        indicators: row.get::<String, _>("indicators"),
                        event_id: row.get::<String, _>("event_id"),
                    };
                    events.push(stored.try_into_network_behavior_indicator()?);
                }

                Ok(events)
            }
        }
    }

    pub async fn load_events_for_node(
        &self,
        node_id: &str,
    ) -> Result<Vec<NetworkBehaviorIndicator>, String> {
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
                             FROM nbi_events WHERE node_id = ?1 ORDER BY id ASC",
                        )
                        .map_err(|e| format!("load events error: {}", e))?;

                    let rows = stmt
                        .query_map([node_id], |row| {
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
                        events.push(stored.try_into_network_behavior_indicator()?);
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
                     FROM nbi_events WHERE node_id = $1 ORDER BY id ASC",
                )
                .bind(node_id)
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
                        src_port: row.get::<i32, _>("src_port") as u16,
                        dst_ip: row.get::<String, _>("dst_ip"),
                        dst_port: row.get::<i32, _>("dst_port") as u16,
                        process_name: row.get::<Option<String>, _>("process_name"),
                        process_pid: row
                            .get::<Option<i32>, _>("process_pid")
                            .map(|pid| pid as u32),
                        indicators: row.get::<String, _>("indicators"),
                        event_id: row.get::<String, _>("event_id"),
                    };
                    events.push(stored.try_into_network_behavior_indicator()?);
                }

                Ok(events)
            }
        }
    }

    pub async fn load_events_for_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<NetworkBehaviorIndicator>, String> {
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
                             FROM nbi_events WHERE run_id = ?1 ORDER BY id ASC",
                        )
                        .map_err(|e| format!("load events error: {}", e))?;

                    let rows = stmt
                        .query_map([run_id], |row| {
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
                        events.push(stored.try_into_network_behavior_indicator()?);
                    }

                    Ok(events)
                })
                .await
                .map_err(|e| format!("spawn_blocking error: {}", e))?
            }
            DatabaseBackend::Postgres(db) => db.load_events_for_run(run_id).await,
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
        "" | "none" => Ok(None),
        "sqlite" => {
            let path = config.sqlite_path.as_deref().unwrap_or("nettrap.db");
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

fn ensure_sqlite_schema(conn: &rusqlite::Connection) -> Result<(), String> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(nbi_events)")
        .map_err(|e| format!("SQLite pragma error: {}", e))?;
    let columns: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| format!("SQLite pragma error: {}", e))?
        .filter_map(|row| row.ok())
        .collect();

    if !columns.iter().any(|column| column == "dst_ip") {
        conn.execute(
            "ALTER TABLE nbi_events ADD COLUMN dst_ip TEXT NOT NULL DEFAULT '0.0.0.0'",
            [],
        )
        .map_err(|e| format!("SQLite migration error: {}", e))?;
    }

    if !columns.iter().any(|column| column == "run_id") {
        conn.execute(
            "ALTER TABLE nbi_events ADD COLUMN run_id TEXT NOT NULL DEFAULT ''",
            [],
        )
        .map_err(|e| format!("SQLite migration error: {}", e))?;
    }

    if !columns.iter().any(|column| column == "event_id") {
        conn.execute(
            "ALTER TABLE nbi_events ADD COLUMN event_id TEXT NOT NULL DEFAULT ''",
            [],
        )
        .map_err(|e| format!("SQLite migration error: {}", e))?;
    }

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_nbi_dst_ip ON nbi_events (dst_ip)",
        [],
    )
    .map_err(|e| format!("SQLite index error: {}", e))?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_nbi_run_id ON nbi_events (run_id)",
        [],
    )
    .map_err(|e| format!("SQLite index error: {}", e))?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_nbi_event_id ON nbi_events (event_id)",
        [],
    )
    .map_err(|e| format!("SQLite index error: {}", e))?;

    Ok(())
}

async fn ensure_postgres_schema(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "ALTER TABLE nbi_events ADD COLUMN IF NOT EXISTS dst_ip VARCHAR(45) NOT NULL DEFAULT '0.0.0.0'",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "ALTER TABLE nbi_events ADD COLUMN IF NOT EXISTS run_id VARCHAR(128) NOT NULL DEFAULT ''",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "ALTER TABLE nbi_events ADD COLUMN IF NOT EXISTS event_id VARCHAR(128) NOT NULL DEFAULT ''",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_nbi_dst_ip ON nbi_events (dst_ip)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_nbi_run_id ON nbi_events (run_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_nbi_event_id ON nbi_events (event_id)")
        .execute(pool)
        .await?;
    Ok(())
}

const SCHEMA_SQL: &str = r#"
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
mod tests {
    use super::*;
    use crate::nbi::raw_nbi;
    use crate::session::SessionDestination;

    const TEST_RUN_ID: &str = "test-run";

    fn cleanup_sqlite(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[tokio::test]
    async fn stats_for_node_only_counts_events_for_current_node() {
        let db_path =
            std::env::temp_dir().join(format!("nettrap-db-stats-node-{}.db", uuid::Uuid::new_v4()));
        let current = DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path.to_string_lossy(), "current-node", TEST_RUN_ID).unwrap(),
        );
        let other = DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path.to_string_lossy(), "other-node", TEST_RUN_ID).unwrap(),
        );

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
            "127.0.0.2",
            12346,
            &SessionDestination::unknown(8081),
            4,
            "",
        );
        current.insert_event(&current_event).await.unwrap();
        other.insert_event(&other_event).await.unwrap();

        let stats = current.stats_for_node("current-node").await.unwrap();
        assert_eq!(stats.total_events, 1);
        assert_eq!(stats.unique_sources, 1);
        assert_eq!(stats.unique_nodes, 2); // counts all nodes in DB, not just current
        assert_eq!(stats.protocol_counts.len(), 1);
        assert_eq!(stats.protocol_counts[0], ("RAW".to_string(), 1));

        cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn load_events_for_node_fails_when_indicators_are_corrupt() {
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-db-corrupt-indicators-{}.db",
            uuid::Uuid::new_v4()
        ));
        let db = DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path.to_string_lossy(), "test-node", TEST_RUN_ID).unwrap(),
        );

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
        let db = DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path.to_string_lossy(), "test-node", TEST_RUN_ID).unwrap(),
        );

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
        let current = DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path.to_string_lossy(), "test-node", "run-a").unwrap(),
        );
        let previous = DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path.to_string_lossy(), "test-node", "run-b").unwrap(),
        );

        let current_event = raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &SessionDestination::unknown(8080),
            4,
            "",
        );
        let previous_event = raw_nbi(
            "raw",
            "127.0.0.2",
            12346,
            &SessionDestination::unknown(8081),
            4,
            "",
        );
        current.insert_event(&current_event).await.unwrap();
        previous.insert_event(&previous_event).await.unwrap();

        let events = current.load_events_for_run("run-a").await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].src_ip, "127.0.0.1");

        cleanup_sqlite(&db_path);
    }
}
