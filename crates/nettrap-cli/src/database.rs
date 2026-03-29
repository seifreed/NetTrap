//! Database storage for NBI events.
//! Supports SQLite (standalone) and MariaDB/MySQL (distributed).
//! All database features are optional — file-based JSONL remains the default.

use crate::config::DatabaseConfig;
use crate::nbi::NetworkBehaviorIndicator;

// ─── SQLite Backend ──────────────────────────────────────────────────────────

pub struct SqliteStorage {
    conn: parking_lot::Mutex<rusqlite::Connection>,
    node_id: String,
}

impl SqliteStorage {
    pub fn new(path: &str, node_id: &str) -> Result<Self, String> {
        let conn = rusqlite::Connection::open(path)
            .map_err(|e| format!("SQLite open error: {}", e))?;

        // Enable WAL mode for concurrent reads during writes
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| format!("SQLite pragma error: {}", e))?;

        // Create tables
        conn.execute_batch(SCHEMA_SQL)
            .map_err(|e| format!("SQLite schema error: {}", e))?;

        tracing::info!("SQLite database initialized at {}", path);

        Ok(Self {
            conn: parking_lot::Mutex::new(conn),
            node_id: node_id.to_string(),
        })
    }

    pub fn insert_event(&self, event: &NetworkBehaviorIndicator) -> Result<(), String> {
        let conn = self.conn.lock();
        let indicators_json = serde_json::to_string(&event.indicators).unwrap_or_default();

        conn.execute(
            "INSERT INTO nbi_events (timestamp, node_id, listener, protocol, src_ip, src_port, dst_port, process_name, process_pid, indicators) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                event.timestamp,
                self.node_id,
                event.listener,
                event.protocol,
                event.src_ip,
                event.src_port,
                event.dst_port,
                event.process_name,
                event.process_pid,
                indicators_json,
            ],
        ).map_err(|e| format!("SQLite insert error: {}", e))?;

        Ok(())
    }

    pub fn query_events(&self, limit: usize) -> Result<Vec<StoredEvent>, String> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, node_id, listener, protocol, src_ip, src_port, dst_port, process_name, process_pid, indicators FROM nbi_events ORDER BY id DESC LIMIT ?1"
        ).map_err(|e| format!("SQLite query error: {}", e))?;

        let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
            Ok(StoredEvent {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                node_id: row.get(2)?,
                listener: row.get(3)?,
                protocol: row.get(4)?,
                src_ip: row.get(5)?,
                src_port: row.get(6)?,
                dst_port: row.get(7)?,
                process_name: row.get(8)?,
                process_pid: row.get(9)?,
                indicators: row.get(10)?,
            })
        }).map_err(|e| format!("SQLite query error: {}", e))?;

        let mut events = Vec::new();
        for row in rows {
            if let Ok(event) = row {
                events.push(event);
            }
        }
        Ok(events)
    }

    pub fn count_events(&self) -> Result<i64, String> {
        let conn = self.conn.lock();
        conn.query_row("SELECT COUNT(*) FROM nbi_events", [], |row| row.get(0))
            .map_err(|e| format!("SQLite count error: {}", e))
    }

    pub fn stats(&self) -> Result<DbStats, String> {
        let conn = self.conn.lock();

        let total: i64 = conn.query_row("SELECT COUNT(*) FROM nbi_events", [], |row| row.get(0))
            .map_err(|e| format!("stats error: {}", e))?;

        let mut stmt = conn.prepare("SELECT protocol, COUNT(*) FROM nbi_events GROUP BY protocol ORDER BY COUNT(*) DESC")
            .map_err(|e| format!("stats error: {}", e))?;
        let protocol_counts: Vec<(String, i64)> = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        }).map_err(|e| format!("stats error: {}", e))?
        .filter_map(|r| r.ok())
        .collect();

        let mut stmt = conn.prepare("SELECT COUNT(DISTINCT src_ip) FROM nbi_events")
            .map_err(|e| format!("stats error: {}", e))?;
        let unique_ips: i64 = stmt.query_row([], |row| row.get(0))
            .map_err(|e| format!("stats error: {}", e))?;

        let mut stmt = conn.prepare("SELECT COUNT(DISTINCT node_id) FROM nbi_events")
            .map_err(|e| format!("stats error: {}", e))?;
        let unique_nodes: i64 = stmt.query_row([], |row| row.get(0))
            .map_err(|e| format!("stats error: {}", e))?;

        Ok(DbStats {
            total_events: total,
            unique_sources: unique_ips,
            unique_nodes,
            protocol_counts,
        })
    }
}

// ─── MariaDB/MySQL Backend ───────────────────────────────────────────────────

pub struct MysqlStorage {
    pool: sqlx::MySqlPool,
    node_id: String,
}

impl MysqlStorage {
    pub async fn new(url: &str, node_id: &str, pool_size: u32) -> Result<Self, String> {
        let pool = sqlx::mysql::MySqlPoolOptions::new()
            .max_connections(pool_size)
            .connect(url)
            .await
            .map_err(|e| format!("MariaDB connect error: {}", e))?;

        // Create tables if they don't exist
        sqlx::query(MYSQL_SCHEMA_SQL)
            .execute(&pool)
            .await
            .map_err(|e| format!("MariaDB schema error: {}", e))?;

        // Create indexes
        let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_nbi_timestamp ON nbi_events (timestamp)")
            .execute(&pool).await;
        let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_nbi_node_id ON nbi_events (node_id)")
            .execute(&pool).await;
        let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_nbi_protocol ON nbi_events (protocol)")
            .execute(&pool).await;
        let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_nbi_src_ip ON nbi_events (src_ip)")
            .execute(&pool).await;

        tracing::info!("MariaDB/MySQL connected to {} (pool_size={})", url.split('@').last().unwrap_or(url), pool_size);

        Ok(Self {
            pool,
            node_id: node_id.to_string(),
        })
    }

    pub async fn insert_event(&self, event: &NetworkBehaviorIndicator) -> Result<(), String> {
        let indicators_json = serde_json::to_string(&event.indicators).unwrap_or_default();

        sqlx::query(
            "INSERT INTO nbi_events (timestamp, node_id, listener, protocol, src_ip, src_port, dst_port, process_name, process_pid, indicators) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
            .bind(&event.timestamp)
            .bind(&self.node_id)
            .bind(&event.listener)
            .bind(&event.protocol)
            .bind(&event.src_ip)
            .bind(event.src_port)
            .bind(event.dst_port)
            .bind(&event.process_name)
            .bind(&event.process_pid)
            .bind(&indicators_json)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("MariaDB insert error: {}", e))?;

        Ok(())
    }

    pub async fn count_events(&self) -> Result<i64, String> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM nbi_events")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| format!("MariaDB count error: {}", e))?;
        Ok(row.0)
    }

    pub async fn stats(&self) -> Result<DbStats, String> {
        let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM nbi_events")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| format!("stats error: {}", e))?;

        let protocol_counts: Vec<(String, i64)> = sqlx::query_as(
            "SELECT protocol, COUNT(*) as cnt FROM nbi_events GROUP BY protocol ORDER BY cnt DESC"
        )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| format!("stats error: {}", e))?;

        let (unique_ips,): (i64,) = sqlx::query_as("SELECT COUNT(DISTINCT src_ip) FROM nbi_events")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| format!("stats error: {}", e))?;

        let (unique_nodes,): (i64,) = sqlx::query_as("SELECT COUNT(DISTINCT node_id) FROM nbi_events")
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
}

// ─── Shared Types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub id: i64,
    pub timestamp: String,
    pub node_id: String,
    pub listener: String,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub indicators: String,
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

// ─── Unified Database Wrapper ────────────────────────────────────────────────

/// Wraps either SQLite or MySQL, providing a uniform async interface
pub enum DatabaseBackend {
    Sqlite(SqliteStorage),
    Mysql(MysqlStorage),
}

impl DatabaseBackend {
    pub async fn insert_event(&self, event: &NetworkBehaviorIndicator) -> Result<(), String> {
        match self {
            DatabaseBackend::Sqlite(db) => db.insert_event(event),
            DatabaseBackend::Mysql(db) => db.insert_event(event).await,
        }
    }

    pub async fn stats(&self) -> Result<DbStats, String> {
        match self {
            DatabaseBackend::Sqlite(db) => db.stats(),
            DatabaseBackend::Mysql(db) => db.stats().await,
        }
    }

    pub async fn close(&self) {
        match self {
            DatabaseBackend::Sqlite(_) => {} // SQLite drops on its own
            DatabaseBackend::Mysql(db) => db.close().await,
        }
    }
}

/// Initialize database from config. Returns None if backend = "none" or empty.
pub async fn init_database(config: &DatabaseConfig) -> Option<DatabaseBackend> {
    match config.backend.as_str() {
        "sqlite" => {
            let path = config.sqlite_path.as_deref().unwrap_or("nettrap.db");
            let node_id = config.node_id.as_deref().unwrap_or("standalone");
            match SqliteStorage::new(path, node_id) {
                Ok(db) => Some(DatabaseBackend::Sqlite(db)),
                Err(e) => {
                    tracing::warn!("Failed to initialize SQLite: {}", e);
                    None
                }
            }
        }
        "mariadb" | "mysql" => {
            let url = match &config.mysql_url {
                Some(u) => u.as_str(),
                None => {
                    tracing::warn!("MariaDB/MySQL backend configured but no mysql_url provided");
                    return None;
                }
            };
            let node_id = config.node_id.as_deref().unwrap_or("standalone");
            match MysqlStorage::new(url, node_id, config.pool_size).await {
                Ok(db) => Some(DatabaseBackend::Mysql(db)),
                Err(e) => {
                    tracing::warn!("Failed to initialize MariaDB/MySQL: {}", e);
                    None
                }
            }
        }
        _ => None,
    }
}

// ─── SQL Schemas ─────────────────────────────────────────────────────────────

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS nbi_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    node_id TEXT NOT NULL DEFAULT 'standalone',
    listener TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    process_name TEXT,
    process_pid INTEGER,
    indicators TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_nbi_timestamp ON nbi_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_nbi_node_id ON nbi_events (node_id);
CREATE INDEX IF NOT EXISTS idx_nbi_protocol ON nbi_events (protocol);
CREATE INDEX IF NOT EXISTS idx_nbi_src_ip ON nbi_events (src_ip);
"#;

const MYSQL_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS nbi_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp VARCHAR(64) NOT NULL,
    node_id VARCHAR(128) NOT NULL DEFAULT 'standalone',
    listener VARCHAR(64) NOT NULL,
    protocol VARCHAR(32) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    src_port INT UNSIGNED NOT NULL,
    dst_port INT UNSIGNED NOT NULL,
    process_name VARCHAR(256),
    process_pid INT UNSIGNED,
    indicators JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"#;
