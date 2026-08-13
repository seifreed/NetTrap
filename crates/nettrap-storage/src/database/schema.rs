//! Idempotent schema migration helpers for the SQLite and PostgreSQL backends.

pub(crate) fn ensure_sqlite_schema(conn: &rusqlite::Connection) -> Result<(), String> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(nbi_events)")
        .map_err(|e| format!("SQLite pragma error: {}", e))?;
    let columns: Vec<SqliteColumn> = stmt
        .query_map([], |row| {
            Ok(SqliteColumn {
                name: row.get(1)?,
                not_null: row.get::<_, i64>(3)? != 0,
                default_value: row.get(4)?,
                primary_key: row.get::<_, i64>(5)? != 0,
            })
        })
        .map_err(|e| format!("SQLite pragma error: {}", e))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(sqlite_pragma_row_error)?;
    drop(stmt);

    if sqlite_schema_needs_rebuild(&columns) {
        rebuild_sqlite_nbi_events(conn, &columns)?;
        return ensure_sqlite_schema(conn);
    }

    add_sqlite_column_if_missing(conn, &columns, "event_id", "TEXT NOT NULL DEFAULT ''")?;
    add_sqlite_column_if_missing(
        conn,
        &columns,
        "timestamp",
        "TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z'",
    )?;
    add_sqlite_column_if_missing(
        conn,
        &columns,
        "node_id",
        "TEXT NOT NULL DEFAULT 'standalone'",
    )?;
    add_sqlite_column_if_missing(conn, &columns, "run_id", "TEXT NOT NULL DEFAULT ''")?;
    add_sqlite_column_if_missing(conn, &columns, "listener", "TEXT NOT NULL DEFAULT 'legacy'")?;
    add_sqlite_column_if_missing(conn, &columns, "protocol", "TEXT NOT NULL DEFAULT 'RAW'")?;
    add_sqlite_column_if_missing(conn, &columns, "src_ip", "TEXT NOT NULL DEFAULT '0.0.0.0'")?;
    add_sqlite_column_if_missing(conn, &columns, "src_port", "INTEGER NOT NULL DEFAULT 0")?;
    add_sqlite_column_if_missing(conn, &columns, "dst_ip", "TEXT NOT NULL DEFAULT '0.0.0.0'")?;
    add_sqlite_column_if_missing(conn, &columns, "dst_port", "INTEGER NOT NULL DEFAULT 0")?;
    add_sqlite_column_if_missing(conn, &columns, "process_name", "TEXT")?;
    add_sqlite_column_if_missing(conn, &columns, "process_pid", "INTEGER")?;
    add_sqlite_column_if_missing(conn, &columns, "indicators", "TEXT DEFAULT '{}'")?;
    add_sqlite_column_if_missing(
        conn,
        &columns,
        "created_at",
        "TEXT DEFAULT (datetime('now'))",
    )?;

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

#[derive(Debug)]
struct SqliteColumn {
    name: String,
    not_null: bool,
    default_value: Option<String>,
    primary_key: bool,
}

fn sqlite_schema_needs_rebuild(columns: &[SqliteColumn]) -> bool {
    columns.iter().any(|column| {
        !SQLITE_NBI_EVENT_COLUMNS.contains(&column.name.as_str())
            && column.not_null
            && column.default_value.is_none()
            && !column.primary_key
    })
}

const SQLITE_NBI_EVENT_COLUMNS: &[&str] = &[
    "id",
    "event_id",
    "timestamp",
    "node_id",
    "run_id",
    "listener",
    "protocol",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "process_name",
    "process_pid",
    "indicators",
    "created_at",
];

fn rebuild_sqlite_nbi_events(
    conn: &rusqlite::Connection,
    columns: &[SqliteColumn],
) -> Result<(), String> {
    let has_column = |name: &str| columns.iter().any(|column| column.name == name);
    let select = [
        if has_column("event_id") {
            "event_id"
        } else {
            "''"
        },
        if has_column("timestamp") {
            "timestamp"
        } else {
            "'1970-01-01T00:00:00Z'"
        },
        if has_column("node_id") {
            "node_id"
        } else {
            "'standalone'"
        },
        if has_column("run_id") { "run_id" } else { "''" },
        if has_column("listener") {
            "listener"
        } else {
            "'legacy'"
        },
        if has_column("protocol") {
            "protocol"
        } else {
            "'RAW'"
        },
        if has_column("src_ip") {
            "src_ip"
        } else {
            "'0.0.0.0'"
        },
        if has_column("src_port") {
            "src_port"
        } else {
            "0"
        },
        if has_column("dst_ip") {
            "dst_ip"
        } else {
            "'0.0.0.0'"
        },
        if has_column("dst_port") {
            "dst_port"
        } else {
            "0"
        },
        if has_column("process_name") {
            "process_name"
        } else {
            "NULL"
        },
        if has_column("process_pid") {
            "process_pid"
        } else {
            "NULL"
        },
        if has_column("indicators") {
            "indicators"
        } else {
            "'{}'"
        },
        if has_column("created_at") {
            "created_at"
        } else {
            "datetime('now')"
        },
    ]
    .join(", ");

    conn.execute_batch(&format!(
        "BEGIN;
         ALTER TABLE nbi_events RENAME TO nbi_events_legacy;
         CREATE TABLE nbi_events (
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
             indicators TEXT DEFAULT '{{}}',
             created_at TEXT DEFAULT (datetime('now'))
         );
         INSERT INTO nbi_events (
             event_id, timestamp, node_id, run_id, listener, protocol, src_ip, src_port,
             dst_ip, dst_port, process_name, process_pid, indicators, created_at
         )
         SELECT {select} FROM nbi_events_legacy;
         DROP TABLE nbi_events_legacy;
         COMMIT;"
    ))
    .map_err(|e| format!("SQLite migration error: {}", e))?;

    Ok(())
}

fn add_sqlite_column_if_missing(
    conn: &rusqlite::Connection,
    columns: &[SqliteColumn],
    column: &str,
    definition: &str,
) -> Result<(), String> {
    if columns.iter().any(|existing| existing.name == column) {
        return Ok(());
    }

    conn.execute(
        &format!("ALTER TABLE nbi_events ADD COLUMN {column} {definition}"),
        [],
    )
    .map_err(|e| format!("SQLite migration error: {}", e))?;

    Ok(())
}

fn sqlite_pragma_row_error(error: rusqlite::Error) -> String {
    format!("SQLite pragma row error: {}", error)
}

pub(crate) async fn ensure_postgres_schema(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
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

#[cfg(test)]
mod tests {
    use super::ensure_sqlite_schema;

    #[test]
    fn ensure_sqlite_schema_migrates_existing_event_table() {
        let conn = rusqlite::Connection::open_in_memory().expect("open sqlite");
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

        ensure_sqlite_schema(&conn).expect("schema migration should succeed");

        let columns = conn
            .prepare("PRAGMA table_info(nbi_events)")
            .expect("prepare pragma")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query pragma")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("read columns");

        assert!(columns.iter().any(|column| column == "dst_ip"));
        assert!(columns.iter().any(|column| column == "run_id"));
        assert!(columns.iter().any(|column| column == "event_id"));
        assert!(columns.iter().any(|column| column == "listener"));
        assert!(columns.iter().any(|column| column == "protocol"));
        assert!(columns.iter().any(|column| column == "src_ip"));
        assert!(columns.iter().any(|column| column == "src_port"));
        assert!(columns.iter().any(|column| column == "dst_port"));
        assert!(columns.iter().any(|column| column == "indicators"));
        assert!(!columns.iter().any(|column| column == "event_json"));
    }

    #[test]
    fn sqlite_pragma_row_errors_are_reported() {
        let err =
            super::sqlite_pragma_row_error(rusqlite::Error::InvalidColumnName("name".to_string()));

        assert!(err.contains("SQLite pragma row error"));
        assert!(err.contains("name"));
    }
}
