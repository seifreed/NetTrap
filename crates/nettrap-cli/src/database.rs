//! Database storage for NBI events.

pub use nettrap_storage::database::{
    DatabaseBackend, DbStats, PostgresStorage, SqliteStorage, StoredEvent, init_database,
};
