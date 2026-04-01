use std::path::Path;

use payjoin::bitcoin::consensus::encode::serialize;
use payjoin::bitcoin::OutPoint;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection};

pub(crate) mod error;
use error::*;

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

pub(crate) const DB_PATH: &str = "payjoin.sqlite";

#[derive(Debug)]
pub(crate) struct Database(Pool<SqliteConnectionManager>);

impl Database {
    pub(crate) fn create(path: impl AsRef<Path>) -> Result<Self> {
        // locking_mode is a per-connection PRAGMA, so it must be set via
        // with_init to apply to every connection the pool creates, not only
        // the first one used during init_schema.
        let manager = SqliteConnectionManager::file(path.as_ref())
            .with_init(|conn| conn.execute_batch("PRAGMA locking_mode = EXCLUSIVE;"));
        let pool = Pool::new(manager)?;

        // Initialize database schema
        let conn = pool.get()?;
        Self::init_schema(&conn)?;

        Ok(Self(pool))
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        // Enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON", [])?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS send_sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                pj_uri TEXT NOT NULL,
                receiver_pubkey BLOB NOT NULL,
                socks_username TEXT,
                socks_password TEXT,
                completed_at INTEGER
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS receive_sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                socks_username TEXT,
                socks_password TEXT,
                completed_at INTEGER
            )",
            [],
        )?;

        Self::ensure_column(conn, "send_sessions", "socks_username", "TEXT")?;
        Self::ensure_column(conn, "send_sessions", "socks_password", "TEXT")?;
        Self::ensure_column(conn, "receive_sessions", "socks_username", "TEXT")?;
        Self::ensure_column(conn, "receive_sessions", "socks_password", "TEXT")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS send_session_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                event_data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(session_id) REFERENCES send_sessions(session_id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS receive_session_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                event_data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(session_id) REFERENCES receive_sessions(session_id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS inputs_seen (
                outpoint BLOB PRIMARY KEY,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        Ok(())
    }

    fn ensure_column(conn: &Connection, table: &str, column: &str, definition: &str) -> Result<()> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let existing_columns = stmt.query_map([], |row| row.get::<_, String>(1))?;

        for existing_column in existing_columns {
            if existing_column? == column {
                return Ok(());
            }
        }

        conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"), [])?;
        Ok(())
    }

    pub(crate) fn get_connection(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
        Ok(self.0.get()?)
    }
    /// Inserts the input and returns true if the input was seen before, false otherwise.
    pub(crate) fn insert_input_seen_before(&self, input: OutPoint) -> Result<bool> {
        let conn = self.get_connection()?;
        let key = serialize(&input);

        let was_seen_before = conn.execute(
            "INSERT OR IGNORE INTO inputs_seen (outpoint, created_at) VALUES (?1, ?2)",
            params![key, now()],
        )? == 0;

        Ok(was_seen_before)
    }
}

#[cfg(feature = "v2")]
pub(crate) mod v2;
