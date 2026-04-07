use std::sync::Arc;

use payjoin::persist::SessionPersister;
use payjoin::receive::v2::SessionEvent as ReceiverSessionEvent;
use payjoin::send::v2::SessionEvent as SenderSessionEvent;
use payjoin::HpkePublicKey;
use rusqlite::params;

use super::*;

#[derive(Debug, Clone)]
pub(crate) struct SessionId(i64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SocksAuth {
    pub(crate) username: String,
    pub(crate) password: String,
}

impl SocksAuth {
    pub(crate) fn generate() -> Self {
        use payjoin::bitcoin::key::rand::Rng;

        let mut rng = payjoin::bitcoin::key::rand::thread_rng();
        Self {
            username: format!("{:032x}", rng.gen::<u128>()),
            password: format!("{:032x}", rng.gen::<u128>()),
        }
    }
}

impl core::ops::Deref for SessionId {
    type Target = i64;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}

#[derive(Clone)]
pub(crate) struct SenderPersister {
    db: Arc<Database>,
    session_id: SessionId,
}

impl SenderPersister {
    pub fn new(db: Arc<Database>, receiver_pubkey: HpkePublicKey) -> crate::db::Result<Self> {
        let conn = db.get_connection()?;

        // Create a new session in send_sessions and get its ID
        let session_id: i64 = conn.query_row(
            "INSERT INTO send_sessions (session_id, receiver_pubkey) VALUES (NULL, ?1) RETURNING session_id",
            params![receiver_pubkey.to_compressed_bytes()],
            |row| row.get(0),
        )?;

        Ok(Self { db, session_id: SessionId(session_id) })
    }

    pub fn from_id(db: Arc<Database>, id: SessionId) -> Self { Self { db, session_id: id } }

    pub fn get_or_create_socks_auth(&self) -> crate::db::Result<SocksAuth> {
        self.db.get_or_create_send_session_socks_auth(&self.session_id)
    }
}

impl SessionPersister for SenderPersister {
    type SessionEvent = SenderSessionEvent;
    type InternalStorageError = crate::db::error::Error;

    fn save_event(
        &self,
        event: SenderSessionEvent,
    ) -> std::result::Result<(), Self::InternalStorageError> {
        let conn = self.db.get_connection()?;
        let event_data = serde_json::to_string(&event).map_err(Error::Serialize)?;

        conn.execute(
            "INSERT INTO send_session_events (session_id, event_data, created_at) VALUES (?1, ?2, ?3)",
            params![*self.session_id, event_data, now()],
        )?;

        Ok(())
    }

    fn load(
        &self,
    ) -> std::result::Result<Box<dyn Iterator<Item = SenderSessionEvent>>, Self::InternalStorageError>
    {
        let conn = self.db.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT event_data FROM send_session_events WHERE session_id = ?1 ORDER BY id ASC",
        )?;

        let event_rows = stmt.query_map(params![*self.session_id], |row| {
            let event_data: String = row.get(0)?;
            Ok(event_data)
        })?;

        let events: Vec<SenderSessionEvent> = event_rows
            .map(|row| {
                let event_data = row.expect("Failed to read event data from database");
                serde_json::from_str::<SenderSessionEvent>(&event_data)
                    .expect("Database corruption: failed to deserialize session event")
            })
            .collect();

        Ok(Box::new(events.into_iter()))
    }

    fn close(&self) -> std::result::Result<(), Self::InternalStorageError> {
        let conn = self.db.get_connection()?;

        conn.execute(
            "UPDATE send_sessions SET completed_at = ?1 WHERE session_id = ?2",
            params![now(), *self.session_id],
        )?;

        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct ReceiverPersister {
    db: Arc<Database>,
    session_id: SessionId,
}

impl ReceiverPersister {
    pub fn new(db: Arc<Database>) -> crate::db::Result<Self> {
        let conn = db.get_connection()?;

        // Create a new session in receive_sessions and get its ID
        let session_id: i64 = conn.query_row(
            "INSERT INTO receive_sessions (session_id) VALUES (NULL) RETURNING session_id",
            [],
            |row| row.get(0),
        )?;

        Ok(Self { db, session_id: SessionId(session_id) })
    }

    pub fn from_id(db: Arc<Database>, id: SessionId) -> Self { Self { db, session_id: id } }

    pub fn session_id(&self) -> &SessionId { &self.session_id }

    pub fn get_or_create_socks_auth(&self) -> crate::db::Result<SocksAuth> {
        self.db.get_or_create_receive_session_socks_auth(&self.session_id)
    }
}

impl SessionPersister for ReceiverPersister {
    type SessionEvent = ReceiverSessionEvent;
    type InternalStorageError = crate::db::error::Error;

    fn save_event(
        &self,
        event: ReceiverSessionEvent,
    ) -> std::result::Result<(), Self::InternalStorageError> {
        let conn = self.db.get_connection()?;
        let event_data = serde_json::to_string(&event).map_err(Error::Serialize)?;

        conn.execute(
            "INSERT INTO receive_session_events (session_id, event_data, created_at) VALUES (?1, ?2, ?3)",
            params![*self.session_id, event_data, now()],
        )?;

        Ok(())
    }

    fn load(
        &self,
    ) -> std::result::Result<
        Box<dyn Iterator<Item = ReceiverSessionEvent>>,
        Self::InternalStorageError,
    > {
        let conn = self.db.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT event_data FROM receive_session_events WHERE session_id = ?1 ORDER BY id ASC",
        )?;

        let event_rows = stmt.query_map(params![*self.session_id], |row| {
            let event_data: String = row.get(0)?;
            Ok(event_data)
        })?;

        let events: Vec<ReceiverSessionEvent> = event_rows
            .map(|row| {
                let event_data = row.expect("Failed to read event data from database");
                serde_json::from_str::<ReceiverSessionEvent>(&event_data)
                    .expect("Database corruption: failed to deserialize session event")
            })
            .collect();

        Ok(Box::new(events.into_iter()))
    }

    fn close(&self) -> std::result::Result<(), Self::InternalStorageError> {
        let conn = self.db.get_connection()?;

        conn.execute(
            "UPDATE receive_sessions SET completed_at = ?1 WHERE session_id = ?2",
            params![now(), *self.session_id],
        )?;

        Ok(())
    }
}

const KNOWN_SESSION_TABLES: &[&str] = &["send_sessions", "receive_sessions"];

fn assert_known_session_table(table: &str) {
    assert!(KNOWN_SESSION_TABLES.contains(&table), "unexpected session table name: {table}");
}

impl Database {
    fn get_session_socks_auth(
        &self,
        table: &str,
        session_id: &SessionId,
    ) -> Result<Option<SocksAuth>> {
        assert_known_session_table(table);
        let conn = self.get_connection()?;
        Self::get_session_socks_auth_from_conn(&conn, table, session_id)
    }

    fn get_session_socks_auth_from_conn(
        conn: &r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>,
        table: &str,
        session_id: &SessionId,
    ) -> Result<Option<SocksAuth>> {
        let mut stmt = conn.prepare(&format!(
            "SELECT socks_username, socks_password FROM {table} WHERE session_id = ?1"
        ))?;
        let (username, password): (Option<String>, Option<String>) =
            stmt.query_row(params![session_id.0], |row| Ok((row.get(0)?, row.get(1)?)))?;

        match (username, password) {
            (Some(username), Some(password)) => Ok(Some(SocksAuth { username, password })),
            (None, None) => Ok(None),
            _ => Err(rusqlite::Error::InvalidQuery.into()),
        }
    }

    fn get_or_create_session_socks_auth(
        &self,
        table: &str,
        session_id: &SessionId,
    ) -> Result<SocksAuth> {
        assert_known_session_table(table);
        if let Some(existing_auth) = self.get_session_socks_auth(table, session_id)? {
            return Ok(existing_auth);
        }

        let conn = self.get_connection()?;
        let generated_auth = SocksAuth::generate();
        conn.execute(
            &format!(
                "UPDATE {table}
                 SET socks_username = COALESCE(socks_username, ?1),
                     socks_password = COALESCE(socks_password, ?2)
                 WHERE session_id = ?3"
            ),
            params![generated_auth.username, generated_auth.password, session_id.0],
        )?;

        Self::get_session_socks_auth_from_conn(&conn, table, session_id)?
            .ok_or_else(|| rusqlite::Error::QueryReturnedNoRows.into())
    }

    pub(crate) fn get_or_create_send_session_socks_auth(
        &self,
        session_id: &SessionId,
    ) -> Result<SocksAuth> {
        self.get_or_create_session_socks_auth("send_sessions", session_id)
    }

    pub(crate) fn get_or_create_receive_session_socks_auth(
        &self,
        session_id: &SessionId,
    ) -> Result<SocksAuth> {
        self.get_or_create_session_socks_auth("receive_sessions", session_id)
    }

    pub(crate) fn get_recv_session_ids(&self) -> Result<Vec<SessionId>> {
        let conn = self.get_connection()?;
        let mut stmt =
            conn.prepare("SELECT session_id FROM receive_sessions WHERE completed_at IS NULL")?;

        let session_rows = stmt.query_map([], |row| {
            let session_id: i64 = row.get(0)?;
            Ok(SessionId(session_id))
        })?;

        let mut session_ids = Vec::new();
        for session_row in session_rows {
            let session_id = session_row?;
            session_ids.push(session_id);
        }

        Ok(session_ids)
    }

    pub(crate) fn get_send_session_ids(&self) -> Result<Vec<SessionId>> {
        let conn = self.get_connection()?;
        let mut stmt =
            conn.prepare("SELECT session_id FROM send_sessions WHERE completed_at IS NULL")?;

        let session_rows = stmt.query_map([], |row| {
            let session_id: i64 = row.get(0)?;
            Ok(SessionId(session_id))
        })?;

        let mut session_ids = Vec::new();
        for session_row in session_rows {
            let session_id = session_row?;
            session_ids.push(session_id);
        }

        Ok(session_ids)
    }

    pub(crate) fn get_send_session_receiver_pk(
        &self,
        session_id: &SessionId,
    ) -> Result<HpkePublicKey> {
        let conn = self.get_connection()?;
        let mut stmt =
            conn.prepare("SELECT receiver_pubkey FROM send_sessions WHERE session_id = ?1")?;
        let receiver_pubkey: Vec<u8> = stmt.query_row(params![session_id.0], |row| row.get(0))?;
        Ok(HpkePublicKey::from_compressed_bytes(&receiver_pubkey).expect("Valid receiver pubkey"))
    }

    pub(crate) fn get_inactive_send_session_ids(&self) -> Result<Vec<(SessionId, u64)>> {
        let conn = self.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT session_id, completed_at FROM send_sessions WHERE completed_at IS NOT NULL",
        )?;
        let session_rows = stmt.query_map([], |row| {
            let session_id: i64 = row.get(0)?;
            let completed_at: u64 = row.get(1)?;
            Ok((SessionId(session_id), completed_at))
        })?;

        let mut session_ids = Vec::new();
        for session_row in session_rows {
            let (session_id, completed_at) = session_row?;
            session_ids.push((session_id, completed_at));
        }
        Ok(session_ids)
    }

    pub(crate) fn get_inactive_recv_session_ids(&self) -> Result<Vec<(SessionId, u64)>> {
        let conn = self.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT session_id, completed_at FROM receive_sessions WHERE completed_at IS NOT NULL",
        )?;
        let session_rows = stmt.query_map([], |row| {
            let session_id: i64 = row.get(0)?;
            let completed_at: u64 = row.get(1)?;
            Ok((SessionId(session_id), completed_at))
        })?;

        let mut session_ids = Vec::new();
        for session_row in session_rows {
            let (session_id, completed_at) = session_row?;
            session_ids.push((session_id, completed_at));
        }
        Ok(session_ids)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn receiver_session_socks_auth_is_reused_after_reload() {
        let temp_dir = tempdir().expect("temp dir should be created");
        let db = Arc::new(
            Database::create(temp_dir.path().join("payjoin.sqlite"))
                .expect("database should initialize"),
        );
        let persister =
            ReceiverPersister::new(db.clone()).expect("receiver session should persist");

        let first_auth =
            persister.get_or_create_socks_auth().expect("first auth should be generated");
        let second_auth = ReceiverPersister::from_id(db, persister.session_id().clone())
            .get_or_create_socks_auth()
            .expect("stored auth should be reloaded");

        assert_eq!(first_auth, second_auth);
    }

    #[test]
    fn receiver_sessions_get_distinct_socks_auth() {
        let temp_dir = tempdir().expect("temp dir should be created");
        let db = Arc::new(
            Database::create(temp_dir.path().join("payjoin.sqlite"))
                .expect("database should initialize"),
        );
        let first =
            ReceiverPersister::new(db.clone()).expect("first receiver session should persist");
        let second = ReceiverPersister::new(db).expect("second receiver session should persist");

        let first_auth =
            first.get_or_create_socks_auth().expect("first session auth should be generated");
        let second_auth =
            second.get_or_create_socks_auth().expect("second session auth should be generated");

        assert_ne!(first_auth, second_auth);
    }
}
