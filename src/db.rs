//! The embedded Turso database: outbox, inbound log, suppressions, webhook queue.
//!
//! Turso only allows one writer at a time and reports a second one as
//! "database is locked" rather than waiting, so every statement goes through
//! a single connection behind a mutex. At this volume nothing ever queues.

use std::path::Path;

use anyhow::{Context, Result};
use tokio::sync::Mutex;
use turso::{Builder, Connection, Value};

use crate::util::now;

pub struct Db {
    conn: Mutex<Connection>,
}

pub const QUEUED: &str = "queued";
pub const SENDING: &str = "sending";
pub const DEFERRED: &str = "deferred";
pub const SENT: &str = "sent";
pub const FAILED: &str = "failed";
pub const BOUNCED: &str = "bounced";

/// The `inbound.action` of mail taken for an address with an empty forward
/// list. Its body is the only copy, so cleanup leaves it alone.
pub const KEPT: &str = "kept";

/// An outgoing message. `kind` is `send` for mail a site asked for and
/// `forward` for inbound mail on its way to somebody's real inbox.
#[derive(Debug, Clone)]
pub struct MessageRow {
    pub id: String,
    pub site: String,
    pub batch_id: String,
    pub kind: String,
    pub domain: String,
    pub mail_from: String,
    pub rcpt_to: String,
    pub from_header: String,
    pub subject: String,
    pub raw: Vec<u8>,
    pub status: String,
    pub attempts: i64,
    pub next_attempt_at: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub sent_at: Option<String>,
}

pub struct NewMessage {
    pub id: String,
    pub site: String,
    pub batch_id: String,
    pub kind: String,
    pub domain: String,
    pub mail_from: String,
    pub rcpt_to: String,
    pub from_header: String,
    pub subject: String,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EventRow {
    pub id: i64,
    pub site: String,
    pub url: String,
    pub event_type: String,
    pub body: String,
    pub attempts: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Suppression {
    pub email: String,
    pub reason: String,
    pub created_at: String,
}

const MESSAGE_COLS: &str = "id, site, batch_id, kind, domain, mail_from, rcpt_to, from_header, subject, \
                            raw, status, attempts, next_attempt_at, last_error, created_at, updated_at, sent_at";

fn message_from_row(row: &turso::Row) -> Result<MessageRow> {
    Ok(MessageRow {
        id: row.get(0)?,
        site: row.get(1)?,
        batch_id: row.get(2)?,
        kind: row.get(3)?,
        domain: row.get(4)?,
        mail_from: row.get(5)?,
        rcpt_to: row.get(6)?,
        from_header: row.get(7)?,
        subject: row.get(8)?,
        raw: match row.get_value(9)? {
            Value::Blob(b) => b,
            _ => Vec::new(),
        },
        status: row.get(10)?,
        attempts: row.get(11)?,
        next_attempt_at: row.get(12)?,
        last_error: row.get(13)?,
        created_at: row.get(14)?,
        updated_at: row.get(15)?,
        sent_at: row.get(16)?,
    })
}

impl Db {
    pub async fn open(path: &Path) -> Result<Db> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let db = Builder::new_local(path.to_str().context("db path is not utf-8")?)
            .build()
            .await
            .with_context(|| format!("opening {}", path.display()))?;
        let conn = db.connect()?;
        let db = Db { conn: Mutex::new(conn) };
        db.migrate().await.context("migrating schema")?;
        Ok(db)
    }

    async fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock().await;
        // PRAGMA returns a row, so it has to go through query().
        let mut rows = conn.query("PRAGMA journal_mode=WAL", ()).await?;
        let _ = rows.next().await;
        drop(rows);

        for stmt in [
            "CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                site TEXT NOT NULL,
                batch_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                domain TEXT NOT NULL,
                mail_from TEXT NOT NULL,
                rcpt_to TEXT NOT NULL,
                from_header TEXT NOT NULL,
                subject TEXT NOT NULL,
                raw BLOB,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                sent_at TEXT
            )",
            "CREATE INDEX IF NOT EXISTS idx_messages_due ON messages (status, next_attempt_at)",
            "CREATE INDEX IF NOT EXISTS idx_messages_batch ON messages (batch_id)",
            "CREATE TABLE IF NOT EXISTS suppressions (
                email TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            )",
            "CREATE TABLE IF NOT EXISTS inbound (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                remote_ip TEXT NOT NULL,
                helo TEXT NOT NULL,
                mail_from TEXT NOT NULL,
                rcpt_to TEXT NOT NULL,
                from_header TEXT NOT NULL,
                subject TEXT NOT NULL,
                auth TEXT NOT NULL,
                action TEXT NOT NULL,
                size INTEGER NOT NULL,
                raw BLOB,
                created_at TEXT NOT NULL
            )",
            "CREATE INDEX IF NOT EXISTS idx_inbound_created ON inbound (created_at)",
            "CREATE TABLE IF NOT EXISTS webhook_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                url TEXT NOT NULL,
                event_type TEXT NOT NULL,
                body TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT NOT NULL,
                last_error TEXT,
                created_at TEXT NOT NULL,
                delivered_at TEXT
            )",
            "CREATE INDEX IF NOT EXISTS idx_events_due ON webhook_events (status, next_attempt_at)",
        ] {
            conn.execute(stmt, ())
                .await
                .with_context(|| format!("running: {}", stmt.lines().next().unwrap_or("")))?;
        }
        Ok(())
    }

    /// Anything left in `sending` when the process died goes back to the queue.
    pub async fn recover(&self) -> Result<u64> {
        let conn = self.conn.lock().await;
        let n = conn
            .execute(
                "UPDATE messages SET status = ?1, updated_at = ?2 WHERE status = ?3",
                (QUEUED, now(), SENDING),
            )
            .await?;
        Ok(n)
    }

    // ---- messages ---------------------------------------------------------

    /// Inserts a batch atomically: either every recipient is queued or none.
    pub async fn insert_messages(&self, msgs: &[NewMessage]) -> Result<()> {
        let conn = self.conn.lock().await;
        let ts = now();
        conn.execute("BEGIN", ()).await?;
        for m in msgs {
            let r = conn
                .execute(
                    &format!(
                        "INSERT INTO messages ({MESSAGE_COLS}) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, NULL, NULL, ?12, ?12, NULL)"
                    ),
                    (
                        Value::from(m.id.as_str()),
                        Value::from(m.site.as_str()),
                        Value::from(m.batch_id.as_str()),
                        Value::from(m.kind.as_str()),
                        Value::from(m.domain.as_str()),
                        Value::from(m.mail_from.as_str()),
                        Value::from(m.rcpt_to.as_str()),
                        Value::from(m.from_header.as_str()),
                        Value::from(m.subject.as_str()),
                        Value::Blob(m.raw.clone()),
                        Value::from(QUEUED),
                        Value::from(ts.as_str()),
                    ),
                )
                .await;
            if let Err(e) = r {
                let _ = conn.execute("ROLLBACK", ()).await;
                return Err(e.into());
            }
        }
        if let Err(e) = conn.execute("COMMIT", ()).await {
            // Every statement shares this connection; an open transaction
            // left behind would swallow all of them.
            let _ = conn.execute("ROLLBACK", ()).await;
            return Err(e.into());
        }
        Ok(())
    }

    /// The next message that is due, already marked `sending` so a second
    /// worker could not pick it up too.
    pub async fn claim_due_message(&self) -> Result<Option<MessageRow>> {
        let conn = self.conn.lock().await;
        let ts = now();
        let mut rows = conn
            .query(
                &format!(
                    "SELECT {MESSAGE_COLS} FROM messages \
                     WHERE (status = ?1 OR (status = ?2 AND next_attempt_at <= ?3)) \
                     ORDER BY created_at LIMIT 1"
                ),
                (QUEUED, DEFERRED, ts.as_str()),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let msg = message_from_row(&row)?;
        drop(rows);
        conn.execute(
            "UPDATE messages SET status = ?1, updated_at = ?2 WHERE id = ?3",
            (SENDING, ts.as_str(), msg.id.as_str()),
        )
        .await?;
        Ok(Some(msg))
    }

    pub async fn mark_sent(&self, id: &str, detail: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        let ts = now();
        conn.execute(
            "UPDATE messages SET status = ?1, attempts = attempts + 1, last_error = ?2, \
             next_attempt_at = NULL, sent_at = ?3, updated_at = ?3 WHERE id = ?4",
            (SENT, detail, ts.as_str(), id),
        )
        .await?;
        Ok(())
    }

    pub async fn mark_deferred(&self, id: &str, next_at: &str, error: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE messages SET status = ?1, attempts = attempts + 1, next_attempt_at = ?2, \
             last_error = ?3, updated_at = ?4 WHERE id = ?5",
            (DEFERRED, next_at, error, now(), id),
        )
        .await?;
        Ok(())
    }

    pub async fn mark_failed(&self, id: &str, error: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE messages SET status = ?1, attempts = attempts + 1, next_attempt_at = NULL, \
             last_error = ?2, updated_at = ?3 WHERE id = ?4",
            (FAILED, error, now(), id),
        )
        .await?;
        Ok(())
    }

    /// A bounce came back for a message that was already `sent`.
    pub async fn mark_bounced(&self, id: &str, detail: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE messages SET status = ?1, last_error = ?2, updated_at = ?3 WHERE id = ?4",
            (BOUNCED, detail, now(), id),
        )
        .await?;
        Ok(())
    }

    pub async fn get_message(&self, id: &str) -> Result<Option<MessageRow>> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(&format!("SELECT {MESSAGE_COLS} FROM messages WHERE id = ?1"), (id,))
            .await?;
        match rows.next().await? {
            Some(row) => Ok(Some(message_from_row(&row)?)),
            None => Ok(None),
        }
    }

    pub async fn batch_messages(&self, batch_id: &str) -> Result<Vec<MessageRow>> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                &format!("SELECT {MESSAGE_COLS} FROM messages WHERE batch_id = ?1 ORDER BY created_at, id"),
                (batch_id,),
            )
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(message_from_row(&row)?);
        }
        Ok(out)
    }

    /// Status counts for the queue, for `/healthz` and the log.
    pub async fn status_counts(&self) -> Result<Vec<(String, i64)>> {
        let conn = self.conn.lock().await;
        let mut rows = conn.query("SELECT status, COUNT(*) FROM messages GROUP BY status", ()).await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push((row.get(0)?, row.get(1)?));
        }
        Ok(out)
    }

    // ---- suppressions -----------------------------------------------------

    pub async fn is_suppressed(&self, email: &str) -> Result<bool> {
        let conn = self.conn.lock().await;
        let mut rows = conn.query("SELECT 1 FROM suppressions WHERE email = ?1", (email,)).await?;
        Ok(rows.next().await?.is_some())
    }

    pub async fn add_suppression(&self, email: &str, reason: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO suppressions (email, reason, created_at) VALUES (?1, ?2, ?3) \
             ON CONFLICT(email) DO UPDATE SET reason = excluded.reason",
            (email, reason, now()),
        )
        .await?;
        Ok(())
    }

    pub async fn remove_suppression(&self, email: &str) -> Result<bool> {
        let conn = self.conn.lock().await;
        let n = conn.execute("DELETE FROM suppressions WHERE email = ?1", (email,)).await?;
        Ok(n > 0)
    }

    pub async fn list_suppressions(&self) -> Result<Vec<Suppression>> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query("SELECT email, reason, created_at FROM suppressions ORDER BY created_at DESC", ())
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(Suppression {
                email: row.get(0)?,
                reason: row.get(1)?,
                created_at: row.get(2)?,
            });
        }
        Ok(out)
    }

    // ---- inbound ----------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_inbound(
        &self,
        id: &str,
        domain: &str,
        remote_ip: &str,
        helo: &str,
        mail_from: &str,
        rcpt_to: &str,
        from_header: &str,
        subject: &str,
        auth: &str,
        action: &str,
        raw: &[u8],
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO inbound (id, domain, remote_ip, helo, mail_from, rcpt_to, from_header, subject, \
             auth, action, size, raw, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            (
                Value::from(id),
                Value::from(domain),
                Value::from(remote_ip),
                Value::from(helo),
                Value::from(mail_from),
                Value::from(rcpt_to),
                Value::from(from_header),
                Value::from(subject),
                Value::from(auth),
                Value::from(action),
                Value::Integer(raw.len() as i64),
                Value::Blob(raw.to_vec()),
                Value::from(now().as_str()),
            ),
        )
        .await?;
        Ok(())
    }

    /// Lets a test break the store on purpose.
    #[cfg(test)]
    pub async fn execute_for_test(&self, sql: &str) -> Result<()> {
        self.conn.lock().await.execute(sql, ()).await?;
        Ok(())
    }

    #[cfg(test)]
    pub async fn inbound_by_subject(&self, subject: &str) -> Result<Option<(String, Option<Vec<u8>>)>> {
        let conn = self.conn.lock().await;
        let mut rows = conn.query("SELECT action, raw FROM inbound WHERE subject = ?1", (subject,)).await?;
        match rows.next().await? {
            Some(row) => {
                let raw = match row.get_value(1)? {
                    Value::Blob(b) => Some(b),
                    _ => None,
                };
                Ok(Some((row.get(0)?, raw)))
            }
            None => Ok(None),
        }
    }

    // ---- webhook events ---------------------------------------------------

    pub async fn enqueue_event(&self, site: &str, url: &str, event_type: &str, body: &str) -> Result<i64> {
        let conn = self.conn.lock().await;
        let ts = now();
        conn.execute(
            "INSERT INTO webhook_events (site, url, event_type, body, status, attempts, next_attempt_at, created_at) \
             VALUES (?1, ?2, ?3, ?4, 'pending', 0, ?5, ?5)",
            (site, url, event_type, body, ts.as_str()),
        )
        .await?;
        Ok(conn.last_insert_rowid())
    }

    pub async fn due_events(&self, limit: usize) -> Result<Vec<EventRow>> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                &format!(
                    "SELECT id, site, url, event_type, body, attempts FROM webhook_events \
                     WHERE status = 'pending' AND next_attempt_at <= ?1 ORDER BY id LIMIT {limit}"
                ),
                (now(),),
            )
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(EventRow {
                id: row.get(0)?,
                site: row.get(1)?,
                url: row.get(2)?,
                event_type: row.get(3)?,
                body: row.get(4)?,
                attempts: row.get(5)?,
            });
        }
        Ok(out)
    }

    pub async fn event_delivered(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE webhook_events SET status = 'delivered', attempts = attempts + 1, delivered_at = ?1, \
             last_error = NULL WHERE id = ?2",
            (now(), id),
        )
        .await?;
        Ok(())
    }

    pub async fn event_retry(&self, id: i64, next_at: &str, error: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE webhook_events SET attempts = attempts + 1, next_attempt_at = ?1, last_error = ?2 WHERE id = ?3",
            (next_at, error, id),
        )
        .await?;
        Ok(())
    }

    pub async fn event_failed(&self, id: i64, error: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE webhook_events SET status = 'failed', attempts = attempts + 1, last_error = ?1 WHERE id = ?2",
            (error, id),
        )
        .await?;
        Ok(())
    }

    // ---- housekeeping -----------------------------------------------------

    /// Drops message bodies that are no longer needed and old log rows. The
    /// metadata rows stay, so a status lookup still answers months later.
    pub async fn cleanup(&self, finished_before: &str, inbound_before: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE messages SET raw = NULL WHERE raw IS NOT NULL AND status IN (?1, ?2, ?3) AND updated_at < ?4",
            (SENT, FAILED, BOUNCED, finished_before),
        )
        .await?;
        // `action` is space-separated, one entry per recipient.
        conn.execute(
            "UPDATE inbound SET raw = NULL WHERE raw IS NOT NULL AND created_at < ?1 \
             AND ' ' || action || ' ' NOT LIKE '% ' || ?2 || ' %'",
            (inbound_before, KEPT),
        )
        .await?;
        conn.execute(
            "DELETE FROM webhook_events WHERE status <> 'pending' AND created_at < ?1",
            (inbound_before,),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tempdir;

    async fn temp_db() -> (Db, tempdir::Dir) {
        let dir = tempdir::Dir::new("db");
        let db = Db::open(&dir.path.join("t.db")).await.unwrap();
        (db, dir)
    }

    fn msg(id: &str, to: &str) -> NewMessage {
        NewMessage {
            id: id.into(),
            site: "s".into(),
            batch_id: "b1".into(),
            kind: "send".into(),
            domain: "example.com".into(),
            mail_from: format!("bounce+{id}@example.com"),
            rcpt_to: to.into(),
            from_header: "a@example.com".into(),
            subject: "hi".into(),
            raw: b"Subject: hi\r\n\r\nbody".to_vec(),
        }
    }

    #[tokio::test]
    async fn queue_claims_in_order_and_defers() {
        let (db, _d) = temp_db().await;
        db.insert_messages(&[msg("00a", "x@y.com"), msg("00b", "z@y.com")]).await.unwrap();
        let first = db.claim_due_message().await.unwrap().unwrap();
        assert_eq!(first.id, "00a");
        assert_eq!(first.status, QUEUED);
        // Claimed rows are `sending` and are not handed out twice.
        let second = db.claim_due_message().await.unwrap().unwrap();
        assert_eq!(second.id, "00b");
        assert!(db.claim_due_message().await.unwrap().is_none());

        db.mark_deferred(&first.id, "2999-01-01T00:00:00Z", "451 try later").await.unwrap();
        assert!(db.claim_due_message().await.unwrap().is_none());
        db.mark_deferred(&second.id, "2000-01-01T00:00:00Z", "451").await.unwrap();
        let again = db.claim_due_message().await.unwrap().unwrap();
        assert_eq!(again.id, "00b");
        assert_eq!(again.attempts, 1);

        db.mark_sent(&again.id, "250 ok").await.unwrap();
        let row = db.get_message("00b").await.unwrap().unwrap();
        assert_eq!(row.status, SENT);
        assert!(row.sent_at.is_some());
        assert_eq!(db.batch_messages("b1").await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn recover_requeues_sending_rows() {
        let (db, _d) = temp_db().await;
        db.insert_messages(&[msg("00a", "x@y.com")]).await.unwrap();
        db.claim_due_message().await.unwrap().unwrap();
        assert_eq!(db.recover().await.unwrap(), 1);
        assert!(db.claim_due_message().await.unwrap().is_some());
    }

    #[tokio::test]
    async fn suppressions_upsert_and_delete() {
        let (db, _d) = temp_db().await;
        assert!(!db.is_suppressed("a@b.com").await.unwrap());
        db.add_suppression("a@b.com", "bounce").await.unwrap();
        db.add_suppression("a@b.com", "unsubscribe").await.unwrap();
        assert!(db.is_suppressed("a@b.com").await.unwrap());
        let list = db.list_suppressions().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].reason, "unsubscribe");
        assert!(db.remove_suppression("a@b.com").await.unwrap());
        assert!(!db.remove_suppression("a@b.com").await.unwrap());
    }

    #[tokio::test]
    async fn events_retry_then_deliver() {
        let (db, _d) = temp_db().await;
        let id = db.enqueue_event("s", "https://x/y", "message.sent", "{}").await.unwrap();
        assert_eq!(db.due_events(10).await.unwrap().len(), 1);
        db.event_retry(id, "2999-01-01T00:00:00Z", "500").await.unwrap();
        assert!(db.due_events(10).await.unwrap().is_empty());
        db.event_retry(id, "2000-01-01T00:00:00Z", "500").await.unwrap();
        let ev = &db.due_events(10).await.unwrap()[0];
        assert_eq!(ev.attempts, 2);
        db.event_delivered(id).await.unwrap();
        assert!(db.due_events(10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn cleanup_drops_bodies_but_keeps_rows() {
        let (db, _d) = temp_db().await;
        db.insert_messages(&[msg("00a", "x@y.com")]).await.unwrap();
        db.claim_due_message().await.unwrap();
        db.mark_sent("00a", "ok").await.unwrap();
        db.cleanup("2999-01-01T00:00:00Z", "2999-01-01T00:00:00Z").await.unwrap();
        let row = db.get_message("00a").await.unwrap().unwrap();
        assert_eq!(row.status, SENT);
        assert!(row.raw.is_empty());
    }
}

/// A throwaway directory that is removed when dropped.
#[cfg(test)]
pub mod tempdir {
    pub struct Dir {
        pub path: std::path::PathBuf,
    }
    impl Dir {
        pub fn new(tag: &str) -> Dir {
            let path = std::env::temp_dir().join(format!("mail_sloth_test_{tag}_{}_{}", std::process::id(), crate::util::new_id()));
            std::fs::create_dir_all(&path).unwrap();
            Dir { path }
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
