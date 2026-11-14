//! Shared state handed to every task and request handler.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mail_auth::MessageAuthenticator;
use tokio::sync::Notify;

use crate::config::Config;
use crate::db::Db;
use crate::dkim::DkimKeys;

pub struct App {
    pub cfg: Arc<Config>,
    pub db: Arc<Db>,
    pub dkim: Arc<DkimKeys>,
    pub http: reqwest::Client,
    pub resolver: Arc<MessageAuthenticator>,
    /// Poked when something is queued so the sender does not wait for its tick.
    pub wake_sender: Notify,
    pub wake_webhooks: Notify,
    /// Failed submission logins per client IP, for the lockout.
    auth_failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    /// Messages submitted per authenticated address in the current hour.
    submissions: Mutex<HashMap<String, (u32, Instant)>>,
}

/// Failed logins in this window lock the IP out.
const AUTH_FAILURES: u32 = 5;
const AUTH_WINDOW: Duration = Duration::from_secs(600);
const AUTH_LOCKOUT: Duration = Duration::from_secs(3600);
/// Recipients one address may submit in an hour. Gmail replies are a
/// handful a day; this only stops a leaked password from mailing a list.
pub const SUBMISSIONS_PER_HOUR: u32 = 200;

impl App {
    pub fn new(cfg: Config, db: Db, dkim: DkimKeys, resolver: MessageAuthenticator) -> Arc<App> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("mail_sloth/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .expect("reqwest client");
        Arc::new(App {
            cfg: Arc::new(cfg),
            db: Arc::new(db),
            dkim: Arc::new(dkim),
            http,
            resolver: Arc::new(resolver),
            wake_sender: Notify::new(),
            wake_webhooks: Notify::new(),
            auth_failures: Mutex::new(HashMap::new()),
            submissions: Mutex::new(HashMap::new()),
        })
    }

    pub fn auth_locked(&self, ip: IpAddr) -> bool {
        let map = self.auth_failures.lock().unwrap();
        matches!(map.get(&ip), Some((n, since)) if *n >= AUTH_FAILURES && since.elapsed() < AUTH_LOCKOUT)
    }

    /// Returns true when this failure locks the IP out.
    pub fn record_auth_failure(&self, ip: IpAddr) -> bool {
        let mut map = self.auth_failures.lock().unwrap();
        if map.len() > 10_000 {
            map.retain(|_, (_, since)| since.elapsed() < AUTH_LOCKOUT);
        }
        let now = Instant::now();
        let entry = map.entry(ip).or_insert((0, now));
        if entry.0 >= AUTH_FAILURES && entry.1.elapsed() >= AUTH_LOCKOUT || entry.0 < AUTH_FAILURES && entry.1.elapsed() >= AUTH_WINDOW {
            *entry = (0, now);
        }
        entry.0 += 1;
        if entry.0 == AUTH_FAILURES {
            // The lockout runs from the failure that triggered it.
            entry.1 = now;
        }
        entry.0 >= AUTH_FAILURES
    }

    pub fn clear_auth_failures(&self, ip: IpAddr) {
        self.auth_failures.lock().unwrap().remove(&ip);
    }

    /// Reserves `n` more submitted messages for the address this hour, or
    /// says no if that would go over the cap.
    pub fn allow_submissions(&self, address: &str, n: u32) -> bool {
        let mut map = self.submissions.lock().unwrap();
        let now = Instant::now();
        let entry = map.entry(address.to_string()).or_insert((0, now));
        if entry.1.elapsed() >= Duration::from_secs(3600) {
            *entry = (0, now);
        }
        if entry.0 + n > SUBMISSIONS_PER_HOUR {
            return false;
        }
        entry.0 += n;
        true
    }
}
