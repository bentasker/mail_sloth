//! Signed event delivery to each site's webhook, with retries.
//!
//! Events go through the database first, so a site being down for an hour
//! costs nothing but a delay, and a restart mid-delivery loses nothing.

use std::sync::Arc;
use std::time::Duration;

use crate::app::App;
use crate::db::EventRow;
use crate::util::{after_seconds, hmac_sha256_hex, new_id, now, unix_now};

/// Seconds to wait before each retry; after the last one the event fails.
const RETRY_SECONDS: [i64; 6] = [30, 120, 600, 3600, 6 * 3600, 24 * 3600];

pub const MESSAGE_SENT: &str = "message.sent";
pub const MESSAGE_FAILED: &str = "message.failed";
pub const MESSAGE_BOUNCED: &str = "message.bounced";
pub const MAIL_RECEIVED: &str = "mail.received";

/// Queues an event for a site. A site with no webhook_url gets nothing.
pub async fn enqueue(app: &App, site_name: &str, event_type: &str, data: serde_json::Value) {
    let Some(site) = app.cfg.site(site_name) else {
        return;
    };
    let Some(url) = site.webhook_url.as_deref() else {
        return;
    };
    let body = serde_json::json!({
        "id": new_id(),
        "type": event_type,
        "created_at": now(),
        "data": data,
    })
    .to_string();
    match app.db.enqueue_event(site_name, url, event_type, &body).await {
        Ok(_) => app.wake_webhooks.notify_one(),
        Err(e) => tracing::error!(site = site_name, event_type, error = %e, "could not queue webhook event"),
    }
}

/// The `X-Sloth-Signature` value for a body: `t=<unix>,v1=<hex hmac>` over
/// `"{t}.{body}"`, so a replayed body cannot be re-signed with a new time.
pub fn signature(secret: &str, t: i64, body: &str) -> String {
    let sig = hmac_sha256_hex(secret.as_bytes(), format!("{t}.{body}").as_bytes());
    format!("t={t},v1={sig}")
}

pub async fn run(app: Arc<App>) {
    loop {
        match deliver_due(&app).await {
            Ok(0) => {
                let _ = tokio::time::timeout(Duration::from_secs(15), app.wake_webhooks.notified()).await;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, "reading webhook queue");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

/// Posts every due event once. Returns how many were attempted.
pub async fn deliver_due(app: &App) -> anyhow::Result<usize> {
    let due = app.db.due_events(20).await?;
    let n = due.len();
    for ev in due {
        match post(app, &ev).await {
            Ok(()) => {
                tracing::info!(id = ev.id, site = %ev.site, event_type = %ev.event_type, "webhook delivered");
                let _ = app.db.event_delivered(ev.id).await;
            }
            Err(e) => {
                let attempt = ev.attempts as usize;
                if attempt < RETRY_SECONDS.len() {
                    let next = after_seconds(RETRY_SECONDS[attempt]);
                    tracing::warn!(id = ev.id, site = %ev.site, error = %e, next_attempt = %next, "webhook failed, will retry");
                    let _ = app.db.event_retry(ev.id, &next, &e).await;
                } else {
                    tracing::error!(id = ev.id, site = %ev.site, error = %e, "webhook gave up");
                    let _ = app.db.event_failed(ev.id, &e).await;
                }
            }
        }
    }
    Ok(n)
}

async fn post(app: &App, ev: &EventRow) -> Result<(), String> {
    let secret = app
        .cfg
        .site(&ev.site)
        .and_then(|s| s.webhook_secret.clone())
        .ok_or_else(|| "site no longer has a webhook_secret".to_string())?;
    let t = unix_now();
    let resp = app
        .http
        .post(&ev.url)
        .header("content-type", "application/json")
        .header("x-sloth-signature", signature(&secret, t, &ev.body))
        .header("x-sloth-event", &ev.event_type)
        .body(ev.body.clone())
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else {
        let text = resp.text().await.unwrap_or_default();
        Err(format!("HTTP {status}: {}", text.chars().take(200).collect::<String>()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_binds_time_and_body() {
        let a = signature("k", 1, "{}");
        let b = signature("k", 2, "{}");
        let c = signature("k", 1, "{ }");
        assert!(a.starts_with("t=1,v1="));
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, signature("k", 1, "{}"));
    }
}
