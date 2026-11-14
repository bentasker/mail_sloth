//! The outbox worker: MX lookup, SMTP delivery, retries.
//!
//! One message at a time, at a fixed rate. That is slow on purpose. A new IP
//! that opens twenty connections to Gmail at once looks like a spam run; one
//! that trickles looks like a person's mail server.

use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::proto::op::ResponseCode;
use mail_auth::common::cache::NoCache;
use mail_auth::{DnsError, IpLookupStrategy, RecordSet, MX};
use mail_send::smtp::message::Message;
use mail_send::smtp::tls::build_tls_connector;
use mail_send::{Error as SmtpError, SmtpClient, SmtpClientBuilder};
use smtp_proto::EXT_START_TLS;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::app::App;
use crate::db::MessageRow;
use crate::util::after_seconds;
use crate::webhook;

/// Seconds until the next try after each temporary failure. After the last
/// one the message fails: two days is long enough for any outage that is
/// going to end.
const RETRY_SECONDS: [i64; 8] = [60, 300, 900, 3600, 4 * 3600, 12 * 3600, 24 * 3600, 24 * 3600];

/// Google took over ten seconds to answer the first connections from a fresh IP.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(75);
const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub enum Outcome {
    Sent(String),
    Deferred(String),
    Failed(String),
}

enum HostError {
    Temporary(String),
    Permanent(String),
}

pub async fn run(app: Arc<App>) {
    let gap = Duration::from_millis(1000 / u64::from(app.cfg.send_rate_per_second));
    loop {
        match app.db.claim_due_message().await {
            Ok(Some(m)) => {
                let outcome = deliver(&app, &m).await;
                record(&app, &m, outcome).await;
                tokio::time::sleep(gap).await;
            }
            Ok(None) => {
                let _ = tokio::time::timeout(Duration::from_secs(10), app.wake_sender.notified()).await;
            }
            Err(e) => {
                tracing::error!(error = %e, "reading outbox");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

pub async fn record(app: &App, m: &MessageRow, outcome: Outcome) {
    let is_send = m.kind == "send";
    match outcome {
        Outcome::Sent(reply) => {
            tracing::info!(id = %m.id, kind = %m.kind, to = %m.rcpt_to, reply = %reply, "delivered");
            let _ = app.db.mark_sent(&m.id, &reply).await;
            if is_send {
                webhook::enqueue(app, &m.site, webhook::MESSAGE_SENT, event_data(m, &reply)).await;
            }
        }
        Outcome::Deferred(err) => {
            let attempt = m.attempts as usize;
            if attempt < RETRY_SECONDS.len() {
                let next = after_seconds(RETRY_SECONDS[attempt]);
                tracing::warn!(id = %m.id, to = %m.rcpt_to, error = %err, next_attempt = %next, "deferred");
                let _ = app.db.mark_deferred(&m.id, &next, &err).await;
            } else {
                let err = format!("gave up after {} attempts: {err}", attempt + 1);
                tracing::error!(id = %m.id, to = %m.rcpt_to, error = %err, "failed");
                let _ = app.db.mark_failed(&m.id, &err).await;
                if is_send {
                    webhook::enqueue(app, &m.site, webhook::MESSAGE_FAILED, event_data(m, &err)).await;
                }
            }
        }
        Outcome::Failed(err) => {
            tracing::error!(id = %m.id, to = %m.rcpt_to, error = %err, "failed");
            let _ = app.db.mark_failed(&m.id, &err).await;
            if is_send {
                if looks_like_bad_address(&err) {
                    let _ = app.db.add_suppression(&m.rcpt_to, &format!("hard bounce: {err}")).await;
                }
                webhook::enqueue(app, &m.site, webhook::MESSAGE_FAILED, event_data(m, &err)).await;
            }
        }
    }
}

pub fn event_data(m: &MessageRow, detail: &str) -> serde_json::Value {
    serde_json::json!({
        "message_id": m.id,
        "batch_id": m.batch_id,
        "to": m.rcpt_to,
        "from": m.from_header,
        "subject": m.subject,
        "detail": detail,
    })
}

/// A permanent rejection that names the mailbox rather than the message.
/// Those addresses are never worth trying again; a content rejection might be.
pub fn looks_like_bad_address(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    e.contains("5.1.1")
        || e.contains("5.1.2")
        || e.contains("5.1.3")
        || e.contains("5.1.6")
        || e.contains("5.1.10")
        || e.contains("5.4.1")
        || e.contains("user unknown")
        || e.contains("no such user")
        || e.contains("does not exist")
        || e.contains("unknown user")
        || e.contains("mailbox unavailable")
        || e.contains("recipient address rejected")
        || e.contains("no such domain")
        || e.contains("does not accept mail")
}

pub async fn deliver(app: &App, m: &MessageRow) -> Outcome {
    if m.raw.is_empty() {
        return Outcome::Failed("message body is gone".into());
    }
    let raw = if m.kind == "send" {
        match app.dkim.sign(&m.domain, &m.raw) {
            Ok(r) => r,
            Err(e) => return Outcome::Failed(e.to_string()),
        }
    } else {
        m.raw.clone()
    };
    let Some((_, rcpt_domain)) = m.rcpt_to.rsplit_once('@') else {
        return Outcome::Failed("recipient has no domain".into());
    };
    let hosts = match resolve_mx(app, rcpt_domain).await {
        Ok(h) => h,
        Err(HostError::Temporary(e)) => return Outcome::Deferred(e),
        Err(HostError::Permanent(e)) => return Outcome::Failed(e),
    };
    let mut last = "no MX host reachable".to_string();
    for (host, port) in hosts {
        match tokio::time::timeout(SESSION_TIMEOUT, try_host(app, &host, port, m, &raw)).await {
            Ok(Ok(reply)) => return Outcome::Sent(format!("{host}: {reply}")),
            Ok(Err(HostError::Permanent(e))) => return Outcome::Failed(format!("{host}: {e}")),
            Ok(Err(HostError::Temporary(e))) => last = format!("{host}: {e}"),
            Err(_) => last = format!("{host}: session timed out"),
        }
    }
    Outcome::Deferred(last)
}

/// MX hosts in preference order, or the domain itself when it has no MX.
async fn resolve_mx(app: &App, domain: &str) -> Result<Vec<(String, u16)>, HostError> {
    if let Some(over) = &app.cfg.mx_override {
        let (host, port) = over.rsplit_once(':').unwrap_or((over.as_str(), "25"));
        return Ok(vec![(host.to_string(), port.parse().unwrap_or(25))]);
    }
    match app.resolver.mx_lookup(domain, None::<&NoCache<Box<str>, RecordSet<MX>>>).await {
        Ok(set) => {
            let mut hosts = Vec::new();
            for mx in set.rrset.iter() {
                for ex in mx.exchanges.iter() {
                    let ex = ex.trim_end_matches('.');
                    if ex.is_empty() {
                        // RFC 7505 null MX: the domain says it takes no mail.
                        return Err(HostError::Permanent(format!("{domain} does not accept mail (null MX)")));
                    }
                    hosts.push((ex.to_string(), 25));
                }
            }
            if hosts.is_empty() {
                hosts.push((domain.to_string(), 25));
            }
            Ok(hosts)
        }
        Err(mail_auth::Error::Dns(DnsError::RecordNotFound(ResponseCode::NXDomain))) => {
            Err(HostError::Permanent(format!("no such domain: {domain}")))
        }
        Err(mail_auth::Error::Dns(DnsError::RecordNotFound(_))) => {
            // No MX records but the name exists: RFC 5321 says try the A record.
            match app
                .resolver
                .ip_lookup(
                    domain,
                    IpLookupStrategy::Ipv4thenIpv6,
                    1,
                    None::<&NoCache<_, _>>,
                    None::<&NoCache<_, _>>,
                )
                .await
            {
                Ok(ips) if !ips.is_empty() => Ok(vec![(domain.to_string(), 25)]),
                _ => Err(HostError::Permanent(format!("{domain} has no MX or A record"))),
            }
        }
        Err(e) => Err(HostError::Temporary(format!("MX lookup for {domain}: {e}"))),
    }
}

async fn try_host(app: &App, host: &str, port: u16, m: &MessageRow, raw: &[u8]) -> Result<String, HostError> {
    let hostname = app.cfg.hostname.clone();
    let builder = SmtpClientBuilder::new(host.to_string(), port)
        .map_err(HostError::Temporary)?
        .implicit_tls(false)
        .allow_invalid_certs()
        .helo_host(hostname.clone())
        .say_ehlo(false)
        .timeout(Duration::from_secs(60));
    let mut plain = tokio::time::timeout(CONNECT_TIMEOUT, builder.connect_plain())
        .await
        .map_err(|_| HostError::Temporary("connect timed out".into()))?
        .map_err(classify)?;
    let ehlo = plain.ehlo(&hostname).await.map_err(classify)?;
    if ehlo.has_capability(EXT_START_TLS) {
        // Opportunistic TLS: an MX with a self-signed or mismatched
        // certificate still gets encrypted delivery, which is what every
        // other MTA does absent DANE or MTA-STS.
        let connector = build_tls_connector(true).map_err(HostError::Temporary)?;
        let mut tls = plain.start_tls(&connector, host).await.map_err(classify)?;
        tls.ehlo(&hostname).await.map_err(classify)?;
        let r = transact(&mut tls, m, raw).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), tls.quit()).await;
        r
    } else {
        let r = transact(&mut plain, m, raw).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), plain.quit()).await;
        r
    }
}

async fn transact<S: AsyncRead + AsyncWrite + Unpin>(client: &mut SmtpClient<S>, m: &MessageRow, raw: &[u8]) -> Result<String, HostError> {
    let msg = Message::new(m.mail_from.as_str(), [m.rcpt_to.as_str()], raw);
    client
        .mail_from(&msg.mail_from.email, &msg.mail_from.parameters)
        .await
        .map_err(classify)?;
    for r in &msg.rcpt_to {
        client.rcpt_to(&r.email, &r.parameters).await.map_err(classify)?;
    }
    let reply = client.cmd(b"DATA\r\n").await.map_err(classify)?;
    if reply.code != 354 {
        return Err(classify(SmtpError::UnexpectedReply(reply)));
    }
    client.write_message(raw).await.map_err(|e| HostError::Temporary(e.to_string()))?;
    let reply = client.read().await.map_err(classify)?;
    if (200..300).contains(&reply.code) {
        Ok(reply_text(&reply))
    } else {
        Err(classify(SmtpError::UnexpectedReply(reply)))
    }
}

/// The reply as a human reads it: code, enhanced status if any, text.
/// The client parses the `5.1.1` out of the message, and that is exactly the
/// part bounce classification looks for, so it goes back in.
fn reply_text(r: &smtp_proto::Response<String>) -> String {
    if r.esc == [0, 0, 0] {
        format!("{} {}", r.code, r.message.trim())
    } else {
        format!("{} {}.{}.{} {}", r.code, r.esc[0], r.esc[1], r.esc[2], r.message.trim())
    }
}

/// 5xx is the other server's final word; everything else is worth another try.
fn classify(e: SmtpError) -> HostError {
    match e {
        SmtpError::UnexpectedReply(r) | SmtpError::AuthenticationFailed(r) => {
            let text = reply_text(&r);
            if (500..600).contains(&r.code) {
                HostError::Permanent(text)
            } else {
                HostError::Temporary(text)
            }
        }
        SmtpError::Timeout => HostError::Temporary("timed out".into()),
        SmtpError::Io(e) => HostError::Temporary(format!("io: {e}")),
        SmtpError::Tls(e) => HostError::Temporary(format!("tls: {e}")),
        other => HostError::Temporary(format!("{other:?}")),
    }
}

/// Days after which finished messages lose their bodies.
pub const KEEP_BODIES_DAYS: i64 = 7;
/// Days after which inbound raw mail and finished webhook rows are dropped.
pub const KEEP_INBOUND_DAYS: i64 = 30;

pub async fn run_cleanup(app: Arc<App>) {
    loop {
        let finished = after_seconds(-KEEP_BODIES_DAYS * 86_400);
        let inbound = after_seconds(-KEEP_INBOUND_DAYS * 86_400);
        if let Err(e) = app.db.cleanup(&finished, &inbound).await {
            tracing::error!(error = %e, "cleanup");
        }
        tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_address_detection() {
        assert!(looks_like_bad_address(
            "550 5.1.1 The email account that you tried to reach does not exist"
        ));
        assert!(looks_like_bad_address("550 User unknown"));
        assert!(!looks_like_bad_address("550 5.7.1 Message rejected as spam"));
        assert!(!looks_like_bad_address("552 5.3.4 Message too large"));
    }

    #[test]
    fn reply_codes_classify() {
        let r = |code| smtp_proto::Response {
            code,
            esc: [0; 3],
            message: "x".to_string(),
        };
        assert!(matches!(classify(SmtpError::UnexpectedReply(r(550))), HostError::Permanent(_)));
        let esc = smtp_proto::Response {
            code: 550,
            esc: [5, 1, 1],
            message: "no such user".to_string(),
        };
        assert_eq!(reply_text(&esc), "550 5.1.1 no such user");
        assert!(matches!(classify(SmtpError::UnexpectedReply(r(451))), HostError::Temporary(_)));
        assert!(matches!(classify(SmtpError::Timeout), HostError::Temporary(_)));
    }

    #[test]
    fn retry_schedule_spans_two_days() {
        assert_eq!(
            RETRY_SECONDS.iter().sum::<i64>(),
            60 + 300 + 900 + 3600 + 4 * 3600 + 12 * 3600 + 48 * 3600
        );
    }
}
