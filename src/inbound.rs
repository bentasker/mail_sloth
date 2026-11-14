//! What happens to a message once port 25 has accepted it.
//!
//! Three kinds of recipient exist at our domains:
//!  - `bounce+<id>@domain`: a delivery report for something we sent;
//!  - `SRS0=...@domain`: a bounce for something we forwarded, unwrapped and
//!    passed back to the original sender;
//!  - anything else: forwarded to the configured inbox and, if the site
//!    wants it, POSTed to its webhook.
//!
//! Everything is authenticated (SPF, DKIM, ARC, DMARC) first, both to reject
//! outright forgeries and so the forwarded copy carries an ARC seal that lets
//! Gmail trust the original results across our hop.

use std::collections::BTreeMap;
use std::net::IpAddr;

use mail_auth::common::headers::HeaderWriter;
use mail_auth::dmarc::verify::DmarcParameters;
use mail_auth::dmarc::Policy;
use mail_auth::spf::verify::SpfParameters;
use mail_auth::{AuthenticatedMessage, AuthenticationResults, DkimResult, DmarcResult, SpfResult};
use mail_parser::{HeaderName, MessageParser, MimeHeaders};

use crate::app::App;
use crate::db::{NewMessage, KEPT};
use crate::srs;
use crate::util::{new_id, normalize_email, rfc2822_now, split_email};
use crate::webhook;

pub struct Envelope {
    pub helo: String,
    pub remote_ip: IpAddr,
    pub mail_from: String,
    pub rcpts: Vec<String>,
    pub tls: bool,
}

pub struct Reject {
    pub code: u16,
    pub text: String,
}

fn reject(code: u16, text: impl Into<String>) -> Reject {
    Reject { code, text: text.into() }
}

pub enum Kind {
    /// A DSN for the message with this id.
    Bounce(String),
    /// A bounce for a forwarded message; the original sender it goes back to.
    SrsReturn(String),
    /// A real mailbox at one of our domains.
    Local,
}

/// Whether we take mail for this address, decided at RCPT time so the
/// sending server learns about a bad address before it transmits the body.
pub fn classify_recipient(app: &App, addr: &str) -> Result<(String, Kind), Reject> {
    let addr = normalize_email(addr);
    let Some((local, domain)) = split_email(&addr) else {
        return Err(reject(501, "5.1.3 bad recipient address"));
    };
    let Some(d) = app.cfg.domain(domain) else {
        return Err(reject(550, "5.7.1 relay not permitted"));
    };
    if let Some(id) = local.strip_prefix("bounce+") {
        if id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok((d.name.clone(), Kind::Bounce(id.to_string())));
        }
        return Err(reject(550, "5.1.1 no such bounce address"));
    }
    if local.starts_with("srs0=") {
        // A host that forwards nothing has no secret and so no SRS addresses.
        // The reply is the same whatever was wrong, so it is no help to
        // someone guessing hashes; the reason goes to the log.
        let secret = app.cfg.srs_secret.as_deref().unwrap_or("");
        return match srs::reverse(secret, local) {
            Ok(orig) => Ok((d.name.clone(), Kind::SrsReturn(orig))),
            Err(e) => {
                tracing::info!(rcpt = %addr, reason = e, "invalid SRS address");
                Err(reject(550, "5.1.1 no such user"))
            }
        };
    }
    if d.forward_targets(local).is_some() || d.inbound_webhook {
        return Ok((d.name.clone(), Kind::Local));
    }
    Err(reject(550, "5.1.1 no such user"))
}

/// SPF is checked for the envelope sender, or for the HELO name when there
/// is none (a bounce). Not `SpfParameters::verify`: it checks HELO first and
/// returns that unless it passes, so a host whose HELO name publishes no SPF
/// (all of Google's outbound) got `none` for a sender whose SPF passes.
fn spf_identity<'x>(env: &'x Envelope, hostname: &'x str) -> SpfParameters<'x> {
    if env.mail_from.is_empty() {
        SpfParameters::verify_ehlo(env.remote_ip, &env.helo, hostname)
    } else {
        SpfParameters::verify_mail_from(env.remote_ip, &env.helo, hostname, &env.mail_from)
    }
}

/// Verifies, stores, forwards, and notifies. Returns the inbound id.
pub async fn accept(app: &App, env: Envelope, raw: Vec<u8>) -> Result<String, Reject> {
    let id = new_id();
    let hostname = app.cfg.hostname.clone();
    let Some(auth_msg) = AuthenticatedMessage::parse(&raw) else {
        return Err(reject(550, "5.6.0 message could not be parsed"));
    };

    // ---- authenticate ---------------------------------------------------
    let spf = app.resolver.verify_spf(spf_identity(&env, &hostname)).await;
    let dkim = app.resolver.verify_dkim(&auth_msg).await;
    let arc = app.resolver.verify_arc(&auth_msg).await;
    let mail_from_domain = env
        .mail_from
        .rsplit_once('@')
        .map(|(_, d)| d.to_string())
        .unwrap_or_else(|| env.helo.clone());
    let dmarc = app
        .resolver
        .verify_dmarc(DmarcParameters::new(&auth_msg, &dkim, &mail_from_domain, &spf))
        .await;
    let dkim_pass = dkim.iter().any(|d| matches!(d.result(), DkimResult::Pass));
    let dmarc_pass = matches!(dmarc.dkim_result(), DmarcResult::Pass) || matches!(dmarc.spf_result(), DmarcResult::Pass);
    let from_header = auth_msg.from.first().cloned().unwrap_or_default();

    let auth_summary = serde_json::json!({
        "spf": format!("{:?}", spf.result()).to_ascii_lowercase(),
        "dkim": if dkim_pass { "pass" } else if dkim.is_empty() { "none" } else { "fail" },
        "dmarc": if dmarc.policy() == Policy::Unspecified && !dmarc_pass { "none".to_string() } else if dmarc_pass { "pass".to_string() } else { "fail".to_string() },
        "dmarc_policy": format!("{:?}", dmarc.policy()).to_ascii_lowercase(),
        "arc": arc_result_name(&arc),
        "tls": env.tls,
    });

    if dmarc.policy() == Policy::Reject && !dmarc_pass {
        tracing::info!(peer = %env.remote_ip, from = %from_header, "rejected by DMARC policy");
        return Err(reject(550, format!("5.7.1 rejected by the DMARC policy of {}", dmarc.domain())));
    }
    if spf.result() == SpfResult::Fail && !dkim_pass {
        tracing::info!(peer = %env.remote_ip, mail_from = %env.mail_from, "rejected: SPF fail and no DKIM");
        return Err(reject(550, format!("5.7.23 SPF check failed for {}", spf.domain())));
    }

    let results = AuthenticationResults::new(&hostname)
        .with_spf_mailfrom_result(&spf, env.remote_ip, &env.mail_from, &env.helo)
        .with_dkim_results(&dkim, &from_header)
        .with_arc_result(&arc, env.remote_ip)
        .with_dmarc_result(&dmarc);

    // ---- what the message looks like ------------------------------------
    let parsed = MessageParser::default().parse(&raw);
    let subject = parsed
        .as_ref()
        .and_then(|p| p.subject())
        .unwrap_or("")
        .chars()
        .take(500)
        .collect::<String>();
    let from_display = parsed
        .as_ref()
        .and_then(|p| p.from())
        .and_then(|a| a.first())
        .map(|a| match (a.name(), a.address()) {
            (Some(n), Some(e)) => format!("{n} <{e}>"),
            (_, Some(e)) => e.to_string(),
            _ => String::new(),
        })
        .unwrap_or_default();

    // ---- route ------------------------------------------------------------
    // Decide everything first and act on none of it: the message is recorded
    // before anything is queued, so a storage failure is a 451 and a retry,
    // not a 250 for mail we did not keep.
    let mut actions: Vec<String> = Vec::new();
    let mut bounces: Vec<String> = Vec::new();
    let mut forwards: Vec<(String, String, String)> = Vec::new(); // (target, envelope sender, our domain)
    let mut webhooks: BTreeMap<String, Vec<String>> = BTreeMap::new(); // site -> its recipients
    let mut first_domain = String::new();
    let secret = app.cfg.srs_secret.clone().unwrap_or_default();

    for rcpt in &env.rcpts {
        let Ok((domain, kind)) = classify_recipient(app, rcpt) else {
            continue;
        };
        if first_domain.is_empty() {
            first_domain = domain.clone();
        }
        match kind {
            Kind::Bounce(mid) => {
                actions.push(format!("bounce:{mid}"));
                bounces.push(mid);
            }
            Kind::SrsReturn(orig) => {
                forwards.push((orig.clone(), String::new(), domain.clone()));
                actions.push(format!("srs-return:{orig}"));
            }
            Kind::Local => {
                let local = rcpt.rsplit_once('@').map(|(l, _)| l).unwrap_or("");
                let d = app.cfg.domain(&domain).expect("classified domain exists");
                match d.forward_targets(local) {
                    Some(targets) if targets.is_empty() => actions.push(KEPT.to_string()),
                    Some(targets) => {
                        for t in targets {
                            forwards.push((t.clone(), srs::rewrite(&secret, &env.mail_from, &domain), domain.clone()));
                        }
                        actions.push(format!("forward:{}", targets.join(",")));
                    }
                    None => {}
                }
                if d.inbound_webhook {
                    if let Some(site) = app.cfg.site_for_domain(&domain) {
                        webhooks.entry(site.name.clone()).or_default().push(rcpt.clone());
                    }
                }
            }
        }
    }
    if !webhooks.is_empty() {
        actions.push(format!(
            "webhook:{}",
            webhooks.keys().map(String::as_str).collect::<Vec<_>>().join(",")
        ));
    }
    let action = if actions.is_empty() {
        "dropped".to_string()
    } else {
        actions.join(" ")
    };

    // ---- record -------------------------------------------------------------
    if let Err(e) = app
        .db
        .insert_inbound(
            &id,
            &first_domain,
            &env.remote_ip.to_string(),
            &env.helo,
            &env.mail_from,
            &env.rcpts.join(","),
            &from_display,
            &subject,
            &auth_summary.to_string(),
            &action,
            &raw,
        )
        .await
    {
        tracing::error!(id = %id, error = %e, "could not record inbound message");
        return Err(reject(451, "4.3.0 temporary storage failure, try again later"));
    }
    for mid in &bounces {
        handle_bounce(app, mid, &raw, &subject).await;
    }

    // ---- forward ------------------------------------------------------------
    if !forwards.is_empty() {
        let received = format!(
            "Received: from {} ([{}])\r\n\tby {hostname} with {} id {id}\r\n\tfor <{}>; {}\r\n",
            sanitize(&env.helo),
            env.remote_ip,
            if env.tls { "ESMTPS" } else { "ESMTP" },
            env.rcpts.first().map(String::as_str).unwrap_or(""),
            rfc2822_now()
        );
        let mut sealed_headers: Vec<u8> = Vec::new();
        if let Some(keys) = app.dkim.get(&first_domain) {
            match keys.sealer.seal(&auth_msg, &results, &arc) {
                Ok(set) => set.write_header(&mut sealed_headers),
                Err(e) => tracing::warn!(id = %id, error = %e, "could not ARC-seal, forwarding unsealed"),
            }
        }
        let mut results_header: Vec<u8> = Vec::new();
        results.write_header(&mut results_header);

        let mut rows = Vec::new();
        for (target, envelope_sender, domain) in &forwards {
            let mut body = Vec::with_capacity(raw.len() + 1024);
            body.extend_from_slice(received.as_bytes());
            // A bounce going back to the original sender carries no seal:
            // there is nothing to vouch for and it must not be forwarded on.
            if !envelope_sender.is_empty() {
                body.extend_from_slice(&sealed_headers);
                body.extend_from_slice(&results_header);
            }
            body.extend_from_slice(&raw);
            rows.push(NewMessage {
                id: new_id(),
                site: app.cfg.site_for_domain(domain).map(|s| s.name.clone()).unwrap_or_default(),
                batch_id: id.clone(),
                kind: "forward".into(),
                domain: domain.clone(),
                mail_from: envelope_sender.clone(),
                rcpt_to: target.clone(),
                from_header: from_display.clone(),
                subject: subject.clone(),
                raw: body,
            });
        }
        if let Err(e) = app.db.insert_messages(&rows).await {
            tracing::error!(id = %id, error = %e, "could not queue forwards");
            return Err(reject(451, "4.3.0 temporary storage failure, try again later"));
        }
        app.wake_sender.notify_one();
    }

    // ---- notify ---------------------------------------------------------------
    // One event per site however many of its addresses the message named,
    // and a site is told only about its own recipients.
    for (site, to) in &webhooks {
        let rcpt_to: Vec<String> = env
            .rcpts
            .iter()
            .filter(|r| {
                let domain = r.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
                app.cfg.site_for_domain(domain).is_some_and(|s| &s.name == site)
            })
            .cloned()
            .collect();
        let data = received_event(
            &id,
            &env,
            parsed.as_ref(),
            &raw,
            &from_display,
            &subject,
            &auth_summary,
            to,
            &rcpt_to,
        );
        webhook::enqueue(app, site, webhook::MAIL_RECEIVED, data).await;
    }

    tracing::info!(id = %id, peer = %env.remote_ip, mail_from = %env.mail_from, rcpts = ?env.rcpts,
        from = %from_display, subject = %subject, auth = %auth_summary, action = %action, size = raw.len(), "inbound");
    Ok(id)
}

/// A message handed to the submission port by an authenticated sender:
/// queued as a `send` for each recipient, so it is DKIM-signed and
/// delivered exactly like a message from the API. Returns the batch id.
pub async fn submit(app: &App, sender: &str, rcpts: &[String], raw: Vec<u8>) -> Result<String, Reject> {
    let sender = normalize_email(sender);
    let Some((_, domain)) = split_email(&sender) else {
        return Err(reject(550, "5.7.1 sender is not an address"));
    };
    let Some(site) = app.cfg.site_for_domain(domain) else {
        return Err(reject(550, "5.7.1 no site owns this domain"));
    };
    if app.dkim.get(domain).is_none() {
        return Err(reject(
            550,
            format!("5.7.1 no DKIM key for {domain}; run `mail_sloth dkim {domain}`"),
        ));
    }
    let Some(parsed) = MessageParser::default().parse(&raw) else {
        return Err(reject(550, "5.6.0 message could not be parsed"));
    };
    // Exactly one From header naming exactly one mailbox. Readers show the
    // first of two and we would be checking the last, so a second From, or a
    // second address in the one From, is a way to sign somebody else's name.
    let from_headers = parsed.headers().iter().filter(|h| h.name == HeaderName::From).count();
    let from = match parsed.from().and_then(|a| a.as_list()) {
        Some([only]) if from_headers == 1 => Some(only),
        _ => None,
    };
    let from_addr = from.and_then(|a| a.address()).map(normalize_email).unwrap_or_default();
    if from_addr != sender {
        return Err(reject(550, "5.7.1 From must match login"));
    }
    let from_display = match from.and_then(|a| a.name()) {
        Some(n) => format!("{n} <{from_addr}>"),
        None => from_addr.clone(),
    };
    let subject = parsed.subject().unwrap_or("").chars().take(500).collect::<String>();

    // Rebuild the header block: a Bcc must not reach the recipients, and
    // the receiving side wants a Date and a Message-ID.
    let batch_id = new_id();
    let mut out = Vec::with_capacity(raw.len() + 256);
    if parsed.date().is_none() {
        out.extend_from_slice(format!("Date: {}\r\n", rfc2822_now()).as_bytes());
    }
    if parsed.message_id().is_none() {
        out.extend_from_slice(format!("Message-ID: <{batch_id}@{domain}>\r\n").as_bytes());
    }
    for h in parsed.headers() {
        if h.name.as_str().eq_ignore_ascii_case("Bcc") {
            continue;
        }
        let field = &raw[h.offset_field as usize..h.offset_end as usize];
        out.extend_from_slice(field);
        if !field.ends_with(b"\n") {
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&raw[parsed.root_part().offset_body as usize..]);

    let rows: Vec<NewMessage> = rcpts
        .iter()
        .map(|rcpt| {
            let id = new_id();
            NewMessage {
                mail_from: format!("bounce+{id}@{domain}"),
                id,
                site: site.name.clone(),
                batch_id: batch_id.clone(),
                kind: "send".into(),
                domain: domain.to_string(),
                rcpt_to: rcpt.clone(),
                from_header: from_display.clone(),
                subject: subject.clone(),
                raw: out.clone(),
            }
        })
        .collect();
    if let Err(e) = app.db.insert_messages(&rows).await {
        tracing::error!(batch_id = %batch_id, error = %e, "could not queue submission");
        return Err(reject(451, "4.3.0 temporary storage failure, try again later"));
    }
    app.wake_sender.notify_one();
    tracing::info!(batch_id = %batch_id, sender = %sender, rcpts = ?rcpts, subject = %subject, size = out.len(), "submitted");
    Ok(batch_id)
}

fn arc_result_name(arc: &mail_auth::ArcOutput) -> &'static str {
    match arc.result() {
        DkimResult::Pass => "pass",
        DkimResult::None => "none",
        DkimResult::Fail(_) => "fail",
        DkimResult::Neutral(_) => "neutral",
        DkimResult::PermError(_) => "permerror",
        DkimResult::TempError(_) => "temperror",
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '[' | ']' | ':' | '_'))
        .take(255)
        .collect()
}

/// A DSN for one of our messages: mark it bounced, stop mailing the address
/// if the report says the mailbox is gone, tell the site.
async fn handle_bounce(app: &App, message_id: &str, raw: &[u8], subject: &str) {
    let Ok(Some(m)) = app.db.get_message(message_id).await else {
        tracing::info!(message_id, "bounce for an unknown message, ignored");
        return;
    };
    let diagnostic = bounce_diagnostic(raw).unwrap_or_else(|| subject.to_string());
    tracing::info!(id = %m.id, to = %m.rcpt_to, diagnostic = %diagnostic, "bounce received");
    let _ = app.db.mark_bounced(&m.id, &diagnostic).await;
    if m.kind == "send" {
        if diagnostic.contains("5.1.") || crate::deliver::looks_like_bad_address(&diagnostic) {
            let _ = app.db.add_suppression(&m.rcpt_to, &format!("bounce: {diagnostic}")).await;
        }
        webhook::enqueue(app, &m.site, webhook::MESSAGE_BOUNCED, crate::deliver::event_data(&m, &diagnostic)).await;
    }
}

/// The most useful line of a delivery status report: the Diagnostic-Code if
/// there is one, else the Status, else nothing.
pub fn bounce_diagnostic(raw: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    let find = |prefix: &str| {
        text.lines()
            .find(|l| l.len() > prefix.len() && l[..prefix.len()].eq_ignore_ascii_case(prefix))
            .map(|l| l[prefix.len()..].trim().chars().take(300).collect::<String>())
            .filter(|s| !s.is_empty())
    };
    find("Diagnostic-Code:").or_else(|| find("Status:"))
}

#[allow(clippy::too_many_arguments)]
fn received_event(
    id: &str,
    env: &Envelope,
    parsed: Option<&mail_parser::Message<'_>>,
    raw: &[u8],
    from_display: &str,
    subject: &str,
    auth: &serde_json::Value,
    to: &[String],
    rcpt_to: &[String],
) -> serde_json::Value {
    const MAX_BODY_CHARS: usize = 256 * 1024;
    let clip = |s: Option<std::borrow::Cow<'_, str>>| s.map(|s| s.chars().take(MAX_BODY_CHARS).collect::<String>());
    let (from_name, from_email, text, html, date, message_id, in_reply_to, headers, attachments) = match parsed {
        Some(p) => {
            let from = p.from().and_then(|a| a.first());
            let headers: Vec<serde_json::Value> = p
                .headers()
                .iter()
                .map(|h| {
                    let value = String::from_utf8_lossy(&raw[h.offset_start as usize..h.offset_end as usize]);
                    serde_json::json!([h.name.as_str(), value.trim()])
                })
                .collect();
            let attachments: Vec<serde_json::Value> = p
                .attachments()
                .map(|a| {
                    serde_json::json!({
                        "name": a.attachment_name(),
                        "content_type": a.content_type().map(|c| match c.subtype() {
                            Some(s) => format!("{}/{s}", c.ctype()),
                            None => c.ctype().to_string(),
                        }),
                        "size": a.contents().len(),
                    })
                })
                .collect();
            (
                from.and_then(|a| a.name()).map(str::to_string),
                from.and_then(|a| a.address()).map(str::to_string),
                clip(p.body_text(0)),
                clip(p.body_html(0)),
                p.date().map(|d| d.to_rfc3339()),
                p.message_id().map(str::to_string),
                p.in_reply_to().as_text().map(str::to_string),
                headers,
                attachments,
            )
        }
        None => (None, None, None, None, None, None, None, Vec::new(), Vec::new()),
    };
    serde_json::json!({
        "inbound_id": id,
        "to": to,
        "envelope": { "mail_from": env.mail_from, "rcpt_to": rcpt_to, "remote_ip": env.remote_ip.to_string(), "helo": env.helo },
        "from": { "name": from_name, "email": from_email, "display": from_display },
        "subject": subject,
        "date": date,
        "message_id": message_id,
        "in_reply_to": in_reply_to,
        "text": text,
        "html": html,
        "headers": headers,
        "attachments": attachments,
        "auth": auth,
        "size": raw.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_auth::MessageAuthenticator;

    #[test]
    fn diagnostics_come_from_dsn_lines() {
        let raw = b"Subject: Undelivered\r\n\r\nFinal-Recipient: rfc822; x@y.com\r\nAction: failed\r\nStatus: 5.1.1\r\nDiagnostic-Code: smtp; 550 5.1.1 No such user\r\n";
        assert_eq!(bounce_diagnostic(raw).unwrap(), "smtp; 550 5.1.1 No such user");
        let raw = b"Action: failed\r\nStatus: 4.4.1\r\n";
        assert_eq!(bounce_diagnostic(raw).unwrap(), "4.4.1");
        assert!(bounce_diagnostic(b"nothing here").is_none());
    }

    /// TXT answers from a map, so SPF is evaluated without the network.
    struct FakeTxt(std::sync::Mutex<std::collections::HashMap<Box<str>, mail_auth::Txt>>);

    impl mail_auth::ResolverCache<Box<str>, mail_auth::Txt> for FakeTxt {
        fn get<Q>(&self, name: &Q) -> Option<mail_auth::Txt>
        where
            Box<str>: std::borrow::Borrow<Q>,
            Q: std::hash::Hash + Eq + ?Sized,
        {
            self.0.lock().unwrap().get(name).cloned()
        }
        fn remove<Q>(&self, name: &Q) -> Option<mail_auth::Txt>
        where
            Box<str>: std::borrow::Borrow<Q>,
            Q: std::hash::Hash + Eq + ?Sized,
        {
            self.0.lock().unwrap().remove(name)
        }
        fn insert(&self, key: Box<str>, value: mail_auth::Txt, _: std::time::Instant) {
            self.0.lock().unwrap().insert(key, value);
        }
    }

    fn spf_record(name: &str, record: &str) -> (Box<str>, mail_auth::Txt) {
        use mail_auth::common::parse::TxtRecordParser;
        let spf = mail_auth::spf::Spf::parse(record.as_bytes()).unwrap();
        (format!("{name}.").into(), mail_auth::Txt::Spf(std::sync::Arc::new(spf)))
    }

    #[tokio::test]
    async fn spf_judges_the_envelope_sender_not_the_helo_name() {
        let txt = FakeTxt(std::sync::Mutex::new(
            [
                spf_record("sender.example", "v=spf1 ip4:192.0.2.1 -all"),
                spf_record("relay.example", "v=spf1 ip4:198.51.100.1 -all"),
            ]
            .into(),
        ));
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let mut env = Envelope {
            helo: "relay.example".into(),
            remote_ip: "192.0.2.1".parse().unwrap(),
            mail_from: "reports@sender.example".into(),
            rcpts: vec![],
            tls: true,
        };
        async fn check(resolver: &MessageAuthenticator, txt: &FakeTxt, env: &Envelope) -> SpfResult {
            let params = mail_auth::Parameters::new(spf_identity(env, "mx.example")).with_txt_cache(txt);
            resolver.verify_spf(params).await.result()
        }
        // The HELO name's SPF does not cover this IP; the sender's does.
        assert_eq!(check(&resolver, &txt, &env).await, SpfResult::Pass);
        // A bounce has no sender, so the HELO name is all there is.
        env.mail_from.clear();
        assert_eq!(check(&resolver, &txt, &env).await, SpfResult::Fail);
    }

    #[test]
    fn helo_is_sanitized_before_it_lands_in_a_header() {
        assert_eq!(sanitize("mail.example.com"), "mail.example.com");
        assert_eq!(sanitize("evil\r\nX-Injected: yes"), "evilX-Injected:yes");
    }
}
