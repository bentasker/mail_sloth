//! The REST API the sites call.
//!
//! One endpoint does the work: `POST /v1/send`. The rest is looking things
//! up. Authentication is a bearer key per site, and a key can only send from
//! the domains its site owns.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::extract::{FromRequestParts, Path, State};
use axum::http::{request::Parts, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::app::App;
use crate::config::Site;
use crate::db::{MessageRow, NewMessage};
use crate::message::{self, Draft, Mailbox};
use crate::util::{is_valid_email, new_id, normalize_email, sha256_hex};

const MAX_RECIPIENTS: usize = 500;
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/send", post(send))
        .route("/v1/messages/{id}", get(get_message))
        .route("/v1/batches/{id}", get(get_batch))
        .route("/v1/suppressions", get(list_suppressions).post(add_suppression))
        .route("/v1/suppressions/{email}", axum::routing::delete(delete_suppression))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(app)
}

// ---- errors -------------------------------------------------------------------

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    tracing::error!(error = %e, "request failed");
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
}

// ---- auth ---------------------------------------------------------------------

/// The site behind a bearer key.
pub struct Auth(pub Site);

impl FromRequestParts<Arc<App>> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let key = header.strip_prefix("Bearer ").unwrap_or("").trim();
        if key.is_empty() {
            return Err(ApiError(StatusCode::UNAUTHORIZED, "missing bearer key".into()));
        }
        match authenticate(&app.cfg.sites, key) {
            Some(site) => Ok(Auth(site.clone())),
            None => Err(ApiError(StatusCode::UNAUTHORIZED, "unknown key".into())),
        }
    }
}

pub fn authenticate<'a>(sites: &'a [Site], key: &str) -> Option<&'a Site> {
    let digest = sha256_hex(key.as_bytes());
    // Compare every hash rather than stopping at the first match so the
    // response time does not say which site a wrong key was close to.
    let mut found = None;
    for site in sites {
        for k in &site.api_keys {
            if k.to_ascii_lowercase().as_bytes().ct_eq(digest.as_bytes()).into() && found.is_none() {
                found = Some(site);
            }
        }
    }
    found
}

// ---- send ---------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    /// `paul@example.com` or `Paul <paul@example.com>`.
    pub from: String,
    pub to: Vec<Recipient>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    /// Defaults to the sender's configured reply_to, if any.
    pub reply_to: Option<String>,
    /// Extra headers. Values are templates too.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Template variables shared by every recipient.
    #[serde(default)]
    pub vars: HashMap<String, String>,
    /// One-off mail (a receipt, a login link, a note to the hosts) rather
    /// than a list send. Without it, a message to more than one recipient
    /// must carry a List-Unsubscribe header.
    #[serde(default)]
    pub transactional: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum Recipient {
    Address(String),
    Full {
        email: String,
        name: Option<String>,
        #[serde(default)]
        vars: HashMap<String, String>,
    },
}

#[derive(Serialize)]
pub struct SendResponse {
    pub batch_id: String,
    pub queued: Vec<Queued>,
    pub skipped: Vec<Skipped>,
}

#[derive(Serialize)]
pub struct Queued {
    pub id: String,
    pub to: String,
}

#[derive(Serialize)]
pub struct Skipped {
    pub to: String,
    pub reason: String,
}

async fn send(
    State(app): State<Arc<App>>,
    Auth(site): Auth,
    Json(req): Json<SendRequest>,
) -> Result<(StatusCode, Json<SendResponse>), ApiError> {
    let mut from = Mailbox::parse(&req.from).map_err(|e| bad(e.to_string()))?;
    let domain = from.domain().to_ascii_lowercase();
    if !site.domains.contains(&domain) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            format!("site {} may not send from {domain}", site.name),
        ));
    }
    let domain_cfg = app.cfg.domain(&domain).ok_or_else(|| bad("unknown domain"))?;
    let sender_cfg = domain_cfg.sender(from.local_part()).cloned().unwrap_or_default();
    if from.name.is_none() {
        from.name = sender_cfg.name.clone();
    }
    let reply_to = req.reply_to.clone().or(sender_cfg.reply_to.clone());
    if let Some(r) = &reply_to {
        if !is_valid_email(r) {
            return Err(bad(format!("reply_to is not an address: {r}")));
        }
    }
    let subject = req.subject.trim();
    if subject.is_empty() {
        return Err(bad("subject is required"));
    }
    if req.text.as_deref().is_none_or(str::is_empty) && req.html.as_deref().is_none_or(str::is_empty) {
        return Err(bad("text or html is required"));
    }
    if req.to.is_empty() {
        return Err(bad("to is required"));
    }
    if req.to.len() > MAX_RECIPIENTS {
        return Err(bad(format!("at most {MAX_RECIPIENTS} recipients per request")));
    }
    for name in req.headers.keys() {
        if !message::is_valid_header_name(name) {
            return Err(bad(format!("header not allowed: {name}")));
        }
    }
    if let Err(e) = check_unsubscribe(&req) {
        return Err(bad(e));
    }
    if app.dkim.get(&domain).is_none() {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("no DKIM key for {domain} on the mail host; run `mail_sloth dkim {domain}`"),
        ));
    }

    let batch_id = new_id();
    let mut queued = Vec::new();
    let mut skipped = Vec::new();
    let mut rows = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for r in &req.to {
        let (email, name, rvars) = match r {
            Recipient::Address(a) => (a.clone(), None, HashMap::new()),
            Recipient::Full { email, name, vars } => (email.clone(), name.clone(), vars.clone()),
        };
        let email = normalize_email(&email);
        if !is_valid_email(&email) {
            skipped.push(Skipped {
                to: email,
                reason: "invalid address".into(),
            });
            continue;
        }
        if !seen.insert(email.clone()) {
            skipped.push(Skipped {
                to: email,
                reason: "duplicate".into(),
            });
            continue;
        }
        if app.db.is_suppressed(&email).await.map_err(internal)? {
            skipped.push(Skipped {
                to: email,
                reason: "suppressed".into(),
            });
            continue;
        }

        let mut vars = req.vars.clone();
        vars.extend(rvars);
        vars.insert("email".into(), email.clone());
        vars.insert("name".into(), name.clone().unwrap_or_default());

        let id = new_id();
        let to = Mailbox {
            name: name.map(|n| message::clean_header(&n)),
            email: email.clone(),
        };
        let subj = message::clean_header(&message::substitute(subject, &vars, false));
        let text = req.text.as_deref().map(|t| message::substitute(t, &vars, false));
        let html = req.html.as_deref().map(|h| message::substitute(h, &vars, true));
        let headers: Vec<(String, String)> = req
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), message::clean_header(&message::substitute(v, &vars, false))))
            .collect();
        let message_id = format!("{id}@{domain}");
        let raw = message::build(&Draft {
            from: &from,
            to: &to,
            reply_to: reply_to.as_deref(),
            subject: &subj,
            text: text.as_deref().filter(|t| !t.is_empty()),
            html: html.as_deref().filter(|h| !h.is_empty()),
            headers: &headers,
            message_id: &message_id,
        })
        .map_err(|e| bad(e.to_string()))?;

        rows.push(NewMessage {
            id: id.clone(),
            site: site.name.clone(),
            batch_id: batch_id.clone(),
            kind: "send".into(),
            domain: domain.clone(),
            mail_from: format!("bounce+{id}@{domain}"),
            rcpt_to: email.clone(),
            from_header: from.header_value(),
            subject: subj,
            raw,
        });
        queued.push(Queued { id, to: email });
    }

    if !rows.is_empty() {
        app.db.insert_messages(&rows).await.map_err(internal)?;
        app.wake_sender.notify_one();
    }
    tracing::info!(site = %site.name, batch = %batch_id, queued = queued.len(), skipped = skipped.len(), from = %from.email, "batch queued");
    Ok((StatusCode::ACCEPTED, Json(SendResponse { batch_id, queued, skipped })))
}

/// A list send must let people leave the list. Every message to more than
/// one person needs a `List-Unsubscribe` header unless the caller says it is
/// transactional, because a broadcast that forgot its unsubscribe link is
/// the one mistake that gets a whole domain blocked.
pub fn check_unsubscribe(req: &SendRequest) -> Result<(), String> {
    if req.transactional || req.to.len() <= 1 {
        return Ok(());
    }
    let has = |name: &str| req.headers.keys().any(|k| k.eq_ignore_ascii_case(name));
    if !has("List-Unsubscribe") {
        return Err("a message to more than one recipient needs a List-Unsubscribe header \
                    (and List-Unsubscribe-Post: List-Unsubscribe=One-Click), or \"transactional\": true \
                    if it is not a list send"
            .into());
    }
    if !has("List-Unsubscribe-Post") {
        return Err(
            "List-Unsubscribe needs List-Unsubscribe-Post: List-Unsubscribe=One-Click alongside it; \
                    Gmail ignores the link without it"
                .into(),
        );
    }
    Ok(())
}

// ---- lookups ------------------------------------------------------------------

#[derive(Serialize)]
pub struct MessageView {
    pub id: String,
    pub batch_id: String,
    pub kind: String,
    pub to: String,
    pub from: String,
    pub subject: String,
    pub status: String,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub next_attempt_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub sent_at: Option<String>,
}

impl From<MessageRow> for MessageView {
    fn from(m: MessageRow) -> Self {
        MessageView {
            id: m.id,
            batch_id: m.batch_id,
            kind: m.kind,
            to: m.rcpt_to,
            from: m.from_header,
            subject: m.subject,
            status: m.status,
            attempts: m.attempts,
            last_error: m.last_error,
            next_attempt_at: m.next_attempt_at,
            created_at: m.created_at,
            updated_at: m.updated_at,
            sent_at: m.sent_at,
        }
    }
}

async fn get_message(State(app): State<Arc<App>>, Auth(site): Auth, Path(id): Path<String>) -> Result<Json<MessageView>, ApiError> {
    match app.db.get_message(&id).await.map_err(internal)? {
        Some(m) if m.site == site.name => Ok(Json(m.into())),
        _ => Err(ApiError(StatusCode::NOT_FOUND, "no such message".into())),
    }
}

#[derive(Serialize)]
pub struct BatchView {
    pub batch_id: String,
    pub counts: BTreeMap<String, usize>,
    pub messages: Vec<MessageView>,
}

async fn get_batch(State(app): State<Arc<App>>, Auth(site): Auth, Path(id): Path<String>) -> Result<Json<BatchView>, ApiError> {
    let rows = app.db.batch_messages(&id).await.map_err(internal)?;
    let rows: Vec<MessageRow> = rows.into_iter().filter(|m| m.site == site.name).collect();
    if rows.is_empty() {
        return Err(ApiError(StatusCode::NOT_FOUND, "no such batch".into()));
    }
    let mut counts = BTreeMap::new();
    for m in &rows {
        *counts.entry(m.status.clone()).or_insert(0) += 1;
    }
    Ok(Json(BatchView {
        batch_id: id,
        counts,
        messages: rows.into_iter().map(Into::into).collect(),
    }))
}

// ---- suppressions -------------------------------------------------------------

async fn list_suppressions(State(app): State<Arc<App>>, Auth(_): Auth) -> Result<Json<Vec<crate::db::Suppression>>, ApiError> {
    Ok(Json(app.db.list_suppressions().await.map_err(internal)?))
}

#[derive(Deserialize)]
pub struct SuppressRequest {
    pub email: String,
    #[serde(default = "default_reason")]
    pub reason: String,
}

fn default_reason() -> String {
    "manual".into()
}

async fn add_suppression(State(app): State<Arc<App>>, Auth(_): Auth, Json(req): Json<SuppressRequest>) -> Result<StatusCode, ApiError> {
    let email = normalize_email(&req.email);
    if !is_valid_email(&email) {
        return Err(bad("not an address"));
    }
    app.db.add_suppression(&email, &req.reason).await.map_err(internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_suppression(State(app): State<Arc<App>>, Auth(_): Auth, Path(email): Path<String>) -> Result<StatusCode, ApiError> {
    let removed = app.db.remove_suppression(&normalize_email(&email)).await.map_err(internal)?;
    Ok(if removed { StatusCode::NO_CONTENT } else { StatusCode::NOT_FOUND })
}

async fn healthz(State(app): State<Arc<App>>) -> Result<Json<serde_json::Value>, ApiError> {
    let counts = app.db.status_counts().await.map_err(internal)?;
    let counts: BTreeMap<String, i64> = counts.into_iter().collect();
    Ok(Json(serde_json::json!({ "ok": true, "queue": counts })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_authenticate_by_hash() {
        let site = Site {
            name: "s".into(),
            api_keys: vec![sha256_hex(b"secret-key")],
            webhook_url: None,
            webhook_secret: None,
            domains: vec![],
        };
        assert_eq!(
            authenticate(std::slice::from_ref(&site), "secret-key").map(|s| s.name.as_str()),
            Some("s")
        );
        assert!(authenticate(std::slice::from_ref(&site), "wrong").is_none());
        assert!(authenticate(&[], "secret-key").is_none());
        // A hash pasted in upper case is the same hash.
        let upper = Site {
            api_keys: vec![sha256_hex(b"secret-key").to_ascii_uppercase()],
            ..site.clone()
        };
        assert!(authenticate(std::slice::from_ref(&upper), "secret-key").is_some());
    }

    #[test]
    fn list_sends_must_carry_an_unsubscribe_header() {
        let parse = |j: &str| serde_json::from_str::<SendRequest>(j).unwrap();
        let two = r#"{"from":"a@b.co","to":["x@y.co","z@y.co"],"subject":"s","text":"t"}"#;
        assert!(check_unsubscribe(&parse(two)).unwrap_err().contains("List-Unsubscribe"));
        let one = r#"{"from":"a@b.co","to":["x@y.co"],"subject":"s","text":"t"}"#;
        assert!(check_unsubscribe(&parse(one)).is_ok());
        let flagged = r#"{"from":"a@b.co","to":["x@y.co","z@y.co"],"subject":"s","text":"t","transactional":true}"#;
        assert!(check_unsubscribe(&parse(flagged)).is_ok());
        let half = r#"{"from":"a@b.co","to":["x@y.co","z@y.co"],"subject":"s","text":"t","headers":{"list-unsubscribe":"<u>"}}"#;
        assert!(check_unsubscribe(&parse(half)).unwrap_err().contains("List-Unsubscribe-Post"));
        let full = r#"{"from":"a@b.co","to":["x@y.co","z@y.co"],"subject":"s","text":"t","headers":{"List-Unsubscribe":"<u>","List-Unsubscribe-Post":"List-Unsubscribe=One-Click"}}"#;
        assert!(check_unsubscribe(&parse(full)).is_ok());
    }

    #[test]
    fn recipients_accept_both_shapes() {
        let req: SendRequest = serde_json::from_str(
            r#"{"from":"a@b.co","to":["x@y.co",{"email":"z@y.co","name":"Z","vars":{"k":"v"}}],"subject":"s","text":"t"}"#,
        )
        .unwrap();
        assert_eq!(req.to.len(), 2);
        assert!(matches!(&req.to[1], Recipient::Full { name: Some(n), .. } if n == "Z"));
        assert!(serde_json::from_str::<SendRequest>(r#"{"from":"a@b.co","to":[],"subject":"s","bogus":1}"#).is_err());
    }
}
