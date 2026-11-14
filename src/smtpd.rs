//! The SMTP listeners: inbound on port 25 and submission on 465.
//!
//! Port 25 is plain RFC 5321 with STARTTLS and SIZE. No AUTH, no relaying: a
//! recipient is accepted only when it is an address at one of our domains
//! that has somewhere to go. Port 465 is the same protocol behind implicit
//! TLS with the rules reversed: AUTH is required, the sender must be the
//! login, and any recipient is taken. That is what lets Gmail "Send mail as"
//! a domain address. Everything about what to *do* with a message lives in
//! `inbound.rs`; this file only speaks the protocol.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::Engine;
use mail_auth::common::cache::NoCache;
use smtp_proto::request::receiver::{DataReceiver, RequestReceiver};
use smtp_proto::{Error as ParseError, Request, AUTH_LOGIN, AUTH_PLAIN};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::app::App;
use crate::inbound::{self, Envelope};

const MAX_CONNECTIONS: usize = 32;
const MAX_RECIPIENTS: usize = 20;
const MAX_MESSAGES_PER_CONNECTION: u32 = 50;
const MAX_ERRORS: u32 = 10;
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const SESSION_TIMEOUT: Duration = Duration::from_secs(1200);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Port 25: mail from the world for our domains.
    Inbound,
    /// Port 465: mail from our own senders for the world.
    Submission,
}

pub async fn run(app: Arc<App>, tls: Option<TlsAcceptor>) -> Result<()> {
    let listener = TcpListener::bind(&app.cfg.smtp_listen)
        .await
        .with_context(|| format!("binding smtp listener {}", app.cfg.smtp_listen))?;
    tracing::info!(addr = %app.cfg.smtp_listen, starttls = tls.is_some(), "smtp listening");
    serve(app, tls, listener).await
}

pub async fn run_submission(app: Arc<App>, tls: TlsAcceptor) -> Result<()> {
    let addr = app.cfg.submission_listen.clone().context("submission_listen is not set")?;
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding submission listener {addr}"))?;
    tracing::info!(addr = %addr, "submission listening (implicit tls)");
    serve_submission(app, Some(tls), listener).await
}

pub async fn serve(app: Arc<App>, tls: Option<TlsAcceptor>, listener: TcpListener) -> Result<()> {
    serve_with(app, tls, listener, Mode::Inbound).await
}

/// A submission listener. `tls` is the acceptor wrapped around every
/// connection before the greeting; `None` takes passwords in the clear and
/// exists only for the loopback tests, since the config refuses
/// `submission_listen` without `tls`.
pub async fn serve_submission(app: Arc<App>, tls: Option<TlsAcceptor>, listener: TcpListener) -> Result<()> {
    serve_with(app, tls, listener, Mode::Submission).await
}

async fn serve_with(app: Arc<App>, tls: Option<TlsAcceptor>, listener: TcpListener, mode: Mode) -> Result<()> {
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "accept");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            tracing::warn!(peer = %peer, "too many connections, dropping");
            continue;
        };
        let app = app.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let ip = peer.ip();
            let r = match mode {
                Mode::Inbound => handle(app, tls, stream, ip).await,
                Mode::Submission => handle_submission(app, tls, stream, ip).await,
            };
            if let Err(e) = r {
                tracing::debug!(peer = %ip, error = %e, "smtp session ended");
            }
        });
    }
}

async fn handle(app: Arc<App>, tls: Option<TlsAcceptor>, stream: TcpStream, ip: IpAddr) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let mut session = Session::new(app, ip, tls.is_some(), Mode::Inbound);
    let upgrade = tokio::time::timeout(SESSION_TIMEOUT, session.run(stream))
        .await
        .context("session timed out")??;
    if let (Some(tcp), Some(acceptor)) = (upgrade, tls) {
        let tls_stream = tokio::time::timeout(Duration::from_secs(30), acceptor.accept(tcp))
            .await
            .context("tls handshake timed out")?
            .context("tls handshake")?;
        session.upgraded();
        tokio::time::timeout(SESSION_TIMEOUT, session.run(tls_stream))
            .await
            .context("session timed out")??;
    }
    Ok(())
}

async fn handle_submission(app: Arc<App>, tls: Option<TlsAcceptor>, stream: TcpStream, ip: IpAddr) -> Result<()> {
    let _ = stream.set_nodelay(true);
    if app.auth_locked(ip) {
        // Do not even hand out a greeting to a locked-out client.
        return Ok(());
    }
    let mut session = Session::new(app, ip, false, Mode::Submission);
    match tls {
        Some(acceptor) => {
            let tls_stream = tokio::time::timeout(Duration::from_secs(30), acceptor.accept(stream))
                .await
                .context("tls handshake timed out")?
                .context("tls handshake")?;
            session.tls = true;
            tokio::time::timeout(SESSION_TIMEOUT, session.run(tls_stream))
                .await
                .context("session timed out")??;
        }
        None => {
            session.insecure_auth = true;
            tokio::time::timeout(SESSION_TIMEOUT, session.run(stream))
                .await
                .context("session timed out")??;
        }
    }
    Ok(())
}

enum Action {
    Continue,
    Quit,
    StartTls,
    Data,
    Auth { mechanism: u64, initial: String },
}

struct Session {
    app: Arc<App>,
    ip: IpAddr,
    mode: Mode,
    tls: bool,
    starttls_available: bool,
    /// Test-only: lets a submission session authenticate without TLS.
    insecure_auth: bool,
    greeted: bool,
    helo: Option<String>,
    /// The address a submission session logged in as.
    authenticated: Option<String>,
    mail_from: Option<String>,
    rcpts: Vec<String>,
    errors: u32,
    messages: u32,
    /// None until checked; then the zone the client is listed in, if any.
    dnsbl: Option<Option<String>>,
}

impl Session {
    fn new(app: Arc<App>, ip: IpAddr, starttls_available: bool, mode: Mode) -> Session {
        Session {
            app,
            ip,
            mode,
            tls: false,
            starttls_available,
            insecure_auth: false,
            greeted: false,
            helo: None,
            authenticated: None,
            mail_from: None,
            rcpts: Vec::new(),
            errors: 0,
            messages: 0,
            dnsbl: None,
        }
    }

    fn auth_allowed(&self) -> bool {
        self.mode == Mode::Submission && (self.tls || self.insecure_auth)
    }

    /// RFC 3207: after STARTTLS the client must start over with EHLO.
    fn upgraded(&mut self) {
        self.tls = true;
        self.starttls_available = false;
        self.helo = None;
        self.reset();
    }

    fn reset(&mut self) {
        self.mail_from = None;
        self.rcpts.clear();
    }

    /// Runs the command loop. Returns the stream when the client asked for
    /// STARTTLS so the caller can wrap it; None when the session is over.
    async fn run<S: AsyncRead + AsyncWrite + Unpin>(&mut self, mut stream: S) -> Result<Option<S>> {
        if !self.greeted {
            self.greeted = true;
            reply(&mut stream, &format!("220 {} ESMTP mail_sloth\r\n", self.app.cfg.hostname)).await?;
        }
        let mut receiver = RequestReceiver::default();
        let mut buf = vec![0u8; 8192];
        let mut pending: Vec<u8> = Vec::new();
        loop {
            if pending.is_empty() {
                let n = tokio::time::timeout(IDLE_TIMEOUT, stream.read(&mut buf))
                    .await
                    .context("idle timeout")??;
                if n == 0 {
                    return Ok(None);
                }
                pending.extend_from_slice(&buf[..n]);
            }
            let (parsed, consumed) = {
                let mut iter = pending.iter();
                let r = receiver.ingest(&mut iter).map(|req| req.into_owned());
                (r, pending.len() - iter.as_slice().len())
            };
            match parsed {
                Ok(req) => {
                    pending.drain(..consumed);
                    match self.command(req, &mut stream).await? {
                        Action::Continue => {}
                        Action::Quit => return Ok(None),
                        Action::StartTls => return Ok(Some(stream)),
                        Action::Data => {
                            let data = self.read_data(&mut stream, &mut pending, &mut buf).await?;
                            self.finish_message(&mut stream, data).await?;
                            if self.messages >= MAX_MESSAGES_PER_CONNECTION {
                                reply(&mut stream, "421 4.7.0 too many messages on one connection\r\n").await?;
                                return Ok(None);
                            }
                        }
                        Action::Auth { mechanism, initial } => {
                            if self.authenticate(mechanism, initial, &mut stream, &mut pending, &mut buf).await? {
                                return Ok(None);
                            }
                        }
                    }
                }
                Err(ParseError::NeedsMoreData { .. }) => {
                    // The receiver keeps the partial line itself.
                    pending.clear();
                }
                Err(e) => {
                    pending.drain(..consumed.max(1).min(pending.len()));
                    self.errors += 1;
                    if self.errors > MAX_ERRORS {
                        reply(&mut stream, "421 4.7.0 too many errors\r\n").await?;
                        return Ok(None);
                    }
                    let text = match e {
                        ParseError::UnknownCommand => "500 5.5.1 command not recognized\r\n".to_string(),
                        ParseError::InvalidSenderAddress => "501 5.1.7 bad sender address syntax\r\n".to_string(),
                        ParseError::InvalidRecipientAddress => "501 5.1.3 bad recipient address syntax\r\n".to_string(),
                        ParseError::SyntaxError { syntax } => format!("501 5.5.4 syntax: {syntax}\r\n"),
                        ParseError::InvalidParameter { param } => format!("501 5.5.4 invalid parameter {param}\r\n"),
                        ParseError::UnsupportedParameter { param } => format!("504 5.5.4 unsupported parameter {param}\r\n"),
                        ParseError::ResponseTooLong => "500 5.5.2 line too long\r\n".to_string(),
                        other => format!("500 5.5.1 {other:?}\r\n"),
                    };
                    reply(&mut stream, &text).await?;
                }
            }
        }
    }

    async fn command<S: AsyncRead + AsyncWrite + Unpin>(&mut self, req: Request<String>, stream: &mut S) -> Result<Action> {
        let hostname = self.app.cfg.hostname.clone();
        match req {
            Request::Ehlo { host } | Request::Lhlo { host } => {
                self.helo = Some(host);
                self.reset();
                let mut caps = vec![
                    hostname.clone(),
                    format!("SIZE {}", self.app.cfg.max_message_bytes),
                    "8BITMIME".to_string(),
                    "ENHANCEDSTATUSCODES".to_string(),
                ];
                if self.starttls_available && !self.tls {
                    caps.push("STARTTLS".to_string());
                }
                if self.auth_allowed() {
                    caps.push("AUTH PLAIN LOGIN".to_string());
                }
                caps.push("PIPELINING".to_string());
                let mut text = String::new();
                let last = caps.len() - 1;
                for (i, c) in caps.iter().enumerate() {
                    text.push_str(if i == last { "250 " } else { "250-" });
                    text.push_str(c);
                    text.push_str("\r\n");
                }
                reply(stream, &text).await?;
            }
            Request::Helo { host } => {
                self.helo = Some(host);
                self.reset();
                reply(stream, &format!("250 {hostname}\r\n")).await?;
            }
            Request::StartTls => {
                if self.tls {
                    reply(stream, "503 5.5.1 already using TLS\r\n").await?;
                } else if !self.starttls_available {
                    reply(stream, "454 4.7.0 TLS not available\r\n").await?;
                } else {
                    reply(stream, "220 2.0.0 ready to start TLS\r\n").await?;
                    return Ok(Action::StartTls);
                }
            }
            Request::Mail { from } => {
                if self.helo.is_none() {
                    reply(stream, "503 5.5.1 send HELO or EHLO first\r\n").await?;
                } else if self.mode == Mode::Submission && self.authenticated.is_none() {
                    reply(stream, "530 5.7.0 authentication required\r\n").await?;
                } else if self.mail_from.is_some() {
                    reply(stream, "503 5.5.1 nested MAIL command\r\n").await?;
                } else if from.size > self.app.cfg.max_message_bytes {
                    reply(stream, "552 5.3.4 message too large\r\n").await?;
                } else if !from.address.is_empty() && !crate::util::is_valid_email(&from.address) {
                    reply(stream, "501 5.1.7 bad sender address\r\n").await?;
                } else if self.mode == Mode::Submission {
                    let login = self.authenticated.clone().unwrap_or_default();
                    if crate::util::normalize_email(&from.address) != login {
                        tracing::info!(peer = %self.ip, login = %login, mail_from = %from.address, "rejected: sender does not match login");
                        reply(stream, "553 5.7.1 sender does not match login\r\n").await?;
                    } else {
                        self.mail_from = Some(login);
                        self.rcpts.clear();
                        reply(stream, "250 2.1.0 ok\r\n").await?;
                    }
                } else if let Some(zone) = self.dnsbl_listed().await {
                    tracing::info!(peer = %self.ip, zone = %zone, "rejected: listed in dnsbl");
                    reply(stream, &format!("554 5.7.1 {} is listed in {zone}\r\n", self.ip)).await?;
                } else {
                    self.mail_from = Some(from.address);
                    self.rcpts.clear();
                    reply(stream, "250 2.1.0 ok\r\n").await?;
                }
            }
            Request::Rcpt { to } => {
                if self.mail_from.is_none() {
                    reply(stream, "503 5.5.1 send MAIL first\r\n").await?;
                } else if self.rcpts.len() >= MAX_RECIPIENTS {
                    reply(stream, "452 4.5.3 too many recipients\r\n").await?;
                } else if self.mode == Mode::Submission {
                    // Relaying is the point here; the sender is who we vouch for.
                    let addr = crate::util::normalize_email(&to.address);
                    if !crate::util::is_valid_email(&addr) {
                        reply(stream, "501 5.1.3 bad recipient address\r\n").await?;
                    } else {
                        if !self.rcpts.contains(&addr) {
                            self.rcpts.push(addr);
                        }
                        reply(stream, "250 2.1.5 ok\r\n").await?;
                    }
                } else {
                    let addr = to.address;
                    match inbound::classify_recipient(&self.app, &addr) {
                        Ok(_) => {
                            let lower = crate::util::normalize_email(&addr);
                            if !self.rcpts.contains(&lower) {
                                self.rcpts.push(lower);
                            }
                            reply(stream, "250 2.1.5 ok\r\n").await?;
                        }
                        Err(r) => {
                            tracing::info!(peer = %self.ip, rcpt = %addr, reason = %r.text, "rejected recipient");
                            // A refused recipient is an error like any other:
                            // otherwise one connection can try addresses, or
                            // SRS hashes, for as long as it stays open.
                            self.errors += 1;
                            if self.errors > MAX_ERRORS {
                                reply(stream, "421 4.7.0 too many errors\r\n").await?;
                                return Ok(Action::Quit);
                            }
                            reply(stream, &format!("{} {}\r\n", r.code, r.text)).await?;
                        }
                    }
                }
            }
            Request::Data => {
                if self.mail_from.is_none() {
                    reply(stream, "503 5.5.1 send MAIL first\r\n").await?;
                } else if self.rcpts.is_empty() {
                    reply(stream, "503 5.5.1 no valid recipients\r\n").await?;
                } else {
                    reply(stream, "354 end data with <CR><LF>.<CR><LF>\r\n").await?;
                    return Ok(Action::Data);
                }
            }
            Request::Rset => {
                self.reset();
                reply(stream, "250 2.0.0 ok\r\n").await?;
            }
            Request::Noop { .. } => reply(stream, "250 2.0.0 ok\r\n").await?,
            Request::Quit => {
                reply(stream, &format!("221 2.0.0 {hostname} closing connection\r\n")).await?;
                return Ok(Action::Quit);
            }
            Request::Vrfy { .. } | Request::Expn { .. } => reply(stream, "252 2.5.2 cannot verify, try sending\r\n").await?,
            Request::Help { .. } => reply(stream, "214 2.0.0 https://github.com/pauldix/mail_sloth\r\n").await?,
            Request::Bdat { .. } => reply(stream, "503 5.5.1 CHUNKING not offered\r\n").await?,
            Request::Auth {
                mechanism,
                initial_response,
            } => {
                if self.mode != Mode::Submission {
                    reply(stream, "503 5.5.1 AUTH not offered\r\n").await?;
                } else if !self.auth_allowed() {
                    reply(stream, "538 5.7.11 encryption required for requested authentication mechanism\r\n").await?;
                } else if self.helo.is_none() {
                    reply(stream, "503 5.5.1 send EHLO first\r\n").await?;
                } else if self.authenticated.is_some() {
                    reply(stream, "503 5.5.1 already authenticated\r\n").await?;
                } else if mechanism != AUTH_PLAIN && mechanism != AUTH_LOGIN {
                    reply(stream, "504 5.5.4 mechanism not supported\r\n").await?;
                } else {
                    return Ok(Action::Auth {
                        mechanism,
                        initial: initial_response,
                    });
                }
            }
            Request::Etrn { .. } | Request::Atrn { .. } | Request::Burl { .. } => {
                reply(stream, "502 5.5.1 command not implemented\r\n").await?
            }
        }
        Ok(Action::Continue)
    }

    /// Reads the message body after DATA, dot-unstuffed. Leftover bytes
    /// after the terminator go back into `pending` for the next command.
    async fn read_data<S: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        stream: &mut S,
        pending: &mut Vec<u8>,
        buf: &mut [u8],
    ) -> Result<Option<Vec<u8>>> {
        let max = self.app.cfg.max_message_bytes;
        let mut rx = DataReceiver::new();
        let mut data = Vec::new();
        let mut too_big = false;
        let mut chunk = std::mem::take(pending);
        loop {
            let done = {
                let mut it = chunk.iter();
                let done = rx.ingest(&mut it, &mut data);
                if done {
                    *pending = it.as_slice().to_vec();
                }
                done
            };
            if data.len() > max {
                too_big = true;
                data.clear();
            }
            if done {
                break;
            }
            let n = tokio::time::timeout(IDLE_TIMEOUT, stream.read(buf))
                .await
                .context("timeout reading DATA")??;
            if n == 0 {
                bail!("connection closed during DATA");
            }
            chunk = buf[..n].to_vec();
        }
        Ok(if too_big { None } else { Some(data) })
    }

    async fn finish_message<S: AsyncRead + AsyncWrite + Unpin>(&mut self, stream: &mut S, data: Option<Vec<u8>>) -> Result<()> {
        self.messages += 1;
        let Some(raw) = data else {
            self.reset();
            reply(stream, "552 5.3.4 message too large\r\n").await?;
            return Ok(());
        };
        if self.mode == Mode::Submission {
            let sender = self.mail_from.take().unwrap_or_default();
            let rcpts = std::mem::take(&mut self.rcpts);
            let text = if !self.app.allow_submissions(&sender, rcpts.len() as u32) {
                tracing::warn!(peer = %self.ip, login = %sender, "submission cap reached");
                "452 4.5.3 too many messages from this address this hour\r\n".to_string()
            } else {
                match inbound::submit(&self.app, &sender, &rcpts, raw).await {
                    Ok(id) => format!("250 2.0.0 ok: queued as {id}\r\n"),
                    Err(r) => format!("{} {}\r\n", r.code, r.text),
                }
            };
            return reply(stream, &text).await;
        }
        let env = Envelope {
            helo: self.helo.clone().unwrap_or_default(),
            remote_ip: self.ip,
            mail_from: self.mail_from.take().unwrap_or_default(),
            rcpts: std::mem::take(&mut self.rcpts),
            tls: self.tls,
        };
        let text = match inbound::accept(&self.app, env, raw).await {
            Ok(id) => format!("250 2.0.0 ok: queued as {id}\r\n"),
            Err(r) => format!("{} {}\r\n", r.code, r.text),
        };
        reply(stream, &text).await
    }

    /// Runs one AUTH exchange. Returns true when the connection must close.
    async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        mechanism: u64,
        initial: String,
        stream: &mut S,
        pending: &mut Vec<u8>,
        buf: &mut [u8],
    ) -> Result<bool> {
        if self.app.auth_locked(self.ip) {
            reply(stream, "421 4.7.0 too many failed logins, try again later\r\n").await?;
            return Ok(true);
        }
        let decode = |s: &str| base64::engine::general_purpose::STANDARD.decode(s.trim()).ok();
        // A client line of "*" cancels the exchange (RFC 4954 §4).
        let (user, pass) = if mechanism == AUTH_PLAIN {
            let line = if initial.is_empty() {
                reply(stream, "334 \r\n").await?;
                read_line(stream, pending, buf).await?
            } else {
                initial
            };
            if line.trim() == "*" {
                reply(stream, "501 5.7.0 authentication cancelled\r\n").await?;
                return Ok(false);
            }
            let Some(bytes) = decode(&line) else {
                reply(stream, "501 5.5.2 cannot decode response\r\n").await?;
                return Ok(false);
            };
            let mut parts = bytes.split(|b| *b == 0);
            let _authzid = parts.next();
            let user = parts.next().map(|b| String::from_utf8_lossy(b).to_string());
            let pass = parts.next().map(|b| String::from_utf8_lossy(b).to_string());
            match (user, pass) {
                (Some(u), Some(p)) => (u, p),
                _ => {
                    reply(stream, "501 5.5.2 malformed PLAIN response\r\n").await?;
                    return Ok(false);
                }
            }
        } else {
            let user_line = if initial.is_empty() {
                reply(stream, "334 VXNlcm5hbWU6\r\n").await?;
                read_line(stream, pending, buf).await?
            } else {
                initial
            };
            if user_line.trim() == "*" {
                reply(stream, "501 5.7.0 authentication cancelled\r\n").await?;
                return Ok(false);
            }
            reply(stream, "334 UGFzc3dvcmQ6\r\n").await?;
            let pass_line = read_line(stream, pending, buf).await?;
            if pass_line.trim() == "*" {
                reply(stream, "501 5.7.0 authentication cancelled\r\n").await?;
                return Ok(false);
            }
            match (decode(&user_line), decode(&pass_line)) {
                (Some(u), Some(p)) => (String::from_utf8_lossy(&u).to_string(), String::from_utf8_lossy(&p).to_string()),
                _ => {
                    reply(stream, "501 5.5.2 cannot decode response\r\n").await?;
                    return Ok(false);
                }
            }
        };
        match self.app.cfg.verify_password(&user, &pass) {
            Some(addr) => {
                tracing::info!(peer = %self.ip, login = %addr, "authenticated");
                self.app.clear_auth_failures(self.ip);
                self.authenticated = Some(addr);
                reply(stream, "235 2.7.0 authentication successful\r\n").await?;
                Ok(false)
            }
            None => {
                let locked = self.app.record_auth_failure(self.ip);
                tracing::warn!(peer = %self.ip, user = %user, locked, "authentication failed");
                self.errors += 1;
                if locked {
                    reply(stream, "421 4.7.0 too many failed logins, try again later\r\n").await?;
                    return Ok(true);
                }
                reply(stream, "535 5.7.8 authentication failed\r\n").await?;
                Ok(false)
            }
        }
    }

    async fn dnsbl_listed(&mut self) -> Option<String> {
        if let Some(cached) = &self.dnsbl {
            return cached.clone();
        }
        let result = match self.ip {
            IpAddr::V4(v4) if !self.app.cfg.dnsbl.is_empty() && !v4.is_private() && !v4.is_loopback() => {
                let o = v4.octets();
                let mut listed = None;
                for zone in &self.app.cfg.dnsbl {
                    let name = format!("{}.{}.{}.{}.{zone}", o[3], o[2], o[1], o[0]);
                    if let Ok(set) = self
                        .app
                        .resolver
                        .ipv4_lookup(&name, None::<&NoCache<Box<str>, mail_auth::RecordSet<std::net::Ipv4Addr>>>)
                        .await
                    {
                        // 127.0.0.x means listed; 127.255.x.x is the zone
                        // saying our query was refused, which is not a verdict.
                        if set.rrset.iter().any(|ip| ip.octets()[0] == 127 && ip.octets()[1] == 0) {
                            listed = Some(zone.clone());
                            break;
                        }
                    }
                }
                listed
            }
            _ => None,
        };
        self.dnsbl = Some(result.clone());
        result
    }
}

/// One line of an AUTH continuation. Bytes after it stay in `pending`.
async fn read_line<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, pending: &mut Vec<u8>, buf: &mut [u8]) -> Result<String> {
    loop {
        if let Some(i) = pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = pending.drain(..=i).collect();
            return Ok(String::from_utf8_lossy(&line).trim_end_matches(['\r', '\n']).to_string());
        }
        if pending.len() > 8192 {
            bail!("auth line too long");
        }
        let n = tokio::time::timeout(IDLE_TIMEOUT, stream.read(buf))
            .await
            .context("idle timeout")??;
        if n == 0 {
            bail!("connection closed during AUTH");
        }
        pending.extend_from_slice(&buf[..n]);
    }
}

async fn reply<S: AsyncWrite + Unpin>(stream: &mut S, text: &str) -> Result<()> {
    stream.write_all(text.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}
