//! mail_sloth: a small mail server with a REST API.
//!
//! `serve` runs everything. The other subcommands set a host up: make keys,
//! print the DNS records, check them, and send a test message.

mod api;
mod app;
mod config;
mod db;
mod deliver;
mod dkim;
mod inbound;
mod message;
mod smtpd;
mod srs;
mod tls;
mod util;
mod webhook;

#[cfg(test)]
mod e2e_tests;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use mail_auth::MessageAuthenticator;

use crate::config::Config;

#[derive(Parser)]
#[command(name = "mail_sloth", version, about = "A small mail server with a REST API")]
struct Cli {
    /// Path to the config file.
    #[arg(long, global = true, env = "MAIL_SLOTH_CONFIG", default_value = "/etc/mail_sloth/config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the mail server and API.
    Serve,
    /// Print a new API key and the sha256 to put in the config.
    Key,
    /// Print a random secret for `srs_secret` or `webhook_secret`.
    Secret,
    /// Print a new submission password and the line to put on the sender.
    Password,
    /// Create the DKIM key for a domain if it has none and print its DNS record.
    Dkim { domain: String },
    /// Print every DNS record the config needs, for one domain or all.
    Dns { domain: Option<String> },
    /// Look up the DNS records and say which are missing or wrong.
    Check,
    /// Send a message through a running server.
    Send {
        /// Base URL of the server, e.g. https://mail.example.com
        #[arg(long)]
        url: String,
        #[arg(long, env = "MAIL_SLOTH_API_KEY")]
        api_key: String,
        #[arg(long)]
        from: String,
        #[arg(long, required = true)]
        to: Vec<String>,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        html: Option<String>,
    },
}

fn main() -> Result<()> {
    // `mail_sloth dns | head` must not panic when head closes the pipe.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,hickory_resolver=warn,hickory_proto=warn,rustls=warn,h2=warn".into()),
        )
        .with_target(false)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        match cli.cmd {
            Cmd::Serve => serve(&cli.config).await,
            Cmd::Key => {
                let key = format!("ms_{}", util::hex(&util::random_bytes::<32>()));
                println!("API key (give this to the site, it is not stored anywhere):\n  {key}\n");
                println!(
                    "Add to the site's [[site]] block in the config:\n  api_keys = [\"{}\"]",
                    util::sha256_hex(key.as_bytes())
                );
                Ok(())
            }
            Cmd::Secret => {
                println!("{}", util::hex(&util::random_bytes::<32>()));
                Ok(())
            }
            Cmd::Password => {
                const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
                let mut rng = rand::rng();
                let password: String = (0..24)
                    .map(|_| ALPHABET[rand::Rng::random_range(&mut rng, 0..ALPHABET.len())] as char)
                    .collect();
                println!("Password (type it into Gmail's \"Send mail as\" dialog, it is not stored anywhere):\n  {password}\n");
                println!(
                    "Add to the address's entry under [domain.senders] in the config:\n  password = \"sha256:{}\"",
                    util::sha256_hex(password.as_bytes())
                );
                Ok(())
            }
            Cmd::Dkim { domain } => dkim_cmd(&cli.config, &domain),
            Cmd::Dns { domain } => dns_cmd(&cli.config, domain.as_deref()),
            Cmd::Check => check_cmd(&cli.config).await,
            Cmd::Send {
                url,
                api_key,
                from,
                to,
                subject,
                text,
                html,
            } => send_cmd(&url, &api_key, &from, &to, &subject, text, html).await,
        }
    })
}

async fn serve(config_path: &std::path::Path) -> Result<()> {
    tls::install_crypto_provider();
    let cfg = Config::load(config_path)?;
    std::fs::create_dir_all(&cfg.data_dir).with_context(|| format!("creating {}", cfg.data_dir.display()))?;
    let db = db::Db::open(&cfg.db_path()).await?;
    let requeued = db.recover().await?;
    if requeued > 0 {
        tracing::info!(requeued, "messages left in flight by the last run were requeued");
    }
    let dkim = dkim::DkimKeys::load(&cfg)?;
    let resolver = MessageAuthenticator::new_system_conf().context("dns resolver from system config")?;
    let tls_setup = if cfg.tls { Some(tls::setup(&cfg)?) } else { None };
    let http_addr: SocketAddr = cfg.http_listen.parse().context("http_listen is not host:port")?;
    let app = app::App::new(cfg, db, dkim, resolver);

    let router = api::router(app.clone());
    let http = tokio::spawn({
        let acceptor = tls_setup.as_ref().map(|t| t.axum.clone());
        async move {
            let r = match acceptor {
                Some(acceptor) => {
                    tracing::info!(addr = %http_addr, "https listening");
                    axum_server::bind(http_addr)
                        .acceptor(acceptor)
                        .serve(router.into_make_service())
                        .await
                }
                None => {
                    tracing::warn!(addr = %http_addr, "http listening WITHOUT tls");
                    axum_server::bind(http_addr).serve(router.into_make_service()).await
                }
            };
            if let Err(e) = r {
                tracing::error!(error = %e, "http server stopped");
            }
        }
    });
    let submission_acceptor = match (&tls_setup, &app.cfg.submission_listen) {
        (Some(t), Some(_)) => Some(t.smtp.clone()),
        _ => None,
    };
    let smtp = tokio::spawn({
        let app = app.clone();
        let acceptor = tls_setup.map(|t| t.smtp);
        async move {
            if let Err(e) = smtpd::run(app, acceptor).await {
                tracing::error!(error = %e, "smtp server stopped");
            }
        }
    });
    if let Some(acceptor) = submission_acceptor {
        tokio::spawn({
            let app = app.clone();
            async move {
                if let Err(e) = smtpd::run_submission(app, acceptor).await {
                    tracing::error!(error = %e, "submission server stopped");
                }
            }
        });
    }
    tokio::spawn(deliver::run(app.clone()));
    tokio::spawn(webhook::run(app.clone()));
    tokio::spawn(deliver::run_cleanup(app.clone()));
    tracing::info!(hostname = %app.cfg.hostname, domains = ?app.cfg.domains.iter().map(|d| &d.name).collect::<Vec<_>>(), "mail_sloth up");

    let shutdown = async {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("sigterm handler");
            tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
        }
    };
    tokio::select! {
        _ = shutdown => tracing::info!("shutting down"),
        _ = http => tracing::error!("http task ended"),
        _ = smtp => tracing::error!("smtp task ended"),
    }
    Ok(())
}

fn dkim_cmd(config_path: &std::path::Path, domain: &str) -> Result<()> {
    let cfg = Config::load(config_path)?;
    let d = cfg
        .domain(domain)
        .with_context(|| format!("{domain} is not a [[domain]] in the config"))?;
    let selector = cfg.selector_for(d);
    let path = dkim::key_path(&cfg, domain, selector);
    if dkim::generate_if_missing(&path)? {
        println!("generated {}", path.display());
    } else {
        println!("using existing {}", path.display());
    }
    println!("\nPublish this TXT record (one string; most DNS UIs split it for you):\n");
    println!("{selector}._domainkey.{domain}.  TXT  \"{}\"", dkim::dns_record(&path)?);
    Ok(())
}

fn spf_value(cfg: &Config) -> String {
    match &cfg.public_ip {
        Some(ip) => format!("v=spf1 ip4:{ip} -all"),
        None => format!("v=spf1 a:{} -all", cfg.hostname),
    }
}

fn dns_cmd(config_path: &std::path::Path, only: Option<&str>) -> Result<()> {
    let cfg = Config::load(config_path)?;
    println!("; ---- the mail host itself ----");
    match &cfg.public_ip {
        Some(ip) => {
            println!("{}.  A  {ip}", cfg.hostname);
            println!("; and at the hosting provider: PTR {ip} -> {}", cfg.hostname);
        }
        None => println!("{}.  A  <public ip>   ; set public_ip in the config to fill this in", cfg.hostname),
    }
    for d in &cfg.domains {
        if only.is_some_and(|o| o != d.name) {
            continue;
        }
        let selector = cfg.selector_for(d);
        println!("\n; ---- {} ----", d.name);
        println!("{}.  MX  10 {}.", d.name, cfg.hostname);
        println!("{}.  TXT  \"{}\"", d.name, spf_value(&cfg));
        let path = dkim::key_path(&cfg, &d.name, selector);
        match dkim::dns_record(&path) {
            Ok(rec) => println!("{selector}._domainkey.{}.  TXT  \"{rec}\"", d.name),
            Err(_) => println!("{selector}._domainkey.{}.  TXT  ; run `mail_sloth dkim {}` first", d.name, d.name),
        }
        let rua = cfg.acme_contact.clone().unwrap_or_else(|| format!("postmaster@{}", d.name));
        println!("_dmarc.{}.  TXT  \"v=DMARC1; p=none; rua=mailto:{rua}\"", d.name);
    }
    Ok(())
}

async fn check_cmd(config_path: &std::path::Path) -> Result<()> {
    use mail_auth::common::cache::NoCache;
    let cfg = Config::load(config_path)?;
    let resolver = MessageAuthenticator::new_system_conf().context("dns resolver")?;
    let mut problems = 0usize;
    let mut report = |ok: bool, what: String| {
        println!("{} {what}", if ok { "ok     " } else { "MISSING" });
        if !ok {
            problems += 1;
        }
    };
    let txt = |name: String| {
        let resolver = &resolver;
        async move {
            resolver
                .txt_raw_lookup(name.as_str())
                .await
                .ok()
                .map(|b| String::from_utf8_lossy(&b).to_string())
                .unwrap_or_default()
        }
    };

    // The host.
    let a = resolver
        .ipv4_lookup(&cfg.hostname, None::<&NoCache<Box<str>, mail_auth::RecordSet<std::net::Ipv4Addr>>>)
        .await
        .ok()
        .map(|s| s.rrset.iter().map(|ip| ip.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();
    match &cfg.public_ip {
        Some(ip) => {
            report(a.contains(ip), format!("A {} -> {ip} (found {:?})", cfg.hostname, a));
            let ptr = match ip.parse::<std::net::IpAddr>() {
                Ok(ip) => resolver
                    .ptr_lookup(ip, None::<&NoCache<std::net::IpAddr, mail_auth::RecordSet<Box<str>>>>)
                    .await
                    .ok()
                    .map(|s| s.rrset.iter().map(|n| n.trim_end_matches('.').to_string()).collect::<Vec<_>>())
                    .unwrap_or_default(),
                Err(_) => Vec::new(),
            };
            report(
                ptr.iter().any(|n| n == &cfg.hostname),
                format!("PTR {ip} -> {} (found {:?})", cfg.hostname, ptr),
            );
        }
        None => report(
            !a.is_empty(),
            format!("A {} (found {:?}); set public_ip to check the PTR too", cfg.hostname, a),
        ),
    }

    for d in &cfg.domains {
        let selector = cfg.selector_for(d);
        let mx = resolver
            .mx_lookup(d.name.as_str(), None::<&NoCache<Box<str>, mail_auth::RecordSet<mail_auth::MX>>>)
            .await
            .ok()
            .map(|s| {
                s.rrset
                    .iter()
                    .flat_map(|m| m.exchanges.iter().map(|e| e.trim_end_matches('.').to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let receives_here = !d.forward.is_empty() || d.inbound_webhook;
        if receives_here {
            report(
                mx.iter().any(|m| m == &cfg.hostname),
                format!("MX {} -> {} (found {:?})", d.name, cfg.hostname, mx),
            );
        } else {
            // No forward rules and no inbound webhook: this domain only
            // sends from here, so its MX is somebody else's business.
            println!("skip    MX {} stays at {:?}; add forward rules to receive here", d.name, mx);
        }

        let spf = txt(d.name.clone()).await;
        let spf_ok = spf.contains("v=spf1") && (cfg.public_ip.as_ref().is_some_and(|ip| spf.contains(ip)) || spf.contains(&cfg.hostname));
        report(
            spf_ok,
            format!(
                "SPF {} (found {:?}); want {:?}",
                d.name,
                spf.replace("\r\n", " ").trim(),
                spf_value(&cfg)
            ),
        );

        let dkim_name = format!("{selector}._domainkey.{}", d.name);
        let found = txt(dkim_name.clone()).await;
        let want = dkim::dns_record(&dkim::key_path(&cfg, &d.name, selector)).unwrap_or_default();
        let strip = |s: &str| s.chars().filter(|c| !c.is_whitespace() && *c != '"').collect::<String>();
        let dkim_ok = !want.is_empty() && strip(&found).contains(&strip(want.split("p=").nth(1).unwrap_or("")));
        report(
            dkim_ok,
            format!(
                "DKIM {dkim_name} {}",
                if want.is_empty() {
                    "(no local key; run `mail_sloth dkim`)"
                } else if found.is_empty() {
                    "(no record)"
                } else {
                    ""
                }
            ),
        );

        let dmarc = txt(format!("_dmarc.{}", d.name)).await;
        report(
            dmarc.contains("v=DMARC1"),
            format!("DMARC _dmarc.{} (found {:?})", d.name, dmarc.trim()),
        );
    }

    print!("       outbound port 25 to gmail-smtp-in.l.google.com ... ");
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect("gmail-smtp-in.l.google.com:25"),
    )
    .await
    {
        Ok(Ok(_)) => println!("open"),
        Ok(Err(e)) => {
            println!("BLOCKED ({e})");
            problems += 1;
        }
        Err(_) => {
            println!("BLOCKED (timed out; the host or provider is filtering port 25)");
            problems += 1;
        }
    }
    if problems > 0 {
        bail!("{problems} problem(s) found");
    }
    println!("all good");
    Ok(())
}

async fn send_cmd(
    url: &str,
    api_key: &str,
    from: &str,
    to: &[String],
    subject: &str,
    text: Option<String>,
    html: Option<String>,
) -> Result<()> {
    let text = text.or_else(|| html.is_none().then(|| format!("Test message from mail_sloth at {}", util::now())));
    let body = serde_json::json!({ "from": from, "to": to, "subject": subject, "text": text, "html": html });
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/send", url.trim_end_matches('/')))
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .context("calling the server")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    println!("{status}\n{text}");
    if !status.is_success() {
        bail!("send failed");
    }
    Ok(())
}
