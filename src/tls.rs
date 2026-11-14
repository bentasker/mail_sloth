//! Certificates from Let's Encrypt, shared by the HTTPS API and STARTTLS.
//!
//! The TLS-ALPN-01 challenge is answered on the API port, so nothing needs
//! port 80. rustls-acme keeps the certificate fresh in the background and
//! both listeners read it through the same resolver.

use anyhow::{Context, Result};
use futures_util::StreamExt;
use rustls_acme::axum::AxumAcceptor;
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;
use tokio_rustls::TlsAcceptor;

use crate::config::Config;

pub struct Tls {
    pub smtp: TlsAcceptor,
    pub axum: AxumAcceptor,
}

pub fn setup(cfg: &Config) -> Result<Tls> {
    let contact = cfg.acme_contact.as_deref().context("acme_contact is required for tls")?;
    std::fs::create_dir_all(cfg.acme_dir()).context("creating the acme cache dir")?;
    let mut state = AcmeConfig::new([cfg.hostname.clone()])
        .contact_push(format!("mailto:{contact}"))
        .cache(DirCache::new(cfg.acme_dir()))
        .directory_lets_encrypt(cfg.acme_production)
        .state();
    let server_config = state.default_rustls_config();
    let axum = state.axum_acceptor(server_config.clone());
    if !cfg.acme_production {
        tracing::warn!("using the Let's Encrypt STAGING directory; certificates will not be trusted");
    }
    tokio::spawn(async move {
        loop {
            match state.next().await {
                Some(Ok(ev)) => tracing::info!(event = ?ev, "acme"),
                Some(Err(e)) => tracing::error!(error = %e, "acme"),
                None => break,
            }
        }
    });
    Ok(Tls {
        smtp: TlsAcceptor::from(server_config),
        axum,
    })
}

/// Ring is the only provider compiled in, but rustls still wants one named
/// as the process default before the first handshake.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
