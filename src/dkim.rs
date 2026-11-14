//! DKIM keys: generation, loading, signing, and the DNS record to publish.
//!
//! One RSA-2048 key per domain, kept as a PEM file under `data_dir/dkim/`.
//! RSA rather than Ed25519 because Gmail still does not verify Ed25519
//! signatures, and Gmail is most of the list.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use base64::Engine;
use mail_auth::arc::ArcSealer;
use mail_auth::common::crypto::{RsaKey, Sha256};
use mail_auth::common::headers::HeaderWriter;
use mail_auth::dkim::{DkimSigner, Done};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer};

use crate::config::Config;

/// Headers covered by our signature. Everything a receiver uses to decide
/// what the message is, plus the two unsubscribe headers so nobody can strip
/// them on the way without breaking the signature.
const SIGNED_HEADERS: [&str; 15] = [
    "From",
    "To",
    "Cc",
    "Reply-To",
    "Subject",
    "Date",
    "Message-ID",
    "In-Reply-To",
    "References",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
    "List-Unsubscribe",
    "List-Unsubscribe-Post",
    "Sender",
];

pub struct DomainKeys {
    pub signer: DkimSigner<RsaKey<Sha256>, Done>,
    pub sealer: ArcSealer<RsaKey<Sha256>, Done>,
}

/// Every domain's loaded keys. A domain without a key file is absent, and
/// sending from it fails with a message that says to run `mail_sloth dkim`.
pub struct DkimKeys {
    keys: HashMap<String, Arc<DomainKeys>>,
}

pub fn key_path(cfg: &Config, domain: &str, selector: &str) -> PathBuf {
    cfg.dkim_dir().join(format!("{domain}.{selector}.pem"))
}

impl DkimKeys {
    pub fn load(cfg: &Config) -> Result<DkimKeys> {
        let mut keys = HashMap::new();
        for d in &cfg.domains {
            let selector = cfg.selector_for(d);
            let path = key_path(cfg, &d.name, selector);
            if !path.exists() {
                tracing::warn!(domain = %d.name, path = %path.display(),
                    "no DKIM key; run `mail_sloth dkim {}` before sending from it", d.name);
                continue;
            }
            let pem = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            let signer = DkimSigner::from_key(load_key(&pem).with_context(|| format!("parsing {}", path.display()))?)
                .domain(d.name.clone())
                .selector(selector.to_string())
                .headers(SIGNED_HEADERS);
            let sealer = ArcSealer::from_key(load_key(&pem)?)
                .domain(d.name.clone())
                .selector(selector.to_string())
                .headers(SIGNED_HEADERS);
            keys.insert(d.name.clone(), Arc::new(DomainKeys { signer, sealer }));
        }
        Ok(DkimKeys { keys })
    }

    pub fn get(&self, domain: &str) -> Option<Arc<DomainKeys>> {
        self.keys.get(domain).cloned()
    }

    /// The message with a DKIM-Signature header prepended.
    pub fn sign(&self, domain: &str, raw: &[u8]) -> Result<Vec<u8>> {
        let Some(keys) = self.keys.get(domain) else {
            bail!("no DKIM key for {domain}; run `mail_sloth dkim {domain}`");
        };
        let signature = keys.signer.sign(raw).map_err(|e| anyhow::anyhow!("DKIM signing: {e}"))?;
        let mut out = Vec::with_capacity(raw.len() + 512);
        signature.write_header(&mut out);
        out.extend_from_slice(raw);
        Ok(out)
    }
}

/// Generates a key if there is none yet and returns the TXT record value.
pub fn generate_if_missing(path: &Path) -> Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    let pair = mail_auth::dkim::generate::DkimKeyPair::generate_rsa(2048).map_err(|e| anyhow::anyhow!("generating key: {e}"))?;
    let pem = to_pem("RSA PRIVATE KEY", pair.private_key());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    write_private(path, pem.as_bytes())?;
    Ok(true)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}

/// `v=DKIM1; k=rsa; p=...` for the key at `path`.
pub fn dns_record(path: &Path) -> Result<String> {
    let pem = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let key = load_key(&pem)?;
    let pkcs1 = key.public_key();
    let spki = wrap_spki(&pkcs1);
    Ok(format!(
        "v=DKIM1; k=rsa; p={}",
        base64::engine::general_purpose::STANDARD.encode(spki)
    ))
}

/// A PKCS#1 `RSA PRIVATE KEY` PEM file as a signing key.
fn load_key(pem: &str) -> Result<RsaKey<Sha256>> {
    let der = from_pem(pem, "RSA PRIVATE KEY")?;
    RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der))).map_err(|e| anyhow::anyhow!("loading RSA key: {e}"))
}

fn from_pem(pem: &str, label: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem.find(&begin).with_context(|| format!("no {begin} in key file"))? + begin.len();
    let stop = pem[start..].find(&end).with_context(|| format!("no {end} in key file"))? + start;
    let b64: String = pem[start..stop].chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("key file is not valid base64")
}

fn to_pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Wraps a PKCS#1 RSAPublicKey in a SubjectPublicKeyInfo, which is the
/// encoding every DKIM verifier expects in `p=`. mail-auth would accept the
/// bare PKCS#1 too, but Gmail does not.
fn wrap_spki(pkcs1: &[u8]) -> Vec<u8> {
    const RSA_ALG_ID: [u8; 15] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut bitstring = vec![0x03];
    der_len(&mut bitstring, pkcs1.len() + 1);
    bitstring.push(0x00);
    bitstring.extend_from_slice(pkcs1);
    let mut body = RSA_ALG_ID.to_vec();
    body.extend_from_slice(&bitstring);
    let mut out = vec![0x30];
    der_len(&mut out, body.len());
    out.extend_from_slice(&body);
    out
}

fn der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tempdir::Dir;

    #[test]
    fn spki_wrapping_matches_openssl_layout() {
        // A 2048-bit PKCS#1 key is 270 bytes; SPKI adds 24 bytes of framing
        // and every real-world DKIM record starts with this prefix.
        let pkcs1 = vec![0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00];
        let fake = [pkcs1.clone(), vec![0xaa; 270 - pkcs1.len()]].concat();
        let spki = wrap_spki(&fake);
        assert_eq!(spki.len(), 294);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&spki);
        assert!(b64.starts_with("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"));
    }

    #[test]
    fn generate_load_sign_roundtrip() {
        let dir = Dir::new("dkim");
        let path = dir.path.join("dkim").join("example.com.sloth.pem");
        assert!(generate_if_missing(&path).unwrap());
        assert!(!generate_if_missing(&path).unwrap());
        let record = dns_record(&path).unwrap();
        assert!(record.starts_with("v=DKIM1; k=rsa; p=MIIBIjAN"));

        let cfg = Config::parse(&format!(
            r#"
hostname = "mail.example.com"
tls = false
data_dir = "{}"
[[site]]
name = "s"
domains = ["example.com"]
[[domain]]
name = "example.com"
"#,
            dir.path.display()
        ))
        .unwrap();
        let keys = DkimKeys::load(&cfg).unwrap();
        let raw = b"From: a@example.com\r\nTo: b@example.org\r\nSubject: hi\r\nDate: Tue, 9 Sep 2026 10:00:00 +0000\r\nMessage-ID: <x@example.com>\r\n\r\nhello\r\n";
        let signed = keys.sign("example.com", raw).unwrap();
        let text = String::from_utf8_lossy(&signed);
        assert!(text.starts_with("DKIM-Signature: v=1; a=rsa-sha256;"));
        assert!(text.contains("d=example.com;"));
        assert!(text.contains("s=sloth;"));
        assert!(text.ends_with("hello\r\n"));
        assert!(keys.sign("other.com", raw).is_err());
    }
}
