//! The TOML config file: hostname, listeners, sites, domains, routing.
//!
//! Everything that is a decision rather than data lives here, not in the
//! database: which domains exist, who may send from them, where their inbound
//! mail goes, and which API keys are valid. The file is root-only on the
//! server and is the whole story of how the host is set up.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The mail host's own name: HELO, PTR target, MX target, API host.
    pub hostname: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_http_listen")]
    pub http_listen: String,
    #[serde(default = "default_smtp_listen")]
    pub smtp_listen: String,
    /// Authenticated submission over implicit TLS, e.g. `"0.0.0.0:465"`,
    /// for Gmail's "Send mail as". Off when unset. Needs `tls`.
    pub submission_listen: Option<String>,
    /// Off means plain HTTP and no STARTTLS. Only for running locally.
    #[serde(default = "default_true")]
    pub tls: bool,
    /// Let's Encrypt account contact. Required when `tls` is on.
    pub acme_contact: Option<String>,
    /// Off means the Let's Encrypt staging directory: untrusted certs, no rate limits.
    #[serde(default = "default_true")]
    pub acme_production: bool,
    /// Public IPv4 of this host, used only to print DNS records and check them.
    pub public_ip: Option<String>,
    #[serde(default = "default_rate")]
    pub send_rate_per_second: u32,
    #[serde(default = "default_max_bytes")]
    pub max_message_bytes: usize,
    /// DNS blocklists checked at MAIL FROM, e.g. `["zen.spamhaus.org"]`.
    #[serde(default)]
    pub dnsbl: Vec<String>,
    /// Secret for SRS envelope rewriting. Required if any domain forwards.
    pub srs_secret: Option<String>,
    #[serde(default = "default_selector")]
    pub dkim_selector: String,
    /// Development only: deliver everything to this `host:port` instead of
    /// the recipient's real MX. Point it at your own SMTP listener.
    pub mx_override: Option<String>,
    #[serde(default, rename = "site")]
    pub sites: Vec<Site>,
    #[serde(default, rename = "domain")]
    pub domains: Vec<Domain>,
}

/// One calling application. A site owns domains and holds API keys.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    pub name: String,
    /// SHA-256 hex of each valid key. `mail_sloth key` prints a pair.
    #[serde(default)]
    pub api_keys: Vec<String>,
    /// Where delivery events and inbound mail are POSTed. Optional.
    pub webhook_url: Option<String>,
    /// HMAC key for the `X-Sloth-Signature` header. Required with `webhook_url`.
    pub webhook_secret: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Domain {
    pub name: String,
    /// Overrides the global selector for this domain.
    pub dkim_selector: Option<String>,
    /// Local part -> display name and default Reply-To for outgoing mail.
    #[serde(default)]
    pub senders: BTreeMap<String, Sender>,
    /// Local part -> addresses inbound mail is forwarded to. `"*"` is a catch-all.
    /// An empty list keeps the mail here without forwarding it.
    #[serde(default)]
    pub forward: BTreeMap<String, Vec<String>>,
    /// POST every accepted inbound message to the owning site's webhook.
    #[serde(default)]
    pub inbound_webhook: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Sender {
    pub name: Option<String>,
    pub reply_to: Option<String>,
    /// `sha256:<hex>` of the submission password; `mail_sloth password`
    /// prints a pair. Without one the address cannot log in.
    pub password: Option<String>,
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/mail_sloth")
}
fn default_http_listen() -> String {
    "0.0.0.0:443".into()
}
fn default_smtp_listen() -> String {
    "0.0.0.0:25".into()
}
fn default_true() -> bool {
    true
}
fn default_rate() -> u32 {
    1
}
fn default_max_bytes() -> usize {
    25 * 1024 * 1024
}
fn default_selector() -> String {
    "sloth".into()
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config = toml::from_str(&text).context("parsing config")?;
        cfg.validate()?;
        Ok(cfg)
    }

    #[cfg(test)]
    pub fn parse(text: &str) -> Result<Config> {
        let cfg: Config = toml::from_str(text).context("parsing config")?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.hostname.trim().is_empty() || !self.hostname.contains('.') {
            bail!("hostname must be a fully qualified name like mail.example.com");
        }
        if self.tls && self.acme_contact.as_deref().unwrap_or("").is_empty() {
            bail!("acme_contact is required when tls is on");
        }
        if self.send_rate_per_second == 0 {
            bail!("send_rate_per_second must be at least 1");
        }
        if self.submission_listen.is_some() && !self.tls {
            bail!("submission_listen needs tls = true; passwords never cross the wire in the clear");
        }
        let mut seen = std::collections::HashSet::new();
        for d in &self.domains {
            if d.name != d.name.to_ascii_lowercase() || d.name.trim().is_empty() {
                bail!("domain names must be lowercase: {}", d.name);
            }
            if !seen.insert(d.name.clone()) {
                bail!("domain {} is listed twice", d.name);
            }
            let owners = self.sites.iter().filter(|s| s.domains.contains(&d.name)).count();
            if owners != 1 {
                bail!("domain {} must belong to exactly one site (found {owners})", d.name);
            }
            if d.forward.values().any(|t| !t.is_empty()) && self.srs_secret.as_deref().unwrap_or("").len() < 16 {
                bail!(
                    "srs_secret (at least 16 chars) is required because {} forwards mail; `mail_sloth secret` makes one",
                    d.name
                );
            }
            for (local, targets) in &d.forward {
                for t in targets {
                    if !crate::util::is_valid_email(t) {
                        bail!("forward target {t} for {local}@{} is not an address", d.name);
                    }
                }
            }
            for (local, s) in &d.senders {
                if let Some(r) = &s.reply_to {
                    if !crate::util::is_valid_email(r) {
                        bail!("reply_to {r} for {local}@{} is not an address", d.name);
                    }
                }
                if let Some(p) = &s.password {
                    let hex = p.strip_prefix("sha256:").unwrap_or("");
                    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        bail!(
                            "password for {local}@{} must be sha256:<hex>; `mail_sloth password` prints one",
                            d.name
                        );
                    }
                }
            }
        }
        let mut names = std::collections::HashSet::new();
        for s in &self.sites {
            if !names.insert(s.name.clone()) {
                bail!("site {} is listed twice", s.name);
            }
            for d in &s.domains {
                if !self.domains.iter().any(|x| &x.name == d) {
                    bail!("site {} lists domain {d} which has no [[domain]] block", s.name);
                }
            }
            if s.webhook_url.is_some() && s.webhook_secret.as_deref().unwrap_or("").len() < 16 {
                bail!("site {} has a webhook_url but no webhook_secret (at least 16 chars)", s.name);
            }
            for k in &s.api_keys {
                if k.len() != 64 || !k.chars().all(|c| c.is_ascii_hexdigit()) {
                    bail!(
                        "site {} has an api key that is not a sha256 hex digest; `mail_sloth key` prints one",
                        s.name
                    );
                }
            }
        }
        Ok(())
    }

    pub fn domain(&self, name: &str) -> Option<&Domain> {
        self.domains.iter().find(|d| d.name == name)
    }

    pub fn site(&self, name: &str) -> Option<&Site> {
        self.sites.iter().find(|s| s.name == name)
    }

    pub fn site_for_domain(&self, domain: &str) -> Option<&Site> {
        self.sites.iter().find(|s| s.domains.iter().any(|d| d == domain))
    }

    /// The address a username and password log in as, if they are right.
    /// Every failure takes the same path so a wrong user and a wrong
    /// password are not told apart by timing.
    pub fn verify_password(&self, username: &str, password: &str) -> Option<String> {
        use subtle::ConstantTimeEq;
        let addr = crate::util::normalize_email(username);
        let stored = crate::util::split_email(&addr)
            .and_then(|(local, domain)| self.domain(domain)?.sender(local)?.password.clone())
            .and_then(|p| p.strip_prefix("sha256:").map(str::to_ascii_lowercase))
            .unwrap_or_else(|| "0".repeat(64));
        let given = crate::util::sha256_hex(password.as_bytes());
        if given.as_bytes().ct_eq(stored.as_bytes()).into() {
            Some(addr)
        } else {
            None
        }
    }

    pub fn selector_for<'a>(&'a self, domain: &'a Domain) -> &'a str {
        domain.dkim_selector.as_deref().unwrap_or(&self.dkim_selector)
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("mail_sloth.db")
    }

    pub fn dkim_dir(&self) -> PathBuf {
        self.data_dir.join("dkim")
    }

    pub fn acme_dir(&self) -> PathBuf {
        self.data_dir.join("acme")
    }
}

impl Domain {
    /// Forward targets for a local part: an exact rule, else the catch-all.
    pub fn forward_targets(&self, local: &str) -> Option<&Vec<String>> {
        let local = local.to_ascii_lowercase();
        self.forward
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == local)
            .or_else(|| self.forward.iter().find(|(k, _)| k.as_str() == "*"))
            .map(|(_, v)| v)
    }

    pub fn sender(&self, local: &str) -> Option<&Sender> {
        let local = local.to_ascii_lowercase();
        self.senders.iter().find(|(k, _)| k.to_ascii_lowercase() == local).map(|(_, v)| v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
hostname = "mail.example.com"
acme_contact = "me@example.com"
srs_secret = "0123456789abcdef0123456789abcdef"

[[site]]
name = "party"
api_keys = ["0000000000000000000000000000000000000000000000000000000000000000"]
webhook_url = "https://party.example.com/mail"
webhook_secret = "0123456789abcdef0123456789abcdef"
domains = ["party.example.com"]

[[domain]]
name = "party.example.com"
inbound_webhook = true
[domain.senders]
paul = { name = "Paul", reply_to = "paul@gmail.example", password = "sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" }
[domain.forward]
paul = ["paul@gmail.example"]
"*" = ["catch@gmail.example"]
"#;

    #[test]
    fn a_good_config_parses_and_routes() {
        let cfg = Config::parse(GOOD).unwrap();
        let d = cfg.domain("party.example.com").unwrap();
        assert_eq!(d.forward_targets("Paul").unwrap()[0], "paul@gmail.example");
        assert_eq!(d.forward_targets("nobody").unwrap()[0], "catch@gmail.example");
        assert_eq!(cfg.site_for_domain("party.example.com").unwrap().name, "party");
        assert_eq!(cfg.selector_for(d), "sloth");
        assert_eq!(d.sender("PAUL").unwrap().name.as_deref(), Some("Paul"));
    }

    #[test]
    fn a_domain_needs_exactly_one_site() {
        let bad = GOOD.replace("domains = [\"party.example.com\"]", "domains = []");
        assert!(Config::parse(&bad).unwrap_err().to_string().contains("exactly one site"));
    }

    #[test]
    fn forwarding_needs_an_srs_secret() {
        let bad = GOOD.replace("srs_secret = \"0123456789abcdef0123456789abcdef\"", "");
        assert!(Config::parse(&bad).unwrap_err().to_string().contains("srs_secret"));
    }

    #[test]
    fn an_empty_forward_list_keeps_mail_here() {
        let cfg = Config::parse(&GOOD.replace("[domain.forward]\n", "[domain.forward]\ndmarc = []\n")).unwrap();
        let d = cfg.domain("party.example.com").unwrap();
        assert!(d.forward_targets("dmarc").unwrap().is_empty(), "the catch-all does not take it");
        // Keeping mail forwards nothing, so it needs no SRS secret.
        let keep_only = GOOD
            .replace("srs_secret = \"0123456789abcdef0123456789abcdef\"", "")
            .replace("paul = [\"paul@gmail.example\"]\n\"*\" = [\"catch@gmail.example\"]", "dmarc = []");
        Config::parse(&keep_only).unwrap();
    }

    #[test]
    fn passwords_verify_by_full_address() {
        let cfg = Config::parse(GOOD).unwrap();
        // The hash in GOOD is sha256("password").
        assert_eq!(
            cfg.verify_password("Paul@Party.Example.com", "password").as_deref(),
            Some("paul@party.example.com")
        );
        assert!(cfg.verify_password("paul@party.example.com", "passw0rd").is_none());
        assert!(cfg.verify_password("nobody@party.example.com", "password").is_none());
        assert!(cfg.verify_password("paul@elsewhere.example", "password").is_none());
        assert!(cfg.verify_password("paul", "password").is_none());
        let upper = Config::parse(&GOOD.replace(
            "sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "sha256:5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8",
        ))
        .unwrap();
        assert!(
            upper.verify_password("paul@party.example.com", "password").is_some(),
            "an upper-case hash is the same hash"
        );
        let bad = GOOD.replace("sha256:5e88", "sha256:zz88");
        assert!(Config::parse(&bad).unwrap_err().to_string().contains("password"));
        let bad = format!("submission_listen = \"0.0.0.0:465\"\ntls = false\n{GOOD}");
        assert!(Config::parse(&bad).unwrap_err().to_string().contains("submission_listen"));
    }

    #[test]
    fn unknown_keys_are_errors() {
        let bad = GOOD.replace("acme_contact", "acme_contct");
        assert!(Config::parse(&bad).is_err());
    }
}
