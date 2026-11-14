//! Building the outgoing MIME message for one recipient.
//!
//! Every recipient gets their own copy. That is what lets the body carry
//! their name and their own unsubscribe link, and it is what Gmail expects of
//! List-Unsubscribe: one message, one recipient.

use std::collections::HashMap;

use anyhow::{bail, Result};
use mail_builder::headers::raw::Raw;
use mail_builder::MessageBuilder;

/// `Name <addr>` or bare `addr`, already checked to be an address.
#[derive(Debug, Clone, PartialEq)]
pub struct Mailbox {
    pub name: Option<String>,
    pub email: String,
}

impl Mailbox {
    pub fn parse(s: &str) -> Result<Mailbox> {
        let s = s.trim();
        let (name, email) = match (s.rfind('<'), s.ends_with('>')) {
            (Some(i), true) => {
                let name = s[..i].trim().trim_matches('"').trim();
                let email = &s[i + 1..s.len() - 1];
                ((!name.is_empty()).then(|| name.to_string()), email.trim())
            }
            _ => (None, s),
        };
        if !crate::util::is_valid_email(email) {
            bail!("not an email address: {s}");
        }
        Ok(Mailbox {
            name: name.map(|n| clean_header(&n)),
            email: email.to_string(),
        })
    }

    pub fn local_part(&self) -> &str {
        self.email.rsplit_once('@').map(|(l, _)| l).unwrap_or("")
    }

    pub fn domain(&self) -> &str {
        self.email.rsplit_once('@').map(|(_, d)| d).unwrap_or("")
    }

    pub fn header_value(&self) -> String {
        match &self.name {
            Some(n) => format!("{n} <{}>", self.email),
            None => self.email.clone(),
        }
    }
}

pub struct Draft<'a> {
    pub from: &'a Mailbox,
    pub to: &'a Mailbox,
    pub reply_to: Option<&'a str>,
    pub subject: &'a str,
    pub text: Option<&'a str>,
    pub html: Option<&'a str>,
    /// Extra headers, values already substituted.
    pub headers: &'a [(String, String)],
    /// `local@domain` for the Message-ID.
    pub message_id: &'a str,
}

/// A mailbox as mail-builder wants it. A missing name must become a bare
/// address: `("", addr)` renders as `"" <addr>`, which looks forged.
fn address(m: &Mailbox) -> mail_builder::headers::address::Address<'static> {
    match &m.name {
        Some(n) if !n.trim().is_empty() => (n.clone(), m.email.clone()).into(),
        _ => m.email.clone().into(),
    }
}

/// The wire bytes for one message. Not yet signed: DKIM happens at delivery
/// time so that a retry days later still carries a fresh timestamp.
pub fn build(d: &Draft) -> Result<Vec<u8>> {
    let mut b = MessageBuilder::new()
        .from(address(d.from))
        .to(address(d.to))
        .subject(d.subject.to_string())
        .message_id(d.message_id.to_string())
        .date(crate::util::unix_now());
    if let Some(r) = d.reply_to {
        b = b.reply_to(r.to_string());
    }
    for (name, value) in d.headers {
        b = b.header(name.clone(), Raw::new(value.clone()));
    }
    match (d.text, d.html) {
        (Some(t), Some(h)) => b = b.text_body(t.to_string()).html_body(h.to_string()),
        (Some(t), None) => b = b.text_body(t.to_string()),
        (None, Some(h)) => b = b.html_body(h.to_string()),
        (None, None) => bail!("a message needs a text or html body"),
    }
    Ok(b.write_to_vec()?)
}

/// Header field names are letters, digits and hyphens; anything else is a
/// way to smuggle a second header in.
pub fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 64
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        && !matches!(
            name.to_ascii_lowercase().as_str(),
            "from"
                | "to"
                | "cc"
                | "bcc"
                | "subject"
                | "date"
                | "message-id"
                | "reply-to"
                | "content-type"
                | "content-transfer-encoding"
                | "mime-version"
                | "dkim-signature"
                | "return-path"
                | "received"
        )
}

/// Strips line breaks so a value cannot terminate its header.
pub fn clean_header(v: &str) -> String {
    v.chars().filter(|c| *c != '\r' && *c != '\n').collect()
}

/// `{{ key }}` substitution. A key that is not in `vars` is left exactly as
/// written: a post that quotes `{{ .Values.tag }}` from a Helm chart must
/// reach the list with the braces intact, and only the site knows which
/// braces are its own.
pub fn substitute(template: &str, vars: &HashMap<String, String>, html: bool) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => {
                let key = after[..end].trim();
                match vars.get(key) {
                    Some(v) if html => out.push_str(&escape_html(v)),
                    Some(v) => out.push_str(v),
                    None => out.push_str(&rest[start..start + 2 + end + 2]),
                }
                rest = &after[end + 2..];
            }
            None => {
                out.push_str("{{");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_parsing() {
        let m = Mailbox::parse("Paul Dix <paul@example.com>").unwrap();
        assert_eq!(m.name.as_deref(), Some("Paul Dix"));
        assert_eq!(m.email, "paul@example.com");
        assert_eq!(m.local_part(), "paul");
        assert_eq!(m.domain(), "example.com");
        let m = Mailbox::parse("  paul@example.com ").unwrap();
        assert_eq!(m.name, None);
        assert!(Mailbox::parse("paul").is_err());
        assert!(Mailbox::parse("<paul@example.com").is_err());
        // A name cannot inject a header.
        let m = Mailbox::parse("Evil\r\nBcc: x@y.com <paul@example.com>").unwrap();
        assert!(!m.name.unwrap().contains('\n'));
    }

    #[test]
    fn substitution_escapes_in_html_only() {
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "A <b>".to_string());
        assert_eq!(substitute("hi {{ name }}!", &vars, false), "hi A <b>!");
        assert_eq!(substitute("hi {{name}}!", &vars, true), "hi A &lt;b&gt;!");
        assert_eq!(substitute("{{missing}}x{{", &vars, false), "{{missing}}x{{");
        assert_eq!(substitute("a {{ .Values.tag }} b", &vars, true), "a {{ .Values.tag }} b");
    }

    #[test]
    fn header_names_are_restricted() {
        assert!(is_valid_header_name("List-Unsubscribe"));
        assert!(!is_valid_header_name("From"));
        assert!(!is_valid_header_name("X Y"));
        assert!(!is_valid_header_name(""));
    }

    #[test]
    fn a_built_message_has_the_expected_shape() {
        let from = Mailbox::parse("Paul <paul@example.com>").unwrap();
        let to = Mailbox::parse("Reader <r@example.org>").unwrap();
        let headers = vec![
            ("List-Unsubscribe".to_string(), "<https://example.com/u?t=1>".to_string()),
            ("List-Unsubscribe-Post".to_string(), "List-Unsubscribe=One-Click".to_string()),
        ];
        let raw = build(&Draft {
            from: &from,
            to: &to,
            reply_to: Some("paul@gmail.example"),
            subject: "Hello",
            text: Some("plain"),
            html: Some("<p>rich</p>"),
            headers: &headers,
            message_id: "abc@example.com",
        })
        .unwrap();
        let s = String::from_utf8(raw).unwrap();
        assert!(s.contains("From: \"Paul\" <paul@example.com>\r\n") || s.contains("From: Paul <paul@example.com>\r\n"));
        assert!(s.contains("Reply-To: <paul@gmail.example>\r\n") || s.contains("Reply-To: paul@gmail.example\r\n"));
        assert!(s.contains("Message-ID: <abc@example.com>\r\n"));
        let bare = Mailbox {
            name: None,
            email: "r@example.org".into(),
        };
        let raw = build(&Draft {
            from: &from,
            to: &bare,
            reply_to: None,
            subject: "x",
            text: Some("t"),
            html: None,
            headers: &[],
            message_id: "b@example.com",
        })
        .unwrap();
        let s2 = String::from_utf8(raw).unwrap();
        assert!(
            s2.contains("To: <r@example.org>\r\n") || s2.contains("To: r@example.org\r\n"),
            "{s2}"
        );
        assert!(!s2.contains("\"\" <"), "no empty quoted display name: {s2}");
        assert!(s.contains("List-Unsubscribe: <https://example.com/u?t=1>\r\n"));
        assert!(s.contains("List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"));
        assert!(s.contains("Content-Type: multipart/alternative"));
        assert!(s.contains("plain"));
        assert!(s.contains("<p>rich</p>"));
        assert!(s.contains("\r\nDate: "));
        assert!(build(&Draft {
            from: &from,
            to: &to,
            reply_to: None,
            subject: "x",
            text: None,
            html: None,
            headers: &[],
            message_id: "a@b.c"
        })
        .is_err());
    }
}
