//! Small shared helpers: ids, clocks, hex, random bytes.

use std::fmt::Write as _;

use rand::RngCore;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// UTC now as `2026-09-09T10:00:00Z`.
///
/// Every timestamp in the database is written by this function, so they all
/// share one format and one width. That is what makes `next_attempt_at <= ?`
/// a plain string comparison rather than a date parse on every row.
pub fn now() -> String {
    format_ts(OffsetDateTime::now_utc())
}

pub fn format_ts(t: OffsetDateTime) -> String {
    t.replace_nanosecond(0)
        .unwrap_or(t)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// `now` plus a number of seconds, in the same format as [`now`].
pub fn after_seconds(secs: i64) -> String {
    format_ts(OffsetDateTime::now_utc() + time::Duration::seconds(secs))
}

pub fn unix_now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// RFC 2822 date for Received and Date headers.
pub fn rfc2822_now() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".to_string())
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// A 32-character id that sorts by creation time: 12 hex digits of
/// milliseconds followed by 80 random bits. Used for messages, batches,
/// inbound mail and webhook events, so an id never says which table it is
/// from, and it is safe to put in an envelope address or a URL.
pub fn new_id() -> String {
    let millis = (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as u64;
    let rand = random_bytes::<10>();
    format!("{millis:012x}{}", hex(&rand))
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(data))
}

pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    hex(&mac.finalize().into_bytes())
}

/// Lowercases and trims an address. Mail addresses are compared this way
/// everywhere so a suppression for `Bob@Example.com` also covers `bob@`.
pub fn normalize_email(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

/// `local@domain` split, or None if it does not look like an address.
pub fn split_email(addr: &str) -> Option<(&str, &str)> {
    let (local, domain) = addr.rsplit_once('@')?;
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || addr.chars().any(|c| c.is_whitespace() || c == '<' || c == '>' || c == ',')
    {
        return None;
    }
    Some((local, domain))
}

pub fn is_valid_email(addr: &str) -> bool {
    addr.len() <= 254 && split_email(addr).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_sort_by_time_and_do_not_repeat() {
        let a = new_id();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = new_id();
        assert_eq!(a.len(), 32);
        assert!(a < b);
        assert_ne!(new_id(), new_id());
    }

    #[test]
    fn timestamps_are_fixed_width_utc() {
        let t = now();
        assert_eq!(t.len(), 20);
        assert!(t.ends_with('Z'));
        assert!(after_seconds(60) > t);
    }

    #[test]
    fn email_validation_rejects_the_obvious() {
        assert!(is_valid_email("a@b.co"));
        assert!(!is_valid_email("a@b"));
        assert!(!is_valid_email("a b@c.com"));
        assert!(!is_valid_email("<a@c.com>"));
        assert!(!is_valid_email("@c.com"));
        assert_eq!(split_email("x@y.z"), Some(("x", "y.z")));
    }
}
