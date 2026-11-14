//! Sender Rewriting Scheme, so forwarded mail passes SPF at the next hop.
//!
//! When we forward `alice@example.org`'s mail to Gmail, Gmail checks SPF for
//! the envelope sender against *our* IP. With the original sender that fails.
//! So the envelope sender becomes `SRS0=hash=ts=example.org=alice@ourdomain`,
//! which our SPF covers, and a bounce to that address is unwrapped and sent
//! back to Alice. The hash stops strangers using us as a relay by minting
//! SRS addresses, and the timestamp stops old ones being replayed.
//!
//! The classic scheme keeps four characters of the hash, which is a few
//! million guesses at RCPT. Nobody but us ever checks the hash, so it is
//! longer here: ten base32 characters, fifty bits, and base32 so that a
//! server that lowercases the local part on the way does not break it.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const MAX_AGE_DAYS: i64 = 21;
const HASH_CHARS: usize = 10;

fn day_number() -> i64 {
    crate::util::unix_now() / 86_400
}

fn timestamp(day: i64) -> String {
    let d = (day.rem_euclid(1024)) as usize;
    let mut s = String::with_capacity(2);
    s.push(BASE32[(d >> 5) & 31] as char);
    s.push(BASE32[d & 31] as char);
    s
}

fn parse_timestamp(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    if b.len() != 2 {
        return None;
    }
    let idx = |c: u8| BASE32.iter().position(|&x| x == c.to_ascii_uppercase());
    Some(((idx(b[0])? << 5) | idx(b[1])?) as i64)
}

fn hash(secret: &str, ts: &str, domain: &str, local: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
    // A NUL between the fields: without it `a.com` + `bob` and `a.co` +
    // `mbob` are the same bytes, and one valid address vouches for another.
    for field in [ts, domain, local] {
        mac.update(field.to_ascii_lowercase().as_bytes());
        mac.update(&[0]);
    }
    let out = mac.finalize().into_bytes();
    let bits = u64::from_be_bytes(out[..8].try_into().expect("sha256 is longer than 8 bytes"));
    (0..HASH_CHARS)
        .map(|i| BASE32[((bits >> (59 - 5 * i)) & 31) as usize] as char)
        .collect()
}

/// The envelope sender to use when forwarding mail from `sender`.
/// An empty sender (a bounce) stays empty: bounces are never forwarded back.
pub fn rewrite(secret: &str, sender: &str, our_domain: &str) -> String {
    if sender.is_empty() {
        return String::new();
    }
    let Some((local, domain)) = sender.rsplit_once('@') else {
        return String::new();
    };
    let ts = timestamp(day_number());
    let h = hash(secret, &ts, domain, local);
    format!("SRS0={h}={ts}={domain}={local}@{our_domain}")
}

/// The original sender behind an SRS0 local part, if it is ours and fresh.
pub fn reverse(secret: &str, local_part: &str) -> Result<String, &'static str> {
    // Anyone can compute an HMAC under the empty key.
    if secret.is_empty() {
        return Err("no srs_secret configured");
    }
    let rest = local_part
        .strip_prefix("SRS0=")
        .or_else(|| local_part.strip_prefix("srs0="))
        .ok_or("not an SRS0 address")?;
    let mut parts = rest.splitn(4, '=');
    let (h, ts, domain, local) = (
        parts.next().ok_or("malformed")?,
        parts.next().ok_or("malformed")?,
        parts.next().ok_or("malformed")?,
        parts.next().ok_or("malformed")?,
    );
    let expected = hash(secret, ts, domain, local);
    if !bool::from(h.to_ascii_uppercase().as_bytes().ct_eq(expected.as_bytes())) {
        return Err("bad hash");
    }
    let day = parse_timestamp(ts).ok_or("bad timestamp")?;
    let age = (day_number() - day).rem_euclid(1024);
    if age > MAX_AGE_DAYS {
        return Err("expired");
    }
    Ok(format!("{local}@{domain}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_and_reverse_roundtrip() {
        let s = rewrite("secret", "alice@example.org", "ours.com");
        assert!(s.starts_with("SRS0="));
        assert!(s.ends_with("=example.org=alice@ours.com"));
        let local = s.split('@').next().unwrap();
        assert_eq!(reverse("secret", local).unwrap(), "alice@example.org");
        assert_eq!(reverse("other", local).unwrap_err(), "bad hash");
        assert_eq!(reverse("secret", "bob").unwrap_err(), "not an SRS0 address");
    }

    #[test]
    fn plus_addresses_and_case_survive() {
        let s = rewrite("k", "Al+tag@Example.org", "ours.com");
        let local = s.split('@').next().unwrap();
        assert_eq!(reverse("k", local).unwrap(), "Al+tag@Example.org");
        assert_eq!(reverse("k", &local.to_ascii_lowercase()).unwrap(), "al+tag@example.org");
    }

    #[test]
    fn the_hash_covers_where_the_domain_ends() {
        // bob@a.com and mbob@a.co are the same bytes once joined, and must not share a hash.
        let s = rewrite("k", "bob@a.com", "ours.com");
        let mut parts = s.split('@').next().unwrap().splitn(4, '=');
        let (_, h, ts) = (parts.next(), parts.next().unwrap(), parts.next().unwrap());
        assert!(reverse("k", &format!("SRS0={h}={ts}=a.com=bob")).is_ok());
        assert!(reverse("k", &format!("SRS0={h}={ts}=a.co=mbob")).is_err());
        assert!(h.len() >= 10, "a short hash can be guessed: {h}");
    }

    #[test]
    fn an_empty_secret_signs_nothing() {
        let s = rewrite("", "alice@example.org", "ours.com");
        assert!(reverse("", s.split('@').next().unwrap()).is_err());
    }

    #[test]
    fn bounces_are_not_rewritten() {
        assert_eq!(rewrite("k", "", "ours.com"), "");
    }

    #[test]
    fn old_timestamps_expire() {
        let old = timestamp(day_number() - 30);
        let h = hash("k", &old, "example.org", "alice");
        assert_eq!(reverse("k", &format!("SRS0={h}={old}=example.org=alice")).unwrap_err(), "expired");
        let recent = timestamp(day_number() - 5);
        let h = hash("k", &recent, "example.org", "alice");
        assert!(reverse("k", &format!("SRS0={h}={recent}=example.org=alice")).is_ok());
    }
}
