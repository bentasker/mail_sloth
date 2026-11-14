# CLAUDE.md

A mail server with a REST API in one Rust binary: axum for the API, an SMTP
listener on 25, direct-to-MX delivery with DKIM, forwarding with ARC and SRS,
webhooks back to the calling sites. `README.md` covers using it; this covers
what to keep intact when changing it. `TODO.md` is designed-but-unbuilt work,
written to be picked up cold.

## Commands

```sh
cargo test                                  # unit tests + end-to-end runs on loopback; needs DNS
cargo fmt && cargo clippy --all-targets     # both are kept clean; rustfmt.toml sets the width
cargo build --release --locked              # what ships; ~2 min with LTO
deploy/deploy.sh root@mail.example.com      # build (docker / zigbuild / gh release), scp, restart
deploy/deploy.sh root@host --setup          # first time on a fresh Debian 12 box
```

Docker Desktop is on the dev Mac (its CLI lives in `~/.docker/bin`, which the
build script adds to PATH). The Mac is arm64, so the build runs natively in an
arm64 Debian 12 container and cross-links for x86_64 with Debian's cross gcc;
never use `--platform linux/amd64`, emulation takes most of an hour. Without
Docker the script falls back to `cargo zigbuild`, then to downloading the
binary the GitHub release workflow built for the latest `v*` tag.

## Layout

```
src/main.rs      CLI (serve, key, secret, password, dkim, dns, check, send) and boot
src/app.rs       shared state: config, db, keys, resolver, login and submission counters
src/util.rs      ids, clocks, hashes, address checks
src/config.rs    the TOML config: sites, domains, senders, forwards, keys
src/db.rs        Turso store: messages (outbox), inbound, suppressions, webhook_events
src/api.rs       POST /v1/send and the lookups; bearer auth per site
src/message.rs   MIME building and {{var}} substitution
src/dkim.rs      key files, signing, ARC sealer, the DNS record
src/deliver.rs   outbox worker: MX lookup, SMTP client, retries, cleanup
src/smtpd.rs     the SMTP protocol: port 25 inbound, port 465 authenticated submission
src/inbound.rs   what to do with an accepted message: auth, bounce, forward, webhook; submit()
src/srs.rs       SRS0 envelope rewriting
src/webhook.rs   signed event delivery with retries
src/tls.rs       rustls-acme: one certificate for HTTPS and STARTTLS
src/e2e_tests.rs the loopback end-to-end test
deploy/          systemd unit, setup.sh, build-linux.sh, deploy.sh
```

## Invariants

- **Every database statement goes through the one connection in `Db`.**
  Turso returns "database is locked" to a second writer instead of waiting,
  so `Db` holds a single `Connection` behind a mutex. Do not open another.
- **A recipient is refused at RCPT or not at all.** `classify_recipient` is
  the only place that decides whether an address exists here. `accept()`
  calls it again but only to route; anything it rejects there is dropped
  silently, so keep the two in step. There is no relaying: a domain that is
  not in the config is `550 5.7.1` before the body is ever sent. A refused
  recipient counts toward the connection's error limit, so nobody gets to
  try addresses or SRS hashes at leisure.
- **Inbound mail is recorded before anything is done with it.** `accept()`
  decides the routing, writes the `inbound` row, and only then queues
  forwards, handles bounces and enqueues webhooks. If the row cannot be
  written the sender gets a 451. For an address with an empty forward list
  that row is the only copy of the message.
- **Forwarded mail carries an ARC seal and an SRS envelope.** Without SRS,
  Gmail's SPF check on the forwarded copy fails; without ARC, its DMARC
  check does. A bounce being returned to an original sender (an `SRS0=`
  recipient) gets neither and goes out with an empty MAIL FROM, so it can
  never loop. An `SRS0=` address is a way to make this host send mail to a
  stranger, so its hash is fifty bits, covers the field boundaries, and is
  never checked against an empty secret; every failure is the same
  `550 5.1.1 no such user`.
- **Submission never relays unauthenticated, and a login may only send as
  itself.** Port 465 is implicit TLS; the config refuses `submission_listen`
  without `tls`, and AUTH is only advertised on a TLS stream (or the test-only
  `serve_submission(.., None, ..)`). After AUTH, `MAIL FROM` must equal the
  login address and the message must have exactly one `From:` header naming
  exactly that mailbox. Five failed logins lock the IP
  out for an hour before it gets a greeting. Submitted mail becomes ordinary
  `send` rows, so it is DKIM-signed at delivery and its events reach the
  site's webhook like an API send.
- **The envelope sender of every outgoing message is `bounce+<id>@domain`.**
  That is how a bounce finds its message without parsing anything. The id is
  32 hex chars and `classify_recipient` checks that shape.
- **DKIM signs at delivery time, not at queue time.** A message that waits two
  days in the queue still gets a fresh signature. The signed header list is
  in `dkim.rs`; `List-Unsubscribe` is in it deliberately.
- **Enhanced status codes go back into recorded replies.** mail-send parses
  `5.1.1` out of the message text; `reply_text` puts it back, and
  `looks_like_bad_address` depends on seeing it. That is what turns a
  "no such user" into a suppression.
- **Webhook events are rows first.** `webhook::enqueue` writes the row and
  pokes the worker; the worker posts and retries. Never post inline from a
  request or from the SMTP session. An inbound message is one
  `mail.received` per site, listing only that site's recipients.
- **Config is the only source of decisions.** Sites, keys, domains, routes and
  secrets are in the TOML file; the database holds mail and its state. A CLI
  command therefore never needs the database open while the server runs.
- **Rate is one message a second by default and forwards share it.** A new
  IP that bursts at Gmail gets junked. Raise `send_rate_per_second` only
  after the IP has a history.
- **The one-click unsubscribe endpoint belongs to the site.** mail_sloth
  passes `List-Unsubscribe` headers through with substitution; it does not
  host the endpoint. A site that wants an address dropped calls
  `POST /v1/suppressions`.

## Traps hit before

- **Turso `PRAGMA` returns a row**, so it needs `query()`, not `execute()`.
- **mail-auth's `ring` feature picks the crypto backend.** With it on, `RsaKey`
  comes from `ring_impls` and loads PKCS#1 DER via `from_key_der`; the
  `rust-crypto` feature is ignored. `generate` still needs the `rsa` crate.
- **The DKIM `p=` value must be SubjectPublicKeyInfo**, not the bare PKCS#1
  that `DkimKeyPair` hands back. `wrap_spki` adds the framing; Gmail rejects
  the bare form even though mail-auth accepts both.
- **`SpfParameters` and `DmarcParameters` live under `::verify`**, not the
  module root.
- **`smtp-proto`'s `RequestReceiver` keeps partial lines itself.** After a
  `NeedsMoreData` the caller must discard its own buffer or the bytes are fed
  twice.
- **aws-lc-sys sneaks in through default features** of tokio-rustls,
  axum-server, rustls-acme, mail-send and mail-auth. Every one of them is
  pinned to `ring` in `Cargo.toml`; check `cargo tree -i aws-lc-sys` after
  adding a dependency. It needs cmake and breaks cross-compiles.
- **The VPS must resolve DNS itself.** RackNerd's image pointed resolv.conf at
  8.8.8.8, whose cache kept serving the old MX for hours; a test send would
  have gone to ImprovMX. Spamhaus also refuses queries via public resolvers.
  setup.sh installs unbound and points systemd-resolved at it; the service
  reads resolv.conf once at start, so restart it after changing resolvers.
  hickory also answers PTR lookups from /etc/hosts, which the image seeds
  with the provider's hostname.
- **Raw strings and `"#`.** `r#"..."#` ends at the first `"#`. Use `r##`.

## Conventions

- Comments explain *why*, not what. Most lines need none.
- A behaviour that could lose or misroute mail gets a test in `e2e_tests.rs`
  or the module. Check the test fails against the bug before trusting it.
- Log addresses at info for inbound mail (it is our own mail) but never log
  message bodies.
