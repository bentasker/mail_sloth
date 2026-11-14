# TODO

Work that is designed but not built. Each item has enough detail to be picked
up cold. Read `CLAUDE.md` first for the invariants.

## Known gaps

- No per-IP limits on port 25. One host can hold all 32 connection slots for
  the 20-minute session timeout, and nothing caps how much mail one sender
  can have stored. A per-IP connection cap in `serve_with` and a per-IP
  message rate would cover both.
- The submission lockout is per client IP, and Gmail's outbound IPs are
  shared: someone else's failed logins through Gmail can lock a real user
  out for the hour. Keying the counter on IP and username would narrow it.
- No hop count. A forward rule that leads back to this host, directly or
  through the inbox it forwards to, loops until the queue is cleared by
  hand. Refuse a message that already carries, say, 30 `Received:` headers.
- Outbound TLS is opportunistic and unauthenticated, like most MTAs: no
  MTA-STS, no DANE.

## Smaller items

- `mail_sloth check` should also verify that the DKIM record's public key
  matches the local private key byte for byte, not only that a `p=` is
  published.
- A `GET /v1/inbound/{id}/raw` endpoint returning the stored message, so a
  site handling `mail.received` can fetch attachments on demand.
- Google Postmaster Tools verification records for each domain, once volume
  makes the dashboards useful.
- A STARTTLS submission listener on 587 next to the implicit-TLS one on 465,
  for clients that cannot do implicit TLS. It is the port 25 flow with AUTH
  refused until after STARTTLS; `Session::auth_allowed` already keys on
  `self.tls`, so it is a listener and a config key, not new protocol.
