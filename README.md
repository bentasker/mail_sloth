# mail_sloth

A small mail server with a REST API, in one Rust binary. It sends mail for
your domains straight to the recipient's mail server with DKIM, receives mail
for those domains and forwards it to real inboxes, and tells your applications
what happened over signed webhooks. It runs on an $11-a-year VPS with 512 MB of
RAM and needs no third-party mail service.

It was written for a handful of personal sites that each send a couple of
messages a month to a hundred people, and for replacing an email forwarding
service for the same domains. It is not a bulk mailer and does not try to be.

```
                 POST /v1/send                     SMTP + DKIM
  your site  ───────────────────▶  mail_sloth  ───────────────────▶  gmail.com, etc.
             ◀───────────────────              ◀───────────────────
              webhook: sent /                    port 25: replies,
              failed / bounced /                 bounces, anything
              mail.received                      sent to your domains
                                                     │
                                                     ▼  forwarded with ARC + SRS
                                               your real inbox
```

**Contents:** [Using the service](#using-the-service) ·
[Setting it up on RackNerd](#setting-it-up-on-racknerd) ·
[Integrating a site](#integrating-a-site) ·
[Configuration](#configuration) · [CLI](#cli) · [Operating it](#operating-it) ·
[How it works](#how-it-works) · [Development](#development)

## Using the service

Everything a site does is one HTTPS call to send, and one endpoint of its own
to receive events. Base URL is `https://<your mail host>`. Every request
carries `Authorization: Bearer <api key>`; a key belongs to one site and may
only send from that site's domains. Errors come back as `{"error": "..."}`.

### Send: `POST /v1/send`

```json
{
  "from": "paul@example.com",
  "to": [
    "someone@example.org",
    {"email": "other@example.org", "name": "Other", "vars": {"first": "O"}}
  ],
  "subject": "Hello {{name}}",
  "text": "Hi {{first}}, plain text here.",
  "html": "<p>Hi {{first}}, rich text here.</p>",
  "headers": {
    "List-Unsubscribe": "<https://example.com/unsubscribe?e={{email}}>",
    "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"
  }
}
```

- `from` can be a bare address or `Name <address>`. The display name and the
  `Reply-To` default to the sender's entry in the server config, so a site
  usually sends from `paul@example.com` and replies land in Paul's Gmail
  without the site knowing that address. Pass `reply_to` to override.
- `to` takes up to 500 entries, strings or objects. **Each recipient gets
  their own message.** That is what makes per-recipient unsubscribe links and
  names work, and what Gmail expects of `List-Unsubscribe`.
- `{{name}}`, `{{email}}`, and any key in `vars` (request-wide) or a
  recipient's `vars` are substituted in the subject, both bodies and header
  values. Values substituted into `html` are HTML-escaped. A `{{...}}` whose
  key is not in `vars` is left exactly as written, so a post that quotes
  template syntax goes out intact.
- `text` or `html` is required; sending both is best.
- `headers` adds headers such as `List-Unsubscribe`. The standard ones (From,
  To, Date, Message-ID and so on) cannot be overridden.
- **A message to more than one recipient must carry `List-Unsubscribe` and
  `List-Unsubscribe-Post` headers** or it is refused with a `400`. That is
  the rule that keeps a list send from ever going out without a way off the
  list; put the same link in the body too, since not every client shows the
  header. A one-off message to several people that is not a list send, say a
  note to both hosts, passes `"transactional": true` instead.

The response is `202` and the message is queued; delivery happens in the
background at one message a second:

```json
{
  "batch_id": "01a086bf4951b5d824e0fc19267e79bf",
  "queued": [{"id": "01a086bf4951...", "to": "someone@example.org"}],
  "skipped": [{"to": "gone@example.org", "reason": "suppressed"}]
}
```

`skipped` reasons are `suppressed` (a hard bounce or an unsubscribe put the
address on the suppression list), `invalid address`, and `duplicate`.

A minimal client is a few lines in any language. From a shell:

```sh
curl -sS https://mail.example.com/v1/send \
  -H "Authorization: Bearer $MAIL_SLOTH_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"from":"paul@example.com","to":["you@gmail.com"],"subject":"hi","text":"hello"}'
```

### Find out what happened

Two ways. Polling:

- `GET /v1/messages/{id}` for one message.
- `GET /v1/batches/{batch_id}` for every message in a send, with counts.

Statuses are `queued`, `sending`, `deferred` (a temporary failure, will
retry), `sent`, `failed`, and `bounced` (accepted, then a bounce came back).
`last_error` carries the receiving server's reply.

Or webhooks, which is the intended way. Set `webhook_url` and
`webhook_secret` for the site in the config and every outcome is POSTed to
the URL as JSON:

```json
{
  "id": "01a086bf49590bea9516cf492f9c9661",
  "type": "message.sent",
  "created_at": "2026-09-09T16:22:58Z",
  "data": {
    "message_id": "01a086bf4951...", "batch_id": "01a086bf4951...",
    "to": "someone@example.org", "from": "Paul Dix <paul@example.com>",
    "subject": "Hello", "detail": "gmail-smtp-in.l.google.com: 250 2.0.0 OK ..."
  }
}
```

| `type` | when | `data` |
|---|---|---|
| `message.sent` | the recipient's server accepted it | `message_id`, `batch_id`, `to`, `from`, `subject`, `detail` |
| `message.failed` | permanently refused, or retries exhausted | same; `detail` is the rejection |
| `message.bounced` | a bounce arrived for a message that was accepted | same; `detail` is the bounce's diagnostic line |
| `mail.received` | mail arrived for one of the site's domains | see below |

Two headers come with every POST:

```
X-Sloth-Event: message.sent
X-Sloth-Signature: t=1757434978,v1=<hex hmac-sha256>
```

The signature is HMAC-SHA256 with the site's `webhook_secret` over the string
`"{t}.{body}"`, where `body` is the exact request body. Verify it before
trusting the event, and reject a `t` older than a few minutes. In Rust with
the `hmac`, `sha2` and `subtle` crates:

```rust
fn verify(secret: &str, header: &str, body: &str) -> bool {
    let (mut t, mut v1) = (None, None);
    for part in header.split(',') {
        match part.split_once('=') {
            Some(("t", x)) => t = x.parse::<i64>().ok(),
            Some(("v1", x)) => v1 = Some(x.to_string()),
            _ => {}
        }
    }
    let (Some(t), Some(v1)) = (t, v1) else { return false };
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{t}.{body}").as_bytes());
    let expected: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
    use subtle::ConstantTimeEq;
    expected.as_bytes().ct_eq(v1.as_bytes()).into()
}
```

Answer with any `2xx` once the event is stored. Anything else is retried at
30 s, 2 m, 10 m, 1 h, 6 h and 24 h, then dropped. Events can arrive out of
order and, after a retry, more than once; key on `id`.

### Receiving mail

Mail sent to any address at your domains is forwarded to the inboxes in the
config. Nothing is needed from the site for that. If the site wants to see the
mail too, set `inbound_webhook = true` on the domain and every accepted
message is also posted as `mail.received`:

```json
{
  "type": "mail.received",
  "data": {
    "inbound_id": "...",
    "to": ["rsvp@example.com"],
    "envelope": {"mail_from": "alice@example.org", "rcpt_to": ["rsvp@example.com"], "remote_ip": "203.0.113.5", "helo": "mail.example.org"},
    "from": {"name": "Alice", "email": "alice@example.org", "display": "Alice <alice@example.org>"},
    "subject": "Re: the party", "date": "2026-09-09T16:22:00Z",
    "message_id": "<...>", "in_reply_to": "<...>",
    "text": "...", "html": "...",
    "headers": [["From", "Alice <alice@example.org>"], ["Subject", "Re: the party"]],
    "attachments": [{"name": "photo.jpg", "content_type": "image/jpeg", "size": 48213}],
    "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass", "dmarc_policy": "none", "arc": "none", "tls": true},
    "size": 51200
  }
}
```

A message is one event per site, however many of the site's addresses it was
sent to; `to` and `envelope.rcpt_to` list only that site's recipients. Bodies
are cut at 256 KB and attachment contents are not included. With
`inbound_webhook` on, mail to *any* local part at the domain is accepted, so a
site can invent addresses like `rsvp+42@example.com` and route on them.

### Sending as the domain from Gmail

Replies to `paul@example.com` land in Gmail because of forwarding, but an
answer written there goes out from the Gmail address. Gmail's "Send mail as"
fixes that: it hands the message to an SMTP server with a username and
password, and mail_sloth provides that server on port 465. The message is
DKIM-signed and delivered like anything sent through the API, and its
`message.sent` / `message.failed` / `message.bounced` events reach the site's
webhook too.

On the mail host, give the address a password and open the port:

```sh
mail_sloth password      # prints the password and a `password = "sha256:..."` line
```

Put that line on the sender's entry under `[domain.senders]`, make sure
`submission_listen = "0.0.0.0:465"` is set, `ufw allow 465/tcp`, and restart
the service. Then in Gmail: Settings, Accounts and Import, "Send mail as",
"Add another email address":

| field | value |
|---|---|
| Name | whatever you like |
| Email address | `paul@example.com` |
| Treat as an alias | checked |
| SMTP Server | `mail.example.com` |
| Port | `465` |
| Username | `paul@example.com` (the full address) |
| Password | what `mail_sloth password` printed |
| Secured connection | SSL |

Gmail then mails a verification code to the address, which arrives in the
same inbox by forwarding. Once verified, replies to forwarded mail can go out
from the domain address, and "Reply from the same address the message was
sent to" in the same settings page makes that the default.

The rules on the port: a login may only send as its own address (the
envelope sender, and a single `From:` header naming that one mailbox), any
recipient is accepted, 20 per message and 200 an hour per address, and five
failed logins lock the client IP out for an hour. A `Bcc:` header is stripped
before delivery; `Date` and `Message-ID` are added if the client did not.

Use the password `mail_sloth password` prints rather than one of your own.
The config holds its plain SHA-256, which is sound for 24 random characters
and would not be for something a person made up.

### Suppressions

`GET /v1/suppressions` lists addresses that will not be mailed.
`POST /v1/suppressions` with `{"email": "...", "reason": "unsubscribe"}` adds
one; a site's unsubscribe handler should call this. `DELETE
/v1/suppressions/{email}` removes one. Hard bounces add entries on their own.

The list belongs to the host, not to a site: any site's key can read it and
change it. That is deliberate, since a person who unsubscribes from one site
should not hear from the others either, and it means the sites on one host
have to trust each other.

### Health

`GET /healthz`, no auth: `{"ok": true, "queue": {"sent": 12, "deferred": 1}}`.

## Setting it up on RackNerd

RackNerd sells KVM VPSes for about $11 a year that have outbound port 25 open
by default and let you set reverse DNS. Any provider with those two properties
works the same way; the big clouds block port 25 and are not an option. The
whole setup is about an hour, most of it waiting for DNS.

### 1. Buy the VPS

The cheapest KVM plan is enough: 1 CPU, 512 MB RAM, 10 GB disk. Pick
**Ubuntu 24.04** or **Debian 12** as the OS and a datacenter near you. Note the
IP address and root password from the welcome email.

### 2. Decide the mail host's name

The server needs one name of its own, separate from the domains you send for.
`mail.<your main domain>` is the convention; below it is `mail.example.com`.
At your DNS provider, add an A record for it pointing at the VPS IP.

### 3. Set reverse DNS

In the RackNerd control panel (nerdvm.racknerd.com) the `Network` tab shows
the IP. Some plans let you edit rDNS there; on the cheap ones you open a
support ticket:

```
Please set the reverse DNS for 192.0.2.10 to mail.example.com.
The forward A record already resolves to this IP. The server runs a small
personal mail server for my own domains, no bulk mail.
```

They usually do it within the hour. Gmail refuses mail from a host whose PTR
does not match its name, so do not skip this.

### 4. Put your SSH key on the server and turn off password login

```sh
ssh-copy-id root@192.0.2.10          # uses the password from the welcome email
ssh root@192.0.2.10 'printf "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n" > /etc/ssh/sshd_config.d/10-keys-only.conf && sshd -t && systemctl reload ssh'
```

### 5. Install mail_sloth

From a checkout of this repository, with Docker Desktop running:

```sh
deploy/deploy.sh root@192.0.2.10 --setup
```

That cross-compiles a Linux binary in a Debian container, copies it up with
the systemd unit and an example config, and runs `deploy/setup.sh` on the
server, which: creates the `mail_sloth` user and directories, installs the
service, adds a 1 GB swap file, installs `unbound` as a local recursive
resolver (the provider's resolvers cache stale answers, and Spamhaus refuses
shared resolvers), and opens ports 22, 25, 443 and 465 in ufw.

Without Docker the script falls back to `cargo zigbuild`, then to downloading
the binary the GitHub release workflow built for the latest `v*` tag.

### 6. Write the config

Still on the server, `/etc/mail_sloth/config.toml` starts as a copy of
[`config.example.toml`](config.example.toml). Fill in:

- `hostname`, `public_ip`, and `acme_contact` (Let's Encrypt writes to it
  before a certificate expires, which should never happen).
- `srs_secret` from `mail_sloth secret`.
- One `[[site]]` per application, with `api_keys` from `mail_sloth key`
  (which prints a key to give the site and the hash to put in the config),
  a `webhook_secret` from `mail_sloth secret`, and `webhook_url` once the
  site has an endpoint.
- One `[[domain]]` per domain: who sends from it and where replies go
  (`senders`), and where inbound mail is forwarded (`forward`). A sender
  that should be usable from Gmail gets a `password` from
  `mail_sloth password` (see [Sending as the domain from
  Gmail](#sending-as-the-domain-from-gmail)).

Then make each domain's DKIM key, as the service user so it can read them:

```sh
sudo -u mail_sloth mail_sloth dkim example.com
```

### 7. Publish DNS and start

`mail_sloth dns` prints every record for every domain. Per domain, at your
DNS provider:

| Record | Host | Value |
|---|---|---|
| MX | `@` | `10 mail.example.com.` |
| TXT | `@` | `v=spf1 ip4:<vps ip> -all` |
| TXT | `sloth._domainkey` | `v=DKIM1; k=rsa; p=...` (one long string; the provider splits it) |
| TXT | `_dmarc` | `v=DMARC1; p=none; rua=mailto:you@example.com` |

If the domain used a forwarding service before (ImprovMX, the registrar's
email forwarding), remove its MX records and its `include:` from SPF. On
Namecheap, switch Mail Settings from "Email Forwarding" to "Custom MX" first
or the records are locked. Mail keeps flowing during the change: whatever
still hits the old MX is forwarded the old way until the record expires.

Start DMARC at `p=none`; move to `p=quarantine` after a few weeks of clean
reports. Then:

```sh
systemctl start mail_sloth && journalctl -fu mail_sloth   # certificate arrives within a minute
mail_sloth check                                          # every record, plus a port 25 test
```

### 8. Prove it

```sh
mail_sloth send --url https://mail.example.com --api-key ms_... \
    --from paul@example.com --to you@gmail.com --subject test
```

Open it in Gmail, choose "Show original", and confirm SPF, DKIM and DMARC all
say PASS. Then send something *to* an address at the domain from Gmail and
watch it come back forwarded; its "Show original" should show `arc=pass`.

A brand-new IP earns its reputation slowly. Send the first few real messages
to friendly addresses before mailing a whole list, and check the IP against
[MXToolbox's blocklist lookup](https://mxtoolbox.com/blacklists.aspx) before
you start.

Later deploys are `deploy/deploy.sh root@192.0.2.10`.

## Integrating a site

What every site needs, in one place. A working integration is about a
hundred lines: one function that POSTs, one route that receives events.

### The pieces

**Secrets.** Three environment variables per site:

```
MAIL_SLOTH_URL=https://mail.example.com
MAIL_SLOTH_API_KEY=ms_...          # the site's bearer key
MAIL_SLOTH_WEBHOOK_SECRET=...      # matches webhook_secret in the site's config block
```

Treat a missing key as mail being switched off: log once at boot that
sending is off, and keep serving.

**Sending.** One POST per broadcast, not per recipient. The server paces
delivery itself, so the client needs no rate limiting or sleeps of its own.
Put per-recipient values in each recipient's `vars` and reference them as
`{{name}}` in the subject, bodies and headers. In Rust with `reqwest`:

```rust
#[derive(serde::Serialize)]
struct Recipient<'a> { email: &'a str, name: Option<&'a str>, vars: std::collections::HashMap<&'a str, String> }

async fn send_batch(http: &reqwest::Client, from: &str, to: &[Recipient<'_>], subject: &str, text: &str, html: &str,
                    headers: &[(&str, &str)]) -> anyhow::Result<serde_json::Value> {
    let url = format!("{}/v1/send", std::env::var("MAIL_SLOTH_URL")?);
    let resp = http.post(url)
        .bearer_auth(std::env::var("MAIL_SLOTH_API_KEY")?)
        .json(&serde_json::json!({
            "from": from, "to": to, "subject": subject, "text": text, "html": html,
            "headers": headers.iter().cloned().collect::<std::collections::HashMap<_, _>>(),
        }))
        .send().await?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await?;
    anyhow::ensure!(status.is_success(), "mail_sloth {status}: {body}");
    Ok(body) // {"batch_id", "queued": [{"id","to"}], "skipped": [{"to","reason"}]}
}
```

Store the returned `batch_id` and each recipient's message `id` next to the
address in whatever table the site already logs sends in. That id is how the
webhook events refer back to the row.

**Receiving events.** One POST route, public, no session. Verify the
signature with the code in [Find out what happened](#find-out-what-happened),
then switch on `type`:

| event | what the site does |
|---|---|
| `message.sent` | mark the row sent |
| `message.failed` | mark it failed with `detail` |
| `message.bounced` | mark it bounced; if `detail` names the mailbox (`5.1.1`, "no such user") also unsubscribe the address locally |
| `mail.received` | only if `inbound_webhook` is on for the domain; store or route as the site sees fit |

Return `204` as soon as the row is updated. Events can repeat after a retry
and can arrive out of order, so make the update idempotent (a `sent` after a
`bounced` should not un-bounce). Then have the mail host's config point at
the route: set `webhook_url` in the site's block in
`/etc/mail_sloth/config.toml` and restart the service. Until that is set, the
mail host queues nothing for the site and the send response is all it gets.

**Unsubscribes.** The site keeps owning the unsubscribe page and the
one-click POST endpoint, and keeps sending `List-Unsubscribe` and
`List-Unsubscribe-Post` headers with a per-recipient URL via `vars`. When a
person unsubscribes, the site should additionally `POST /v1/suppressions`
with the address, so a stale list on another site of yours cannot mail them
either. Bounces get suppressed on the mail host automatically.

**Local development.** Point `MAIL_SLOTH_URL` at a local `mail_sloth serve`
running with `tls = false` and `mx_override` (see [Development](#development)),
or leave the key unset and let the site log instead of sending.

## Configuration

[`config.example.toml`](config.example.toml) is annotated. The parts that
matter:

- **`[[site]]`** is an application: `name`, `api_keys` (sha256 hex of each
  key), optional `webhook_url` and `webhook_secret`, and the `domains` it may
  send from. A domain belongs to exactly one site.
- **`[[domain]]`** has `senders` (local part to display name and default
  `reply_to`), `forward` (local part to a list of inboxes, `"*"` as
  catch-all), and `inbound_webhook`. Without a forward rule, a catch-all, or
  `inbound_webhook`, an address does not exist and is refused at `RCPT`. An
  empty list (`dmarc = []`) accepts the mail and keeps it in the `inbound`
  table, body and all, without forwarding it: the place for DMARC aggregate
  reports, which Gmail throttles when they are forwarded back to it.
- `srs_secret` is required if anything forwards. `dnsbl` lists zones checked
  at `MAIL FROM`. `send_rate_per_second` defaults to one.
  `submission_listen` turns on the authenticated port for Gmail.

The config is read once at start. Change it, then `systemctl restart
mail_sloth`. Sites, keys, domains and secrets all live in the config; the
database only holds mail and its state.

## CLI

```
mail_sloth serve            run the server
mail_sloth key              print a new API key and its hash
mail_sloth secret           print a random secret
mail_sloth password         print a submission password and its hash for a sender
mail_sloth dkim <domain>    create the domain's key if missing; print its TXT record
mail_sloth dns [domain]     print every DNS record the config needs
mail_sloth check            look the records up and test outbound port 25
mail_sloth send ...         send a message through a running server
```

`--config PATH` or `MAIL_SLOTH_CONFIG` picks the config file; the default is
`/etc/mail_sloth/config.toml`.

## Operating it

- **Logs:** `journalctl -fu mail_sloth`. Every inbound message logs one line
  with its authentication results and what was done with it. `RUST_LOG=debug`
  in the unit file shows SMTP session detail.
- **Data:** `/var/lib/mail_sloth/` holds `mail_sloth.db` (plus its WAL),
  `dkim/` (private keys, mode 600) and `acme/` (certificates and account).
  Back up the directory with the service stopped, or copy `mail_sloth.db*`
  together; the WAL holds recent writes. Losing `dkim/` means new DNS
  records; losing `acme/` costs nothing but a new certificate.
- **Retention:** message bodies are dropped 7 days after a message finishes;
  raw inbound mail and finished webhook rows after 30 days, except mail
  kept by an empty forward list, which is never dropped. Metadata stays.
- **Limits:** 25 MB messages, 20 recipients per inbound or submitted
  message, 200 submitted recipients an hour per login, 32 concurrent
  connections per listener, 500 recipients per API call. An SMTP connection
  is closed after ten errors, refused recipients included.
- **Restarts and outages:** in-flight messages are requeued at start. If the
  server is down, sending servers retry for days, which is normal SMTP;
  nothing is lost during a reboot or a deploy.
- **Reputation:** if Outlook junks you, Microsoft's SNDS and JMRP programs
  are free to join and usually fix it.

## How it works

- **Sending.** Each recipient's copy is queued in an embedded
  [Turso](https://github.com/tursodatabase/turso) database. A worker signs it
  with the domain's RSA-2048 DKIM key (Gmail does not verify Ed25519), looks
  up the recipient's MX, and delivers over SMTP with opportunistic STARTTLS.
  The envelope sender is `bounce+<id>@domain`, so a bounce finds its message
  without parsing anything. Temporary failures retry for two days; a
  permanent one that names the mailbox suppresses the address.
- **Receiving.** Port 25 accepts mail only for configured addresses. Each
  message is verified for SPF, DKIM, ARC and DMARC. A failing `p=reject`
  DMARC policy or a hard SPF fail with no DKIM is refused, as are senders on
  the configured blocklists. Accepted mail is forwarded with an ARC seal
  (so the next hop can trust the original authentication) and an SRS
  envelope (so its SPF check passes). A bounce for a forwarded message
  comes back to the SRS address and is returned to the original sender.
- **Webhooks** are rows in the database first and posted by a worker, so a
  site being down costs a delay, not an event.
- **TLS** comes from Let's Encrypt over the TLS-ALPN-01 challenge on port
  443. One certificate serves the API, STARTTLS on 25 and implicit TLS on
  465; only those three ports are open.
- **Rate.** One message a second, on purpose. A fresh IP that bursts at
  Gmail is treated as a spam run; one that trickles is a mail server.

The whole thing is about 5,000 lines, tests included. The mail plumbing comes from the
[Stalwart](https://stalw.art) libraries: `mail-auth` (DKIM, SPF, DMARC, ARC),
`mail-send`, `mail-parser`, `mail-builder` and `smtp-proto`.

## Development

```sh
cargo test                      # unit tests plus an end-to-end run on loopback
cargo run -- --config dev.toml serve
```

For a local run set `tls = false`, high ports for `http_listen` and
`smtp_listen`, and `mx_override = "127.0.0.1:<smtp port>"` so outbound mail
lands on your own listener instead of the internet. The end-to-end test in
`src/e2e_tests.rs` does exactly that: the real API, the real SMTP client and
listener, forwarding, bounces and signed webhooks, all on loopback.

## Roadmap

[`TODO.md`](TODO.md) holds the smaller pieces of designed-but-unbuilt work,
written to be picked up cold.

## License

MIT.
