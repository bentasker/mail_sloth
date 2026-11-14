#!/bin/sh
# First-time setup of a fresh Debian 12 / Ubuntu 24.04 host. Run as root from
# the directory holding the mail_sloth binary, config.example.toml and
# mail_sloth.service (deploy.sh --setup copies them all up and runs this).
set -eu

echo "== packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates ufw unbound >/dev/null

echo "== dns: resolve recursively ourselves"
# The provider's resolvers cache aggressively, which delivers mail to a
# stale MX, and Spamhaus refuses queries that arrive through shared
# resolvers. A local unbound fixes both. Some images ship a static
# resolv.conf that bypasses systemd-resolved; point it at the stub.
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/unbound.conf <<EOF
[Resolve]
DNS=127.0.0.1
Domains=~.
DNSSEC=no
EOF
systemctl enable --now unbound >/dev/null 2>&1 || true
systemctl restart systemd-resolved 2>/dev/null || true
if [ -f /run/systemd/resolve/stub-resolv.conf ] && [ ! -L /etc/resolv.conf ]; then
    rm -f /etc/resolv.conf && ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
fi

echo "== user and directories"
id mail_sloth >/dev/null 2>&1 || useradd --system --home /var/lib/mail_sloth --shell /usr/sbin/nologin mail_sloth
install -d -o mail_sloth -g mail_sloth -m 750 /var/lib/mail_sloth
install -d -o root -g mail_sloth -m 750 /etc/mail_sloth
if [ ! -f /etc/mail_sloth/config.toml ]; then
    install -o root -g mail_sloth -m 640 config.example.toml /etc/mail_sloth/config.toml
    echo "   wrote /etc/mail_sloth/config.toml from the example; EDIT IT before starting"
fi

echo "== binary and service"
install -m 755 mail_sloth /usr/local/bin/mail_sloth
install -m 644 mail_sloth.service /etc/systemd/system/mail_sloth.service
systemctl daemon-reload
systemctl enable mail_sloth >/dev/null

echo "== swap: 1 GB, insurance on a small VPS"
if [ ! -f /swapfile ]; then
    fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo "== firewall: 22, 25, 443, 465"
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp >/dev/null
ufw allow 25/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw allow 465/tcp >/dev/null
ufw --force enable >/dev/null
ufw status | sed 's/^/   /'

cat <<'NEXT'

== next
1. Edit /etc/mail_sloth/config.toml (hostname, public_ip, sites, domains).
   `mail_sloth key` and `mail_sloth secret` print the values it needs.
2. Make a DKIM key per domain, as the service user so it can read them:
      sudo -u mail_sloth mail_sloth dkim example.com
3. Publish the DNS it prints:  mail_sloth dns
4. Start it:                   systemctl start mail_sloth && journalctl -fu mail_sloth
5. Verify DNS and port 25:     mail_sloth check
NEXT
